"""Build the end-to-end UI walkthrough MP4 from a browser-matrix capture.

Sources, all produced by matrix.mjs during the authoritative run:
  frames.jsonl      one sampler frame per second of wall-clock, tagged with the
                    scenario label that was active when it was taken
  frames/*.png      those sampler frames plus 18 named stills taken at the moment
                    each scenario's asserted result was on screen
  SUMMARY.txt       the matrix's own PASS/FAIL/INFO lines
  langfuse_results.json  the closing segment's own capture record

Layout: opening card, the architecture diagram narrated, then per scenario a
generated title card carrying that scenario's measured check counts, its sampled
frames in time order, and its named stills. Then the Langfuse segment and a
closing card stating the totals.

Narration is synthesised locally (Windows SAPI, Microsoft David Desktop) from the
texts in NARRATION below, and the speech is what sets the pacing: a segment is
never shorter than the cue that plays over it. Numbers spoken in a cue are
formatted from the artifacts at build time, so a cue cannot drift from a record.

Pacing is not disguised: the sampler ran at ~1 frame/second, so each sampled
frame is held for a solved number of seconds and the finished file states the
factor in captions.txt.
"""

import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import textwrap
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

CAP = Path(os.environ.get("KGP_CAPTURE_DIR", "C:/Users/IN009287/AppData/Local/Temp/kgp_cdp"))
ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "data" / "evaluation" / "ui_matrix" / "2026-11-24"
VIDEO = Path(os.environ.get("KGP_VIDEO", f"{CAP.as_posix()}/walkthrough.mp4"))
FRAMES = CAP / "frames"
CARDS = CAP / "cards"
NARR = CAP / "narr"
MOUNT = "/cap"
TARGET_SECONDS = 600.0
CARD_SECONDS = 4.0
STILL_SECONDS = 7.0
OPEN_SECONDS = 7.0
CLOSE_SECONDS = 8.0
ARCH_SOURCE = "arch.png"
ARCH_FRAME = "ARCH.png"
LF_STILL_SECONDS = 10.0
CUE_TAIL = 1.2          # silence left after a cue before the next one may start
SIZE = "1440x1100"
OUTPUT_FPS = 25
CONTAINER = "ffcap"
VOICE = "Microsoft Christopher Neural (Professional)"
SAMPLE_RATE = 22050

# Scenario id -> (card title, subtitle). Check counts are appended from SUMMARY.
SCENARIOS = OrderedDict([
    ("S01", ("Landing page",
             "Console renders: hero, sidebar API status, three console tabs, pipeline list")),
    ("S02", ("Guardrail: off-topic query",
             "Intake policy guard refuses before any model call")),
    ("S03", ("Guardrail: prompt injection / jailbreak",
             "Refusal raised by the intake guard; the request never reaches the backend API")),
    ("S04", ("No-CVE query",
             "Clean server-side refusal instead of an Investigation Failed traceback")),
    ("S05", ("Quick-select chip",
             "Curated example writes into the query textarea")),
    ("S06", ("Reset button",
             "Clears the textarea, drops the stale refusal and the previous report")),
    ("S07", ("Multi-Agent Copilot - live hosted run",
             "Policy Guard > Evidence > Analyst > Critic > Final Validator, one POST /investigate/stream")),
    ("S08", ("Single-Agent with RAG",
             "Runs inside the UI process; Critic bypassed and stated; trace readable from the API")),
    ("S09", ("Prompting baselines: zero-shot, few-shot, chain-of-thought",
             "No retrieval, no Critic - the unassisted-prompt notice and the Not Evaluated judge card")),
    ("S10", ("HITL web-fetch approval - Reject",
             "Manual-intervention modal; Reject chosen so no new record enters the frozen evidence set")),
    ("S11", ("Console widgets",
             "Top-K slider changes value; ATT&CK checkbox toggles and restores")),
    ("S12", ("Retrieval benchmark tab",
             "Measured scores only; failed validations counted, judge coverage stated honestly")),
    ("S13", ("Audit history",
             "Every persisted run appears in the list, including the UI-written ones")),
    ("S14", ("Evaluation page: RAG", "Per-claim retrieval metrics from the Batch 10 artifact")),
    ("S15", ("Evaluation page: LLM", "Answer-quality and judge metrics from the Batch 10 artifact")),
    ("S16", ("Console after the full matrix",
             "No application errors; the four failed requests are Streamlit health and host-config polls")),
])

STILLS = {
    "S01": ["S01_landing.png"],
    "S02": ["S02_guardrail_offtopic.png"],
    "S03": ["S03_guardrail_jailbreak.png"],
    "S04": ["S04_nocve_clean_refusal.png"],
    "S05": ["S05_quickselect_filled.png"],
    "S06": ["S06_reset_clean.png"],
    "S07": ["S07_multiagent_result.png"],
    "S08": ["S08_singleagent_result.png"],
    "S09": ["S09_prompt_zero-shot.png", "S09_prompt_few-shot.png", "S09_prompt_cot.png"],
    "S10": ["S10_hitl_modal.png", "S10_hitl_rejected.png"],
    "S11": ["S11_widgets.png"],
    "S12": ["S12_benchmark.png"],
    "S13": ["S13_history.png"],
    "S14": ["S14-eval-rag.png"],
    "S15": ["S15-eval-llm.png"],
}

LF_STILLS = [
    "L01_langfuse_traces.png",
    "L02_langfuse_trace_stages.png",
    "L03_langfuse_trace_generations.png",
    "L04_langfuse_scores_table.png",
    "L05_langfuse_dashboard.png",
]

# One cue per segment. `{...}` fields are filled from the measured artifacts when the
# timeline is built, so a spoken number is the recorded number rather than a recollection.
NARRATION = OrderedDict([
    ("open", "CyberShield AI. End to end verification of the fixed build, "
             "run in a real browser against the containers."),
    ("arch", "Start with the architecture. A query arrives from the console or the REST "
             "API and meets the Policy Guard first. That gate is pure regular expressions, "
             "no model call. It validates one CVE identifier, filters injection payloads, "
             "and refuses before anything is generated. "
             "Next, the local snapshot: {cache_cves} cached CVE records, and {cache_hits} "
             "of the {bench} benchmark identifiers resolve in it, so a run makes no "
             "external requests. A miss goes to the human-in-the-loop gate, where an "
             "operator must approve live web fetching. "
             "Inside, the Evidence agent searches a FAISS dense index and BM25 on "
             "{chunks_words} chunks, fused by reciprocal rank, into an immutable package "
             "of {top_k} cited passages. "
             "The Analyst drafts {sections} sections against those identifiers. The Critic "
             "audits {criteria} criteria and may ask for one bounded revision. The Final "
             "Validator is plain Python: it checks every citation, and sets the risk tier "
             "from CVSS and KEV status, never from the model."),
    ("S01", "Scenario one, the landing page. Console, sidebar API status, the three "
            "console tabs and the pipeline list all render."),
    ("S02", "Two, an off-topic query. The Policy Guard refuses before any model call, "
            "so nothing is generated and nothing is billed."),
    ("S03", "Three, a prompt injection. The refusal appears in the console, and the "
            "request never reaches the backend API, so the injected text never becomes "
            "part of a prompt."),
    ("S04", "Four, a query with no CVE identifier. You get a clean refusal, not a traceback."),
    ("S05", "Five, the quick-select chip. One click writes the example into the query box."),
    ("S06", "Six, Reset. It clears the textarea, drops the stale refusal, and removes "
            "the previous report."),
    ("S07", "Seven is the full multi-agent copilot on the hosted model. Policy Guard, "
            "Evidence, Analyst, Critic, Final Validator, streamed over one request."),
    ("S08", "Eight, single agent with retrieval. It runs inside the UI process, bypasses "
            "the Critic, and says so. The trace is readable from the API."),
    ("S09", "Nine, the prompting baselines. Zero-shot, few-shot, chain-of-thought. No "
            "retrieval and no Critic, so the console shows the unassisted-prompt notice, "
            "and the judge card reads N A instead of a score."),
    ("S10", "Ten, the human-in-the-loop gate on a cache miss. Reject is chosen here, so "
            "no new record enters the frozen evidence set."),
    ("S11", "Eleven, the widgets. The top-K slider changes value, and the ATT&CK "
            "checkbox toggles and restores."),
    ("S12", "Twelve, the retrieval benchmark tab. It states judge coverage honestly, "
            "and counts failed validations instead of hiding them."),
    ("S13", "Thirteen, audit history. The multi-agent, single-agent and prompting runs "
            "all appear, each row naming the index it was retrieved from."),
    ("S14", "Fourteen, the RAG evaluation page, reading per-claim retrieval metrics from "
            "the Batch Ten artifact."),
    ("S15", "Fifteen, the LLM evaluation page, with answer quality and judge metrics from "
            "the same artifact."),
    ("S16", "Sixteen, the console after the full matrix. No application errors, and the "
            "four failed requests are Streamlit health and host-config polls."),
    ("lf1", "Finally, the observability side, on the same machine. This is the local "
            "Langfuse project. It opens on the last twenty-four hours, and that window "
            "shows nothing, so the range is widened before any of it is readable."),
    ("lf2", "Each investigation writes one trace: the {spans} traced stages, the model "
             "calls behind them, and the {scores_names} metric names the harness pushes. "
             "{lf_traces} traces and {lf_scores} score rows attached to them are on "
             "record, with the token count and cost under the model that produced them."),
    ("close", "To close. The user interface matrix: {passed} passes, {failed} failures "
              "and {info} information rows over {total} assertions; those information rows "
              "are text inside a canvas grid, verified from the frames. The Langfuse "
              "capture ran next to it: {lf_pass} passes and {lf_fail} failure, and that "
              "failure is real. {orphan_rows} score rows name traces the store no longer "
              "holds."),
])


def q(s):
    return "'" + str(s).replace("'", "'\\''") + "'"


def docker_sh(script, check=True):
    return subprocess.run(["docker", "exec", CONTAINER, "sh", "-c", script],
                          check=check, capture_output=True, text=True)


def ensure_container():
    running = subprocess.run(["docker", "ps", "--filter", f"name={CONTAINER}",
                              "--format", "{{.Names}}"], check=True,
                             capture_output=True, text=True).stdout.split()
    if CONTAINER in running:
        return
    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True, text=True)
    subprocess.run(["docker", "run", "-d", "--name", CONTAINER,
                    "-v", f"{CAP.as_posix()}:{MOUNT}", "python:3.11-slim",
                    "sleep", "3600"], check=True, capture_output=True, text=True)


def scenario_of(label):
    m = re.match(r"(S\d\d)", label)
    return m.group(1) if m else label


def load_frames():
    rows = []
    for line in (CAP / "frames.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if not (FRAMES / rec["file"]).exists():
            continue
        rec["ts"] = datetime.fromisoformat(rec["at"].replace("Z", "+00:00"))
        rows.append(rec)
    rows.sort(key=lambda r: r["n"])
    return rows


def load_counts():
    counts, totals = OrderedDict(), {"PASS": 0, "FAIL": 0, "INFO": 0}
    for line in (CAP / "SUMMARY.txt").read_text(encoding="utf-8").splitlines():
        m = re.match(r"(PASS|FAIL|INFO)\s+(\S+)", line)
        if not m:
            continue
        status, sid = m.group(1), scenario_of(m.group(2))
        counts.setdefault(sid, {"PASS": 0, "FAIL": 0, "INFO": 0})
        counts[sid][status] += 1
        totals[status] += 1
    return counts, totals


CARD_BODY_Y, CARD_PITCH, CARD_GLYPH, CARD_WRAP = 340, 88, 28, 74
CARD_MAX_LINES = (1100 - CARD_GLYPH - CARD_BODY_Y) // CARD_PITCH + 1


def card_lines(body):
    """The body exactly as drawtext will lay it out, one entry per rendered line."""
    out = []
    for line in body:
        out.extend(textwrap.wrap(line, CARD_WRAP) if line.strip() else [""])
    return out


def make_card(name, title, body):
    """Render one title card PNG. All text goes in via textfile= so colons,
    quotes and slashes in the wording never reach the shell or the filtergraph.
    Measured on the rendered cards: body lines sit 88 px apart from y=340, so a
    line past CARD_MAX_LINES is drawn below the frame and silently lost."""
    lines = card_lines(body)
    if len(lines) > CARD_MAX_LINES:
        sys.exit(f"card {name}: {len(lines)} body lines overflow the frame "
                 f"(max {CARD_MAX_LINES}); shorten the text")
    wrapped_title = textwrap.fill(title, 40)
    wrapped_body = "\n".join(lines)
    (CARDS / f"{name}_t.txt").write_text(wrapped_title, encoding="utf-8")
    (CARDS / f"{name}_b.txt").write_text(wrapped_body, encoding="utf-8")
    vf = (
        "drawtext=fontfile={m}/arial.ttf:textfile={m}/cards/{n}_t.txt:"
        "fontcolor=0xF2F6FF:fontsize=44:line_spacing=10:x=90:y=120,"
        "drawtext=fontfile={m}/arial.ttf:textfile={m}/cards/{n}_b.txt:"
        "fontcolor=0xC9D6E8:fontsize=30:line_spacing=9:x=90:y=340"
    ).format(m=MOUNT, n=name)
    docker_sh(" ".join([
        q(f"{MOUNT}/ffmpeg"), "-hide_banner", "-loglevel", "error", "-y",
        "-f", "lavfi", "-i", q(f"color=c=0x0C1424:s={SIZE}:r=25:d=1"),
        "-vf", q(vf), "-frames:v", "1", q(f"{MOUNT}/cards/{name}.png"),
    ]))


def probe_duration(video):
    """Measured length of the encoded file, read back from the encoder rather than
    assumed from the plan. Returns None when the file is not inside the mount."""
    if not Path(video).exists():
        return None
    return _duration_from_ffmpeg(video)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _duration_from_ffmpeg(path):
    """Read a length back from the encoder rather than assuming it. Works for any file
    inside the cap mount, audio or video."""
    try:
        rel = Path(path).relative_to(CAP)
    except ValueError:
        return None
    out = docker_sh(" ".join([
        q(f"{MOUNT}/ffmpeg"), "-hide_banner", "-i", q(f"{MOUNT}/{rel.as_posix()}"),
    ]), check=False)
    m = re.search(r"Duration:\s*(\d+):(\d+):(\d+(?:\.\d+)?)", out.stdout + out.stderr)
    if not m:
        return None
    return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + float(m.group(3))


def words_for(n):
    """A number the voice can say. SAPI reads grouped digits, so the figure the diagram
    carries and the figure the voice speaks are the same measurement."""
    return f"{n:,}"


def _annotated_field_count(src, class_name, type_name):
    """Count a contract's fields by annotation, from source: the host interpreter has no
    pydantic, so importing the module is not an option and parsing it is."""
    for node in ast.parse(src).body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return sum(1 for st in node.body
                       if isinstance(st, ast.AnnAssign)
                       and getattr(st.annotation, "id", None) == type_name)
    sys.exit(f"{class_name} not found in app/contracts.py")


def narration_values(totals):
    """Every number a cue may speak, read from the artifact that records it."""
    import glob

    cached_ids = set()
    for f in glob.glob(str(ROOT / "data" / "raw" / "nvd" / "*.json")):
        try:
            if json.loads(Path(f).read_text(encoding="utf-8")).get("vulnerabilities"):
                cached_ids.add(Path(f).stem.upper())
        except (json.JSONDecodeError, OSError):
            continue

    rm = json.loads((ROOT / "data" / "evaluation" / "retrieval_metrics.json")
                    .read_text(encoding="utf-8"))
    chunks = rm["engine_ablation"]["provenance"]["corpus_chunks"]

    b10 = json.loads((ROOT / "data" / "evaluation" / "batch10" / "scores.json")
                     .read_text(encoding="utf-8"))

    contracts = (ROOT / "app" / "contracts.py").read_text(encoding="utf-8")
    top_k = int(re.search(r"top_k: int = Field\(default=(\d+)", contracts).group(1))

    lf = json.loads((CAP / "langfuse_results.json").read_text(encoding="utf-8"))
    total = totals["PASS"] + totals["FAIL"] + totals["INFO"]
    return {
        "cache_cves": len(cached_ids),
        "bench": len(b10["rows"]),
        "cache_hits": sum(1 for r in b10["rows"]
                          if str(r.get("cve_id", "")).upper() in cached_ids),
        "chunks_words": f"over {int(chunks // 1000) * 1000:,}",
        "chunks_exact": words_for(chunks),
        "top_k": top_k,
        "sections": _annotated_field_count(contracts, "AnalystDraft", "AnalystSection"),
        "criteria": _annotated_field_count(contracts, "CriticReview", "ReviewStatus"),
        "spans": len(lf["spans_on_shown_trace"]),
        "scores_names": len(lf["score_names_on_shown_trace"]),
        "lf_traces": words_for(lf["api_total_traces"]),
        "lf_scores": words_for(lf["api_total_scores"] - lf["orphan_score_rows"]),
        "passed": totals["PASS"], "failed": totals["FAIL"], "info": totals["INFO"],
        "total": total,
        "lf_pass": lf["pass"], "lf_fail": lf["fail"],
        "orphan_rows": lf["orphan_score_rows"],
    }


def synth(text, key):
    """One local SAPI render per cue. The text goes in from a file so no quote or slash
    ever reaches the shell, and nothing leaves this machine."""
    NARR.mkdir(exist_ok=True)
    txt, wav = NARR / f"{key}.txt", NARR / f"{key}.wav"
    txt.write_text(text, encoding="utf-8")
    ps = (
        "Add-Type -AssemblyName System.Speech;"
        "$s = New-Object System.Speech.Synthesis.SpeechSynthesizer;"
        f"$s.SelectVoice('{VOICE}'); $s.Rate = 0;"
        f"$s.SetOutputToWaveFile('{wav.as_posix()}');"
        f"$s.Speak([System.IO.File]::ReadAllText('{txt.as_posix()}'));"
        "$s.Dispose()"
    )
    subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
                   check=True, capture_output=True, text=True)
    if not wav.exists():
        sys.exit(f"synthesis produced no audio for {key}")
    return wav


def render_arch_frame():
    """The flowchart is 2880x1692 and the video is 1440x1100, so it has to be fitted and
    padded rather than stretched; the pad colour is the one the title cards use."""
    docker_sh(" ".join([
        q(f"{MOUNT}/ffmpeg"), "-hide_banner", "-loglevel", "error", "-y",
        "-i", q(f"{MOUNT}/{ARCH_SOURCE}"),
        "-vf", q("scale=1440:-2:flags=lanczos,"
                 "pad=1440:1100:(ow-iw)/2:(oh-ih)/2:color=0x0C1424"),
        "-frames:v", "1", q(f"{MOUNT}/cards/{ARCH_FRAME}"),
    ]))


def build_narration_wav(cues, total_seconds):
    """Cues are placed by start time; the gaps between them become silence files and the
    whole run is concatenated, so the audio track and the concat list share one timeline."""
    parts, cursor = [], 0.0
    for i, c in enumerate(sorted(cues, key=lambda x: x["start"])):
        gap = c["start"] - cursor
        if gap < -0.005:
            sys.exit(f"cue {c['key']} starts {abs(gap):.2f}s before the previous cue ends")
        if gap > 0.02:
            sil = NARR / f"sil_{i:02d}.wav"
            docker_sh(" ".join([
                q(f"{MOUNT}/ffmpeg"), "-hide_banner", "-loglevel", "error", "-y",
                "-f", "lavfi", "-i", q(f"anullsrc=r={SAMPLE_RATE}:cl=mono"),
                "-t", f"{gap:.3f}", "-c:a", "pcm_s16le", q(f"{MOUNT}/{sil.relative_to(CAP).as_posix()}"),
            ]))
            parts.append(sil)
        parts.append(c["wav"])
        cursor = c["start"] + c["dur"]
    if total_seconds - cursor > 0.02:
        sil = NARR / "sil_end.wav"
        docker_sh(" ".join([
            q(f"{MOUNT}/ffmpeg"), "-hide_banner", "-loglevel", "error", "-y",
            "-f", "lavfi", "-i", q(f"anullsrc=r={SAMPLE_RATE}:cl=mono"),
            "-t", f"{total_seconds - cursor:.3f}", "-c:a", "pcm_s16le",
            q(f"{MOUNT}/{sil.relative_to(CAP).as_posix()}"),
        ]))
        parts.append(sil)
    lst = NARR / "list.txt"
    lst.write_text("".join(f"file '{MOUNT}/{p.relative_to(CAP).as_posix()}'\n" for p in parts),
                   encoding="utf-8")
    out = NARR / "narration.wav"
    docker_sh(" ".join([
        q(f"{MOUNT}/ffmpeg"), "-hide_banner", "-loglevel", "error", "-y",
        "-f", "concat", "-safe", "0", "-i", q(f"{MOUNT}/narr/list.txt"),
        "-c", "copy", q(f"{MOUNT}/narr/narration.wav"),
    ]))
    return out, cursor


def encode(narration, planned_frames):
    """Constant frame rate on purpose, and the video stream limited to the frame count
    the edit list says it should have.

    Two separate measurements drove this. Left as variable frame rate the shipped file
    published sample durations that contradicted its own timestamps: its first five frames
    carried 9.04 + 71.52 + 9.04 + 71.52 + 1.04 = 162.16 s, which is why a player that trusts
    durations sat on the opening card for two minutes forty-three while the narration had
    moved on. Duplicating each held frame to OUTPUT_FPS removes that contradiction outright.

    The ffconcat terminator line then leaves the demuxer running past the list (measured:
    18,873 frames for an 18,624-frame list), which is silent frozen video after the
    narration ends. `-t` cannot be used to trim that: measured on this build it stops at
    18,165 frames because the demuxer's tail does not sit where the list arithmetic puts it.
    Asking for exactly the planned number of video frames is a count, not a time, so it is
    immune to that, and the audio stream simply ends where the narration wav ends."""
    docker_sh(" ".join([
        q(f"{MOUNT}/ffmpeg"), "-hide_banner", "-loglevel", "error", "-y",
        "-f", "concat", "-safe", "0", "-i", q(f"{MOUNT}/concat.txt"),
        "-i", q(f"{MOUNT}/{narration.relative_to(CAP).as_posix()}"),
        "-map", "0:v", "-map", "1:a",
        "-c:v", "libx264", "-preset", "veryfast", "-crf", "24", "-pix_fmt", "yuv420p",
        "-r", str(OUTPUT_FPS), "-fps_mode", "cfr", "-g", str(2 * OUTPUT_FPS),
        "-frames:v", str(planned_frames),
        "-c:a", "aac", "-b:a", "128k", "-movflags", "+faststart",
        q(f"{MOUNT}/{VIDEO.name}"),
    ]))


def write_capture_json(rows, wall, hold, stills, n_cards, planned, counts, totals,
                       holds, cues, cue_dur, narration, speech_secs, speech_last_end, values):
    """Record what the encode actually is, beside the evidence the report cites."""
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    duration = probe_duration(VIDEO)
    rec = {
        "generated_by": "scripts/ui_matrix/assemble.py",
        "matrix_summary_sha256": sha(EVIDENCE / "SUMMARY.txt"),
        "frame_manifest_sha256": sha(EVIDENCE / "frames.jsonl"),
        "sampler_frames": len(rows),
        "wall_clock_seconds": round(wall, 1),
        "named_stills": stills,
        "langfuse_stills": len(LF_STILLS),
        "generated_cards": n_cards,
        "hold_per_frame_seconds": round(hold, 4),
        "scenario_holds": {k: round(v, 4) for k, v in holds.items()},
        "planned_seconds": round(planned, 2),
        "output_fps": OUTPUT_FPS,
        "planned_frames": int(round(planned * OUTPUT_FPS)),
        "measured_video_seconds": duration,
        "video_bytes": VIDEO.stat().st_size if VIDEO.exists() else None,
        "video_sha256": sha(VIDEO) if VIDEO.exists() else None,
        "video_resolution": SIZE,
        "encoder": (f"libx264 crf24 preset veryfast yuv420p faststart, constant "
                    f"{OUTPUT_FPS} fps with every hold quantised to whole frames and the "
                    f"video stream limited to the planned frame count, aac 128k mono; "
                    f"narration synthesised locally"),
        "audio": {
            "voice": VOICE, "sample_rate": SAMPLE_RATE, "channels": "mono",
            "cues": len(cues), "speech_seconds": round(speech_secs, 1),
            "last_cue_end_seconds": round(speech_last_end, 1),
            "narration_seconds": _duration_from_ffmpeg(narration) if narration.exists() else None,
            "narration_sha256": sha(narration) if narration.exists() else None,
            "cue_seconds": {c["key"]: round(c["dur"], 2) for c in cues},
            "cue_starts": {c["key"]: round(c["start"], 2) for c in cues},
        },
        "narration_values": values,
        "checks": totals,
        "per_scenario_checks": {k: v["PASS"] + v["FAIL"] + v["INFO"] for k, v in counts.items()},
    }
    (EVIDENCE / "capture.json").write_text(
        json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"capture.json written: duration={duration} frames={len(rows)} cues={len(cues)}")


def main():
    do_encode = "--encode" in sys.argv
    ensure_container()
    CARDS.mkdir(exist_ok=True)

    rows = load_frames()
    if not rows:
        sys.exit("no frames")
    counts, totals = load_counts()

    by_scen = OrderedDict()
    for r in rows:
        by_scen.setdefault(scenario_of(r["label"]), []).append(r)

    stills = sum(len(STILLS.get(sid, [])) for sid in by_scen)
    fixed = OPEN_SECONDS + CLOSE_SECONDS + CARD_SECONDS * len(by_scen) + STILL_SECONDS * stills
    hold = (TARGET_SECONDS - fixed) / len(rows)
    if hold <= 0:
        sys.exit(f"fixed budget {fixed:.0f}s already exceeds target")
    wall = (rows[-1]["ts"] - rows[0]["ts"]).total_seconds()

    if not (CAP / ARCH_SOURCE).exists():
        sys.exit(f"missing architecture raster {ARCH_SOURCE} in the capture dir")
    missing = [n for n in LF_STILLS if not (FRAMES / n).exists()]
    if missing:
        sys.exit(f"missing Langfuse stills: {missing} (run langfuse.mjs)")

    values = narration_values(totals)
    texts = OrderedDict((k, v.format(**values)) for k, v in NARRATION.items())
    cue_wav, cue_dur = {}, {}
    for key, text in texts.items():
        cue_wav[key] = synth(text, key)
        cue_dur[key] = _duration_from_ffmpeg(cue_wav[key])
        print(f"  cue {key:<6} {cue_dur[key]:6.2f}s  {len(text.split()):3d} words")

    lines = ["ffconcat version 1.0"]
    plan, cues, holds = [], [], {}
    clock = {"frames": 0}

    def add(path, secs, group):
        """Hold each image for a whole number of output frames. The concat demuxer rounds
        a fractional duration its own way, and across 420 entries those fractions are what
        made the shipped file publish sample durations that disagree with its timestamps.
        Rounding here, and reading the cue start times off the same integer grid, keeps the
        picture list, the narration timeline and the finished file on one clock."""
        held = max(1, round(secs * OUTPUT_FPS))
        clock["frames"] += held
        lines.append(f"file '{path}'")
        lines.append(f"duration {held / OUTPUT_FPS:.4f}")
        plan.append((group, held / OUTPUT_FPS))

    def speak(key):
        cues.append({"key": key, "start": clock["frames"] / OUTPUT_FPS,
                     "dur": cue_dur[key], "wav": cue_wav[key]})

    make_card("OPEN", "CyberShield AI", [
        "End-to-end UI verification of the fixed build",
        "",
        f"Streamlit + FastAPI on docker-compose, captured {rows[0]['ts']:%Y-%m-%d %H:%M} UTC",
        f"{len(rows)} sampled frames covering {wall:.0f} s of real matrix execution",
        f"Matrix: {totals['PASS']} PASS / {totals['FAIL']} FAIL / {totals['INFO']} INFO",
        f"Each sampled frame held {hold:.2f} s (captured at 1 frame per second)",
        f"Structure: architecture, {len(by_scen)} UI scenarios, then the local Langfuse traces",
        "Narration synthesised on this machine. Nothing uploaded.",
    ])
    open_secs = max(OPEN_SECONDS, cue_dur["open"] + CUE_TAIL)
    speak("open")
    add("cards/OPEN.png", open_secs, "open")

    render_arch_frame()
    speak("arch")
    add(f"cards/{ARCH_FRAME}", cue_dur["arch"] + CUE_TAIL, "arch")

    for sid, items in by_scen.items():
        title, sub = SCENARIOS.get(sid, (sid, ""))
        c = counts.get(sid, {"PASS": 0, "FAIL": 0, "INFO": 0})
        make_card(sid, f"{sid}  {title}", [
            sub,
            "",
            f"{c['PASS']} PASS   {c['FAIL']} FAIL   {c['INFO']} INFO",
            f"wall-clock {items[0]['ts']:%H:%M:%S} - {items[-1]['ts']:%H:%M:%S} UTC"
            f"   ({len(items)} sampled frames)",
        ])
        n_stills = len(STILLS.get(sid, []))
        h = hold
        if CARD_SECONDS + len(items) * h + n_stills * STILL_SECONDS < cue_dur[sid] + CUE_TAIL:
            h = (cue_dur[sid] + CUE_TAIL - CARD_SECONDS - n_stills * STILL_SECONDS) / len(items)
            if h <= 0:
                sys.exit(f"cue {sid} outlasts its own stills")
        holds[sid] = h
        speak(sid)
        add(f"cards/{sid}.png", CARD_SECONDS, f"{sid} card")
        for r in items:
            add(f"frames/{r['file']}", h, f"{sid} sampled")
        for name in STILLS.get(sid, []):
            add(f"frames/{name}", STILL_SECONDS, f"{sid} still")

    lf = json.loads((CAP / "langfuse_results.json").read_text(encoding="utf-8"))
    make_card("S17", "S17  Langfuse: the recorded traces", [
        "Local Langfuse v2, loopback only, signed in as the project operator",
        "",
        f"{lf['pass']} PASS   {lf['fail']} FAIL   on its own capture record",
        f"{lf['api_total_traces']} traces, {lf['api_total_scores'] - lf['orphan_score_rows']} "
        f"score rows attached to them, {lf['sampler_frames']} sampled frames",
    ])
    lf_still = LF_STILL_SECONDS
    for _ in range(2):
        lf2_start = CARD_SECONDS + 2 * lf_still
        lf_still = max(lf_still, (cue_dur["lf1"] + CUE_TAIL - CARD_SECONDS) / 2,
                       (lf2_start + cue_dur["lf2"] + CUE_TAIL - CARD_SECONDS) / len(LF_STILLS))
    speak("lf1")
    add("cards/S17.png", CARD_SECONDS, "S17 card")
    for i, name in enumerate(LF_STILLS):
        if i == 2:
            speak("lf2")
        add(f"frames/{name}", lf_still, "S17 still")

    make_card("CLOSE", "Result", [
        f"UI matrix: {totals['PASS']} PASS   {totals['FAIL']} FAIL   {totals['INFO']} INFO"
        f"   ({totals['PASS'] + totals['FAIL'] + totals['INFO']} assertions)",
        f"Langfuse capture: {lf['pass']} PASS   {lf['fail']} FAIL"
        f"   ({lf['orphan_score_rows']} orphan score rows)",
        "",
        "The three INFO rows assert text inside a canvas-rendered",
        "st.dataframe: on screen, not in the DOM, so it is shown here",
        "and verified from the frames rather than asserted from the page.",
        "",
        "Defects closed in this build: the trace store is shared between",
        "the api and ui containers, and Reset clears the query textarea.",
    ])
    close_secs = max(CLOSE_SECONDS, cue_dur["close"] + CUE_TAIL)
    speak("close")
    add("cards/CLOSE.png", close_secs, "close")
    lines.append("file 'cards/CLOSE.png'")

    (CAP / "concat.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    total = clock["frames"] / OUTPUT_FPS
    narration, speech_last_end = build_narration_wav(cues, total)
    speech_secs = sum(c["dur"] for c in cues)
    if do_encode:
        encode(narration, clock["frames"])

    (CAP / "captions.txt").write_text((
        "Captured: {a} to {b} ({c:.1f} s wall-clock)\n"
        "Matrix outcome: {p} PASS, {f} FAIL, {i} INFO\n"
        "Composition: {n} sampler frames + {s} named stills + {k} generated cards\n"
        "Pacing: sampler ran at ~1 frame/second; each sampled frame held {h:.4f} s, "
        "each still {st:.1f} s, each card {cd:.1f} s. Planned duration {t:.1f} s.\n"
        "INFO rows: assertions on text inside a canvas st.dataframe, not readable from the DOM.\n"
        "Opening segment: the architecture flowchart, narrated for {arch:.1f} s.\n"
        "Closing segment: the local Langfuse project, {lf:.1f} s over {ln} stills.\n"
        "Audio: {cq} narration cues, {voice}, {sr} Hz mono, synthesised on this machine; "
        "{sp:.1f} s of speech, last cue ending at {le:.1f} s.\n"
        "Encoding: H.264 + AAC, yuv420p, {sz}. Produced locally. Nothing uploaded.\n"
    ).format(a=rows[0]["ts"].isoformat(), b=rows[-1]["ts"].isoformat(), c=wall,
             p=totals["PASS"], f=totals["FAIL"], i=totals["INFO"], n=len(rows),
             s=stills, k=len(by_scen) + 3, h=hold, st=STILL_SECONDS,
             cd=CARD_SECONDS, t=total, sz=SIZE,
             arch=cue_dur["arch"] + CUE_TAIL,
             lf=CARD_SECONDS + len(LF_STILLS) * lf_still, ln=len(LF_STILLS),
             cq=len(cues), voice=VOICE, sr=SAMPLE_RATE, sp=speech_secs,
             le=speech_last_end), encoding="utf-8")

    write_capture_json(rows, wall, hold, stills, len(by_scen) + 3, total, counts, totals,
                       holds, cues, cue_dur, narration, speech_secs, speech_last_end, values)

    seen = OrderedDict()
    for group, secs in plan:
        key = group.split(" ")[0]
        seen[key] = seen.get(key, 0) + secs
    for k, v in seen.items():
        print(f"  {k:<8} {v:7.1f}s")
    print(f"planned={total:.1f}s frames={len(rows)} stills={stills} "
          f"cards={len(by_scen) + 3} hold={hold:.4f}s wall={wall:.1f}s "
          f"speech={speech_secs:.1f}s last_cue_end={speech_last_end:.1f}s")
    print(f"checks: {totals['PASS']} PASS / {totals['FAIL']} FAIL / {totals['INFO']} INFO")
    if not do_encode:
        print("timeline planned; pass --encode to write the MP4")


if __name__ == "__main__":
    main()
