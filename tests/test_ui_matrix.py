"""Guards for the automated browser-matrix evidence and the report section that cites it.

The matrix ran against a live `docker compose` stack, so it cannot be re-executed offline.
What can be checked offline is that the numbers Section 11.3 publishes are the numbers the
stored log recorded, and that the stored record still matches the files it describes.
"""

import hashlib
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

from scripts.build_report_html import SRC

EVIDENCE = Path(__file__).resolve().parents[1] / "data" / "evaluation" / "ui_matrix" / "2026-11-24"
SUMMARY = EVIDENCE / "SUMMARY.txt"
FRAMES = EVIDENCE / "frames.jsonl"
CAPTURE = EVIDENCE / "capture.json"
LANGFUSE = EVIDENCE / "langfuse_results.json"


def _rows():
    out = []
    for line in SUMMARY.read_text(encoding="utf-8").splitlines():
        m = re.match(r"(PASS|FAIL|INFO) (\S+) :: (.*?) :: (.*)$", line)
        if m:
            out.append({"status": m.group(1), "scenario": m.group(2),
                        "name": m.group(3), "detail": m.group(4)})
    return out


def _counts():
    return Counter(r["status"] for r in _rows())


def _capture():
    return json.loads(CAPTURE.read_text(encoding="utf-8"))


def _section() -> str:
    text = SRC.read_text(encoding="utf-8")
    start = text.index("### 11.3 Automated End-to-End UI Verification")
    end = text.index("## 12.", start)
    return text[start:end]


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_the_stored_matrix_log_has_no_failures():
    """The substantive guard: a failure left in the log fails here, not in review."""
    failed = [r for r in _rows() if r["status"] == "FAIL"]
    assert not failed, f"browser matrix reported failures: {failed[:3]}"


def test_every_scenario_row_names_a_scenario_that_the_report_table_lists():
    scenarios = {r["scenario"].split("-")[0] for r in _rows()}
    section = _section()
    for sid in sorted(scenarios):
        assert sid in section, f"{sid} ran but is not described in Section 11.3"


def test_the_capture_record_matches_the_files_it_describes():
    """capture.json is generated; if the evidence behind it is swapped, this stops the swap."""
    cap = _capture()
    assert cap["matrix_summary_sha256"] == _sha(SUMMARY)
    assert cap["frame_manifest_sha256"] == _sha(FRAMES)


def test_the_capture_counts_are_the_matrix_log_counts():
    cap = _capture()
    assert cap["checks"] == {"PASS": _counts()["PASS"], "FAIL": _counts()["FAIL"],
                             "INFO": _counts()["INFO"]}
    per = Counter(r["scenario"].split("-")[0] for r in _rows())
    assert cap["per_scenario_checks"] == dict(per)


def test_the_frame_count_and_wall_clock_recompute_from_the_manifest():
    rows = [json.loads(line) for line in FRAMES.read_text(encoding="utf-8").splitlines() if line.strip()]
    stamps = sorted(datetime.fromisoformat(r["at"].replace("Z", "+00:00")) for r in rows)
    cap = _capture()
    assert cap["sampler_frames"] == len(rows)
    assert cap["wall_clock_seconds"] == round((stamps[-1] - stamps[0]).total_seconds(), 1)


def test_the_narration_totals_recompute_from_the_cue_table():
    """One build published the last cue's end time as the amount of speech. Both figures
    are in the record, so the pair is checkable without listening to anything."""
    audio = _capture()["audio"]
    cap = _capture()
    assert len(audio["cue_seconds"]) == audio["cues"]
    assert round(sum(audio["cue_seconds"].values()), 1) == audio["speech_seconds"]
    assert set(audio["cue_starts"]) == set(audio["cue_seconds"])
    last = max(start + audio["cue_seconds"][name]
               for name, start in audio["cue_starts"].items())
    assert round(last, 1) == audio["last_cue_end_seconds"]
    assert audio["speech_seconds"] < audio["last_cue_end_seconds"] <= cap["measured_video_seconds"]


def test_the_recorded_video_runs_on_one_clock_at_25_frames_per_second():
    """One build's player sat on the opening card for 162 s while another moved on
    schedule, because the concat list held each image for a fraction of a frame and the
    encode left a file whose sample durations contradicted its own timestamps. The record
    carries the frame grid, so the two-clocks defect is checkable without a player."""
    cap, audio = _capture(), _capture()["audio"]
    assert cap["output_fps"] == 25
    assert cap["planned_frames"] == round(cap["planned_seconds"] * cap["output_fps"])
    assert abs(cap["measured_video_seconds"] * cap["output_fps"] - cap["planned_frames"]) <= 1
    assert abs(cap["measured_video_seconds"] - audio["narration_seconds"]) <= 0.15, \
        "video and narration diverged: silent tail or cut speech"
    for name, start in audio["cue_starts"].items():
        assert abs(start * cap["output_fps"] - round(start * cap["output_fps"])) < 1e-6, \
            f"cue {name} starts mid-frame"
    assert audio["cue_starts"]["arch"] < 15.0, "the architecture no longer leads the video"


def test_the_narration_cues_speak_only_numbers_the_build_derives():
    """A figure written into a cue is a figure no artifact produced. Digits inside a name
    (BM25) are part of the term; a digit that starts a word is a statistic."""
    from scripts.ui_matrix import assemble
    values = _capture()["narration_values"]
    for name, cue in assemble.NARRATION.items():
        typed = re.search(r"(?<![A-Za-z0-9-])\d", cue)
        assert not typed, f"cue {name} speaks a typed figure: ...{cue[typed.start()-30:typed.start()+20]}"
        for field in re.findall(r"\{(\w+)\}", cue):
            assert field in values, f"cue {name} asks for {field}, which no artifact records"
    assert len(assemble.NARRATION) == _capture()["audio"]["cues"]


def test_the_langfuse_segment_is_recorded_and_matches_what_is_published():
    """The closing minute is a separate capture with a real failure in it; its record is
    committed so 17 PASS / 1 FAIL is a read, not a recollection."""
    lf = json.loads(LANGFUSE.read_text(encoding="utf-8"))
    counted = Counter(r["status"] for r in lf["results"])
    assert counted["PASS"] == lf["pass"] and counted["FAIL"] == lf["fail"]
    assert counted.get("FAIL") == 1, "the recorded Langfuse failure was dropped or grew"
    orphans = [r for r in lf["results"] if r["status"] == "FAIL"]
    assert str(lf["orphan_score_rows"]) in orphans[0]["detail"]

    values = _capture()["narration_values"]
    assert (lf["pass"], lf["fail"], lf["orphan_score_rows"]) == (
        values["lf_pass"], values["lf_fail"], values["orphan_rows"])
    assert lf["api_total_traces"] == int(values["lf_traces"])
    assert lf["dashboard_score_card"] == values["lf_scores"]
    assert lf["api_total_scores"] - lf["orphan_score_rows"] == int(values["lf_scores"])
    assert len(lf["score_names_on_shown_trace"]) == values["scores_names"]
    assert len(lf["spans_on_shown_trace"]) == values["spans"]

    section = _section()
    assert f"{lf['pass']} PASS, {lf['fail']} FAIL" in section
    assert f"{lf['orphan_score_rows']} score rows" in section


def test_section_11_3_publishes_exactly_the_measured_counts():
    cap, counts, section = _capture(), _counts(), _section()
    total = counts["PASS"] + counts["FAIL"] + counts["INFO"]
    assert f"{counts['PASS']} PASS, {counts['FAIL']} FAIL, {counts['INFO']} INFO" in section
    assert f"{total} assertions" in section
    assert f"{cap['sampler_frames']} sampled frames covering {cap['wall_clock_seconds']} s" in section
    minutes, seconds = divmod(int(cap["measured_video_seconds"]), 60)
    assert f"({minutes}:{seconds:02d}," in section
    assert f"{len(cap['per_scenario_checks'])} scenarios" in section


def test_section_11_3_does_not_claim_a_cleaner_run_than_the_log_shows():
    """A number typed to look better than the log is the failure mode this exists to catch."""
    counts, section = _counts(), _section()
    for wrong in ("92 PASS", "93 PASS", "94 PASS", "90 PASS"):
        assert wrong not in section
    assert f"{counts['PASS']} PASS" in section

    # The section quotes three capture records. Any failure count in it must be one of theirs.
    lf = json.loads(LANGFUSE.read_text(encoding="utf-8"))
    shipped = Counter(re.match(r"(PASS|FAIL) ", line).group(1)
                      for line in (EVIDENCE / "first_run_before_fixes.txt")
                      .read_text(encoding="utf-8").splitlines()
                      if re.match(r"(PASS|FAIL) ", line))
    allowed = {f"{counts['FAIL']} FAIL", f"{lf['fail']} FAIL", f"{shipped['FAIL']} FAIL"}
    for found in set(re.findall(r"\d+ FAIL", section)):
        assert found in allowed, f"{found} is in Section 11.3 and in no capture record"


def test_the_as_shipped_run_is_reported_at_the_count_its_own_log_shows():
    """Section 11.3 quotes the first run's score. That score is a recorded file, not a
    recollection, and the split between app defects and harness bugs is fixed here."""
    first = EVIDENCE / "first_run_before_fixes.txt"
    rows = [re.match(r"(PASS|FAIL) (\S+) :: (.*?) :: (.*)$", line)
            for line in first.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows = [m.groups() for m in rows]
    counts = Counter(row[0] for row in rows)
    section = _section()
    assert f"{counts['PASS']} PASS / {counts['FAIL']} FAIL" in section

    failed = {row[2] for row in rows if row[0] == "FAIL"}
    real_defects = {
        "reset clears textarea",
        "defect#1: single-agent citation readback",
        "defect#1b: single-agent run appears in history",
        "defect#1b: prompting run appears in history",
    }
    assert real_defects <= failed, f"named defects no longer in the first-run log: {real_defects - failed}"
    assert len(failed - real_defects) == counts["FAIL"] - len(real_defects)


def test_the_matrix_log_ends_with_the_counts_the_report_publishes():
    log = (EVIDENCE / "matrix.log").read_text(encoding="utf-8")
    counts = _counts()
    assert (f"MATRIX DONE pass={counts['PASS']} fail={counts['FAIL']} "
            f"info={counts['INFO']}") in log
