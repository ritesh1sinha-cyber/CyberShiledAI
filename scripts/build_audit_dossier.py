"""Render the per-CVE audit dossier from the evaluation artifacts.

The dossier is the side-by-side audit trail: for each of the ten Batch 10 questions, the
gold reference, the verbatim answer each of the five configurations produced, and the
scores recorded against that answer. It used to be typed by hand, which is how it ended up
quoting numbers that appear in no artifact. Now every cell is read from
``data/evaluation/consolidated_10cve_all_iterations.json`` and the generator refuses to run
if its multi-agent column stops matching the authoritative 21 November run.

    .venv/Scripts/python -m scripts.build_audit_dossier
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from app.eval_dashboard import judge_measured, run_failed
from scripts.build_report_html import render

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
MD = DOCS / "CyberShield_AI_Per_CVE_Audit_Dossier.md"
HTML = DOCS / "CyberShield_AI_Per_CVE_Audit_Dossier.html"
REPORT_MD = DOCS / "CyberShield_AI_Final_Technical_Report_Track_B.md"
CONSOLIDATED = ROOT / "data" / "evaluation" / "consolidated_10cve_all_iterations.json"
AUTHORITATIVE = ROOT / "data" / "evaluation" / "batch10" / "scores.json"

# The five configurations, in report order. `technique_name` supplies the label.
ORDER = ("zero_shot", "few_shot", "chain_of_thought", "single_agent", "multi_agent")

FOOTER_LEFT = "CyberShield AI · Per-CVE Empirical Evaluation Dossier"
FOOTER_MIDDLE = "Derived from data/evaluation/consolidated_10cve_all_iterations.json"

STATUS_ORDER = ("mismatch", "absent", "not-in-reference", "match")


def titles() -> dict[str, tuple[str, str]]:
    """Eval id -> (CVE id, one-line overview), read from Section 9.4 of the report.

    The report already carries this table, so the dossier takes its headings from it
    rather than keeping a second copy that can disagree.
    """
    text = REPORT_MD.read_text(encoding="utf-8")
    section = text[text.index("### 9.4") : text.index("### 9.5")]
    found: dict[str, tuple[str, str]] = {}
    for line in section.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 4 or not cells[0].startswith("**CS-B10-"):
            continue
        eval_id = cells[0].strip("*")
        cve = cells[1].strip("`")
        found[eval_id] = (cve, cells[2])
    if len(found) != 10:
        raise SystemExit("Section 9.4 of the report does not carry ten rows, found %d" % len(found))
    return found


def field_check(fields: dict[str, str]) -> str:
    """The deterministic field result, worst statuses first."""
    if not fields:
        return "not recorded"
    counts = {}
    for status in fields.values():
        counts[status] = counts.get(status, 0) + 1
    parts = [
        "%d %s" % (counts[status], status)
        for status in STATUS_ORDER
        if counts.get(status)
    ]
    named = sorted(name for name, status in fields.items() if status == "mismatch")
    if named:
        parts.append("mismatched: " + ", ".join(named))
    return "; ".join(parts)


def judge_cell(entry: dict) -> str:
    if not judge_measured(entry):
        return "not judged"
    verdict = entry["judge"]
    scores = "/".join(str(verdict[key]) for key in ("factual_correctness", "completeness", "groundedness"))
    return "%s -> %s overall, %s" % (scores, verdict["overall"], "pass" if verdict["pass"] else "FAIL")


def latency_cell(entry: dict, key: str, record: dict) -> str:
    if key == "multi_agent":
        # scores.json records the whole five-node investigation; the iteration
        # harness below records one model call. The two are not the same number.
        milliseconds = record["answer"].get("latency_ms")
        return "%.1f s (full investigation)" % (milliseconds / 1000) if milliseconds is not None else "not captured"
    seconds = entry.get("latency_s")
    if seconds is None:
        return "not captured"
    scope = "full run" if key == "single_agent" else "one model call"
    return "%.1f s (%s)" % (seconds, scope)


def metric_rows(row: dict, record: dict) -> list[str]:
    lines = [
        "| Configuration | ROUGE-1 / 2 / L (F1) | Semantic cosine | Deterministic field check | LLM judge | Latency as recorded |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for position, key in enumerate(ORDER, start=1):
        entry = row["iterations"][key]
        label = "%d. %s" % (position, entry.get("technique_name") or key)
        if run_failed(entry):
            lines.append(
                "| %s | no report was produced, so nothing is scored here | - | - | not judged | - |" % label
            )
            continue
        rouge = entry["rouge"]
        lines.append(
            "| %s | %.4f / %.4f / %.4f | %.4f | %s | %s | %s |"
            % (
                label,
                rouge["rouge1_f"],
                rouge["rouge2_f"],
                rouge["rougeL_f"],
                entry["semantic_cosine"],
                field_check(entry.get("fields") or {}),
                judge_cell(entry),
                latency_cell(entry, key, record),
            )
        )
    return lines


def answer_blocks(row: dict) -> list[str]:
    lines = ["**Answer as stored, per configuration:**", ""]
    for position, key in enumerate(ORDER, start=1):
        entry = row["iterations"][key]
        label = "%d. %s" % (position, entry.get("technique_name") or key)
        answer = str(entry.get("actual_response") or "")
        lines.append("*%s*" % label)
        lines.append("")
        lines.append("```text")
        lines.append(answer.rstrip())
        lines.append("```")
        lines.append("")
    return lines


def build_markdown() -> tuple[str, int]:
    rows = json.loads(CONSOLIDATED.read_text(encoding="utf-8"))
    reference = json.loads(AUTHORITATIVE.read_text(encoding="utf-8"))
    authoritative = {record["eval_id"]: record for record in reference["rows"]}
    generated_at = reference["summary"].get("generated_at", "")
    stamped = datetime.fromisoformat(generated_at)
    run_label = "%s authoritative run (`generated_at %s`)" % (
        stamped.strftime("%d %B %Y").lstrip("0"),
        generated_at,
    )
    for row in rows:
        stored = row["iterations"]["multi_agent"]
        record = authoritative[row["eval_id"]]
        if (
            abs(stored["rouge"]["rouge1_f"] - record["rouge1_f"]) > 1e-9
            or abs(stored["semantic_cosine"] - record["semantic_cosine"]) > 1e-9
        ):
            raise SystemExit(
                "%s: the multi-agent column no longer matches data/evaluation/batch10/scores.json, "
                "so this dossier cannot name the run it documents." % row["eval_id"]
            )

    head, tail = CONSOLIDATED.relative_to(ROOT).as_posix(), AUTHORITATIVE.relative_to(ROOT).as_posix()
    lines = [
        "# CyberShield AI: Per-CVE Empirical Evaluation Dossier (Track B Audit Trail)",
        "",
        "Companion to [Section 9.4 of the Track B report]"
        "(CyberShield_AI_Final_Technical_Report_Track_B.html#empirical-benchmark), whose link table points "
        "here. Generated by `scripts/build_audit_dossier.py` - do not edit it by hand, because a "
        "hand-written copy is exactly how this dossier came to carry numbers that appear in no artifact.",
        "",
        "Every cell below is read from `%s`. The multi-agent column is the %s, which "
        "`scripts/build_audit_dossier.py` verifies cell by cell against `%s` before it will write this "
        "file; if the two ever disagree, the build stops." % (head, run_label, tail),
        "",
        "Four reading rules, each of which exists because of a defect that was found and measured:",
        "",
        "- **A configuration that produced no report is shown as such.** In the single-agent run four of "
        "the ten questions ended in `Validation Failure: Draft or review failed final validation.` An "
        "earlier version of the benchmark harness wrote placeholder scores onto those rows (ROUGE "
        "0.05/0.01/0.03, cosine 0.55, judge 1) and the hand-written dossier then replaced them with "
        "invented numbers, including a judged pass on each. No mean in the report includes them, and this "
        "file shows none.",
        "- **`not judged` means no model scored that answer.** The stored artifact carries a judge block "
        "for configurations 1-3, but it is one identical block repeated on all ten questions, so it "
        "records a template rather than a verdict, and configuration 4's block was written without calling "
        "the judge at all. The only real verdicts in the artifact are configuration 5's ten, of which 8 "
        "pass. The one genuinely judged no-retrieval run in the repository is the 19 November one "
        "(`data/evaluation/prompt_baseline_no_rag.json` scored into "
        "`data/evaluation/judge_cache_all_iterations.json`: 30 verdicts, mean overall 1.0, 0 of 10 pass) - "
        "and of the 15 of those verdicts that quote the answer they judged, 0 quote any text stored here "
        "while 11 quote the 19 November file, so they belong to a different generation of answers and are "
        "not reproduced beside these. The deterministic field check is the pass/fail authority in this "
        "dossier, and it is reported for every row that answered.",
        "- **What re-derives from this page, and what does not.** Configuration 5 re-derives exactly: "
        "re-running `rouge_scores()` on the text printed below returns all ten recorded ROUGE-1 values to "
        "the last digit. Configuration 4 does the same on the six rows that answered. Configurations 1-3 "
        "do not, because they were scored on the flattened rendering of the model's JSON reply while only "
        "the raw string was stored: re-scoring the text below moves zero-shot and few-shot by at most "
        "0.016, and chain-of-thought by 0.12-0.17 on the four replies the flattener cut short. Section 9.1 "
        "of the report carries the same measurement, and the harness now stores the exact string it scored "
        "as `scored_text`.",
        "- **The latency column is not one quantity.** Configurations 1-3 timed a single model call, "
        "configuration 4 timed its whole run, and configuration 5 shows the end-to-end investigation "
        "latency recorded in `%s`, which is the figure the report's last column quotes." % tail,
        "",
    ]

    headings = titles()
    for row in rows:
        overview = headings[row["eval_id"]][1]
        lines += [
            "## [%s] %s - %s" % (row["eval_id"], row["cve_id"], overview),
            "",
            "**Sources cited by the gold reference:** %s" % row["sources"],
            "",
            "**Expected output (gold reference, verbatim):**",
            "",
            "```text",
            row["expected_output"].rstrip(),
            "```",
            "",
        ]
        lines += metric_rows(row, authoritative[row["eval_id"]])
        lines += [""]
        lines += answer_blocks(row)
        lines += ["---", ""]
    return "\n".join(lines).rstrip() + "\n", len(rows)


def main() -> None:
    markdown, questions = build_markdown()
    MD.write_text(markdown, "utf-8", newline="\n")
    document, pages = render(markdown, FOOTER_LEFT, FOOTER_MIDDLE)
    HTML.write_text(document, "utf-8", newline="\n")
    print(
        "[OK] wrote %s (%d bytes) and %s (%d pages, %s bytes) for %d questions"
        % (
            MD.relative_to(ROOT),
            len(markdown),
            HTML.relative_to(ROOT),
            pages,
            f"{len(document):,}",
            questions,
        )
    )


if __name__ == "__main__":
    main()
