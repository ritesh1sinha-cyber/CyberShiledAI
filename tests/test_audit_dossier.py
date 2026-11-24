import json
import re
from pathlib import Path

import pytest

from app.eval_dashboard import CONSOLIDATED_JSON, judge_measured, run_failed
from scripts.build_audit_dossier import MD, HTML, REPORT_MD, build_markdown

ROOT = Path(__file__).resolve().parent.parent

# Figures the hand-written dossier published and no artifact ever contained. If any of
# them comes back, someone has typed a number into a generated file again.
UNSOURCEABLE = ["0.9390", "0.9014", "0.7488", "R1:0.220"]

CONFIGURATIONS = {
    1: "zero_shot",
    2: "few_shot",
    3: "chain_of_thought",
    4: "single_agent",
    5: "multi_agent",
}


def _rows() -> list[dict]:
    return json.loads(CONSOLIDATED_JSON.read_text(encoding="utf-8"))


def _table(text: str) -> dict[tuple[str, int], list[str]]:
    """(eval id, configuration number) -> the cells of that dossier row."""
    found: dict[tuple[str, int], list[str]] = {}
    current = None
    for line in text.splitlines():
        heading = re.match(r"## \[(CS-B10-\d\d)\]", line)
        if heading:
            current = heading.group(1)
            continue
        row = re.match(r"\| ([1-5])\. ", line)
        if row and current:
            found[(current, int(row.group(1)))] = [
                cell.strip() for cell in line.strip().strip("|").split("|")
            ]
    return found


def test_the_dossier_is_exactly_what_the_artifact_renders():
    rendered, questions = build_markdown()
    assert questions == 10
    assert rendered == MD.read_text(encoding="utf-8")


def test_every_metric_cell_in_the_dossier_equals_the_value_the_artifact_stored():
    """The guard the hand-written dossier would have failed: 194 of its 200 cells disagreed."""
    cells = _table(MD.read_text(encoding="utf-8"))
    assert len(cells) == 50
    checked = 0
    for row in _rows():
        for number, key in CONFIGURATIONS.items():
            entry = row["iterations"][key]
            columns = cells[(row["eval_id"], number)]
            if run_failed(entry):
                assert "no report was produced" in columns[1], columns
                continue
            rouge = re.findall(r"([0-9.]+)", columns[1])
            assert len(rouge) == 3, columns[1]
            for value, field in zip(rouge, ("rouge1_f", "rouge2_f", "rougeL_f")):
                assert float(value) == pytest.approx(entry["rouge"][field], abs=5e-5)
                checked += 1
            cosine = float(re.findall(r"([0-9.]+)", columns[2])[0])
            assert cosine == pytest.approx(entry["semantic_cosine"], abs=5e-5)
            checked += 1
    assert checked == 184  # 46 rows that answered, three ROUGE values and a cosine each


def test_the_runs_that_produced_no_report_are_not_given_scores():
    text = MD.read_text(encoding="utf-8")
    assert text.count("no report was produced, so nothing is scored here") == 4
    for placeholder in ("0.0500 / 0.0100 / 0.0300", "0.5500"):
        assert placeholder not in text


def test_the_judge_column_is_filled_only_where_a_model_actually_judged():
    cells = _table(MD.read_text(encoding="utf-8"))
    for row in _rows():
        for number, key in CONFIGURATIONS.items():
            entry = row["iterations"][key]
            verdict = cells[(row["eval_id"], number)][4]
            if judge_measured(entry):
                assert "overall" in verdict, (row["eval_id"], key, verdict)
            else:
                assert verdict == "not judged", (row["eval_id"], key, verdict)


def test_the_multi_agent_column_is_the_run_scores_json_records():
    reference = {
        record["eval_id"]: record
        for record in json.loads(
            (ROOT / "data" / "evaluation" / "batch10" / "scores.json").read_text(encoding="utf-8")
        )["rows"]
    }
    for row in _rows():
        stored = row["iterations"]["multi_agent"]
        assert stored["rouge"]["rouge1_f"] == pytest.approx(reference[row["eval_id"]]["rouge1_f"])
        assert stored["semantic_cosine"] == pytest.approx(reference[row["eval_id"]]["semantic_cosine"])


def test_the_unsourceable_hand_written_figures_stay_out():
    documents = {"markdown": MD.read_text(encoding="utf-8"), "html": HTML.read_text(encoding="utf-8")}
    for name, text in documents.items():
        for figure in UNSOURCEABLE:
            assert figure not in text, f"{name} still publishes {figure}"


def test_every_report_link_lands_on_a_dossier_heading():
    report = REPORT_MD.read_text(encoding="utf-8")
    html = HTML.read_text(encoding="utf-8")
    targets = set(
        re.findall(r"CyberShield_AI_Per_CVE_Audit_Dossier\.html#([A-Za-z0-9-]+)", report)
    )
    assert len(targets) == 10, "Section 9.4 is supposed to link all ten CVEs"
    for anchor in targets:
        assert f'id="{anchor}"' in html, f"the dossier has no heading anchored {anchor}"


def test_the_gold_reference_and_each_stored_answer_are_printed():
    text = MD.read_text(encoding="utf-8")
    for row in _rows():
        assert row["expected_output"].splitlines()[0].strip() in text
        for entry in row["iterations"].values():
            answer = str(entry.get("actual_response") or "").strip()
            if len(answer) > 40:
                assert answer[:60] in text


def test_the_dossier_states_the_provenance_it_claims():
    text = MD.read_text(encoding="utf-8")
    intro = text[: text.index("## [CS-B10-01]")]
    assert "scripts/build_audit_dossier.py" in intro
    assert "generated_at 2026-11-21" in intro
    assert "not judged" in intro
    assert "0 quote any text stored here" in intro
