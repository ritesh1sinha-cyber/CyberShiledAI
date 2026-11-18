"""Tests for the evaluation dashboards: the pages show what the frozen artifacts
record, and everything they did not record says so out loud."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest
from openpyxl import Workbook

from app import eval_dashboard as ui

NOT = ui.NOT_CAPTURED


# ------------------------------------------------------------- fixtures ----


def write_workbook(path: Path, sheet: str, header_row: int, rows: list[dict[int, object]], columns: int) -> None:
    workbook = Workbook()
    tab = workbook.active
    tab.title = sheet
    for column in range(1, columns + 1):
        tab.cell(row=header_row, column=column).value = f"header {column}"
    for offset, values in enumerate(rows, start=header_row + 1):
        for column, value in values.items():
            tab.cell(row=offset, column=column).value = value
    path.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(path)
    workbook.close()


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_trace(directory: Path, name: str, payload: dict) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.json").write_text(json.dumps(payload), encoding="utf-8")


B10_CLAIM = {
    "eval_id": "CS-B10-01",
    "cve_id": "CVE-2021-23017",
    "claim_id": "CS-B10-01-C01",
    "family": "SEVERITY",
    "gold_claim_text": "CVSS 3.1 score is 7.5.",
    "generated_claim": "STATUS: completed\nSEVERITY: cvss_score 7.5",
    "chunk_text": "nginx advisory text",
    "source_document_id": "NVDREF-187f",
    "source_chunk_id": "NVDREF-187f#000",
    "retriever_rank": 5,
    "retrieval_score": 3.571077,
    "retrieval_method": "retrieved_passage",
    "evidence_supports_claim": "Partial",
    "support_ratio": 0.4375,
    "gold_evidence_recall": 0.5,
    "claim_coverage": 0.25,
    "coverage_grade": "N",
    "coverage_missing": ["forged"],
    "claim_result": "Pass",
    "result_basis": "deterministic field check",
    "claim_rouge1_f": 0.155251,
    "claim_rouge2_f": 0.036866,
    "claim_rougeL_f": 0.091324,
    "claim_cosine": 0.47433,
    "claim_judge": {
        "agreement": 3,
        "verdict": "partial",
        "element_share": 0.6,
        "element_count": 5,
        "elements_stated": 2,
        "elements_conceded": 1,
        "elements_missing": 1,
        "elements_unquoted": 1,
        "elements_contradicted": 0,
        "elements": [
            {"element": "7.5", "status": "stated", "quote": "cvss_score 7.5"},
            {"element": "vector", "status": "unquoted", "quote": "not in the answer"},
        ],
    },
    "required_elements": ["7.5", "vector"],
    "conflict_notes": "",
}

B10_CLAIM_TWO = {
    **B10_CLAIM,
    "claim_id": "CS-B10-01-C02",
    "family": "REMEDIATION",
    "gold_claim_text": "Upgrade to the fixed version.",
    "claim_result": "Fail",
    "result_basis": "lexical anchor proxy",
    "claim_cosine": 0.11,
}

B10_ROW = {
    "eval_id": "CS-B10-01",
    "cve_id": "CVE-2021-23017",
    "trace_id": "CS-20261118020023189185",
    "rouge1_f": 0.369515,
    "rouge2_f": 0.148492,
    "rougeL_f": 0.244804,
    "semantic_cosine": 0.673146,
    "relevance_cosine": 0.498032,
    "fields": {"cve_id": "match", "cvss_score": "match", "kev_status": "not-in-reference"},
    "judge": {
        "factual_correctness": 2,
        "completeness": 3,
        "groundedness": 3,
        "overall": 2,
        "pass": False,
        "issues": ["missing CWE"],
    },
    "answer": {
        "eval_id": "CS-B10-01",
        "trace_id": "CS-20261118020023189185",
        "report_status": "completed",
        "claims": 11,
        "claims_pass": 3,
        "claims_partial": 2,
        "claims_fail": 5,
        "claims_abstain": 1,
        "retrieved_contexts": 16,
        "evidence_records": 24,
        "citations": 24,
        "top_k": 8,
        "latency_ms": 21032,
        "model_calls": 4,
        "prompt_tokens": 12395,
        "completion_tokens": 571,
        "gold_claim_coverage": 0.3636,
        "gold_evidence_recall": 0.7727,
    },
}


@pytest.fixture
def batch10(tmp_path, monkeypatch):
    write_workbook(
        tmp_path / "batch10.xlsx",
        ui.BATCH10_SHEET,
        4,
        [
            {
                3: "Investigate CVE-2021-23017",
                4: "SEVERITY: CVSS 3.1 score is 7.5.",
                6: "PENDING HUMAN DOMAIN REVIEW",
                8: "CS-B10-01-C01",
                11: "NVD record",
                12: "https://nvd.nist.gov/vuln/detail/CVE-2021-23017",
                18: "NOT YET VERIFIED - candidate URL only",
                77: "Claim-level result comes from the field check.",
            },
            {
                3: "Investigate CVE-2021-23017",
                4: "SEVERITY: CVSS 3.1 score is 7.5.",
                8: "CS-B10-01-C02",
                11: "Vendor advisory",
                12: "https://nginx.org/en/security_advisories.html",
                18: "NOT YET VERIFIED - candidate URL only",
                77: "Claim-level result comes from the lexical anchor rule.",
            },
        ],
        ui.BATCH10_COLUMNS,
    )
    (tmp_path / "scores.json").write_text(
        json.dumps(
            {
                "summary": {"model": "Qwen/Qwen3-8B", "claims": 2},
                "rows": [B10_ROW],
                "claims": [B10_CLAIM, B10_CLAIM_TWO],
            }
        ),
        encoding="utf-8",
    )
    write_trace(
        tmp_path / "traces",
        "CS-B10-01",
        {
            "query": "Investigate CVE-2021-23017",
            "model": "Qwen/Qwen3-8B",
            "elapsed_ms": "21032",
            "service_trace": {
                "retrieval_meta": {"queries": ["CVE-2021-23017 details"], "review": {"sufficient": True}},
                "contexts": [
                    {"evidence_id": "EV-0009", "chunk_id": "NVDREF-9#002", "title": "Fedora update", "score": 1.5, "text": "Passage nine."}
                ],
            },
            "response": {
                "report": {
                    "status": "completed",
                    "summary": "High-severity memory overwrite",
                    "summary_evidence_ids": ["EV-0002"],
                    "cve": {
                        "cve_id": "CVE-2021-23017",
                        "description": "A security issue in nginx resolver.",
                        "cvss_version": "3.1",
                        "cvss_score": 7.5,
                        "severity": "HIGH",
                        "cvss_vector": "CVSS:3.1/AV:N",
                        "published": "2021-05-25",
                    },
                    "affected_products": ["nginx 1.20.1"],
                    "kev": {"status": "not listed", "date_added": None},
                    "attack_mapping": [
                        {"technique_id": "T1499", "name": "Endpoint DoS", "basis": "source-reference", "confidence": "high", "evidence_id": "EV-0004"}
                    ],
                    "remediation": [{"text": "Upgrade to 1.20.1.", "evidence_ids": ["EV-0001"]}],
                    "risk": {"tier": "high", "rationale": "reachable service"},
                    "limitations": ["The KEV snapshot has a fixed date."],
                    "citations": [{"evidence_id": "EV-0001"}, {"evidence_id": "EV-0002"}],
                }
            },
        },
    )
    monkeypatch.setattr(ui, "BATCH10_WORKBOOK", tmp_path / "batch10.xlsx")
    monkeypatch.setattr(ui, "BATCH10_SCORES_JSON", tmp_path / "scores.json")
    monkeypatch.setattr(ui, "BATCH10_TRACE_DIR", tmp_path / "traces")
    return tmp_path


# ------------------------------------------------------------- formatting ----


def test_blank_cell_reads_as_not_captured_instead_of_looking_like_zero():
    assert ui.text(None) == NOT
    assert ui.text("   ") == NOT
    assert ui.number(None) == NOT
    assert ui.number(0) == "0.0000"


def test_a_stored_non_numeric_metric_is_passed_through_not_invented():
    assert ui.number("n/a - prose claim") == "n/a - prose claim"
    assert ui.number(0.4375) == "0.4375"
    assert ui.number(5, 0) == "5"


def test_excerpt_flattens_a_multiline_cell_for_a_table():
    assert ui.excerpt("a\nb\nc") == "a / b / c"
    assert ui.excerpt("abcdef", limit=4) == "abcd …"
    assert ui.excerpt("abcdef") == "abcdef"


def test_verdict_from_fields_follows_the_deterministic_rule():
    assert ui.verdict_from_fields({"cve_id": "match", "kev_status": "not-in-reference"}) == "PASS"
    assert ui.verdict_from_fields({"cve_id": "match", "severity": "absent"}) == "PARTIAL"
    assert ui.verdict_from_fields({"cve_id": "mismatch", "severity": "absent"}) == "FAIL"
    assert ui.verdict_from_fields({"kev_status": "not-in-reference"}) == NOT


def test_yes_no_spells_out_a_stored_boolean():
    assert ui.yes_no("True") == "yes"
    assert ui.yes_no(False) == "no"
    assert ui.yes_no(None) == NOT


# ------------------------------------------------------------- Batch 10 ----


def test_batch10_claim_rows_carry_the_workbook_gold_text(batch10):
    claims = ui.batch10_claims()
    assert [claim["claim_id"] for claim in claims] == ["CS-B10-01-C01", "CS-B10-01-C02"]
    assert claims[0]["question"] == "Investigate CVE-2021-23017"
    assert claims[1]["source_labels"] == "Vendor advisory"
    assert claims[0]["live_caveat"] == "Claim-level result comes from the field check."


def test_a_claim_id_that_is_not_in_the_workbook_stays_blank(batch10):
    payload = json.loads((batch10 / "scores.json").read_text(encoding="utf-8"))
    payload["claims"][1]["claim_id"] = "CS-B10-01-C99"
    (batch10 / "scores.json").write_text(json.dumps(payload), encoding="utf-8")
    row = ui.llm_table()[1]
    assert row["Gold claim (excerpt)"] == "Upgrade to the fixed version."
    assert ui.batch10_claims()[1]["source_urls"] is None


def test_answer_level_numbers_repeat_across_claim_rows_while_claim_numbers_differ(batch10):
    rows = ui.llm_table()
    assert rows[0]["Answer-level ROUGE-L F1"] == rows[1]["Answer-level ROUGE-L F1"] == "0.2448"
    assert rows[0]["Per-claim ROUGE-L F1"] == "0.0913"
    assert rows[1]["Per-claim semantic cosine"] == "0.1100"
    assert rows[0]["Per-claim judge verdict"] == "partial"
    assert rows[0]["Deterministic claim result (authority)"] == "Pass"
    assert rows[1]["Deterministic claim result (authority)"] == "Fail"
    assert rows[0]["Rule behind that result"] == "deterministic field check"


def test_batch10_answer_verdict_is_derived_from_the_stored_field_states(batch10):
    row = ui.llm_table()[0]
    assert row["Answer-level deterministic verdict (authority)"] == "PASS"
    payload = json.loads((batch10 / "scores.json").read_text(encoding="utf-8"))
    payload["rows"][0]["fields"]["severity"] = "absent"
    (batch10 / "scores.json").write_text(json.dumps(payload), encoding="utf-8")
    assert ui.llm_table()[0]["Answer-level deterministic verdict (authority)"] == "PARTIAL"


def test_batch10_rag_detail_shows_the_verification_gap_the_reviewer_recorded(batch10):
    detail = ui.rag_detail("CS-B10-01")
    claims = next(section for section in detail["sections"] if section["kind"] == "table")["rows"]
    assert claims[0]["Exact source locator recorded in Excel"] == NOT
    assert claims[0]["Source verification recorded in Excel"] == (
        "NOT YET VERIFIED - candidate URL only"
    )
    assert claims[0]["Anchors not found in the answer"] == "forged"
    caveats = next(
        section for section in detail["sections"] if section["heading"] == "What these rows do not prove"
    )
    assert [row["Caveat written by the run"] for row in caveats["rows"]] == [
        "Claim-level result comes from the field check.",
        "Claim-level result comes from the lexical anchor rule.",
    ]


def test_batch10_answer_text_is_read_from_the_trace_not_the_truncated_copy(batch10):
    detail = ui.llm_detail("CS-B10-01")
    answer = next(section for section in detail["sections"] if section["heading"] == "Agent response")
    assert answer["note"] == ui.ANSWER_FROM_TRACE
    text = answer["text"]
    assert "STATUS: completed" in text
    assert "SEVERITY: cvss_version 3.1 | cvss_score 7.5 | severity HIGH" in text
    assert "ATT&CK: T1499 Endpoint DoS [basis source-reference" in text
    assert "REMEDIATION: Upgrade to 1.20.1. [evidence EV-0001]" in text
    assert "LIMITATION: The KEV snapshot has a fixed date." in text
    assert "CITATIONS: 2" in text


def test_an_unreadable_batch10_trace_says_so(batch10):
    (batch10 / "traces" / "CS-B10-01.json").unlink()
    detail = ui.llm_detail("CS-B10-01")
    answer = next(section for section in detail["sections"] if section["heading"] == "Agent response")
    assert answer["text"] == ui.NO_TRACE


def test_claim_elements_expose_the_quote_the_judge_found(batch10):
    found = ui.claim_elements("CS-B10-01-C01")
    assert found["required"] == ["7.5", "vector"]
    assert found["elements"] == [
        {"Fact element": "7.5", "Status": "stated", "Quote found in the answer": "cvss_score 7.5"},
        {
            "Fact element": "vector",
            "Status": "unquoted",
            "Quote found in the answer": "not in the answer",
        },
    ]
    assert "1 unquotable" in ui.claim_judge_line(found["claim"]["claim_judge"])
    with pytest.raises(KeyError):
        ui.claim_elements("CS-B10-01-C77")


def test_judge_lines_state_their_own_units(batch10):
    line = ui.judge_line(ui.batch10_claims()[0]["answer_judge"])
    assert line.startswith("factual 2/5, completeness 3/5, groundedness 3/5, overall 2/5")
    assert "strict pass no" in line and "issues: missing CWE" in line
    assert ui.judge_line({}) == "not scored"


def test_batch10_options_are_one_per_investigation(batch10):
    assert ui.options() == [("CS-B10-01", "CS-B10-01 - CVE-2021-23017")]


# --------------------------------------------------------------- exports ----


def test_csv_export_keeps_every_column_and_row(batch10):
    rows = ui.rag_table()
    parsed = list(csv.DictReader(ui.table_csv(rows).splitlines()))
    assert len(parsed) == len(rows)
    assert list(parsed[0]) == list(rows[0])
    assert parsed[0]["Eval ID"] == "CS-B10-01"
    assert parsed[0]["Claim ID"] == "CS-B10-01-C01"
    assert ui.table_csv([]) == ""


def test_markdown_export_survives_a_pipe_and_a_newline():
    markdown = ui.table_markdown([{"Claim": "a|b", "Expected": "line1\nline2"}])
    assert "| Claim | Expected |" in markdown
    assert "a\\|b" in markdown
    assert "line1<br>line2" in markdown
    assert ui.table_markdown([]) == "_no rows to export_"


def test_detail_markdown_names_every_section_and_blank(batch10):
    detail = ui.llm_detail("CS-B10-01")
    markdown = ui.detail_markdown(detail)
    for section in detail["sections"]:
        assert section["heading"] in markdown
    assert NOT in markdown
    assert markdown.startswith("### CVE-2021-23017 (CS-B10-01)")


# ------------------------------------------------------------ real data ----


def test_pages_do_not_read_the_workbooks_themselves():
    for page in sorted((ui.ROOT / "pages").glob("*.py")):
        source = page.read_text(encoding="utf-8")
        assert "load_workbook" not in source, page
        assert "eval_dashboard" in source, page


def test_the_real_batch10_dashboards_hold_the_frozen_hundred_and_ten_claims():
    if ui.missing_artifacts():
        pytest.skip("the frozen Batch 10 artifacts are not in the working tree")
    claims = ui.batch10_claims()
    assert len(claims) == 110
    assert len(ui.options()) == 10
    summary = ui.batch10_summary()["claim_result_totals"]
    tally: dict[str, int] = {}
    for claim in claims:
        tally[claim["claim_result"]] = tally.get(claim["claim_result"], 0) + 1
    assert tally == summary
    detail = ui.llm_detail("CS-B10-01")
    per_claim = next(
        section for section in detail["sections"] if "per gold claim" in section["heading"]
    )
    assert len(per_claim["rows"]) == 11
    assert {row["Deterministic claim result (authority)"] for row in ui.llm_table()} == {
        "Pass",
        "Partial",
        "Fail",
        "Abstain",
    }


# ----------------------------------------------------- the pages themselves ----
# These runs are the only tests that execute the page files. They exist because a
# widget keyword argument the installed Streamlit does not accept kills every detail
# section at once while all the data-layer tests stay green - the first draft passed
# wrap= to st.code, which is named wrap_lines in 1.67.


def run_page(page: str):
    from streamlit.testing.v1 import AppTest

    return AppTest.from_file(str(ui.ROOT / "pages" / page), default_timeout=120).run()


@pytest.mark.parametrize(
    "page,rows,headings",
    [
        (
            "1_Evaluation_RAG.py",
            110,
            (
                "Expected versus retrieved, one row per gold claim",
                "Every passage this investigation retrieved",
                "What these rows do not prove",
            ),
        ),
        (
            "2_Evaluation_LLM.py",
            110,
            (
                "Gold answer (Excel column D, frozen)",
                "The four measured layers, per gold claim (varies row by row)",
                "What the claim judge found, element by element",
            ),
        ),
    ],
)
def test_a_page_renders_the_frozen_batch10_without_an_error(page, rows, headings):
    if ui.missing_artifacts():
        pytest.skip("the frozen Batch 10 artifacts are not in the working tree")
    app = run_page(page)
    assert not app.exception, [error.value for error in app.exception]
    assert not app.error, [error.value for error in app.error]
    assert len(app.dataframe[0].value) == rows
    shown = " | ".join(head.value for head in app.subheader)
    for heading in headings:
        assert heading in shown
    assert "Copy this investigation for the report" in shown
    assert app.get("download_button"), page
