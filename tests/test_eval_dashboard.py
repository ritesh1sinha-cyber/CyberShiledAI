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

RETRIEVAL = {
    "generated_at": "2026-11-23T00:00:00+00:00",
    "tool": "scripts/measure_retrieval_metrics.py",
    "provenance": {
        "scores_artifact": "data/evaluation/batch10/scores.json",
        "trace_dir": "data/traces/batch10",
        "dataset_sha256": "22faa6",
        "model": "Qwen/Qwen3-8B",
        "embedding_model": "bge-small-en-v1.5",
        "relevance_rule": "The frozen grading names the supporting chunk.",
        "reproduce": ".venv/Scripts/python -m scripts.measure_retrieval_metrics",
    },
    "claim_support": {
        "overall": {"gold_claims": 2},
        "note": "support@k says nothing about whether the answer used it.",
        "per_cve": [
            {
                "cve_id": "CVE-2021-23017",
                "gold_claims": 2,
                "passage_grounded": 1,
                "structured_record_grounded": 1,
                "deepest_rank_seen": 6,
                "median_rank": 6.0,
                "mrr": 0.1667,
                "support_at_1": 0.0,
                "support_at_3": 0.0,
                "support_at_5": 0.0,
                "support_at_8": 1.0,
            }
        ],
        "rows": [
            {
                "eval_id": "CS-B10-01",
                "cve_id": "CVE-2021-23017",
                "claim_id": "CS-B10-01-C01",
                "family": "SEVERITY",
                "grounding": "retrieved_passage",
                "supporting_chunk_id": "NVDREF-187f#000",
                "production_rank": 6,
                "claim_result": "Pass",
                "result_basis": "deterministic field check",
            }
        ],
    },
    "engine_ablation": {
        "overall": {
            "bm25": {
                "recall_at_k_mean": 0.95,
                "precision_at_k_mean": 0.3,
                "mrr": 1.0,
                "first_hit_none": 0,
                "median_latency_ms": 172.43,
                "min_latency_ms": 111.77,
                "max_latency_ms": 221.84,
            },
            "dense": {"recall_at_k_mean": 0.8133, "median_latency_ms": 320.92},
        },
        "per_cve": [],
        "provenance": {
            "index_dir": "data/index",
            "corpus_chunks": 10457,
            "reference_chunks_tagged_to_benchmark_cves": 312,
            "gold_passages_in_reference_store": 23,
            "gold_passages_in_generic_corpus": 3,
            "repeats_per_query": 5,
            "note": "The only variable is the ranking engine.",
        },
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
                "summary": {
                    "model": "Qwen/Qwen3-8B",
                    "claims": 2,
                    "claim_judge": {
                        "scored": 1,
                        "of": 2,
                        "verdict_totals": {"conveys": 1, "partial": 1},
                    },
                },
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
    (tmp_path / "retrieval_metrics.json").write_text(json.dumps(RETRIEVAL), encoding="utf-8")
    monkeypatch.setattr(ui, "RETRIEVAL_METRICS_JSON", tmp_path / "retrieval_metrics.json")
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


def test_claim_judge_coverage_names_an_unjudged_run(batch10, monkeypatch):
    assert ui.claim_judge_coverage() == (
        "1 of 2 gold claims carry a judge verdict in this run (1 conveys, 1 partial)"
    )
    monkeypatch.setattr(ui, "batch10_scores", lambda: {"summary": {}})
    assert ui.claim_judge_coverage() == NOT


def test_judge_lines_state_their_own_units(batch10):
    line = ui.judge_line(ui.batch10_claims()[0]["answer_judge"])
    assert line.startswith("factual 2/5, completeness 3/5, groundedness 3/5, overall 2/5")
    assert "strict pass no" in line and "issues: missing CWE" in line
    assert ui.judge_line({}) == "not scored"


def test_batch10_options_are_one_per_investigation(batch10):
    assert ui.options() == [("CS-B10-01", "CS-B10-01 - CVE-2021-23017")]


# ------------------------------------------------- retrieval benchmark ----


def test_the_engine_table_keeps_every_engine_and_marks_unmeasured_cells(batch10):
    rows = ui.retrieval_ablation_table()
    assert [row["Ranking engine tested"] for row in rows] == list(ui.ENGINE_LABELS.values())
    bm25, dense, hybrid = rows
    assert bm25["Gold passages found (recall@8)"] == "0.9500"
    assert bm25["Fastest and slowest repeat (ms)"] == "111.77 / 221.84"
    assert dense["Of the eight passages handed over, how many were gold (precision@8)"] == NOT
    assert all(value == NOT for key, value in hybrid.items() if key != "Ranking engine tested")


def test_the_support_tables_are_the_recorded_rows_not_a_recomputation(batch10):
    support = ui.retrieval_support_table()
    assert support[0]["Gold claims"] == "2"
    assert support[0]["Support@1"] == "0.0000"
    assert support[0]["Support@8"] == "1.0000"
    assert support[0]["Deepest rank any gold passage reached"] == "6"
    claim = ui.retrieval_claim_table()[0]
    assert claim["Supporting chunk"] == "NVDREF-187f#000"
    assert claim["Rank in the evidence package"] == "6"
    assert claim["What the claim rests on"] == "retrieved_passage"


def test_the_benchmark_names_the_command_that_produced_it(batch10):
    recorded = dict(ui.retrieval_provenance())
    assert recorded["How to reproduce"] == RETRIEVAL["provenance"]["reproduce"]
    assert recorded["Written by"] == "scripts/measure_retrieval_metrics.py"
    assert (
        recorded["Gold passages that live in the per-CVE reference store / the generic corpus"]
        == "23 / 3"
    )


def test_an_absent_benchmark_file_returns_nothing_rather_than_zeroes(tmp_path, monkeypatch):
    monkeypatch.setattr(ui, "RETRIEVAL_METRICS_JSON", tmp_path / "absent.json")
    assert ui.retrieval_metrics() == {}
    assert ui.retrieval_support_table() == []
    assert ui.retrieval_claim_table() == []
    assert ui.retrieval_provenance()[0][1] == NOT


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
    # Which verdicts exist at all is a property of the run, so it is read back from
    # the scores file rather than hardcoded; what must hold is that the authority
    # column of the rendered table carries exactly those verdicts and nothing else.
    assert {row["Deterministic claim result (authority)"] for row in ui.llm_table()} == set(
        tally
    )


def test_the_measured_benchmark_describes_the_run_the_dashboards_show():
    if ui.missing_artifacts():
        pytest.skip("the measured retrieval benchmark is not in the working tree")
    payload = ui.retrieval_metrics()
    scores = ui.BATCH10_SCORES_JSON.relative_to(ui.ROOT).as_posix()
    traces = ui.BATCH10_TRACE_DIR.relative_to(ui.ROOT).as_posix()
    provenance = payload["provenance"]
    assert provenance["scores_artifact"].replace("\\", "/") == scores
    assert provenance["trace_dir"].replace("\\", "/") == traces
    claims = ui.batch10_claims()
    assert len(claims) == len(ui.retrieval_claim_table()) == 110
    assert len(ui.retrieval_support_table()) == len(ui.options()) == 10
    assert payload["claim_support"]["overall"]["gold_claims"] == 110
    # A claim the benchmark calls passage-grounded must carry the same chunk id and
    # rank the frozen scoring recorded for it, so the two cannot drift apart quietly.
    graded = {claim["claim_id"]: claim for claim in claims}
    for row in ui.retrieval_claim_table():
        claim = graded[row["Claim ID"]]
        assert (claim["retrieval_method"] == "retrieved_passage") is (
            row["What the claim rests on"] == "retrieved_passage"
        )
        if row["What the claim rests on"] == "retrieved_passage":
            assert claim["source_chunk_id"] == row["Supporting chunk"]
            assert claim["retriever_rank"] == int(row["Rank in the evidence package"])
        assert claim["claim_result"] == row["Deterministic claim result"]


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
                "Three ways of searching, same questions, same material",
                "Where the evidence for each gold claim landed, one row per CVE",
                "How these numbers were produced",
                "What this benchmark does not show",
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


# ---------------------------------------------------- iteration scorecard ----


def synthetic_iterations(rows: list[dict]) -> dict:
    """One row per iteration, with the keys the scorecard reads defaulted."""
    iterations = {}
    for index, key in enumerate(("zero_shot", "few_shot", "chain_of_thought", "single_agent", "multi_agent")):
        entry = rows[index]
        entry.setdefault("rouge", {"rouge1_f": 0.1, "rouge2_f": 0.01, "rougeL_f": 0.05})
        entry.setdefault("semantic_cosine", 0.5)
        entry.setdefault("latency_s", 5.0)
        entry.setdefault("fields", {})
        entry.setdefault("judge", None)
        entry.setdefault("actual_response", "STATUS: completed\nCVE: CVE-2021-23017")
        iterations[key] = entry
    return {"eval_id": "CS-B10-01", "iterations": iterations}


def write_iterations(tmp_path, rows) -> Path:
    path = tmp_path / "consolidated.json"
    path.write_text(json.dumps(rows), encoding="utf-8")
    return path


def test_a_failed_run_is_counted_as_a_failure_not_a_low_score(tmp_path, monkeypatch):
    rows = [
        synthetic_iterations(
            [
                {},
                {},
                {},
                {
                    "actual_response": "Validation Failure: Draft or review failed final validation.",
                    "rouge": {"rouge1_f": 0.05, "rouge2_f": 0.01, "rougeL_f": 0.03},
                    "semantic_cosine": 0.55,
                },
                {},
            ]
        )
    ]
    monkeypatch.setattr(ui, "CONSOLIDATED_JSON", write_iterations(tmp_path, rows))
    single = ui.iteration_scorecard()[3]
    assert single["runs_scored"] == 0
    assert single["runs_failed"] == 1
    # The placeholder 0.05 is not averaged in, so there is no mean to report at all.
    assert single["rouge1_f"] is None
    assert single["semantic_cosine"] is None


def test_the_scorecard_reports_a_judge_only_where_a_model_judged(tmp_path, monkeypatch):
    judged = {"overall": 4, "pass": True, "judge_attempt": "full"}
    proxy = {"factual_correctness": 4, "completeness": 4, "overall": 4, "pass": True}
    rows = [synthetic_iterations([{"judge": proxy}, {}, {}, {}, {"judge": judged}])]
    monkeypatch.setattr(ui, "CONSOLIDATED_JSON", write_iterations(tmp_path, rows))
    table = ui.iteration_scorecard()
    assert table[0]["judge_pass"] == NOT
    assert table[0]["judge_overall"] is None
    assert table[4]["judge_pass"] == "1/1"
    assert table[4]["judge_overall"] == 4.0


def test_the_stored_single_agent_mean_covers_the_six_runs_that_answered():
    single = ui.iteration_scorecard()[3]
    assert (single["runs_scored"], single["runs_failed"]) == (6, 4)
    # Averaging all ten rows, as the old UI did, mixes in four placeholder scores and
    # reports 0.3399 / 0.7570 for a system that answered six times.
    assert single["rouge1_f"] == pytest.approx(0.5332)
    assert single["semantic_cosine"] == pytest.approx(0.8951)


def test_only_the_multi_agent_row_was_judged_in_the_stored_artifact():
    table = ui.iteration_scorecard()
    assert [row["judge_pass"] for row in table[:4]] == [NOT] * 4
    assert table[4]["judge_pass"] == "8/10"
    assert table[4]["judge_overall"] == pytest.approx(4.2)


def test_the_takeaway_claims_no_pass_rate_the_rows_do_not_show():
    sentence = ui.scorecard_takeaway(ui.iteration_scorecard())
    assert "100%" not in sentence
    assert "eliminat" not in sentence.lower()
    assert "8/10" in sentence
    assert "4 of 10 single-agent runs failed final validation" in sentence


def test_an_absent_scorecard_file_returns_nothing_rather_than_zeroes(tmp_path, monkeypatch):
    monkeypatch.setattr(ui, "CONSOLIDATED_JSON", tmp_path / "absent.json")
    assert ui.iteration_scorecard() == []
    assert ui.scorecard_takeaway([]) == NOT
