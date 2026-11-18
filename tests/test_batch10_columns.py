"""Tests for the Batch 10 column writer's cell builders and its safety guard.

The writer owns only the workbook's capture range and the columns appended after
it, so these tests pin two things: how each cell is phrased (an unscored judge
row must say so rather than carry invented text) and that the guard refuses to
overwrite anything the user already filled in or to write left of column V.
"""

import json

import pytest

from scripts.batch10_dataset import COLUMNS
from scripts.write_batch10_columns import (
    APPEND_HEADERS,
    CLAIM_LEVEL,
    LAST_CAPTURE_COLUMN,
    LIVE_APPEND_HEADERS,
    LIVE_FIRST_COLUMN,
    ROOT,
    NEW_FIRST_COLUMN,
    PROXY_NOTE,
    LEXICAL_NOTE,
    answer_level_cells,
    build,
    caveat_cell,
    cell,
    claim_level_cells,
    field_check_cell,
    guard,
    index_snapshot,
    judge_cell,
    live_answer_cell,
    live_build,
    live_caveat_cell,
    live_claim_judge_cell,
    live_claim_verdict_cell,
    live_rouge_cell,
    retrieval_method_cell,
    rouge_cell,
    run_cells,
)

RUN_META = {
    "run_id": "B10-22faa619bae3",
    "model_version": "Qwen/Qwen3-8B via hosted inference API",
    "prompt_version": "judge b10-1.0",
    "index_snapshot": "chunks_sha256=72a0ce2e829fc64f",
    "run_timestamp_utc": "2026-11-17T18:14:04+00:00",
}

ANSWER = {
    "trace_id": "CS-20261117181123870525",
    "report_status": "completed",
    "gold_claim_coverage": 0.3636,
    "context_precision": 0.5,
    "context_recall": 0.9091,
    "faithfulness": 1.0,
    "answer_correctness": 0.3,
    "claims_pass": 3,
    "claims_partial": 2,
    "claims_fail": 5,
    "claims_abstain": 1,
    "revised": False,
    "first_draft_invalid": False,
    "top_k": 8,
    "latency_ms": 18461,
    "prompt_tokens": 12000,
    "completion_tokens": 3472,
    "model_calls": 5,
    "citations": 24,
    "retrieved_contexts": 16,
    "evidence_records": 24,
}

ROW = {
    "eval_id": "CS-B10-01",
    "cve_id": "CVE-2021-23017",
    "rouge1_f": 0.3704,
    "rouge2_f": 0.1488,
    "rougeL_f": 0.2454,
    "semantic_cosine": 0.673512,
    "relevance_cosine": 0.50051,
    "fields": {
        "cve_id": "match",
        "cvss_version": "match",
        "cvss_score": "match",
        "severity": "match",
        "cvss_vector": "match",
        "kev_status": "match",
        "kev_date_added": "not-in-reference",
    },
    "judge": {
        "factual_correctness": 2,
        "completeness": 3,
        "groundedness": 3,
        "overall": 2,
        "pass": False,
        "issues": ["claims a product the evidence does not support"],
    },
    "judge_prompt_version": "b10-1.0",
    "answer": ANSWER,
    "run": RUN_META,
}

CLAIM = {
    "claim_id": "CS-B10-01-C09",
    "eval_id": "CS-B10-01",
    "workbook_row": 13,
    "family": "PROJECT RISK",
    "source_document_id": "NVDREF-eebfda7d36c0537b",
    "source_chunk_id": "NVDREF-eebfda7d36c0537b#027",
    "chunk_locator": "paragraph 3",
    "chunk_text": "Retrieved text.",
    "retriever_rank": 4,
    "retrieval_method": "retrieved_passage",
    "retrieval_score": 0.01639,
    "structured_record_id": "",
    "evidence_supports_claim": "N",
    "conflict_notes": "KEV snapshot label differs",
    "generated_claim": "Project risk is MEDIUM under kev-cvss-v1.",
    "generated_citations": "EV-0002",
    "claim_result": "Fail",
    "result_basis": "deterministic field check",
    "gold_evidence_recall": 0.0,
    "claim_coverage": 0.1,
    "coverage_missing": ["kev-cvss-v1", "snapshot"],
    "support_ratio": 0.2,
    "supporting_citations": [],
    "critical_fact_match": "mismatch: gold HIGH vs kev-cvss-v1 MEDIUM",
    "citation_precision": 0.0,
    "citation_coverage": 0.0,
    "unsupported_claim_rate": "n/a",
    "conflict_preservation": 0.5,
    "abstention_correctness": 1,
    "abstention_note": "",
}


class Sheet:
    """Minimal stand-in: reports a fixed width and whatever cells were pre-filled."""

    def __init__(self, occupied=None, max_row=114):
        self._occupied = dict(occupied or {})
        self.max_row = max_row

    def cell(self, row, column):
        return type("Cell", (), {"value": self._occupied.get((row, column))})()


# --- value formatting --------------------------------------------------------


def test_cell_turns_booleans_into_words_a_reviewer_can_read():
    assert cell(True) == "yes" and cell(False) == "no"


def test_cell_blanks_missing_values_and_rounds_numbers():
    assert cell(None) == "" and cell(0.016391) == 0.0164 and cell(1) == 1


def test_rouge_cell_labels_itself_as_descriptive_not_a_score():
    text = rouge_cell(ROW)
    assert "ROUGE-1 F1 0.3704" in text and "not a score" in text


def test_judge_cell_keeps_the_authority_note_visible():
    text = judge_cell(ROW)
    assert "not the pass/fail authority" in text and "factual_correctness 2/5" in text
    assert "strict pass (all four >=4): no" in text


def test_judge_cell_reports_an_unscored_row_instead_of_inventing_a_grade():
    row = {"judge": None, "judge_error": "ReadTimeout: gateway closed"}
    assert judge_cell(row) == "LLM JUDGE: not scored (ReadTimeout: gateway closed)"


def test_judge_cell_marks_a_skipped_run_as_skipped():
    assert "not run for this row" in judge_cell({"judge": None})


# --- retrieval provenance ----------------------------------------------------


def test_retrieval_method_cell_carries_rank_and_score_for_a_passage():
    assert retrieval_method_cell(CLAIM) == "retrieved_passage rank 4, score 0.0164"


def test_retrieval_method_cell_names_the_record_for_structured_lookups():
    claim = {**CLAIM, "retrieval_method": "structured_record", "structured_record_id": "EV-0004"}
    assert retrieval_method_cell(claim) == "structured_record EV-0004"


def test_retrieval_method_cell_says_so_when_nothing_supported_the_claim():
    assert retrieval_method_cell({**CLAIM, "retrieval_method": "none"}) == (
        "none - no retrieved item matches this claim's anchors"
    )


# --- answer-level verdict text -----------------------------------------------


def test_field_check_cell_passes_when_no_stated_field_disagrees():
    text = field_check_cell(ROW)
    assert text.startswith("PASS - deterministic field check over 6 reference-stated fields")
    assert "not-in-reference" not in text


def test_field_check_cell_lists_the_disagreeing_fields_on_a_fail():
    row = {**ROW, "fields": {**ROW["fields"], "severity": "mismatch"}}
    assert "severity: mismatch" in field_check_cell(row)


def test_answer_level_cells_put_relevancy_on_the_cosine_not_a_model_score():
    cells = answer_level_cells(ROW)
    # The builder passes the raw cosine through; the workbook cell is rounded on
    # the way out, so the rounding is asserted where it actually happens.
    assert cells["answer_relevancy"] == 0.50051
    assert cell(cells["answer_relevancy"]) == 0.5005
    assert cells["gold_claim_coverage"] == 0.3636
    assert cells["run_id"] == "B10-22faa619bae3"
    assert cells["token_usage"] == "prompt 12000 + completion 3472 over 5 model calls"


def test_claim_level_cells_cover_every_claim_column_the_workbook_defines():
    cells = claim_level_cells(CLAIM)
    assert set(cells) == set(CLAIM_LEVEL) | {"retrieval_score"}
    assert cells["claim_result"] == "Fail" and cells["critical_fact_match"].startswith("mismatch:")


# --- caveats -----------------------------------------------------------------


def test_caveat_cell_flags_the_proxy_only_when_the_proxy_decided_the_row():
    note = caveat_cell(CLAIM, ANSWER)
    assert PROXY_NOTE in note and LEXICAL_NOTE not in note
    assert "PENDING HUMAN DOMAIN REVIEW" in note


def test_caveat_cell_explains_a_lexically_graded_prose_claim():
    claim = {**CLAIM, "result_basis": "lexical anchor proxy", "abstention_note": "answer invents a technique id"}
    note = caveat_cell(claim, ANSWER)
    assert LEXICAL_NOTE in note and "answer invents a technique id" in note


def test_caveat_cell_records_an_investigation_that_stopped_early():
    note = caveat_cell(CLAIM, {**ANSWER, "report_status": "partial"})
    assert "stopped at status=partial" in note


def test_index_snapshot_names_both_sides_of_the_hybrid_index():
    snapshot = index_snapshot()
    assert "chunks_sha256=" in snapshot and "reference-first" in snapshot
    # the model named in the cell is the one recorded when the index was built, not a
    # constant in this file, so swapping embedding model cannot leave a stale attribution
    manifest = json.loads((ROOT / "data" / "manifests" / "index.json").read_text("utf-8"))
    assert manifest["model"] in snapshot


# --- layout and safety guards ------------------------------------------------


def test_appended_columns_start_after_the_workbooks_own_capture_range():
    assert NEW_FIRST_COLUMN == LAST_CAPTURE_COLUMN + 1
    assert min(APPEND_HEADERS) == NEW_FIRST_COLUMN
    assert max(APPEND_HEADERS) == LAST_CAPTURE_COLUMN + len(APPEND_HEADERS)


def test_guard_accepts_writes_that_stay_inside_the_owned_range():
    updates = build(Sheet(), [ROW], [CLAIM])
    assert guard(Sheet(), updates) == {
        "occupied_capture_cells": [],
        "replaced_capture_cells": 0,
        "writes_before_V": [],
    }


def test_guard_refuses_to_overwrite_a_cell_the_user_already_filled():
    occupied = {(13, COLUMNS["claim_result"]): "human verdict"}
    updates = build(Sheet(), [ROW], [CLAIM])
    offenders = guard(Sheet(occupied), updates)["occupied_capture_cells"]
    assert len(offenders) == 1 and offenders[0].startswith("AF13")


def test_overwrite_mode_trades_the_refusal_for_a_count_of_cells_it_replaces():
    occupied = {(13, COLUMNS["claim_result"]): "earlier machine write"}
    updates = build(Sheet(), [ROW], [CLAIM])
    report = guard(Sheet(occupied), updates, overwrite=True)
    assert report["occupied_capture_cells"] == [] and report["replaced_capture_cells"] == 1


def test_overwrite_mode_still_refuses_to_write_left_of_the_capture_range():
    updates = [(13, {COLUMNS["cve_id"]: "CVE-2021-23017"})]
    assert guard(Sheet(), updates, overwrite=True)["writes_before_V"] == ["B13"]


def test_guard_ignores_the_appended_columns_it_is_free_to_replace():
    updates = build(Sheet(), [ROW], [CLAIM])
    assert guard(Sheet({(13, NEW_FIRST_COLUMN): "earlier machine write"}), updates)["occupied_capture_cells"] == []


def test_guard_flags_any_write_left_of_the_capture_range():
    updates = [(13, {COLUMNS["cve_id"]: "CVE-2021-23017"})]
    assert guard(Sheet(), updates)["writes_before_V"] == [f"B{13}"]


def test_build_rejects_a_claim_row_beyond_the_sheet():
    with pytest.raises(SystemExit):
        build(Sheet(max_row=10), [ROW], [{**CLAIM, "workbook_row": 11}])


# --- the 18 November live re-run columns --------------------------------------

JUDGED = {
    "agreement": 3,
    "verdict": "partial",
    "element_share": 0.6,
    "element_count": 5,
    "elements_stated": 3,
    "elements_conceded": 0,
    "elements_missing": 1,
    "elements_unquoted": 1,
    "elements_contradicted": 0,
    "elements": [
        {"element": "8.2", "status": "stated", "effective_status": "stated", "quote": "CVSS 8.2"},
        {"element": "fixed in 9.1", "status": "stated", "effective_status": "unquoted", "quote": "not in the answer"},
    ],
}

LIVE_CLAIM = {
    **CLAIM,
    "gold_claim_text": "F5 BIG-IP 8.7.4 through 8.8.2 are affected by CVE-2023-40044.",
    "claim_rouge1_f": 0.11,
    "claim_rouge2_f": 0.02,
    "claim_rougeL_f": 0.09,
    "claim_cosine": 0.359732,
    "claim_judge": JUDGED,
    "coverage_grade": "weak",
}


def live_claim(**overrides):
    return {**LIVE_CLAIM, **overrides}


def test_live_appended_columns_start_after_the_projects_own_appended_range():
    assert LIVE_FIRST_COLUMN == 68
    assert min(LIVE_APPEND_HEADERS) == LIVE_FIRST_COLUMN
    assert max(LIVE_APPEND_HEADERS) == 77
    assert set(LIVE_APPEND_HEADERS).isdisjoint(APPEND_HEADERS)


def test_live_headers_name_the_version_behind_each_measure():
    assert "b10-claim-1.1" in LIVE_APPEND_HEADERS[72]
    assert "b10-1.0" in LIVE_APPEND_HEADERS[73]


def test_live_headers_announce_which_column_repeats():
    assert "repeats across its 11 rows" in LIVE_APPEND_HEADERS[73]
    assert "repeats" not in LIVE_APPEND_HEADERS[70]


def test_live_rouge_cell_marks_itself_per_claim_and_descriptive():
    text = live_rouge_cell(live_claim())
    assert "ROUGE-1 F1 0.1100" in text and "ROUGE-L F1 0.0900" in text
    assert "one gold claim" in text and "descriptive, not a score" in text


def test_live_claim_judge_cell_shows_the_quotes_behind_the_verdict():
    text = live_claim_judge_cell(live_claim())
    assert "b10-claim-1.1" in text
    assert "agreement 3/5 | verdict partial" in text
    assert 'quoted "CVSS 8.2"' in text
    assert "[unquoted]" in text


def test_live_claim_judge_cell_reports_an_unscored_claim_instead_of_inventing_one():
    text = live_claim_judge_cell(live_claim(claim_judge=None, claim_judge_error="ValueError: bad JSON"))
    assert text.startswith("CLAIM JUDGE: not scored")
    assert "bad JSON" in text
    assert "agreement" not in text


def test_live_verdict_cell_keeps_the_rule_that_decided_the_row():
    text = live_claim_verdict_cell(live_claim())
    assert text.startswith("Fail - deterministic field check")
    assert "gold HIGH vs kev-cvss-v1 MEDIUM" in text


def test_live_answer_cell_labels_the_repetition():
    text = live_answer_cell(ROW)
    assert "answer-vs-gold cosine 0.6735" in text
    assert "same on all of its claim rows" in text


def test_live_answer_cell_says_when_the_judge_did_not_run():
    text = live_answer_cell({**ROW, "judge": None, "judge_error": "timeout"})
    assert "not scored (timeout)" in text


def test_live_caveat_cell_calls_an_unchanged_verdict_a_reproduction():
    text = live_caveat_cell(live_claim(), ROW["answer"], {"claim_result": "Fail"})
    assert "independent reproduction, not a fix" in text
    assert "moved" not in text


def test_live_caveat_cell_reports_a_verdict_that_changed_between_runs():
    text = live_caveat_cell(live_claim(claim_result="Pass"), ROW["answer"], {"claim_result": "Fail"})
    assert "moved Fail -> Pass" in text


def test_live_caveat_cell_admits_when_it_has_no_baseline_row():
    text = live_caveat_cell(live_claim(), ROW["answer"], None)
    assert "no 17 Nov claim row to compare with" in text


def test_live_build_writes_only_the_live_range():
    row_index, cells = live_build(Sheet(), [ROW], [live_claim()], {})[0]
    assert row_index == LIVE_CLAIM["workbook_row"]
    assert min(cells) == LIVE_FIRST_COLUMN
    assert max(cells) == max(LIVE_APPEND_HEADERS)


def test_live_build_leaves_the_17_nov_columns_and_the_capture_range_alone():
    written = set(live_build(Sheet(), [ROW], [live_claim()], {})[0][1])
    assert written.isdisjoint(APPEND_HEADERS)
    assert written.isdisjoint(range(1, LAST_CAPTURE_COLUMN + 1))


def test_live_build_keeps_per_claim_columns_distinct_but_answer_columns_shared():
    other = live_claim(
        claim_id="CS-B10-01-C10",
        workbook_row=14,
        gold_claim_text="The vendor fixed this in BIG-IP 10.0.0.",
        claim_rouge1_f=0.9,
        claim_rouge2_f=0.5,
        claim_rougeL_f=0.8,
        claim_cosine=0.77,
        claim_result="Pass",
        evidence_supports_claim="Y",
        support_ratio=1.0,
        claim_coverage=0.9,
        coverage_grade="strong",
        gold_evidence_recall=1.0,
        claim_judge={**JUDGED, "verdict": "conveys", "agreement": 5},
    )
    built = dict(live_build(Sheet(), [ROW], [live_claim(), other], {}))
    first, second = built[LIVE_CLAIM["workbook_row"]], built[other["workbook_row"]]
    for column in (69, 70, 71, 72, 74):
        assert first[column] != second[column], column
    for column in (73, 75, 76):
        assert first[column] == second[column], column


def test_live_build_rejects_a_claim_row_beyond_the_sheet():
    with pytest.raises(SystemExit):
        live_build(Sheet(max_row=10), [ROW], [live_claim()], {})
