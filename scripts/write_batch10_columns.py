"""Write the Batch 10 RAG and agent-eval columns into the consolidated workbook.

Four rules bound what this does.

- Columns A-F are the frozen gold. Their fingerprint is taken before and after,
  and a non-equal pair is a hard failure with a non-zero exit.
- Only the workbook's own pre-created capture range V-BB (22-54) is filled, and
  only where it is still empty; a cell that already holds something is reported
  and left alone. New columns start at BC (55) and are named here.
- ``--appended-only`` writes nothing into V-BB at all, which is what a second
  run needs: the 17 November numbers already occupy that range, so the live
  18 November run is written to its own labelled columns BP-BY (68-77) beside
  them and the two runs stay readable side by side. Re-running the same date
  overwrites that block, which is why ``--overwrite`` is required for it.
- The per-cell authority is the deterministic layer: the answer-level field
  check and the claim-level audit. ROUGE, cosine and the judge are written as
  descriptive columns and say so in their header.

A backup copy is written before anything changes, because the workbook is not
tracked by git.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

from openpyxl import load_workbook
from openpyxl.styles import Alignment
from openpyxl.utils import get_column_letter

from scripts.batch10_dataset import (
    COLUMNS,
    FIRST_DATA_ROW,
    NEW_FIRST_COLUMN,
    SHEET,
    WORKBOOK,
    dataset_fingerprint,
    frozen_fingerprint,
    investigations,
    ledger,
)

ROOT = Path(__file__).resolve().parent.parent
SCORES = ROOT / "data" / "evaluation" / "batch10" / "scores.json"
BACKUPS = ROOT / "data" / "backups"
LAST_CAPTURE_COLUMN = COLUMNS["reviewer_notes"]  # 54, column BB

# Columns this project appends after the workbook's own capture range.
APPEND_HEADERS = {
    55: "Agent eval - deterministic field check (pass/fail authority)",
    56: "Agent eval - ROUGE-1/2/L F1, answer vs frozen gold (descriptive)",
    57: "Agent eval (17 Nov run) - semantic cosine (MiniLM, retired by D32), answer vs frozen gold (descriptive, not comparable with BS-BU)",
    58: "Agent eval (17 Nov run) - answer relevancy cosine (MiniLM, retired by D32), question vs answer (descriptive, not comparable with BS-BU)",
    59: "Agent eval - LLM-as-judge b10-1.0 (secondary, same model family)",
    60: "Claim audit - rule that produced the claim-level result",
    61: "Claim audit - anchor coverage of this claim (lexical share)",
    62: "Claim audit - anchors not found in the answer",
    63: "Claim audit - support over the whole retrieved set (share)",
    64: "Claim audit - citations whose text supports this claim",
    65: "Run - trace id",
    66: "Run - report status and workflow flags",
    67: "Caveat - what this row does not prove",
}

# The 18 November live re-run on the hosted bge-small dense index, written beside
# the 17 November numbers instead of over them. It replaces an earlier 18 November
# run made on the MiniLM vectors that D32 removed; that one is quarantined, so no
# column in this workbook carries it. Every value here is per gold claim
# except the two columns that say they are per investigation.
LIVE_FIRST_COLUMN = 68
LIVE_APPEND_HEADERS = {
    68: "D33 live run 18 Nov 2026 (hosted bge-small index, FAISS) RAG - the retrieved item that answers this claim: method, rank, chunk, score",
    69: "D33 live run RAG - deterministic support for this claim: evidence support grade, support ratio, recall proxy, citation precision",
    70: "D33 live run RAG - PER-CLAIM ROUGE-1/2/L F1, this gold claim vs the answer text it was graded on (descriptive)",
    71: "D33 live run RAG - PER-CLAIM embedding cosine (hosted bge-small), this gold claim vs its answer text (descriptive topic signal, not a fact check; not comparable with the MiniLM cosines in BC-BO)",
    72: "D33 live run LLM - PER-CLAIM judge b10-claim-1.1, one claim located element by element in the whole answer (secondary, same model family)",
    73: "D33 live run LLM - answer-level judge b10-1.0 plus answer ROUGE and cosines for this investigation (repeats across its 11 rows by design)",
    74: "D33 live run deterministic - PER-CLAIM verdict: result, rule that produced it, source-derived field check",
    75: "D33 live run deterministic - answer-level field check over the reference-stated fields (pass/fail authority)",
    76: "D33 live run provenance - trace id, report status, latency, model calls, tokens, citations, workflow flags",
    77: "D33 live run - what this row does not prove, and how it compares with the 17 Nov columns BC-BO",
}

CLAIM_LEVEL = (
    "source_document_id",
    "source_chunk_id",
    "chunk_locator",
    "chunk_text",
    "retriever_rank",
    "evidence_supports_claim",
    "conflict_notes",
    "generated_claim",
    "generated_citations",
    "claim_result",
    "gold_evidence_recall",
    "critical_fact_match",
    "citation_precision",
    "citation_coverage",
    "unsupported_claim_rate",
    "conflict_preservation",
    "abstention_correctness",
)

PROXY_NOTE = (
    "Gold Evidence Recall@k is an anchor proxy here: column R of this sheet says the "
    "candidate URL is not yet verified, so no verified gold passage exists to recall."
)
LEXICAL_NOTE = (
    "Claim-level result comes from the lexical anchor rule because no source-derived "
    "field check exists for this claim family; it is not a verified fact check."
)


def cell(value: object) -> object:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float)):
        return round(float(value), 4)
    return value


def retrieval_method_cell(claim: dict) -> str:
    if claim["retrieval_method"] == "retrieved_passage":
        score = claim.get("retrieval_score")
        return f"retrieved_passage rank {claim.get('retriever_rank')}" + (
            f", score {round(float(score), 4)}" if isinstance(score, (int, float)) else ""
        )
    if claim["retrieval_method"] == "structured_record":
        return f"structured_record {claim.get('structured_record_id', '')}"
    return "none - no retrieved item matches this claim's anchors"


def field_check_cell(row: dict) -> str:
    fields = row["fields"]
    neutral = {"match", "not-in-reference"}
    disagreements = {key: value for key, value in fields.items() if value not in neutral}
    stated = sum(1 for value in fields.values() if value not in {"not-in-reference"})
    if not disagreements:
        return (
            f"PASS - deterministic field check over {stated} reference-stated fields "
            "(CVE id, CVSS version/score/severity/vector, KEV status and date added) all agree"
        )
    return (
        f"FAIL - {', '.join(f'{key}: {value}' for key, value in disagreements.items())} "
        f"over {stated} reference-stated fields"
    )


def rouge_cell(row: dict) -> str:
    return (
        f"ROUGE-1 F1 {row['rouge1_f']:.4f}\nROUGE-2 F1 {row['rouge2_f']:.4f}\n"
        f"ROUGE-L F1 {row['rougeL_f']:.4f}\n(answer vs frozen gold; descriptive, not a score)"
    )


def judge_cell(row: dict) -> str:
    judge = row.get("judge")
    if not judge:
        return f"LLM JUDGE: not scored ({row.get('judge_error') or 'judge not run for this row'})"
    return (
        "LLM JUDGE b10-1.0 (secondary measure, not the pass/fail authority)\n"
        f"factual_correctness {judge['factual_correctness']}/5 | "
        f"completeness {judge['completeness']}/5 | groundedness {judge['groundedness']}/5 | "
        f"overall {judge['overall']}/5\n"
        f"strict pass (all four >=4): {'yes' if judge['pass'] else 'no'}\n"
        f"issues: {'; '.join(judge['issues']) if judge['issues'] else 'none recorded'}"
    )


def live_rouge_cell(claim: dict) -> str:
    return (
        f"ROUGE-1 F1 {claim['claim_rouge1_f']:.4f}\nROUGE-2 F1 {claim['claim_rouge2_f']:.4f}\n"
        f"ROUGE-L F1 {claim['claim_rougeL_f']:.4f}\n"
        "(one gold claim vs the answer text this claim was graded on; descriptive, not a score)"
    )


def live_claim_judge_cell(claim: dict) -> str:
    judge = claim.get("claim_judge")
    if not judge:
        return (
            "CLAIM JUDGE: not scored "
            f"({claim.get('claim_judge_error') or 'claim judge not run for this row'})"
        )
    elements = "\n".join(
        "- {} [{}] {}".format(
            row["element"],
            row.get("effective_status") or row["status"],
            f'quoted "{row["quote"][:120]}"' if row.get("quote") else "no quote offered",
        )
        for row in judge["elements"]
    )
    return (
        "CLAIM JUDGE b10-claim-1.1 (secondary measure, not the pass/fail authority)\n"
        f"agreement {judge['agreement']}/5 | verdict {judge['verdict']} | "
        f"element share {judge['element_share']:.4f} of {judge['element_count']} "
        f"({judge['elements_stated']} stated, {judge['elements_conceded']} conceded, "
        f"{judge['elements_missing']} missing, {judge['elements_unquoted']} unquotable, "
        f"{judge['elements_contradicted']} contradicted)\n"
        f"{elements}\n"
        f"gold claim: {claim['gold_claim_text'][:300]}"
    )


def live_support_cell(claim: dict) -> str:
    return (
        f"evidence_supports_claim={claim['evidence_supports_claim']} "
        f"(support ratio {claim['support_ratio']} over the whole retrieved set), "
        f"gold evidence recall proxy {claim['gold_evidence_recall']}, "
        f"anchor coverage {claim['claim_coverage']} graded {claim['coverage_grade']}, "
        f"citation precision {claim['citation_precision']} over "
        f"{claim['generated_citations'] or 'no attached citations'}"
    )


def live_answer_cell(row: dict) -> str:
    judge = row.get("judge")
    head = (
        "LLM JUDGE b10-1.0 "
        + (
            f"factual {judge['factual_correctness']}/5 completeness {judge['completeness']}/5 "
            f"groundedness {judge['groundedness']}/5 overall {judge['overall']}/5, "
            f"strict pass {'yes' if judge['pass'] else 'no'}"
            if judge
            else f"not scored ({row.get('judge_error') or 'not run'})"
        )
    )
    return (
        f"{head}\nanswer ROUGE-1 {row['rouge1_f']:.4f} ROUGE-2 {row['rouge2_f']:.4f} "
        f"ROUGE-L {row['rougeL_f']:.4f}\nanswer-vs-gold cosine {row['semantic_cosine']:.4f}, "
        f"question-vs-answer cosine {row['relevance_cosine']:.4f}\n"
        "(computed once per investigation, so this text is the same on all of its claim rows)"
    )


def live_claim_verdict_cell(claim: dict) -> str:
    return (
        f"{claim['claim_result']} - {claim['result_basis']}\n"
        f"source-derived field check: {claim['critical_fact_match']}"
    )


def live_run_cell(answer: dict) -> str:
    return (
        f"trace {answer['trace_id']}, report_status={answer['report_status']}, "
        f"{answer['latency_ms']} ms over {answer['model_calls']} model calls "
        f"(prompt {answer['prompt_tokens']} + completion {answer['completion_tokens']} tokens), "
        f"{answer['citations']} citations, {answer['retrieved_contexts']} retrieved contexts, "
        f"{answer['evidence_records']} evidence records, critic_revision={answer['revised']}, "
        f"first_draft_invalid={answer['first_draft_invalid']}"
    )


def live_caveat_cell(claim: dict, answer: dict, previous: dict | None) -> str:
    notes: list[str] = []
    if claim["result_basis"] == "lexical anchor proxy":
        notes.append(LEXICAL_NOTE)
    notes.append(PROXY_NOTE)
    notes.append(
        "per-claim ROUGE and cosine compare wording between this gold claim and the answer "
        "text it was graded on; on short templated families they carry almost no "
        "cross-CVE signal, so they are a topic check and never a fact check"
    )
    if claim["abstention_note"]:
        notes.append(claim["abstention_note"])
    if answer["report_status"] != "completed":
        notes.append(f"the investigation stopped at status={answer['report_status']}")
    if previous is None:
        notes.append("no 17 Nov claim row to compare with was supplied for this claim")
    elif previous.get("claim_result") == claim["claim_result"]:
        notes.append(
            f"deterministic verdict unchanged from the 17 Nov run ({claim['claim_result']}); "
            "this row is an independent reproduction, not a fix"
        )
    else:
        notes.append(
            f"deterministic verdict moved {previous.get('claim_result')} -> "
            f"{claim['claim_result']} between the 17 Nov and 18 Nov runs"
        )
    notes.append("the gold answer for this row is still PENDING HUMAN DOMAIN REVIEW (column F)")
    return " | ".join(notes)


def run_cells(answer: dict, trace_meta: dict) -> dict[str, object]:
    return {
        "run_id": trace_meta["run_id"],
        "model_version": trace_meta["model_version"],
        "prompt_version": trace_meta["prompt_version"],
        "index_snapshot": trace_meta["index_snapshot"],
        "run_timestamp_utc": trace_meta["run_timestamp_utc"],
        "top_k": answer.get("top_k"),
        "latency_ms": answer.get("latency_ms"),
        "token_usage": (
            f"prompt {answer.get('prompt_tokens')} + completion {answer.get('completion_tokens')}"
            f" over {answer.get('model_calls')} model calls"
        ),
    }


def answer_level_cells(row: dict) -> dict[str, object]:
    answer = row["answer"]
    return {
        "gold_claim_coverage": answer["gold_claim_coverage"],
        "context_precision": answer["context_precision"],
        "context_recall": answer["context_recall"],
        "faithfulness": answer["faithfulness"],
        "answer_relevancy": row["relevance_cosine"],
        "answer_correctness": answer["answer_correctness"],
        **run_cells(answer, row["run"]),
    }


def claim_level_cells(claim: dict) -> dict[str, object]:
    cells = {key: claim[key] for key in CLAIM_LEVEL}
    cells["retrieval_score"] = retrieval_method_cell(claim)
    cells["generated_claim"] = claim["generated_claim"]
    return cells


def caveat_cell(claim: dict, answer: dict) -> str:
    notes: list[str] = []
    if claim["result_basis"] == "lexical anchor proxy":
        notes.append(LEXICAL_NOTE)
    notes.append(PROXY_NOTE)
    if claim["abstention_note"]:
        notes.append(claim["abstention_note"])
    if answer["report_status"] != "completed":
        notes.append(f"the investigation stopped at status={answer['report_status']}")
    notes.append("the gold answer for this row is still PENDING HUMAN DOMAIN REVIEW (column F)")
    return " | ".join(notes)


def index_snapshot() -> str:
    index = json.loads((ROOT / "data" / "manifests" / "index.json").read_text("utf-8"))
    reference = json.loads(
        (ROOT / "data" / "manifests" / "nvd_reference_chunks.json").read_text("utf-8")
    )
    return (
        f"hybrid BM25+dense RRF over chunks_sha256={index['chunks_sha256'][:16]} "
        f"({index['chunks']} chunks, {index['model']}, {index['dim']}d) plus reference-first "
        f"NVD reference chunks ({reference['chunks_total']} chunks over "
        f"{reference['docs_chunked']} cited reference pages)"
    )


def build(sheet, rows: list[dict], claims: list[dict]) -> list[tuple[int, dict[int, object]]]:
    by_eval = {row["eval_id"]: row for row in rows}
    updates: list[tuple[int, dict[int, object]]] = []
    for claim in claims:
        row = by_eval[claim["eval_id"]]
        answer = row["answer"]
        cells: dict[int, object] = {}
        for name, value in {**claim_level_cells(claim), **answer_level_cells(row)}.items():
            cells[COLUMNS[name]] = cell(value)
        cells[COLUMNS["gold_evidence_recall"]] = cell(claim["gold_evidence_recall"])
        for column, value in {
            55: field_check_cell(row),
            56: rouge_cell(row),
            57: round(row["semantic_cosine"], 4),
            58: round(row["relevance_cosine"], 4),
            59: judge_cell(row),
            60: claim["result_basis"],
            61: cell(claim["claim_coverage"]),
            62: ", ".join(claim["coverage_missing"]) if claim["coverage_missing"] else "",
            63: cell(claim["support_ratio"]),
            64: ", ".join(claim["supporting_citations"]) or "none",
            65: answer["trace_id"],
            66: (
                f"report_status={answer['report_status']}, claims "
                f"P{answer['claims_pass']}/X{answer['claims_partial']}/F{answer['claims_fail']}"
                f"/A{answer['claims_abstain']}, critic_revision={answer['revised']}, "
                f"first_draft_invalid={answer['first_draft_invalid']}"
            ),
            67: caveat_cell(claim, answer),
        }.items():
            cells[column] = cell(value)
        if claim["workbook_row"] > sheet.max_row:
            raise SystemExit(f"{claim['claim_id']}: workbook row {claim['workbook_row']} is past the sheet")
        updates.append((claim["workbook_row"], cells))
    return sorted(updates, key=lambda item: item[0])


def live_build(sheet, rows: list[dict], claims: list[dict], previous: dict) -> list[tuple[int, dict[int, object]]]:
    """Columns 68-77 only: the live re-run, written beside the 17 November numbers.

    Nothing in the workbook's own capture range is touched, so the two runs can
    be read against each other instead of one replacing the other.
    """
    by_eval = {row["eval_id"]: row for row in rows}
    updates: list[tuple[int, dict[int, object]]] = []
    for claim in claims:
        row = by_eval[claim["eval_id"]]
        answer = row["answer"]
        retrieval = retrieval_method_cell(claim)
        if claim["source_chunk_id"]:
            retrieval += f"\nchunk {claim['source_chunk_id']}\n{claim['chunk_locator']}\n{claim['chunk_text'][:400]}"
        cells = {
            68: retrieval,
            69: live_support_cell(claim),
            70: live_rouge_cell(claim),
            71: round(claim["claim_cosine"], 4),
            72: live_claim_judge_cell(claim),
            73: live_answer_cell(row),
            74: live_claim_verdict_cell(claim),
            75: field_check_cell(row),
            76: live_run_cell(answer),
            77: live_caveat_cell(claim, answer, previous.get(claim["claim_id"])),
        }
        if claim["workbook_row"] > sheet.max_row:
            raise SystemExit(f"{claim['claim_id']}: workbook row {claim['workbook_row']} is past the sheet")
        updates.append((claim["workbook_row"], {column: cell(value) for column, value in cells.items()}))
    return sorted(updates, key=lambda item: item[0])


def guard(sheet, updates: list[tuple[int, dict[int, object]]], overwrite: bool = False) -> dict:
    """The capture range must be empty, and nothing may be written before column V.

    ``overwrite`` relaxes only the first rule, for a re-run that replaces cells
    this same writer filled after a grader fix. The second rule never relaxes:
    columns A-F and everything left of V belong to the reviewer.
    """
    offenders: list[str] = []
    replaced: list[str] = []
    for index, cells in updates:
        for column, value in cells.items():
            if column > LAST_CAPTURE_COLUMN or value in ("", None):
                continue
            current = sheet.cell(row=index, column=column).value
            if current in (None, ""):
                continue
            occupant = f"{get_column_letter(column)}{index}: holds {str(current)[:40]!r}"
            (replaced if overwrite else offenders).append(occupant)
    protected = [
        f"{get_column_letter(column)}{index}"
        for index, cells in updates
        for column in cells
        if column < COLUMNS["source_document_id"]
    ]
    return {
        "occupied_capture_cells": offenders,
        "replaced_capture_cells": len(replaced),
        "writes_before_V": protected,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workbook", type=Path, default=WORKBOOK)
    parser.add_argument("--scores", type=Path, default=SCORES)
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace capture cells this writer already filled (after a grader fix); never touches A-F",
    )
    parser.add_argument(
        "--appended-only",
        action="store_true",
        help="write only columns 68-77 for a later run, leaving the 17 November capture and append columns alone",
    )
    parser.add_argument("--run", type=Path, default=ROOT / "data" / "evaluation" / "batch10" / "run.json")
    parser.add_argument(
        "--baseline",
        type=Path,
        help="an earlier scores.json whose per-claim deterministic verdict is named in the comparison column",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    payload = json.loads(args.scores.read_text("utf-8"))
    rows, claims = payload["rows"], payload["claims"]
    entries = investigations(ledger(args.workbook))
    digest = dataset_fingerprint(entries)
    if digest != payload["summary"]["dataset_sha256"]:
        raise SystemExit(
            f"scores.json was computed for a different dataset hash: "
            f"{payload['summary']['dataset_sha256'][:16]} vs current {digest[:16]}"
        )

    run_meta = json.loads(args.run.read_text("utf-8"))
    if run_meta.get("dataset_sha256") != digest:
        raise SystemExit(f"{args.run.name} was produced for a different dataset hash")
    claim_judge = payload["summary"].get("claim_judge_prompt_version")
    run = {
        "run_id": f"B10-{digest[:12]}",
        "model_version": (
            f"{payload['summary']['model']} via hosted inference API "
            "(TLS verified, one active request at a time)"
        ),
        "prompt_version": (
            "LangGraph Evidence/Analyst/Critic/FinalValidator prompts, unversioned in the trace; "
            f"judge prompt {payload['summary']['judge_prompt_version']} = retained prompt revision "
            "g100-1.1 (that label names the text's lineage, not a live dataset)"
            + (f"; claim judge {claim_judge}" if claim_judge else "")
        ),
        "index_snapshot": index_snapshot(),
        "run_timestamp_utc": run_meta["generated_at"],
    }
    for row in rows:
        row["run"] = run

    previous: dict[str, dict] = {}
    if args.baseline:
        previous = {
            claim["claim_id"]: claim
            for claim in json.loads(args.baseline.read_text("utf-8"))["claims"]
        }

    before = frozen_fingerprint(args.workbook)
    workbook = load_workbook(args.workbook)
    sheet = workbook[SHEET]
    headers = LIVE_APPEND_HEADERS if args.appended_only else APPEND_HEADERS
    updates = (
        live_build(sheet, rows, claims, previous)
        if args.appended_only
        else build(sheet, rows, claims)
    )
    safety = guard(sheet, updates, args.overwrite)
    report = {
        "workbook": args.workbook.name,
        "sheet": SHEET,
        "dataset_sha256": digest,
        "frozen_af_fingerprint_before": before,
        "rows_written": len(updates),
        "capture_columns": (
            [] if args.appended_only
            else [get_column_letter(column) for column in range(COLUMNS["source_document_id"], LAST_CAPTURE_COLUMN + 1)]
        ),
        "appended_columns": [get_column_letter(column) for column in sorted(headers)],
        "claims_expected": len(claims),
        **safety,
    }
    if args.dry_run:
        report["written"] = False
        print(json.dumps(report, indent=1, ensure_ascii=False))
        return 0
    if safety["occupied_capture_cells"] or safety["writes_before_V"]:
        print(json.dumps({**report, "written": False, "refused": True}, indent=1, ensure_ascii=False))
        return 1

    BACKUPS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = BACKUPS / f"{args.workbook.stem}.{stamp}.before-column-write.xlsx"
    shutil.copy2(args.workbook, backup)
    report["backup"] = backup.relative_to(ROOT).as_posix()

    for column, title in headers.items():
        head = sheet.cell(row=FIRST_DATA_ROW - 1, column=column)
        head.value = title
        head.alignment = Alignment(wrap_text=True, vertical="bottom")
    for index, cells in updates:
        for column, value in cells.items():
            target = sheet.cell(row=index, column=column)
            target.value = value
            if column >= NEW_FIRST_COLUMN or column in (COLUMNS["chunk_text"], COLUMNS["generated_claim"], COLUMNS["conflict_notes"], LAST_CAPTURE_COLUMN):
                target.alignment = Alignment(wrap_text=True, vertical="top")
    for column in headers:
        sheet.column_dimensions[get_column_letter(column)].width = 46
    workbook.save(args.workbook)
    workbook.close()

    after = frozen_fingerprint(args.workbook)
    report["frozen_af_fingerprint_after"] = after
    report["frozen_unchanged"] = before == after
    print(json.dumps(report, indent=1, ensure_ascii=False))
    return 0 if report["frozen_unchanged"] else 1


if __name__ == "__main__":
    sys.exit(main())
