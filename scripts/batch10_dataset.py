"""Read the Batch 10 consolidated RAG + agent evaluation workbook.

The workbook is the frozen reference for this set: one row per gold claim, the
frozen gold answer repeated on every row of its investigation so the sheet can
be filtered. Nothing here writes to the workbook, and nothing here calls a
model - it only parses what the user supplied.

Column letters are named once, in ``COLUMNS``, so a writer and a reader cannot
drift apart on the layout.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from openpyxl import load_workbook

ROOT = Path(__file__).resolve().parent.parent
WORKBOOK = ROOT / "CyberShield_Batch10_Consolidated_RAG_Agent_Evaluation_Traceability.xlsx"
SHEET = "Batch 10 - RAG Agent Eval"
FIRST_DATA_ROW = 5

COLUMNS = {
    "eval_id": 1,
    "cve_id": 2,
    "question": 3,
    "gold_answer": 4,
    "gold_sha256": 5,
    "gold_approval": 6,
    "evidence_readiness": 7,
    "claim_id": 8,
    "claim_family": 9,
    "claim_text": 10,
    "source_labels": 11,
    "source_urls": 12,
    "resolver": 13,
    "reference_discovery": 14,
    "retrieval_rule": 15,
    "guardrail": 16,
    "evidence_object": 17,
    "evidence_status": 18,
    "source_locator": 19,
    "source_excerpt": 20,
    "source_snapshot": 21,
    "source_document_id": 22,
    "source_chunk_id": 23,
    "chunk_locator": 24,
    "chunk_text": 25,
    "retriever_rank": 26,
    "retrieval_score": 27,
    "evidence_supports_claim": 28,
    "conflict_notes": 29,
    "generated_claim": 30,
    "generated_citations": 31,
    "claim_result": 32,
    "gold_evidence_recall": 33,
    "gold_claim_coverage": 34,
    "critical_fact_match": 35,
    "context_precision": 36,
    "context_recall": 37,
    "faithfulness": 38,
    "answer_relevancy": 39,
    "answer_correctness": 40,
    "citation_precision": 41,
    "citation_coverage": 42,
    "unsupported_claim_rate": 43,
    "conflict_preservation": 44,
    "abstention_correctness": 45,
    "run_id": 46,
    "model_version": 47,
    "prompt_version": 48,
    "index_snapshot": 49,
    "run_timestamp_utc": 50,
    "top_k": 51,
    "latency_ms": 52,
    "token_usage": 53,
    "reviewer_notes": 54,
}

# The columns the user owns. A writer may touch nothing before this range.
FROZEN_COLUMNS = ("eval_id", "cve_id", "question", "gold_answer", "gold_sha256", "gold_approval")
NEW_FIRST_COLUMN = 55  # BC: the first column this project appends.


@dataclass(frozen=True)
class ClaimRow:
    row: int
    eval_id: str
    cve_id: str
    question: str
    gold_answer: str
    gold_sha256: str
    gold_approval: str
    evidence_readiness: str
    claim_id: str
    family: str
    claim_text: str
    source_labels: str
    source_urls: str
    resolver: str
    reference_discovery: str
    retrieval_rule: str
    guardrail: str
    evidence_object: str
    evidence_status: str
    source_locator: str
    source_excerpt: str


def _text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def ledger(path: Path = WORKBOOK) -> list[ClaimRow]:
    """Every gold-claim row, in workbook order, with the frozen columns verbatim."""
    workbook = load_workbook(path, read_only=True, data_only=True)
    sheet = workbook[SHEET]
    cells = list(sheet.iter_rows(min_row=FIRST_DATA_ROW, max_col=COLUMNS["source_excerpt"], values_only=True))
    workbook.close()
    rows: list[ClaimRow] = []
    for index, values in enumerate(cells, start=FIRST_DATA_ROW):
        if not values or not _text(values[COLUMNS["eval_id"] - 1]):
            continue
        rows.append(
            ClaimRow(
                row=index,
                eval_id=_text(values[COLUMNS["eval_id"] - 1]),
                cve_id=_text(values[COLUMNS["cve_id"] - 1]).upper(),
                question=_text(values[COLUMNS["question"] - 1]),
                gold_answer=str(values[COLUMNS["gold_answer"] - 1] or ""),
                gold_sha256=_text(values[COLUMNS["gold_sha256"] - 1]).lower(),
                gold_approval=_text(values[COLUMNS["gold_approval"] - 1]),
                evidence_readiness=_text(values[COLUMNS["evidence_readiness"] - 1]),
                claim_id=_text(values[COLUMNS["claim_id"] - 1]),
                family=_text(values[COLUMNS["claim_family"] - 1]),
                claim_text=str(values[COLUMNS["claim_text"] - 1] or ""),
                source_labels=_text(values[COLUMNS["source_labels"] - 1]),
                source_urls=_text(values[COLUMNS["source_urls"] - 1]),
                resolver=_text(values[COLUMNS["resolver"] - 1]),
                reference_discovery=_text(values[COLUMNS["reference_discovery"] - 1]),
                retrieval_rule=_text(values[COLUMNS["retrieval_rule"] - 1]),
                guardrail=_text(values[COLUMNS["guardrail"] - 1]),
                evidence_object=_text(values[COLUMNS["evidence_object"] - 1]),
                evidence_status=_text(values[COLUMNS["evidence_status"] - 1]),
                source_locator=_text(values[COLUMNS["source_locator"] - 1]),
                source_excerpt=_text(values[COLUMNS["source_excerpt"] - 1]),
            )
        )
    return rows


def investigations(rows: list[ClaimRow]) -> list[dict]:
    """One entry per Eval ID, carrying the question and the frozen gold answer."""
    ordered: dict[str, dict] = {}
    for row in rows:
        entry = ordered.setdefault(
            row.eval_id,
            {
                "eval_id": row.eval_id,
                "cve_id": row.cve_id,
                "question": row.question,
                "gold_answer": row.gold_answer,
                "gold_sha256": row.gold_sha256,
                "gold_approval": row.gold_approval,
                "evidence_readiness": row.evidence_readiness,
                "source_urls": "",
                "claims": [],
            },
        )
        for url in row.source_urls.replace(",", "\n").splitlines():
            url = url.strip()
            if url.startswith(("http://", "https://")) and url not in entry["source_urls"]:
                entry["source_urls"] = f"{entry['source_urls']}\n{url}".strip()
        entry["claims"].append(row)
    return list(ordered.values())


def verify_gold_hashes(entries: list[dict]) -> list[str]:
    """Eval IDs whose stored SHA-256 is not sha256(gold answer as UTF-8)."""
    bad = []
    for entry in entries:
        computed = hashlib.sha256(entry["gold_answer"].encode("utf-8")).hexdigest()
        if computed != entry["gold_sha256"]:
            bad.append(entry["eval_id"])
    return bad


def claims_of(gold_answer: str) -> dict[str, str]:
    """Split the frozen gold answer into its labelled lines, label -> text."""
    labelled: dict[str, str] = {}
    for line in gold_answer.splitlines():
        label, separator, rest = line.partition(":")
        label = label.strip()
        if separator and label and label.upper() == label:
            labelled.setdefault(label.upper(), rest.strip())
    return labelled


def dataset_fingerprint(entries: list[dict]) -> str:
    """Content address of what is compared: question plus gold answer per row.

    Keyed on the reference only, so replacing a stored agent answer never
    invalidates the reference identity.
    """
    return hashlib.sha256(
        "\x1e".join(
            f"{entry['eval_id']}\x1f{entry['cve_id']}\x1f{entry['question']}\x1f{entry['gold_answer']}"
            for entry in entries
        ).encode("utf-8")
    ).hexdigest()


def frozen_fingerprint(path: Path = WORKBOOK) -> str:
    """Hash the user-owned columns of every sheet row, so a writer can prove it left them alone."""
    last = COLUMNS[FROZEN_COLUMNS[-1]]
    workbook = load_workbook(path, read_only=True, data_only=True)
    sheet = workbook[SHEET]
    parts = [
        "\x1f".join(_text(value) for value in (row + (None,) * last)[:last])
        for row in sheet.iter_rows(min_row=1, max_col=last, values_only=True)
    ]
    workbook.close()
    return hashlib.sha256("\x1e".join(parts).encode("utf-8")).hexdigest()
