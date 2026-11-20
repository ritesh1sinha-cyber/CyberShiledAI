"""Read-only data layer behind the two evaluation dashboards.

The dashboards show what the frozen Batch 10 run already recorded in the
traceability workbook, its scores file and the run traces; nothing here computes
a new score. A value that was never captured comes back as NOT_CAPTURED rather
than a blank or a plausible number, because a report writer cannot tell those
apart later.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from openpyxl import load_workbook

ROOT = Path(__file__).resolve().parents[1]

BATCH10_WORKBOOK = (
    ROOT / "CyberShield_Batch10_Consolidated_RAG_Agent_Evaluation_Traceability.xlsx"
)
BATCH10_SHEET = "Batch 10 - RAG Agent Eval"
BATCH10_FIRST_ROW, BATCH10_LAST_ROW = 5, 114
BATCH10_COLUMNS = 77
BATCH10_SCORES_JSON = ROOT / "data" / "evaluation" / "batch10_live_20261118" / "scores.json"
BATCH10_TRACE_DIR = ROOT / "data" / "traces" / "batch10_live_20261118"

NOT_CAPTURED = "not captured"
NO_TRACE = "not captured: no run trace file for this row"
ANSWER_FROM_TRACE = (
    "The workbook copy of the answer is capped at 1,200 characters, so this text is "
    "read back from the run trace report - the same report the deterministic field "
    "check graded."
)

BATCH10_SOURCES = (BATCH10_WORKBOOK, BATCH10_SCORES_JSON, BATCH10_TRACE_DIR)

BATCH10_GOLD_COLUMNS = {
    3: "question",
    4: "gold_answer",
    6: "gold_approval",
    8: "claim_id",
    11: "source_labels",
    12: "source_urls",
    18: "evidence_verification",
    19: "source_locator",
    77: "live_caveat",
}

# Answer-level metrics are computed once per investigation; scores.json stores
# them on rows[], so they are copied onto every claim row of that investigation.
ANSWER_LEVEL_FIELDS = ("rouge1_f", "rouge2_f", "rougeL_f", "semantic_cosine", "relevance_cosine")


# ------------------------------------------------------------ formatting ----


def missing_artifacts() -> list[Path]:
    """Which artifact paths this view needs that are not on disk."""
    return [path for path in BATCH10_SOURCES if not path.exists()]


def text(value: object) -> str:
    if value is None:
        return NOT_CAPTURED
    return str(value).strip() or NOT_CAPTURED


def excerpt(value: object, limit: int = 240) -> str:
    """One-line preview of a multi-line cell, for a table."""
    flat = " / ".join(line.strip() for line in text(value).splitlines() if line.strip())
    return flat if len(flat) <= limit else flat[:limit].rstrip() + " …"


def number(value: object, digits: int = 4) -> str:
    """A stored metric, formatted; a non-numeric stored value is passed through."""
    if value is None or value == "":
        return NOT_CAPTURED
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return text(value)


def yes_no(value: object) -> str:
    lowered = text(value).lower()
    if lowered in {"true", "yes"}:
        return "yes"
    if lowered in {"false", "no"}:
        return "no"
    return text(value)


def verdict_from_fields(fields: dict[str, str]) -> str:
    """The deterministic field check, stated as a label.

    Same rule as app.batch10_metrics.derive_result() - a contradiction fails, an
    omission is partial, otherwise every reference-stated field agrees.
    """
    scored = {
        name: state
        for name, state in fields.items()
        if state not in (None, "", "not-in-reference")
    }
    if not scored:
        return NOT_CAPTURED
    if any(state == "mismatch" for state in scored.values()):
        return "FAIL"
    if any(state == "absent" for state in scored.values()):
        return "PARTIAL"
    return "PASS"


# ---------------------------------------------------------------- loaders ----


def _sheet_rows(path: Path, sheet: str, first_row: int, last_row: int, columns: int) -> list[list]:
    workbook = load_workbook(path, read_only=True, data_only=True)
    tab = workbook[sheet]
    rows = [
        [*values, *([None] * (columns - len(values)))]
        for values in tab.iter_rows(
            min_row=first_row, max_row=last_row, max_col=columns, values_only=True
        )
    ]
    workbook.close()
    return rows


def _trace(directory: Path, name: str) -> dict | None:
    path = directory / f"{name}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text("utf-8"))


def _service_trace(trace: dict | None) -> dict:
    return (trace or {}).get("service_trace") or {}


def _named(path: Path, sheet: str, columns: dict[int, str], first: int, last: int, count: int):
    """Yield (row_number, {name: cell}) for each non-empty row of a sheet."""
    for offset, values in enumerate(
        _sheet_rows(path, sheet, first, last, count), start=first
    ):
        if not any(value not in (None, "") for value in values[:count]):
            continue
        yield offset, {name: values[column - 1] for column, name in columns.items()}


def _batch10_gold() -> dict[str, dict]:
    """The reviewer-owned gold columns, keyed by claim id."""
    return {
        text(cells["claim_id"]): cells
        for _, cells in _named(
            BATCH10_WORKBOOK,
            BATCH10_SHEET,
            BATCH10_GOLD_COLUMNS,
            BATCH10_FIRST_ROW,
            BATCH10_LAST_ROW,
            BATCH10_COLUMNS,
        )
    }


def batch10_scores() -> dict:
    return json.loads(BATCH10_SCORES_JSON.read_text("utf-8"))


def batch10_summary() -> dict:
    """What the scoring run itself says about the run: model, hashes, tallies."""
    return batch10_scores()["summary"]


def batch10_claims() -> list[dict]:
    """The 110 per-claim records of the 18 November live run: scores.json numbers
    joined to the workbook gold columns by claim id."""
    gold = _batch10_gold()
    payload = batch10_scores()
    answers = {row["eval_id"]: row for row in payload["rows"]}
    merged = []
    for claim in payload["claims"]:
        reference = gold.get(text(claim["claim_id"]), {})
        answer = answers.get(claim["eval_id"], {})
        merged.append(
            {
                **claim,
                **{
                    name: reference.get(name)
                    for name in (
                        "question",
                        "gold_answer",
                        "gold_approval",
                        "source_labels",
                        "source_urls",
                        "evidence_verification",
                        "source_locator",
                        "live_caveat",
                    )
                },
                "answer_fields": answer.get("fields") or {},
                "answer_judge": answer.get("judge") or {},
                "answer_rollup": answer.get("answer") or {},
                "answer_numbers": {
                    name: number(answer.get(name)) for name in ANSWER_LEVEL_FIELDS
                },
            }
        )
    return merged


def judge_line(judge: dict) -> str:
    """One readable line for an answer-level judge record."""
    if not judge:
        return "not scored"
    issues = "; ".join(judge.get("issues") or []) or "none recorded"
    return (
        f"factual {judge.get('factual_correctness', '?')}/5, "
        f"completeness {judge.get('completeness', '?')}/5, "
        f"groundedness {judge.get('groundedness', '?')}/5, "
        f"overall {judge.get('overall', '?')}/5; strict pass "
        f"{yes_no(judge.get('pass'))}; issues: {issues}"
    )


def claim_judge_line(judge: dict) -> str:
    if not judge:
        return "not scored"
    return (
        f"agreement {judge.get('agreement', '?')}/5, verdict {text(judge.get('verdict'))}, "
        f"element share {number(judge.get('element_share'))} of {judge.get('element_count')} "
        f"({judge.get('elements_stated')} stated, {judge.get('elements_conceded')} conceded, "
        f"{judge.get('elements_missing')} missing, {judge.get('elements_unquoted')} unquotable, "
        f"{judge.get('elements_contradicted')} contradicted)"
    )


def claim_element_rows(judge: dict) -> list[dict]:
    return [
        {
            "Fact element": element.get("element"),
            "Status": text(element.get("effective_status") or element.get("status")),
            "Quote found in the answer": text(element.get("quote")) if element.get("quote") else "no quote offered",
        }
        for element in (judge or {}).get("elements", [])
    ]


# ------------------------------------------------------------- RAG views ----


def options() -> list[tuple[str, str]]:
    """One selectable entry per investigation: Batch 10 keys on the eval id because
    its eleven claim rows share one investigation."""
    seen: dict[str, str] = {}
    for claim in batch10_claims():
        seen.setdefault(
            text(claim["eval_id"]), f"{text(claim['eval_id'])} - {text(claim['cve_id'])}"
        )
    return list(seen.items())


def passages(trace: dict | None, limit: int = 700) -> list[dict]:
    """Every passage the run retrieved, in the order the retriever returned them."""
    return [
        {
            "Rank": index,
            "Citation": item.get("evidence_id"),
            "Chunk ID": item.get("chunk_id"),
            "Source title": item.get("title"),
            "Retrieval score": number(item.get("score")),
            "Passage text (excerpt)": excerpt(item.get("text"), limit),
        }
        for index, item in enumerate(_service_trace(trace).get("contexts") or [], start=1)
    ]


def rag_table() -> list[dict]:
    return _batch10_rag_table()


def _batch10_rag_table() -> list[dict]:
    return [
        {
            "Eval ID": text(claim["eval_id"]),
            "CVE": text(claim["cve_id"]),
            "Claim ID": text(claim["claim_id"]),
            "Claim family": text(claim["family"]),
            "Expected (gold claim)": excerpt(claim["gold_claim_text"], 260),
            "Retrieved passage for this claim": excerpt(claim["chunk_text"], 260),
            "Source document": text(claim["source_document_id"]),
            "Chunk ID": text(claim["source_chunk_id"]),
            "Rank": number(claim["retriever_rank"], 0),
            "Retrieval score": number(claim["retrieval_score"]),
            "Method": text(claim["retrieval_method"]),
            "Evidence supports the claim": text(claim["evidence_supports_claim"]),
            "Support ratio over the retrieved set": number(claim["support_ratio"]),
            "Gold evidence recall@k (anchor proxy)": number(claim["gold_evidence_recall"]),
            "Gold claim coverage (lexical anchors)": number(claim["claim_coverage"]),
            "Deterministic claim result": text(claim["claim_result"]),
            "Rule behind that result": text(claim["result_basis"]),
        }
        for claim in batch10_claims()
    ]


def rag_detail(key: str) -> dict:
    return _batch10_rag_detail(key)


def _batch10_rag_detail(eval_id: str) -> dict:
    claims = [claim for claim in batch10_claims() if claim["eval_id"] == eval_id]
    if not claims:
        raise KeyError(f"no Batch 10 claims for {eval_id}")
    trace = _trace(BATCH10_TRACE_DIR, eval_id)
    meta = _service_trace(trace).get("retrieval_meta") or {}
    rollup = claims[0]["answer_rollup"]
    return {
        "title": f"{text(claims[0]['cve_id'])} ({eval_id})",
        "meta": [
            ["Investigation question", text(claims[0]["question"])],
            ["Retrieval queries actually run", " | ".join(meta.get("queries") or []) or NOT_CAPTURED],
            ["Reviewer verdict on the passages", yes_no((meta.get("review") or {}).get("sufficient"))],
            ["Refined query the reviewer asked for", text((meta.get("review") or {}).get("refined_query"))],
            ["Passages retrieved", number(rollup.get("retrieved_contexts"), 0)],
            ["Evidence records built", number(rollup.get("evidence_records"), 0)],
            ["Citations in the published report", number(rollup.get("citations"), 0)],
            ["Top-k", number(rollup.get("top_k"), 0)],
            ["Trace ID", text(rollup.get("trace_id"))],
        ],
        "sections": [
            {
                "heading": "Expected versus retrieved, one row per gold claim",
                "kind": "table",
                "rows": [
                    {
                        "Claim ID": text(claim["claim_id"]),
                        "Family": text(claim["family"]),
                        "Expected (gold claim)": text(claim["gold_claim_text"]),
                        "Retrieved passage for this claim": text(claim["chunk_text"]),
                        "Source document": text(claim["source_document_id"]),
                        "Chunk ID": text(claim["source_chunk_id"]),
                        "Rank": number(claim["retriever_rank"], 0),
                        "Retrieval score": number(claim["retrieval_score"]),
                        "Method": text(claim["retrieval_method"]),
                        "Evidence supports the claim": text(claim["evidence_supports_claim"]),
                        "Support ratio over the retrieved set": number(claim["support_ratio"]),
                        "Gold evidence recall@k (anchor proxy)": number(claim["gold_evidence_recall"]),
                        "Gold claim coverage (lexical anchors)": number(claim["claim_coverage"]),
                        "Coverage grade": text(claim["coverage_grade"]),
                        "Anchors not found in the answer": "; ".join(claim["coverage_missing"] or []) or "none",
                        "Deterministic claim result": text(claim["claim_result"]),
                        "Rule behind that result": text(claim["result_basis"]),
                        "Source verification recorded in Excel": text(claim["evidence_verification"]),
                        "Exact source locator recorded in Excel": text(claim["source_locator"]),
                    }
                    for claim in claims
                ],
                "note": (
                    "The last two columns are copied from the reviewer-owned gold columns, so the "
                    "gap between a candidate URL and a verified locator stays visible."
                ),
            },
            {
                "heading": "Every passage this investigation retrieved",
                "kind": "table",
                "rows": passages(trace),
                "note": "From the run trace." if trace else NO_TRACE,
            },
            {
                "heading": "RAG eval score for the investigation",
                "kind": "pairs",
                "rows": [
                    ["Gold claim coverage", number(rollup.get("gold_claim_coverage"))],
                    ["Mean lexical anchor coverage", number(rollup.get("anchor_coverage_mean"))],
                    ["Gold evidence recall@k (anchor proxy)", number(rollup.get("gold_evidence_recall"))],
                    ["Critical fact exact match", number(rollup.get("critical_fact_exact_match"))],
                    ["Context precision", number(rollup.get("context_precision"))],
                    ["Context recall", number(rollup.get("context_recall"))],
                    ["Citation precision", number(rollup.get("citation_precision"))],
                    ["Citation coverage", number(rollup.get("citation_coverage"))],
                    ["Unsupported claim rate", number(rollup.get("unsupported_claim_rate"))],
                    ["Conflict preservation", number(rollup.get("conflict_preservation"))],
                    ["Abstention correctness", number(rollup.get("abstention_correctness"))],
                    ["Claim results", text(rollup.get("claims_pass")) + " pass, " + text(rollup.get("claims_partial")) + " partial, " + text(rollup.get("claims_fail")) + " fail, " + text(rollup.get("claims_abstain")) + " abstain of " + text(rollup.get("claims"))],
                ],
                "note": "",
            },
            {
                "heading": "What these rows do not prove",
                "kind": "table",
                "rows": [
                    {
                        "Claim ID": text(claim["claim_id"]),
                        "Caveat written by the run": text(claim["live_caveat"]),
                    }
                    for claim in claims
                ],
                "note": "Copied from the workbook caveat column written by the same run, one row per claim.",
            },
        ],
    }


# ------------------------------------------------------------- LLM views ----


def llm_table() -> list[dict]:
    return _batch10_llm_table()


def _batch10_llm_table() -> list[dict]:
    return [
        {
            "Eval ID": text(claim["eval_id"]),
            "CVE": text(claim["cve_id"]),
            "Claim ID": text(claim["claim_id"]),
            "Claim family": text(claim["family"]),
            "Gold claim (excerpt)": excerpt(claim["gold_claim_text"], 220),
            "Agent answer (excerpt)": excerpt(claim["generated_claim"], 220),
            "Deterministic claim result (authority)": text(claim["claim_result"]),
            "Rule behind that result": text(claim["result_basis"]),
            "Per-claim ROUGE-1 F1": number(claim["claim_rouge1_f"]),
            "Per-claim ROUGE-2 F1": number(claim["claim_rouge2_f"]),
            "Per-claim ROUGE-L F1": number(claim["claim_rougeL_f"]),
            "Per-claim semantic cosine": number(claim["claim_cosine"]),
            "Per-claim judge agreement /5": text((claim.get("claim_judge") or {}).get("agreement")),
            "Per-claim judge verdict": text((claim.get("claim_judge") or {}).get("verdict")),
            "Answer-level deterministic verdict (authority)": verdict_from_fields(
                claim["answer_fields"]
            ),
            "Answer-level ROUGE-L F1": claim["answer_numbers"]["rougeL_f"],
            "Answer-level semantic cosine": claim["answer_numbers"]["semantic_cosine"],
            "Answer-level judge overall /5": text(
                (claim["answer_judge"] or {}).get("overall")
            ),
        }
        for claim in batch10_claims()
    ]


def llm_detail(key: str) -> dict:
    return _batch10_llm_detail(key)


_FIELD_READING = {
    "match": "agrees with the source",
    "absent": "not stated by the answer",
    "mismatch": "contradicts the source",
    "not-in-reference": "not stated in the gold answer",
}


def _batch10_llm_detail(eval_id: str) -> dict:
    claims = [claim for claim in batch10_claims() if claim["eval_id"] == eval_id]
    if not claims:
        raise KeyError(f"no Batch 10 claims for {eval_id}")
    first = claims[0]
    trace = _trace(BATCH10_TRACE_DIR, eval_id)
    rollup = first["answer_rollup"]
    judge = first["answer_judge"]
    return {
        "title": f"{text(first['cve_id'])} ({eval_id})",
        "meta": [
            ["Investigation question", text(first["question"])],
            ["Report status", text(rollup.get("report_status"))],
            ["Deterministic answer verdict (the only pass/fail authority)", verdict_from_fields(first["answer_fields"])],
            ["Trace ID", text(rollup.get("trace_id"))],
            ["Latency", f"{number(rollup.get('latency_ms'), 0)} ms"],
            ["Model calls", text(rollup.get("model_calls"))],
            ["Tokens", f"prompt {text(rollup.get('prompt_tokens'))} + completion {text(rollup.get('completion_tokens'))}"],
            ["Gold answer approval status", text(first["gold_approval"])],
        ],
        "sections": [
            {
                "heading": "Gold answer (Excel column D, frozen)",
                "kind": "text",
                "text": text(first["gold_answer"]),
                "note": "Frozen before the agents ran; the SHA-256 in the workbook is what the evaluator verified.",
            },
            {
                "heading": "Sources the gold answer cites, one row per claim",
                "kind": "table",
                "rows": [
                    {
                        "Claim ID": text(claim["claim_id"]),
                        "Family": text(claim["family"]),
                        "Candidate source labels (Excel column K)": text(claim["source_labels"]),
                        "Candidate source URLs (Excel column L)": text(claim["source_urls"]),
                    }
                    for claim in claims
                ],
                "note": (
                    "Candidate, not yet verified: the RAG view shows the verification status and "
                    "locator columns for the same claim rows."
                ),
            },
            {
                "heading": "Agent response",
                "kind": "text",
                "text": _report_text(trace),
                "note": ANSWER_FROM_TRACE,
            },
            {
                "heading": "The four measured layers, answer level (one value per investigation, repeated across its 11 claim rows by design)",
                "kind": "pairs",
                "rows": [
                    ["ROUGE-1 / ROUGE-2 / ROUGE-L F1 (descriptive)", " / ".join(first["answer_numbers"][name] for name in ("rouge1_f", "rouge2_f", "rougeL_f"))],
                    ["Semantic cosine, answer vs gold (descriptive)", first["answer_numbers"]["semantic_cosine"]],
                    ["Answer-relevancy cosine, question vs answer (descriptive)", first["answer_numbers"]["relevance_cosine"]],
                    ["LLM-as-judge b10-1.0 (secondary, same model family)", judge_line(judge)],
                    ["Deterministic field check (authority)", verdict_from_fields(first["answer_fields"])],
                ],
                "note": "",
            },
            {
                "heading": "Reference-stated fields, checked one by one",
                "kind": "table",
                "rows": [
                    {"Field": name, "State": state, "Reading": _FIELD_READING.get(state, state)}
                    for name, state in first["answer_fields"].items()
                ],
                "note": "",
            },
            {
                "heading": "The four measured layers, per gold claim (varies row by row)",
                "kind": "table",
                "rows": [
                    {
                        "Claim ID": text(claim["claim_id"]),
                        "Family": text(claim["family"]),
                        "Gold claim": text(claim["gold_claim_text"]),
                        "Deterministic claim result (authority)": text(claim["claim_result"]),
                        "Rule behind that result": text(claim["result_basis"]),
                        "Per-claim ROUGE-1 / 2 / L F1": " / ".join(
                            number(claim[name]) for name in ("claim_rouge1_f", "claim_rouge2_f", "claim_rougeL_f")
                        ),
                        "Per-claim semantic cosine": number(claim["claim_cosine"]),
                        "Per-claim judge b10-claim-1.1": claim_judge_line(claim.get("claim_judge") or {}),
                    }
                    for claim in claims
                ],
                "note": "The claim judge only locates and quotes the required elements; agreement and verdict are computed in code from those quotes.",
            },
            {
                "heading": "What these rows do not prove",
                "kind": "table",
                "rows": [
                    {
                        "Claim ID": text(claim["claim_id"]),
                        "Caveat written by the run": text(claim["live_caveat"]),
                    }
                    for claim in claims
                ],
                "note": "Copied from the workbook caveat column written by the same run, one row per claim.",
            },
        ],
    }


def claim_elements(claim_id: str) -> dict:
    """The per-element table behind one claim-level judge call."""
    for claim in batch10_claims():
        if text(claim["claim_id"]) == claim_id:
            return {
                "claim": claim,
                "elements": claim_element_rows(claim["claim_judge"] or {}),
                "required": claim.get("required_elements") or [],
            }
    raise KeyError(f"no Batch 10 claim {claim_id}")


def _report_text(trace: dict | None) -> str:
    """The published report, section by section, from the run trace."""
    report = ((trace or {}).get("response") or {}).get("report") or {}
    if not report:
        return NO_TRACE
    lines = [
        f"STATUS: {text(report.get('status'))}",
        f"SUMMARY: {text(report.get('summary'))}",
        f"SUMMARY EVIDENCE: {', '.join(report.get('summary_evidence_ids') or []) or 'none'}",
    ]
    cve = report.get("cve") or {}
    if cve:
        lines += [
            f"CVE: {text(cve.get('cve_id'))}",
            f"TECHNICAL OVERVIEW: {text(cve.get('description'))}",
            "SEVERITY: "
            + " | ".join(
                f"{name} {text(cve.get(name))}"
                for name in ("cvss_version", "cvss_score", "severity")
            ),
            f"CVSS VECTOR: {text(cve.get('cvss_vector'))}",
            f"PUBLISHED: {text(cve.get('published'))} / LAST MODIFIED: {text(cve.get('last_modified'))}",
        ]
    products = report.get("affected_products") or []
    lines.append("AFFECTED: " + ("; ".join(products) if products else NOT_CAPTURED))
    kev = report.get("kev") or {}
    kev_line = f"KEV: {text(kev.get('status'))}"
    kev_dates = [
        f"{label} {text(kev.get(key))}"
        for key, label in (("date_added", "added"), ("due_date", "due"))
        if kev.get(key)
    ]
    lines.append(kev_line + (f" ({', '.join(kev_dates)})" if kev_dates else ""))
    for item in report.get("attack_mapping") or []:
        lines.append(
            f"ATT&CK: {text(item.get('technique_id'))} {text(item.get('name'))} "
            f"[basis {text(item.get('basis'))}, confidence {text(item.get('confidence'))}, "
            f"evidence {text(item.get('evidence_id'))}]"
        )
    for item in report.get("remediation") or []:
        lines.append(
            f"REMEDIATION: {text(item.get('text'))} "
            f"[evidence {', '.join(item.get('evidence_ids') or []) or 'none'}]"
        )
    risk = report.get("risk") or {}
    lines.append(f"PROJECT RISK: {text(risk.get('tier'))} - {text(risk.get('rationale'))}")
    for note in report.get("limitations") or []:
        lines.append(f"LIMITATION: {text(note)}")
    lines.append(f"CITATIONS: {len(report.get('citations') or [])}")
    return "\n".join(lines)


# --------------------------------------------------------------- exports ----


def _markdown_cell(value: object) -> str:
    rendered = "" if value is None else str(value)
    return rendered.replace("|", "\\|").replace("\n", "<br>").strip() or NOT_CAPTURED


def table_markdown(rows: list[dict]) -> str:
    if not rows:
        return "_no rows to export_"
    headers = list(rows[0])
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(" --- " for _ in headers) + "|",
    ]
    lines += [
        "| " + " | ".join(_markdown_cell(row.get(header)) for header in headers) + " |"
        for row in rows
    ]
    return "\n".join(lines)


def table_csv(rows: list[dict]) -> str:
    if not rows:
        return ""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(list(rows[0]))
    for row in rows:
        writer.writerow(list(row.values()))
    return buffer.getvalue()


def detail_markdown(detail: dict) -> str:
    """A paste-ready Markdown block for one investigation, for the written report."""
    lines = [f"### {detail['title']}", ""]
    lines += ["| Field | Value |", "| --- | --- |"]
    lines += [
        "| " + _markdown_cell(label) + " | " + _markdown_cell(value) + " |"
        for label, value in detail["meta"]
    ]
    for section in detail["sections"]:
        lines += ["", f"#### {section['heading']}", ""]
        if section["kind"] == "text":
            lines += ["> " + line for line in str(section["text"]).splitlines()] or [NOT_CAPTURED]
        elif section["kind"] == "pairs":
            lines += ["| Field | Value |", "| --- | --- |"]
            lines += [
                "| " + _markdown_cell(label) + " | " + _markdown_cell(value) + " |"
                for label, value in section["rows"]
            ]
        else:
            lines += [table_markdown(section["rows"])]
        if section.get("note"):
            lines += ["", f"_{section['note']}_"]
    return "\n".join(lines)
