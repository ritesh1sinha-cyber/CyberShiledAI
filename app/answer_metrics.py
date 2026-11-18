"""Secondary text metrics for answer-vs-reference benchmarks."""

from __future__ import annotations

import re
from collections import Counter

TOKEN_RE = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", re.I)


def tokenize(text: str) -> list[str]:
    return [token.casefold() for token in TOKEN_RE.findall(text)]


def _f1(overlap: int, candidate_count: int, reference_count: int) -> float:
    if not candidate_count or not reference_count or not overlap:
        return 0.0
    precision = overlap / candidate_count
    recall = overlap / reference_count
    return 2 * precision * recall / (precision + recall)


def _ngram_f1(candidate: list[str], reference: list[str], n: int) -> float:
    candidate_grams = Counter(tuple(candidate[i : i + n]) for i in range(len(candidate) - n + 1))
    reference_grams = Counter(tuple(reference[i : i + n]) for i in range(len(reference) - n + 1))
    overlap = sum((candidate_grams & reference_grams).values())
    return _f1(overlap, sum(candidate_grams.values()), sum(reference_grams.values()))


def rouge_scores(candidate_text: str, reference_text: str) -> dict[str, float]:
    """Return ROUGE-1, ROUGE-2 and ROUGE-L F1 with deterministic tokenization."""
    candidate = tokenize(candidate_text)
    reference = tokenize(reference_text)
    previous = [0] * (len(reference) + 1)
    for token in candidate:
        current = [0]
        for index, ref_token in enumerate(reference, start=1):
            if token == ref_token:
                current.append(previous[index - 1] + 1)
            else:
                current.append(max(previous[index], current[-1]))
        previous = current
    return {
        "rouge1_f": round(_ngram_f1(candidate, reference, 1), 6),
        "rouge2_f": round(_ngram_f1(candidate, reference, 2), 6),
        "rougeL_f": round(_f1(previous[-1], len(candidate), len(reference)), 6),
    }


def candidate_text(report: dict) -> str:
    """Flatten user-facing report content while excluding trace/citation metadata."""
    parts: list[str] = []

    def add(value: object) -> None:
        if isinstance(value, str) and value.strip():
            parts.append(value.strip())

    add(report.get("summary"))
    cve = report.get("cve") or {}
    if isinstance(cve, dict):
        add(cve.get("cve_id"))
        add(cve.get("description"))
        for key in ("cvss_version", "cvss_score", "severity", "cvss_vector", "published"):
            if cve.get(key) is not None:
                parts.append(f"{key.replace('_', ' ')}: {cve[key]}")
    products = report.get("affected_products") or []
    if isinstance(products, list):
        parts.extend(str(item) for item in products if item)
    kev = report.get("kev") or {}
    if isinstance(kev, dict):
        add(kev.get("status"))
        add(kev.get("required_action"))
    for mapping in report.get("attack_mapping") or []:
        if isinstance(mapping, dict):
            add(mapping.get("technique_id"))
            add(mapping.get("name"))
    for item in report.get("remediation") or []:
        if isinstance(item, dict):
            add(item.get("text"))
    risk = report.get("risk") or {}
    if isinstance(risk, dict):
        add(risk.get("tier"))
        add(risk.get("rationale"))
        parts.extend(str(item) for item in risk.get("drivers", []) if item)
    parts.extend(str(item) for item in report.get("limitations", []) if item)
    return "\n".join(parts)

