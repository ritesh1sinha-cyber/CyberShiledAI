"""Verify the retrieval corpus against the capstone's 500-2,000 document gate.

Counts only unique, valid documents. KEV is excluded because it is structured
enrichment, not retrieval text (D5). NVD is excluded for the same reason.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROC = ROOT / "data" / "processed"
OUT = ROOT / "data" / "manifests" / "corpus.json"

GATE_MIN, GATE_MAX = 500, 2000
THIN_CHARS = 200


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load(name: str) -> list[dict]:
    path = PROC / name
    return [json.loads(line) for line in path.read_text("utf-8").splitlines() if line]


def content_of(source: str, row: dict) -> str:
    if source == "ATTACK":
        return "\n".join([row.get("name", ""), row.get("description", "")])
    if source == "OWASP":
        return row.get("text", "")
    if source == "CWE":
        return "\n".join(
            row.get(key, "")
            for key in ("name", "description", "extended_description", "mitigations")
        )
    return row.get("text", "")


def digest(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text).strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def main() -> int:
    corpus = {
        "ATTACK": load("attack_techniques.jsonl"),
        "OWASP": load("owasp_docs.jsonl"),
        "CWE": load("cwe.jsonl"),
        "NIST": load("nist_docs.jsonl"),
    }

    seen_ids: dict[str, str] = {}
    seen_hashes: dict[str, str] = {}
    duplicates: list[dict] = []
    missing_url: list[str] = []
    empty: list[str] = []
    thin: list[str] = []
    valid: list[dict] = []
    per_source = {}

    for source, rows in corpus.items():
        source_valid = 0
        source_thin = 0
        for row in rows:
            doc_id = str(row.get("doc_id") or "")
            text = content_of(source, row)

            if not doc_id:
                empty.append(f"{source}:missing-id")
                continue
            if doc_id in seen_ids:
                duplicates.append({"doc_id": doc_id, "first": seen_ids[doc_id], "again": source})
                continue
            seen_ids[doc_id] = source

            if len(text.strip()) < 100:
                empty.append(doc_id)
                continue
            if not str(row.get("source_url") or "").startswith("http"):
                missing_url.append(doc_id)
                continue
            if len(text.strip()) < THIN_CHARS:
                thin.append(doc_id)
                source_thin += 1

            fingerprint = digest(text)
            if fingerprint in seen_hashes:
                duplicates.append(
                    {"doc_id": doc_id, "first": seen_hashes[fingerprint], "again": source,
                     "reason": "identical content"}
                )
                continue
            seen_hashes[fingerprint] = doc_id

            valid.append({"doc_id": doc_id, "source": source, "chars": len(text)})
            source_valid += 1

        per_source[source] = {
            "loaded": len(rows),
            "valid": source_valid,
            "thin": source_thin,
        }

    state = {
        "generated_at": now(),
        "gate": {"min": GATE_MIN, "max": GATE_MAX,
                 "met": GATE_MIN <= len(valid) <= GATE_MAX},
        "documents_loaded": sum(len(rows) for rows in corpus.values()),
        "documents_valid": len(valid),
        "documents_thin_under_200_chars": len(thin),
        "per_source": per_source,
        "duplicates": duplicates,
        "missing_source_url": missing_url,
        "empty_or_too_short": empty,
        "excluded": {
            "KEV": "structured enrichment, not retrieval text (D5)",
            "NVD": "structured tool responses, not retrieval text (D5)",
        },
        "doc_ids_sha256": hashlib.sha256(
            "\n".join(sorted(r["doc_id"] for r in valid)).encode("utf-8")
        ).hexdigest(),
        "files": {
            name: hashlib.sha256((PROC / name).read_bytes()).hexdigest()
            for name in ("attack_techniques.jsonl", "owasp_docs.jsonl",
                         "cwe.jsonl", "nist_docs.jsonl")
        },
    }
    OUT.write_text(json.dumps(state, indent=2), "utf-8")

    print(f"loaded {state['documents_loaded']} rows")
    for source, info in per_source.items():
        print(f"  {source:<7} loaded {info['loaded']:>4}  valid {info['valid']:>4}"
              f"  thin {info['thin']:>3}")
    print(f"valid unique documents: {state['documents_valid']}")
    print(f"duplicates removed: {len(duplicates)}  "
          f"missing url: {len(missing_url)}  empty: {len(empty)}")
    print(f"gate {GATE_MIN}-{GATE_MAX}: {'MET' if state['gate']['met'] else 'NOT MET'}")
    print(f"manifest: {OUT.relative_to(ROOT)}")
    return 0 if state["gate"]["met"] else 1


if __name__ == "__main__":
    sys.exit(main())
