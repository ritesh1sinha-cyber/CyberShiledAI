"""Audit the table content that survived PDF extraction.

For every NIST document this checks that each recorded table span really starts
and ends with a Markdown row, counts the rows that survived, and compares the
number of tables with the number of "Table N-M" captions. A wide caption gap
flags borderless tables, which the ruled-lines strategy cannot recover.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROC = ROOT / "data" / "processed"
OUT = ROOT / "data" / "manifests" / "table_audit.json"

CAPTION_RE = re.compile(r"\bTable\s+\d+(?:[-.\u2013]\d+)+\b")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> int:
    rows = [
        json.loads(line)
        for line in (PROC / "nist_docs.jsonl").read_text("utf-8").splitlines()
        if line.strip()
    ]

    documents = {}
    totals = Counter()
    for row in rows:
        text = row["text"]
        spans = row.get("tables", [])
        mismatched = 0
        rows_kept = 0
        empty = 0
        for span in spans:
            start, end = span["start"], span["end"]
            if not (text[start:start + 1] == "|" and text[end - 1:end] == "|"):
                mismatched += 1
                continue
            block = text[start:end]
            if len(block.splitlines()) < 2:
                empty += 1
            rows_kept += span["rows"]
        captions = len(set(CAPTION_RE.findall(text)))
        documents[row["doc_id"]] = {
            "tables": len(spans),
            "table_rows": rows_kept,
            "captions": captions,
            "caption_table_gap": captions - len(spans),
            "span_offset_mismatches": mismatched,
            "empty_tables": empty,
        }
        totals["tables"] += len(spans)
        totals["table_rows"] += rows_kept
        totals["captions"] += captions
        totals["span_offset_mismatches"] += mismatched

    flagged = {
        doc_id: info["caption_table_gap"]
        for doc_id, info in documents.items()
        if info["caption_table_gap"] > 2
    }
    state = {
        "generated_at": now(),
        "documents": len(rows),
        "totals": dict(totals),
        "documents_without_tables": [d for d, i in documents.items() if i["tables"] == 0],
        "caption_gap_over_2": flagged,
        "per_document": documents,
    }
    OUT.write_text(json.dumps(state, indent=2), "utf-8")

    print(f"nist tables: {totals['tables']} across {len(rows)} documents, "
          f"{totals['table_rows']} data rows kept")
    print(f"span offsets verified: {totals['span_offset_mismatches']} mismatches")
    print(f"documents with no ruled tables: {len(state['documents_without_tables'])}")
    print(f"documents where captions exceed tables by >2: {len(flagged)}")
    print(f"manifest: {OUT.relative_to(ROOT)}")
    return 1 if totals["span_offset_mismatches"] else 0


if __name__ == "__main__":
    sys.exit(main())