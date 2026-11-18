"""Download NIST guidance PDFs and extract their text for the retrieval corpus.

Only the NIST slice of the corpus is PDF-based; ATT&CK, OWASP and CWE already
come from structured snapshots. Extraction keeps ruled tables as Markdown
blocks (see app/pdf_extract.py) so compliance baselines and risk matrices keep
their column meaning. Every file is hashed and every page count recorded so the
corpus manifest can be audited.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import httpx

from app.pdf_extract import extract_pdf

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw" / "nist"
PROC = ROOT / "data" / "processed"
MAN = ROOT / "data" / "manifests"
PART = PROC / "nist_docs.part.jsonl"

SP = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.{}.pdf"
LEGACY = "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication{}.pdf"
CSWP = "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.{}.pdf"

PUBLICATIONS = [
    ("NIST-SP-800-30r1", LEGACY.format("800-30r1")),
    ("NIST-SP-800-37r2", SP.format("SP.800-37r2")),
    ("NIST-SP-800-39", LEGACY.format("800-39")),
    ("NIST-SP-800-40r4", SP.format("SP.800-40r4")),
    ("NIST-SP-800-41r1", LEGACY.format("800-41r1")),
    ("NIST-SP-800-52r2", SP.format("SP.800-52r2")),
    ("NIST-SP-800-53r5", SP.format("SP.800-53r5")),
    ("NIST-SP-800-53Ar5", SP.format("SP.800-53Ar5")),
    ("NIST-SP-800-53B", SP.format("SP.800-53B")),
    ("NIST-SP-800-57pt1r5", SP.format("SP.800-57pt1r5")),
    ("NIST-SP-800-61r3", SP.format("SP.800-61r3")),
    ("NIST-SP-800-63B-4", SP.format("SP.800-63b-4")),
    ("NIST-SP-800-77r1", SP.format("SP.800-77r1")),
    ("NIST-SP-800-82r3", SP.format("SP.800-82r3")),
    ("NIST-SP-800-92", LEGACY.format("800-92")),
    ("NIST-SP-800-115", LEGACY.format("800-115")),
    ("NIST-SP-800-123", LEGACY.format("800-123")),
    ("NIST-SP-800-125", LEGACY.format("800-125")),
    ("NIST-SP-800-128", SP.format("SP.800-128")),
    ("NIST-SP-800-137", LEGACY.format("800-137")),
    ("NIST-SP-800-144", LEGACY.format("800-144")),
    ("NIST-SP-800-145", LEGACY.format("800-145")),
    ("NIST-SP-800-153", LEGACY.format("800-153")),
    ("NIST-SP-800-160v1r1", SP.format("SP.800-160v1r1")),
    ("NIST-SP-800-161r1", SP.format("SP.800-161r1")),
    ("NIST-SP-800-171r3", SP.format("SP.800-171r3")),
    ("NIST-SP-800-172", SP.format("SP.800-172")),
    ("NIST-SP-800-183", SP.format("SP.800-183")),
    ("NIST-SP-800-190", SP.format("SP.800-190")),
    ("NIST-SP-800-204", SP.format("SP.800-204")),
    ("NIST-SP-800-207", SP.format("SP.800-207")),
    ("NIST-SP-800-210", SP.format("SP.800-210")),
    ("NIST-SP-800-215", SP.format("SP.800-215")),
    ("NIST-SP-800-218", SP.format("SP.800-218")),
    ("NIST-SP-800-233", SP.format("SP.800-233")),
    ("NIST-CSF-2.0", CSWP.format("CSWP.29")),
    ("NIST-CSWP-30", CSWP.format("CSWP.30")),
]


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(client: httpx.Client, doc_id: str, url: str) -> Path:
    path = RAW / f"{doc_id}.pdf"
    if path.exists() and path.stat().st_size > 1000:
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".part")
    with client.stream("GET", url) as resp:
        resp.raise_for_status()
        if "pdf" not in resp.headers.get("content-type", ""):
            raise ValueError(f"{doc_id}: not a PDF ({resp.headers.get('content-type')})")
        with open(tmp, "wb") as handle:
            for chunk in resp.iter_bytes(65536):
                handle.write(chunk)
    tmp.replace(path)
    return path


def derive_title(metadata_title: str, text: str, doc_id: str) -> str:
    title = metadata_title.strip()
    if len(title) < 8:
        for line in text.splitlines():
            line = line.strip()
            if (
                len(line) >= 12
                and not line.startswith("|")
                and not line.lower().startswith(("nist", "special publication"))
            ):
                title = line
                break
    return (title or doc_id)[:200]


def build_row(doc_id: str, url: str, path: Path) -> dict:
    result = extract_pdf(path)
    text = result["text"]
    if len(text) < 500:
        raise ValueError(f"{doc_id}: extracted only {len(text)} characters")
    spans = [
        {
            "page": table["page"],
            "start": table["start"],
            "end": table["end"],
            "rows": table["rows"],
            "cols": table["cols"],
        }
        for table in result["tables"]
    ]
    return {
        "doc_id": doc_id,
        "title": derive_title(result["metadata_title"], text, doc_id),
        "text": text,
        "char_count": len(text),
        "pages": result["pages"],
        "tables": spans,
        "table_count": len(spans),
        "pages_with_tables": result["stats"]["pages_with_tables"],
        "sha256": sha256(path),
        "source_url": url,
    }


def load_partial() -> dict[str, dict]:
    if not PART.exists():
        return {}
    rows = {}
    for line in PART.read_text("utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            rows[row["doc_id"]] = row
    return rows


def process_doc(item: tuple[str, str]) -> dict:
    doc_id, url = item
    with httpx.Client(follow_redirects=True, timeout=300.0) as client:
        path = download(client, doc_id, url)
    return build_row(doc_id, url, path)


def report(row: dict) -> None:
    print(
        f"  {row['doc_id']:<24} {row['pages']:>4} pages "
        f"{row['char_count']:>8} chars {row['table_count']:>4} tables  "
        f"{row['title'][:54]}",
        flush=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--only", help="comma-separated doc_ids to extract without writing outputs"
    )
    parser.add_argument(
        "--resume", action="store_true", help="reuse documents already in the partial file"
    )
    parser.add_argument(
        "--workers", type=int, default=3, help="parallel extraction processes"
    )
    args = parser.parse_args()

    selected = [d.strip() for d in args.only.split(",")] if args.only else None
    known = {doc_id for doc_id, _ in PUBLICATIONS}
    unknown = [d for d in selected or [] if d not in known]
    if unknown:
        print(f"unknown doc ids: {', '.join(unknown)}")
        return 2

    PROC.mkdir(parents=True, exist_ok=True)
    rows = load_partial() if (args.resume and not selected) else {}
    manifest = {"generated_at": now(), "documents": {}, "count": 0}
    failures = []
    paths: dict[str, Path] = {}

    pending = [
        (doc_id, url)
        for doc_id, url in PUBLICATIONS
        if doc_id not in rows and (not selected or doc_id in selected)
    ]
    for doc_id in rows:
        paths[doc_id] = RAW / f"{doc_id}.pdf"

    part = open(PART, "a", encoding="utf-8") if not selected else None
    try:
        if args.workers > 1 and len(pending) > 1:
            with ProcessPoolExecutor(max_workers=args.workers) as pool:
                futures = {pool.submit(process_doc, item): item for item in pending}
                for future in as_completed(futures):
                    doc_id = futures[future][0]
                    try:
                        row = future.result()
                    except Exception as exc:
                        failures.append((doc_id, str(exc)))
                        print(f"  {doc_id:<24} FAILED {exc}", flush=True)
                        continue
                    rows[doc_id] = row
                    if part is not None:
                        part.write(json.dumps(row, ensure_ascii=False) + "\n")
                        part.flush()
                    report(row)
        else:
            for doc_id, url in pending:
                try:
                    row = process_doc((doc_id, url))
                except Exception as exc:
                    failures.append((doc_id, str(exc)))
                    print(f"  {doc_id:<24} FAILED {exc}", flush=True)
                    continue
                rows[doc_id] = row
                if part is not None:
                    part.write(json.dumps(row, ensure_ascii=False) + "\n")
                    part.flush()
                report(row)
    finally:
        if part is not None:
            part.close()

    if selected:
        print()
        print(f"validation run: {len(rows)} documents, {len(failures)} failures")
        return 1 if failures else 0

    ordered = [rows[doc_id] for doc_id, _ in PUBLICATIONS if doc_id in rows]
    for row in ordered:
        path = paths.get(row["doc_id"], RAW / f"{row['doc_id']}.pdf")
        manifest["documents"][row["doc_id"]] = {
            "url": row["source_url"],
            "sha256": row["sha256"],
            "pages": row["pages"],
            "chars": row["char_count"],
            "bytes": path.stat().st_size if path.exists() else None,
            "tables": row["table_count"],
            "pages_with_tables": row["pages_with_tables"],
        }

    out = PROC / "nist_docs.jsonl"
    with open(out, "w", encoding="utf-8") as handle:
        for row in ordered:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    PART.unlink(missing_ok=True)

    manifest.update(
        count=len(ordered),
        failures=failures,
        total_pages=sum(r["pages"] for r in ordered),
        total_chars=sum(r["char_count"] for r in ordered),
        total_tables=sum(r["table_count"] for r in ordered),
    )
    MAN.mkdir(parents=True, exist_ok=True)
    (MAN / "nist.json").write_text(json.dumps(manifest, indent=2), "utf-8")

    print()
    print(
        f"nist: {len(ordered)} documents, {manifest['total_pages']} pages, "
        f"{manifest['total_chars'] / 1e6:.1f}M characters, "
        f"{manifest['total_tables']} tables, {len(failures)} failures"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
