"""Extract and chunk the fetched NVD reference pages for retrieval.

Every document in data/raw/nvd_references is a snapshot copy of a page that
the NVD record itself cites. Each fetched URL maps to one or more CVEs, so
the CVE id is the natural partition key: reference-first retrieval only needs
the chunks of the investigated CVE's own references, ahead of the generic
corpus. The generic chunks.jsonl/index stay untouched so the frozen retrieval
benchmark remains reproducible.

HTML is reduced with the stdlib parser (project avoids adding packages);
PDFs reuse the table-aware app.pdf_extract extractor.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REF_DIR = ROOT / "data" / "raw" / "nvd_references"
INDEX_PATH = REF_DIR / "references_index.jsonl"
OUT_PATH = ROOT / "data" / "processed" / "reference_chunks.jsonl"
MANIFEST_PATH = ROOT / "data" / "manifests" / "nvd_reference_chunks.json"

TARGET_CHARS = 1800
MAX_CHARS = 2600
MIN_CHARS = 250
MIN_DOC_CHARS = 100

BLOCK_TAGS = {
    "p", "div", "li", "tr", "br", "table", "ul", "ol", "pre", "blockquote",
    "h1", "h2", "h3", "h4", "h5", "h6", "section", "article", "header",
    "footer", "aside", "dt", "dd", "form", "figure", "figcaption",
}
SKIP_TAGS = {"script", "style", "noscript", "template", "svg", "iframe"}


class PageText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.title_parts: list[str] = []
        self._skip_depth = 0
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in SKIP_TAGS:
            self._skip_depth += 1
        elif tag == "title":
            self._in_title = True
        elif tag in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "title":
            self._in_title = False
        elif tag in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        if self._skip_depth:
            return
        if self._in_title:
            self.title_parts.append(data)
        else:
            self.parts.append(data)


def normalize(text: str) -> str:
    lines = [re.sub(r"[ \t\xa0]+", " ", line).strip() for line in text.splitlines()]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def extract_html(path: Path) -> tuple[str, str]:
    parser = PageText()
    parser.feed(path.read_text(encoding="utf-8", errors="replace"))
    title = re.sub(r"\s+", " ", " ".join(parser.title_parts)).strip()
    return normalize("".join(parser.parts)), title


def extract_any(path: Path) -> tuple[str, str]:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        from app.pdf_extract import extract_pdf

        result = extract_pdf(str(path))
        return result["text"].strip(), result.get("metadata_title") or ""
    if suffix in {".html", ".htm", ".txt", ".json"}:
        text, title = extract_html(path) if suffix != ".txt" else (
            normalize(path.read_text(encoding="utf-8", errors="replace")), ""
        )
        return text, title
    text = path.read_text(encoding="utf-8", errors="replace")
    return normalize(text), ""


def split_paragraphs(text: str) -> list[str]:
    return [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]


def chunk_text(text: str) -> list[str]:
    if len(text) <= MAX_CHARS:
        return [text]
    pieces: list[str] = []
    for para in split_paragraphs(text):
        while len(para) > MAX_CHARS:
            cut = para.rfind(". ", TARGET_CHARS // 2, MAX_CHARS)
            cut = cut + 1 if cut > 0 else MAX_CHARS
            pieces.append(para[:cut].strip())
            para = para[cut:].strip()
        if para:
            pieces.append(para)
    chunks: list[str] = []
    current: list[str] = []
    size = 0
    for piece in pieces:
        if current and size + len(piece) + 2 > TARGET_CHARS:
            chunks.append("\n\n".join(current))
            current, size = [], 0
        current.append(piece)
        size += len(piece) + 2
    if current:
        tail = "\n\n".join(current)
        if len(tail) < MIN_CHARS and chunks:
            chunks[-1] += "\n\n" + tail
        else:
            chunks.append(tail)
    return chunks


def latest_ok_rows() -> list[dict]:
    rows: dict[str, dict] = {}
    with INDEX_PATH.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                rows[row["url"]] = row
    return [rows[url] for url in sorted(rows) if rows[url].get("status") == "ok"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()

    rows = latest_ok_rows()
    out_rows: list[dict] = []
    per_cve: dict[str, int] = {}
    too_short: list[str] = []
    missing: list[str] = []
    skipped_extract: list[dict] = []

    for row in rows:
        filename = row.get("filename")
        path = REF_DIR / filename if filename else None
        if not filename or not path or not path.exists():
            missing.append(row["url"])
            continue
        try:
            text, title = extract_any(path)
        except Exception as exc:
            skipped_extract.append({"url": row["url"], "error": f"{type(exc).__name__}: {exc}"})
            continue
        if len(text) < MIN_DOC_CHARS:
            too_short.append(row["url"])
            continue
        doc_id = f"NVDREF-{row['url_hash']}"
        title = (title or path.stem)[:200] or doc_id
        chunks = chunk_text(text)
        offset = 0
        for ordinal, chunk in enumerate(chunks):
            out_rows.append(
                {
                    "chunk_id": f"{doc_id}#{ordinal:03d}",
                    "doc_id": doc_id,
                    "source": "nvd_reference",
                    "cve_ids": row.get("cves") or [],
                    "url": row["url"],
                    "title": title,
                    "sha256": row.get("sha256"),
                    "tags": row.get("tags") or [],
                    "ordinal": ordinal,
                    "chunks_in_doc": len(chunks),
                    "text": chunk,
                    "start": offset,
                    "end": offset + len(chunk),
                    "chars": len(chunk),
                    "tokens_est": max(1, len(chunk) // 4),
                    "oversized": len(chunk) > MAX_CHARS,
                }
            )
            offset += len(chunk)
            for cve_id in row.get("cves") or []:
                per_cve[cve_id] = per_cve.get(cve_id, 0) + 1

    OUT_PATH.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in out_rows) + "\n",
        encoding="utf-8",
    )
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_index": str(INDEX_PATH.relative_to(ROOT)),
        "urls_ok": len(rows),
        "docs_chunked": len(rows) - len(too_short) - len(missing) - len(skipped_extract),
        "docs_too_short": len(too_short),
        "docs_missing_file": len(missing),
        "docs_extract_error": len(skipped_extract),
        "chunks_total": len(out_rows),
        "cves_covered": len(per_cve),
        "chunks_by_cve": dict(sorted(per_cve.items())),
        "detail": {
            "too_short_urls": too_short,
            "missing_files": missing,
            "extract_errors": skipped_extract,
        },
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(
        f"docs chunked={manifest['docs_chunked']}/{len(rows)} "
        f"too_short={len(too_short)} missing={len(missing)} extract_error={len(skipped_extract)}; "
        f"chunks={len(out_rows)} across {len(per_cve)} CVEs"
    )
    print(f"wrote {OUT_PATH}")
    print(f"wrote {MANIFEST_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
