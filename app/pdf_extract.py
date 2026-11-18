"""Table-aware PDF extraction for the retrieval corpus.

pypdf flattens a page into a single text stream, which destroys the column
structure of NIST's compliance tables (800-53B baselines, 800-171 mappings,
risk matrices). This module keeps every ruled table as a Markdown block in
reading order and records its character span so the chunker can keep tables
atomic instead of slicing a row in half.

Pipeline per page: find ruled tables, crop the page into the text bands above,
between and below them, clean both, and concatenate in vertical order. Every
table keeps its header row so a fragment is understandable on its own.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

import pdfplumber

# Rows/cols below these are layout artefacts (single-column "tables", stray boxes).
MIN_TABLE_ROWS = 2
MIN_TABLE_COLS = 2
MIN_TABLE_AREA = 900.0

# NIST draws cell borders as pairs of rules ~5pt apart. The default 3pt snap
# splits every column in two, so snap wide enough to collapse the pair.
TABLE_SETTINGS = {
    "vertical_strategy": "lines",
    "horizontal_strategy": "lines",
    "snap_tolerance": 6,
    "join_tolerance": 6,
    "intersection_tolerance": 6,
    "edge_min_length": 5,
}

PAGE_NUMBER_RE = re.compile(r"^(?:page\s*)?(?:\d{1,4}|[ivxlcdm]{1,6})$", re.IGNORECASE)
HYPHEN_BREAK_RE = re.compile(r"(?<=[a-z])-\s*\n\s*(?=[a-z])")


def _cell(value: object) -> str:
    if value is None:
        return ""
    text = unicodedata.normalize("NFKC", str(value))
    text = text.replace("\ufffd", "").replace("\u00ad", "")
    text = text.replace("\n", " ").replace("|", "\\|")
    return re.sub(r"\s+", " ", text).strip()


def _clean_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = text.replace("\ufffd", "").replace("\u00ad", "")
    text = HYPHEN_BREAK_RE.sub("", text)
    return "\n".join(re.sub(r"[ \t]+", " ", line).strip() for line in text.splitlines())


def _keep_table(table) -> bool:
    try:
        rows = table.rows or []
    except Exception:
        return False
    if len(rows) < MIN_TABLE_ROWS:
        return False
    widths = [len(row.cells) for row in rows]
    if not widths or max(widths) < MIN_TABLE_COLS:
        return False
    x0, top, x1, bottom = table.bbox
    return (x1 - x0) * (bottom - top) >= MIN_TABLE_AREA


def _render_table(table) -> tuple[str, list[str], int] | None:
    raw = [[_cell(c) for c in row] for row in (table.extract() or [])]
    raw = [row for row in raw if any(row)]
    if len(raw) < MIN_TABLE_ROWS:
        return None
    width = max(len(row) for row in raw)
    if width < MIN_TABLE_COLS:
        return None
    raw = [row + [""] * (width - len(row)) for row in raw]

    cells = table.rows[0].cells if table.rows else []
    for i, cell in enumerate(raw[0]):
        if i < len(cells) and cells[i] and _is_rotated(cells[i], cell):
            raw[0][i] = cell[::-1]

    header_rows, data_rows = _split_header(raw)
    if not data_rows:
        return None

    # Grid lines drawn for nested/shaded boxes add phantom columns; a column
    # with no data in any row carries nothing, so drop it and keep headers aligned.
    keep = [i for i in range(width) if any(row[i] for row in data_rows)]
    if len(keep) < MIN_TABLE_COLS:
        return None
    header = _merge_header(header_rows, keep)
    if not any(header):
        return None
    data_rows = [[row[i] for i in keep] for row in data_rows]
    lines = [
        "| " + " | ".join(header) + " |",
        "|" + "|".join([" --- "] * len(keep)) + "|",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in data_rows)
    return "\n".join(lines), header, len(data_rows)


def _split_header(rows: list[list[str]]) -> tuple[list[list[str]], list[list[str]]]:
    header = [rows[0]]
    start = 1
    while start < len(rows) and len(header) < 3 and _looks_like_header(rows[start]):
        header.append(rows[start])
        start += 1
    return header, rows[start:]


def _looks_like_header(row: list[str]) -> bool:
    """Wrapped header rows are short labels; data rows carry long text or ids."""
    if any(len(cell) > 40 for cell in row):
        return False
    if row[0] and any(char.isdigit() for char in row[0]):
        return False
    return True


def _merge_header(header_rows: list[list[str]], keep: list[int]) -> list[str]:
    merged = []
    for i in keep:
        parts: list[str] = []
        for row in header_rows:
            value = row[i]
            if value and value not in parts:
                parts.append(value)
        merged.append(" ".join(parts))
    return merged


def _is_rotated(bbox, text: str) -> bool:
    """Rotated labels are laid out bottom-up, so extraction returns them reversed."""
    if sum(char.isalpha() for char in text) < 4:
        return False
    width = bbox[2] - bbox[0]
    height = bbox[3] - bbox[1]
    return width > 0 and height / width >= 2.5


def _page_blocks(page) -> list[dict]:
    """Split a page into text bands and rendered tables, top to bottom."""
    tables = []
    if len(page.horizontal_edges) >= 2 and len(page.vertical_edges) >= 2:
        try:
            tables = [t for t in page.find_tables(TABLE_SETTINGS) if _keep_table(t)]
        except Exception:
            tables = []
    tables.sort(key=lambda t: t.bbox[1])

    x0, page_top, x1, page_bottom = page.bbox
    blocks: list[dict] = []
    cursor = page_top

    def add_band(top: float, bottom: float) -> None:
        if bottom - top < 2:
            return
        try:
            text = page.crop((x0, top, x1, bottom)).extract_text() or ""
        except Exception:
            return
        text = _clean_text(text).strip()
        if text:
            blocks.append({"kind": "text", "text": text})

    for table in tables:
        _, top, _, bottom = table.bbox
        add_band(cursor, top - 1)
        rendered = _render_table(table)
        if rendered is not None:
            markdown, header, rows = rendered
            blocks.append({"kind": "table", "markdown": markdown, "header": header, "rows": rows})
        cursor = bottom + 1
    add_band(cursor, page_bottom)
    return blocks


def _running_lines(page_texts: list[str], pages: int) -> set[str]:
    """Keys of lines that repeat in the header/footer zone of many pages."""
    counts: dict[str, int] = {}
    for text in page_texts:
        lines = [line for line in text.splitlines() if line.strip()]
        zone = lines[:2] + lines[-2:]
        for line in dict.fromkeys(zone):
            if line.startswith("|"):
                continue
            key = re.sub(r"\d+", "#", line.strip().lower())
            counts[key] = counts.get(key, 0) + 1
    threshold = max(4, int(0.2 * max(pages, 1)))
    return {key for key, count in counts.items() if count >= threshold}


def _strip_running(text: str, repeated: set[str]) -> str:
    lines = text.splitlines()
    filled = [i for i, line in enumerate(lines) if line.strip()]
    zone = set(filled[:2]) | set(filled[-2:])
    kept = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if i in zone and stripped and not stripped.startswith("|"):
            key = re.sub(r"\d+", "#", stripped.lower())
            if key in repeated or PAGE_NUMBER_RE.match(stripped):
                continue
        kept.append(line)
    return "\n".join(kept).strip("\n")


def _render_page(blocks: list[dict], repeated: set[str]) -> tuple[str, list[dict]]:
    pieces: list[str] = []
    tables: list[dict] = []
    length = 0

    def add(text: str) -> tuple[int, int]:
        nonlocal length
        if length:
            length += 2
        start = length
        pieces.append(text)
        length += len(text)
        return start, length

    for block in blocks:
        if block["kind"] == "text":
            text = _strip_running(block["text"], repeated)
            if text.strip():
                add(text)
            continue
        start, end = add(block["markdown"])
        tables.append(
            {
                "rows": block["rows"],
                "cols": len(block["header"]),
                "start": start,
                "end": end,
                "header": block["header"][:8],
            }
        )
    return "\n\n".join(pieces), tables


def extract_pdf(path: str | Path) -> dict:
    """Extract reading-order text with tables preserved as Markdown."""
    path = Path(path)
    page_texts: list[str] = []
    pages: list[list[dict]] = []

    with pdfplumber.open(str(path)) as pdf:
        total_pages = len(pdf.pages)
        for page in pdf.pages:
            blocks = _page_blocks(page)
            pages.append(blocks)
            page_texts.append("\n".join(b["text"] for b in blocks if b["kind"] == "text"))
        title_meta = (pdf.metadata or {}).get("Title") or ""

        repeated = _running_lines(page_texts, total_pages)

        chunks: list[str] = []
        table_spans: list[dict] = []
        length = 0
        for page_no in range(1, total_pages + 1):
            page_text, rel_tables = _render_page(pages[page_no - 1], repeated)
            if not page_text:
                continue
            if length:
                length += 2
            base = length
            chunks.append(page_text)
            length += len(page_text)
            for table in rel_tables:
                table["page"] = page_no
                table["start"] += base
                table["end"] += base
                table_spans.append(table)

    text = "\n\n".join(chunks).strip()
    return {
        "text": text,
        "pages": total_pages,
        "metadata_title": str(title_meta).strip(),
        "tables": table_spans,
        "stats": {
            "chars": len(text),
            "table_count": len(table_spans),
            "pages_with_tables": len({t["page"] for t in table_spans}),
            "running_lines_removed": len(repeated),
        },
    }
