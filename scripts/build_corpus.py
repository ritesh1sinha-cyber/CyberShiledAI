"""Clean the four snapshots and cut them into table-safe retrieval chunks.

Chunking rules, all enforced in code rather than left to the model:
  * a Markdown table is atomic: it is never split and never repeated as overlap;
  * ATT&CK and CWE are short structured records, so one document is one chunk
    unless it exceeds the size cap;
  * OWASP is split on Markdown headings, NIST on numbered/uppercase headings,
    and each chunk carries its heading so a fragment stays self-describing;
  * chunks target ~450 tokens (chars / 4) with a small paragraph overlap.
"""

from __future__ import annotations

import json
import math
import re
import sys
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROC = ROOT / "data" / "processed"
MAN = ROOT / "data" / "manifests"

TARGET_CHARS = 1800
MAX_CHARS = 2600
MIN_CHARS = 250
OVERLAP_CHARS = 400

CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MD_HEADING_RE = re.compile(r"^(#{1,4})\s+(.+)$")
NIST_HEADING_RE = re.compile(r"^(?:\d+(?:\.\d+)*|[A-Z]{2,}(?:-\d+)?)\s+[A-Z0-9][A-Z0-9 ,\-/&():.]{4,}$")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "")
    text = text.replace("\ufffd", "").replace("\u00ad", "")
    text = text.replace("\u200b", "").replace("\u200e", "").replace("\u200f", "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = CONTROL_RE.sub("", text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def clean_attack(text: str) -> str:
    text = CITATION_RE.sub("", text)
    text = MD_LINK_RE.sub(r"\1", text)
    return re.sub(r"\s+([.,;])", r"\1", clean_text(text))


def parse_mitigations(raw: str) -> list[tuple[str, str]]:
    """Turn ``::PHASE:x:DESCRIPTION:y::`` markup into (phase, description) pairs."""
    out: list[tuple[str, str]] = []
    for part in (raw or "").split("::PHASE:")[1:]:
        if ":DESCRIPTION:" not in part:
            continue
        phase, desc = part.split(":DESCRIPTION:", 1)
        if desc.endswith("::"):
            desc = desc[:-2]
        desc = clean_text(desc)
        if desc:
            out.append((clean_text(phase), desc))
    return out


def attack_document(row: dict) -> str:
    lines = [f"{row['technique_id']} {row['name']}"]
    if row.get("tactics"):
        lines.append("Tactics: " + ", ".join(row["tactics"]))
    if row.get("platforms"):
        lines.append("Platforms: " + ", ".join(row["platforms"]))
    if row.get("is_subtechnique"):
        lines.append("Type: sub-technique")
    lines.append("")
    lines.append(clean_attack(row.get("description", "")))
    return "\n".join(lines)


def cwe_document(row: dict) -> str:
    lines = [f"{row['cwe_id']} {row['name']}"]
    if row.get("description"):
        lines += ["", "Description: " + clean_text(row["description"])]
    if row.get("extended_description"):
        lines += ["", "Extended description: " + clean_text(row["extended_description"])]
    mitigations = parse_mitigations(row.get("mitigations", ""))
    if mitigations:
        lines += ["", "Potential mitigations:"]
        lines += [f"- {phase or 'General'}: {desc}" for phase, desc in mitigations]
    return "\n".join(lines)


def owasp_document(row: dict) -> str:
    text = HTML_COMMENT_RE.sub("", row.get("text", ""))
    return clean_text(text)


def split_paragraphs(text: str) -> list[tuple[int, int, str]]:
    blocks = []
    pos = 0
    for match in re.finditer(r"\n{2,}", text):
        segment = text[pos : match.start()]
        if segment.strip():
            blocks.append((pos, match.start(), segment))
        pos = match.end()
    if text[pos:].strip():
        blocks.append((pos, len(text), text[pos:]))
    return blocks


def split_sentences(text: str, limit: int) -> list[str]:
    parts: list[str] = []
    current = ""
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        if current and len(current) + 1 + len(sentence) > limit:
            parts.append(current)
            current = sentence
        else:
            current = f"{current} {sentence}".strip()
        while len(current) > limit:
            cut = current.rfind(" ", 0, limit)
            cut = cut if cut > limit // 2 else limit
            parts.append(current[:cut].rstrip())
            current = current[cut:].lstrip()
    if current:
        parts.append(current)
    return parts


def split_table(markdown: str, limit: int) -> list[str]:
    """Split a wide table by rows, repeating the header so every part reads alone."""
    lines = markdown.splitlines()
    if len(lines) < 3:
        return [markdown]
    head, separator, rows = lines[0], lines[1], lines[2:]
    budget = limit - len(head) - len(separator) - 2
    parts, current, size = [], [], 0
    for row in rows:
        if current and size + len(row) + 1 > budget:
            parts.append("\n".join([head, separator] + current))
            current, size = [], 0
        current.append(row)
        size += len(row) + 1
    if current:
        parts.append("\n".join([head, separator] + current))
    return parts or [markdown]


def split_long(blocks: list[tuple[int, int, str]], limit: int) -> list[tuple[int, int, str]]:
    out = []
    for start, end, segment in blocks:
        if len(segment) <= limit or is_table(segment):
            out.append((start, end, segment))
            continue
        out.extend((start, end, piece) for piece in split_sentences(segment, limit))
    return out


def is_table(segment: str) -> bool:
    lines = [line for line in segment.splitlines() if line.strip()]
    return len(lines) >= 2 and lines[0].lstrip().startswith("|")


def is_nist_heading(segment: str) -> bool:
    line = segment.strip()
    if "\n" in line or len(line) > 110:
        return False
    if NIST_HEADING_RE.match(line):
        return True
    letters = [c for c in line if c.isalpha()]
    return len(letters) >= 4 and sum(c.isupper() for c in letters) / len(letters) > 0.85


def owasp_sections(text: str) -> list[tuple[str, str]]:
    matches = list(MD_HEADING_RE.finditer(text))
    if not matches:
        return [("", text)]
    sections = []
    if text[: matches[0].start()].strip():
        sections.append(("", text[: matches[0].start()]))
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[match.end() : end].strip()
        if body:
            sections.append((match.group(2).strip(), body))
    return sections


def pack(
    blocks: list[tuple[int, int, str]],
    base: int = 0,
    prefix: str = "",
) -> list[dict]:
    """Greedy pack paragraphs into chunks; tables are atomic and never overlapped."""
    blocks = split_long(blocks, MAX_CHARS)
    chunks: list[dict] = []
    current: list[dict] = []
    size = 0

    def flush() -> None:
        nonlocal current, size
        if not current:
            return
        body = "\n\n".join(b["text"] for b in current)
        text = f"{prefix}\n\n{body}".strip() if prefix else body
        chunks.append(
            {
                "text": text,
                "start": current[0]["start"],
                "end": current[-1]["end"],
                "has_table": any(b["table"] for b in current),
                "oversized": len(text) > MAX_CHARS,
            }
        )
        tail = next((b for b in reversed(current) if not b["table"]), None)
        current = [tail] if tail and len(tail["text"]) <= OVERLAP_CHARS else []
        size = sum(len(b["text"]) for b in current)

    for start, end, segment in blocks:
        block = {
            "text": segment.strip(),
            "start": base + start,
            "end": base + end,
            "table": is_table(segment),
        }
        if block["table"] and len(block["text"]) > MAX_CHARS:
            flush()
            for part in split_table(block["text"], MAX_CHARS):
                current = [{**block, "text": part}]
                size = len(part)
                flush()
            current, size = [], 0
            continue
        if size and size + len(block["text"]) > TARGET_CHARS:
            flush()
        current.append(block)
        size += len(block["text"])
    flush()

    cleaned = []
    for chunk in chunks:
        if len(chunk["text"]) < MIN_CHARS and cleaned:
            merged = cleaned.pop()
            merged["text"] += "\n\n" + chunk["text"]
            merged["end"] = chunk["end"]
            merged["has_table"] |= chunk["has_table"]
            merged["oversized"] = len(merged["text"]) > MAX_CHARS
            chunk = merged
        cleaned.append(chunk)
    return cleaned


def chunk_structured(row: dict, text: str) -> list[dict]:
    paragraphs = split_paragraphs(text)
    if len(text) <= MAX_CHARS:
        return [
            {
                "text": text,
                "start": 0,
                "end": len(text),
                "has_table": any(is_table(p[2]) for p in paragraphs),
                "oversized": False,
            }
        ]
    chunks = []
    for section in split_at_size(paragraphs, MAX_CHARS):
        chunks.extend(pack(section))
    return chunks


def split_at_size(blocks: list[tuple[int, int, str]], limit: int) -> list[list[tuple[int, int, str]]]:
    groups, current, size = [], [], 0
    for block in blocks:
        if current and size + len(block[2]) > limit:
            groups.append(current)
            current, size = [], 0
        current.append(block)
        size += len(block[2])
    if current:
        groups.append(current)
    return groups


def chunk_owasp(row: dict) -> list[dict]:
    text = owasp_document(row)
    chunks = []
    for heading, body in owasp_sections(text):
        offset = text.find(body)
        title = (row["title"] or "")[:100]
        prefix = f"{title} - {heading}" if heading else title
        chunks.extend(pack(split_paragraphs(body), base=max(offset, 0), prefix=prefix))
    return chunks


def chunk_nist(row: dict, spans: list[tuple[int, int]]) -> list[dict]:
    text = clean_text(row["text"])
    blocks = split_paragraphs(text)
    chunks = []
    section = ""
    group: list[tuple[int, int, str]] = []
    split_spans = 0
    for span_start, span_end in spans:
        if not any(a <= span_start and span_end <= b for a, b, _ in blocks):
            split_spans += 1

    def flush_group() -> None:
        nonlocal group
        if group:
            title = (row["title"] or "")[:100]
            chunks.extend(pack(group, prefix=f"{title} - {section}" if section else title))
            group = []

    for block in blocks:
        if is_nist_heading(block[2]):
            flush_group()
            section = block[2].strip()
            continue
        group.append(block)
    flush_group()
    if split_spans:
        raise SystemExit(f"{row['doc_id']}: {split_spans} table spans cross a paragraph boundary")
    return chunks


def doc_title(row: dict, source: str) -> str:
    if source == "attack":
        return f"{row['technique_id']} {row['name']}"
    if source == "cwe":
        return f"{row['cwe_id']} {row['name']}"
    return row.get("title") or row["doc_id"]


def load(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


MIN_DOC_CHARS = 100


def source_content(source: str, row: dict) -> str:
    """Same text the corpus gate measures, so both scripts agree on what is empty."""
    if source == "attack":
        return "\n".join([row.get("name", ""), row.get("description", "")])
    if source == "cwe":
        return "\n".join(
            row.get(key, "")
            for key in ("name", "description", "extended_description", "mitigations")
        )
    return row.get("text", "")


def main() -> int:
    sources = {
        "attack": load(PROC / "attack_techniques.jsonl"),
        "cwe": load(PROC / "cwe.jsonl"),
        "owasp": load(PROC / "owasp_docs.jsonl"),
        "nist": load(PROC / "nist_docs.jsonl"),
    }

    records = []
    for row in sources["attack"]:
        if len(source_content("attack", row).strip()) < MIN_DOC_CHARS:
            continue
        for chunk in chunk_structured(row, attack_document(row)):
            records.append((row, chunk, "attack"))
    for row in sources["cwe"]:
        if len(source_content("cwe", row).strip()) < MIN_DOC_CHARS:
            continue
        for chunk in chunk_structured(row, cwe_document(row)):
            records.append((row, chunk, "cwe"))
    for row in sources["owasp"]:
        if len(source_content("owasp", row).strip()) < MIN_DOC_CHARS:
            continue
        for chunk in chunk_owasp(row):
            records.append((row, chunk, "owasp"))
    for row in sources["nist"]:
        if len(source_content("nist", row).strip()) < MIN_DOC_CHARS:
            continue
        spans = [(t["start"], t["end"]) for t in row.get("tables", [])]
        for chunk in chunk_nist(row, spans):
            records.append((row, chunk, "nist"))

    out_path = PROC / "chunks.jsonl"
    per_doc_totals: Counter = Counter()
    prepared = []
    for row, chunk, source in records:
        per_doc_totals[row["doc_id"]] += 1
        prepared.append((row, chunk, source))

    stats: Counter = Counter()
    sizes = []
    with open(out_path, "w", encoding="utf-8") as handle:
        counters: Counter = Counter()
        for row, chunk, source in prepared:
            ordinal = counters[row["doc_id"]]
            counters[row["doc_id"]] += 1
            record = {
                "chunk_id": f"{row['doc_id']}#{ordinal:03d}",
                "doc_id": row["doc_id"],
                "source": source,
                "title": doc_title(row, source),
                "ordinal": ordinal,
                "chunks_in_doc": per_doc_totals[row["doc_id"]],
                "text": chunk["text"],
                "start": chunk["start"],
                "end": chunk["end"],
                "chars": len(chunk["text"]),
                "tokens_est": math.ceil(len(chunk["text"]) / 4),
                "has_table": chunk["has_table"],
                "oversized": chunk["oversized"],
            }
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            stats[source] += 1
            sizes.append(record["chars"])
            if record["has_table"]:
                stats["table_chunks"] += 1
            if record["oversized"]:
                stats["oversized"] += 1

    sizes.sort()
    manifest = {
        "generated_at": now(),
        "documents": len(per_doc_totals),
        "chunks": sum(stats[s] for s in ("attack", "cwe", "owasp", "nist")),
        "per_source": {s: stats[s] for s in ("attack", "cwe", "owasp", "nist")},
        "chunks_per_doc": round(len(sizes) / max(len(per_doc_totals), 1), 2),
        "table_chunks": stats["table_chunks"],
        "oversized_chunks": stats["oversized"],
        "chars": {
            "p50": sizes[len(sizes) // 2],
            "p95": sizes[int(len(sizes) * 0.95)],
            "max": sizes[-1],
        },
        "params": {
            "target_chars": TARGET_CHARS,
            "max_chars": MAX_CHARS,
            "min_chars": MIN_CHARS,
            "overlap_chars": OVERLAP_CHARS,
        },
    }
    MAN.mkdir(parents=True, exist_ok=True)
    (MAN / "chunks.json").write_text(json.dumps(manifest, indent=2), "utf-8")

    print(f"chunks: {manifest['chunks']} from {manifest['documents']} documents")
    for source in ("attack", "cwe", "owasp", "nist"):
        print(f"  {source:<7} {stats[source]:>5}")
    print(
        f"  table chunks {stats['table_chunks']}, oversized {stats['oversized']}, "
        f"chars p50 {manifest['chars']['p50']} p95 {manifest['chars']['p95']} "
        f"max {manifest['chars']['max']}"
    )
    print(f"  -> {out_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())