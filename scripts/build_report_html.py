"""Render the Track B technical report from its Markdown source to paginated HTML.

The submission bundle links the HTML as the "Master Report", and the per-CVE dossier
links into it, so the HTML is a derived artifact: it is never edited by hand, and every
number in it comes from the Markdown, which in turn is recomputed from data/evaluation.
Run this after every Markdown change.

    .venv/Scripts/python -m scripts.build_report_html
"""

from __future__ import annotations

import html
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "CyberShield_AI_Final_Technical_Report_Track_B.md"
DST = ROOT / "docs" / "CyberShield_AI_Final_Technical_Report_Track_B.html"

FOOTER_LEFT = "CyberShield AI · Track B Technical Capstone Report"
FOOTER_MIDDLE = "Executive Post Graduate Programme in Generative AI and Agentic AI"

# CyberShield_AI_Per_CVE_Audit_Dossier.html links "#empirical-benchmark" from ten places,
# a name that predates this generator, so that anchor stays as an alias on section 9.
ANCHOR_ALIASES = {"9": "empirical-benchmark"}

CSS = """:root {
  --ink: #172033;
  --muted: #5d687b;
  --line: #dce3ed;
  --blue: #1F497D;
  --pale: #f3f6fa;
  --accent: #0969da;
  --success: #1a7f37;
  --danger: #cf222e;
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  padding: 0;
  background: #eef2f7;
  color: var(--ink);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  font-size: 13.5px;
  line-height: 1.55;
}
.report-container {
  max-width: 980px;
  margin: 24px auto;
  background: white;
  box-shadow: 0 4px 20px rgba(0,0,0,0.08);
}
.report-page {
  padding: 44px 52px 60px;
  border-bottom: 2px solid #e1e7f0;
  min-height: 1050px;
  position: relative;
}
.page-footer {
  position: absolute;
  bottom: 18px;
  left: 52px;
  right: 52px;
  display: flex;
  justify-content: space-between;
  font-size: 11px;
  color: var(--muted);
  border-top: 1px solid var(--line);
  padding-top: 8px;
}
h1 {
  font-size: 21px;
  color: var(--blue);
  margin-top: 0;
  margin-bottom: 12px;
  line-height: 1.3;
}
h2 {
  font-size: 16.5px;
  color: var(--blue);
  border-bottom: 2px solid var(--blue);
  padding-bottom: 6px;
  margin-top: 22px;
  margin-bottom: 14px;
}
h3 {
  font-size: 14px;
  color: #274b7a;
  margin-top: 16px;
  margin-bottom: 8px;
}
h4 {
  font-size: 13px;
  color: var(--ink);
  margin-top: 12px;
  margin-bottom: 6px;
}
p {
  margin: 8px 0;
}
pre {
  background: #0f172a;
  color: #e2e8f0;
  padding: 12px 14px;
  border-radius: 6px;
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: 11.5px;
  line-height: 1.45;
  overflow-x: auto;
  margin: 10px 0;
}
code {
  background: #f1f5f9;
  color: #0f172a;
  padding: 2px 5px;
  border-radius: 4px;
  font-size: 12px;
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}
pre code {
  background: transparent;
  color: inherit;
  padding: 0;
}
table {
  width: 100%;
  border-collapse: collapse;
  margin: 12px 0 16px;
  font-size: 12px;
}
th {
  background: var(--pale);
  color: var(--blue);
  font-weight: 700;
  padding: 7px 10px;
  border: 1px solid var(--line);
  text-align: left;
}
td {
  padding: 7px 10px;
  border: 1px solid var(--line);
  vertical-align: top;
}
tr:nth-child(even) td {
  background: #fafcff;
}
ul, ol {
  padding-left: 20px;
  margin: 6px 0;
}
li {
  margin: 3px 0;
}
blockquote {
  border-left: 4px solid var(--blue);
  background: var(--pale);
  margin: 10px 0;
  padding: 8px 14px;
  border-radius: 0 8px 8px 0;
  font-size: 13px;
}
a {
  color: var(--accent);
  text-decoration: none;
  font-weight: 500;
}
a:hover {
  text-decoration: underline;
}
@media print {
  body {
    background: white;
  }
  .report-container {
    box-shadow: none;
    margin: 0;
    max-width: 100%;
  }
  .report-page {
    page-break-after: always;
    break-after: page;
    min-height: 100vh;
    padding: 36px 44px 50px;
    border-bottom: none;
  }
}"""

_HEADING = re.compile(r"^(#{1,6}) +(.*)$")
_LIST_ITEM = re.compile(r"^(\s*)([-*]|\d+\.) +(.*)$")
_TABLE_ROW = re.compile(r"^\s*\|.*\|\s*$")
_TABLE_SEP = re.compile(r"^\s*\|(\s*:?-+:?\s*\|)+\s*$")


def _inline(text: str) -> str:
    """Escape everything, then apply the small inline dialect this report uses.

    Code spans are lifted out behind sentinels first: emphasis that crosses a span,
    like ``**Layer 1 (``app/policy.py``)**``, only pairs if the markup pass sees the
    whole line.
    """
    lifted: list[str] = []

    def lift(match: re.Match) -> str:
        lifted.append(match.group(1))
        return "\x00%d\x01" % (len(lifted) - 1)

    marked = re.sub(r"`([^`]*)`", lift, text)
    rendered = html.escape(marked, quote=False)
    rendered = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", r'<a href="\2">\1</a>', rendered)
    rendered = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", rendered)
    rendered = re.sub(r"\*([^*\n]+)\*", r"<i>\1</i>", rendered)
    for number, span in enumerate(lifted):
        rendered = rendered.replace("\x00%d\x01" % number, "<code>" + html.escape(span) + "</code>")
    return rendered


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _render_list(lines: list[str], start: int) -> tuple[str, int]:
    """Render one consecutive list block, nesting deeper indents inside the item above."""
    items: list[list] = []
    i = start
    while i < len(lines):
        match = _LIST_ITEM.match(lines[i])
        if match:
            indent = len(match.group(1))
            items.append([indent, match.group(2)[0].isdigit(), match.group(3)])
        elif items and lines[i].strip() and lines[i][0] in " \t":
            items[-1][2] += " " + lines[i].strip()
        else:
            break
        i += 1

    base = items[0][0]
    index = 0

    def emit(depth: int) -> list[str]:
        nonlocal index
        ordered = items[index][1]
        parts: list[str] = []
        while index < len(items):
            indent, _, text = items[index]
            if indent < depth:
                break
            if indent > depth:
                nested = "".join(emit(indent))
                parts[-1] = parts[-1][: -len("</li>")] + nested + "</li>"
                continue
            index += 1
            parts.append(f"<li>{_inline(text)}</li>")
        tag = "ol" if ordered else "ul"
        return [f"<{tag}>\n" + "\n".join(parts) + f"\n</{tag}>"]

    rendered = emit(base)
    return "\n".join(rendered), i


def _blocks(markdown: str) -> list[tuple[str, object]]:
    lines = markdown.splitlines()
    blocks: list[tuple[str, object]] = []
    paragraph: list[str] = []
    i = 0

    def flush() -> None:
        if paragraph:
            blocks.append(("p", " ".join(paragraph)))
            paragraph.clear()

    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            flush()
            body: list[str] = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                body.append(lines[i])
                i += 1
            i += 1
            blocks.append(("pre", "\n".join(body)))
            continue
        heading = _HEADING.match(line)
        if heading:
            flush()
            blocks.append(("h%d" % len(heading.group(1)), heading.group(2).strip()))
            i += 1
            continue
        if _TABLE_ROW.match(line) and i + 1 < len(lines) and _TABLE_SEP.match(lines[i + 1]):
            flush()
            header = _cells(line)
            i += 2
            rows: list[list[str]] = []
            while i < len(lines) and _TABLE_ROW.match(lines[i]):
                rows.append(_cells(lines[i]))
                i += 1
            blocks.append(("table", (header, rows)))
            continue
        if _LIST_ITEM.match(line):
            flush()
            rendered, i = _render_list(lines, i)
            blocks.append(("list", rendered))
            continue
        if line.startswith(">"):
            flush()
            quote = [line.lstrip(">").strip()]
            i += 1
            while i < len(lines) and lines[i].startswith(">"):
                quote.append(lines[i].lstrip(">").strip())
                i += 1
            blocks.append(("quote", " ".join(part for part in quote if part)))
            continue
        if line.strip() == "---":
            flush()
            blocks.append(("hr", None))
            i += 1
            continue
        if not line.strip():
            flush()
            i += 1
            continue
        paragraph.append(line.strip())
        i += 1
    flush()
    return blocks


def _anchor(text: str) -> str:
    number = re.match(r"(\d+)\.", text)
    if number:
        key = number.group(1)
        return ' id="%s"' % ANCHOR_ALIASES.get(key, "sec-" + key)
    if text.lower().startswith("project repository"):
        return ' id="repository-links"'
    # The per-CVE dossier section headings are linked by CVE id from Section 9.4.
    cve = re.search(r"CVE-\d{4}-\d{4,7}", text)
    if cve:
        return ' id="%s"' % cve.group(0)
    return ""


def _render(kind: str, payload: object) -> str:
    if kind == "pre":
        return "<pre><code>" + html.escape(str(payload)) + "</code></pre>"
    if kind == "quote":
        return "<blockquote><p>" + _inline(str(payload)) + "</p></blockquote>"
    if kind == "list":
        return str(payload)
    if kind == "hr":
        return ""
    if kind == "table":
        header, rows = payload
        out = [
            "<table><tr>"
            + "".join("<th>%s</th>" % _inline(cell) for cell in header)  # type: ignore[union-attr]
            + "</tr>"
        ]
        for row in rows:  # type: ignore[union-attr]
            out.append(
                "<tr>" + "".join("<td>%s</td>" % _inline(cell) for cell in row) + "</tr>"
            )
        out.append("</table>")
        return "\n".join(out)
    if kind.startswith("h"):
        level = int(kind[1:])
        text = str(payload)
        anchor = _anchor(text) if level == 2 else ""
        return "<h%d%s>%s</h%d>" % (level, anchor, _inline(text), level)
    return "<p>" + _inline(str(payload)) + "</p>"


def render(markdown: str, footer_left: str, footer_middle: str) -> tuple[str, int]:
    blocks = _blocks(markdown)
    title = next(str(payload) for kind, payload in blocks if kind == "h1")

    # One page per level-2 section; the title block rides along with section 1.
    pages: list[list[str]] = [[]]
    for kind, payload in blocks:
        if kind == "h2" and any(part.startswith("<h2") for part in pages[-1]):
            pages.append([])
        pages[-1].append(_render(kind, payload))
    body = [[part for part in page if part] for page in pages]
    total = len(body)

    chunks: list[str] = []
    for number, page in enumerate(body, start=1):
        chunks.append(
            '    <div class="report-page" id="page-%d">\n%s\n'
            '      <div class="page-footer">\n'
            "        <span>%s</span>\n"
            "        <span>%s</span>\n"
            "        <span>Page %d of %d</span>\n"
            "      </div>\n"
            "    </div>"
            % (
                number,
                "\n".join("      " + part for part in page),
                footer_left,
                footer_middle,
                number,
                total,
            )
        )

    document = (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>%s</title>\n"
        "<style>\n%s\n</style>\n"
        "</head>\n"
        "<body>\n"
        '<div class="report-container">\n\n'
        "%s\n\n"
        "</div>\n"
        "</body>\n"
        "</html>\n" % (html.escape(title), CSS, "\n\n".join(chunks))
    )
    return document, total


def build() -> tuple[str, int]:
    return render(SRC.read_text(encoding="utf-8"), FOOTER_LEFT, FOOTER_MIDDLE)


def main() -> None:
    document, pages = build()
    DST.write_text(document, "utf-8", newline="\n")
    print(
        "[OK] wrote %s (%d pages, %s bytes) from %s"
        % (DST.relative_to(ROOT), pages, f"{len(document):,}", SRC.name)
    )


if __name__ == "__main__":
    main()
