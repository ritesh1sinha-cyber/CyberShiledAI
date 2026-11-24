import html
import re

from scripts.build_report_html import ANCHOR_ALIASES, DST, SRC, build

DOSSIER = SRC.parent / "CyberShield_AI_Per_CVE_Audit_Dossier.html"

RETRACTED_CLAIMS = [
    "100% defense rate (20/20 attacks blocked)",
    "Attack blocked (100% defense)",
    "CVSS accuracy from 20% to 100%",
    "semantic cosine similarity from 0.74 to 0.93",
    "100/100 Ground-Truth Claims Passed",
    "guaranteeing 100% verifiable accuracy",
]


def _markdown() -> str:
    return SRC.read_text(encoding="utf-8")


def _headings(text: str, level: int) -> list[str]:
    prefix = "#" * level + " "
    return [line[len(prefix) :].strip() for line in text.splitlines() if line.startswith(prefix)]


def test_the_html_is_exactly_what_the_markdown_renders_to():
    """The HTML is a derived artifact; a hand-edited copy would fail here, not drift silently."""
    rendered, _ = build()
    assert rendered == DST.read_text(encoding="utf-8")


def test_every_markdown_heading_reaches_the_html():
    rendered, _ = build()
    for level in (2, 3, 4):
        for heading in _headings(_markdown(), level):
            assert _plain(heading) in _plain(rendered), f"h{level} lost: {heading}"


def test_the_retracted_guardrail_and_score_claims_are_gone_from_both_files():
    rendered, _ = build()
    documents = {"markdown": _markdown(), "html": rendered}
    for name, text in documents.items():
        for claim in RETRACTED_CLAIMS:
            assert claim not in text, f"{name} still asserts {claim!r}"


def test_the_scorecard_table_in_section_9_1_is_the_artifact_s_arithmetic():
    """No typed number may sit in the five-configuration table.

    Row 4 of that table carried four invented constants for runs that produced no
    report, so the published mean read 0.3399 instead of the 0.5332 the six real
    answers score. The function the Streamlit benchmark tab reads now has to agree
    with the markdown, cell for cell.
    """
    import pytest

    from app.eval_dashboard import CONSOLIDATED_JSON, iteration_scorecard

    if not CONSOLIDATED_JSON.exists():
        pytest.fail("the report cites an evaluation artifact that is not on disk")
    text = _markdown()
    section = text[text.index("### 9.1") : text.index("### 9.2")]
    rows = [line for line in section.splitlines() if line.startswith("| **")]
    table = iteration_scorecard()
    assert len(rows) == len(table), f"{len(rows)} table rows against {len(table)} iterations"
    for line, row in zip(rows, table):
        cells = [cell.strip().replace("*", "") for cell in line.strip("|").split("|")]
        for index, key in ((1, "rouge1_f"), (2, "rouge2_f"), (3, "rougeL_f"), (4, "semantic_cosine")):
            stored = row[key]
            assert stored is not None, f"{cells[0]}: the artifact stores no {key}"
            assert cells[index] == f"{stored:.4f}", (
                f"{cells[0]} {key}: markdown says {cells[index]}, artifact says {stored:.4f}"
            )


def test_the_injection_section_reports_the_measured_layers():
    text = _markdown()
    start = text.index("### 12.1")
    section = text[start : text.index("### 12.2")]
    assert "1 of 20 complied" in section
    assert "5 blocked, 15 would have shipped" in section
    assert "RJ-10" in section


def test_a_section_reference_never_points_at_a_section_that_does_not_exist():
    numbers = {int(match.group(1)) for match in re.finditer(r"^## (\d+)\.", _markdown(), re.M)}
    cited = {int(match.group(1)) for match in re.finditer(r"Section (\d+)", _markdown())}
    assert cited <= numbers, f"cited sections missing: {sorted(cited - numbers)}"


def test_the_dossier_back_link_still_lands_somewhere():
    rendered, _ = build()
    if not DOSSIER.exists():
        return
    anchors = {
        match.group(1)
        for match in re.finditer(r"Track_B\.html#([a-z0-9-]+)", DOSSIER.read_text(encoding="utf-8"))
    }
    assert anchors <= set(ANCHOR_ALIASES.values()), f"dossier links to dead anchors: {sorted(anchors)}"
    for anchor in anchors:
        assert f'id="{anchor}"' in rendered


def test_no_markdown_syntax_survives_into_the_html():
    rendered, _ = build()
    body = rendered.split("</style>", 1)[1]
    assert "**" not in body
    assert "<p>|" not in body
    assert "`" not in re.sub(r"<code>.*?</code>", "", body, flags=re.S)


def _plain(fragment: str) -> str:
    stripped = re.sub(r"<[^>]+>", "", fragment).replace("**", "")
    return html.unescape(stripped).strip()
