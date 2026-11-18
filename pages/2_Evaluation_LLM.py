"""LLM evaluation dashboard: for one investigation, the gold claims and their sources,
the answer the agents produced, and the measured layers beside each claim."""

from __future__ import annotations

import streamlit as st

from app import eval_dashboard

st.set_page_config(page_title="CyberShield AI - LLM evaluation", layout="wide")

LAYER_NOTE = (
    "Four layers, never mixed up: the deterministic field check against the official "
    "source values is the only pass/fail authority; ROUGE and the embedding cosine "
    "describe surface and topic overlap; the LLM-as-judge column is a secondary opinion "
    "from Qwen3-8B, the same model family as the system under test."
)
BLANK_NOTE = (
    "A cell that reads \"not captured\" was empty in the run artifacts. Nothing on this "
    "page is filled in by hand or recomputed: the text comes from the frozen workbooks "
    "and the numbers from the scoring output of the same run."
)


@st.cache_data(show_spinner="Reading the answer columns")
def cached_table() -> list[dict]:
    return eval_dashboard.llm_table()


@st.cache_data(show_spinner="Reading the gold answer and the agent response")
def cached_detail(key: str) -> dict:
    return eval_dashboard.llm_detail(key)


@st.cache_data(show_spinner=False)
def cached_options() -> list[tuple[str, str]]:
    return eval_dashboard.options()


@st.cache_data(show_spinner=False)
def cached_elements(claim_id: str) -> dict:
    return eval_dashboard.claim_elements(claim_id)


def pairs(rows: list[list[str]]) -> None:
    if not rows:
        st.info(eval_dashboard.NOT_CAPTURED)
        return
    st.table([{"Field": label, "Value": value} for label, value in rows])


def download(label: str, payload: str, filename: str, mime: str, with_bom: bool = False) -> None:
    st.download_button(
        label,
        data=payload.encode("utf-8-sig" if with_bom else "utf-8"),
        file_name=filename,
        mime=mime,
    )


def render(section: dict, stem: str) -> None:
    st.subheader(section["heading"])
    if section.get("note"):
        st.caption(section["note"])
    if section["kind"] == "text":
        st.code(section["text"], language=None, wrap_lines=True)
    elif section["kind"] == "pairs":
        pairs(section["rows"])
    elif section["rows"]:
        st.dataframe(section["rows"], hide_index=True, width="stretch")
        download(
            "Download this table (CSV)",
            eval_dashboard.table_csv(section["rows"]),
            f"{stem}.csv",
            "text/csv",
            with_bom=True,
        )
    else:
        st.info(eval_dashboard.NO_TRACE)


def matching(rows: list[dict], needle: str) -> list[dict]:
    lowered = needle.strip().lower()
    if not lowered:
        return rows
    return [
        row
        for row in rows
        if any(lowered in str(value).lower() for value in row.values())
    ]


def section_rows(detail: dict, prefix: str) -> list[dict]:
    """The rows of the first table section whose heading starts with prefix."""
    for section in detail["sections"]:
        if section["kind"] == "table" and section["heading"].startswith(prefix):
            return section["rows"]
    return []


def totals(rows: list[dict], column: str) -> str:
    counts: dict[str, int] = {}
    for row in rows:
        counts[str(row[column])] = counts.get(str(row[column]), 0) + 1
    ranked = sorted(counts.items(), key=lambda item: -item[1])
    return ", ".join(f"{value} {label}" for label, value in ranked)


st.title("LLM evaluation dashboard")
st.caption(
    "For one investigation: the gold claims, the sources they were built from, the answer "
    "the agents published, and the measured layers next to each claim. " + LAYER_NOTE
)

missing = eval_dashboard.missing_artifacts()
if missing:
    st.error(
        "This view needs artifacts that are not in the working tree: "
        + ", ".join(path.relative_to(eval_dashboard.ROOT).as_posix() for path in missing)
    )
    st.stop()

st.caption(BLANK_NOTE)

rows = cached_table()
verdict_column = next(
    column for column in rows[0] if "Deterministic" in column and "(authority)" in column
)
claim_column = next((column for column in rows[0] if "claim result" in column), None)
st.caption(
    f"{len(rows)} rows. Verdict distribution over the authority column ({verdict_column}): "
    + totals(rows, verdict_column)
    + (f". Claim results: {totals(rows, claim_column)}." if claim_column else ".")
)

table_tab, detail_tab = st.tabs(["All rows", "One investigation in detail"])

with table_tab:
    needle = st.text_input("Filter rows containing", placeholder="CVE, PASS, Fail, CWE-89 …")
    shown = matching(rows, needle)
    st.caption(f"{len(shown)} of {len(rows)} rows.")
    st.dataframe(shown, hide_index=True, width="stretch", height=520)
    note, button = st.columns([3, 3])
    with note:
        st.caption(
            "The Markdown block below is paste-ready for the report; the CSV keeps the full "
            "multi-line text of every cell. Long answers are excerpted in the table - open "
            "an investigation in the other tab for the untruncated text."
        )
        preview = shown[:25]
        if len(shown) > len(preview):
            st.caption(f"Copy block shows the first {len(preview)} of {len(shown)} rows.")
        st.code(eval_dashboard.table_markdown(preview), language=None, wrap_lines=True)
    with button:
        download(
            "Download CSV",
            eval_dashboard.table_csv(shown),
            "llm_batch10.csv",
            "text/csv",
            with_bom=True,
        )

with detail_tab:
    options = cached_options()
    labels = dict(options)
    key = st.selectbox(
        "Investigation",
        [item for item, _ in options],
        format_func=lambda item: labels[item],
    )
    detail = cached_detail(key)
    st.subheader(detail["title"])
    st.caption(
        "Sources: "
        + ", ".join(
            path.relative_to(eval_dashboard.ROOT).as_posix()
            for path in eval_dashboard.BATCH10_SOURCES
        )
    )
    pairs(detail["meta"])
    for position, section in enumerate(detail["sections"]):
        render(section, f"llm_batch10_{key}_{position + 1}")
    st.subheader("What the claim judge found, element by element")
    st.caption(
        "The judge model only locates and quotes; the agreement score and verdict are "
        "computed in code from those quotes, and a quote that is not found in the answer "
        "counts against it."
    )
    claim_ids = [row["Claim ID"] for row in section_rows(detail, "The four measured layers, per gold claim")]
    claim_id = st.selectbox("Claim", claim_ids)
    found = cached_elements(claim_id)
    st.write(found["claim"]["gold_claim_text"])
    st.write("Required elements: " + ", ".join(found["required"]))
    if found["elements"]:
        st.dataframe(found["elements"], hide_index=True, width="stretch")
    else:
        st.info(eval_dashboard.NOT_CAPTURED)
    st.subheader("Copy this investigation for the report")
    markdown = eval_dashboard.detail_markdown(detail)
    st.caption(
        f"{len(markdown)} characters: the header fields and every section above, as one "
        "Markdown block. Nothing in it is written by hand."
    )
    download("Download as Markdown", markdown, f"llm_batch10_{key}.md", "text/markdown")
    with st.expander("Markdown block for pasting"):
        st.code(markdown, language=None, wrap_lines=True)
