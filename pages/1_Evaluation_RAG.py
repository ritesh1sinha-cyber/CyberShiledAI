"""RAG evaluation dashboard: for one investigation, what retrieval returned for each
gold claim, what the claim states, and the retrieval scores recorded for that row."""

from __future__ import annotations

import streamlit as st

from app import eval_dashboard

st.set_page_config(page_title="CyberShield AI - RAG evaluation", layout="wide")

BLANK_NOTE = (
    "A cell that reads \"not captured\" was empty in the run artifacts. Nothing on this "
    "page is filled in by hand, and nothing here is computed: every value is read from "
    "the frozen workbook, the scores file and the run traces."
)


@st.cache_data(show_spinner="Reading the retrieval columns")
def cached_table() -> list[dict]:
    return eval_dashboard.rag_table()


@st.cache_data(show_spinner="Reading the retrieved passages")
def cached_detail(key: str) -> dict:
    return eval_dashboard.rag_detail(key)


@st.cache_data(show_spinner=False)
def cached_options() -> list[tuple[str, str]]:
    return eval_dashboard.options()


def pairs(rows: list[list[str]]) -> None:
    if not rows:
        st.info(eval_dashboard.NOT_CAPTURED)
        return
    st.table([{"Field": label, "Value": value} for label, value in rows])


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


def exports(rows: list[dict], stem: str) -> None:
    note, button = st.columns([3, 3])
    with note:
        st.caption(
            f"{len(rows)} rows. The Markdown block below is paste-ready for the report; "
            "the CSV keeps the full multi-line text of every cell."
        )
    with button:
        download(
            "Download CSV",
            eval_dashboard.table_csv(rows),
            f"{stem}.csv",
            "text/csv",
            with_bom=True,
        )
    if not rows:
        st.info("No rows match the filter.")
        return
    preview = rows[:25]
    if len(rows) > len(preview):
        st.caption(f"Copy block shows the first {len(preview)} of {len(rows)} rows.")
    st.code(eval_dashboard.table_markdown(preview), language=None, wrap_lines=True)


def download(label: str, payload: str, filename: str, mime: str, with_bom: bool = False) -> None:
    st.download_button(
        label,
        data=payload.encode("utf-8-sig" if with_bom else "utf-8"),
        file_name=filename,
        mime=mime,
    )


st.title("RAG evaluation dashboard")
st.caption(
    "One investigation at a time: what each gold claim states, the passage retrieval "
    "actually returned for it, and the retrieval scores recorded for that row. The recall "
    "and support figures here are rules-only measures against the claim's own terms, not a "
    "judgement by a model."
)

missing = eval_dashboard.missing_artifacts()
if missing:
    st.error(
        "This view needs artifacts that are not in the working tree: "
        + ", ".join(path.relative_to(eval_dashboard.ROOT).as_posix() for path in missing)
    )
    st.stop()

st.caption(BLANK_NOTE)

table_tab, detail_tab = st.tabs(["All rows", "One investigation in detail"])

with table_tab:
    rows = cached_table()
    needle = st.text_input("Filter rows containing", placeholder="CVE, chunk id, pass, fail …")
    shown = matching(rows, needle)
    st.caption(f"{len(shown)} of {len(rows)} rows.")
    st.dataframe(shown, hide_index=True, width="stretch", height=520)
    exports(shown, "rag_batch10")

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
        render(section, f"rag_batch10_{key}_{position + 1}")
    st.subheader("Copy this investigation for the report")
    markdown = eval_dashboard.detail_markdown(detail)
    st.caption(
        f"{len(markdown)} characters: the header fields and every section above, as one "
        "Markdown block. Nothing in it is written by hand."
    )
    download("Download as Markdown", markdown, f"rag_batch10_{key}.md", "text/markdown")
    with st.expander("Markdown block for pasting"):
        st.code(markdown, language=None, wrap_lines=True)
