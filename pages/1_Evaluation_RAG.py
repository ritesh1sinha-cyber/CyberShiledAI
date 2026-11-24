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


@st.cache_data(show_spinner="Measuring the retrieval benchmark")
def cached_benchmark() -> dict:
    return eval_dashboard.retrieval_metrics()


def pairs(rows: list[list[str]]) -> None:
    if not rows:
        st.info(eval_dashboard.NOT_CAPTURED)
        return
    st.table([{"Field": label, "Value": value} for label, value in rows])


def table(rows: list[dict], stem: str, caption: str) -> None:
    st.dataframe(rows, hide_index=True, width="stretch")
    st.caption(caption)
    download("Download CSV", eval_dashboard.table_csv(rows), f"{stem}.csv", "text/csv", with_bom=True)
    st.code(eval_dashboard.table_markdown(rows), language=None, wrap_lines=True)


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

table_tab, detail_tab, benchmark_tab = st.tabs(
    ["All rows", "One investigation in detail", "Measured retrieval benchmark"]
)

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

with benchmark_tab:
    benchmark = cached_benchmark()
    st.subheader("Three ways of searching, same questions, same material")
    st.caption(
        "The ten benchmark questions were run through the search step three times, changing "
        "only how passages are ranked. \"Keywords only\" matches the words that were typed. "
        "\"Meaning only\" matches the sense of the sentence using the embedding model. \"Both "
        "fused\" is what the product does: it ranks with both and merges the two lists. Recall@8 "
        "is the share of paragraphs that genuinely contain the requested fact and also reached "
        "the top eight. The times are the median of five repeats of the same search, so the "
        "dense rows include the call to the hosted embedding model."
    )
    table(
        eval_dashboard.retrieval_ablation_table(),
        "retrieval_engines",
        "Written by scripts/measure_retrieval_metrics.py into "
        "data/evaluation/retrieval_metrics.json.",
    )

    st.subheader("Where the evidence for each gold claim landed, one row per CVE")
    st.caption(
        "For every one of the 110 facts the reviewer froze, the run recorded which passage "
        "supports it. Support@1 / @3 / @5 / @8 say how often that passage was inside the top "
        "one, three, five or eight pieces of evidence the writer actually received. A claim "
        "that rests on a structured NVD or KEV record instead of a paragraph is counted in its "
        "own column, because no search rank exists for it."
    )
    table(
        eval_dashboard.retrieval_support_table(),
        "retrieval_support_by_cve",
        benchmark.get("claim_support", {}).get("note", eval_dashboard.NOT_CAPTURED),
    )

    st.subheader("One row per gold claim")
    st.caption(
        "The same figures broken down to claim level: what the claim rests on, which passage "
        "or record it is, the rank it reached in the evidence package, and the verdict the "
        "deterministic check recorded for it."
    )
    table(
        eval_dashboard.retrieval_claim_table(),
        "retrieval_support_by_claim",
        "110 rows, one per frozen gold claim.",
    )

    st.subheader("How these numbers were produced")
    pairs(eval_dashboard.retrieval_provenance())
    st.code(
        benchmark.get("provenance", {}).get("relevance_rule", eval_dashboard.NOT_CAPTURED),
        language=None,
        wrap_lines=True,
    )
    st.caption(
        benchmark.get("engine_ablation", {}).get("provenance", {}).get(
            "note", eval_dashboard.NOT_CAPTURED
        )
    )

    st.subheader("What this benchmark does not show")
    st.code(
        "It measures whether the right passage was retrieved, not whether the answer then used "
        "it - that is what the deterministic field check on the other tabs decides.\n"
        "The passages counted as correct are the ones the reviewer's own frozen grading already "
        "named; no new relevance judgement was made here.\n"
        "Latency is search time on one machine, measured five times. It is not end-to-end "
        "answer time.",
        language=None,
        wrap_lines=True,
    )
