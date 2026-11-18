from __future__ import annotations

import streamlit as st
from pydantic import ValidationError

from app import observability
from app.client import ApiError, ApiValidationError, CyberShieldClient
from app.config import settings
from app.contracts import (
    ConversationTurn,
    HistoryEntry,
    InvestigateRequest,
    InvestigateResponse,
    Report,
    TraceDetail,
)

st.set_page_config(page_title="CyberShield AI", layout="wide")


@st.cache_resource
def get_client() -> CyberShieldClient:
    return CyberShieldClient()


def _excerpt(text: str, limit: int = 400) -> str:
    return text if len(text) <= limit else text[:limit].rstrip() + " …"


def _vectors_label(entry: HistoryEntry) -> str:
    """The index a row retrieved with; "not recorded" is how pre-stamp rows look."""
    sha = (entry.index_chunks_sha256 or "")[:8]
    parts = [item for item in (entry.embeddings_model, sha) if item]
    return " · ".join(parts) if parts else "not recorded"


def citation_attribution(
    evidence_id: str,
    used_by: dict[str, list[str]],
    passages: dict,
    package: TraceDetail | None,
) -> str:
    """What the stored trace says about one citation.

    When the trace cannot be read back the answer is unknown, so it is stated as
    unavailable rather than as "no report section cites it".
    """
    if package is None:
        return "attribution unavailable: the trace could not be read back"
    sections = used_by.get(evidence_id) or []
    if sections:
        return "used by " + ", ".join(sections)
    if evidence_id in passages:
        return "retrieved, but no report section cites it"
    return "no report section cites it"


def render_report(report: Report, client: CyberShieldClient) -> None:
    st.subheader("1. Summary")
    st.write(report.summary)
    if report.summary_evidence_ids:
        st.caption("Evidence: " + ", ".join(report.summary_evidence_ids))

    st.subheader("2. CVE")
    if report.cve is None:
        st.info("NVD facts are unavailable.")
    else:
        st.write(report.cve.description or "Description unavailable.")
        columns = st.columns(3)
        columns[0].metric("CVSS version", report.cve.cvss_version or "Unknown")
        columns[1].metric(
            "CVSS score",
            str(report.cve.cvss_score) if report.cve.cvss_score is not None else "Unknown",
        )
        columns[2].metric("Severity", report.cve.severity or "Unknown")
        st.caption(
            f"Published: {report.cve.published or 'Unknown'} · "
            f"Last modified: {report.cve.last_modified or 'Unknown'}"
        )
        if report.cve.cvss_vector:
            st.code(report.cve.cvss_vector, language=None)

    st.subheader("3. Affected products")
    if report.affected_products:
        for product in report.affected_products:
            st.write(f"- {product}")
    else:
        st.info("Affected product information is unavailable.")

    st.subheader("4. CISA KEV")
    if report.kev is None:
        st.info("CISA KEV status is unavailable.")
    else:
        st.write(f"Status: **{report.kev.status}**")
        st.caption(
            f"Catalog {report.kev.catalog_version} · checked {report.kev.checked_at}"
        )
        if report.kev.required_action:
            st.write(f"Required action: {report.kev.required_action}")
        if report.kev.due_date:
            st.write(f"Due date: {report.kev.due_date}")

    st.subheader("5. ATT&CK mapping")
    if report.attack_mapping:
        st.table(
            [
                {
                    "Technique": item.technique_id,
                    "Name": item.name,
                    "Basis": item.basis,
                    "Confidence": item.confidence,
                    "Evidence": item.evidence_id,
                }
                for item in report.attack_mapping
            ]
        )
    else:
        st.info("No verified ATT&CK mapping is available; the system does not guess.")

    st.subheader("6. Remediation")
    if report.remediation:
        for item in report.remediation:
            st.write(item.text)
            st.caption("Evidence: " + ", ".join(item.evidence_ids))
    else:
        st.info("Remediation guidance is unavailable.")

    st.subheader("7. Risk")
    st.write(f"Deterministic risk tier: **{report.risk.tier}**")
    for driver in report.risk.drivers:
        st.write(f"- {driver}")
    if report.risk.rationale:
        st.write(report.risk.rationale)
    if report.risk.evidence_ids:
        st.caption("Evidence: " + ", ".join(report.risk.evidence_ids))

    st.subheader("8. Limitations")
    if report.limitations:
        for limitation in report.limitations:
            st.warning(limitation)
    else:
        st.write("No limitations were recorded for this investigation.")

    package: TraceDetail | None = None
    readback_error: str | None = None
    try:
        package = client.trace(report.request_id)
    except ApiError as exc:
        readback_error = str(exc)
        st.caption(readback_error)

    passages = {item.evidence_id: item for item in (package.contexts if package else [])}
    claims = {item.evidence_id: item.claim for item in (package.evidence if package else [])}
    used_by = package.used_by if package else {}

    with st.expander("Sources, citation IDs and retrieved paragraphs"):
        if report.citations:
            for citation in report.citations:
                attribution = citation_attribution(
                    citation.evidence_id, used_by, passages, package
                )
                st.write(f"**{citation.evidence_id} · {citation.source} · {attribution}**")
                st.markdown(f"[Open source]({citation.source_url})")
                passage = passages.get(citation.evidence_id)
                if passage:
                    st.caption(
                        f"Retrieved chunk `{passage.chunk_id}` · retrieval score "
                        f"{passage.score:.3f} · {passage.title}"
                    )
                    st.write(f"> {_excerpt(passage.text)}")
                elif citation.evidence_id in claims:
                    st.write(f"> {claims[citation.evidence_id]}")
        else:
            st.write("No source citations are available.")

    with st.expander("Full retrieved paragraphs"):
        if passages:
            if package and package.queries:
                st.caption(
                    "Search queries that produced them: "
                    + " | ".join(_excerpt(query, 120) for query in package.queries)
                )
            for evidence_id, passage in passages.items():
                st.write(f"**{evidence_id} · {passage.title}**")
                st.write(passage.text)
        else:
            st.write(
                f"Paragraphs could not be read back: {readback_error}"
                if readback_error
                else "No retrieved paragraphs are stored for this investigation."
            )


def render_response(response: InvestigateResponse, client: CyberShieldClient) -> None:
    report = response.report
    st.divider()
    st.header("Investigation report")
    total_ms = next((item.ms for item in response.timings if item.stage == "total"), 0)
    columns = st.columns(4)
    columns[0].metric("Status", report.status)
    columns[1].metric("Risk", report.risk.tier)
    columns[2].metric("Total time", f"{total_ms / 1000:.2f} s")
    columns[3].metric("Trace ID", report.request_id)
    trace_link = observability.trace_url(report.request_id)
    if trace_link:
        st.markdown(
            f"[Open this trace in Langfuse]({trace_link}) to read the raw prompt and "
            "completion of every Qwen call, with the deterministic score attached."
        )
    else:
        st.caption(
            f"Langfuse link unavailable. Search trace id {report.request_id} in the "
            "local Langfuse project if the stack is running."
        )
    render_report(report, client)
    with st.expander("Stage timings"):
        st.table([{"Stage": item.stage, "Milliseconds": item.ms} for item in response.timings])


STAGE_TITLES = {
    "evidence": "Evidence agent",
    "analyst": "Analyst agent",
    "critic": "Critic agent",
    "final_validator": "Final Validator",
}


def progress_lines(stage: str, detail: dict) -> list[str]:
    """Turn one finished agent stage into plain, source-derived statements."""
    if stage == "evidence":
        sources = detail.get("sources") or []
        lines = [
            f"Trusted records: {detail.get('records', 0)} from "
            f"{', '.join(sources) if sources else 'no source'}",
            f"NVD: severity {detail.get('severity')} · CVSS {detail.get('cvss_score')}",
            f"CISA KEV: {detail.get('kev_status')}",
            f"Corpus passages: {detail.get('passages')} · "
            f"ATT&CK techniques: {detail.get('attack_techniques')}",
        ]
        if detail.get("intent"):
            lines.append(f"Retrieval intent: {detail['intent']}")
        if detail.get("limitations"):
            lines.append(f"Evidence limitations recorded: {detail['limitations']}")
        return lines
    if stage == "analyst":
        lines = [f"Sections written: {detail.get('sections_written')} of 8"]
        if detail.get("unknown_sections"):
            lines.append("Left unknown: " + ", ".join(detail["unknown_sections"]))
        if detail.get("revised"):
            lines.append("Rewrote the draft against the Critic's issues.")
        if detail.get("deterministic_fallback"):
            lines.append(f"Deterministic draft fallback: {detail['deterministic_fallback']}")
        if detail.get("validation_failure"):
            lines.append(f"Deterministic rule broken: {detail['validation_failure']}")
        return lines
    if stage == "critic":
        if not detail.get("review_available", True):
            return [f"No independent review was available: {detail.get('reason')}."]
        lines = [
            "Review verdicts — "
            + " · ".join(
                f"{name}: {detail.get(name)}"
                for name in ("support", "completeness", "citations", "uncertainty")
            )
        ]
        issues = detail.get("issues") or []
        if issues:
            lines.extend(
                f"{issue.get('section')} / {issue.get('category')}: {issue.get('detail')}"
                for issue in issues
            )
        else:
            lines.append("No issues raised.")
        return lines
    if stage == "final_validator":
        return [
            f"Report status: {detail.get('status')} · risk tier {detail.get('risk_tier')}",
            f"Citations: {detail.get('citations')} · remediation items: "
            f"{detail.get('remediation_items')} · limitations: {detail.get('limitations')}",
        ]
    return []


def investigate_live(
    client: CyberShieldClient, request: InvestigateRequest
) -> InvestigateResponse:
    """Run one investigation and print what each agent is doing while it runs."""
    slots: dict[str, object] = {}
    counters = {"qwen": 0}

    def on_event(event: dict) -> None:
        kind = event.get("type")
        stage = event.get("stage") or "workflow"
        title = STAGE_TITLES.get(stage, "Boundary check")
        if kind == "begin":
            st.caption(f"Trace {event.get('request_id')} · the request passed the safety check.")
        elif kind == "refused":
            st.warning(event.get("reason"))
        elif kind == "stage_start":
            slot = st.container()
            slots[stage] = slot
            slot.write(f"{title} — {event.get('note')}")
        elif kind == "model_start":
            counters["qwen"] += 1
            box = slots.get(stage) or st
            box.caption(
                f"Qwen call {counters['qwen']} running — generating JSON, up to "
                f"{event.get('max_tokens')} output tokens."
            )
        elif kind == "model_end":
            box = slots.get(stage) or st
            if event.get("ok"):
                box.caption(
                    f"Qwen answered in {event.get('ms')} ms · "
                    f"{event.get('prompt_tokens')} prompt / "
                    f"{event.get('completion_tokens')} completion tokens · "
                    f"finish_reason={event.get('finish_reason')}"
                )
            else:
                box.caption(f"Qwen call failed: {event.get('reason')}")
        elif kind == "stage_failed":
            box = slots.pop(stage, None) or st
            box.error(f"{title} stopped before it produced a result ({event.get('error')}).")
        elif kind == "stage_end":
            box = slots.pop(stage, None) or st
            box.caption(f"{title} finished in {event.get('ms')} ms")
            for line in progress_lines(stage, event.get("detail") or {}):
                box.caption(line)

    return client.investigate_stream(request, on_event)


def main() -> None:
    st.title("CyberShield AI")
    st.write(
        "Ask a defensive question about exactly one CVE. The system gathers trusted "
        "facts and supporting passages, then produces an evidence-backed report."
    )
    client = get_client()

    with st.sidebar:
        st.header("Local runtime")
        st.code(settings.api_base_url, language=None)
        try:
            health = client.health()
            st.write(f"API: {health.status}")
            st.write(f"Model: {health.model}")
            st.write(f"Qwen configured: {health.qwen_configured}")
        except ApiError as exc:
            st.error(str(exc))
            st.code(
                "uvicorn app.api:app --host 127.0.0.1 --port 8000",
                language=None,
            )
        st.caption(
            "Sequential path: Evidence with Qwen → RAG → Analyst → Critic → Final Validator. "
            "Safety checks run deterministically before the workflow. One active Qwen request; "
            "up to ten calls when retrieval refines twice, the Critic requests a revision, and "
            "either review is retried once because its JSON was unusable."
        )
        st.caption(
            f"Observability: Langfuse on {settings.langfuse_host}. Each report's Trace ID is "
            "the Langfuse trace ID, and the link under it opens that trace to read the raw "
            "prompts and completions of every Qwen call plus the deterministic score. "
            "The local JSONL file stays the system of record."
        )

    investigate_tab, history_tab = st.tabs(["Investigate", "History"])

    with investigate_tab:
        st.session_state.setdefault("conversation_context", [])
        if st.button("Clear follow-up context"):
            st.session_state["conversation_context"] = []
            st.session_state.pop("investigation_response", None)
        if st.session_state["conversation_context"]:
            st.caption("Follow-up context is active. You can ask about the previous CVE without repeating its ID.")
        with st.form("investigation_form"):
            query = st.text_area(
                "CVE question or follow-up",
                value="Investigate CVE-2021-44228: severity, KEV status and remediation.",
                max_chars=500,
                height=100,
            )
            columns = st.columns(2)
            include_attack = columns[0].checkbox("Include ATT&CK mapping", value=True)
            top_k = columns[1].slider("Retrieved passages", min_value=1, max_value=20, value=8)
            submitted = st.form_submit_button("Investigate", type="primary")

        if submitted:
            st.session_state.pop("investigation_response", None)
            try:
                request = InvestigateRequest(
                    query=query,
                    include_attack=include_attack,
                    top_k=top_k,
                    conversation_context=st.session_state["conversation_context"],
                )
            except ValidationError as exc:
                st.error(exc.errors()[0]["msg"])
            else:
                with st.status("Running sequential investigation", expanded=True) as status:
                    st.write("Evidence with Qwen → RAG → Analyst → Critic → Final Validator")
                    st.caption("Each agent reports here while the investigation runs.")
                    try:
                        response = investigate_live(client, request)
                    except ApiValidationError as exc:
                        st.error(f"{exc.code}: {exc}")
                        status.update(
                            label="Request validation failed", expanded=True, state="error"
                        )
                    except ApiError as exc:
                        st.error(str(exc))
                        status.update(
                            label="Investigation unavailable", expanded=True, state="error"
                        )
                    except Exception as exc:  # keep local paths out of the browser
                        st.error(
                            f"The investigation could not be completed ({type(exc).__name__}). "
                            "See the local trace file for the recorded error."
                        )
                        status.update(label="Investigation failed", expanded=True, state="error")
                    else:
                        st.session_state["investigation_response"] = response
                        context = st.session_state["conversation_context"]
                        context.extend(
                            [
                                ConversationTurn(role="user", content=query),
                                ConversationTurn(
                                    role="assistant",
                                    content=response.report.summary[:1600]
                                    or f"Investigation status: {response.report.status}",
                                ),
                            ]
                        )
                        st.session_state["conversation_context"] = context[-8:]
                        st.session_state.pop("history_entries", None)
                        for item in response.timings:
                            st.write(f"Completed {item.stage}: {item.ms} ms")
                        state = "error" if response.report.status == "failed" else "complete"
                        status.update(
                            label=f"Investigation {response.report.status}", state=state
                        )

        if "investigation_response" in st.session_state:
            render_response(st.session_state["investigation_response"], client)

    with history_tab:
        st.write("Recent investigations stored in the local JSONL trace file.")
        if st.button("Refresh history"):
            st.session_state.pop("history_entries", None)
        if "history_entries" not in st.session_state:
            try:
                st.session_state["history_entries"] = client.history()
            except ApiError as exc:
                st.error(str(exc))
                st.session_state["history_entries"] = []
        entries = st.session_state["history_entries"]
        if entries:
            st.table(
                [
                    {
                        "Trace ID": item.trace_id,
                        "Status": item.status,
                        "Query": item.query,
                        "Summary": item.summary,
                        "Vectors": _vectors_label(item),
                        "Total ms": item.total_ms,
                        "Generated at": item.generated_at,
                    }
                    for item in entries
                ]
            )
            st.caption(
                "Vectors names the embedding model and index that each row retrieved with. "
                '"not recorded" means the row was written before that stamp existed.'
            )
        else:
            st.info("No investigation history is available.")


if __name__ == "__main__":
    main()
