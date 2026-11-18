from datetime import datetime, timezone

import streamlit_app as ui
from app.contracts import HistoryEntry, TraceDetail

PKG = TraceDetail(request_id="CS-1001", used_by={"EV-0001": ["Remediation"]})
PASSAGES = {"EV-0002": object()}


def test_attribution_names_the_sections_that_used_the_citation():
    assert ui.citation_attribution("EV-0001", PKG.used_by, PASSAGES, PKG) == "used by Remediation"


def test_attribution_reports_a_passage_no_section_cited():
    assert (
        ui.citation_attribution("EV-0002", PKG.used_by, PASSAGES, PKG)
        == "retrieved, but no report section cites it"
    )


def test_attribution_reports_a_record_no_section_cited():
    assert ui.citation_attribution("EV-0009", PKG.used_by, PASSAGES, PKG) == "no report section cites it"


def test_failed_readback_states_unknown_instead_of_denying_attribution():
    text = ui.citation_attribution("EV-0001", {}, {}, None)
    assert "unavailable" in text
    assert "no report section cites it" not in text


def history_row(model, sha):
    return HistoryEntry(
        trace_id="CS-1001",
        request_id="CS-1001",
        status="completed",
        query="q",
        summary="s",
        generated_at=datetime(2026, 11, 18, tzinfo=timezone.utc),
        total_ms=1,
        embeddings_model=model,
        index_chunks_sha256=sha,
    )


def test_history_row_shows_the_model_and_the_short_index_fingerprint():
    assert (
        ui._vectors_label(history_row("bge-small-en-v1.5", "72a0ce2e829fc64f" + "0" * 48))
        == "bge-small-en-v1.5 · 72a0ce2e"
    )


def test_history_row_without_a_stamp_reads_as_not_recorded():
    assert ui._vectors_label(history_row(None, None)) == "not recorded"
