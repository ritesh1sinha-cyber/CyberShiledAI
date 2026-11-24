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


def test_single_agent_and_prompt_traces_persist_and_readback(tmp_path):
    from app.history import TraceStore
    from app.contracts import InvestigateRequest, InvestigateResponse, Report, StageTiming
    store = TraceStore(tmp_path / "traces.jsonl")
    
    req_id = "CS-20261124120000000000"
    report = Report(
        request_id=req_id,
        status="completed",
        summary="Test single agent summary",
        generated_at=datetime.now(timezone.utc),
    )
    resp = InvestigateResponse(
        report=report,
        trace_id=req_id,
        timings=[StageTiming(stage="total", ms=100)],
    )
    store.append(InvestigateRequest(query="Investigate CVE-2024-27198: test"), resp, state={"package": None})
    
    prompt_id = "CS-20261124120100000000"
    p_report = Report(
        request_id=prompt_id,
        status="completed",
        summary="Test prompt summary",
        generated_at=datetime.now(timezone.utc),
    )
    p_resp = InvestigateResponse(
        report=p_report,
        trace_id=prompt_id,
        timings=[StageTiming(stage="total", ms=50)],
    )
    store.append(InvestigateRequest(query="Investigate CVE-2024-27198: prompt"), p_resp, state={"architecture": "zero_shot"})
    
    history = store.list_recent(limit=10)
    assert len(history) == 2
    assert history[0].trace_id == prompt_id
    assert history[1].trace_id == req_id
    assert store.get(req_id) is not None
    assert store.get(prompt_id) is not None



def test_reset_button_empties_the_query_textarea(monkeypatch):
    # The reset click submits the form the textarea lives in, so the textarea's own text is
    # written back into its key before the handler runs. Clearing the key in that same run is
    # reverted when Streamlit restores the submitted value, hence the deferred clear.
    from streamlit.testing.v1 import AppTest

    import app.client as client_module
    from streamlit_app import ROOT

    def offline(self):
        raise client_module.ApiError("offline")

    monkeypatch.setattr(client_module.CyberShieldClient, "health", offline)
    monkeypatch.setattr(client_module.CyberShieldClient, "history", lambda self, limit=20: [])
    monkeypatch.setattr(client_module.CyberShieldClient, "investigate_stream", lambda self, req, on_event: offline(self))

    at = AppTest.from_file(str(ROOT / "streamlit_app.py"), default_timeout=180).run()
    at.text_area[0].set_value("Investigate CVE-2021-44228: explain severity and remediation.")
    submit = next(b for b in at.button if "Run Vulnerability" in (b.label or ""))
    submit.click().run()
    assert at.text_area[0].value.startswith("Investigate CVE-2021-44228")

    reset = next(b for b in at.button if "Reset UI" in (b.label or ""))
    reset.click().run()

    assert at.text_area[0].value == ""
