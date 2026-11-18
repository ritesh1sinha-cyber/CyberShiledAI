import json
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from test_analyst import CVE_ID, make_package
from test_critic import make_draft, valid_review

from app.api import create_app
from app.config import settings
from app.contracts import CriticReview, InvestigateRequest, InvestigateResponse, StageTiming
from app.final_validator import build_report
from app.history import TraceStore
from app.service import InvestigationService

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)
REQUEST_ID = "CS-1001"
PASSAGE = "Avoid evaluating untrusted input and apply the documented mitigations."


def _record(tmp_path, index_manifest=None):
    """Store one investigation in a trace file and return its store.

    index_manifest=None means a manifest that does not exist, so the run is not
    reading the repository's real data/manifests/index.json.
    """
    store = TraceStore(
        tmp_path / "traces.jsonl", index_manifest or tmp_path / "index.json"
    )
    package = make_package()
    report = build_report(
        package,
        make_draft(),
        CriticReview.model_validate(valid_review()),
        request_id=REQUEST_ID,
        generated_at=NOW,
    )
    response = InvestigateResponse(
        report=report, trace_id=REQUEST_ID, timings=[StageTiming(stage="total", ms=100)]
    )
    store.append(
        InvestigateRequest(query=f"Investigate {CVE_ID}", include_attack=False, top_k=3),
        response,
        state={
            "package": package,
            "retrieval_meta": {"queries": [f"remediation for {CVE_ID}"]},
        },
    )
    return store


def stored_client(tmp_path):
    """A service holding one investigation in the trace file and no workflow, so any
    model or graph work during a read would fail the test instead of passing silently."""
    store = _record(tmp_path)
    return TestClient(create_app(InvestigationService(workflow=None, store=store)))


def test_trace_detail_returns_the_retrieved_paragraph(tmp_path):
    body = stored_client(tmp_path).get(f"/traces/{REQUEST_ID}").json()
    assert body["request_id"] == REQUEST_ID
    assert body["queries"] == [f"remediation for {CVE_ID}"]
    assert body["contexts"] == [
        {
            "evidence_id": "EV-0005",
            "chunk_id": "CWE-917#000",
            "title": "CWE-917 Improper Neutralization",
            "text": PASSAGE,
            "score": 0.025,
        }
    ]
    assert len(body["evidence"]) == len(make_package().evidence)
    assert {item["evidence_id"] for item in body["evidence"]} >= {"EV-0001", "EV-0005"}


def test_trace_detail_names_the_sections_that_used_each_source(tmp_path):
    used = stored_client(tmp_path).get(f"/traces/{REQUEST_ID}").json()["used_by"]
    assert used["EV-0001"] == ["Summary"]
    assert used["EV-0002"] == ["Summary", "Project risk"]
    assert used["EV-0005"] == ["Remediation"]
    assert used["EV-0006"] == ["ATT&CK mapping"]
    assert "EV-0004" not in used


def test_trace_detail_never_calls_the_model(tmp_path):
    client = stored_client(tmp_path)
    assert client.get(f"/traces/{REQUEST_ID}").status_code == 200
    assert client.get("/history").status_code == 200


def test_missing_trace_gets_a_scoped_not_found(tmp_path):
    response = stored_client(tmp_path).get("/traces/CS-9999")
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "trace_not_found"


def test_hostile_trace_id_is_rejected_before_the_file_is_read(tmp_path):
    response = stored_client(tmp_path).get("/traces/..%2Fsecrets")
    assert response.status_code in (404, 422)
    if response.status_code == 422:
        assert response.json()["detail"]["code"] == "trace_id_invalid"
    body = json.dumps(response.json())
    assert "traces.jsonl" not in body
    assert PASSAGE not in body


MANIFEST = {
    "model": "bge-small-en-v1.5",
    "dim": 384,
    "dense_backend": "faiss",
    "chunks_sha256": "72a0ce2e829fc64f" + "0" * 48,
    "generated_at": "2026-11-18T06:00:00+00:00",
}


def history_client(store):
    return TestClient(create_app(InvestigationService(workflow=None, store=store)))


def test_history_rows_name_the_index_they_retrieved_with(tmp_path):
    """A row that cannot name its vectors is indistinguishable from a retired index."""
    manifest = tmp_path / "index.json"
    manifest.write_text(json.dumps(MANIFEST), encoding="utf-8")
    store = _record(tmp_path, manifest)
    row = history_client(store).get("/history").json()[0]
    assert row["embeddings_model"] == "bge-small-en-v1.5"
    assert row["index_chunks_sha256"] == MANIFEST["chunks_sha256"]


def test_the_stamp_survives_without_any_index_manifest(tmp_path):
    store = _record(tmp_path)
    row = history_client(store).get("/history").json()[0]
    assert row["embeddings_model"] == settings.embeddings_model
    assert row["index_chunks_sha256"] is None


def test_rows_written_before_the_stamp_still_list(tmp_path):
    store = _record(tmp_path, tmp_path / "index.json")
    record = json.loads(store.path.read_text(encoding="utf-8"))
    del record["runtime"]
    store.path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    row = history_client(store).get("/history").json()[0]
    assert row["embeddings_model"] is None
    assert row["index_chunks_sha256"] is None
    assert row["request_id"] == REQUEST_ID
