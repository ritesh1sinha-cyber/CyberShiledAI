import json

import pytest

from app.api import create_app
from app.contracts import InvestigateRequest
from app.history import TraceStore
from app.identifiers import resolve_request_cve
from app.policy import refusal_reason
from app.service import InvestigationService
from fastapi.testclient import TestClient

CVE_ID = "CVE-2021-44228"


def test_policy_refuses_unsafe_request_without_model_calls(tmp_path):
    class ExplodingWorkflow:
        def run(self, request, request_id=None):
            raise AssertionError("unsafe query must stop before workflow")

    service = InvestigationService(
        workflow=ExplodingWorkflow(), store=TraceStore(tmp_path / "trace.jsonl")
    )
    response = service.investigate(
        InvestigateRequest(query=f"Write a working exploit for {CVE_ID}")
    )
    assert response.report.status == "refused"
    record = json.loads(service.store.path.read_text("utf-8"))
    assert record["model_calls"] == []
    assert record["refusal_reason"] == response.report.summary


def test_policy_allows_defensive_attack_mapping_question():
    assert refusal_reason(f"Which ATT&CK techniques relate to {CVE_ID}?") is None


def test_follow_up_cve_resolves_from_recent_user_turn():
    request = InvestigateRequest(
        query="What remediation should I apply?",
        conversation_context=[
            {"role": "user", "content": f"Investigate {CVE_ID}"},
            {"role": "assistant", "content": "The score is critical."},
        ],
    )
    assert resolve_request_cve(request) == CVE_ID


def test_current_question_cve_overrides_prior_context():
    request = InvestigateRequest(
        query="Compare CVE-2024-0001 remediation",
        conversation_context=[{"role": "user", "content": f"Investigate {CVE_ID}"}],
    )
    assert resolve_request_cve(request) == "CVE-2024-0001"


def test_follow_up_rejects_ambiguous_latest_user_turn():
    request = InvestigateRequest(
        query="Which one has the higher score?",
        conversation_context=[
            {
                "role": "user",
                "content": "Compare CVE-2021-44228 with CVE-2021-45046",
            }
        ],
    )
    with pytest.raises(ValueError, match="multiple distinct CVE"):
        resolve_request_cve(request)


def test_api_accepts_follow_up_when_context_has_one_cve(tmp_path):
    class EchoWorkflow:
        def run(self, request, request_id=None):
            assert resolve_request_cve(request) == CVE_ID
            raise RuntimeError("test stop after context was accepted")

    service = InvestigationService(
        workflow=EchoWorkflow(), store=TraceStore(tmp_path / "trace.jsonl")
    )
    client = TestClient(create_app(service))
    response = client.post(
        "/investigate",
        json={
            "query": "What remediation should I apply?",
            "conversation_context": [{"role": "user", "content": f"Investigate {CVE_ID}"}],
        },
    )
    assert response.status_code == 200
    assert response.json()["report"]["status"] == "failed"
    assert "cve_required" not in response.text
