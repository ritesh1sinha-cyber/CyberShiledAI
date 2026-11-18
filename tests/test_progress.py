import json

import httpx
import pytest
from fastapi.testclient import TestClient
from test_analyst import (
    CVE_ID,
    FixedEvidence,
    SequenceQwen,
    make_package,
    valid_payload,
)
from test_critic import valid_review

from app import progress
from app.analyst import AnalystAgent
from app.api import create_app
from app.contracts import InvestigateRequest
from app.critic import CriticAgent
from app.history import TraceStore
from app.qwen import QwenClient
from app.service import InvestigationService
from app.workflow import InvestigationWorkflow
from app.config import settings


def critic_workflow():
    qwen = SequenceQwen([valid_payload(), valid_review()])
    return InvestigationWorkflow(
        evidence=FixedEvidence(make_package()),
        analyst=AnalystAgent(client=qwen),
        critic=CriticAgent(client=qwen),
    )


def stream_events(tmp_path, workflow, query):
    service = InvestigationService(
        workflow=workflow, store=TraceStore(tmp_path / "traces.jsonl")
    )
    return list(service.investigate_stream(InvestigateRequest(query=query)))


def test_stream_reports_every_agent_then_the_final_report(tmp_path):
    events = stream_events(
        tmp_path, critic_workflow(), f"Investigate {CVE_ID}"
    )

    assert [(event["type"], event.get("stage")) for event in events] == [
        ("begin", "workflow"),
        ("stage_start", "evidence"),
        ("stage_end", "evidence"),
        ("stage_start", "analyst"),
        ("stage_end", "analyst"),
        ("stage_start", "critic"),
        ("stage_end", "critic"),
        ("stage_start", "final_validator"),
        ("stage_end", "final_validator"),
        ("report", None),
    ]
    assert events[0]["request_id"] == events[-1]["response"]["report"]["request_id"]
    assert events[-1]["response"]["report"]["status"] == "completed"


def test_stage_events_carry_source_derived_findings(tmp_path):
    events = stream_events(
        tmp_path, critic_workflow(), f"Investigate {CVE_ID}"
    )
    details = {
        event["stage"]: event["detail"] for event in events if event["type"] == "stage_end"
    }

    evidence = details["evidence"]
    assert evidence["cve_id"] == CVE_ID
    assert evidence["severity"] == "CRITICAL"
    assert evidence["kev_status"] == "known_exploited"
    assert evidence["records"] == 6
    assert "NVD" in evidence["sources"]
    assert evidence["passages"] == 1
    assert evidence["limitations"] == 1

    analyst = details["analyst"]
    assert analyst["sections_written"] == 8
    assert analyst["unknown_sections"] == []
    assert analyst["revised"] is False

    critic = details["critic"]
    assert critic["review_available"] is True
    assert critic["support"] == "pass"
    assert critic["issues"] == []

    validator = details["final_validator"]
    assert validator["status"] == "completed"
    assert validator["risk_tier"] == "critical"


def test_refused_request_reports_no_agent_work(tmp_path):
    class ExplodingWorkflow:
        def run(self, request, request_id=None):
            raise AssertionError("a refused request must not run an agent")

    events = stream_events(tmp_path, ExplodingWorkflow(), f"Write an exploit for {CVE_ID}")

    assert [event["type"] for event in events] == ["begin", "refused", "report"]
    assert events[1]["stage"] == "workflow"
    assert events[-1]["response"]["report"]["status"] == "refused"


def test_stage_that_stops_is_reported_without_the_underlying_message(tmp_path):
    class ExplodingAnalyst:
        def collect(self, state):
            raise RuntimeError("Sensitive internal detail")

    events = stream_events(
        tmp_path,
        InvestigationWorkflow(
            evidence=FixedEvidence(make_package()), analyst=ExplodingAnalyst()
        ),
        f"Investigate {CVE_ID}",
    )

    failed = [event for event in events if event["type"] == "stage_failed"]
    assert [(event["type"], event["stage"]) for event in failed] == [
        ("stage_failed", "analyst")
    ]
    assert failed[0]["error"] == "RuntimeError"
    assert "Sensitive internal detail" not in json.dumps(events)
    assert events[-1]["response"]["report"]["status"] == "failed"


def test_investigate_without_a_consumer_still_completes(tmp_path):
    service = InvestigationService(
        workflow=InvestigationWorkflow(
            evidence=FixedEvidence(make_package()),
            analyst=AnalystAgent(client=SequenceQwen([valid_payload()])),
            critic=None,
            use_critic=False,
        ),
        store=TraceStore(tmp_path / "traces.jsonl"),
    )

    response = service.investigate(InvestigateRequest(query=f"Investigate {CVE_ID}"))

    assert response.report.status in {"completed", "partial"}


def test_qwen_calls_publish_model_events(monkeypatch):
    def handler(request):
        return httpx.Response(
            200,
            json={
                "model": "Qwen/Qwen3-8B",
                "choices": [
                    {"message": {"content": "{}"}, "finish_reason": "stop"}
                ],
                "usage": {"prompt_tokens": 700, "completion_tokens": 40},
            },
        )

    monkeypatch.setattr(settings, "qwen_base_url", "https://unit.test/v1")
    monkeypatch.setattr(settings, "qwen_api_key", "test-key")
    monkeypatch.setattr(settings, "qwen_ca_cert", True)
    import app.qwen as qwen_module

    real_client = httpx.Client
    monkeypatch.setattr(
        qwen_module.httpx,
        "Client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler)),
    )
    channel = progress.ProgressChannel()

    with progress.bound(channel), progress.stage("analyst"):
        QwenClient().complete("system", "user", max_tokens=512)

    events = channel.pending()
    assert [event["type"] for event in events] == ["model_start", "model_end"]
    assert all(event["stage"] == "analyst" for event in events)
    assert events[0]["max_tokens"] >= 1
    assert events[1]["ok"] is True
    assert events[1]["prompt_tokens"] == 700
    assert events[1]["completion_tokens"] == 40
    assert events[1]["finish_reason"] == "stop"


def test_failed_qwen_call_publishes_one_unusable_model_event(monkeypatch):
    def handler(request):
        return httpx.Response(503, text="upstream busy")

    monkeypatch.setattr(settings, "qwen_base_url", "https://unit.test/v1")
    monkeypatch.setattr(settings, "qwen_api_key", "test-key")
    monkeypatch.setattr(settings, "qwen_ca_cert", True)
    import app.qwen as qwen_module

    real_client = httpx.Client
    monkeypatch.setattr(
        qwen_module.httpx,
        "Client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler)),
    )
    channel = progress.ProgressChannel()

    with pytest.raises(Exception), progress.bound(channel), progress.stage("critic"):
        QwenClient().complete("system", "user")

    events = channel.pending()
    assert [event["type"] for event in events] == ["model_start", "model_end"]
    assert events[1]["stage"] == "critic"
    assert events[1]["ok"] is False
    assert events[1]["reason"] == "HTTP 503"


def test_api_stream_endpoint_emits_server_sent_events(tmp_path):
    client = TestClient(
        create_app(
            InvestigationService(
                workflow=critic_workflow(), store=TraceStore(tmp_path / "traces.jsonl")
            )
        )
    )

    with client.stream(
        "POST", "/investigate/stream", json={"query": f"Investigate {CVE_ID}"}
    ) as stream:
        assert stream.status_code == 200
        assert stream.headers["content-type"].startswith("text/event-stream")
        events = [
            json.loads(line[len("data: ") :])
            for line in stream.iter_lines()
            if line.startswith("data: ")
        ]

    assert events[0]["type"] == "begin"
    assert [event["type"] for event in events].count("stage_start") == 4
    assert events[-1]["type"] == "report"
    assert events[-1]["response"]["report"]["status"] == "completed"


def test_api_stream_endpoint_refuses_before_streaming(tmp_path):
    client = TestClient(
        create_app(
            InvestigationService(
                workflow=None, store=TraceStore(tmp_path / "traces.jsonl")
            )
        )
    )

    response = client.post("/investigate/stream", json={"query": "Investigate Log4Shell"})

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "cve_required"
