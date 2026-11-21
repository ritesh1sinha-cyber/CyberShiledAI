import json
from datetime import datetime, timezone

import httpx
import pytest
from test_analyst import make_package
from test_critic import make_draft, valid_review

from app.client import ApiError, ApiValidationError, CyberShieldClient
from app.contracts import (
    CriticReview,
    InvestigateRequest,
    InvestigateResponse,
    StageTiming,
)
from app.final_validator import build_report

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)
CVE_ID = "CVE-2021-44228"


def response_payload():
    report = build_report(
        make_package(),
        make_draft(),
        CriticReview.model_validate(valid_review()),
        request_id="CS-1001",
        generated_at=NOW,
    )
    return InvestigateResponse(
        report=report,
        trace_id="CS-1001",
        timings=[StageTiming(stage="total", ms=125)],
    ).model_dump(mode="json")


def test_client_posts_strict_request_and_parses_investigation_response():
    def handler(request):
        payload = json.loads(request.content)
        assert payload == {
            "query": f"Investigate {CVE_ID}",
            "include_attack": False,
            "top_k": 3,
            "conversation_context": [],
            "web_fallback_approved": False,
        }
        return httpx.Response(200, json=response_payload())

    client = CyberShieldClient(
        base_url="http://test", transport=httpx.MockTransport(handler)
    )
    response = client.investigate(
        InvestigateRequest(query=f"Investigate {CVE_ID}", include_attack=False, top_k=3)
    )
    assert response.report.status == "completed"
    assert response.trace_id == "CS-1001"


def test_client_preserves_scoped_validation_code():
    def handler(request):
        return httpx.Response(
            422,
            json={
                "detail": {
                    "code": "cve_required",
                    "message": "Enter exactly one CVE identifier.",
                }
            },
        )

    client = CyberShieldClient(
        base_url="http://test", transport=httpx.MockTransport(handler)
    )
    with pytest.raises(ApiValidationError) as caught:
        client.investigate(InvestigateRequest(query="Investigate Log4Shell"))
    assert caught.value.code == "cve_required"


def test_client_rejects_invalid_success_envelope():
    client = CyberShieldClient(
        base_url="http://test",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})),
    )
    with pytest.raises(ApiError, match="invalid investigation response"):
        client.investigate(InvestigateRequest(query=CVE_ID))


def test_client_parses_health_and_history():
    def handler(request):
        if request.url.path == "/health":
            return httpx.Response(
                200,
                json={
                    "status": "ok",
                    "model": "Qwen/Qwen3-8B",
                    "qwen_configured": True,
                },
            )
        assert request.url.params["limit"] == "5"
        return httpx.Response(
            200,
            json=[
                {
                    "trace_id": "CS-1001",
                    "request_id": "CS-1001",
                    "status": "completed",
                    "query": CVE_ID,
                    "summary": "Completed report.",
                    "generated_at": NOW.isoformat(),
                    "total_ms": 125,
                }
            ],
        )

    client = CyberShieldClient(
        base_url="http://test", transport=httpx.MockTransport(handler)
    )
    assert client.health().qwen_configured is True
    history = client.history(limit=5)
    assert history[0].total_ms == 125
    assert history[0].generated_at == NOW


def test_client_hides_network_implementation_details():
    def handler(request):
        raise httpx.ConnectError("Internal socket detail", request=request)

    client = CyberShieldClient(
        base_url="http://test", transport=httpx.MockTransport(handler)
    )
    with pytest.raises(ApiError, match="Cannot reach the local FastAPI service") as caught:
        client.health()
    assert "Internal socket detail" not in str(caught.value)


def trace_payload():
    return {
        "request_id": "CS-1001",
        "queries": [f"remediation for {CVE_ID}"],
        "evidence": [],
        "contexts": [
            {
                "evidence_id": "EV-0005",
                "chunk_id": "CWE-917#000",
                "title": "CWE-917 Improper Neutralization",
                "text": "Avoid evaluating untrusted input.",
                "score": 0.025,
            }
        ],
        "used_by": {"EV-0005": ["Remediation"]},
    }


def test_client_reads_back_the_stored_paragraphs():
    def handler(request):
        assert request.url.path == "/traces/CS-1001"
        return httpx.Response(200, json=trace_payload())

    client = CyberShieldClient(
        base_url="http://test", transport=httpx.MockTransport(handler)
    )
    detail = client.trace("CS-1001")
    assert detail.contexts[0].text == "Avoid evaluating untrusted input."
    assert detail.used_by == {"EV-0005": ["Remediation"]}


def test_client_treats_a_missing_trace_as_absent_not_an_error():
    client = CyberShieldClient(
        base_url="http://test",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                404,
                json={
                    "detail": {
                        "code": "trace_not_found",
                        "message": "No local trace is stored for that investigation.",
                    }
                },
            )
        ),
    )
    assert client.trace("CS-9999") is None


def test_client_rejects_an_invalid_trace_detail():
    client = CyberShieldClient(
        base_url="http://test",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})),
    )
    with pytest.raises(ApiError, match="invalid trace detail"):
        client.trace("CS-1001")


def sse_body(events):
    return "".join(f"data: {json.dumps(event)}\n\n" for event in events)


def test_client_streams_agent_progress_and_returns_the_report():
    body = sse_body(
        [
            {"type": "begin", "stage": "workflow", "request_id": "CS-1001"},
            {"type": "stage_start", "stage": "evidence", "note": "Reading records."},
            {"type": "stage_end", "stage": "evidence", "ms": 5, "detail": {"records": 6}},
            {"type": "report", "response": response_payload()},
        ]
    )

    def handler(request):
        assert request.url.path == "/investigate/stream"
        return httpx.Response(
            200, content=body.encode("utf-8"), headers={"content-type": "text/event-stream"}
        )

    seen = []
    client = CyberShieldClient(
        base_url="http://test", transport=httpx.MockTransport(handler)
    )
    response = client.investigate_stream(
        InvestigateRequest(query=f"Investigate {CVE_ID}"), seen.append
    )

    assert [event["type"] for event in seen] == ["begin", "stage_start", "stage_end"]
    assert response.report.status == "completed"
    assert response.trace_id == "CS-1001"


def test_client_maps_a_stream_refusal_to_the_validation_error():
    def handler(request):
        return httpx.Response(
            422,
            json={
                "detail": {
                    "code": "cve_required",
                    "message": "Enter exactly one CVE identifier for a defensive investigation.",
                }
            },
        )

    client = CyberShieldClient(
        base_url="http://test", transport=httpx.MockTransport(handler)
    )
    with pytest.raises(ApiValidationError) as caught:
        client.investigate_stream(
            InvestigateRequest(query="Investigate Log4Shell"), lambda event: None
        )
    assert caught.value.code == "cve_required"


def test_client_rejects_a_stream_that_ends_without_a_report():
    def handler(request):
        return httpx.Response(
            200,
            content=sse_body(
                [{"type": "begin", "stage": "workflow", "request_id": "CS-1001"}]
            ).encode("utf-8"),
        )

    client = CyberShieldClient(
        base_url="http://test", transport=httpx.MockTransport(handler)
    )
    with pytest.raises(ApiError, match="without a report"):
        client.investigate_stream(
            InvestigateRequest(query=CVE_ID), lambda event: None
        )
