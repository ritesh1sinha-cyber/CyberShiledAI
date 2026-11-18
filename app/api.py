from __future__ import annotations

import json
import re
from collections.abc import Iterator

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool

from app.config import settings
from app.contracts import (
    HealthResponse,
    HistoryEntry,
    InvestigateRequest,
    InvestigateResponse,
    TraceDetail,
)
from app.identifiers import CVE_RE, resolve_request_cve
from app.service import InvestigationService

REQUEST_ID_RE = re.compile(r"CS-\d{4,}")


def _boundary_detail(request: InvestigateRequest) -> dict | None:
    """Return the structured refusal when a request is outside the one-CVE boundary."""
    cve_ids = {match.upper() for match in CVE_RE.findall(request.query)}
    if cve_ids:
        if len(cve_ids) > 1:
            return {
                "code": "multiple_cves_unsupported",
                "message": "Investigate one CVE at a time.",
            }
        return None
    try:
        resolve_request_cve(request)
    except ValueError:
        pass
    else:
        return None
    query = request.query.casefold()
    if any(
        term in query for term in ("system prompt", "ignore all previous", "reveal your prompt")
    ):
        return {
            "code": "unsafe_request_refused",
            "message": "I cannot provide hidden system prompts. I can help with a defensive investigation of one CVE.",
        }
    if any(
        term in query
        for term in ("next month", "next year", "will be published", "will be assigned")
    ):
        return {
            "code": "future_cves_unpredictable",
            "message": "Future CVE assignments cannot be predicted, so I can’t provide future CVE identifiers.",
        }
    return {
        "code": "cve_required",
        "message": "Enter exactly one CVE identifier for a defensive investigation.",
    }


def _server_sent_events(events: Iterator[dict]) -> Iterator[str]:
    for event in events:
        yield f"data: {json.dumps(event, default=str)}\n\n"


def _used_by(report: dict) -> dict[str, list[str]]:
    """Map each evidence id to the report sections that actually cite it."""
    used: dict[str, list[str]] = {}

    def add(evidence_id: str, label: str) -> None:
        labels = used.setdefault(evidence_id, [])
        if label not in labels:
            labels.append(label)

    for evidence_id in report.get("summary_evidence_ids", []):
        add(evidence_id, "Summary")
    for item in report.get("remediation", []):
        for evidence_id in item.get("evidence_ids", []):
            add(evidence_id, "Remediation")
    for evidence_id in report.get("risk", {}).get("evidence_ids", []):
        add(evidence_id, "Project risk")
    for mapping in report.get("attack_mapping", []):
        add(mapping["evidence_id"], "ATT&CK mapping")
    return used


def create_app(service: InvestigationService | None = None) -> FastAPI:
    app = FastAPI(title="CyberShield AI", version="1.0.0")
    app.state.service = service or InvestigationService()

    def guard(request: InvestigateRequest) -> None:
        detail = _boundary_detail(request)
        if detail is not None:
            raise HTTPException(status_code=422, detail=detail)

    @app.post("/investigate", response_model=InvestigateResponse)
    async def investigate(request: InvestigateRequest) -> InvestigateResponse:
        guard(request)
        return await run_in_threadpool(app.state.service.investigate, request)

    @app.post("/investigate/stream")
    def investigate_stream(request: InvestigateRequest) -> StreamingResponse:
        guard(request)
        return StreamingResponse(
            _server_sent_events(app.state.service.investigate_stream(request)),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(
            model=settings.qwen_model,
            qwen_configured=(
                "example.invalid" not in settings.qwen_base_url
                and bool(settings.qwen_api_key)
            ),
        )

    @app.get("/history", response_model=list[HistoryEntry])
    def history(limit: int = Query(default=20, ge=1, le=100)) -> list[HistoryEntry]:
        return app.state.service.store.list_recent(limit)

    @app.get("/traces/{request_id}", response_model=TraceDetail)
    def trace_detail(request_id: str) -> TraceDetail:
        """Read one stored investigation back from the local trace file. No model call."""
        if not REQUEST_ID_RE.fullmatch(request_id):
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "trace_id_invalid",
                    "message": "Trace ids look like CS-20261117114516962032.",
                },
            )
        record = app.state.service.store.get(request_id)
        if record is None:
            raise HTTPException(
                status_code=404,
                detail={
                    "code": "trace_not_found",
                    "message": "No local trace is stored for that investigation.",
                },
            )
        report = record["response"]["report"]
        return TraceDetail(
            request_id=report["request_id"],
            queries=(record.get("retrieval_meta") or {}).get("queries", []),
            evidence=record.get("evidence", []),
            contexts=record.get("contexts", []),
            used_by=_used_by(report),
        )

    return app


app = create_app()
