from __future__ import annotations

import json
from collections.abc import Callable

import httpx
from pydantic import ValidationError

from app.config import settings
from app.contracts import (
    HealthResponse,
    HistoryEntry,
    InvestigateRequest,
    InvestigateResponse,
    TraceDetail,
)


class ApiError(RuntimeError):
    pass


class ApiValidationError(ApiError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class CyberShieldClient:
    def __init__(
        self,
        base_url: str | None = None,
        timeout: float | None = None,
        transport: httpx.BaseTransport | None = None,
    ):
        self._client = httpx.Client(
            base_url=(base_url or settings.api_base_url).rstrip("/"),
            timeout=timeout or settings.investigation_timeout_s,
            transport=transport,
        )

    def investigate(self, request: InvestigateRequest) -> InvestigateResponse:
        response = self._post(
            "/investigate", request.model_dump(mode="json")
        )
        if response.status_code != 200:
            self._raise_response_error(response)
        try:
            return InvestigateResponse.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise ApiError("The local API returned an invalid investigation response.") from exc

    def investigate_stream(
        self, request: InvestigateRequest, on_event: Callable[[dict], None]
    ) -> InvestigateResponse:
        """Run one investigation over a server-sent event stream, reporting each agent live."""
        try:
            with self._client.stream(
                "POST", "/investigate/stream", json=request.model_dump(mode="json")
            ) as response:
                if response.status_code != 200:
                    response.read()
                    self._raise_response_error(response)
                report: dict | None = None
                for line in response.iter_lines():
                    if not line.startswith("data: "):
                        continue
                    event = json.loads(line[6:])
                    if event.get("type") == "report":
                        report = event
                    else:
                        on_event(event)
        except httpx.HTTPError as exc:
            raise ApiError("Cannot reach the local FastAPI service.") from exc
        except (ValueError, KeyError, TypeError) as exc:
            raise ApiError("The local API returned an invalid investigation stream.") from exc
        if report is None:
            raise ApiError("The local API ended the investigation without a report.")
        try:
            return InvestigateResponse.model_validate(report["response"])
        except (ValueError, ValidationError) as exc:
            raise ApiError("The local API returned an invalid investigation response.") from exc

    def health(self) -> HealthResponse:
        try:
            response = self._client.get("/health")
        except httpx.HTTPError as exc:
            raise ApiError("Cannot reach the local FastAPI service.") from exc
        if response.status_code != 200:
            self._raise_response_error(response)
        try:
            return HealthResponse.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise ApiError("The local API returned an invalid health response.") from exc

    def history(self, limit: int = 20) -> list[HistoryEntry]:
        try:
            response = self._client.get("/history", params={"limit": limit})
        except httpx.HTTPError as exc:
            raise ApiError("Cannot reach the local FastAPI service.") from exc
        if response.status_code != 200:
            self._raise_response_error(response)
        try:
            return [HistoryEntry.model_validate(item) for item in response.json()]
        except (ValueError, ValidationError, TypeError) as exc:
            raise ApiError("The local API returned invalid history.") from exc

    def trace(self, request_id: str) -> TraceDetail | None:
        """Read back the evidence records and retrieved paragraphs of one run."""
        try:
            response = self._client.get(f"/traces/{request_id}")
        except httpx.HTTPError as exc:
            raise ApiError("Cannot reach the local FastAPI service.") from exc
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            self._raise_response_error(response)
        try:
            return TraceDetail.model_validate(response.json())
        except (ValueError, ValidationError, TypeError) as exc:
            raise ApiError("The local API returned an invalid trace detail.") from exc

    def _post(self, path: str, payload: dict) -> httpx.Response:
        try:
            return self._client.post(path, json=payload)
        except httpx.HTTPError as exc:
            raise ApiError("Cannot reach the local FastAPI service.") from exc

    @staticmethod
    def _raise_response_error(response: httpx.Response) -> None:
        if response.status_code == 422:
            try:
                detail = response.json()["detail"]
                if isinstance(detail, dict):
                    raise ApiValidationError(
                        code=detail.get("code", "invalid_request"),
                        message=detail.get("message", "The request is invalid."),
                    )
            except (ValueError, KeyError, TypeError):
                pass
            raise ApiValidationError("invalid_request", "The request is invalid.")
        raise ApiError(f"The local API returned HTTP {response.status_code}.")
