from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from typing import Any

from app import progress
from app.config import settings
from app.contracts import (
    InvestigateRequest,
    InvestigateResponse,
    Report,
    StageTiming,
)
from app.history import TraceStore
from app.policy import refusal_reason
from app.workflow import InvestigationWorkflow


class InvestigationService:
    def __init__(
        self,
        workflow: InvestigationWorkflow | None = None,
        store: TraceStore | None = None,
        clock: Callable[[], datetime] | None = None,
    ):
        self._workflow = workflow
        self.store = store or TraceStore(settings.trace_file)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()

    def investigate(self, request: InvestigateRequest) -> InvestigateResponse:
        with self._lock:
            started = time.perf_counter()
            request_id = f"CS-{self._clock():%Y%m%d%H%M%S%f}"
            progress.emit("begin", request_id=request_id, query=request.query)
            state = {}
            error = None
            try:
                reason = refusal_reason(request.query)
                if reason:
                    state = {"refusal_reason": reason}
                    progress.emit("refused", reason=reason)
                    report = self._refused_report(request_id, reason)
                else:
                    if self._workflow is None:
                        self._workflow = InvestigationWorkflow()
                    state = self._workflow.run(request, request_id=request_id)
                    report = Report.model_validate(state["report"])
                    if report.request_id != request_id:
                        raise RuntimeError("Workflow returned a mismatched request ID.")
            except Exception as exc:
                state = getattr(exc, "investigation_state", {})
                model_call = getattr(exc, "model_call", None)
                stage_timing = getattr(exc, "stage_timing", None)
                if model_call is not None:
                    state["model_calls"] = [*state.get("model_calls", []), model_call]
                if stage_timing is not None:
                    state["timings"] = [*state.get("timings", []), stage_timing]
                error = {"type": type(exc).__name__, "message": str(exc)[:500]}
                report = Report(
                    request_id=request_id,
                    status="failed",
                    summary="Investigation failed; see limitations.",
                    limitations=[
                        "The investigation stopped before a validated report could be assembled. "
                        "See the local trace for the recorded error type."
                    ],
                    generated_at=self._clock(),
                )

            timings = [
                *state.get("timings", []),
                StageTiming(
                    stage="total",
                    ms=max(0, round((time.perf_counter() - started) * 1000)),
                ),
            ]
            review = state.get("review")
            if review is not None and isinstance(review, dict):
                try:
                    from app.contracts import CriticReview
                    review = CriticReview.model_validate(review)
                except Exception:
                    pass
            response = InvestigateResponse(
                report=report,
                trace_id=request_id,
                timings=timings,
                critic_review=review,
                revised=bool(state.get("revised")),
            )
            self.store.append(request, response, state=state, error=error)
            return response

    def investigate_stream(self, request: InvestigateRequest) -> Iterator[dict]:
        """Yield each agent's progress live, then the final response, for one investigation.

        The workflow runs in a worker thread bound to a progress channel; the
        serialized single-Qwen-slot behaviour of investigate() is unchanged.
        """
        channel = progress.ProgressChannel()
        outcome: dict[str, Any] = {}

        def worker() -> None:
            try:
                with progress.bound(channel):
                    outcome["response"] = self.investigate(request)
            except Exception as exc:
                outcome["error"] = exc
            finally:
                channel.close()

        threading.Thread(target=worker, daemon=True).start()
        yield from channel
        if "error" in outcome:
            raise outcome["error"]
        yield {"type": "report", "response": outcome["response"].model_dump(mode="json")}

    def _refused_report(
        self, request_id: str, reason: str
    ) -> Report:
        return Report(
            request_id=request_id,
            status="refused",
            summary=reason,
            limitations=[
                "No evidence collection, drafting, critique, or final validation was performed."
            ],
            generated_at=self._clock(),
        )
