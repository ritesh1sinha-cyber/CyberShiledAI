from __future__ import annotations

import json
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from app.config import settings
from app.contracts import HistoryEntry, InvestigateRequest, InvestigateResponse

ROOT = Path(__file__).resolve().parent.parent
INDEX_MANIFEST = ROOT / "data" / "manifests" / "index.json"


def _dump(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    return value


class TraceStore:
    def __init__(
        self, path: str | Path, index_manifest: str | Path | None = None
    ) -> None:
        self.path = Path(path)
        self.index_manifest = Path(index_manifest or INDEX_MANIFEST)
        self._runtime: dict[str, Any] | None = None
        self._lock = threading.Lock()

    def runtime(self) -> dict[str, Any]:
        """Which vectors this investigation retrieved with."""
        # A row that cannot name its model is indistinguishable from one made by a retired index.
        if self._runtime is None:
            try:
                manifest = json.loads(self.index_manifest.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                manifest = {}
            self._runtime = {
                "embeddings_model": manifest.get("model") or settings.embeddings_model,
                "embeddings_dim": manifest.get("dim"),
                "dense_backend": manifest.get("dense_backend"),
                "chunks_sha256": manifest.get("chunks_sha256"),
                "index_generated_at": manifest.get("generated_at"),
            }
        return self._runtime

    def append(
        self,
        request: InvestigateRequest,
        response: InvestigateResponse,
        state: dict[str, Any] | None = None,
        error: dict[str, str] | None = None,
    ) -> None:
        state = state or {}
        package = state.get("package")
        record = {
            "trace_id": response.trace_id,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "request": request.model_dump(mode="json"),
            "response": response.model_dump(mode="json"),
            "evidence_interpretation": _dump(state.get("evidence_interpretation")),
            "retrieval_meta": _dump(state.get("retrieval_meta")),
            "runtime": self.runtime(),
            "revised": bool(state.get("revised")),
            "first_draft_invalid": bool(state.get("first_draft_invalid")),
            "first_draft_invalid_reason": state.get("first_draft_invalid_reason"),
            "draft_invalid_reason": state.get("draft_invalid_reason"),
            "draft_fallback_reason": state.get("draft_fallback_reason"),
            "revision_review_failed": bool(state.get("revision_review_failed")),
            "first_review_failed": bool(state.get("first_review_failed")),
            "refusal_reason": state.get("refusal_reason"),
            "evidence": [_dump(item) for item in getattr(package, "evidence", [])],
            "contexts": [_dump(item) for item in getattr(package, "contexts", [])],
            "model_calls": [
                _dump(item) for item in state.get("model_calls", [])
            ],
            "error": error,
        }
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    def list_recent(self, limit: int = 20) -> list[HistoryEntry]:
        with self._lock:
            if not self.path.exists():
                return []
            with self.path.open("r", encoding="utf-8") as handle:
                records = deque(
                    (json.loads(line) for line in handle if line.strip()), maxlen=limit
                )
        return [self._history_entry(record) for record in reversed(records)]

    def get(self, request_id: str) -> dict[str, Any] | None:
        """Return the full stored record for one investigation, or None."""
        with self._lock:
            if not self.path.exists():
                return None
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    if record.get("trace_id") == request_id:
                        return record
        return None

    @staticmethod
    def _history_entry(record: dict[str, Any]) -> HistoryEntry:
        response = record["response"]
        report = response["report"]
        timings = response["timings"]
        total_ms = next(
            (item["ms"] for item in timings if item["stage"] == "total"),
            sum(item["ms"] for item in timings),
        )
        runtime = record.get("runtime") or {}
        return HistoryEntry(
            trace_id=response["trace_id"],
            request_id=report["request_id"],
            status=report["status"],
            query=record["request"]["query"],
            summary=report["summary"],
            generated_at=report["generated_at"],
            total_ms=total_ms,
            embeddings_model=runtime.get("embeddings_model"),
            index_chunks_sha256=runtime.get("chunks_sha256"),
        )
