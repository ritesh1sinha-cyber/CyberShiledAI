from __future__ import annotations

import contextlib
import contextvars
import queue
from collections.abc import Iterator
from typing import Any

_END = object()

_emitter: contextvars.ContextVar[Any | None] = contextvars.ContextVar(
    "progress_emitter", default=None
)
_stage: contextvars.ContextVar[str] = contextvars.ContextVar(
    "progress_stage", default="workflow"
)


class ProgressChannel:
    """One-way, thread-safe hand-off of live investigation events to a consumer."""

    def __init__(self) -> None:
        self._queue: queue.Queue[Any] = queue.Queue()

    def publish(self, event: dict) -> None:
        self._queue.put(event)

    def close(self) -> None:
        self._queue.put(_END)

    def __iter__(self) -> Iterator[dict]:
        while True:
            event = self._queue.get()
            if event is _END:
                return
            yield event

    def pending(self) -> list[dict]:
        """Return the events queued so far without waiting for more."""
        events: list[dict] = []
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                return events
            if item is not _END:
                events.append(item)


@contextlib.contextmanager
def bound(channel: ProgressChannel | None) -> Iterator[None]:
    token = _emitter.set(channel)
    try:
        yield
    finally:
        _emitter.reset(token)


@contextlib.contextmanager
def stage(name: str) -> Iterator[None]:
    token = _stage.set(name)
    try:
        yield
    finally:
        _stage.reset(token)


def emit(event_type: str, **fields: Any) -> None:
    """Publish one progress event. A no-op unless a stream consumer is bound."""
    channel = _emitter.get()
    if channel is None:
        return
    channel.publish({"type": event_type, "stage": _stage.get(), **fields})
