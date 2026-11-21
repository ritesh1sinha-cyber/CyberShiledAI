from __future__ import annotations

import contextlib
import contextvars
from collections.abc import Iterator
from typing import Any
from urllib.parse import quote

from app.config import settings

_current_parent: contextvars.ContextVar[Any | None] = contextvars.ContextVar(
    "langfuse_parent", default=None
)
_current_stage: contextvars.ContextVar[str] = contextvars.ContextVar(
    "langfuse_stage", default="workflow"
)
_current_output: contextvars.ContextVar[dict] = contextvars.ContextVar(
    "langfuse_output", default={}
)
_client: Any | None = None
_client_unavailable = False
_trace: Any | None = None
_trace_id: str | None = None
_project_id: str | None = None
_prompt_cache: dict[str, Any] = {}

STAGE_PROMPT_MAP = {
    "analyst": "analyst_agent_system",
    "critic": "critic_agent_system",
    "evidence": "evidence_agent_system",
    "single_agent": "single_agent_system",
}


def _get_prompt_obj(stage: str) -> Any | None:
    prompt_name = STAGE_PROMPT_MAP.get(stage)
    if not prompt_name:
        return None
    if prompt_name in _prompt_cache:
        return _prompt_cache[prompt_name]
    client = _get_client()
    if client is None:
        return None
    try:
        obj = client.get_prompt(prompt_name)
        _prompt_cache[prompt_name] = obj
        return obj
    except Exception:
        _prompt_cache[prompt_name] = None
        return None


def _loopback(host: str) -> bool:
    scheme, _, rest = host.partition("://")
    if scheme not in {"http", "https"}:
        return False
    authority = rest.split("/", 1)[0]
    hostname = authority.rsplit("@", 1)[-1].split(":", 1)[0].strip("[]")
    return hostname in {"127.0.0.1", "localhost", "::1"}


def enabled() -> bool:
    return bool(
        settings.langfuse_enabled
        and settings.langfuse_public_key
        and settings.langfuse_secret_key
        and _loopback(settings.langfuse_host)
    )


def _get_client() -> Any | None:
    global _client, _client_unavailable
    if not enabled():
        return None
    if _client is not None or _client_unavailable:
        return _client
    try:
        from langfuse import Langfuse

        _client = Langfuse(
            public_key=settings.langfuse_public_key,
            secret_key=settings.langfuse_secret_key,
            host=settings.langfuse_host,
        )
    except Exception:
        _client_unavailable = True
        _client = None
    return _client


def flush() -> None:
    global _client
    client = _client
    if client is None:
        return
    try:
        client.flush()
    except Exception:
        pass


def jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        try:
            return dump(mode="json")
        except Exception:
            pass
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    return str(value)


def start_trace(name: str, trace_id: str, input_data: Any, metadata: Any) -> None:
    global _trace, _trace_id
    try:
        client = _get_client()
        if client is None:
            return
        _trace = client.trace(
            id=trace_id,
            name=name,
            input=jsonable(input_data),
            metadata=jsonable(metadata),
        )
        _trace_id = trace_id
    except Exception:
        _trace = None
        _trace_id = None


@contextlib.contextmanager
def span(
    name: str,
    input_data: Any = None,
    metadata: Any = None,
) -> Iterator[None]:
    handle = None
    output: dict[str, Any] = {}
    token_parent = _current_parent.set(None)
    token_stage = _current_stage.set(name)
    token_output = _current_output.set(output)
    level, status_message = "DEFAULT", None
    try:
        try:
            if _trace is not None:
                handle = _trace.span(
                    name=name, input=jsonable(input_data), metadata=jsonable(metadata)
                )
                _current_parent.set(handle)
        except Exception:
            handle = None
        yield
    except Exception as exc:
        level, status_message = "ERROR", f"{type(exc).__name__}: {exc}"
        raise
    finally:
        _current_parent.reset(token_parent)
        _current_stage.reset(token_stage)
        _current_output.reset(token_output)
        if handle is not None:
            try:
                handle.end(
                    output=jsonable(output.get("payload")),
                    level=level,
                    status_message=status_message,
                )
            except Exception:
                pass


def record_output(payload: Any) -> None:
    """Attach the node result to the span that is currently open."""
    if _current_parent.get() is None:
        return
    try:
        _current_output.get()["payload"] = payload
    except (KeyError, TypeError):
        pass


def record_generation(
    model: str,
    system_prompt: str,
    user_prompt: str,
    output: Any,
    usage: dict[str, Any],
    metadata: dict[str, Any],
    level: str = "DEFAULT",
    status_message: str | None = None,
) -> None:
    parent = _current_parent.get() or _trace
    if parent is None:
        return
    try:
        stage = _current_stage.get()
        prompt_obj = _get_prompt_obj(stage)
        gen_kwargs = {
            "name": stage,
            "model": model,
            "input": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        if prompt_obj is not None:
            gen_kwargs["prompt"] = prompt_obj
        generation = parent.generation(
            **gen_kwargs,
            output=jsonable(output),
            usage={
                key: value
                for key, value in usage.items()
                if isinstance(value, int) and value > 0
            }
            or None,
            metadata=jsonable(metadata),
            level=level,
            status_message=status_message,
        )
        generation.end()
    except Exception:
        pass


def score(
    name: str,
    value: float | str,
    data_type: str,
    comment: str | None = None,
    trace_id: str | None = None,
    score_id: str | None = None,
) -> None:
    """Attach one deterministic measurement to a trace. Never judges text with a model."""
    target = trace_id or _trace_id
    if target is None:
        return
    try:
        client = _get_client()
        if client is None:
            return
        client.score(
            id=score_id,
            name=name,
            value=value,
            data_type=data_type,
            comment=comment,
            trace_id=target,
        )
    except Exception:
        pass


def trace_url(trace_id: str | None) -> str | None:
    if not trace_id or not enabled():
        return None
    global _project_id
    try:
        client = _get_client()
        if client is None:
            return None
        if _project_id is None:
            # Private in the v2 SDK; the only public way to resolve the project
            # slug that the trace URL is built from.
            _project_id = client._get_project_id()
        if not _project_id:
            return None
        host = settings.langfuse_host.rstrip("/")
        return f"{host}/project/{_project_id}/traces/{quote(trace_id, safe='')}"
    except Exception:
        return None


def finish_trace(output: Any, metadata: Any) -> None:
    global _trace, _trace_id
    trace, _trace = _trace, None
    _trace_id = None
    try:
        if trace is not None:
            trace.update(output=jsonable(output), metadata=jsonable(metadata))
    except Exception:
        pass
    try:
        if _client is not None:
            _client.flush()
    except Exception:
        pass
