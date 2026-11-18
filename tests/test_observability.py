import pytest

from app import observability
from app.config import settings


class Handle:
    def __init__(self, events, kind, start):
        self.events = events
        self.kind = kind
        self.start = start

    def span(self, **kwargs):
        return Handle(self.events, "span", kwargs)

    def generation(self, **kwargs):
        return Handle(self.events, "generation", kwargs)

    def end(self, **kwargs):
        self.events.append((self.kind, self.start, kwargs))

    def update(self, **kwargs):
        self.events.append(("update", self.start, kwargs))

    def score(self, **kwargs):
        self.events.append(("score", self.start, kwargs))
        return self


def recorder(monkeypatch):
    events = []
    monkeypatch.setattr(observability, "_trace", Handle(events, "trace", {}))
    return events


def keys(monkeypatch, enabled=True, host="http://127.0.0.1:3100"):
    monkeypatch.setattr(settings, "langfuse_enabled", enabled)
    monkeypatch.setattr(settings, "langfuse_host", host)
    monkeypatch.setattr(settings, "langfuse_public_key", "pk-lf-test")
    monkeypatch.setattr(settings, "langfuse_secret_key", "sk-lf-test")


def test_tracing_is_off_unless_enabled_with_keys_and_loopback(monkeypatch):
    monkeypatch.setattr(settings, "langfuse_enabled", True)
    monkeypatch.setattr(settings, "langfuse_public_key", "")
    assert observability.enabled() is False
    keys(monkeypatch, enabled=False)
    assert observability.enabled() is False
    keys(monkeypatch, enabled=True)
    assert observability.enabled() is True


def test_public_langfuse_host_is_refused(monkeypatch):
    keys(monkeypatch, enabled=True, host="https://cloud.langfuse.com")
    assert observability.enabled() is False


def test_disabled_tracing_is_a_no_op(monkeypatch):
    client = Handle([], "client", {})
    monkeypatch.setattr(observability, "_client", client)
    observability.start_trace("cve_investigation", "CS-1", {"query": "q"}, {})
    with observability.span("analyst", {}):
        observability.record_generation("model", "sys", "usr", "out", {}, {})
        observability.record_output({"draft": {}})
    observability.finish_trace({"status": "completed"}, {})
    assert client.events == []


def test_span_records_generation_and_node_output(monkeypatch):
    events = recorder(monkeypatch)
    with observability.span("analyst", {"revising": False}):
        observability.record_generation(
            "Qwen/Qwen3-8B",
            "system rules",
            "evidence package",
            '{"summary": "text"}',
            {"input": 1200, "output": 300, "total": 1500, "unknown": None},
            {"finish_reason": "stop", "latency_ms": 4200},
        )
        observability.record_output({"draft": {"summary": "text"}})
    kinds = [event[0] for event in events]
    assert kinds == ["generation", "span"]
    generation = events[0]
    assert generation[1]["input"] == [
        {"role": "system", "content": "system rules"},
        {"role": "user", "content": "evidence package"},
    ]
    assert generation[1]["usage"] == {"input": 1200, "output": 300, "total": 1500}
    assert generation[1]["name"] == "analyst"
    assert events[1][2]["output"] == {"draft": {"summary": "text"}}


def test_truncated_output_is_flagged_and_errors_are_recorded(monkeypatch):
    events = recorder(monkeypatch)
    observability.record_generation(
        "Qwen/Qwen3-8B",
        "s",
        "u",
        "partial json",
        {"output": 400},
        {"finish_reason": "length"},
        level="WARNING",
        status_message="output truncated at the token budget",
    )
    assert events[0][1]["level"] == "WARNING"
    assert events[0][1]["status_message"] == "output truncated at the token budget"

    with pytest.raises(ValueError):
        with observability.span("critic", {}):
            raise ValueError("bad review")
    assert events[-1][2]["level"] == "ERROR"
    assert "ValueError: bad review" in events[-1][2]["status_message"]


def test_finish_trace_records_status_on_the_trace(monkeypatch):
    events = recorder(monkeypatch)
    observability.finish_trace(
        {"status": "partial"}, {"revised": True, "cve_id": "CVE-2021-44228"}
    )
    assert events[0][0] == "update"
    assert events[0][2]["metadata"] == {"revised": True, "cve_id": "CVE-2021-44228"}
    assert observability._trace is None


def test_record_output_ignored_without_open_span(monkeypatch):
    events = recorder(monkeypatch)
    observability.record_output({"draft": {}})
    assert events == []


class Client:
    def __init__(self, events, project_id="proj-1"):
        self.events = events
        self.project_id = project_id

    def trace(self, **kwargs):
        self.events.append(("trace", kwargs, {}))
        return Handle(self.events, "trace", kwargs)

    def score(self, **kwargs):
        self.events.append(("score", {}, kwargs))
        return self

    def _get_project_id(self):
        return self.project_id

    def flush(self):
        self.events.append(("flush", {}, {}))


def test_score_writes_an_explicit_trace_id(monkeypatch):
    keys(monkeypatch, enabled=True)
    events = []
    client = Client(events)
    monkeypatch.setattr(observability, "_client", client)
    monkeypatch.setattr(observability, "_trace_id", None)
    observability.score("deterministic_verdict", "PASS", "CATEGORICAL", trace_id="CS-1")
    assert events[0] == (
        "score",
        {},
        {
            "id": None,
            "name": "deterministic_verdict",
            "value": "PASS",
            "data_type": "CATEGORICAL",
            "comment": None,
            "trace_id": "CS-1",
        },
    )


def test_score_without_any_trace_id_is_a_no_op(monkeypatch):
    keys(monkeypatch, enabled=True)
    events = []
    monkeypatch.setattr(observability, "_client", Client(events))
    monkeypatch.setattr(observability, "_trace_id", None)
    observability.score("deterministic_verdict", "PASS", "CATEGORICAL")
    assert events == []


def test_start_and_finish_own_the_trace_id(monkeypatch):
    keys(monkeypatch, enabled=True)
    events = []
    client = Client(events)
    monkeypatch.setattr(observability, "_client", client)
    monkeypatch.setattr(observability, "_trace_id", None)
    observability.start_trace("cve_investigation", "CS-9", {"query": "q"}, {})
    assert observability._trace_id == "CS-9"
    observability.score("deterministic_status", "partial", "CATEGORICAL", comment="flag")
    assert events[-1][2]["trace_id"] == "CS-9"
    observability.finish_trace({"status": "partial"}, {})
    assert observability._trace_id is None


def test_trace_url_is_built_only_for_a_loopback_project(monkeypatch):
    events = []
    keys(monkeypatch, enabled=True)
    monkeypatch.setattr(observability, "_client", Client(events))
    monkeypatch.setattr(observability, "_project_id", None)
    assert (
        observability.trace_url("CS-20261117072335696363")
        == "http://127.0.0.1:3100/project/proj-1/traces/CS-20261117072335696363"
    )
    assert observability._project_id == "proj-1"

    keys(monkeypatch, enabled=True, host="https://cloud.langfuse.com")
    assert observability.trace_url("CS-1") is None
    monkeypatch.setattr(settings, "langfuse_enabled", False)
    assert observability.trace_url("CS-1") is None


def test_trace_url_encodes_the_trace_id(monkeypatch):
    keys(monkeypatch, enabled=True)
    monkeypatch.setattr(observability, "_client", Client([]))
    monkeypatch.setattr(observability, "_project_id", "proj-1")
    url = observability.trace_url("CS-1](http://127.0.0.1:9/evil")
    assert "]" not in url.split("/traces/")[1]
    assert "%5D" in url

