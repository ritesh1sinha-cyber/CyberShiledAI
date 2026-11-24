import httpx
import pytest

from app.config import settings
from app.qwen import QwenClient, QwenError


def _mock_transport(monkeypatch, handler):
    import app.qwen as qwen_module

    real_client = httpx.Client
    monkeypatch.setattr(
        qwen_module.httpx,
        "Client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler)),
    )
    waits = []
    monkeypatch.setattr(qwen_module.time, "sleep", lambda seconds: waits.append(seconds))
    return waits


def _ok(request):
    return httpx.Response(
        200,
        json={
            "model": "Qwen/Qwen3-8B",
            "choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        },
    )


def _configure(monkeypatch):
    monkeypatch.setattr(settings, "qwen_base_url", "https://unit.test/v1")
    monkeypatch.setattr(settings, "qwen_api_key", "test-key")
    monkeypatch.setattr(settings, "qwen_ca_cert", True)


def test_qwen_caps_output_to_combined_context_budget(monkeypatch):
    observed = {}

    def handler(request):
        observed["payload"] = request.read().decode("utf-8")
        return httpx.Response(
            200,
            json={
                "model": "Qwen/Qwen3-8B",
                "choices": [
                    {
                        "message": {"content": "{}"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 7169, "completion_tokens": 10},
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
    response = QwenClient().complete("s" * 1000, "u" * 21000, max_tokens=1024)
    payload = __import__("json").loads(observed["payload"])
    assert 1 <= payload["max_tokens"] < 1024
    assert response.max_tokens == payload["max_tokens"]
    assert payload["max_tokens"] + 7169 < 8192


def test_transport_failure_is_re_asked_once_then_succeeds(monkeypatch):
    _configure(monkeypatch)
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            raise httpx.ConnectTimeout("timed out")
        return _ok(request)

    waits = _mock_transport(monkeypatch, handler)
    response = QwenClient().complete("s", "u")
    assert response.finish_reason == "stop"
    assert len(calls) == 2
    assert waits == [QwenClient.RETRY_BACKOFF_S]


def test_persistent_transport_failure_raises_after_the_bound(monkeypatch):
    _configure(monkeypatch)
    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.ReadError("reset")

    _mock_transport(monkeypatch, handler)
    with pytest.raises(QwenError) as raised:
        QwenClient().complete("s", "u")
    assert len(calls) == QwenClient.ATTEMPTS
    assert "ReadError" in str(raised.value)


@pytest.mark.parametrize("status", [429, 503])
def test_transient_status_codes_are_re_asked(monkeypatch, status):
    _configure(monkeypatch)
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(status, text="busy")
        return _ok(request)

    _mock_transport(monkeypatch, handler)
    assert QwenClient().complete("s", "u").finish_reason == "stop"
    assert len(calls) == 2


def test_rate_limit_still_raises_when_the_re_ask_is_also_refused(monkeypatch):
    _configure(monkeypatch)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(429, text="concurrent request limit")

    _mock_transport(monkeypatch, handler)
    with pytest.raises(QwenError, match="Rate Limit"):
        QwenClient().complete("s", "u")
    assert len(calls) == QwenClient.ATTEMPTS


def test_a_bad_request_is_not_re_asked(monkeypatch):
    _configure(monkeypatch)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(400, text="invalid json_mode")

    waits = _mock_transport(monkeypatch, handler)
    with pytest.raises(QwenError, match="HTTP 400"):
        QwenClient().complete("s", "u")
    assert len(calls) == 1
    assert waits == []
