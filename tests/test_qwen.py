import httpx

from app.config import settings
from app.qwen import QwenClient


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
