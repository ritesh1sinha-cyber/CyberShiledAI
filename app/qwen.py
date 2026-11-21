from __future__ import annotations

import math
import time
from dataclasses import dataclass

import httpx

from app.config import settings
from app import observability, progress


class QwenError(RuntimeError):
    pass


@dataclass(frozen=True)
class QwenResponse:
    content: str
    model: str
    latency_ms: int
    prompt_tokens: int | None
    completion_tokens: int | None
    finish_reason: str | None
    max_tokens: int | None = None


class QwenClient:
    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    def complete(self, system: str, user: str, max_tokens: int = 512, json_mode: bool = True) -> QwenResponse:
        base_url = settings.qwen_base_url.rstrip("/")
        if "example.invalid" in base_url or not settings.qwen_api_key:
            raise QwenError("Qwen endpoint or API key is not configured.")
        # The endpoint caps input plus output at 8,192 tokens. Use a
        # conservative character estimate and reserve a small tokenizer margin.
        estimated_prompt_tokens = math.ceil((len(system) + len(user) + 48) / 3)
        if estimated_prompt_tokens >= 7800:
            context_limited_max = 256
        elif estimated_prompt_tokens >= 6500:
            context_limited_max = 512
        else:
            context_limited_max = 1024
        available_output = 8192 - estimated_prompt_tokens - 128
        if available_output < 128:
            effective_max_tokens = min(max_tokens, context_limited_max)
        else:
            effective_max_tokens = min(max_tokens, context_limited_max, available_output)
        payload = {
            "model": settings.qwen_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "max_tokens": effective_max_tokens,
            "stream": False,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        progress.emit(
            "model_start",
            model=settings.qwen_model,
            max_tokens=effective_max_tokens,
            estimated_prompt_tokens=estimated_prompt_tokens,
        )
        started = time.perf_counter()
        try:
            with httpx.Client(timeout=self.timeout, verify=settings.qwen_ca_cert) as client:
                response = client.post(
                    base_url + "/chat/completions",
                    json=payload,
                    headers={"Authorization": f"Bearer {settings.qwen_api_key}"},
                )
        except httpx.HTTPError as exc:
            latency_ms = max(0, round((time.perf_counter() - started) * 1000))
            progress.emit(
                "model_end",
                ok=False,
                ms=latency_ms,
                reason=f"transport failure: {type(exc).__name__}",
            )
            observability.record_generation(
                settings.qwen_model,
                system,
                user,
                None,
                {},
                {"max_tokens": effective_max_tokens},
                level="ERROR",
                status_message=f"transport failure: {type(exc).__name__}",
            )
            raise QwenError(f"Qwen request failed ({type(exc).__name__}): {exc}") from exc
        latency_ms = max(0, round((time.perf_counter() - started) * 1000))
        if response.status_code != 200:
            detail = " ".join(response.text.split())[:300]
            progress.emit(
                "model_end", ok=False, ms=latency_ms, reason=f"HTTP {response.status_code}"
            )
            observability.record_generation(
                settings.qwen_model,
                system,
                user,
                detail,
                {},
                {"max_tokens": effective_max_tokens},
                level="ERROR",
                status_message=f"HTTP {response.status_code}",
            )
            if response.status_code == 429:
                raise QwenError(f"HTTP 429: Rate Limit / Concurrent Request Limit Exceeded ({detail})")
            raise QwenError(f"Qwen returned HTTP {response.status_code}: {detail}")
        try:
            body = response.json()
            choice = body["choices"][0]
            content = choice["message"]["content"]
            if not isinstance(content, str) or not content.strip():
                raise ValueError("empty content")
            usage = body.get("usage") or {}
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            progress.emit(
                "model_end", ok=False, ms=latency_ms, reason="unexpected response structure"
            )
            observability.record_generation(
                settings.qwen_model,
                system,
                user,
                " ".join(response.text.split())[:500],
                {},
                {"max_tokens": effective_max_tokens},
                level="ERROR",
                status_message=f"unexpected response structure: {type(exc).__name__}",
            )
            raise QwenError("Qwen returned an unexpected response structure.") from exc
        result = QwenResponse(
            content=content,
            model=body.get("model") or settings.qwen_model,
            latency_ms=latency_ms,
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            finish_reason=choice.get("finish_reason"),
            max_tokens=effective_max_tokens,
        )
        progress.emit(
            "model_end",
            ok=True,
            model=result.model,
            ms=result.latency_ms,
            prompt_tokens=result.prompt_tokens,
            completion_tokens=result.completion_tokens,
            finish_reason=result.finish_reason,
        )
        observability.record_generation(
            result.model,
            system,
            user,
            result.content,
            {
                "input": result.prompt_tokens,
                "output": result.completion_tokens,
                "total": (
                    None
                    if result.prompt_tokens is None or result.completion_tokens is None
                    else result.prompt_tokens + result.completion_tokens
                ),
            },
            {
                "finish_reason": result.finish_reason,
                "latency_ms": result.latency_ms,
                "max_tokens": result.max_tokens,
                "estimated_prompt_tokens": estimated_prompt_tokens,
            },
            level="WARNING" if result.finish_reason == "length" else "DEFAULT",
            status_message="output truncated at the token budget"
            if result.finish_reason == "length"
            else None,
        )
        return result
