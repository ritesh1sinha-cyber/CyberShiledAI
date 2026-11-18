"""Measure real generation throughput, TTFT and JSON-mode adherence."""

from __future__ import annotations

import json
import statistics
import sys
import time

import httpx

from app.config import settings

URL = settings.qwen_base_url.rstrip("/") + "/chat/completions"
HEADERS = {"Authorization": f"Bearer {settings.qwen_api_key}"}


def _payload(messages: list[dict], max_tokens: int, stream: bool = False) -> dict:
    return {
        "model": settings.qwen_model,
        "messages": messages,
        "temperature": 0,
        "max_tokens": max_tokens,
        "stream": stream,
    }


def run_once(client: httpx.Client, messages: list[dict], max_tokens: int) -> dict:
    start = time.perf_counter()
    resp = client.post(URL, json=_payload(messages, max_tokens), headers=HEADERS)
    elapsed = time.perf_counter() - start
    resp.raise_for_status()
    body = resp.json()
    usage = body.get("usage") or {}
    out_tokens = usage.get("completion_tokens") or 0
    return {
        "elapsed": elapsed,
        "prompt_tokens": usage.get("prompt_tokens"),
        "out_tokens": out_tokens,
        "tok_s": out_tokens / elapsed if out_tokens else None,
        "content": body["choices"][0]["message"]["content"],
    }


def measure_ttft(client: httpx.Client, max_tokens: int = 256) -> tuple[float | None, float]:
    messages = [{"role": "user", "content": "Count from 1 to 60, comma separated."}]
    start = time.perf_counter()
    first = None
    with client.stream(
        "POST", URL, json=_payload(messages, max_tokens, stream=True), headers=HEADERS
    ) as resp:
        resp.raise_for_status()
        for line in resp.iter_lines():
            if not line.startswith("data: "):
                continue
            data = line[6:].strip()
            if data == "[DONE]":
                break
            try:
                obj = json.loads(data)
            except json.JSONDecodeError:
                continue
            choices = obj.get("choices") or [{}]
            delta = (choices[0].get("delta") or {}).get("content") or ""
            if delta and first is None:
                first = time.perf_counter() - start
    return first, time.perf_counter() - start


def check_json(client: httpx.Client) -> list[bool]:
    messages = [
        {
            "role": "system",
            "content": (
                "Return only a JSON object matching this shape, no prose, no code fences: "
                '{"intent": string, "cve_ids": string[], "needs_clarification": boolean}. '
                "Use an empty array when no CVE is present."
            ),
        },
        {
            "role": "user",
            "content": (
                'Classify: "Is CVE-2021-44228 exploited in the wild? '
                'Also what about the logging library issue from December 2021?"'
            ),
        },
    ]
    ok = []
    for _ in range(3):
        resp = client.post(
            URL,
            json={
                **_payload(messages, 160),
                "response_format": {"type": "json_object"},
            },
            headers=HEADERS,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        try:
            parsed = json.loads(content)
            ok.append(
                isinstance(parsed.get("intent"), str)
                and isinstance(parsed.get("cve_ids"), list)
                and isinstance(parsed.get("needs_clarification"), bool)
            )
        except (json.JSONDecodeError, AttributeError):
            ok.append(False)
    return ok


def main() -> int:
    summary_prompt = [
        {
            "role": "user",
            "content": (
                "Write a technical summary of how remote code execution in a Java logging "
                "library is typically exploited and mitigated. Aim for 120 words."
            ),
        }
    ]
    json_prompt = [
        {
            "role": "user",
            "content": (
                "Return a JSON object with keys summary (about 120 words), "
                "severity_rationale (about 100 words), remediation (5 bullet strings), "
                "limitations (3 strings)."
            ),
        }
    ]

    rows = []
    with httpx.Client(timeout=180.0, verify=settings.qwen_ca_cert) as client:
        for label, messages, cap in (
            ("short-64", summary_prompt, 64),
            ("summary-256", summary_prompt, 256),
            ("report-640", json_prompt, 640),
        ):
            r = run_once(client, messages, cap)
            rows.append((label, r))
            print(
                f"{label:<12} {r['elapsed']:6.2f}s  out={r['out_tokens']:>4}  "
                f"{r['tok_s'] or 0:5.1f} tok/s  prompt={r['prompt_tokens']}"
            )

        first, total = measure_ttft(client)
        print(f"{'ttft-stream':<12} ttft={first or 0:5.2f}s  total={total:6.2f}s")

        adherence = check_json(client)
        print(f"{'json-mode':<12} valid={sum(adherence)}/{len(adherence)} runs")

    rates = [r["tok_s"] for _, r in rows if r["tok_s"]]
    if rates:
        print()
        print(f"median throughput: {statistics.median(rates):.1f} tok/s")
        print(f"longest generation: {max(r['out_tokens'] for _, r in rows)} tokens")
    return 0


if __name__ == "__main__":
    sys.exit(main())
