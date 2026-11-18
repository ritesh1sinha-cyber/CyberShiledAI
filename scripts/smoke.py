"""Prove the four external dependencies work before building on them."""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import numpy as np

from app.config import settings
from app.embeddings import EmbeddingsClient, EmbeddingsError


@dataclass
class Result:
    name: str
    ok: bool
    detail: str


def _brief(text: str, limit: int = 300) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit] + "..."


def check_llm() -> Result:
    base = settings.qwen_base_url.rstrip("/")
    if "example.invalid" in base:
        return Result("qwen", False, "QWEN_BASE_URL is still the placeholder; fill .env")
    if not settings.qwen_api_key:
        return Result("qwen", False, "QWEN_API_KEY is empty; fill .env")

    url = f"{base}/chat/completions"
    headers = {"Authorization": f"Bearer {settings.qwen_api_key}"}
    payload = {
        "model": settings.qwen_model,
        "messages": [
            {"role": "system", "content": "Return JSON only, no prose."},
            {"role": "user", "content": 'Return {"ok": true}.'},
        ],
        "temperature": 0,
        "max_tokens": 32,
    }

    json_mode = True
    try:
        with httpx.Client(
            timeout=settings.http_timeout_s, verify=settings.qwen_ca_cert
        ) as client:
            start = time.perf_counter()
            resp = client.post(
                url,
                json={**payload, "response_format": {"type": "json_object"}},
                headers=headers,
            )
            if resp.status_code == 400:
                json_mode = False
                resp = client.post(url, json=payload, headers=headers)
            elapsed = time.perf_counter() - start
    except httpx.HTTPError as exc:
        return Result("qwen", False, f"{type(exc).__name__}: {exc}")

    if resp.status_code != 200:
        return Result("qwen", False, f"HTTP {resp.status_code} at {url}: {_brief(resp.text)}")

    try:
        body = resp.json()
        content = body["choices"][0]["message"]["content"]
        usage = body.get("usage") or {}
    except (ValueError, KeyError, IndexError, TypeError):
        return Result("qwen", False, f"unexpected response: {_brief(resp.text)}")

    out_tokens = usage.get("completion_tokens") or 0
    rate = f"{out_tokens / elapsed:.1f} out-tok/s" if out_tokens else "out-tok/s unknown"
    detail = (
        f"model={settings.qwen_model} latency={elapsed:.2f}s {rate} "
        f"json_mode={'yes' if json_mode else 'NO (400 on response_format)'} "
        f"usage={json.dumps(usage)} reply={_brief(content, 120)}"
    )
    return Result("qwen", True, detail)


def check_nvd() -> Result:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    try:
        start = time.perf_counter()
        resp = httpx.get(
            url,
            params={"cveId": "CVE-2021-44228"},
            headers=headers,
            timeout=settings.http_timeout_s,
        )
        elapsed = time.perf_counter() - start
    except httpx.HTTPError as exc:
        return Result("nvd", False, f"{type(exc).__name__}: {exc}")

    if resp.status_code != 200:
        return Result("nvd", False, f"HTTP {resp.status_code}: {_brief(resp.text)}")

    vulns = resp.json().get("vulnerabilities") or []
    if not vulns:
        return Result("nvd", False, "HTTP 200 but no vulnerabilities returned")

    metrics = vulns[0]["cve"].get("metrics") or {}
    score = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            score = metrics[key][0]["cvssData"]["baseScore"]
            break
    key_state = "yes" if settings.nvd_api_key else "NO (5 req/30s)"
    return Result(
        "nvd",
        True,
        f"latency={elapsed:.2f}s api_key={key_state} "
        f"metric_sets={sorted(metrics)} base_score={score}",
    )


def check_kev() -> Result:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        start = time.perf_counter()
        resp = httpx.get(url, timeout=60.0, follow_redirects=True)
        elapsed = time.perf_counter() - start
    except httpx.HTTPError as exc:
        return Result("kev", False, f"{type(exc).__name__}: {exc}")

    if resp.status_code != 200:
        return Result("kev", False, f"HTTP {resp.status_code}: {_brief(resp.text)}")

    body = resp.json()
    detail = (
        f"latency={elapsed:.2f}s entries={len(body.get('vulnerabilities') or [])} "
        f"catalog={body.get('catalogVersion')} released={body.get('dateReleased')}"
    )
    return Result("kev", True, detail)


def check_embeddings() -> Result:
    try:
        start = time.perf_counter()
        matrix = EmbeddingsClient().embed(
            ["CVE-2021-44228 remote code execution in the resolver", "known exploited vulnerability"]
        )
        elapsed = time.perf_counter() - start
    except EmbeddingsError as exc:
        return Result("embeddings", False, str(exc))
    except httpx.HTTPError as exc:
        return Result("embeddings", False, f"{type(exc).__name__}: {exc}")

    norms = np.linalg.norm(matrix, axis=1)
    detail = (
        f"model={settings.embeddings_model} dims={matrix.shape[1]} latency={elapsed:.2f}s "
        f"unit_norm={bool((abs(norms - 1.0) < 1e-3).all())} "
        f"cross_text_cosine={float(np.dot(matrix[0], matrix[1])):.4f}"
    )
    ok = matrix.shape[0] == 2 and matrix.shape[1] > 0
    manifest = Path(__file__).resolve().parent.parent / "data" / "manifests" / "index.json"
    if manifest.exists():
        built = json.loads(manifest.read_text("utf-8"))
        # An index the running endpoint cannot search is the failure a fresh checkout hits first.
        if built.get("dim") != matrix.shape[1] or built.get("model") != settings.embeddings_model:
            ok = False
            detail += f" BUT the shipped index was built with {built.get('model')} at {built.get('dim')}d"
    return Result("embeddings", ok, detail)


def main() -> int:
    results = [check_llm(), check_embeddings(), check_nvd(), check_kev()]
    width = max(len(r.name) for r in results)
    for r in results:
        print(f"[{'PASS' if r.ok else 'FAIL'}] {r.name.ljust(width)}  {r.detail}")

    failed = [r.name for r in results if not r.ok]
    print()
    print("all dependencies reachable" if not failed else f"blocked on: {', '.join(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
