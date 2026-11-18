"""Hosted embedding client: the course bge-small endpoint, with no local model.

One client, two jobs. ``scripts.build_index`` embeds the corpus into the dense index and
``app.retrieval`` embeds each query against it, so an index and a search measured on the
same day share one vector space; the answer-level cosine uses the same client for the
same reason. There is no offline fallback by design - a local model would put the query
in a different space from the stored vectors and silently return junk rankings.

The endpoint documents a 512 model-token ceiling per input, 16 texts per request, and a
capacity error to retry briefly. It enforces the ceiling by rejecting the request - there
is no silent server-side truncation to lean on - so text is cut here. A conservative
character budget handles the common case in one batched request, and the exact token
count the endpoint reports on a rejection re-cuts the few dense texts that still overflow
(table-heavy chunks reach 0.28 tokens per character against 0.20 for prose).
"""

from __future__ import annotations

import re
import time
from collections.abc import Sequence

import httpx
import numpy as np

from app import progress
from app.config import settings

MODEL_DIMS = 384
MAX_TEXTS_PER_REQUEST = 16
MAX_TOKENS_PER_TEXT = 512
# 2,200 characters is ~440 tokens at the prose ratio measured on this corpus, which
# leaves room for the denser text without clipping the long tail below what the
# previous local model encoded.
MAX_CHARS_PER_TEXT = 2200
SAFE_TOKENS = 500
# A dense head can need two or three measured cuts to land under the cap.
MAX_RECUT_PASSES = 4
RETRY_BACKOFF_S = 1.5
RETRYABLE_STATUS = (429, 500, 502, 503)
GIVEN_TOKENS = re.compile(r"Given: (\d+)")


class EmbeddingsError(RuntimeError):
    pass


class _Retryable(Exception):
    """The endpoint said back off: capacity, rate limit, or a transport failure."""


class _Overlong(Exception):
    """The endpoint named the input's token count; that count is the re-cut ratio."""

    def __init__(self, detail: str, tokens: int) -> None:
        super().__init__(f"{detail} (cap is under {MAX_TOKENS_PER_TEXT} tokens per input)")
        self.tokens = tokens


class EmbeddingsClient:
    """Sequential, batched access to the hosted embedding endpoint."""

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self.requests = 0
        self.texts = 0
        self.truncated = 0
        self.recuts = 0
        self.prompt_tokens = 0

    def embed(self, texts: Sequence[str]) -> np.ndarray:
        """One L2-normalised float32 vector per text, in the order given."""
        if not texts:
            return np.zeros((0, 0), dtype=np.float32)
        prepared = [self._fit(text) for text in texts]
        url = self._url()
        rows: list[np.ndarray] = []
        with httpx.Client(timeout=self.timeout, verify=settings.embeddings_ca_cert) as client:
            for start in range(0, len(prepared), MAX_TEXTS_PER_REQUEST):
                batch = prepared[start : start + MAX_TEXTS_PER_REQUEST]
                rows.extend(self._post(client, url, batch))
        matrix = np.asarray(rows, dtype=np.float32)
        norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        return matrix / np.where(norms == 0, 1.0, norms)

    def _fit(self, text: str) -> str:
        clean = " ".join((text or "").split())
        if not clean:
            raise EmbeddingsError("refusing to embed empty text; the endpoint rejects it too")
        if len(clean) <= MAX_CHARS_PER_TEXT:
            return clean
        self.truncated += 1
        return clean[:MAX_CHARS_PER_TEXT]

    def _url(self) -> str:
        base_url = settings.embeddings_base_url.rstrip("/")
        if "example.invalid" in base_url or not settings.embeddings_api_key:
            raise EmbeddingsError(
                "Embeddings endpoint or API key is not configured; set EMBEDDINGS_BASE_URL "
                "and EMBEDDINGS_API_KEY (see .env.example)."
            )
        return f"{base_url}/embeddings"

    def _post(
        self, client: httpx.Client, url: str, batch: list[str], passes: int = 0
    ) -> list[np.ndarray]:
        last: _Retryable | None = None
        for attempt in range(1, settings.max_retries + 2):
            if last is not None:
                time.sleep(RETRY_BACKOFF_S * attempt)
            try:
                return self._one(client, url, batch)
            except _Retryable as exc:
                last = exc
            except _Overlong as exc:
                if len(batch) > 1:
                    # The count is one input's, and the endpoint does not say which, so
                    # the batch is re-sent text by text until each overflow is measured.
                    return [row for text in batch for row in self._post(client, url, [text], passes)]
                if passes >= MAX_RECUT_PASSES:
                    raise EmbeddingsError(
                        f"one text still exceeded the token cap after {passes} cuts: {exc}"
                    ) from exc
                self.recuts += 1
                # The ratio is the rejected text's own average density, but the text kept
                # is the denser head of it, so the first cut usually lands just over the
                # cap and the next count tightens the ratio again.
                budget = max(1, int(len(batch[0]) * SAFE_TOKENS / exc.tokens))
                return self._post(client, url, [batch[0][:budget]], passes + 1)
        raise EmbeddingsError(
            f"Embeddings endpoint unavailable after {settings.max_retries + 1} attempts: {last}"
        ) from last

    def _one(self, client: httpx.Client, url: str, batch: list[str]) -> list[np.ndarray]:
        started = time.perf_counter()
        try:
            response = client.post(
                url,
                json={"model": settings.embeddings_model, "input": batch},
                headers={"Authorization": f"Bearer {settings.embeddings_api_key}"},
            )
        except httpx.HTTPError as exc:
            raise _Retryable(f"transport failure: {type(exc).__name__}") from exc
        detail = " ".join(response.text.split())
        if response.status_code in RETRYABLE_STATUS:
            raise _Retryable(f"HTTP {response.status_code}: {detail[:200]}")
        if response.status_code == 422:
            given = GIVEN_TOKENS.search(detail)
            if given is None:
                raise EmbeddingsError(f"Embeddings rejected the input: HTTP 422 {detail[:300]}")
            raise _Overlong(detail[:200], int(given.group(1)))
        if response.status_code != 200:
            raise EmbeddingsError(
                f"Embeddings returned HTTP {response.status_code}: {detail[:300]}"
            )
        try:
            body = response.json()
            rows = self._rows(body, len(batch))
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            raise EmbeddingsError(f"Embeddings returned an unexpected structure: {exc}") from exc
        self.requests += 1
        self.texts += len(batch)
        self.prompt_tokens += int((body.get("usage") or {}).get("prompt_tokens") or 0)
        progress.emit(
            "embedding_end",
            ok=True,
            model=settings.embeddings_model,
            texts=len(batch),
            ms=max(0, round((time.perf_counter() - started) * 1000)),
        )
        return rows

    @staticmethod
    def _rows(body: dict, expected: int) -> list[np.ndarray]:
        data = body["data"]
        if len(data) != expected:
            raise ValueError(f"asked for {expected} vectors, got {len(data)}")
        if sorted(item["index"] for item in data) != list(range(expected)):
            raise ValueError("the response indexes are not a complete 0..n range")
        rows = [
            np.asarray(item["embedding"], dtype=np.float32)
            for item in sorted(data, key=lambda item: item["index"])
        ]
        for row in rows:
            if row.shape != (MODEL_DIMS,):
                raise ValueError(f"expected a {MODEL_DIMS}-dimensional vector, got {row.shape}")
        return rows
