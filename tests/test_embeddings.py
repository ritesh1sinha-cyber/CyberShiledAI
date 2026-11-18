"""The hosted embedding client, tested against a fake endpoint: no network, no key.

These are the promises the index build and every dense search rely on: sixteen texts per
request, text kept inside the token cap, an over-long batch re-cut rather than lost, a
capacity error retried, and a failure message that never repeats the API key back.
"""

from __future__ import annotations

import json

import httpx
import numpy as np
import pytest

from app import embeddings as mod
from app.config import settings
from app.embeddings import MODEL_DIMS, EmbeddingsClient, EmbeddingsError

KEY = "shared-embedding-key-never-print"
LONG = "x" * 120


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(settings, "embeddings_base_url", "https://embed.test/v1")
    monkeypatch.setattr(settings, "embeddings_api_key", KEY)
    monkeypatch.setattr(settings, "embeddings_model", "bge-test")
    monkeypatch.setattr(mod, "RETRY_BACKOFF_S", 0.0)


def install(monkeypatch, route):
    """Send every request through route(request, nth) and return the bodies it saw."""
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return route(request, len(seen))

    real_client = httpx.Client
    monkeypatch.setattr(
        httpx, "Client", lambda **kwargs: real_client(transport=httpx.MockTransport(handler))
    )
    return seen


def ok(texts: list[str], scale: float = 1.0) -> httpx.Response:
    """A well-formed response: one vector per text, delivered in reverse order.

    Each text maps to a unit vector with its length as the non-zero position, and every
    entry keeps its own correct index, so a dropped, duplicated or reordered row cannot
    pass as the right answer.
    """
    entries = []
    for position, text in enumerate(texts):
        vector = np.zeros(MODEL_DIMS, dtype=np.float32)
        vector[len(text) % MODEL_DIMS] = scale
        entries.append({"index": position, "embedding": vector.tolist()})
    return httpx.Response(
        200,
        json={
            "data": list(reversed(entries)),
            "usage": {"prompt_tokens": sum(len(text) for text in texts)},
        },
    )


def too_long(tokens: int) -> httpx.Response:
    return httpx.Response(
        422,
        json={
            "message": f"Input validation error: `inputs` must have less than 512 tokens. Given: {tokens}",
            "code": 422,
            "type": "Validation",
        },
    )


def test_every_text_comes_back_in_the_order_it_was_sent(configured, monkeypatch):
    seen = install(monkeypatch, lambda request, nth: ok(json.loads(request.content)["input"]))
    texts = ["x" * (index + 1) for index in range(35)]
    matrix = EmbeddingsClient().embed(texts)
    assert matrix.shape == (35, MODEL_DIMS)
    assert [len(body["input"]) for body in seen] == [16, 16, 3]
    assert [body["model"] for body in seen] == ["bge-test"] * 3
    # the fake vector puts its one at the text's length, so a shuffled response shows up here
    assert [int(np.argmax(row)) for row in matrix] == list(range(1, 36))


def test_rows_are_normalised_even_when_the_endpoint_scales_them(configured, monkeypatch):
    install(monkeypatch, lambda request, nth: ok(json.loads(request.content)["input"], scale=7.0))
    matrix = EmbeddingsClient().embed(["one text", "another text"])
    assert np.allclose(np.linalg.norm(matrix, axis=1), 1.0)


def test_long_text_is_cut_before_sending_and_the_cut_is_counted(configured, monkeypatch):
    monkeypatch.setattr(mod, "MAX_CHARS_PER_TEXT", 64)
    seen = install(monkeypatch, lambda request, nth: ok(json.loads(request.content)["input"]))
    client = EmbeddingsClient()
    client.embed(["y" * 500, "short"])
    assert [len(item) for item in seen[0]["input"]] == [64, 5]
    assert (client.truncated, client.recuts) == (1, 0)


def test_a_rejected_batch_is_re_cut_text_by_text(configured, monkeypatch):
    def route(request, nth):
        texts = json.loads(request.content)["input"]
        if len(texts) > 1 or len(texts[0]) > 100:
            return too_long(600)
        return ok(texts)

    seen = install(monkeypatch, route)
    client = EmbeddingsClient()
    matrix = client.embed([LONG, "short text"])
    assert matrix.shape == (2, MODEL_DIMS)
    assert client.recuts == 1
    # batch, then the long text alone, then that text re-cut by 500/600, then the short one
    assert [body["input"] for body in seen] == [
        [LONG, "short text"],
        [LONG],
        ["x" * 100],
        ["short text"],
    ]


def test_a_single_text_that_will_not_fit_raises_instead_of_looping(configured, monkeypatch):
    seen = install(monkeypatch, lambda request, nth: too_long(516))
    client = EmbeddingsClient()
    with pytest.raises(EmbeddingsError, match="still exceeded the token cap"):
        client.embed([LONG])
    assert client.recuts == mod.MAX_RECUT_PASSES
    lengths = [len(body["input"][0]) for body in seen]
    assert lengths[0] == len(LONG)
    assert all(shorter < longer for longer, shorter in zip(lengths, lengths[1:]))


def test_a_dense_prefix_is_cut_more_than_once(configured, monkeypatch):
    """The first measured cut uses the whole text's average density, and the text kept is
    its denser head - so a table-heavy chunk can need a second count to fit."""

    def route(request, nth):
        texts = json.loads(request.content)["input"]
        if len(texts) > 1:
            return too_long(581)
        length = len(texts[0])
        tokens = 550 if length > 2000 else 513 if length > 1949 else 490
        return too_long(tokens) if tokens >= 512 else ok(texts)

    seen = install(monkeypatch, route)
    client = EmbeddingsClient()
    matrix = client.embed(["x" * 2200])
    assert matrix.shape == (1, MODEL_DIMS)
    assert client.recuts == 2
    assert [len(body["input"][0]) for body in seen] == [2200, 2000, 1949]


def test_a_capacity_error_is_retried_and_the_batch_still_completes(configured, monkeypatch):
    def route(request, nth):
        if nth < 3:
            return httpx.Response(503, json={"message": "server at capacity"})
        return ok(json.loads(request.content)["input"])

    seen = install(monkeypatch, route)
    client = EmbeddingsClient()
    assert client.embed(["one text"]).shape == (1, MODEL_DIMS)
    assert len(seen) == 3
    assert (client.requests, client.texts) == (1, 1)


def test_giving_up_names_the_attempts_not_the_key(configured, monkeypatch):
    install(monkeypatch, lambda request, nth: httpx.Response(503, text="capacity"))
    with pytest.raises(EmbeddingsError) as raised:
        EmbeddingsClient().embed(["one text"])
    assert "3 attempts" in str(raised.value)
    assert KEY not in str(raised.value)


def test_an_error_body_is_reported_without_leaking_credentials(configured, monkeypatch):
    install(monkeypatch, lambda request, nth: httpx.Response(400, text="no such model"))
    with pytest.raises(EmbeddingsError, match="HTTP 400") as raised:
        EmbeddingsClient().embed(["one text"])
    assert KEY not in str(raised.value)


def test_a_rejection_without_a_token_count_is_not_retried_as_a_length_issue(configured, monkeypatch):
    seen = install(
        monkeypatch, lambda request, nth: httpx.Response(422, json={"message": "bad request shape"})
    )
    with pytest.raises(EmbeddingsError, match="rejected the input"):
        EmbeddingsClient().embed(["one text"])
    assert len(seen) == 1


def test_a_malformed_response_is_an_error_not_a_short_matrix(configured, monkeypatch):
    for body in (
        {"data": [{"index": 0, "embedding": [0.0] * (MODEL_DIMS + 1)}], "usage": {}},
        {"data": [], "usage": {}},
        {"data": [{"index": 7, "embedding": [0.0] * MODEL_DIMS}], "usage": {}},
        {"unexpected": True},
    ):
        install(monkeypatch, lambda request, nth, payload=body: httpx.Response(200, json=payload))
        with pytest.raises(EmbeddingsError, match="unexpected structure"):
            EmbeddingsClient().embed(["one text"])


def test_nothing_is_sent_when_the_endpoint_is_not_configured(monkeypatch):
    seen = install(monkeypatch, lambda request, nth: ok(json.loads(request.content)["input"]))
    monkeypatch.setattr(settings, "embeddings_base_url", "https://example.invalid/v1")
    monkeypatch.setattr(settings, "embeddings_api_key", "")
    with pytest.raises(EmbeddingsError, match="not configured"):
        EmbeddingsClient().embed(["one text"])
    assert seen == []


def test_empty_text_is_refused_before_the_request(configured, monkeypatch):
    seen = install(monkeypatch, lambda request, nth: ok(json.loads(request.content)["input"]))
    with pytest.raises(EmbeddingsError, match="empty text"):
        EmbeddingsClient().embed(["   "])
    assert seen == []
    assert EmbeddingsClient().embed([]).shape == (0, 0)
