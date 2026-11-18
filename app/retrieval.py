"""Hybrid retrieval over the chunk index: BM25, dense, and rank fusion.

Indexes are built by scripts/build_index.py. The dense layer is a FAISS file owned by
app.vector_store, holding vectors from the hosted endpoint in app.embeddings; the
retriever keeps the text of every chunk in memory (a few MB) so callers get usable
evidence, not just ids.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path

import numpy as np
from rank_bm25 import BM25Okapi

from app.embeddings import EmbeddingsClient
from app.vector_store import VectorStore

ROOT = Path(__file__).resolve().parent.parent
PROC = ROOT / "data" / "processed"
INDEX = ROOT / "data" / "index"
REFERENCE_CHUNKS = PROC / "reference_chunks.jsonl"

TOKEN_RE = re.compile(r"[a-z0-9]+(?:[.\-_][a-z0-9]+)*")
MODES = ("bm25", "dense", "hybrid")
DENSE_INDEX = "embeddings.faiss"


def tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall((text or "").lower())


def reciprocal_rank_fusion(
    rankings: list[list[str]], weights: list[float] | None = None, k: int = 60
) -> list[tuple[str, float]]:
    """Merge ranked id lists; score = sum(weight / (k + rank))."""
    weights = weights or [1.0] * len(rankings)
    scores: dict[str, float] = {}
    for weight, ranking in zip(weights, rankings):
        for rank, doc_id in enumerate(ranking, start=1):
            scores[doc_id] = scores.get(doc_id, 0.0) + weight / (k + rank)
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))


class Retriever:
    def __init__(self, index_dir: Path = INDEX, chunks_path: Path = PROC / "chunks.jsonl"):
        self.chunks = {}
        with open(chunks_path, "r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    chunk = json.loads(line)
                    self.chunks[chunk["chunk_id"]] = chunk

        tokens = []
        with open(index_dir / "bm25_tokens.jsonl", "r", encoding="utf-8") as handle:
            for line in handle:
                tokens.append(json.loads(line)["tokens"])
        self.bm25 = BM25Okapi(tokens)
        self.ids: list[str] = json.loads((index_dir / "ids.json").read_text("utf-8"))
        self.store = VectorStore.load(index_dir / DENSE_INDEX)
        self._embedder: EmbeddingsClient | None = None

    @property
    def embedder(self) -> EmbeddingsClient:
        """The hosted model, touched only when a dense search actually runs."""
        if self._embedder is None:
            self._embedder = EmbeddingsClient()
        return self._embedder

    def _top(self, scores: np.ndarray, k: int) -> list[str]:
        k = min(k, len(scores))
        order = np.argsort(-scores, kind="stable")[:k]
        return [self.ids[i] for i in order]

    def bm25_search(self, query: str, k: int = 10) -> list[str]:
        return self._top(np.asarray(self.bm25.get_scores(tokenize(query))), k)

    def dense_search(self, query: str, k: int = 10) -> list[str]:
        return [self.ids[row] for row, _ in self.store.search(self.embedder.embed([query])[0], k)]

    def search(
        self,
        query: str,
        k: int = 10,
        mode: str = "hybrid",
        pool: int = 50,
        alpha: float = 0.5,
    ) -> list[dict]:
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        if mode == "bm25":
            ranking = self.bm25_search(query, k)
            scores = {chunk_id: 1.0 / rank for rank, chunk_id in enumerate(ranking, 1)}
        elif mode == "dense":
            ranking = self.dense_search(query, k)
            scores = {chunk_id: 1.0 / rank for rank, chunk_id in enumerate(ranking, 1)}
        else:
            rankings = [self.bm25_search(query, pool), self.dense_search(query, pool)]
            fused = reciprocal_rank_fusion(rankings, weights=[1 - alpha, alpha])
            ranking = [chunk_id for chunk_id, _ in fused[:k]]
            scores = dict(fused)
        return [
            {"chunk_id": chunk_id, "score": scores[chunk_id], **self.chunks[chunk_id]}
            for chunk_id in ranking
        ]


class ReferenceRetriever:
    """Ranked lookup over the investigated CVE's own fetched NVD reference chunks.

    Each chunk in reference_chunks.jsonl is a snapshot copy of a page the NVD
    record cites, tagged with the CVE ids that cite it, so retrieval is scoped
    to that CVE's references before the generic corpus is consulted. When the
    store is absent (or the CVE's references were not fetched), lookups return
    nothing and callers fall back to the generic corpus unchanged.

    Per-CVE candidate sets are tiny (often a handful of chunks), where classic
    BM25 idf collapses (a term in half the docs scores idf=0), so ranking uses
    the Lucene-style smoothed idf log(1 + (N - df + 0.5) / (df + 0.5)), which
    stays positive; chunks sharing no query token score zero and are dropped.
    """

    K1 = 1.5
    B = 0.75

    def __init__(self, chunks_path: Path = REFERENCE_CHUNKS):
        self.chunks: dict[str, dict] = {}
        self.by_cve: dict[str, list[dict]] = {}
        self._index: dict[str, dict] = {}
        if not chunks_path.exists():
            return
        with open(chunks_path, "r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                chunk = json.loads(line)
                self.chunks[chunk["chunk_id"]] = chunk
                for cve_id in chunk.get("cve_ids") or []:
                    self.by_cve.setdefault(cve_id, []).append(chunk)

    def has_cve(self, cve_id: str) -> bool:
        return bool(self.by_cve.get(cve_id))

    def _ensure_index(self, cve_id: str) -> dict:
        if cve_id not in self._index:
            candidates = self.by_cve[cve_id]
            doc_tokens = [tokenize(chunk["text"]) for chunk in candidates]
            tfs = [Counter(tokens) for tokens in doc_tokens]
            df: Counter = Counter()
            for tf in tfs:
                df.update(tf.keys())
            self._index[cve_id] = {
                "tfs": tfs,
                "df": df,
                "avg_len": sum(map(len, doc_tokens)) / len(doc_tokens) if doc_tokens else 0.0,
            }
        return self._index[cve_id]

    def search_for_cve(self, cve_id: str, query: str, k: int = 5) -> list[dict]:
        candidates = self.by_cve.get(cve_id) or []
        tokens = tokenize(query)
        if not candidates or not tokens:
            return []
        index = self._ensure_index(cve_id)
        df = index["df"]
        tfs = index["tfs"]
        avg_len = index["avg_len"] or 1.0
        scores = []
        for tf in tfs:
            doc_len = sum(tf.values())
            score = 0.0
            for token in tokens:
                freq = tf.get(token, 0)
                if freq:
                    idf = math.log(1.0 + (len(tfs) - df[token] + 0.5) / (df[token] + 0.5))
                    score += idf * freq / (freq + self.K1 * (1 - self.B + self.B * doc_len / avg_len))
            scores.append(score)
        order = sorted(range(len(scores)), key=lambda i: (-scores[i], candidates[i]["chunk_id"]))
        return [
            {"chunk_id": candidates[i]["chunk_id"], "score": round(scores[i], 6), **candidates[i]}
            for i in order[:k]
            if scores[i] > 0
        ]