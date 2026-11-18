import json

import numpy as np

from app.config import settings
from app.retrieval import Retriever, reciprocal_rank_fusion, tokenize
from app.vector_store import write_index


def test_tokenize_keeps_identifiers_intact():
    tokens = tokenize("Is CVE-2021-44228 in CWE-502? See T1190 and AC-1.")
    assert "cve-2021-44228" in tokens
    assert "cwe-502" in tokens
    assert "t1190" in tokens
    assert "ac-1" in tokens


def test_rrf_prefers_documents_ranked_by_both_sources():
    bm25 = ["a", "b", "c"]
    dense = ["b", "a", "d"]
    fused = reciprocal_rank_fusion([bm25, dense], k=60)
    assert [doc for doc, _ in fused[:2]] == ["a", "b"]


def test_rrf_weights_shift_the_order():
    bm25 = ["a", "b"]
    dense = ["b", "a"]
    lean_dense = reciprocal_rank_fusion([bm25, dense], weights=[0.1, 0.9], k=60)
    assert lean_dense[0][0] == "b"


def test_rrf_assigns_higher_scores_to_top_ranks():
    fused = reciprocal_rank_fusion([["x", "y"]], k=60)
    assert fused[0][0] == "x"
    assert fused[0][1] > fused[1][1]


class FakeEmbedder:
    """Stands in for the hosted endpoint: a fixed vector per query string, no call out."""

    def __init__(self, vectors):
        self.vectors = vectors

    def embed(self, texts):
        return np.asarray([self.vectors[int(text)] for text in texts], dtype=np.float32)


def build_index(tmp_path, vectors, ids):
    chunks = tmp_path / "chunks.jsonl"
    chunks.write_text(
        "".join(
            json.dumps({"chunk_id": chunk_id, "text": f"chunk {index}", "doc_id": f"D{index}"}) + "\n"
            for index, chunk_id in enumerate(ids)
        ),
        "utf-8",
    )
    (tmp_path / "bm25_tokens.jsonl").write_text(
        "".join(
            json.dumps({"chunk_id": chunk_id, "tokens": tokenize(f"chunk {index}")}) + "\n"
            for index, chunk_id in enumerate(ids)
        ),
        "utf-8",
    )
    (tmp_path / "ids.json").write_text(json.dumps(ids), "utf-8")
    write_index(vectors, tmp_path / "embeddings.faiss")
    return Retriever(index_dir=tmp_path, chunks_path=chunks)


def test_dense_search_maps_faiss_rows_back_to_chunk_ids(tmp_path):
    vectors = np.eye(4, dtype=np.float32)
    retriever = build_index(tmp_path, vectors, ["EV-0001", "EV-0002", "EV-0003", "EV-0004"])
    retriever._embedder = FakeEmbedder(vectors)
    assert retriever.dense_search("2", k=1) == ["EV-0003"]
    assert retriever.dense_search("0", k=4) == ["EV-0001", "EV-0002", "EV-0003", "EV-0004"]


def test_bm25_only_search_never_touches_the_embedding_endpoint(tmp_path, monkeypatch):
    vectors = np.eye(4, dtype=np.float32)
    retriever = build_index(tmp_path, vectors, ["EV-0001", "EV-0002", "EV-0003", "EV-0004"])
    monkeypatch.setattr(settings, "embeddings_base_url", "https://example.invalid/v1")
    monkeypatch.setattr(settings, "embeddings_api_key", "")
    results = retriever.search("2", k=2, mode="bm25")
    assert results and retriever._embedder is None


def test_hybrid_search_returns_chunk_fields_from_the_store(tmp_path):
    vectors = np.eye(4, dtype=np.float32)
    retriever = build_index(tmp_path, vectors, ["EV-0001", "EV-0002", "EV-0003", "EV-0004"])
    retriever._embedder = FakeEmbedder(vectors)
    results = retriever.search("3", k=2, mode="hybrid")
    assert results[0]["chunk_id"] == "EV-0004"
    assert results[0]["doc_id"] == "D3"
    assert all(item["text"].startswith("chunk ") and item["score"] > 0 for item in results)