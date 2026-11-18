"""FAISS-backed dense vector store over the chunk index.

The vectors are `bge-small-en-v1.5` embeddings from the hosted endpoint in
``app.embeddings``, L2-normalised when the index is built, held in one `IndexFlatIP` file
so the inner product *is* the cosine similarity. FAISS owns the bytes: a serving process
loads the index instead of holding a second copy of the matrix in memory, and the same
file can be swapped for an approximate index later without changing callers.

FAISS answers a query out of a heap, and its SIMD kernels add a dot product together in a
different order from numpy's BLAS, so equal and near-equal scores can come back in either
order - measured on this index as 4 of 140 frozen queries reordered at `k=50`. Every
retrieval benchmark here was measured with one exact rule (highest score first, ties by
lower row id), so the store asks FAISS for `k + CANDIDATE_MARGIN` candidates and settles
the final order itself with float64 dot products of the candidates it gathers back.
FAISS does the search; the shipped ranking stays reproducible.
"""

from __future__ import annotations

from pathlib import Path

import faiss
import numpy as np

CANDIDATE_MARGIN = 32


def write_index(vectors: np.ndarray, path: Path) -> None:
    """Store L2-normalised float32 vectors so an inner-product search is a cosine search."""
    matrix = np.ascontiguousarray(vectors, dtype=np.float32)
    if matrix.ndim != 2:
        raise ValueError(f"expected a (rows, dim) matrix, got shape {matrix.shape}")
    norms = np.linalg.norm(matrix, axis=1)
    if not np.allclose(norms, 1.0, atol=1e-4):
        raise ValueError("vectors must be L2-normalised before indexing (cosine search)")
    index = faiss.IndexFlatIP(matrix.shape[1])
    index.add(matrix)
    path.parent.mkdir(parents=True, exist_ok=True)
    faiss.write_index(index, str(path))


class VectorStore:
    def __init__(self, index: faiss.Index):
        self.index = index

    @classmethod
    def load(cls, path: Path) -> VectorStore:
        index = faiss.read_index(str(path))
        if not hasattr(index, "reconstruct_batch"):
            raise ValueError(f"{path} is not a flat vector index")
        return cls(index)

    @property
    def size(self) -> int:
        return int(self.index.ntotal)

    @property
    def dim(self) -> int:
        return int(self.index.d)

    def search(self, query: np.ndarray, k: int) -> list[tuple[int, float]]:
        """Top k as (row, cosine): FAISS proposes the candidates, exact scores rank them."""
        wanted = min(self.size, k + CANDIDATE_MARGIN)
        if wanted <= 0 or k <= 0:
            return []
        vector = np.ascontiguousarray(np.asarray(query, dtype=np.float32).reshape(1, -1))
        if vector.shape[1] != self.dim:
            raise ValueError(f"query has {vector.shape[1]} dims, index holds {self.dim}")
        _, positions = self.index.search(vector, wanted)
        rows = [int(row) for row in positions[0] if row >= 0]
        if not rows:
            return []
        candidates = self.index.reconstruct_batch(np.asarray(rows, dtype="int64"))
        exact = candidates.astype(np.float64) @ vector.astype(np.float64).ravel()
        ranked = sorted(
            zip(rows, (float(score) for score in exact)), key=lambda item: (-item[1], item[0])
        )
        return ranked[:k]
