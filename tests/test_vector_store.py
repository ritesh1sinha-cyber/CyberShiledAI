import numpy as np
import pytest

from app.vector_store import VectorStore, write_index


def unit(rows: int, dim: int, seed: int = 4) -> np.ndarray:
    matrix = np.random.default_rng(seed).standard_normal((rows, dim)).astype(np.float32)
    return (matrix / np.linalg.norm(matrix, axis=1, keepdims=True)).astype(np.float32)


def numpy_order(matrix: np.ndarray, query: np.ndarray, k: int) -> list[int]:
    """The ranking rule every frozen retrieval benchmark was measured with."""
    return [int(i) for i in np.argsort(-(matrix @ query), kind="stable")[:k]]


@pytest.fixture
def store(tmp_path):
    matrix = unit(120, 16)

    def build(path=tmp_path / "index.faiss", vectors=matrix):
        write_index(vectors, path)
        return VectorStore.load(path), vectors

    return build


def test_roundtrip_keeps_size_and_dimension(store, tmp_path):
    loaded, matrix = store(tmp_path / "roundtrip.faiss")
    assert loaded.size == 120
    assert loaded.dim == 16


def test_nearest_row_is_returned_first_with_its_cosine(store, tmp_path):
    loaded, matrix = store(tmp_path / "nearest.faiss")
    row, score = loaded.search(matrix[7], 1)[0]
    assert row == 7
    assert score == pytest.approx(1.0, abs=1e-6)


def test_ordering_matches_the_numpy_stable_rule(store, tmp_path):
    loaded, matrix = store(tmp_path / "rule.faiss")
    for row in range(0, 120, 7):
        got = [i for i, _ in loaded.search(matrix[row], 8)]
        assert got == numpy_order(matrix, matrix[row], 8)


def test_random_queries_over_a_matrix_with_planted_duplicates(tmp_path):
    matrix = unit(200, 16, seed=11)
    matrix[150:] = matrix[:50]  # 50 exact ties, larger than the candidate margin
    path = tmp_path / "dupes.faiss"
    write_index(matrix, path)
    loaded = VectorStore.load(path)
    for row in range(0, 200, 11):
        query = unit(1, 16, seed=row)[0]
        assert [i for i, _ in loaded.search(query, 8)] == numpy_order(matrix, query, 8)


def test_ties_are_resolved_by_the_lower_row_id(store, tmp_path):
    matrix = unit(40, 16, seed=3)
    matrix[10:14] = matrix[9]
    path = tmp_path / "tied.faiss"
    write_index(matrix, path)
    rows = [i for i, _ in VectorStore.load(path).search(matrix[9], 5)]
    assert rows[:5] == [9, 10, 11, 12, 13]


def test_k_larger_than_the_index_returns_every_row_once(store, tmp_path):
    loaded, _ = store(tmp_path / "all.faiss")
    rows = [i for i, _ in loaded.search(unit(1, 16, seed=5)[0], 500)]
    assert sorted(rows) == list(range(120))


def test_k_of_zero_returns_nothing(store, tmp_path):
    loaded, matrix = store(tmp_path / "zero.faiss")
    assert loaded.search(matrix[0], 0) == []


def test_query_of_the_wrong_width_is_rejected(store, tmp_path):
    loaded, _ = store(tmp_path / "width.faiss")
    with pytest.raises(ValueError, match="query has 3 dims, index holds 16"):
        loaded.search(np.ones(3, dtype=np.float32), 5)


def test_indexing_unnormalised_vectors_is_refused(tmp_path):
    with pytest.raises(ValueError, match="L2-normalised"):
        write_index(np.full((4, 8), 0.5, dtype=np.float32), tmp_path / "bad.faiss")


def test_a_single_vector_index_still_answers(tmp_path):
    matrix = unit(1, 16, seed=2)
    path = tmp_path / "one.faiss"
    write_index(matrix, path)
    assert VectorStore.load(path).search(matrix[0], 5) == [(0, pytest.approx(1.0, abs=1e-6))]
