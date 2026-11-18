"""Build the BM25 token store and dense embedding matrix over corpus chunks.

Three indexes are produced from data/processed/chunks.jsonl:

  * bm25_tokens.jsonl - bag of words per chunk id, rebuilt into BM25Okapi at
    load time (no pickle, deterministic);
  * embeddings.npy    - L2-normalised float32 vectors, row order in ids.json;
  * embeddings.faiss  - the same matrix as a FAISS IndexFlatIP file, which is what
    app.retrieval actually searches (see app/vector_store.py).

The dense vectors come from the hosted endpoint in app.embeddings - the same model and
endpoint app.retrieval queries, so index and query always share one vector space. There
is no --model flag on purpose: picking a different model here than the one in .env would
build an index nothing can search.

The manifest pins the embedding model and the source chunk file hash so a retrieval run
can always be traced back to one corpus snapshot.

--from-npy re-derives embeddings.faiss from an existing embeddings.npy without calling
the endpoint, so a lost FAISS file is repaired locally instead of re-embedding 10,457
chunks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from app.config import settings
from app.embeddings import EmbeddingsClient
from app.vector_store import write_index

ROOT = Path(__file__).resolve().parent.parent
PROC = ROOT / "data" / "processed"
INDEX = ROOT / "data" / "index"
MAN = ROOT / "data" / "manifests"

TOKEN_RE = re.compile(r"[a-z0-9]+(?:[.\-_][a-z0-9]+)*")
TEXTS_PER_PROGRESS_LINE = 512


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall(text.lower())


def load_chunks() -> list[dict]:
    path = PROC / "chunks.jsonl"
    if not path.exists():
        raise SystemExit("run scripts.build_corpus first: data/processed/chunks.jsonl missing")
    with open(path, "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_manifest(vectors: np.ndarray, ids: list[str], model: str) -> None:
    files = ("bm25_tokens.jsonl", "embeddings.npy", "embeddings.faiss", "ids.json")
    missing = [name for name in files if not (INDEX / name).exists()]
    if missing:
        raise SystemExit(f"cannot manifest the index, missing {missing}")
    manifest = {
        "generated_at": now(),
        "chunks": len(ids),
        "model": model,
        "dim": int(vectors.shape[1]),
        "normalised": True,
        "dense_backend": "faiss.IndexFlatIP",
        "chunks_sha256": sha256(PROC / "chunks.jsonl"),
        "files": {name: sha256(INDEX / name) for name in files},
    }
    MAN.mkdir(parents=True, exist_ok=True)
    (MAN / "index.json").write_text(json.dumps(manifest, indent=2), "utf-8")


def from_npy() -> int:
    """Re-derive embeddings.faiss from the existing matrix without calling the endpoint."""
    matrix_path = INDEX / "embeddings.npy"
    if not matrix_path.exists() or not (INDEX / "ids.json").exists():
        raise SystemExit("--from-npy needs embeddings.npy and ids.json; run a full build first")
    vectors = np.load(matrix_path)
    ids = json.loads((INDEX / "ids.json").read_text("utf-8"))
    if len(ids) != vectors.shape[0]:
        raise SystemExit(f"ids.json holds {len(ids)} rows, the matrix holds {vectors.shape[0]}")
    started = time.perf_counter()
    write_index(vectors, INDEX / "embeddings.faiss")
    print(
        f"faiss: {vectors.shape[0]} x {vectors.shape[1]} in {time.perf_counter() - started:.1f}s",
        flush=True,
    )
    write_manifest(vectors, ids, settings.embeddings_model)
    print(f"-> {INDEX.relative_to(ROOT)}/embeddings.faiss + data/manifests/index.json")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--from-npy",
        action="store_true",
        help="rebuild only embeddings.faiss from the existing embeddings.npy (no endpoint call)",
    )
    args = parser.parse_args()

    if args.from_npy:
        return from_npy()

    chunks = load_chunks()
    if not chunks:
        raise SystemExit("no chunks to index")

    INDEX.mkdir(parents=True, exist_ok=True)
    ids = [chunk["chunk_id"] for chunk in chunks]
    texts = [chunk["text"] for chunk in chunks]

    started = time.perf_counter()
    with open(INDEX / "bm25_tokens.jsonl", "w", encoding="utf-8") as handle:
        for chunk_id, text in zip(ids, texts):
            handle.write(json.dumps({"chunk_id": chunk_id, "tokens": tokenize(text)}) + "\n")
    print(f"bm25: {len(ids)} chunks tokenized in {time.perf_counter() - started:.1f}s", flush=True)

    started = time.perf_counter()
    client = EmbeddingsClient(timeout=120.0)
    blocks = [
        texts[start : start + TEXTS_PER_PROGRESS_LINE]
        for start in range(0, len(texts), TEXTS_PER_PROGRESS_LINE)
    ]
    rows: list[np.ndarray] = []
    for done, block in enumerate(blocks, start=1):
        rows.extend(client.embed(block))
        rate = client.texts / (time.perf_counter() - started)
        print(
            f"  dense {client.texts}/{len(texts)} ({rate:.1f}/s, {client.requests} requests,"
            f" {client.truncated} cut, {client.recuts} refit)",
            flush=True,
        )
    vectors = np.asarray(rows, dtype=np.float32)
    np.save(INDEX / "embeddings.npy", vectors)
    (INDEX / "ids.json").write_text(json.dumps(ids), "utf-8")
    write_index(vectors, INDEX / "embeddings.faiss")
    print(
        f"dense: {vectors.shape[0]} x {vectors.shape[1]} in {time.perf_counter() - started:.1f}s "
        f"({client.requests} requests, ~{client.prompt_tokens} model tokens)",
        flush=True,
    )

    write_manifest(vectors, ids, settings.embeddings_model)
    print(f"-> {INDEX.relative_to(ROOT)} + data/manifests/index.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())