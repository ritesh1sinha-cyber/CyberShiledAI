"""Measure retrieval on its own, before any answer is scored (Track B item III).

Two independent sections, deliberately kept apart because they answer different
questions:

A. claim support  replays the frozen Batch 10 grading and reads, for each gold claim,
   the rank the production pipeline gave the passage that supports it. Offline: no
   network, no model call, no embeddings.
B. engine ablation  re-runs the same ten production queries through app.retrieval in
   bm25, dense and hybrid mode over the same two stores and scores each against the
   same gold passages, with the search wall time measured.

Relevance is never hand-labelled here. A chunk counts as ground truth for a CVE only
if the graded run recorded it as the passage supporting one of that CVE's gold claims.

    .venv/Scripts/python -m scripts.measure_retrieval_metrics            # both sections
    .venv/Scripts/python -m scripts.measure_retrieval_metrics --offline  # section A only
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from app.embeddings import EmbeddingsClient
from app.retrieval import INDEX, ROOT, ReferenceRetriever, Retriever

SCORES = ROOT / "data" / "evaluation" / "batch10" / "scores.json"
TRACE_DIR = ROOT / "data" / "traces" / "batch10"
DEFAULT_OUT = ROOT / "data" / "evaluation" / "retrieval_metrics.json"

K_POINTS = (1, 3, 5, 8)
LATENCY_REPEATS = 5

RELEVANCE_RULE = (
    "A chunk is ground truth for a CVE only if the frozen Batch 10 grading recorded it "
    "as the retrieved passage supporting one of that CVE's gold claims "
    "(claim field source_chunk_id where retrieval_method is retrieved_passage). "
    "Claims grounded in a structured NVD or KEV record instead are counted and reported "
    "separately, because no passage rank exists for them."
)


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _claim_support_rows(claims: list[dict]) -> list[dict]:
    rows = []
    for claim in claims:
        rank = claim.get("retriever_rank")
        rows.append(
            {
                "eval_id": claim["eval_id"],
                "cve_id": claim["cve_id"],
                "claim_id": claim["claim_id"],
                "family": claim["family"],
                "grounding": claim.get("retrieval_method"),
                "supporting_chunk_id": claim.get("source_chunk_id"),
                "production_rank": rank,
                "claim_result": claim.get("claim_result"),
                "result_basis": claim.get("result_basis"),
            }
        )
    return rows


def _support_metrics(rows: list[dict]) -> dict:
    """Ranks are positions in the production context list, 1-based."""
    ranked = [row for row in rows if isinstance(row["production_rank"], int)]
    structured = [row for row in rows if row["grounding"] == "structured_record"]
    pool = max((row["production_rank"] for row in ranked), default=0)
    metrics = {
        "gold_claims": len(rows),
        "passage_grounded": len(ranked),
        "structured_record_grounded": len(structured),
        "deepest_rank_seen": pool,
        "median_rank": round(statistics.median([r["production_rank"] for r in ranked]), 2)
        if ranked
        else None,
        "mrr": round(
            statistics.mean([1.0 / r["production_rank"] for r in ranked]), 4
        )
        if ranked
        else None,
    }
    for k in K_POINTS:
        metrics[f"support_at_{k}"] = (
            round(sum(1 for r in ranked if r["production_rank"] <= k) / len(ranked), 4)
            if ranked
            else None
        )
    return metrics


def measure_claim_support(scores: dict) -> dict:
    rows = _claim_support_rows(scores["claims"])
    per_cve = []
    for cve_id in dict.fromkeys(row["cve_id"] for row in rows):
        subset = [row for row in rows if row["cve_id"] == cve_id]
        per_cve.append({"cve_id": cve_id, **_support_metrics(subset)})
    return {
        "overall": _support_metrics(rows),
        "per_cve": per_cve,
        "rows": rows,
        "note": (
            "support_at_k is the share of passage-grounded gold claims whose supporting "
            "passage sat at or above rank k in the evidence package the Analyst actually "
            "received. It says nothing about whether the answer used it."
        ),
    }


def _gold_ids(scores: dict) -> dict[str, set[str]]:
    gold: dict[str, set[str]] = {}
    for claim in scores["claims"]:
        chunk_id = claim.get("source_chunk_id")
        if claim.get("retrieval_method") == "retrieved_passage" and chunk_id:
            gold.setdefault(claim["cve_id"], set()).add(chunk_id)
    return gold


def _trace_queries(scores: dict) -> dict[str, dict]:
    cve_by_eval = {row["eval_id"]: row["cve_id"] for row in scores["rows"]}
    out: dict[str, dict] = {}
    for path in sorted(TRACE_DIR.glob("CS-B10-*.json")):
        trace = _read_json(path)
        meta = (trace.get("service_trace") or {}).get("retrieval_meta") or {}
        queries = meta.get("queries") or []
        if not queries:
            continue
        out[cve_by_eval[trace["test_id"]]] = {
            "eval_id": trace["test_id"],
            "query": queries[0],
            "top_k": (trace.get("request") or {}).get("top_k", 8),
            "context_count": len(
                (trace.get("service_trace") or {}).get("contexts") or []
            ),
        }
    return out


def _dense_over_reference_pool(
    embedder: EmbeddingsClient, pool: list[dict], query: str, k: int, cache: dict
) -> list[str]:
    """Dense scan of the same per-CVE candidate pool the lexical path searches.

    Production searches the reference store lexically; the dense row of the ablation has
    to compete on identical candidates, so the pool is embedded once per CVE and reused.
    """
    vectors = cache.get(query)
    if vectors is None:
        vectors = embedder.embed([chunk["text"] for chunk in pool])
        cache[query] = vectors
    query_vector = np.asarray(embedder.embed([query])[0], dtype=np.float32)
    scores = vectors @ query_vector
    order = sorted(
        range(len(pool)), key=lambda i: (-float(scores[i]), pool[i]["chunk_id"])
    )
    return [pool[i]["chunk_id"] for i in order[:k] if scores[i] > 0]


def _ranking_ids(ranked: list[dict]) -> list[str]:
    seen: list[str] = []
    for item in ranked:
        if item["chunk_id"] not in seen:
            seen.append(item["chunk_id"])
    return seen


def _ablation_metrics(gold: set[str], ranking: list[str], k: int) -> dict:
    hits = [rank for rank, chunk_id in enumerate(ranking[:k], start=1) if chunk_id in gold]
    first = min(hits, default=None)
    return {
        "recall_at_k": round(len(hits) / len(gold), 4) if gold else None,
        "precision_at_k": round(len(hits) / k, 4),
        "first_hit_rank": first,
        "hit_at_3": 1 if first is not None and first <= 3 else 0,
        "reciprocal_rank": round(1.0 / first, 4) if first else 0.0,
    }


def measure_engine_ablation(
    scores: dict, top_k: int, repeats: int
) -> dict:
    retriever = Retriever()
    references = ReferenceRetriever()
    embedder = EmbeddingsClient()
    gold = _gold_ids(scores)
    queries = _trace_queries(scores)
    per_cve: list[dict] = []
    timings: dict[str, list[float]] = {mode: [] for mode in ("bm25", "dense", "hybrid")}
    pool_cache: dict[str, list[str]] = {}

    for cve_id, info in queries.items():
        query = info["query"]
        reference_query = f"{query} {cve_id}"
        gold_set = gold.get(cve_id) or set()
        row = {
            "cve_id": cve_id,
            "eval_id": info["eval_id"],
            "top_k": info["top_k"] or top_k,
            "production_contexts": info["context_count"],
            "gold_passages": len(gold_set),
            "modes": {},
        }
        pool = references.by_cve.get(cve_id) or []
        for mode in ("bm25", "dense", "hybrid"):
            k = info["top_k"] or top_k

            def run() -> list[str]:
                if mode == "dense":
                    corpus = _ranking_ids(retriever.search(query, k=k, mode="dense"))
                    refs = _dense_over_reference_pool(
                        embedder, pool, reference_query, k, pool_cache
                    )
                else:
                    search_mode = "hybrid" if mode == "hybrid" else "bm25"
                    corpus = _ranking_ids(
                        retriever.search(query, k=k, mode=search_mode, pool=50, alpha=0.5)
                    )
                    refs = _ranking_ids(
                        references.search_for_cve(cve_id, reference_query, k=k)
                    )
                return refs + [c for c in corpus if c not in refs]

            run()  # warm the BM25 index, the vector store and the pooled embeddings
            samples = []
            for _ in range(repeats):
                started = time.perf_counter()
                ranking = run()
                samples.append((time.perf_counter() - started) * 1000.0)
            median_ms = round(statistics.median(samples), 2)
            timings[mode].append(median_ms)
            row["modes"][mode] = {**_ablation_metrics(gold_set, ranking, k), "latency_ms": median_ms}
        per_cve.append(row)

    overall = {}
    for mode in ("bm25", "dense", "hybrid"):
        rows = [row["modes"][mode] for row in per_cve]
        measurable = [row for row in rows if row["recall_at_k"] is not None]
        overall[mode] = {
            "recall_at_k_mean": round(statistics.mean(r["recall_at_k"] for r in measurable), 4)
            if measurable
            else None,
            "precision_at_k_mean": round(statistics.mean(r["precision_at_k"] for r in rows), 4),
            "mrr": round(statistics.mean(r["reciprocal_rank"] for r in rows), 4),
            "hit_at_3_rate": round(statistics.mean(r["hit_at_3"] for r in rows), 4),
            "first_hit_none": sum(1 for r in rows if r["first_hit_rank"] is None),
            "median_latency_ms": round(statistics.median(timings[mode]), 2),
            "min_latency_ms": round(min(timings[mode]), 2),
            "max_latency_ms": round(max(timings[mode]), 2),
        }

    in_reference = sum(
        1 for ids in gold.values() for chunk_id in ids if chunk_id.startswith("NVDREF")
    )
    in_corpus = sum(
        1 for ids in gold.values() for chunk_id in ids if not chunk_id.startswith("NVDREF")
    )
    return {
        "overall": overall,
        "per_cve": per_cve,
        "provenance": {
            "index_dir": str(INDEX.relative_to(ROOT)),
            "corpus_chunks": len(retriever.chunks),
            "reference_chunks_tagged_to_benchmark_cves": sum(
                len(references.by_cve.get(cve) or []) for cve in queries
            ),
            "gold_passages_in_reference_store": in_reference,
            "gold_passages_in_generic_corpus": in_corpus,
            "repeats_per_query": repeats,
            "note": (
                "Dense and BM25 rows search the identical candidate pools the production "
                "pipeline uses (the CVE's own NVD-cited reference pages first, then the "
                "generic corpus), so the only variable is the ranking engine. Latency is "
                "the median of repeated searches and includes the hosted embedding call "
                "in the dense rows; corpus load is excluded."
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="skip the engine ablation section")
    parser.add_argument("--top-k", type=int, default=8)
    parser.add_argument("--repeats", type=int, default=LATENCY_REPEATS)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    scores = _read_json(SCORES)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": "scripts/measure_retrieval_metrics.py",
        "provenance": {
            "scores_artifact": str(SCORES.relative_to(ROOT)),
            "trace_dir": str(TRACE_DIR.relative_to(ROOT)),
            "dataset_sha256": scores["summary"].get("dataset_sha256"),
            "model": scores["summary"].get("model"),
            "embedding_model": scores["summary"].get("embedding_model"),
            "relevance_rule": RELEVANCE_RULE,
            "reproduce": ".venv/Scripts/python -m scripts.measure_retrieval_metrics",
        },
        "claim_support": measure_claim_support(scores),
    }
    if not args.offline:
        payload["engine_ablation"] = measure_engine_ablation(
            scores, args.top_k, args.repeats
        )

    args.out.write_text(json.dumps(payload, indent=1, ensure_ascii=False), encoding="utf-8")
    support = payload["claim_support"]["overall"]
    print(f"Wrote {args.out}")
    print(
        f"  claim support: {support['passage_grounded']} passage-grounded of "
        f"{support['gold_claims']} gold claims, {support['structured_record_grounded']} "
        f"from structured records, MRR {support['mrr']}, "
        f"support@3 {support['support_at_3']:.1%}"
    )
    if "engine_ablation" in payload:
        for mode, metrics in payload["engine_ablation"]["overall"].items():
            print(
                f"  {mode:7} recall@k {metrics['recall_at_k_mean']:.3f}  "
                f"precision@k {metrics['precision_at_k_mean']:.3f}  "
                f"MRR {metrics['mrr']:.3f}  hit@3 {metrics['hit_at_3_rate']:.1%}  "
                f"{metrics['median_latency_ms']} ms median"
            )


if __name__ == "__main__":
    main()
