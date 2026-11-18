"""Run the Batch 10 evaluation questions through the real investigation boundary.

The questions are the workbook's own instruction sentences, used verbatim, so
this set is not comparable with the golden-100 run whose query was a bare CVE
ID. Execution is sequential - one active Qwen request at a time - and every
result is cached per Eval ID so a stopped run resumes without repeating Qwen
work. The workbook is never written here; only trace files and the manifest.

``--trace-dir`` and ``--out`` redirect the run so a re-run cannot overwrite an
archived evaluation. The default stays ``data/traces/batch10``.

Usage: PYTHONPATH=. ./.venv/Scripts/python.exe -m scripts.run_batch10
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from app.api import create_app
from app.config import settings
from app.contracts import InvestigateResponse
from app.history import TraceStore
from app.service import InvestigationService
from app.workflow import InvestigationWorkflow, SingleAgentWorkflow
from scripts.batch10_dataset import (
    WORKBOOK,
    dataset_fingerprint,
    investigations,
    ledger,
    verify_gold_hashes,
)

ROOT = Path(__file__).resolve().parent.parent
TRACES = ROOT / "data" / "traces" / "batch10"
OUT = ROOT / "data" / "evaluation" / "batch10"


def write_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=1), "utf-8")
    temporary.replace(path)


def read_service_trace(path: Path, trace_id: str) -> dict:
    lines = [line for line in path.read_text("utf-8").splitlines() if line]
    if not lines:
        raise RuntimeError("the service did not persist an investigation trace")
    record = json.loads(lines[-1])
    if record.get("trace_id") != trace_id:
        raise RuntimeError("the persisted service trace does not match the response")
    return record


def run_records(
    records: list[dict],
    gold_sha256: str,
    trace_dir: Path = TRACES,
    service_trace: Path = TRACES / "service.jsonl",
    force: bool = False,
    service: InvestigationService | None = None,
    architecture: str = "multi",
) -> dict[str, int]:
    if architecture not in {"single", "multi"}:
        raise ValueError("architecture must be single or multi")
    if service is None:
        workflow = SingleAgentWorkflow() if architecture == "single" else InvestigationWorkflow()
        service = InvestigationService(workflow=workflow, store=TraceStore(service_trace))
    counts = {"run": 0, "skipped": 0, "failed": 0}
    with TestClient(create_app(service), raise_server_exceptions=False) as client:
        for index, record in enumerate(records, start=1):
            test_id = record["test_id"]
            path = trace_dir / f"{test_id}.json"
            if path.exists() and not force:
                cached = json.loads(path.read_text("utf-8"))
                if cached.get("gold_sha256") != gold_sha256:
                    raise RuntimeError(f"{test_id}: cached trace uses a different gold set")
                counts["skipped"] += 1
                print(f"[{index}/{len(records)}] {test_id} cached", flush=True)
                continue

            request = {"query": record["query"], "include_attack": True, "top_k": 8}
            started = time.perf_counter()
            error = None
            payload = None
            http_status = None
            persisted = None
            try:
                response = client.post("/investigate", json=request)
                http_status = response.status_code
                payload = response.json()
                if http_status == 200:
                    validated = InvestigateResponse.model_validate(payload)
                    persisted = read_service_trace(service_trace, validated.trace_id)
                elif http_status != 422:
                    raise RuntimeError(f"unexpected HTTP status {http_status}")
            except Exception as exc:
                error = {"type": type(exc).__name__, "message": str(exc)[:500]}

            elapsed_ms = max(0, round((time.perf_counter() - started) * 1000))
            result = {
                "test_id": test_id,
                "query": record["query"],
                "gold_sha256": gold_sha256,
                "model": settings.qwen_model,
                "architecture": architecture,
                "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "request": request,
                "http_status": http_status,
                "elapsed_ms": elapsed_ms,
                "response": payload,
                "service_trace": persisted,
                "error": error,
            }
            write_atomic(path, result)
            counts["run"] += 1
            if error:
                counts["failed"] += 1
            report_status = (payload or {}).get("report", {}).get("status")
            print(
                f"[{index}/{len(records)}] {test_id} http={http_status} "
                f"status={report_status or 'validation'} {elapsed_ms / 1000:.3f}s"
                + (f" ERROR={error['type']}" if error else ""),
                flush=True,
            )
    return counts


def summarise(entries: list[dict], digest: str, counts: dict[str, int], traces: Path = TRACES) -> dict:
    rows = []
    elapsed: list[float] = []
    calls: list[float] = []
    tokens: list[int] = []
    statuses: dict[str, int] = {}
    flags: dict[str, int] = {}
    for entry in entries:
        path = traces / f"{entry['eval_id']}.json"
        if not path.exists():
            rows.append({"eval_id": entry["eval_id"], "cve_id": entry["cve_id"], "trace": "absent"})
            continue
        trace = json.loads(path.read_text("utf-8"))
        service = trace.get("service_trace") or {}
        report = (trace.get("response") or {}).get("report") or {}
        status = str(report.get("status") or (trace.get("error") or {}).get("type") or "no-report")
        statuses[status] = statuses.get(status, 0) + 1
        model_calls = service.get("model_calls") or []
        elapsed.append(trace.get("elapsed_ms", 0) / 1000)
        calls.append(float(len(model_calls)))
        tokens.append(
            sum(int(call.get("prompt_tokens") or 0) + int(call.get("completion_tokens") or 0) for call in model_calls)
        )
        for key in ("revised", "first_draft_invalid", "revision_review_failed", "draft_fallback_reason"):
            value = service.get(key)
            if value:
                name = f"{key}={value}"
                flags[name] = flags.get(name, 0) + 1
        rows.append(
            {
                "eval_id": entry["eval_id"],
                "cve_id": entry["cve_id"],
                "trace_id": trace.get("response", {}).get("trace_id"),
                "http_status": trace.get("http_status"),
                "report_status": status,
                "elapsed_s": round(trace.get("elapsed_ms", 0) / 1000, 3),
                "model_calls": len(model_calls),
                "tokens": tokens[-1],
                "citations": len(report.get("citations") or []),
                "evidence_records": len(service.get("evidence") or []),
                "retrieved_contexts": len(service.get("contexts") or []),
                "limitations": len(report.get("limitations") or []),
                "error": trace.get("error"),
            }
        )

    def stats(values: list[float]) -> dict:
        if not values:
            return {}
        return {
            "count": len(values),
            "mean": round(statistics.fmean(values), 3),
            "median": round(statistics.median(values), 3),
            "min": round(min(values), 3),
            "max": round(max(values), 3),
            "total": round(sum(values), 3),
        }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "workbook": WORKBOOK.name,
        "dataset_sha256": digest,
        "model": settings.qwen_model,
        "questions_are_verbatim_workbook_text": True,
        "runner_counts": counts,
        "report_statuses": statuses,
        "workflow_flags": flags,
        "elapsed_s": stats(elapsed),
        "model_calls_per_investigation": stats(calls),
        "tokens_per_investigation": stats([float(value) for value in tokens]),
        "rows": rows,
        "trace_dir": traces.relative_to(ROOT).as_posix(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workbook", type=Path, default=WORKBOOK)
    parser.add_argument("--architecture", choices=("single", "multi"), default="multi")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--test-ids", nargs="+")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--trace-dir", type=Path, default=TRACES)
    parser.add_argument("--out", type=Path, default=OUT / "run.json")
    args = parser.parse_args()

    traces = args.trace_dir if args.trace_dir.is_absolute() else ROOT / args.trace_dir
    traces.mkdir(parents=True, exist_ok=True)

    entries = investigations(ledger(args.workbook))
    bad = verify_gold_hashes(entries)
    if bad:
        raise SystemExit(f"gold SHA-256 does not match the stored gold answer for: {', '.join(bad)}")
    digest = dataset_fingerprint(entries)
    records = [{"test_id": entry["eval_id"], "query": entry["question"]} for entry in entries]
    if args.test_ids:
        wanted = set(args.test_ids)
        records = [record for record in records if record["test_id"] in wanted]
    if args.limit:
        records = records[: args.limit]
    if not records:
        raise SystemExit("no Batch 10 records selected")

    print(
        f"{len(records)} of {len(entries)} Batch 10 investigations selected; sequential, one active Qwen request.",
        flush=True,
    )
    counts = run_records(
        records,
        digest,
        trace_dir=traces,
        service_trace=traces / "service.jsonl",
        force=args.force,
        architecture=args.architecture,
    )
    manifest = summarise(entries, digest, counts, traces)
    out = args.out if args.out.is_absolute() else ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=1, ensure_ascii=False), "utf-8")
    print(json.dumps({key: value for key, value in manifest.items() if key != "rows"}, indent=1, ensure_ascii=False))
    for row in manifest["rows"]:
        print(" ", json.dumps(row, ensure_ascii=False), flush=True)
    return 1 if counts["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
