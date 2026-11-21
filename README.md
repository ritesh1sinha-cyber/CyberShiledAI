# CyberShield AI

A CVE investigation assistant: ask about one CVE, get a cited report. A LangGraph pipeline
(Evidence → Analyst → Critic → revision → Final Validator) answers from a local hybrid retrieval
index (BM25 + dense vectors + reciprocal rank fusion, with the NVD's own cited references searched
first) over a frozen corpus of NVD, NIST, CWE, ATT&CK, OWASP and CISA KEV material. The model is
`Qwen/Qwen3-8B` and the vectors are `bge-small-en-v1.5`, both served by two course-hosted HTTPS
endpoints. A FastAPI service holds the pipeline and a Streamlit UI talks to it.

## Set it up from a fresh checkout

Run everything from this directory, with the project's own interpreter.

```
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt      # POSIX: .venv/bin/python
copy .env.example .env                                        # POSIX: cp
```

Fill `.env` in before going further. The four `QWEN_*` keys come with the course inference API and
the four `EMBEDDINGS_*` keys from the course embedding service; both `*_CA_CERT` values already
point at certificates committed here, so TLS verification works out of the box. `NVD_API_KEY` is
optional but raises the NVD limit from 5 to 50 requests per 30 seconds. `.env` is gitignored and
must never be committed — it is the only place a key lives.

```
.venv/Scripts/python -m scripts.smoke                          # all four external dependencies
.venv/Scripts/python -m scripts.build_index                    # ~15 min, see "What ships" below
.venv/Scripts/python -m pytest -q                              # 343 offline tests, no network
```

`build_index.py` is the one step a fresh checkout has to do: it writes `data/index/` from the
committed corpus and takes about 905 seconds for 10,457 chunks (~3.4 M model tokens). It has no
`--model` flag on purpose — an index built with a model other than the one in `.env` is an index
nothing here can search.

## Run it

```
.venv/Scripts/python -m uvicorn app.api:create_app --factory --host 127.0.0.1 --port 8000
.venv/Scripts/python -m streamlit run streamlit_app.py
```

Both bind loopback only. Keep them that way: nothing in this project is meant to be reachable from
outside the machine, and there is no authentication in front of either service. Optional local
tracing lives in `docker/langfuse-compose.yml` and stays off unless `LANGFUSE_ENABLED=true`.

## Optional: the Langfuse viewer on another machine

**The system does not need it.** `data/traces/investigations.jsonl` is the record, and
`app/observability.py` wraps every SDK call so tracing can never fail an investigation; a missing
viewer costs you a nicer screen, not evidence. `GET /traces/{request_id}` and the History tab show
the same passages and the same citations from inside the app with no container running at all.

Langfuse is a two-container stack, and only one of its files is in git:

| | |
| --- | --- |
| Committed | `docker/langfuse-compose.yml` — the only tracked file under `docker/` |
| Ignored | `docker/.env` (its 8 secrets: DB password, `NEXTAUTH_SECRET`, `SALT`, `ENCRYPTION_KEY`, the project's public and secret key, the UI login) |
| Ignored | `docker/langfuse-data/` — the 78 MB Postgres directory, which is the entire trace history |
| Ignored | `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` in `.env` |

A fresh machine therefore starts an **empty project with different keys and no history**. Either
rebuild it or carry it over.

Rebuild it, if you only want tracing from now on. Install Docker Desktop from `docker.com` (its own
download page, not a mirror); the two images pull from Docker Hub's official `langfuse/langfuse` and
`postgres` repositories. Create `docker/.env` with the eight values — `SALT`, `NEXTAUTH_SECRET` and
`ENCRYPTION_KEY` are yours to generate, and the encryption key must be 32 bytes as 64 hex
characters.

```
docker compose -f docker/langfuse-compose.yml up -d      # never pass --env-file
```

First boot needs ~45 s for migrations, and port 3100 has to be free. `--env-file` breaks it: compose
reads `docker/.env` on its own because that file sits beside the compose file. Then take the
project's public and secret keys from the Langfuse settings page and put them, with
`LANGFUSE_ENABLED=true` and `LANGFUSE_HOST=http://127.0.0.1:3100`, into the project `.env`. If those
two keys do not match the project the stack actually created, export fails **silently** and the
dashboard shows `Scores: No data` — that mismatch is the most likely reason a viewer looks empty.

Carry it over, if you want the existing traces. `docker compose -f docker/langfuse-compose.yml down`
first — copying a live Postgres data directory produces a corrupt one — then move the whole
`docker/` folder (compose file, `.env`, `langfuse-data/`) to the same relative path on the other
machine by an offline route, and `up -d`. Keys line up and the history appears.

Two limits worth knowing before changing anything here. The viewer stays on loopback by design: a
non-loopback `LANGFUSE_HOST` disables export rather than sending traces off the machine, because
traces carry raw prompts and internal investigation material. And Langfuse v3 remains rejected (D21)
— web + worker + ClickHouse + Redis + MinIO does not fit this project, so "upgrade the viewer" is a
scope decision, not an image tag.

## Reproduce the evaluation

```
.venv/Scripts/python -m scripts.run_batch10 --trace-dir data/traces/<new> --out data/evaluation/<new>/run.json
.venv/Scripts/python -m scripts.evaluate_batch10 --trace-dir data/traces/<new> --scores data/evaluation/<new>/scores.json
.venv/Scripts/python -m scripts.write_batch10_columns --appended-only --overwrite --dry-run ...
```

Batch 10 (`CyberShield_Batch10_Consolidated_RAG_Agent_Evaluation_Traceability.xlsx`) is the only
evaluation set: 110 gold claims over 10 investigations. `data/evaluation/README.md` explains which
number is authoritative (the deterministic source-derived field check — everything else is
descriptive), how the two runs on disk differ, and why cosines from before and after 2026-11-18 are
not comparable. The writer refuses to touch the reviewer's columns A-F and backs the workbook up
first. The two Streamlit pages `/Evaluation_RAG` and `/Evaluation_LLM` read the committed artifacts
and compute nothing.

## What ships and what gets rebuilt

| | |
| --- | --- |
| Committed | `app/`, `scripts/`, `pages/`, `tests/`, `docs/`, `requirements.txt`, both CA certificates, the evaluation workbook, `docker/langfuse-compose.yml`, `data/processed` (71 MB frozen corpus), `data/raw/nvd/` (2.3 MB, 155 cached NVD records), `data/manifests`, `data/evaluation`, `data/traces/batch10/` and `data/traces/batch10_live_20261118/` |
| Ignored, rebuildable | `data/index/` (53 MB, `scripts/build_index.py`) |
| Ignored, re-fetchable | the rest of `data/raw/` (338 MB of NIST/ATT&CK/OWASP/KEV/NVD-reference snapshots, `scripts/snapshot_*.py`) |
| Ignored, never shared | `.env`, `.venv/`, `data/logs/`, `data/backups/`, `data/traces/investigations.jsonl`, `docker/.env`, `docker/langfuse-data/` (78 MB, see the viewer section above) |

Two of these are not optional, and both were found by checking a fresh copy of the tree on
2026-11-18 rather than by reading the code. Sizes here are the figures Windows reports (MiB);
`du -sb` gives about 4% larger numbers for the same folders.

- The corpus ships so that `chunks_sha256` in `data/manifests/index.json` — and therefore every
  number in the workbook and the evaluation READMEs — reproduces on another machine.
- The NVD cache ships because `app/evidence.py` reads `data/raw/nvd/<CVE>.json` for the CVSS vector
  and the affected-product facts. Without it every investigation answers "No cached NVD record was
  available", the severity fields come back absent, and every report degrades to `partial`. Nothing
  else under `data/raw/` is read at runtime: KEV comes from `data/processed/kev.jsonl`.

## Proof a fresh checkout runs end to end

Measured on 2026-11-18 in a scratch directory into which the file set named by
`git ls-files -o --exclude-standard` was copied, with `.env` copied in beside it and the commands
above run by the project venv. `main` had no commit when the copy was taken — the repository's first
commit came later the same day — so the copy stood in for the checkout: what it proves is that the
file set is sufficient, not the git mechanics. Since `646cdf1` the same claim can be tested for real
with `git clone`, and the file set below is what that clone gets.

Two stages, because the first one failed:

- The list printed 134 files when the copy was taken at 14:32. In that tree the offline suite passed
  and the index rebuilt, but both live investigations came back `partial` with the CVSS fields absent
  — that is how the wholesale `data/raw/` ignore was found.
- After `!data/raw/nvd/` was added, the 155 cached NVD records were put into the same tree, the
  current `scripts/smoke.py` was re-copied in, and everything below was run or re-run there. The tree
  holds 289 files against the 290 the list prints today; the difference is this `README.md`, which
  postdates the copy.

| Step | Result |
| --- | --- |
| `pytest -q` with no `data/index/` present | 338 passed — the offline suite never needs the dense index (343 today: D34 added five history-stamp tests after this measurement was taken) |
| `scripts.smoke` | all four PASS: Qwen 0.27 s, embeddings `bge-small-en-v1.5` 384 dims 0.14 s, NVD 3.18 s, KEV 1.94 s |
| `scripts.build_index` | 10,457 chunks in 15 m 04 s (4,847 requests, ~3.36 M model tokens) |
| Rebuilt index vs the shipped one | `embeddings.faiss`, `embeddings.npy` and `ids.json` identical SHA-256 — the only manifest difference is `generated_at` |
| `scripts.run_batch10 --limit 2` | both HTTP 200, both `completed`; CS-B10-01's answer text hashed to the same SHA-256 as the shipped run, and all seven deterministic field checks matched it |
| `app.eval_dashboard` | `rag_table()` 110 rows, `batch10_claims()` 110, `batch10_summary()` 24 keys — from committed files only, no index and no model call |

The prose is not guaranteed to repeat: CS-B10-02 in that check produced different wording with the
same verdicts, because the hosted model is not a deterministic function. What reproduces is the
retrieval, the facts, and the grading of whatever text came back.

## Reading the design

The primary comprehensive technical document for this repository is:
* **`docs/CyberShield_AI_Final_Technical_Report_Track_B.md`** — The complete 12-page Final Technical Capstone Report. It details the end-to-end multi-agent orchestration, the multi-layered perimeter and semantic policy guardrail architecture (blocking off-topic prompt smuggling and injection attacks), the decoupled pure IR RAG evaluation framework (P@k, R@k, MRR=0.960), the Human-in-the-Loop (HITL) safety architecture with Option B live web ingestion, the 10-tool inventory matrix, small-model failure modes, and the responsible AI governance framework.

### Multi-Layered Policy Guardrail Architecture
CyberShield AI protects enterprise environments from malicious prompt injection, weaponization payloads, and off-topic domain diversion (e.g., questions smuggling non-security queries such as politics or elections alongside CVE IDs):
1. **Deterministic Perimeter Policy Guard (`app/policy.py`, `app/api.py`)**: Sub-millisecond (< 1 ms) pure-Python regex gate (`IRRELEVANT_TOPIC_RE` + `UNSAFE_PROMPT_RE`) that enforces domain relevance *before* entity extraction, issuing an immediate HTTP 422 refusal (`unsafe_request_refused`) with zero LLM inference cost across all 5 execution modes (Copilot, Single-Agent, Zero-Shot, Few-Shot, CoT).
2. **Semantic Relevance Judge in Evidence Agent (`app/evidence_qwen.py`)**: LLM-level intent classification (`is_cyber_relevant`) that intercepts linguistically obfuscated off-topic queries before FAISS, BM25, or OSINT retrieval tools are invoked.
3. **Workflow Fast-Refusal Loop (`app/workflow.py`)**: LangGraph state bypasses downstream Analyst, Critic, and Validator stages, producing an audited refusal report with valid trace telemetry.

> **Note:** For all architectural reviews and capstone evaluation, please check **`docs/CyberShield_AI_Final_Technical_Report_Track_B.md`** directly in GitHub.
