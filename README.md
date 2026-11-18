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
| Committed | `app/`, `scripts/`, `pages/`, `tests/`, `docs/`, `requirements.txt`, both CA certificates, the evaluation workbook, `data/processed` (71 MB frozen corpus), `data/raw/nvd/` (2.3 MB, 155 cached NVD records), `data/manifests`, `data/evaluation`, `data/traces/batch10/` and `data/traces/batch10_live_20261118/` |
| Ignored, rebuildable | `data/index/` (53 MB, `scripts/build_index.py`) |
| Ignored, re-fetchable | the rest of `data/raw/` (338 MB of NIST/ATT&CK/OWASP/KEV/NVD-reference snapshots, `scripts/snapshot_*.py`) |
| Ignored, never shared | `.env`, `.venv/`, `data/logs/`, `data/backups/`, `data/traces/investigations.jsonl` |

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
above run by the project venv. `main` still has no commit, so the copy stands in for the checkout:
what it proves is that the file set is sufficient, not the git mechanics.

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

`docs/CyberShield_AI_End_to_End_System_Design.html` is the whole system in one document;
`docs/CyberShield_AI_Project_Structure.html` walks the tree file by file;
`docs/CyberShield_AI_Implementation_Steps.html` is the build log;
`docs/scope.md` §8 is the decision change log (D1-D34) with `docs/architecture_decisions.csv`
behind it; `docs/CyberShield_AI_Manual_Verification_Guide.html` is what to click to check it by hand;
`docs/CyberShield_AI_Architecture_FAQ.md` answers the reviewer questions in one place — chunk size,
vector storage, retrieval and re-ranking, the agent call design, and why the evaluation is
deterministic rather than RAGAS — and then follows one request end to end: what each agent hands to
the next, the Critic-to-Analyst revision round, the three-round retrieval loop, where the 24 seconds
go, what is observable, and what leaves the machine.
