# Evaluation data index

Batch 10 is the only evaluation set in this project. The 80-question architecture set and the
Golden-100 workbook were retired on 2026-11-18 and their artifacts are no longer in this tree; the
quarantine note at the end says where they went and why.

## The set

`CyberShield_Batch10_Consolidated_RAG_Agent_Evaluation_Traceability.xlsx`, sheet
`Batch 10 - RAG Agent Eval`. It is a claim ledger, not an answer ledger: 110 rows, one per gold
claim, over 10 investigations (`CS-B10-01` … `CS-B10-10`), header on row 4, data on rows 5-114.
Columns A-F belong to the reviewer (Eval ID, CVE, question, frozen gold answer, gold SHA-256, gold
approval) and no script writes them. Dataset fingerprint `22faa619bae33e48…`; frozen A-F fingerprint
`8fa38493e8440cb2…`. Every query sent to the agent is the verbatim workbook text.

## The two runs on disk

Both were run through the FastAPI boundary with Qwen calls kept sequential (one active request).

### `batch10/` — 17 November, the first full grading of the set (D28)

- `run.json` — 10/10 HTTP 200, 9 `completed` + 1 `partial`, mean 18.461 s, 5.1 model calls and
  15,472 tokens per investigation (154,724 total), traces `CS-20261117181123870525` …
  `CS-20261117181404987580`.
- `scores.json` — `summary`, `rows` (10 answer-level records), `claims` (110 claim-level records).
  Verdicts Pass 52 / Partial 21 / Fail 27 / Abstain 10; answer-level field check 10/10 clean.
  `summary.embedding_model` is `sentence-transformers/all-MiniLM-L6-v2`.
- `judge_cache.jsonl` — the answer-level judge (`b10-1.0`), mean overall 3.8, strict pass 5/10.

This is the run whose numbers fill the workbook's own capture range V-BB (22-54) and the first
appended block BC-BO (55-67).

### `batch10_live_20261118/` — 18 November, the shipped system (D30 + D33)

The current run: same 10 questions, replayed on the index that ships with this repository (FAISS
dense vectors from the hosted `bge-small-en-v1.5` endpoint, D29 + D32).

- `run.json` — 10/10 HTTP 200, 8 `completed` + 2 `partial`, mean 23.973 s / median 23.057 s,
  5.9 model calls and 19,224 tokens per investigation (192,241 total), traces
  `CS-20261118083935579472` … `CS-20261118084309602474`. Slower than 17 November because each
  retrieval round now makes a network embedding call.
- `scores.json` — the same 110 gold claims scored twice over. The answer-level blocks (`rows`,
  `metrics`, `answer_rollups`) repeat per investigation by design and `summary.granularity` says so;
  the claim-level blocks (`claims`, `claim_metrics`, `claim_judge`) vary row by row.
  Deterministic verdicts Pass 52 / Partial 22 / Fail 26 / Abstain 10, answer-level field check 10/10
  clean, `summary.embedding_model` = `bge-small-en-v1.5` with `embedding_max_input_chars` 2200.
  Claim ROUGE-L spans 0.0000-0.9545 and claim cosine 0.5043-0.9306 (mean 0.7340).
- `claim_judge_cache.jsonl` — the per-claim judge (`b10-claim-1.1`): one status plus a verbatim quote
  per required element, with the agreement score computed in code from those quotes so an unfindable
  quote is downgraded to `unquoted` and cannot raise a row.
- `judge_cache.jsonl` — the answer-level judge (`b10-1.0`) for the same 10 answers: mean overall 3.7,
  strict pass 5/10, mean 3,257 prompt tokens, max 4,237 inside the 8,192-token context budget
  `app/qwen.py` reserves against, zero errors.

Both caches key on the dataset hash **and** the prompt version **and** the answer's SHA-256, so a new
answer can never be served an old verdict and a prompt change cannot reuse a cached one.

This run fills workbook columns BP-BY (68-77). Nothing else was rewritten.

## Which number is authority

The deterministic, source-derived `fact_check()` is the only pass/fail authority, and
`derive_result()` fixes the order: a field-check mismatch fails the row, a broken abstention guardrail
fails it, a clean field check passes it, a stated absence fails it. Only where no field check exists
may the lexical anchor rule decide, and then `result_basis` reads `lexical anchor proxy`. Measured on
the current run: 54 claims on the field check, 5 on field check plus abstention, 10 on the abstention
guardrail, 41 on the labelled proxy.

ROUGE, cosine and the LLM judge are descriptive and labelled as such in every column header. The
judge uses `Qwen/Qwen3-8B`, the same model family as the system under test, so correlated bias remains
possible.

## Comparability rule (D32)

A cosine measured before 2026-11-18 came from the local MiniLM model and one measured after came from
the hosted `bge-small-en-v1.5` endpoint. They are different scales and are never placed in the same
column or the same table. In this workbook that means:

- columns BE-BF (57-58), from the 17 November run, say `MiniLM, retired by D32` in their header;
- columns BS-BU (71-73), from the current run, say `hosted bge-small`;
- comparing them side by side is invalid. Answer semantic cosine moved from a mean of 0.8112 (MiniLM)
  to 0.8991 (bge-small) on comparable text, which is a change of ruler, not of quality.

What *is* comparable across the two runs is the deterministic layer: 109 of 110 claim verdicts are
identical, and the one that moved (`CS-B10-06-C03`, CVE-2023-42793, DISTINCTION) went Fail → Partial.
Column BY states this row by row.

## Known gaps, reported rather than papered over

- All 10 WEAKNESS claims Fail because the shipped report has no CWE field.
- 5 PROJECT RISK claims disagree with the gold's `kev-cvss-v1` tier; 5 Pass.
- Conflict preservation is capped at 0.5 because `cvss_source` and `catalog_version` are captured but
  not rendered into the scored section. That floor is not a case-folding bug — the report contract
  stores `cvss_source` lowercase.
- All 110 claims carry `NOT YET VERIFIED - candidate URL only` in column R, with the locator column
  `PENDING`, so Gold Evidence Recall@k is an anchor proxy.
- The ATT&CK statement is folded into the PROJECT RISK claim.
- Every gold answer remains `PENDING HUMAN DOMAIN REVIEW` (column F).
- Similarity is never a verdict here. An offline separation probe over the 110 claim texts measured
  with the MiniLM model in use on 17 November (positives mean 0.5012, same-family hard negatives
  0.3637, cross-family control 0.2790) found no family separable at p90 and four families at or below
  zero separation, so this project sets **no** embedding threshold. The probe has not been re-run on
  `bge-small`; the policy stands because no threshold was ever justified, not because the new model
  was tested and found unusable.

## Reproducing a run from a fresh checkout

The full runbook is the root `README.md`; the proof it was checked against is the table there.
Every command below is module form (`-m scripts.…`) on purpose: `python scripts/smoke.py` fails with
`ModuleNotFoundError: No module named 'app'` because the repository root is not on `sys.path`, and
that was measured rather than assumed.

```
python -m venv .venv && .venv/Scripts/python -m pip install -r requirements.txt
copy .env.example .env       # then fill in the four QWEN_* and four EMBEDDINGS_* values
.venv/Scripts/python -m scripts.smoke                  # the four external dependencies
.venv/Scripts/python -m scripts.build_index            # 15 m 04 s measured, 10,457 chunks, no --model flag on purpose
.venv/Scripts/python -m pytest -q                      # 343 offline tests, runs with no data/index present
.venv/Scripts/python -m scripts.run_batch10 --trace-dir data/traces/<new> --out data/evaluation/<new>/run.json
.venv/Scripts/python -m scripts.evaluate_batch10 --trace-dir data/traces/<new> --scores data/evaluation/<new>/scores.json
.venv/Scripts/python -m scripts.write_batch10_columns --appended-only --overwrite --dry-run …   # then without --dry-run
```

What ships and what gets rebuilt decided the shape of that list. The frozen corpus ships in
`data/processed` (71 MB) so `chunks_sha256` and every number above reproduce, and `data/index`
(53 MB: `bm25_tokens.jsonl`, `embeddings.npy`, `embeddings.faiss`, `ids.json`) is derived from it by
the fourth command - measured on a copy of the committed set, that rebuild reproduced all three vector
files byte-identically by SHA-256. `data/raw/nvd` (155 records, 2.3 MB) also ships because
`app/evidence.py` reads it for the CVSS vector and the affected-product facts; a checkout without it
answers "No cached NVD record was available" and every report degrades to `partial`. The writer fills
only columns BP-BY, backs the workbook up to `data/backups/` first, and re-verifies the A-F
fingerprint after; it refuses any write left of column V.

Prose does not reproduce, and that is a measured property, not a warning: re-running two questions on
the fresh checkout gave CS-B10-01 an answer byte-identical to the shipped run and CS-B10-02 different
wording with all seven deterministic field checks unchanged. What reproduces is retrieval, facts and
grading.

## Quarantine (nothing was deleted)

`main` has no commits yet, so removals went to
`C:\Users\IN009287\Desktop\KGP_cleanup_20261118T062923Z\` with a `MANIFEST.md` entry per file (reason,
bytes, SHA-256, destination). That folder holds the retired 80-question and Golden-100 artifacts and
the MiniLM-era 18 November live run (`superseded_live_minilm/`) that D33 replaced.

## Viewing these files on the dashboard

`app/eval_dashboard.py` is the read-only layer behind the two Streamlit pages. It computes nothing: it
joins the workbook text to the JSON above by `test_id` and `claim_id`, reads passages and answer text
from `../traces/`, prints `not captured` for an empty value, and names the paths it read in every
detail view.

- `pages/1_Evaluation_RAG.py` (route `/Evaluation_RAG`) — for one CVE: what the gold answer had to
  cover, what retrieval actually returned, and the retrieval scores recorded for that row.
- `pages/2_Evaluation_LLM.py` (route `/Evaluation_LLM`) — for one CVE: the gold answer, the sources it
  was built from, the agent response, and the ROUGE / semantic / LLM-as-judge / deterministic verdict
  side by side.

The pages read `data/evaluation/batch10_live_20261118/scores.json` and
`data/traces/batch10_live_20261118`, both of which ship with the repository. Streamlit has to be
started after `pages/` existed for the two routes to appear in the navigation. For the capstone
report, take a figure from these artifacts instead of re-typing it.
