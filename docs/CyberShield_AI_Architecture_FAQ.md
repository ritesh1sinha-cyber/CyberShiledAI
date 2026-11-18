# CyberShield AI — architecture decision FAQ

Answers to the questions a reviewer asks about this build, each with the file that proves it.
Everything measured is dated **2026-11-18** unless the answer says otherwise.

**One rule explains most of the answers below:** the deterministic, source-derived field check is
the only pass/fail authority in this project. ROUGE, embedding cosine and the LLM judge are
descriptive numbers that are never allowed to decide a verdict. When you are unsure why a design
choice was made, the answer is usually "so a verdict never depends on a model's opinion".

**Three questions in Part one carry a premise that changed recently.** They are corrected in place:
the golden-100 workbook is retired, there is no vector database, and 512 is not a chunk size.

Part one answers how the pieces are built. Part two follows one request end to end — what each agent
hands to the next, the two Critic–Analyst rounds, the three-round retrieval loop, where the 24 seconds
go, what is observable, and what leaves the machine. Part three is the remaining decisions.

---

# Part one — the eight questions asked

## 1. Which file is the golden data set, and which columns hold the LLM and RAG validation?

**Say it:** the evaluation file is the Batch 10 workbook, one row per gold claim; RAG numbers are in
BP–BS, LLM-judge numbers in BT–BU, and the pass/fail authority in BV–BW.

There is exactly one evaluation set today:

| | |
|---|---|
| File | `CyberShield_Batch10_Consolidated_RAG_Agent_Evaluation_Traceability.xlsx` |
| Sheet | `Batch 10 - RAG Agent Eval` (`scripts/batch10_dataset.py:21`) |
| Layout | header row 4, data rows 5–114 — **110 gold claims over 10 investigations** |
| Dataset SHA-256 | `22faa619bae33e4871d471437e659ace535d2658927b9efd8d6c6f3edccf9361` |
| Gold answers | written from source records by rules, never model-generated; each row's `gold_sha256` is re-verified before any write |

Columns this project appends (`scripts/write_batch10_columns.py:76`, the D33 live run of 18 Nov on
the hosted bge-small index):

| Column | Range | What it holds | Kind |
|---|---|---|---|
| 68 | BP | the retrieved item that answers this claim: method, rank, chunk id, score | RAG |
| 69 | BQ | deterministic support for the claim: support grade, support ratio, recall proxy, citation precision | RAG, deterministic |
| 70 | BR | per-claim ROUGE-1/2/L F1 | RAG, descriptive |
| 71 | BS | per-claim embedding cosine (hosted bge-small) | RAG, descriptive |
| 72 | BT | per-claim LLM judge `b10-claim-1.1` | LLM, secondary |
| 73 | BU | answer-level judge `b10-1.0` + answer ROUGE and cosines | LLM, secondary |
| 74 | BV | per-claim verdict: result, the rule that produced it, source-derived field check | **authority** |
| 75 | BW | answer-level field check over the reference-stated fields | **authority** |
| 76 | BX | provenance: trace id, status, latency, model calls, tokens, citations, workflow flags | audit |
| 77 | BY | what the row does not prove | audit |

The 17 November block (columns 55–67, BC–BO) is kept beside it, and its cosine headers now say
`MiniLM, retired by D32` because that is the model that produced those values.

**Premise corrected:** `CyberShield_Golden_Dataset_100.xlsx` and the frozen 80-question gold set are
**retired** — on 2026-11-18 the user directed that all evaluation use the Batch 10 workbook. Their
artifacts were quarantined, not deleted, and their numbers survive only as dated historical records
that must never be presented as current. Two docs still describe them on purpose, each under a
retirement banner: `CyberShield_AI_Gold_Set_and_Validation.html` and
`CyberShield_AI_Single_vs_Multi_Agent_Validation_Report.html`.

Same data, two read-only dashboards instead of the spreadsheet: `pages/1_Evaluation_RAG.py` and
`pages/2_Evaluation_LLM.py`, backed by `app/eval_dashboard.py`, which computes nothing.

---

## 2. Which chunking strategy, and what is the chunk size?

**Say it:** source-aware, table-atomic, paragraph packing that targets 1,800 characters and caps at
2,600 — about 450 tokens — with 400 characters of paragraph overlap.

Rules, all enforced in code (`scripts/build_corpus.py:1-10`, parameters at lines 27–30):

| Parameter | Value | Effect |
|---|---|---|
| `TARGET_CHARS` | 1,800 | flush the chunk when adding the next paragraph would pass it |
| `MAX_CHARS` | 2,600 | hard cap; a paragraph longer than this is split on sentence boundaries |
| `MIN_CHARS` | 250 | a chunk shorter than this is merged into the previous one |
| `OVERLAP_CHARS` | 400 | the last non-table paragraph is carried into the next chunk |
| token estimate | chars ÷ 4 | so the target is ~450 tokens, max ~650 |

Per source, because a NIST 800-61 PDF and an ATT&CK technique record are not the same object:

- **ATT&CK / CWE** — short structured records: one document is one chunk unless it exceeds the cap.
- **OWASP** — split on Markdown headings; every chunk carries `title - heading` so a fragment is still self-describing.
- **NIST** — split on numbered/uppercase headings, same heading prefix.
- **Markdown tables are atomic** — never split mid-table and never repeated as overlap; an over-long table is split by rows with the header repeated in every part (`split_table`, line 139).

Measured output (`data/manifests/chunks.json`): **10,457 chunks from 1,834 documents** — NIST 6,795,
OWASP 1,791, CWE 1,132, ATT&CK 739. Character length p50 1,617 / p95 2,667 / max 3,190; 1,907
chunks carry a table; 1,168 are `oversized` (see question 7).

**Premise corrected:** 512 is **not** a chunk size. It is the embedding endpoint's per-input *token*
ceiling (D32): an input of 512 or more model tokens is rejected with HTTP 422, never truncated. The
corpus was not re-cut when the endpoint changed — `chunks_sha256` is
`72a0ce2e829fc64f…`, identical before and after, which is the proof that only vectors moved. What
that ceiling did change is the client: `MAX_CHARS_PER_TEXT = 2200` pre-cut plus a bounded four-pass
re-cut in `app/embeddings.py`, which leaves 93.8% of chunks untouched.

---

## 3. Which database is used for vector storage?

**Say it:** none — there is no database. Vectors live in one FAISS file on disk, loaded by the
serving process.

| Piece | Where | Notes |
|---|---|---|
| Dense vectors | `data/index/embeddings.faiss` | `faiss.IndexFlatIP`, 10,457 × 384 float32, L2-normalised, so inner product **is** cosine (`app/vector_store.py:36`) |
| Row-id map | `data/index/ids.json` | FAISS row → `chunk_id` |
| BM25 side | `data/index/bm25_tokens.jsonl` | tokenised chunk per row, same order as `ids.json` |
| Chunk text | `data/processed/chunks.jsonl` | held in memory by `Retriever` so callers get usable passages, not just ids |
| Investigation records | `data/traces/investigations.jsonl` | JSONL is the system of record — no database anywhere |

`scripts/build_index.py` writes it, `VectorStore.load()` reads it, and the manifest
(`data/manifests/index.json`) carries the SHA-256 of all four files, so a rebuild can be proven
byte-identical — which it was, on 2026-11-18.

**Why not pgvector / Qdrant / Milvus / Chroma:** at 10,457 vectors an exact flat index already runs
in milliseconds on CPU, so an approximate index or a server buys nothing and costs two things this
project needs: reproducibility (a file is hashable, a service is not) and the fresh-checkout rule
that a clone of the repo runs end to end with no infrastructure. `IndexFlatIP` also has no recall
loss to explain to a reviewer. The file can be swapped for an approximate index later without
touching callers — that is the one reason it is wrapped in `app/vector_store.py` rather than called
directly.

One real gotcha, solved in code: FAISS answers from a heap and its SIMD kernels sum dot products in
a different order from numpy's BLAS, so equal and near-equal scores can come back either way —
measured as 4 of 140 frozen queries reordered at `k=50`. The store therefore asks for
`k + CANDIDATE_MARGIN` (32) candidates and settles the final order itself with float64 dot products
(`app/vector_store.py:61`). FAISS does the search; the shipped ranking stays reproducible.

---

## 4. Which retrieval strategy is used?

**Say it:** reference-first, then hybrid BM25 + dense with weighted reciprocal-rank fusion, retried
up to three rounds by a model-checked relevance review.

Order inside one investigation (`app/evidence.py:400-437`):

1. **Structured facts first, outside RAG.** NVD CVSS/severity/vector and CISA KEV come from the API
   and the local cache; they are never retrieved from the corpus.
2. **Reference-first.** The CVE's own NVD-cited reference pages — snapshot copies fetched locally,
   15,736 chunks over 1,316 pages tagged to 126 CVE ids — are searched before the generic corpus and
   land ahead of it, so a citation prefers the vendor's own advisory. Query is the retrieval query
   plus the CVE id, because advisories state the id while generic CWE terms often do not.
3. **Generic hybrid corpus.** BM25 (`rank_bm25.BM25Okapi`) and dense (hosted `bge-small-en-v1.5`,
   384 dims) each return a 50-chunk pool, fused by weighted RRF with `alpha = 0.5`, `k = 60`
   (`app/retrieval.py:37` and `:91`, fused at `:103`). `top_k` defaults to 8, allowed 1–20 (`app/contracts.py:52`).
4. **Relevance review loop.** A Qwen call judges whether the passages answer the question; if not,
   it supplies a refined query. The initial query plus up to two refinements = `MAX_RAG_CALLS = 3`
   search rounds, deduplicated by chunk id. If the last review still says insufficient, that becomes
   a report limitation instead of a silent pass.

The reference pool uses a Lucene-style smoothed idf, `log(1 + (N − df + 0.5)/(df + 0.5))`, because a
per-CVE pool is often a handful of chunks and classic BM25 idf collapses to zero when a term appears
in half of them (`app/retrieval.py:179`). Chunks sharing no query token score zero and are dropped.

---

## 5. Which re-rank technique is used, and why?

**Say it:** reciprocal-rank fusion plus an exact cosine rescore — no learned re-ranker and no
cross-encoder, deliberately.

Three things do the work a re-ranker normally would:

1. **Weighted RRF** (`1/(k + rank)`, `k = 60`, equal 0.5/0.5 weights). Rank-based fusion ignores the
   fact that BM25 scores and cosine scores are on different scales, which is exactly the failure mode
   a score-weighted blend hits.
2. **Exact rescore with a deterministic tie-break**: highest float64 cosine first, ties by lower row
   id (`app/vector_store.py:75`). This exists to keep the frozen benchmark ranking reproducible.
3. **Reference-first ordering** — a source-level prior, not a score: the CVE's own advisory pages are
   searched and placed ahead of the generic corpus.

**Why no cross-encoder / Cohere-style re-ranker:**

- **It cannot be justified by the metric that matters.** The authority is the deterministic
  field-check verdict; a re-ranker would reorder evidence with no way to prove a verdict improved.
- **Latency and hardware.** Retrieval is CPU-only inside a request whose measured mean is 23.97 s for
  a full investigation; a per-candidate forward pass over 50 passages per round, up to three rounds,
  does not fit.
- **Another model to certify.** Every model in this system is either pinned by hash or hosted by the
  course with a CA certificate and a documented limit. A new re-ranker would be a third vector space
  to keep straight — the exact failure D32 removed by making one endpoint the only producer of vectors.
- **Determinism is a tested property here.** 109 of 110 claim verdicts reproduced across an embedding
  model swap; a learned re-ranker would not survive that comparison.
- **It was measured, not assumed.** Raising dense depth and adding fusion variants was run as the
  R0–R3 retrieval experiments before the current setting was frozen.

---

## 6. What is the call / calling design for the agents?

**Say it:** four LangGraph nodes in a strict sequence, one active Qwen request at a time, a hard cap
of ten calls, and a deterministic validator that makes no call at all.

```
START → evidence → analyst → critic → (conditional) → final_validator → END
                     ↑                    |
                     └──── revise ────────┘   (one revision only)
```

`app/workflow.py:202-222`. Nodes: **Evidence-with-Qwen** → **Analyst** → **Critic** → conditional
route → **Final Validator**. The route sends the draft back to the Analyst exactly once, and only if
one of the four review fields (`support`, `completeness`, `citations`, `uncertainty`) is `fail` or the
draft broke a deterministic content rule (`_route_after_critic`, line 316).

Call budget, worst case = **10 Qwen calls**:

| Stage | Calls | What each does |
|---|---|---|
| Evidence | 1 + up to 3 | 1 question interpretation, then 1 relevance review per search round (`MAX_RAG_CALLS = 3`) |
| Analyst (draft) | 1 | eight sections from the evidence package |
| Critic (first review) | 1 + 1 retry | retry only when the returned JSON is unusable |
| Analyst (revision) | 1 | fixes the Critic's issues plus any validation error, verbatim |
| Critic (second review) | 1 + 1 retry | same rule |
| Final Validator | 0 | deterministic re-check of every field against the trusted records |

That is the ceiling, not the typical run: measured on the shipped ten investigations it came to **5.9
calls per investigation** (question 14 has the timing breakdown, question 11 what the second
Analyst–Critic round costs).

Design constraints a reviewer will probe:

- **Sequential, not parallel.** The endpoint allows one active request per key, and the multi-agent
  requirement is met by distinct agents with distinct contracts, not by concurrent calls.
- **Graph steps are capped too.** `settings.max_steps = 10` is the LangGraph `recursion_limit`, and
  retries count as steps (`app/config.py:26`).
- **Model output is never trusted directly.** Every completion is parsed into a strict Pydantic
  contract (`extra="forbid"`) and then re-checked by code: the Evidence agent may not change the
  validated CVE, the Analyst may not choose the risk tier, the Critic may not own citation counts.
- **Degradation is explicit, never silent.** An unusable *first* review does not fail the run — the
  draft still goes to final validation and the report says plainly that no independent review was
  available (`first_review_failed`). An unusable *post-revision* review reverts to the original draft,
  or falls back to a deterministic draft if that original was itself invalid
  (`workflow.py:336-382`).
- **Failure leaves evidence.** The graph is streamed, and partial state — model calls and stage
  timings — is attached to the exception, so a failed run is still inspectable.
- **Comparison arm.** `SingleAgentWorkflow` (line 483) is the same retrieval plus one synthesis call
  with no Critic, which is how the multi-agent claim gets tested rather than asserted.
- **Every call is traced.** `model_calls` records model, latency, prompt/completion tokens and
  `finish_reason` per call, and the JSONL trace stays the system of record.

---

## 7. Are all documents chunked?

**Say it:** no. Three groups are deliberately outside the 10,457-chunk corpus, and two records were
too short to chunk.

1. **Too-short records are skipped.** `MIN_DOC_CHARS = 100` drops any document with under 100
   characters of real content (`scripts/build_corpus.py:347`). Measured: the four chunked source files
   hold 1,836 records (706 ATT&CK + 956 CWE + 137 OWASP + 37 NIST) and **1,834** were chunked — 2 CWE
   records are under the gate. (`data/processed` also holds `kev.jsonl`, 1,768 rows; see point 2.)
2. **NVD and CISA KEV are not in the corpus at all.** This is a frozen scope decision: NVD is a
   structured tool and KEV a tri-state lookup, so their facts arrive as records with identifiers,
   not as retrieved text. Putting CVE descriptions into the RAG corpus would let a lexical match
   compete with the authoritative field. The 1,768 KEV entries and the 155 cached NVD records are
   read as data, never embedded.
3. **The reference store is separate.** The 15,736 chunks of fetched NVD-cited pages are searched by
   their own scoped BM25 (`app/retrieval.py:112`), not indexed into the 10,457.

Also true *within* the corpus, worth saying before it is mistaken for a bug:

- **1,168 chunks are flagged `oversized`**, above the 2,600-character cap. They are atomic Markdown
  tables and single long paragraphs that cannot be split without breaking the table or the sentence.
  The flag is stored per chunk rather than hidden.
- **1,907 chunks contain a table**, and tables are never duplicated as overlap.
- Chunk ids encode position — `CVE-917#000` is document `CVE-917`, ordinal 0 — and every record
  carries `start`/`end` offsets so a reviewer can locate the passage in the source.
- The corpus is **frozen**: `chunks_sha256 = 72a0ce2e829fc64f…` has not changed since 2026-11-06, so
  every retrieval number in the docs describes the same 10,457 chunks.

---

## 8. What evaluation technique is used for RAG — and why not RAGAS, DeepEval, etc.?

**Say it:** deterministic, source-derived grading per claim family, with retrieval metrics computed
over the whole retrieved set; ROUGE, cosine and an LLM judge are reported but never decide a verdict.
Libraries like RAGAS were not adopted because their core metrics are exactly the ones measured here
and found unable to verify a fact.

### What is computed

**Authority — deterministic, no model call** (`app/batch10_metrics.py`):

- `claim_result` Pass / Fail / Partial / Abstain, decided by a source-derived field check whenever the
  claim family has one: SEVERITY against CVSS fields, EXPLOITATION against KEV listedness plus
  `date_added`/`due_date`, WEAKNESS against stated CWE ids, PROJECT RISK against the `kev-cvss-v1`
  tier, AFFECTED / CONDITIONS / REMEDIATION against version tokens and product terms, GUIDANCE
  against named control and framework ids. `match` → Pass; `mismatch`/`absent` → Fail.
- Where no field check exists (the four prose families) the verdict falls back to a **lexical anchor
  rule** and `result_basis` records `lexical anchor proxy`, so the column can never be read as a
  verified fact check.
- Claims that require a stated non-verification get **Abstain** when the answer hedged and said so —
  refusing correctly is graded, not skipped.
- Anchors are the identifiers a claim cannot be right without (CVE/CWE ids, CVSS vector, score,
  severity word, dates, versions, ATT&CK and NIST ids, product nouns). Coverage grades at 0.60 Y /
  0.30 Partial, and a Y also needs one *discriminative* anchor — otherwise any passage that merely
  names the CVE would pass.

**Retrieval / RAG side:** evidence support grade and support ratio judged against the **whole
retrieved set** (all passages plus all structured records), a recall proxy, citation precision
(citations whose text supports the claim ÷ citations attached), anchor coverage, and locator columns
naming the single best-matching passage with its rank and score.

**Descriptive only:** ROUGE-1/2/L F1, embedding cosine (answer-vs-gold, question-vs-answer,
claim-vs-answer), and an LLM judge (`b10-1.0` answer-level, `b10-claim-1.1` per claim), each labelled
`descriptive` or `secondary, same model family` in its own header.

**Current numbers** (D33 live run, 18 Nov, hosted bge-small index): 10/10 HTTP 200, 8 completed /
2 partial, mean 23.973 s; claim verdicts **Pass 52 / Partial 22 / Fail 26 / Abstain 10**; verdict basis
54 field check, 5 field check + abstention guardrail, 41 lexical anchor proxy, 10 abstention guardrail;
answer-level field check clean on **10/10**; ROUGE-L mean 0.2633; semantic cosine mean 0.8991; claim
cosine mean 0.734.

### Why not RAGAS / DeepEval

1. **Their headline metrics are LLM judgments of text an LLM wrote.** Faithfulness, answer relevance
   and context precision in those libraries are model opinions, and here the judging model is the same
   family as the answering model. That is circular, and the project rule is that no verdict may rest
   on a model's opinion.
2. **The signal they rely on was measured and does not separate fact from topic.** On this set, the
   cosine between a gold claim and its own answer scope versus the same family's scope for *another*
   CVE separates by only **−0.003 to +0.068** for the templated families (EXPLOITATION, WEAKNESS,
   GUIDANCE, PROJECT RISK, SEVERITY) at a chance ordering rate of 0.12–0.55 — no threshold exists.
   The long prose families separate by +0.24 to +0.44, but that is topic attribution (product name
   plus CVE id), not verification. Recorded in `app/batch10_metrics.py:50` and `docs/scope.md` D28.
   That measured gap is precisely what a `faithfulness`-style score would be built on.
3. **Their context metrics need trusted gold contexts, and this data set does not have them.** The
   workbook's gold evidence URLs read `NOT YET VERIFIED - candidate URL only` (column R). Any
   `context_recall` number computed against them would be false precision, so this project reports
   recall-shaped cells as explicitly labelled **proxies** computed against the claim's own anchors.
4. **The judge was already run here, audited, and its defects are counted.** In the golden-100
   review, **246 of 482** issue lines asserted a contradiction that was not in the reference, and the
   prompt capped factual correctness at 2 for "contradicting a reference fact" — which rewarded
   filler. It took prompt `g100-1.1`, then the `b10` rules, to forbid any issue that cannot quote the
   reference phrase it contradicts (D27). A library that hides its judge prompt behind a default
   makes that audit impossible.
5. **Reproducibility.** 109 of 110 claim verdicts survived an embedding-model swap unchanged; the
   deterministic layer runs offline in the test suite with no credentials. A library that calls a
   hosted judge changes scores whenever that judge service updates, silently.
6. **Cost, latency and the CPU budget** — the same reasons there is no cross-encoder (question 5).

**What was taken from that ecosystem instead:** the *vocabulary*. Context precision / recall /
faithfulness are reported under those names in the workbook and the dashboards, computed
deterministically, so a reviewer can compare against a RAGAS number while knowing which one is an
opinion and which one is a check.

**Honest limits, stated in the workbook itself:** 10 investigations and 110 claims is a small frozen
set, not production evidence; 41 of 110 verdicts rest on a lexical proxy rather than a field check;
the judge is the same model family as the writer; prose is not reproducible run to run, only
retrieval, facts and grading are; and there is no independent human review of the gold answers.

---

# Part two — end-to-end behaviour, from the seat of the person asking

Every number in this part is measured from the ten shipped live investigations in
`data/traces/batch10_live_20261118/` (18 November 2026, hosted `bge-small` index, sequential with one
active Qwen request). Where a figure is derived by subtraction rather than read directly, it says so.

## 9. What happens between me typing a question and the answer appearing?

**Say it:** one boundary check, then four agents in a fixed order, then a deterministic rebuild of the
report — and a record is written whether it succeeds or not.

| # | Step | Model calls | Measured |
|---|---|---|---|
| 1 | **Boundary check** — the API refuses anything that is not exactly one CVE before any work happens: two CVE ids, no resolvable CVE, a request for the system prompt, or a question about a future CVE (`app/api.py:25-60`). A separate rule refuses exploit/payload/intrusion wording (`app/policy.py:5-19`). | 0 | under a millisecond |
| 2 | **Trace id minted** as `CS-YYYYMMDDHHMMSSffffff`, and the whole run takes a single lock (`app/service.py:35-38`). | 0 | — |
| 3 | **Evidence agent** — one call interprets the question into an intent plus a retrieval query; code then re-reads the structured NVD and KEV records, searches the reference pages and the hybrid corpus, and one call reviews whether the passages actually answer the question. | 1 + 1 per search round | 4.14 s mean per investigation |
| 4 | **Analyst** — one call writes the eight sections from the evidence package. | 1 | 7.43 s mean per call |
| 5 | **Critic** — one call reviews the draft against the same package: four checks, at most two issues. | 1 | 2.43 s mean per call |
| 6 | **Revision** — the draft goes back to the Analyst exactly once, if a check failed or a deterministic rule was broken (question 11). 9 of these 10 runs took it. | +1 +1 | 9.9 s, derived |
| 7 | **Final Validator** — zero calls. It re-derives the report from the evidence package, owns the risk tier and the citations, and sets the status (`app/final_validator.py:136-204`). | 0 | **4 ms** |
| 8 | **Record** — one JSONL line is appended for every run, including refusals and failures (`app/service.py:84`). | 0 | — |

Refusals at step 1 never reach step 3, so an off-topic or unsafe question costs no inference at all.

## 10. What does each agent actually hand to the next one?

**Say it:** each hand-off is a strict contract, and the split inside it is the design — the model owns
the prose, code owns every fact.

| Contract | Built by | Owned by the model | Owned by code |
|---|---|---|---|
| `InvestigateRequest` | the user / UI | the question, the follow-up turns | the resolved CVE id |
| `EvidencePackage` | Evidence agent | the retrieval query, the intent | CVE facts, KEV status, affected products, ATT&CK mappings, every evidence record and citation, every limitation |
| `AnalystDraft` | Analyst agent | the text of eight sections, which evidence id each section cites | which sections may exist at all, citation eligibility, the 20-id cap |
| `CriticReview` | Critic agent | the issue list | the four pass/fail fields (recomputed from the issues), the citation check, every reference in an issue detail |
| `Report` | Final Validator | the summary and rationale *wording* | status, risk tier, citations, limitations, all structured fields |

Three hand-offs have a hard rule attached: the CVE id may not change between contracts
(`app/evidence_qwen.py:94`, `app/analyst.py:196-197`, `app/critic.py:220-221`), a stage may not cite
evidence that this request did not retrieve, and only the Final Validator produces a `Report` — an
agent cannot promote its own output into the answer.

## 11. The Analyst and the Critic call each other twice — how does that round work?

**Say it:** the Critic sees the evidence, not just the text; it sends back at most two short issues; and
the revision gets those issues verbatim plus the exact deterministic rule the last draft broke.

- **Analyst → Critic.** `build_review_prompt` sends the whole evidence package *and* the whole draft as
  JSON (`app/critic.py:98-105`). The Critic is never asked to judge prose against prose.
- **Critic → route.** Four pass/fail fields plus at most two issues, each one sentence of at most 18
  words (`app/critic.py:57`). The fields are not trusted: `derive_statuses` recomputes all four from the
  issue list (`app/critic.py:108-115`), so a review that says `fail` with nothing to point at cannot
  happen, and a model that says `pass` while raising an issue is corrected rather than believed.
- **Route.** `_route_after_critic` revises only when a field is `fail` or the draft broke a deterministic
  content rule, and only once — `revised` is set, so the second review can never loop back
  (`app/workflow.py:316-324`).
- **Revision input.** `build_revision_prompt(package, draft, issues, validation_error)`
  (`app/analyst.py:432-436`). If the first draft parsed but broke a rule, the failure string is passed
  through verbatim so the model fixes the rule it actually hit instead of guessing. When the Critic
  passed every check but the draft still broke a rule, the workflow synthesises the issue from the
  validation reason so a revision still runs (`app/workflow.py:275-286`).
- **What it costs, measured.** 9 of 10 investigations revised. Revised runs averaged **25.0 s and 6.1
  model calls**; the single run that did not revise took 14.2 s and 4 calls. So the review-and-revise
  round is roughly an 11 s premium on a ~24 s answer — that is the price of the second opinion, and it
  is why `SingleAgentWorkflow` exists to compare the two designs rather than assert one is better.
- **What happened in those runs.** 6 of 10 first drafts broke a deterministic rule, 0 needed the
  deterministic draft fallback, and 0 reviews were unusable. The revision path is load-bearing here,
  not decorative.
- **When the second review is unusable,** the workflow does not ship a revised draft nobody checked:
  it reverts to the original draft with the original review, or to a deterministic draft if the original
  was itself the invalid one (`app/workflow.py:336-382`).

## 12. Retrieval can run three rounds — when does it stop early?

**Say it:** it stops the moment a review calls the passages sufficient, a retry only ever adds new
chunks, and running out of rounds becomes a sentence in the answer instead of a silent weak answer.

The loop is `app/evidence.py:410-438`:

1. Search with the primary query (reference pages first, then hybrid BM25 + dense over a 50-chunk pool).
2. Ask the reviewer: do these passages answer the question? One Qwen call, `app/evidence_qwen.py:107-137`.
3. Sufficient → break. Not sufficient → take the reviewer's refined query, append the CVE id, and loop —
   unless that query was already tried, which ends the loop instead of wasting a round.
4. `MAX_RAG_CALLS = 3` counts *search rounds* (the initial query plus two refinements), and chunks
   already collected are never re-added, so a later round can only widen the set (`app/evidence.py:368-371`).
5. Rounds exhausted and still insufficient → the report carries "Retrieval review still judged the
   passages insufficient after 3 search rounds" (`app/evidence.py:435-438`).

Measured on the shipped run: **11 search rounds across 10 investigations** — nine stopped after the
first round, one used two, none used three. Each round costs one review call averaging 1,277 ms.

One honest caveat about this loop: the reviewer is the same model family as the writer, so it can
declare its own retrieval sufficient too early. That is why a `sufficient` review can only *stop* the
loop and never raises a verdict, while an `insufficient` outcome always adds a limitation. The asymmetry
is deliberate — the loop can only ever make the answer more modest, never more confident.

## 13. What makes an answer `completed`, `partial`, `refused` or `failed`?

**Say it:** the status is computed from which required facts exist, not from how the answer reads.

| Status | Set by | Exact trigger | This run |
|---|---|---|---|
| `completed` | Final Validator | no missing core fact, no open Critic finding, no deterministic fallback, review available (`app/final_validator.py:170-174`) | 8 |
| `partial` | Final Validator | any of: no NVD record, no CVSS score, KEV `unknown`, no affected products, no summary text, no remediation text — or any Critic finding carried into the report, or a deterministic draft was used, or no review was available | 2 |
| `refused` | `InvestigationService` | the safety wording rule matched before any work (`app/service.py:42-46`) | 0 |
| `failed` | `InvestigationService` | an exception escaped the graph; a minimal report is assembled so the caller still gets a trace id (`app/service.py:63-72`) | 0 |

The list that decides `partial` is `missing_core_limitations` (`app/final_validator.py:44-60`), and every
item it finds is written into the report's own limitations, so a `partial` answer names what it is
missing. `partial` is not a wrong answer and not a low score — it is the system declining to call an
answer complete when a required fact was never retrieved.

## 14. How long does it take, and where does the time go?

**Say it:** about 24 seconds, and 90.7% of it is waiting for the model — which means the expensive
lever is the size of the prompt, not the length of the answer.

Per-investigation means from the shipped run (`app/analyst` and `critic` totals cover both the first
pass and the revision):

| Stage | Mean per investigation | Calls | Mean per call |
|---|---|---|---|
| Evidence (interpretation + retrieval + relevance reviews) | 4,142 ms | 1 interpretation, 1.1 reviews | 1,607 / 1,277 ms |
| Analyst (draft + revision) | 14,117 ms | 1.9 | 7,425 ms |
| Critic (review + re-review) | 4,630 ms | 1.9 | 2,427 ms |
| Final Validator | **4 ms** | 0 | — |
| **Total wall clock** | **23,946 ms** (range 14,179–34,843) | 5.9 | — |

- Summed across the run, Qwen latency is **217,306 ms of 239,457 ms wall clock — 90.7%**. The remaining
  ~2.2 s per investigation covers the reference and hybrid search, the single embedding request that
  turns each query into a vector, the NVD/KEV lookups, and every deterministic check.
- Tokens: **19,224 per investigation, 95.3% of them prompt** (183,293 in, 8,948 out). The evidence
  package is re-sent to the Analyst and again to the Critic and again on revision, so retrieval depth
  and package size are the cost drivers. Cutting the answer's length would change almost nothing.
- The whole local half of the system — retrieval, ranking, validation, grading — runs in milliseconds
  and needs no model, which is what makes the 343-test suite finish in about 16 s offline.
- Timeout budget: a per-call HTTP timeout of 180 s (`app/qwen.py:29`) inside a client-side
  `investigation_timeout_s` of 600 s (`app/config.py:29`), so a hung endpoint surfaces as one failed
  call rather than an unbounded wait.

## 15. What do I see while it is running?

**Say it:** every agent reports back in plain language as it finishes, and the lines are generated from
the stage's own output rather than from a progress bar.

`POST /investigate/stream` runs the investigation on a worker thread and forwards a queue of events as
server-sent events (`app/service.py:87-109`, `app/progress.py`); the graph itself is streamed, so a
stage's result is published before the next one starts.

| Event | What the screen shows |
|---|---|
| `begin` | the trace id and that the request passed the safety check |
| `refused` | the refusal reason as a warning, and nothing else |
| `stage_start` | one line per agent, e.g. "Critic agent — Reviewing support, completeness, citations and uncertainty in the draft." |
| `model_start` | "Qwen call 3 running — generating JSON, up to 1024 output tokens." |
| `model_end` | latency, prompt/completion token counts and `finish_reason`; on failure the reason instead |
| `stage_end` | the stage's own numbers: records read, severity and CVSS found, KEV status, passages and techniques retrieved, sections written, which were left unknown, the four review verdicts and each issue, the final status, citation and limitation counts |
| `stage_failed` | which agent stopped before producing a result, and the exception type |

The rendering lives in `progress_lines` (`streamlit_app.py:228-281`) and only ever restates values the
deterministic layer already computed — a progress line can't claim more than the stage returned. Once
the report arrives, the header shows Status, Risk, total time and Trace ID, plus the Langfuse link and
a "Stage timings" table (`streamlit_app.py:194-217`).

## 16. What happens if two people ask at the same time?

**Say it:** the second investigation waits. That is a deliberate consequence of the endpoint, and it is
the weakest part of this design.

`InvestigationService.investigate` holds one `threading.Lock` for the entire run
(`app/service.py:35`), so the API accepts concurrent requests but executes them one at a time. It is
the simplest correct answer for an endpoint that allows one active request per key: the alternative —
interleaving five calls each — would fail at the provider. There is no queue depth limit and no
per-request position estimate, so a burst shows up as rising latency, not as errors. **No concurrency
evidence exists in the test suite**; this is stated as a known limit rather than a measured property.

## 17. Can I ask a follow-up without repeating the CVE?

**Say it:** yes — the CVE resolves from the last turn that named exactly one, and the moment two
different CVEs are in play it refuses instead of guessing.

`resolve_request_cve` (`app/identifiers.py:15-33`) looks at the current question first; if it names no
CVE it walks the recent turns backwards and takes the most recent one that names exactly one. Two
distinct CVE ids in the question, or ambiguity across the stored context, raise rather than pick — the
UI surfaces that as HTTP 422 with `multiple_cves_unsupported` (`app/api.py:28-34`). The interface keeps
the last eight turns (`streamlit_app.py:435`, capped again at `app/evidence_qwen.py:73`) and says
"Follow-up context is active" while they are.

The interpretation call may restate the query for retrieval, but it may not restate the CVE: a model
answer whose `cve_id` differs from the one the code resolved is rejected
(`app/evidence_qwen.py:94`) and the run falls back to deterministic CVE handling.

## 18. Does any of my data leave this machine?

**Say it:** what leaves is a prompt to the course's inference endpoint. Nothing is uploaded anywhere
else, and an investigation makes no NVD or CISA call at all.

| Destination | Calls per investigation | Notes |
|---|---|---|
| Hosted Qwen endpoint | 4–10 (measured mean 5.9) | HTTPS, verified against `vm06-ca.crt`; TLS verification is never disabled; key only in gitignored `.env` |
| Hosted embeddings endpoint | 1–3 — one per search round | the query text only, verified against `vm02-ca.crt` |
| NVD API | **0 at request time** | facts come from `data/raw/nvd/<CVE>.json`; refreshed by script |
| CISA KEV feed | **0 at request time** | `data/processed/kev.jsonl`, a 1,768-row snapshot |
| Langfuse | 0 unless explicitly enabled, then `127.0.0.1` only | a non-loopback host disables export silently (`app/observability.py:27-42`) |

The consequence is worth stating plainly rather than hiding: a CVE with no cached NVD record does not
get fetched mid-run. It answers with "No cached NVD record was available; this does not establish that
the CVE does not exist" (`app/evidence.py:175-179`) and degrades to `partial`. Freezing the data under a
fixed evaluation set matters more here than answering one extra question, and it makes freshness visible
instead of letting facts move underneath a score.

## 19. How is observability designed, and why two systems?

**Say it:** JSONL is the record and Langfuse is a viewer over it. Tracing can never fail a run, and it
can never leave the machine.

**`data/traces/investigations.jsonl` — the system of record.** One line per investigation, written for
successes, refusals and failures alike: `trace_id`, `recorded_at`, request, response, evidence records,
retrieved contexts, `model_calls` (model, latency, prompt/completion tokens, `finish_reason` per call),
stage timings, the revision and fallback flags, the retrieval queries that actually ran, the error if
any, and since D34 a `runtime` block naming the embedding model and index fingerprint the run retrieved
with. Nothing is readable without it.

**Langfuse — a localhost viewer.** `app/observability.py` writes one trace per investigation keyed by the
same `request_id`, one span per graph node carrying that node's output, and one generation per Qwen call
with the **raw system prompt, raw user prompt and raw completion** plus usage and `finish_reason`
(`app/observability.py:160-194`). Level is `ERROR` for a transport failure, a non-200 or an unparseable
body, and `WARNING` when output was cut at the token budget. Exactly one score is attached,
`deterministic_status` as `CATEGORICAL`, and its comment lists the degradations that occurred — the
design keeps the vocabulary of observability platforms but refuses to let one produce a judgement.

Four guards make it safe to run:
- off unless `LANGFUSE_ENABLED=true` **and** both keys are set **and** the host is loopback
  (`app/observability.py:36-42`) — pointing it at a public URL silently disables export rather than
  leaking a trace;
- every call is wrapped in `try`/`except` and swallows its own failure, so a dead viewer cannot fail an
  investigation;
- `tests/conftest.py` forces tracing off for the suite, so no test depends on it;
- the stack itself (`docker/langfuse-compose.yml`) binds `127.0.0.1:3100`, keeps its Postgres on no host
  port, and sets `TELEMETRY_ENABLED=false`.

Rejected: LangSmith cloud and Langfuse cloud, because traces contain internal investigation material
and full prompts; Langfuse v3 self-hosted, because web + worker + ClickHouse + Redis + MinIO does not
fit this host. See D21 in `docs/scope.md`.

## 20. How do I check one claim in an answer myself?

**Say it:** open the trace, and the exact passage behind every citation is there with the query that
retrieved it. No model call involved.

1. Every answer prints its **Trace ID** in the header row.
2. `GET /traces/{request_id}` reads that investigation back from the local JSONL (`app/api.py:126-153`)
   and returns the search queries that ran, the structured evidence records, the retrieved passages,
   and `used_by` — a map from each evidence id to the sections that actually cite it
   (`app/api.py:68-86`).
3. The UI renders the passage text under the citation that used it. If the readback fails it says so in
   those words rather than claiming the section cites nothing.
4. The citation itself carries source, document id, chunk id and URL, so the claim leads back to a
   specific paragraph in a specific snapshot document, and the chunk carries `start`/`end` offsets
   into it.
5. For anything a citation cannot settle — was the prompt right, did the model get truncated — the
   Langfuse link opens the raw prompt and completion for that exact stage.
6. For the evaluation set rather than one answer, the two read-only dashboards
   (`pages/1_Evaluation_RAG.py`, `pages/2_Evaluation_LLM.py`) show, per gold claim, the retrieved item
   that answered it, the deterministic verdict, the rule that produced it, and what the row does not
   prove.

## 21. Where exactly can the model lie, and what catches it?

**Say it:** every failure mode a small model is known for has a named check, and the check raises
rather than negotiating.

| The model tries to… | What stops it |
|---|---|
| state a fact about a CVE nobody gave it | a section may not exist unless the package holds evidence of the right claim type (`app/analyst.py:208-218`) |
| fill in missing NVD facts | "Analyst filled in missing NVD facts." (`app/analyst.py:221-222`) |
| invent affected products | "Analyst invented affected products." (`app/analyst.py:223-224`) |
| turn an unknown KEV status into a claim | "Analyst replaced unknown KEV status with a claim." (`app/analyst.py:225-226`) |
| invent an ATT&CK mapping or name an unverified technique | `app/analyst.py:227-228` and `app/analyst.py:239-248` |
| pick the risk tier | "Analyst attempted to choose the deterministic risk tier." (`app/analyst.py:249-250`) — the tier comes from CVSS + KEV in code (`app/final_validator.py:63-114`) |
| cite evidence from another request | `app/analyst.py:211-216`; the Critic gets the same treatment at `app/critic.py:200-212` |
| smuggle in another CVE id | `app/analyst.py:202-207`, and the Final Validator requires every citation to match the package exactly (`app/final_validator.py:117-121`) |
| pad an answer with every id it can see | 20 ids per section, priority ones kept first (`app/analyst.py:253-261`) — this was a real abort, D23a |
| return half a JSON object | `finish_reason` must be `stop` or the draft/review is rejected outright (`app/analyst.py:440-441`, `app/critic.py:270-271`) |
| criticise a correctly-preserved unknown | "Critic flagged a correctly preserved unknown section." (`app/critic.py:225-228`) |
| call an already-cited id missing | `app/critic.py:229-234`; the model's own citation issues are dropped and replaced by the deterministic check (`app/critic.py:139-176`) |
| say `fail` without an issue, or `pass` while raising one | impossible: the four fields are recomputed from the issues (`app/critic.py:108-115`) and any residue is rejected by `validate_review` (`app/critic.py:235-239`) |
| rewrite the CVE mid-run | rejected at three separate stages, one per agent |

What happens after a check fires depends on which pass it was, and that distinction was earned the hard
way (D19): a **first** draft that breaks a rule is kept, not discarded, so the Critic can see it and the
revision can fix it; only an unparseable output or a failed **revision** falls back to a deterministic
draft immediately (`app/analyst.py:444-456`). Either way the fallback says so in the report's own
limitations, and the status drops to `partial`.

## 22. What still works with no model endpoint?

**Say it:** everything except the sentences.

Retrieval, ranking, the structured NVD/KEV reads, all deterministic validation, the whole Batch 10
grading layer, both dashboards and all 343 offline tests run with no network and no credentials — the
tests use an `httpx.MockTransport` fake for the model clients. What needs the endpoints is prose
generation and the query embedding.

For embeddings there is deliberately **no offline fallback**: a local model would embed the query in a
different vector space from the stored vectors, and a silently mixed space is worse than a visible
error. `scripts/smoke.py` fails fast if the committed `data/manifests/index.json` names a model or
dimension the live service cannot serve, which is the first thing a fresh checkout would otherwise hit.

---

# Part three — remaining architecture decisions, as questions

## Sources and data

**Which sources, and how is a version pinned?**
ATT&CK, OWASP, NIST and CWE are snapshotted locally and cut into the corpus; NVD and CISA KEV are
queried as structured sources. Every snapshot has a manifest entry and a hash, so a number names the
version it was computed on. `data/processed` (71 MB) ships in the committed set; the rest of
`data/raw` is re-fetched by command.

**Why is NVD excluded from the RAG corpus?**
Because a CVSS score is a field, not a passage. Letting a lexical match compete with the authoritative
record is how a wrong number gets cited confidently. NVD is a tool; the corpus is for guidance text.

**Why does the NVD cache ship (155 records) while other raw data does not?**
`app/evidence.py` reads `data/raw/nvd/<CVE>.json` for the CVSS vector and affected-product facts. A
checkout without it answers "No cached NVD record was available" and every report degrades to
`partial`. That was found by running the system from a copy of the committed file set, not by reading
the code — it is the defect the D33 proof existed to catch.

**Why is KEV tri-state (`listed` / `not_listed` / `unknown`)?**
Absence of a CVE from a snapshot is not proof of absence from the catalogue. `unknown` keeps that
distinction instead of letting a stale snapshot read as a negative finding. KEV snapshot date metadata
is validated before its rows are used.

**Why CVSS precedence v3.1 → v3.0 → v2, NVD Primary first?**
It is a frozen deterministic rule so two runs on the same record cannot disagree about severity, and
the risk tier derives from it (`kev-cvss-v1`) rather than from the model.

**Why must ATT&CK mappings be curated or source-backed?**
The schema has no "model guess" value. A technique id in a report has to point at a source reference,
otherwise the report would present an inference as a fact.

## Model and prompts

**Which model, and how is it reached?**
Hosted `Qwen/Qwen3-8B` over certificate-verified HTTPS (`vm06-ca.crt`), key only in the gitignored
`.env`. TLS verification is never disabled. Limits: one active request per key, 60 requests/minute,
8,192 combined input/output tokens, 1,024 maximum output tokens; this design stays stricter at no more
than 3 calls and 400 output tokens per call.

**Why hosted `bge-small-en-v1.5` instead of a local MiniLM?**
The user directed it, and one model defining every vector removes the failure mode where queries and
stored vectors live in different spaces. There is deliberately **no offline fallback**: a local model
would embed queries in a different space from the stored vectors, and a silently mixed space is worse
than a visible error.

**What is the comparability rule for every cosine?**
A cosine measured before 2026-11-18 (local MiniLM) never shares a column or a table with one measured
after (hosted bge-small). It is a property of the metric, not a warning, and the headers say which era
they belong to.

**Why does `build_index.py` have no `--model` flag?**
Building an index with a model other than the one in `.env` produces an index nothing here can search.
Removing the flag is cheaper than documenting the trap.

## Safety and refusals

**Where do refusals happen?**
Before the workflow, in deterministic code (`app/policy.py`). Off-topic or non-CVE requests never cost
a model call, and the refusal reason is recorded in the trace.

**What stops the model inventing structure?**
Strict contracts (`extra="forbid"`), then code checks: the CVE id cannot change mid-run, the risk tier
and citations are owned by deterministic code, section citations are capped at 20 (`MAX_SECTION_CITATIONS`),
important identifiers must survive revision, and the Final Validator re-checks every report field against
the trusted records before anything is returned.

**Does the UI ever show a traceback?**
No. Anything unexpected renders as one plain sentence naming the exception type, because Streamlit's
traceback widget would expose local absolute paths and offer to send the whole thing to a third-party
search engine.

## Observability and records

**Why JSONL and not just Langfuse?**
`data/traces/investigations.jsonl` is the system of record: every run including failures leaves an
inspectable record with request, response, evidence, retrieved contexts, model calls, error, and since
D34 the `runtime` block naming the embedding model and index fingerprint it retrieved with. Langfuse
is a localhost-only viewer over it, never the source of truth.

**What does one investigation record contain?**
`trace_id`, `recorded_at`, request, response, `evidence_interpretation`, `retrieval_meta`, the `runtime`
stamp, the revision and fallback flags, refusal reason, evidence, contexts, `model_calls`, error.
`GET /traces/{request_id}` reads it back with no model call, which is what lets the UI show the exact
paragraph behind each citation.

**Why does the History tab have a Vectors column?**
Because a row that cannot name its embedding model is indistinguishable from one a retired index
produced. D34 added the stamp after 16 pre-swap rows were being shown as current; those rows were
moved to the quarantine folder, and older rows now read `not recorded`.

## Reproducibility and the tree

**What ships and what gets rebuilt?**
`data/processed` (71 MB) and `data/raw/nvd` (155 records, 2.3 MB) ship. `data/index` (53 MB) is
rebuilt by `python -m scripts.build_index`, and the rest of `data/raw` is re-fetched by script. Proven
by copying the `git ls-files -o --exclude-standard` list into an empty directory and running the whole
ladder from there: 343 offline tests, all four smoke checks, a full index rebuild byte-identical by
SHA-256, two live investigations `completed`, and the dashboards serving 110 rows / 110 claims / 24
summary keys from committed files alone.

**Why commands in module form?**
`python scripts/smoke.py` raises `ModuleNotFoundError: No module named 'app'` because the repo root is
not on `sys.path`. Measured, not assumed — so every documented command is `-m scripts.<name>`.

**Why is the repository still uncommitted?**
User choice. It also means nothing has ever been deleted here: removals go to a dated quarantine
folder with a `MANIFEST.md` entry giving reason, bytes, SHA-256 and destination, because with zero
commits a deletion cannot be undone.

**What is not reproducible?**
Answer prose. The same question returned byte-identical answers in one check and different wording with
identical verdicts in another, because the hosted model is not a deterministic function. What
reproduces is retrieval, facts, and the grading of whatever text came back.

## Testing

**What proves any of this?**
343 offline tests in 25 files (`python -m pytest -q`, ~16 s, no credentials, no network, tracing forced
off): contracts, source processing, chunking, retrieval, the FAISS store, the embedding client against
an `httpx.MockTransport` fake, each agent, deterministic validation, graph routing and the revision
loop, FastAPI, the Streamlit client, trace read-back and the history stamp, the Batch 10 metrics, the
workbook writer's safety guards, and the two dashboards executed under `AppTest`.

**What the tests cannot prove.**
No concurrency evidence, no production traffic, no independent human review of gold answers, and no
claim about accuracy beyond 10 investigations / 110 claims. Those limits are printed in the workbook's
own caveat column rather than left for a reviewer to infer.
