# CyberShield AI — Architecture & Design FAQ

A clear, mentor-friendly guide to the architecture, multi-agent design, retrieval pipeline, and evaluation of **CyberShield AI**.

---

## 1. Project Overview

### What is CyberShield AI?
**CyberShield AI** is an AI-powered Cybersecurity Vulnerability (CVE) Investigation Assistant. When a security analyst or developer asks about a specific vulnerability (e.g., `CVE-2021-44228` or `CVE-2021-23017`), CyberShield AI automatically:
1. Gathers structured facts from authoritative sources (NVD CVSS scores, CISA KEV exploitation status).
2. Retrieves relevant security guidance from a curated knowledge base (NIST, CWE, MITRE ATT&CK, OWASP, and vendor advisories).
3. Synthesizes a structured 8-section investigation report with exact source citations.
4. Validates the report through an independent Critic Agent and deterministic rule checks before showing it to the user.

### What problem does it solve?
Security teams face vulnerability fatigue. Sifting through NVD metrics, vendor advisories, exploit databases, and remediation guides for every CVE takes hours. Generic LLMs hallucinate severity scores, invent fake exploit details, and cite non-existent sources. CyberShield AI solves this by combining **multi-agent reasoning**, **hybrid retrieval (RAG)**, and **deterministic guardrails** so that critical facts are 100% verified against trusted databases.

---

## 2. Multi-Agent System Architecture

### What is the workflow and which agents are involved?
CyberShield AI uses **LangGraph** to coordinate four specialized stages:

```
[User Question]
       │
       ▼
[Policy & Safety Guardrail]  ──(Blocked if unsafe / out-of-scope)
       │
       ▼
 1. [Evidence Agent]       ── Reads NVD & KEV; runs Hybrid RAG search (BM25 + FAISS)
       │
       ▼
 2. [Analyst Agent]        ── Drafts the 8-section investigation report
       │
       ▼
 3. [Critic Agent]         ── Reviews draft for factual support, citations, & completeness
       │
   (Issues found?) ──► [Analyst Revision Round] (Max 1 targeted revision)
       │
       ▼
 4. [Final Validator]      ── Deterministic code check: re-verifies CVSS & KEV against raw sources
       │
       ▼
[Final Verified Report]    ── Streamed to Streamlit UI + persisted to audit trace
```

### What does each agent do?

| Agent / Stage | Agent Identifier | Role | Technologies Used |
|---|---|---|---|
| **0. Policy Guard** | `PolicyGuard` | Filters out prompt injections, requests for exploit payloads, or queries outside the vulnerability domain. | Deterministic Regex & Pattern Engine |
| **1. Evidence Agent** | `EvidenceAgent` | Resolves CVE ID, reads local NVD/KEV records, formulates search queries, and retrieves top relevant passages. | Python LangGraph + Hybrid RAG (BM25 + FAISS) |
| **1b. Web Fetch Agent** | `FetchFromWebAgent` | Autonomous live web intelligence collection across 6 sources; executes Option B incremental ingestion. | Multi-Source REST API Orchestrator (6 Live Sources) |
| **2. Analyst Agent** | `AnalystAgent` | Synthesizes an 8-section structured report based *strictly* on the retrieved evidence package. | Qwen 8B + Strict Pydantic Contracts |
| **3. Critic Agent** | `CriticAgent` | Acts as an adversarial reviewer checking four criteria: factual support, completeness, citation accuracy, and explicit handling of unknowns. | Qwen 8B + Structured Output Validation |
| **4. Final Validator** | `FinalValidator` | Code-level authority (zero LLM calls). Ensures critical facts (CVSS score, severity tier, KEV status) match the raw source truth perfectly. | Python Deterministic Rule Engine |

### Is `FetchFromWeb` an Agent or a Tool?
**`FetchFromWebAgent` is an autonomous specialized sub-agent (a satellite collector agent), NOT a simple tool.**
- A **tool** executes a single primitive action (e.g., executing one HTTP GET request or reading a local file).
- An **agent** possesses autonomous control flow, planning, dynamic orchestration, validation, and multi-step execution. `FetchFromWebAgent` coordinates **6 distinct tools/endpoints**, cross-correlates results across disparate cybersecurity schemas, handles missing data fallbacks, verifies exploit weaponization, and executes **Option B Incremental Ingestion** (persisting raw JSON, appending structure-aware chunks, and updating live vector/BM25 indices in memory).

### In total, how many tools are there and which agent is using which tool for what?
In total, CyberShield AI integrates **10 primary tools** across the pipeline:

| # | Tool Name | Used By (Agent) | Exact Operational Purpose & Data Handled |
| :-: | :--- | :--- | :--- |
| **1** | `Tool_Regex_Policy` | **0. Policy Guard** | Validates `CVE-YYYY-NNNN+` format; intercepts prompt injections, jailbreaks, and offensive exploitation requests. |
| **2** | `Tool_Local_NVD` | **1. Evidence Agent** | Parses local NVD JSON records (`data/raw/nvd/`) for official CVSS v3.1/v2 base metrics, vectors, descriptions, and CPE products. |
| **3** | `Tool_Local_KEV` | **1. Evidence Agent** | Queries offline `data/processed/kev.jsonl` to check active in-the-wild exploitation and federal remediation deadlines. |
| **4** | `Tool_ATTACK_Mapper` | **1. Evidence (1) & Web (1b)** | Deterministically maps CWE root causes to enterprise ATT&CK techniques (e.g. CWE-89 &rarr; T1190) without LLM guesswork. |
| **5** | `Tool_Hybrid_RAG` | **1. Evidence Agent** | Dual-path retrieval over 10,457 corpus chunks using CPU FAISS (`bge-small`) + BM25Okapi fused via RRF ($k=60$). |
| **6** | `Tool_HITL_Modal` | **Gateway / Evidence Boundary** | Intercepts uncached CVE queries; presents interactive `[Approve]` / `[Reject]` modal to operator before external calls. |
| **7** | `Tool_Web_6Sources` | **1b. FetchFromWebAgent** | Queries 6 live endpoints: NIST NVD 2.0 API, CISA KEV JSON feed, MITRE ATT&CK, GitHub OSV API, ExploitDB, and Vendor Advisories. |
| **8** | `Tool_OptionB_Ingestion` | **1b. FetchFromWebAgent** | Writes retrieved NVD JSON to disk, chunks references into `reference_chunks.jsonl`, and updates active FAISS/BM25 indices. |
| **9** | `Tool_Pydantic_Enforcer` | **2. Analyst & 3. Critic** | Enforces strict JSON schema contracts (`AnalystDraft`, `CriticReview`) with bounded repair loops. |
| **10** | `Tool_Risk_Engine` | **4. Final Validator** | Applies mathematical business rules (CVSS &ge; 9.0 or KEV listed &rarr; CRITICAL), deterministically overriding LLM errors. |


### Why use LangGraph instead of a simple single prompt?
A single prompt asking an 8B model to retrieve, summarize, calculate risk, and verify citations will frequently hallucinate or drop instructions. LangGraph enforces:
- **Separation of Concerns:** Retrieval, synthesis, critique, and validation are distinct, auditable steps.
- **Controlled Revisions:** If the Critic spots missing details or uncited claims, the Analyst gets one targeted revision pass to fix them.
- **Bounded Execution:** Maximum step caps prevent infinite reasoning loops.

---

## 3. Retrieval-Augmented Generation (RAG) & Knowledge Base

### What knowledge sources are included in the RAG corpus?
The retrieval corpus consists of **10,457 chunks** extracted from authoritative security documentation:
1. **NIST SP 800 Guidelines:** Enterprise remediation and incident handling frameworks.
2. **CWE (Common Weakness Enumeration):** Root-cause weakness definitions and architectural mitigations.
3. **MITRE ATT&CK Framework:** Adversary tactics, techniques, and procedures (TTPs).
4. **OWASP Guidance:** Top 10 vulnerabilities, cheat sheets, and secure coding practices.
5. **NVD-Cited Vendor Advisories:** Pinned snapshot pages cited directly by evaluated CVEs.

*Note: Core CVE metadata (CVSS scores, vectors, publish dates) and CISA KEV exploitation entries are stored as structured records and injected directly into the Evidence Package, preventing fuzzy vector retrieval from corrupting exact numeric metrics.*

### What is the Chunking Strategy?
- **Target Size:** ~1,800 characters (~450 tokens), capped at 2,600 characters (~650 tokens).
- **Overlap:** 400 characters between adjacent paragraphs.
- **Structure-Aware Chunking:**
  - Markdown tables are treated as atomic units (never split mid-row).
  - Headings are preserved in chunk metadata so every passage knows its parent topic.
  - Short structured records (CWE definitions, ATT&CK techniques) are kept intact.

### How does Hybrid Retrieval work?
Pure semantic vector search often misses exact identifiers (like `CVE-2021-23017` or `CWE-190`), while pure keyword search misses semantic synonyms. CyberShield AI combines both:
1. **Keyword Search (BM25):** Finds exact keyword and identifier matches.
2. **Dense Vector Search (FAISS):** Finds conceptually similar security guidance using `bge-small-en-v1.5` embeddings (384 dimensions).
3. **Reciprocal Rank Fusion (RRF):** Fuses the rankings from BM25 and FAISS using standard reciprocal rank weights ($1 / (60 + \text{rank})$) to produce the top candidate passages.
4. **Vendor-Reference Priority:** Vendor advisories linked to the target CVE are prioritized to ensure remediation advice matches the affected software.

### Why use a local FAISS index instead of an external vector database (Pinecone/Milvus/Chroma)?
- **Blazing Fast CPU Retrieval:** With ~10,500 vectors, exact flat indexing runs in milliseconds entirely on CPU without GPU or network overhead.
- **100% Offline & Reproducible:** The entire index is stored locally in `data/index/embeddings.faiss`. It requires no external cloud database subscriptions, credentials, or network calls.
- **Zero Infrastructure Complexity:** A fresh checkout or demonstration runs end-to-end immediately without launching external database containers.


### If live web search is possible at runtime, why did we create RAG in the first place?
This is a critical architectural question. The short answer:

> *"Live web search gives us freshness for zero-days, but RAG gives us speed, security perimeter control, rate-limit resilience, and deep cross-framework intelligence. In an enterprise SecOps environment, you cannot afford 10-second web latency, public API rate-limit throttles, or data leakage on every routine query.*
> *That is why CyberShield AI uses RAG as the primary offline foundation (95%+ of queries) and treats Live Web Fetch as a controlled, Human-in-the-Loop exception that immediately feeds back into RAG via Option B incremental ingestion."*

#### The 6 Core Reasons Why RAG is Mandatory in Enterprise SecOps:
1. **Air-Gapped Perimeter Security & Zero Data Exfiltration:**
   - Enterprise SOCs (banking, healthcare, defense) operate behind strict firewalls with restricted egress.
   - Live web search leaks internal vulnerability queries, hostnames, and software stack details outside the enterprise perimeter.
   - Local RAG executes **100% offline** without a single byte leaving the corporate network.
2. **Deterministic SLAs: 15 Milliseconds vs. 10 Seconds:**
   - Local Hybrid RAG (FAISS + BM25) retrieval completes in **15.8 milliseconds** on CPU.
   - Live web lookups take **4 to 12 seconds** per query due to network latency, DNS lookups, and parsing across multiple APIs.
   - When triaging a batch of 500 CVEs from a vulnerability scanner, RAG finishes in seconds, whereas web search takes over an hour.
3. **API Rate Limits & Throttling (NIST NVD 429 / 403 Bans):**
   - NIST NVD API 2.0 enforces a strict rate limit of **5 requests per 30 seconds** (or 50 with an API key).
   - High-volume SOC triage would immediately exhaust public API quotas and get IP-banned. RAG has zero external rate limits.
4. **Deep Multi-Framework Threat Context vs. Shallow Web Snippets:**
   - A raw web search returns a basic NVD page or a vendor blog post.
   - Our RAG corpus unifies **10,457 structure-aware passages** cross-referencing **NIST SP 800-53 Rev. 5 controls** (SI-2, AC-3), **MITRE ATT&CK enterprise tactics** (T1190, T1059), **OWASP Top 10**, and **CWE root causes**.
   - Live web search cannot automatically map a novel CVE to specific federal compliance controls; RAG synthesizes them deterministically.
5. **Defense Against Prompt Injection & Adversarial CTI Poisoning:**
   - Unvetted live web pages, forums, and GitHub issues can contain indirect prompt injections designed to mislead LLMs into downplaying critical flaws.
   - Our RAG database is **pre-processed, sanitized, and cryptographically verified** offline.
6. **Reproducibility, Auditability & Regulatory Compliance (NIS2 / FedRAMP):**
   - Web pages and API schemas change over time.
   - RAG guarantees that every investigation cites immutable, timestamped Evidence Manifest records (`[EV-0001..EV-0008]`), ensuring identical results across regulatory audits.
---

## 4. Guardrails & Hallucination Prevention

### How does CyberShield AI prevent LLM hallucinations?
Small models (≤8B parameters) are prone to inventing plausibly sounding facts. CyberShield AI applies five layers of defense:

1. **Strict Output Schemas (Pydantic `extra="forbid"`):** The LLM cannot output arbitrary keys or alter the expected JSON structure.
2. **Strict Citation Requirement:** Every claim in the Summary, Remediation, and Risk sections must reference a specific evidence ID (`EV-0001`, `EV-0002`). Uncited claims are flagged by the Critic.
3. **Deterministic Authority:** Critical facts are **owned by Python code, not the LLM**:
   - The LLM *cannot* change the CVE ID.
   - The LLM *cannot* decide the Risk Tier (Risk is computed deterministically from CVSS score + KEV exploit status).
   - If the NVD or KEV record is missing, the system explicitly marks it as `unknown` rather than letting the LLM invent numbers.
4. **Adversarial Critic Agent:** Cross-checks the draft against the retrieved passages before the report is accepted.
5. **Final Validator:** A deterministic code gate that verifies all fields against the raw database records before rendering the final report.

---

## 5. Evaluation & Ground-Truth Validation

### How is RAG evaluated? Why decouple Retrieval (IR) from Generation?
Evaluating RAG simply as "RAG vs. No-RAG" only demonstrates that adding context helps an LLM, but it fails to evaluate retrieval quality scientifically. CyberShield AI decouples evaluation into a **Two-Stage Decoupled Framework**:

1. **Stage 1: Information Retrieval (IR) Quality:**
   - **Context Precision@5 (48.0%):** Proportion of top-5 retrieved passages containing authoritative CVE facts.
   - **Context Recall@8 (94.5% overall, 100% Core Facts):** Coverage of gold-standard vulnerability facts.
   - **Mean Reciprocal Rank (MRR = 0.960):** Verifies that the primary ground-truth NVD/KEV record is ranked at rank #1 or #2.
   - **Hit Rate@3 (100.0%):** 100% of benchmark investigations place an authoritative passage in the top 3 results.
2. **Stage 2: Grounded Generation Quality:**
   - **Semantic Cosine Similarity (0.9280):** High embedding alignment with gold reference answers via `bge-small-en-v1.5`.
   - **ROUGE-L F1 (0.2839):** Strong token overlap with human gold references.
   - **Strict LLM-as-a-Judge Pass Rate (100% / 5.0 out of 5.0):** 0 hallucinated claims across all 110 audited facts.
   - **Citation Grounding (100%):** Zero phantom or uncited claims in the final advisory.

#### Retrieval Engine Architecture Comparison:
| Retrieval Architecture | P@1 | P@3 | P@5 | R@3 | R@5 | R@8 | MRR | Hit Rate@3 | Mean Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Dense Vector (FAISS / BGE-Small)** | 0.600 | 0.500 | 0.420 | 0.525 | 0.730 | 0.820 | 0.825 | 80.0% | **12.4 ms** |
| **Sparse Keyword (BM25Okapi)** | 0.700 | 0.433 | 0.360 | 0.455 | 0.630 | 0.750 | 0.780 | 90.0% | **3.1 ms** |
| **Hybrid RRF ($k=60$) (CyberShield AI)** | **0.900** | **0.633** | **0.480** | **0.665** | **0.840** | **0.945** | **0.960** | **100.0%** | **15.8 ms** |

### In the benchmark Excel workbook (`CyberShield_Gold_Dataset.xlsx`), what is the difference between the "Gold Questions & Answers" and "Gold Claims" tabs?
This is a vital distinction between **Macro-Level** and **Micro-Level** ground truth:

1. **`Gold Questions & Answers` Tab (Macro-Level Document Ground Truth):**
   - Contains **10 comprehensive, human-curated 8-section security advisories** written by experienced cybersecurity practitioners for the 10 benchmark CVEs.
   - **Purpose:** Used for document-level NLP text comparison: evaluating **Semantic Cosine Similarity** (BGE-Small dense vectors) and tokenized n-gram overlap (**ROUGE-1, ROUGE-2, ROUGE-L**) between the LLM's entire generated text and the human reference.

2. **`Gold Claims` Tab (Micro-Level Atomic Truth Unit-Test Suite):**
   - Contains **110 discrete, independently checkable atomic facts** (exactly 11 standardized assertions per CVE × 10 CVEs = 110 claims).
   - **Why it is necessary:** In cybersecurity, an LLM can generate a fluent, professional-sounding 500-word paragraph that scores high on Cosine or ROUGE, but **hallucinates a critical patch version (e.g., claiming `v2.4.1` is fixed instead of `v2.4.2`) or misstates a CVSS score by 0.3**. A document-level similarity score would overlook this fatal error.
   - **The 11 Atomic Ground-Truth Dimensions (C01 to C11):**
     1. `PLAIN-LANGUAGE SUMMARY`: High-level executive description.
     2. `TECHNICAL DETAILS`: Exact flaw mechanism (e.g. 1-byte heap overwrite in `ngx_resolver_copy`).
     3. `PLAIN-LANGUAGE EXPLANATION`: Plain English operational impact.
     4. `AFFECTED / CONDITIONS`: Exact version ranges (e.g. `before 2023.11.4`) and prerequisites.
     5. `SEVERITY`: Official CVSS 3.1 score and vector string.
     6. `EXPLOITATION`: Official CISA KEV listing status and due date.
     7. `WEAKNESS`: Official CWE taxonomy ID (e.g. `CWE-193`, `CWE-288`).
     8. `REMEDIATION`: Official vendor patch build and upgrade instructions.
     9. `PROJECT RISK`: Risk tier mapping under `kev-cvss-v1`.
     10. `GUIDANCE`: NIST SP 800-53 or enterprise compliance control mappings (e.g. `SI-2`).
     11. `DISTINCTION / SAFE ABSTENTION`: Edge cases (e.g. distinguishing from sibling CVEs or refusing to guess missing ATT&CK techniques).

3. **How `Gold Claims` is Used Across the Pipeline:**
   - **For RAG Evaluation (Retrieval):** Measures **Context Recall@8** — did the hybrid retrieval engine actually fetch passages covering all 11 atomic facts? (Result: **94.5% overall**, **100% on Core Facts**).
   - **For LLM Evaluation (Answer Verification):** Powers the **`Evaluation Results`** sheet in the workbook, where each of the 110 atomic facts is audited against the actual system response. CyberShield AI achieved a **perfect 110 / 110 (100% Pass Rate)** with **zero hallucinated claims**!

### How is the system validated against human-created data?
Evaluation is performed against **Batch 10**, a curated golden benchmark covering 10 diverse CVE scenarios and 110 atomic ground-truth claims:

| Component | Description |
|---|---|
| **Evaluation Dataset** | Saved in [`CyberShield_Gold_Dataset.xlsx`](../CyberShield_Gold_Dataset.xlsx), containing 4 clear sheets: <br>1. *Gold Questions & Answers* (10 human-written reference answers)<br>2. *Gold Claims* (110 atomic facts categorized by CVSS, KEV, Remediation, etc.)<br>3. *Evaluation Results* (system output vs. human expectation with verdicts)<br>4. *Summary Scorecard* (performance summary) |
| **Deterministic Field Check** | Critical structured facts (CVSS score, vector, severity, KEV status) must match the ground truth **exactly**. <br>👉 **Result: 10/10 investigations passed 100% cleanly.** |
| **Lexical Anchor Check** | For narrative explanations, verifies that key discriminative security terms and retrieved evidence passages are present. |
| **Descriptive Metrics** | ROUGE-L F1 similarity and semantic embedding cosine are reported to provide holistic text-similarity context. |

### Why not rely solely on LLM-as-a-judge or RAGAS?
- **Circular Reasoning:** Using an LLM to evaluate an LLM from the same model family produces biased, inflated scores.
- **Deterministic Reliability:** In cybersecurity, accuracy is paramount. A system that gets a CVSS score wrong by 0.1 or flips a KEV exploit status is unacceptable. Deterministic checks guarantee ground-truth compliance.

---

## 6. System Runtime, Observability & UI

### How long does an investigation take?
- **Total End-to-End Latency:** ~24 seconds per investigation.
- **Where the time goes:**
  - Local hybrid search + vector math + validation: **~100 milliseconds** (CPU-only).
  - Hosted Qwen 8B inference (Evidence, Analyst, Critic, Revision): **~22–24 seconds** (network roundtrips and text generation).

### How is Observability implemented?
1. **Audit Traces (`data/traces/`):** Every investigation is saved as an atomic JSON trace recording the exact prompt, token usage, retrieved passage IDs, stage timings, and model completions.
2. **Local Langfuse Integration (Optional):** Supports visual trace inspection on `localhost:3100` without sending private data to cloud services.
3. **User-Friendly UI (Streamlit):**
   - Live step-by-step progress tracking showing what each agent is doing in plain English.
   - Expandable evidence cards showing the exact source text behind every citation.
   - Dedicated evaluation dashboard tabs displaying RAG performance and benchmark metrics.

---

## 8. Human-in-the-Loop (HITL) & Autonomous Web Ingestion Architecture

### What happens when an operator queries a CVE not in the local database?
CyberShield AI’s local offline database contains 155 snapshot CVEs. When a user asks about a CVE outside this local set (e.g., `CVE-2024-38077`):
1. **Deterministic Offline Miss Check:** A fast check (`has_local_nvd(cve_id)`) determines that the record is not in `data/raw/nvd/`.
2. **Human-in-the-Loop (HITL) Operator Gate:** The system halts execution *before* any external network calls are made and renders an approval card in the Streamlit UI:
   - **`[❌ Reject / Abort Investigation]`**: Zero external API calls are made. The run aborts safely and immediately, rendering a red explanation banner.
   - **`[✅ Approve & Dispatch FetchFromWebAgent]`**: Dispatches `FetchFromWebAgent` to query 6 live authoritative web sources.

### What 6 authoritative sources does `FetchFromWebAgent` query?
1. **NIST NVD REST API 2.0:** Official CVSS v3.1 / v4.0 metrics, vector string, CWE weaknesses, description, and CPE software configurations.
2. **CISA KEV Live Catalog:** Real-time JSON feed check for known exploited status, remediation deadlines, and ransomware campaign associations.
3. **MITRE ATT&CK Framework:** Technique mappings derived from weakness classes and adversary tactics.
4. **GitHub Security Advisories / OSV API:** Open-source package ecosystem vulnerability records and patch versions.
5. **ExploitDB & Public CTI:** Catalogs public exploit proof-of-concept (PoC) references.
6. **Official Vendor Advisories:** Official bulletins, patch notes, and OWASP Top 10 remediation controls.

### How does Option B (Incremental Chunking & Local Ingestion) work?
Rather than treating web intelligence as ephemeral, CyberShield AI implements **Option B**:
1. **NVD File Ingestion:** The live NVD payload is saved into `data/raw/nvd/{cve_id}.json`.
2. **CISA KEV Ingestion:** If listed as known exploited, the entry is appended to `data/processed/kev.jsonl`.
3. **Incremental Reference Chunking:** OSV advisories, vendor bulletins, exploit intelligence, and NVD notes are transformed into structured passages with headers, URLs, and token estimates, then appended to `data/processed/reference_chunks.jsonl`.
4. **Registry Tracking:** Recorded in `data/raw/web_ingested.json` with timestamp and source metadata.
5. **Dynamic Index Reload:** `ReferenceRetriever` detects the new file modification timestamp (`mtime`) and hot-indexes the new chunks for that CVE.

### What happens when that same CVE is queried again in the future?
- **Zero Approval Needed:** `has_local_nvd(cve_id)` evaluates to `True`. The operator approval card is **never shown again**.
- **100% Offline Retrieval:** The Evidence Agent pulls the cached NVD record and queries `ReferenceRetriever` locally over `reference_chunks.jsonl` with sub-second latency.
- **Smart UI Attribution:** The Live Evaluation banner clearly labels the provenance:
  - `📂 Local DB: Ingested from Prior Web Search` (for previously approved web CVEs)
  - `📂 Local DB: Base Snapshot` (for the original 155 snapshot CVEs)
  - `🌐 Live Web: Ingested to Local DB (6 Sources)` (during the initial approved run)

### What are the 4 tested and verified HITL scenarios?

| # | Scenario | Local DB | Operator Action | System Behavior |
|:---:|:---|:---:|:---:|:---|
| **1** | **Found in Local DB** (`CVE-2024-3094`) | `True` | N/A | **Zero HITL prompts.** Directly served from local offline database (CVSS 10.0). |
| **2** | **Offline Miss &rarr; Reject** (`CVE-2024-38077`) | `False` | **[❌ Reject]** | **Immediate safe abort.** 0 external web calls; red banner displayed. |
| **3** | **Offline Miss &rarr; Approve &rarr; Found** (`CVE-2024-38077`) | `False` | **[✅ Approve]** | **Queries 6 web sources.** Ingests NVD + chunks to local store. Synthesizes full report. |
| **4** | **Offline Miss &rarr; Approve &rarr; Web Miss (Dummy CVE)** (`CVE-2024-999999`) | `False` | **[✅ Approve]** | **Fast deterministic short-circuit.** Web lookup confirms CVE does not exist; sets facts to `N/A`, skips LLM synthesis to prevent hallucination, renders yellow notice banner. |
---

## 9. Quick Summary for Presentation / Mentors

When explaining CyberShield AI in your presentation, keep these four points front and center:

1. **Multi-Agent Specialization:** Instead of one giant prompt, LangGraph orchestrates distinct agents (Evidence, Analyst, Critic, Final Validator), allowing automated self-correction before output reaches the user.
2. **Hybrid RAG Grounding:** Combines BM25 keyword matching with FAISS vector search over 10,400+ security guidance chunks, ensuring every recommendation is anchored in official documentation.
3. **Zero-Hallucination Core:** Critical cybersecurity facts (CVSS scores, vectors, exploitation status) are strictly governed by deterministic Python code, guaranteeing that the model never hallucinates numbers or security tiers.
4. **Human-in-the-Loop Web Ingestion (Option B):** Uncached CVEs require explicit operator approval before hitting external APIs. Once approved, the system incrementally chunks the intelligence into the local RAG store, making all future queries 100% offline and instant!


