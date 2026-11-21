# CyberShield AI

**CyberShield AI** is an autonomous multi-agent cybersecurity copilot designed to investigate software vulnerabilities (CVEs) and produce production-grade, authoritative threat intelligence advisories for enterprise Security Operations Centers (SOCs). 

Built with LangGraph, FastAPI, and Streamlit, CyberShield AI decomposes investigation workflows across specialized agents (Policy Guard → Evidence Gathering → Lead Analyst → Adversarial Critic → Deterministic Validator), grounded in a hybrid retrieval architecture (BM25 + FAISS dense vectors + Reciprocal Rank Fusion) over an immutable corpus of NVD, NIST SP 800-53, CWE, MITRE ATT&CK, OWASP, and CISA KEV records.

---

## Key Features

1. **Multi-Agent Orchestration & Peer Review**: Specialized agents for policy validation, hybrid evidence retrieval, structured drafting, adversarial citation critique, and deterministic risk gating.
2. **Multi-Layered Policy Guardrail Architecture**: Sub-millisecond (< 1 ms) perimeter regex filtering + Evidence Agent semantic intent classification that blocks off-topic prompt smuggling (elections, politics, trivia, cosmology) and malicious prompt injections before retrieval or LLM inference.
3. **User-Tailored Executive Summaries**: Whatever specific aspect the operator requests after the CVE (severity, KEV exploitation status, patch guidance, or admin setup bypass), the executive summary directly answers in plain English while citing supporting evidence IDs.
4. **8 Collapsible Deterministic Technical Checkpoints (`st.expander`)**: Deep dive technical checkpoints follow a fixed, cryptographically verifiable schema, organized into collapsible windows to prevent cognitive overload.
5. **Human-in-the-Loop (HITL) Web Ingestion (Option B)**: Safe boundary gate prompting operators for explicit approval before dispatching `FetchFromWebAgent` to query 6 live external CTI sources.
6. **Unified Evaluation & Observability (Langfuse v2)**: Live automated evaluation (LLM-as-a-Judge, Semantic Cosine via BGE-small, ROUGE-1/2/L, RAG Recall/Precision/MRR) synchronized to local Langfuse traces and prompt templates.

---

## Quickstart & Installation

Run all commands from the repository root using the dedicated Python virtual environment:

```bash
# 1. Create and activate virtual environment
python -m venv .venv
# Windows:
.\.venv\Scripts\activate
# POSIX:
# source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment variables
copy .env.example .env    # POSIX: cp .env.example .env
```

### Configuration (`.env`)
Fill in `.env` with your API endpoints and credentials:
- `QWEN_*`: Inference host URL, API key, model name (`Qwen/Qwen3-8B`), and CA certificate path (`vm06-ca.crt`).
- `EMBEDDINGS_*`: Dense embeddings host URL, API key, model name (`BAAI/bge-small-en-v1.5`), and CA certificate path (`vm02-ca.crt`).
- `LANGFUSE_*`: Optional local tracing (`http://127.0.0.1:3100`).

---

## Build Index & Verify Environment

```bash
# Verify external dependencies and TLS endpoints
python -m scripts.smoke

# Build local FAISS and BM25 index from frozen corpus (~15 min, 10,457 chunks)
python -m scripts.build_index

# Run test suite
pytest -v
```

---

## Run Applications

Start the FastAPI backend service and the Streamlit UI (both bind strictly to loopback `127.0.0.1` for security):

```bash
# Terminal 1: FastAPI Investigation Service (Port 8000)
python -m uvicorn app.api:create_app --factory --host 127.0.0.1 --port 8000

# Terminal 2: Streamlit Interactive UI (Port 8501)
python -m streamlit run streamlit_app.py --server.port 8501 --server.address 127.0.0.1
```

Access the web application at: **[http://127.0.0.1:8501](http://127.0.0.1:8501)**.

---

## Multi-Layered Policy Guardrail Architecture

CyberShield AI enforces a defense-in-depth safety boundary to prevent prompt injection, weaponization payloads, and off-topic domain diversion (e.g., queries smuggling non-security questions alongside CVE IDs):

```
User Query: "Investigate CVE-2021-23017: what is universe"
                    │
                    ▼
[ Layer 1: Deterministic Perimeter Guard ] ──► Matches IRRELEVANT_TOPIC_RE (< 1 ms)
                    │                           └── Fast HTTP 422 Refusal (0 LLM Tokens)
                    ▼ (Safe Cyber Query)
[ Layer 2: Evidence Agent Semantic Judge ] ──► Qwen intent check (is_cyber_relevant)
                    │                           └── Refuses obfuscated prompt smuggling
                    ▼ (Relevant Intent)
[ Layer 3: LangGraph Fast-Refusal Loop   ] ──► Short-circuits invalid states to Report(refused)
```

1. **Deterministic Perimeter Guard (`app/policy.py`, `app/api.py`)**: Sub-millisecond pure-Python regex gate (`IRRELEVANT_TOPIC_RE` + `UNSAFE_REQUEST_RE`) that intercepts politics, elections, general trivia, astronomy, cosmology, philosophy, and prompt injection attempts before entity extraction. Universally enforced across all 5 execution modes.
2. **Semantic Relevance Judge in Evidence Agent (`app/evidence_qwen.py`)**: LLM-level intent classification (`is_cyber_relevant`) that halts retrieval if an off-topic question is attached to a CVE.
3. **Workflow Fast-Refusal Loop (`app/workflow.py`)**: Bypasses downstream Analyst, Critic, and Validator stages, producing an audited refusal report with complete trace telemetry.

---

## 8 Deterministic Technical Checkpoints

Every investigation dossier is organized into a top **Executive Summary & Direct Query Response** card followed by **8 Collapsible Deep Dive Checkpoints**:

1. **🔬 Checkpoint 1: Technical CVE Facts & CVSS 3.1 Metrics**: Grounded base scores, vector string, CWE weakness identifier, and affected product boundaries.
2. **🛡️ Checkpoint 2: Verified Patch & Remediation Guidance**: Official patch versions and mitigations cited directly from vendor and NVD advisories.
3. **🚨 Checkpoint 3: CISA Known Exploited Vulnerabilities (KEV) Status**: In-the-wild weaponization status, federal remediation deadlines, and ransomware associations.
4. **🎯 Checkpoint 4: MITRE ATT&CK Matrix Alignment**: Curated adversary tactic and technique mappings (e.g., T1190).
5. **⚖️ Checkpoint 5: Deterministic Project Risk Tier & Audit Limitations**: Risk classification with transparent disclosure of missing mappings or retrieval boundaries.
6. **📄 Checkpoint 6: Authoritative Evidence Manifest & Citations**: Complete atomic evidence package (`[EV-0001]..[EV-0008]`) with clickable official source URLs.
7. **🛡️ Checkpoint 7: Critic Adversarial Audit & Grounding Verification**: Live audit telemetry validating citation support, uncertainty handling, and **User Inquiry Compliance** (verifying that the executive summary answers every requested facet: severity, KEV status, patch, bypass).
8. **📊 Checkpoint 8: Execution Telemetry, Evaluation & Latency Benchmarks**: Real-time evaluation scores (LLM-as-a-Judge, Semantic Cosine, ROUGE-1/2/L, RAG Recall/Precision/MRR).

---

## Optional: Local Langfuse v2 Tracing

To run local telemetry and prompt version management via Docker:

```bash
# Start Langfuse containers (Port 3100)
docker compose -f docker/langfuse-compose.yml up -d

# Seed and synchronize all 9 production agent prompt templates
python scripts/seed_langfuse_prompts.py
```

Dashboard: **[http://127.0.0.1:3100](http://127.0.0.1:3100)**.

---

## Technical Documentation

For the complete technical capstone report, consult:
* **`docs/CyberShield_AI_Final_Technical_Report_Track_B.md`** — The complete comprehensive capstone report detailing problem formulation, multi-agent orchestration, pure IR RAG evaluation framework (MRR=0.960), HITL Option B live web ingestion, the 10-tool inventory matrix, small-model failure modes, and responsible AI governance.
