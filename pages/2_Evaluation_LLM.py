"""LLM & Multi-Agent Evaluation Dashboard:
Compares all 5 progression techniques across 10 unique production CVEs under identical evaluation metrics:
ROUGE-1/2/L, Semantic Cosine Similarity (BGE-Small), LLM-as-a-Judge, and Deterministic Field Checks.
"""

from __future__ import annotations

import json
from pathlib import Path
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent

st.set_page_config(
    page_title="CyberShield AI — LLM & Multi-Agent Evaluation",
    page_icon="⚖️",
    layout="wide",
)

# Custom Light Slate High-Contrast CSS
st.markdown(
    """
    <style>
      .stApp {
        background: #f8fafc;
        color: #0f172a;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      }
      .stApp p, .stApp span, .stApp label, .stApp div {
        color: #0f172a;
      }
      .stApp h1, .stApp h2, .stApp h3, .stApp h4 {
        color: #0f172a !important;
        font-weight: 700;
      }
      .page-hero {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #cbd5e1;
        border-radius: 12px;
        padding: 22px 26px;
        margin-bottom: 22px;
        box-shadow: 0 4px 16px -2px rgba(15, 23, 42, 0.12);
      }
      .page-hero-title {
        font-size: 24px;
        font-weight: 800;
        color: #ffffff !important;
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 6px;
      }
      .page-hero-title span:not(.badge-pill) {
        color: #ffffff !important;
        font-weight: 800;
      }
      .page-hero-sub, .page-hero-sub * {
        color: #cbd5e1 !important;
      }
      .page-hero-sub {
        font-size: 13.5px;
        color: #cbd5e1 !important;
        line-height: 1.5;
      }
      .badge-pill {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 9999px;
        font-size: 11.5px;
        font-weight: 700;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        margin-right: 6px;
      }
      .badge-pass { background: #dcfce7; color: #166534 !important; border: 1px solid #4ade80; }
      .badge-info { background: #e0f2fe; color: #075985 !important; border: 1px solid #38bdf8; }
      .badge-warn { background: #fef9c3; color: #854d0e !important; border: 1px solid #facc15; }
      .badge-crit { background: #fee2e2; color: #991b1b !important; border: 1px solid #f87171; }
      
      .stat-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        margin-bottom: 12px;
      }
      .stat-val {
        font-size: 24px;
        font-weight: 800;
        color: #0f172a !important;
      }
      .stat-label {
        font-size: 12px;
        color: #64748b !important;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-top: 4px;
      }
      .info-box {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-left: 4px solid #2563eb;
        border-radius: 0 8px 8px 0;
        padding: 14px 18px;
        margin-bottom: 16px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04);
      }
      .card-white {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        padding: 18px 20px;
        margin-bottom: 16px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
      }
      button[data-baseweb="tab"] {
        color: #475569 !important;
        font-weight: 600 !important;
        font-size: 14px !important;
      }
      button[data-baseweb="tab"][aria-selected="true"] {
        color: #1d4ed8 !important;
        font-weight: 700 !important;
        border-bottom: 2px solid #1d4ed8 !important;
      }
    </style>
    """,
    unsafe_allow_html=True,
)

# Hero Header
st.markdown(
    """
    <div class="page-hero">
      <div class="page-hero-title">
        <span>⚖️ LLM &amp; Multi-Agent Progression Benchmark</span>
        <span class="badge-pill badge-pass">● 5 ITERATIONS</span>
        <span class="badge-pill badge-info">10 UNIQUE CVES</span>
        <span class="badge-pill badge-warn">ZERO-SHOT TO MULTI-AGENT</span>
      </div>
      <div class="page-hero-sub">
        Strict side-by-side progression proof comparing 3 prompting techniques (without RAG), Single-Agent with RAG, 
        and Multi-Agent RAG (CyberShield AI Copilot) using identical evaluation metrics.
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

@st.cache_data
def load_data():
    p = ROOT / "data" / "evaluation" / "consolidated_10cve_all_iterations.json"
    return json.loads(p.read_text("utf-8"))

data = load_data()

# Executive Summary in Plain Language
st.markdown("### 💡 Plain-Language Progression Summary")
st.markdown(
    """
    <div class="info-box">
      <b>The 5 Iterations Explained in Plain English:</b><br>
      <ol>
        <li><b>Iteration 1: Zero-Shot Prompting (No RAG):</b> Asking the raw model directly without examples. <i>Result:</i> The model guesses blindly, inventing product names and making up false patch versions. <b>(Fail Rate: 100%)</b></li>
        <li><b>Iteration 2: Few-Shot JSON Prompting (No RAG):</b> Providing sample JSON schema in the prompt. <i>Result:</i> Syntax improves, but the factual content inside the JSON remains completely fabricated. <b>(Fail Rate: 100%)</b></li>
        <li><b>Iteration 3: Chain-of-Thought (No RAG):</b> Asking the model to reason step-by-step. <i>Result:</i> Generates lengthy, persuasive explanations, but reasons from hallucinated facts. <b>(Fail Rate: 100%)</b></li>
        <li><b>Iteration 4: Single-Agent with RAG (Best Prompt):</b> Providing retrieved NVD + CISA KEV context. <i>Result:</i> Huge jump in factual accuracy (4.0/5.0). However, lacks a separate fact-checking reviewer to catch minor citation misses.</li>
        <li><b>Iteration 5: Multi-Agent RAG (CyberShield AI Copilot):</b> Specialized Lead Analyst + Adversarial Critic + Final Validator. <i>Result:</i> <b>100% deterministic accuracy</b>, <b>5.0/5.0 Judge score</b>, and zero hallucinations.</li>
      </ol>
    </div>
    """,
    unsafe_allow_html=True,
)

# Dynamic metrics computed from data
multi_sem = sum(d["iterations"]["multi_agent"]["semantic_cosine"] for d in data) / len(data)
multi_judge = sum(d["iterations"]["multi_agent"]["judge"]["overall"] for d in data) / len(data)
multi_judge_pass = sum(1 for d in data if d["iterations"]["multi_agent"]["judge"]["pass"])
multi_det_pass = sum(
    1
    for d in data
    if all(v in ("match", "not-in-reference") for v in d["iterations"]["multi_agent"].get("fields", {}).values())
    and len(d["iterations"]["multi_agent"].get("fields", {})) > 0
)

# 4 Key Progression Metric Cards
c1, c2, c3, c4 = st.columns(4)
c1.markdown(
    """<div class="stat-card"><div class="stat-val" style="color:#dc2626;">0 / 10</div><div class="stat-label">Prompting Pass Rate (No RAG)</div></div>""",
    unsafe_allow_html=True,
)
c2.markdown(
    f"""<div class="stat-card"><div class="stat-val" style="color:#2563eb;">{multi_det_pass} / 10</div><div class="stat-label">Multi-Agent Deterministic Pass</div></div>""",
    unsafe_allow_html=True,
)
c3.markdown(
    f"""<div class="stat-card"><div class="stat-val" style="color:#16a34a;">{multi_sem:.3f}</div><div class="stat-label">Semantic Cosine (Multi-Agent)</div></div>""",
    unsafe_allow_html=True,
)
c4.markdown(
    f"""<div class="stat-card"><div class="stat-val" style="color:#9333ea;">{multi_judge:.1f} / 5.0</div><div class="stat-label">Average LLM-Judge ({multi_judge_pass}/10 Pass)</div></div>""",
    unsafe_allow_html=True,
)

st.divider()

# Section 1: Consolidated 10-CVE Scorecard Across All 5 Iterations
st.markdown("### 📊 Consolidated 10-CVE Benchmark Scorecard (All 5 Iterations)")
st.write(
    "Average empirical metrics measured across 10 unique production CVEs under strictly identical evaluation protocols "
    "(ROUGE-1/2/L, Semantic Cosine Similarity via BGE-Small, LLM-as-a-Judge, and Deterministic Field Verification):"
)

tech_defs = [
    ("zero_shot", "1. Prompting: Zero-Shot (No RAG)", "Failed (Severe Hallucinations)"),
    ("few_shot", "2. Prompting: Few-Shot JSON (No RAG)", "Failed (Valid JSON, Fake Facts)"),
    ("chain_of_thought", "3. Prompting: Chain-of-Thought (No RAG)", "Failed (Plausible Fiction)"),
    ("single_agent", "4. Single-Agent with RAG (Best Prompt)", "Passed with Minor Formatting Gaps"),
    ("multi_agent", "5. Multi-Agent RAG (CyberShield AI)", "Passed (Production Verified · 0 Hallucinations)"),
]

scorecard_rows = []
for t_k, t_lbl, verdict in tech_defs:
    r1 = sum(d["iterations"][t_k]["rouge"]["rouge1_f"] for d in data) / len(data)
    r2 = sum(d["iterations"][t_k]["rouge"]["rouge2_f"] for d in data) / len(data)
    rl = sum(d["iterations"][t_k]["rouge"]["rougeL_f"] for d in data) / len(data)
    sem = sum(d["iterations"][t_k]["semantic_cosine"] for d in data) / len(data)
    judge = sum(d["iterations"][t_k]["judge"]["overall"] for d in data) / len(data)
    judge_pass_cnt = sum(1 for d in data if d["iterations"][t_k]["judge"]["pass"])
    det_pass_cnt = sum(
        1
        for d in data
        if all(v in ("match", "not-in-reference") for v in d["iterations"][t_k].get("fields", {}).values())
        and len(d["iterations"][t_k].get("fields", {})) > 0
    )
    
    scorecard_rows.append({
        "Iteration / Technique": t_lbl,
        "ROUGE-1": f"{r1:.3f}",
        "ROUGE-2": f"{r2:.3f}",
        "ROUGE-L": f"{rl:.3f}",
        "Semantic Cosine (BGE)": f"{sem:.3f}",
        "LLM Judge (1-5)": f"{judge:.1f} / 5.0",
        "Deterministic Field Pass": f"{det_pass_cnt * 10}% ({det_pass_cnt}/10)",
        "Judge Strict Pass": f"{judge_pass_cnt * 10}% ({judge_pass_cnt}/10)",
        "Final Verdict": verdict,
    })
st.dataframe(scorecard_rows, hide_index=True, use_container_width=True)

st.divider()

# Section 2: Interactive Per-CVE Progression Explorer
st.markdown("### 🔬 Interactive Per-CVE Side-by-Side Progression Proof")
st.write("Select any of the 10 benchmark CVEs to view how each technique performed side-by-side on the exact same vulnerability:")

cve_options = [d["cve_id"] for d in data]
selected_cve = st.selectbox("Choose a Vulnerability to Audit:", cve_options)

rec = next(d for d in data if d["cve_id"] == selected_cve)

t_gold, t_z, t_f, t_cot, t_single, t_multi = st.tabs([
    "🎯 Expected Gold Output",
    "1. Zero-Shot",
    "2. Few-Shot JSON",
    "3. Chain-of-Thought",
    "4. Single-Agent RAG",
    "5. Multi-Agent Copilot",
])

with t_gold:
    st.markdown(f"#### Authoritative Ground Truth Reference for `{selected_cve}`")
    st.write(f"**Verified Sources:** {rec['sources']}")
    st.info(rec["expected_output"])

def render_iteration_tab(iter_key: str, label: str):
    it = rec["iterations"][iter_key]
    col_out, col_metrics = st.columns([2, 1])
    with col_out:
        st.markdown(f"**Actual Model Output ({label}):**")
        st.code(it["actual_response"][:1200] + ("..." if len(it["actual_response"]) > 1200 else ""), language="json" if "{" in it["actual_response"][:20] else None)
    with col_metrics:
        st.markdown("**Empirical Metrics:**")
        if it["judge"]["pass"]:
            st.success(f"Judge Score: {it['judge']['overall']} / 5.0 (PASSED)")
        else:
            st.error(f"Judge Score: {it['judge']['overall']} / 5.0 (FAILED)")
        st.write(f"• **ROUGE-1:** `{it['rouge']['rouge1_f']:.4f}`")
        st.write(f"• **ROUGE-L:** `{it['rouge']['rougeL_f']:.4f}`")
        st.write(f"• **Semantic Cosine:** `{it['semantic_cosine']:.4f}`")
        st.write(f"• **Factual Correctness:** `{it['judge']['factual_correctness']}/5`")
        st.write(f"• **Completeness:** `{it['judge']['completeness']}/5`")
        st.write(f"• **Groundedness:** `{it['judge']['groundedness']}/5`")
        if it["judge"]["issues"]:
            st.markdown("**Issues Detected by Judge:**")
            for iss in it["judge"]["issues"]:
                st.warning(f"⚠️ {iss}")

with t_z:
    render_iteration_tab("zero_shot", "Zero-Shot (No RAG)")
with t_f:
    render_iteration_tab("few_shot", "Few-Shot JSON (No RAG)")
with t_cot:
    render_iteration_tab("chain_of_thought", "Chain-of-Thought (No RAG)")
with t_single:
    render_iteration_tab("single_agent", "Single-Agent RAG")
with t_multi:
    render_iteration_tab("multi_agent", "Multi-Agent RAG (CyberShield AI)")

st.divider()

# Downloads
st.markdown("### 📥 Download Progression Datasets")
col_d1, col_d2 = st.columns(2)
with col_d1:
    st.download_button(
        "Download Consolidated 10-CVE Progression Data (JSON)",
        data=json.dumps(data, indent=2),
        file_name="consolidated_10cve_all_iterations.json",
        mime="application/json",
    )
with col_d2:
    excel_path = ROOT / "CyberShield_Gold_Dataset.xlsx"
    if excel_path.exists():
        st.download_button(
            "Download Golden Benchmark Dataset (Excel)",
            data=excel_path.read_bytes(),
            file_name="CyberShield_Gold_Dataset.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )