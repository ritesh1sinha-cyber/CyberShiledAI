"""Run all baseline prompting techniques (Zero-Shot, Few-Shot, CoT) and Single-Agent RAG
against the live hosted Qwen model across all 10 Golden Benchmark CVEs,
score each using the official evaluators (ROUGE, BGE-Small Cosine, Field Checks, LLM-Judge),
and update data/evaluation/consolidated_10cve_all_iterations.json.
"""

import json
import re
import time
from pathlib import Path

from app.config import settings
from app.qwen import QwenClient
from app.embeddings import EmbeddingsClient, MAX_CHARS_PER_TEXT
from app.answer_metrics import rouge_scores
from app.answer_layers import cosine, field_check, flatten_report
from app.workflow import SingleAgentWorkflow
from app.contracts import InvestigateRequest
from app.identifiers import CVE_RE

ROOT = Path(__file__).resolve().parent.parent
CONS_PATH = ROOT / "data" / "evaluation" / "consolidated_10cve_all_iterations.json"

ZERO_SHOT_SYSTEM = (
    "You are a cybersecurity expert. Provide an authoritative assessment of the requested CVE.\n"
    "In the 'summary' field, directly and specifically answer every question and facet the user asked (such as severity, CVSS rating, KEV status, patch guidance, or attack/bypass mechanism) in clear, plain English.\n"
    "Output pure JSON adhering to this exact schema:\n"
    "{\n"
    '  "cve_id": "string",\n'
    '  "product": "string",\n'
    '  "cvss_score": float,\n'
    '  "severity": "LOW|MEDIUM|HIGH|CRITICAL",\n'
    '  "cwe_id": "string",\n'
    '  "cisa_kev_listed": boolean,\n'
    '  "fixed_version": "string",\n'
    '  "summary": "string"\n'
    "}\n"
    "Return valid JSON only without markdown code fences or conversational preamble."
)

FEW_SHOT_SYSTEM = (
    "You are a cybersecurity analyst. In the 'summary' field, directly and specifically answer every question and facet the user asked (such as severity, CVSS rating, KEV status, patch guidance, or attack/bypass mechanism) in clear, plain English.\n"
    "Answer with pure JSON adhering to this exact schema:\n"
    "{\n"
    '  "cve_id": "string",\n'
    '  "product": "string",\n'
    '  "cvss_score": float,\n'
    '  "severity": "LOW|MEDIUM|HIGH|CRITICAL",\n'
    '  "cwe_id": "string",\n'
    '  "cisa_kev_listed": boolean,\n'
    '  "fixed_version": "string",\n'
    '  "summary": "string"\n'
    "}\n\n"
    "Example 1:\n"
    "User: Analyze CVE-2017-0144: explain severity, KEV status, and exploit\n"
    "Assistant:\n"
    "{\n"
    '  "cve_id": "CVE-2017-0144",\n'
    '  "product": "Microsoft Windows SMBv1",\n'
    '  "cvss_score": 8.1,\n'
    '  "severity": "HIGH",\n'
    '  "cwe_id": "CWE-787",\n'
    '  "cisa_kev_listed": true,\n'
    '  "fixed_version": "MS17-010",\n'
    '  "summary": "CVE-2017-0144 is a high-severity vulnerability (CVSS 8.1) in Microsoft Windows SMBv1. It is listed on the CISA KEV catalog as known exploited. Attackers exploit it via crafted SMBv1 packets (EternalBlue) to execute arbitrary code remotely. Apply security update MS17-010."\n'
    "}"
)

COT_SYSTEM = (
    "You are a cybersecurity analyst. Use step-by-step reasoning to evaluate the CVE and directly address every facet the user asked before providing the final answer in JSON:\n"
    "Step 1: Identify the vulnerability type, product, and architectural component.\n"
    "Step 2: Reason about attack vector, privileges required, and CVSS metric calculation.\n"
    "Step 3: Evaluate whether active in-the-wild exploitation was recognized by CISA KEV.\n"
    "Step 4: Formulate a concise executive summary that directly answers each requested facet of the user inquiry (severity, KEV status, patch guidance, bypass/attack mechanism) in plain English.\n"
    "Step 5: Output the final structured facts adhering to this JSON schema: cve_id, product, cvss_score, severity, cwe_id, cisa_kev_listed, fixed_version, thought_process, summary."
)

def parse_prompting_output(raw: str, query: str = "") -> dict:
    cve_match = CVE_RE.findall(query) or CVE_RE.findall(raw)
    cve_id = cve_match[0].upper() if cve_match else "CVE-INVESTIGATION"

    product = "Unknown Product"
    cvss_score = None
    severity = "HIGH"
    cwe_id = "CWE-UNKNOWN"
    cisa_kev_str = "NOT_LISTED"
    fixed_version = "Vendor Patch / Mitigation"
    summary = ""
    thought_process = ""

    clean_json_str = raw.strip()
    if "```json" in clean_json_str:
        clean_json_str = clean_json_str.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in clean_json_str:
        clean_json_str = clean_json_str.split("```", 1)[1].split("```", 1)[0].strip()

    first_brace = clean_json_str.find("{")
    last_brace = clean_json_str.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        if first_brace > 0:
            thought_process = clean_json_str[:first_brace].strip()
        try:
            parsed = json.loads(clean_json_str[first_brace : last_brace + 1])
            if isinstance(parsed, dict):
                cve_id = parsed.get("cve_id") or parsed.get("cve") or cve_id
                product = parsed.get("product") or parsed.get("affected_product") or product
                cvss_score = parsed.get("cvss_score") or parsed.get("cvss") or parsed.get("cvss_base_score")
                severity = str(parsed.get("severity") or "HIGH").upper()
                cwe_id = parsed.get("cwe_id") or parsed.get("cwe") or cwe_id
                kev_val = parsed.get("cisa_kev_listed") or parsed.get("kev") or parsed.get("cisa_kev")
                if kev_val is True or str(kev_val).lower() in ("true", "yes", "known_exploited"):
                    cisa_kev_str = "KNOWN_EXPLOITED"
                else:
                    cisa_kev_str = "NOT_LISTED"
                fixed_version = parsed.get("fixed_version") or parsed.get("patch") or fixed_version
                summary = parsed.get("summary") or parsed.get("description") or ""
                thought_process = parsed.get("thought_process") or parsed.get("reasoning") or thought_process
        except Exception:
            pass

    return {
        "cve_id": cve_id,
        "product": product,
        "cvss_score": cvss_score,
        "severity": severity,
        "cwe_id": cwe_id,
        "cisa_kev_listed": cisa_kev_str,
        "fixed_version": fixed_version,
        "summary": summary,
        "thought_process": thought_process,
    }

def format_prompting_as_text(parsed: dict) -> str:
    parts = [
        f"CVE: {parsed.get('cve_id')}",
        f"SUMMARY: {parsed.get('summary')}",
        f"AFFECTED: {parsed.get('product')}",
        f"SEVERITY: {parsed.get('cvss_score')} | {parsed.get('severity')}",
        f"WEAKNESS: {parsed.get('cwe_id')}",
        f"KEV: {parsed.get('cisa_kev_listed')}",
        f"REMEDIATION: {parsed.get('fixed_version')}",
    ]
    return "\n".join(parts)


def field_check_proxy(is_clean: bool, note: str) -> dict:
    """The deterministic field check, in the shape the old judge block had.

    No model judged this row, so ``judge`` stays null and this goes under a name that
    cannot be read as a judgment; see the same helper in
    benchmark_all_5_iterations_live.py.
    """
    return {
        "measured": False,
        "source": "deterministic field check - no model judgment",
        "pass": is_clean,
        "note": note,
    }


def main():
    print("Loading benchmark dataset...", flush=True)
    cons_data = json.loads(CONS_PATH.read_text("utf-8"))

    embedder = EmbeddingsClient()
    single_workflow = SingleAgentWorkflow()

    print(f"Re-running Single-Agent RAG live across {len(cons_data)} CVEs...\n", flush=True)

    for idx, item in enumerate(cons_data, start=1):
        eid = item["eval_id"]
        cve = item["cve_id"]
        query = item.get("question") or f"Investigate {cve}: explain the vulnerability, technical mechanism, affected products/versions and prerequisites, severity, exploitation status, weakness, remediation and relevant security guidance."
        expected = item["expected_output"]

        print(f"[{idx}/10] Running Single-Agent for {eid} ({cve})...", flush=True)

        start_sa = time.perf_counter()
        req = InvestigateRequest(query=query, top_k=8, include_attack=True)
        sa_text = ""
        sa_error: str | None = None
        try:
            sa_state = single_workflow.run(req)
            sa_report = sa_state.get("report")
            if sa_report:
                sa_dict = sa_report.model_dump(mode="json")
                sa_text = flatten_report(sa_dict)
        except Exception as sa_e:
            print(f"  [VALIDATION-FAIL] Single-Agent failed deterministic gate: {sa_e}", flush=True)
            sa_text = f"Validation Failure: {sa_e}"
            sa_error = str(sa_e)

        sa_elapsed = time.perf_counter() - start_sa

        completed = bool(sa_text) and not sa_text.startswith("Validation Failure")
        sa_fields = field_check(cve, expected, sa_text)
        sa_is_clean = (
            completed
            and all(v in ("match", "not-in-reference") for v in sa_fields.values())
            and len(sa_fields) > 0
        )
        if completed:
            sa_r = rouge_scores(sa_text, expected)
            sa_rouge = {
                "rouge1_f": round(sa_r["rouge1_f"], 4),
                "rouge2_f": round(sa_r["rouge2_f"], 4),
                "rougeL_f": round(sa_r["rougeL_f"], 4),
            }
            sa_cos_val = round(float(cosine(embedder, [(expected, sa_text)])[0]), 4)
        else:
            # A run that produced no report is a failure, not a low score. The constants
            # this branch used to write (ROUGE 0.05/0.01/0.03, cosine 0.55) were never
            # measured, and they dragged row 4 of the published scorecard down.
            sa_rouge = {"rouge1_f": None, "rouge2_f": None, "rougeL_f": None}
            sa_cos_val = None

        item["iterations"]["single_agent"] = {
            "actual_response": sa_text,
            "rouge": sa_rouge,
            "semantic_cosine": sa_cos_val,
            "judge": None,
            "judge_proxy": field_check_proxy(
                sa_is_clean,
                "Single-agent draft has no adversarial review, and no model judged it.",
            ),
            "fields": sa_fields,
            "technique_name": "Single-Agent RAG (Lead Analyst Only)",
            "latency_s": round(sa_elapsed, 2),
        }
        if not completed:
            item["iterations"]["single_agent"]["error"] = sa_error or "no report produced"
        print(
            f"  [OK] Single-Agent RAG: R1={sa_rouge['rouge1_f']} Cos={sa_cos_val} "
            f"Det={'PASS' if sa_is_clean else 'FAIL'} ({sa_elapsed:.1f}s)"
            + ("" if completed else " [FAILED - not scored]"),
            flush=True,
        )

    # Save consolidated results
    CONS_PATH.write_text(json.dumps(cons_data, indent=2, ensure_ascii=False), "utf-8")
    print("\n[OK] Saved updated data/evaluation/consolidated_10cve_all_iterations.json with fresh live Single-Agent RAG run!", flush=True)

if __name__ == "__main__":
    main()
