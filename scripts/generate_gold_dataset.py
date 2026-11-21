"""Generate a simplified, presentation-friendly gold dataset Excel file.

Reads from:
  - The original 77-column evaluation workbook (CyberShield_Batch10_Consolidated_RAG_Agent_Evaluation_Traceability.xlsx)
  - data/evaluation/batch10_live_20261118/scores.json (D33 live run results)

Writes:
  - CyberShield_Gold_Dataset.xlsx (4 sheets)
  - Also saves a copy of this generator script to scripts/generate_gold_dataset.py

The original workbook is never modified.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

ROOT = Path(__file__).resolve().parent.parent
SOURCE_WORKBOOK = ROOT / "CyberShield_Batch10_Consolidated_RAG_Agent_Evaluation_Traceability.xlsx"
SOURCE_SHEET = "Batch 10 - RAG Agent Eval"
SCORES_JSON = ROOT / "data" / "evaluation" / "batch10" / "scores.json"
if not SCORES_JSON.exists():
    SCORES_JSON = ROOT / "data" / "evaluation" / "batch10_live_20261118" / "scores.json"
OUTPUT = ROOT / "CyberShield_Gold_Dataset.xlsx"

FIRST_DATA_ROW = 5

HEADER_FONT = Font(bold=True, color="FFFFFF", size=11, name="Segoe UI")
HEADER_FILL = PatternFill(start_color="1F497D", end_color="1F497D", fill_type="solid")
DATA_FONT = Font(size=10, name="Segoe UI")
BOLD_DATA_FONT = Font(bold=True, size=10, name="Segoe UI")
TOTAL_FONT = Font(bold=True, size=11, color="1F497D", name="Segoe UI")

WRAP_ALIGN = Alignment(wrap_text=True, vertical="top")
CENTER_ALIGN = Alignment(vertical="center", horizontal="center")
LEFT_CENTER_ALIGN = Alignment(vertical="center", horizontal="left")

THIN_BORDER = Border(
    left=Side(style="thin", color="D9D9D9"),
    right=Side(style="thin", color="D9D9D9"),
    top=Side(style="thin", color="D9D9D9"),
    bottom=Side(style="thin", color="D9D9D9"),
)
TOTAL_BORDER = Border(
    left=Side(style="thin", color="B4C6E7"),
    right=Side(style="thin", color="B4C6E7"),
    top=Side(style="thin", color="1F497D"),
    bottom=Side(style="double", color="1F497D"),
)

PASS_FILL = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
FAIL_FILL = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
PARTIAL_FILL = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")


def _text(value):
    if value is None:
        return ""
    return str(value).strip()


def _clean_source_labels(raw):
    if not raw:
        return ""
    labels = set()
    for part in raw.replace("\n", ";").replace(",", ";").split(";"):
        part = part.strip()
        if not part:
            continue
        up = part.upper()
        if "NVD" in up or "nvd.nist.gov" in part:
            labels.add("NVD (National Vulnerability Database)")
        elif "KEV" in up or "CISA" in up:
            labels.add("CISA KEV Catalog")
        elif "ATT&CK" in up or "MITRE" in up:
            labels.add("MITRE ATT&CK Framework")
        elif "OWASP" in up:
            labels.add("OWASP Top 10 / Guidelines")
        elif "CWE" in up:
            labels.add("CWE Taxonomy")
        elif "NIST" in up:
            labels.add("NIST SP 800 Guidelines")
        elif "nginx" in part.lower():
            labels.add("nginx Security Advisory")
        elif "apache" in part.lower():
            labels.add("Apache Security Advisory")
        elif "vendor" in part.lower():
            labels.add("Vendor Security Advisory")
        else:
            labels.add(part[:50] if len(part) > 50 else part)
    return ", ".join(sorted(labels))


def _style_header_row(ws, num_cols, row=1):
    for col in range(1, num_cols + 1):
        cell = ws.cell(row, col)
        cell.font = HEADER_FONT
        cell.fill = HEADER_FILL
        cell.alignment = Alignment(wrap_text=True, vertical="center", horizontal="center")
        cell.border = THIN_BORDER
    ws.row_dimensions[row].height = 28


def _style_data_cell(ws, row, col, font=DATA_FONT):
    cell = ws.cell(row, col)
    cell.font = font
    cell.border = THIN_BORDER


def _verdict_fill(verdict):
    v = verdict.strip().lower()
    if v.startswith("pass"):
        return PASS_FILL
    elif v.startswith("fail"):
        return FAIL_FILL
    elif v.startswith("partial"):
        return PARTIAL_FILL
    return None


def _parse_verdict_col74(raw):
    t = _text(raw)
    if not t:
        return ("", "")
    first_line = t.split("\n")[0].strip()
    parts = first_line.split(" - ", 1)
    verdict = parts[0].strip() if parts else ""
    rule = parts[1].strip() if len(parts) > 1 else ""
    return (verdict, rule)


def _parse_field_check_col75(raw):
    t = _text(raw)
    if not t:
        return ""
    if t.upper().startswith("PASS"):
        return "PASS"
    elif t.upper().startswith("FAIL"):
        return "FAIL"
    return t[:40]


def _extract_claim_output(claim_dict):
    """Extract targeted system output matching this claim's category."""
    gc = claim_dict.get("generated_claim", "").strip()
    fam = claim_dict.get("family", "")

    if fam == "SEVERITY":
        for line in gc.splitlines():
            if "SEVERITY:" in line:
                return line.replace("SEVERITY:", "").strip()
        return gc

    if fam == "EXPLOITATION":
        if "\n" not in gc and len(gc) < 40:
            return f"KEV Status: {gc}"
        for line in gc.splitlines():
            if "KEV:" in line:
                return line.strip()
        return gc

    if fam == "REMEDIATION":
        for line in gc.splitlines():
            if "REMEDIATION:" in line:
                return line.replace("REMEDIATION:", "").strip()
        return gc

    if fam == "PROJECT RISK":
        for line in gc.splitlines():
            if "PROJECT RISK:" in line:
                return line.replace("PROJECT RISK:", "").strip()
        return gc

    if fam in ("AFFECTED / CONDITIONS", "DISTINCTION"):
        for line in gc.splitlines():
            if "AFFECTED:" in line:
                return line.replace("AFFECTED:", "").strip()

    if fam in ("TECHNICAL DETAILS", "WEAKNESS"):
        for line in gc.splitlines():
            if "TECHNICAL OVERVIEW:" in line:
                return line.replace("TECHNICAL OVERVIEW:", "").strip()

    if fam in ("PLAIN-LANGUAGE SUMMARY", "PLAIN-LANGUAGE EXPLANATION", "GUIDANCE"):
        for line in gc.splitlines():
            if "SUMMARY:" in line:
                return line.replace("SUMMARY:", "").strip()

    # Generic fallback: clean metadata headers
    lines = [
        l.strip()
        for l in gc.splitlines()
        if not l.startswith("STATUS:") and not l.startswith("CVE:") and l.strip()
    ]
    cleaned = " ".join(lines)
    return cleaned[:240] + ("..." if len(cleaned) > 240 else "")


def main():
    print(f"Reading source workbook: {SOURCE_WORKBOOK.name}")
    src_wb = load_workbook(SOURCE_WORKBOOK, read_only=True, data_only=True)
    src_ws = src_wb[SOURCE_SHEET]

    all_rows = []
    for row_values in src_ws.iter_rows(min_row=FIRST_DATA_ROW, max_col=77, values_only=True):
        padded = list(row_values) + [None] * (77 - len(row_values))
        if _text(padded[0]):
            all_rows.append(padded)
    src_wb.close()
    print(f"  Read {len(all_rows)} data rows")

    print(f"Reading scores: {SCORES_JSON.name}")
    scores = json.loads(SCORES_JSON.read_text("utf-8"))
    answer_by_eval = {r["eval_id"]: r for r in scores["rows"]}
    claim_by_id = {c["claim_id"]: c for c in scores["claims"]}
    print(f"  {len(answer_by_eval)} investigations, {len(claim_by_id)} claims")

    investigations = {}
    for row in all_rows:
        eval_id = _text(row[0])
        if eval_id not in investigations:
            investigations[eval_id] = {
                "eval_id": eval_id,
                "cve_id": _text(row[1]),
                "question": _text(row[2]),
                "gold_answer": _text(row[3]),
                "source_labels": set(),
                "claims": [],
            }
        for label in _text(row[10]).replace("\n", ";").replace(",", ";").split(";"):
            label = label.strip()
            if label:
                investigations[eval_id]["source_labels"].add(label)
        investigations[eval_id]["claims"].append(row)

    print(f"  {len(investigations)} investigations")

    wb = Workbook()

    # ================================================================
    # SHEET 1: Gold Questions & Answers (Human Reference)
    # ================================================================
    ws1 = wb.active
    ws1.title = "Gold Questions & Answers"
    headers1 = [
        "Eval ID",
        "CVE ID",
        "Investigation Question (User Input)",
        "Ground Truth Answer (Human Curated)",
        "Authoritative Knowledge Sources",
    ]
    for col, h in enumerate(headers1, 1):
        ws1.cell(1, col, h)
    _style_header_row(ws1, len(headers1))

    for r_idx, inv in enumerate(investigations.values(), start=2):
        ws1.cell(r_idx, 1, inv["eval_id"])
        ws1.cell(r_idx, 2, inv["cve_id"])
        ws1.cell(r_idx, 3, inv["question"])
        ws1.cell(r_idx, 4, inv["gold_answer"])
        ws1.cell(r_idx, 5, _clean_source_labels(";".join(inv["source_labels"])))
        for col in range(1, len(headers1) + 1):
            _style_data_cell(ws1, r_idx, col)
            ws1.cell(r_idx, col).alignment = WRAP_ALIGN

    ws1.column_dimensions["A"].width = 14
    ws1.column_dimensions["B"].width = 20
    ws1.column_dimensions["C"].width = 48
    ws1.column_dimensions["D"].width = 85
    ws1.column_dimensions["E"].width = 40

    # ================================================================
    # SHEET 2: Gold Claims (Atomic Facts)
    # ================================================================
    ws2 = wb.create_sheet("Gold Claims")
    headers2 = [
        "Eval ID",
        "CVE ID",
        "Claim ID",
        "Claim Category / Dimension",
        "Atomic Ground-Truth Fact to Verify",
        "Expected Knowledge Source",
    ]
    for col, h in enumerate(headers2, 1):
        ws2.cell(1, col, h)
    _style_header_row(ws2, len(headers2))

    claim_row_idx = 2
    for inv in investigations.values():
        for row in inv["claims"]:
            ws2.cell(claim_row_idx, 1, _text(row[0]))
            ws2.cell(claim_row_idx, 2, _text(row[1]))
            ws2.cell(claim_row_idx, 3, _text(row[7]))
            ws2.cell(claim_row_idx, 4, _text(row[8]))
            ws2.cell(claim_row_idx, 5, _text(row[9]))
            ws2.cell(claim_row_idx, 6, _clean_source_labels(_text(row[10])))
            for col in range(1, len(headers2) + 1):
                _style_data_cell(ws2, claim_row_idx, col)
                ws2.cell(claim_row_idx, col).alignment = WRAP_ALIGN
            claim_row_idx += 1

    ws2.column_dimensions["A"].width = 14
    ws2.column_dimensions["B"].width = 20
    ws2.column_dimensions["C"].width = 18
    ws2.column_dimensions["D"].width = 28
    ws2.column_dimensions["E"].width = 75
    ws2.column_dimensions["F"].width = 38

    # ================================================================
    # SHEET 3: Evaluation Results (RAG & Agent Validation)
    # ================================================================
    ws3 = wb.create_sheet("Evaluation Results")
    headers3 = [
        "Eval ID",
        "Claim ID",
        "Claim Category",
        "Atomic Ground-Truth Fact",
        "System Output for Claim (LLM + RAG)",
        "Claim Verdict",
        "Validation Method",
        "Overall Investigation Field Check",
    ]
    for col, h in enumerate(headers3, 1):
        ws3.cell(1, col, h)
    _style_header_row(ws3, len(headers3))

    result_row_idx = 2
    for inv in investigations.values():
        eval_id = inv["eval_id"]
        field_check = _parse_field_check_col75(inv["claims"][0][74]) if inv["claims"] else ""

        for row in inv["claims"]:
            claim_id = _text(row[7])
            claim_type = _text(row[8])
            expected = _text(row[9])
            verdict, rule = _parse_verdict_col74(row[73])

            claim_data = claim_by_id.get(claim_id, {})
            system_output = _extract_claim_output(claim_data)

            rule_friendly = rule
            if "deterministic field check" in rule.lower():
                rule_friendly = "Exact Deterministic Match (CVSS / KEV / NVD facts)"
            elif "lexical anchor proxy" in rule.lower():
                rule_friendly = "Lexical Anchor Match (RAG retrieval & synthesis)"
            elif "abstention" in rule.lower():
                rule_friendly = "Correct Abstention (Refusal / Out of bounds)"

            ws3.cell(result_row_idx, 1, _text(row[0]))
            ws3.cell(result_row_idx, 2, claim_id)
            ws3.cell(result_row_idx, 3, claim_type)
            ws3.cell(result_row_idx, 4, expected)
            ws3.cell(result_row_idx, 5, system_output)
            ws3.cell(result_row_idx, 6, verdict)
            ws3.cell(result_row_idx, 7, rule_friendly)
            ws3.cell(result_row_idx, 8, field_check)

            for col in range(1, len(headers3) + 1):
                _style_data_cell(ws3, result_row_idx, col)
                ws3.cell(result_row_idx, col).alignment = WRAP_ALIGN

            fill = _verdict_fill(verdict)
            if fill:
                ws3.cell(result_row_idx, 6).fill = fill
            fc_fill = _verdict_fill(field_check)
            if fc_fill:
                ws3.cell(result_row_idx, 8).fill = fc_fill

            result_row_idx += 1

    ws3.column_dimensions["A"].width = 14
    ws3.column_dimensions["B"].width = 18
    ws3.column_dimensions["C"].width = 28
    ws3.column_dimensions["D"].width = 65
    ws3.column_dimensions["E"].width = 58
    ws3.column_dimensions["F"].width = 14
    ws3.column_dimensions["G"].width = 44
    ws3.column_dimensions["H"].width = 22

    # ================================================================
    # SHEET 4: Summary Scorecard
    # ================================================================
    ws4 = wb.create_sheet("Summary Scorecard")
    headers4 = [
        "Eval ID",
        "CVE ID",
        "Total Facts Tested",
        "Pass",
        "Partial",
        "Fail",
        "Abstain (Safe)",
        "Deterministic Field Check",
        "ROUGE-L F1 Similarity",
    ]
    for col, h in enumerate(headers4, 1):
        ws4.cell(1, col, h)
    _style_header_row(ws4, len(headers4))

    summary_row_idx = 2
    for inv in investigations.values():
        eval_id = inv["eval_id"]
        answer_row = answer_by_eval.get(eval_id, {})
        answer_data = answer_row.get("answer") or {}

        total = len(inv["claims"])
        passes = answer_data.get("claims_pass", 0)
        partials = answer_data.get("claims_partial", 0)
        fails = answer_data.get("claims_fail", 0)
        abstains = answer_data.get("claims_abstain", 0)
        field_check = _parse_field_check_col75(inv["claims"][0][74]) if inv["claims"] else ""
        rouge_l = answer_row.get("rougeL_f")

        ws4.cell(summary_row_idx, 1, eval_id)
        ws4.cell(summary_row_idx, 2, inv["cve_id"])
        ws4.cell(summary_row_idx, 3, total)
        ws4.cell(summary_row_idx, 4, passes)
        ws4.cell(summary_row_idx, 5, partials)
        ws4.cell(summary_row_idx, 6, fails)
        ws4.cell(summary_row_idx, 7, abstains)
        ws4.cell(summary_row_idx, 8, field_check)
        ws4.cell(summary_row_idx, 9, f"{rouge_l:.4f}" if rouge_l is not None else "")

        for col in range(1, len(headers4) + 1):
            _style_data_cell(ws4, summary_row_idx, col)
            ws4.cell(summary_row_idx, col).alignment = Alignment(
                vertical="center",
                horizontal="center" if col not in (1, 2) else "left",
            )

        fc_fill = _verdict_fill(field_check)
        if fc_fill:
            ws4.cell(summary_row_idx, 8).fill = fc_fill

        ws4.row_dimensions[summary_row_idx].height = 20
        summary_row_idx += 1

    total_row = summary_row_idx
    ws4.cell(total_row, 1, "TOTAL")
    ws4.cell(total_row, 1).font = TOTAL_FONT
    ws4.cell(total_row, 1).alignment = Alignment(vertical="center", horizontal="left")
    ws4.cell(total_row, 1).border = TOTAL_BORDER

    ws4.cell(total_row, 2, "10 Investigations")
    ws4.cell(total_row, 2).font = TOTAL_FONT
    ws4.cell(total_row, 2).alignment = Alignment(vertical="center", horizontal="left")
    ws4.cell(total_row, 2).border = TOTAL_BORDER

    for col_idx in range(3, 8):
        formula = f"=SUM({get_column_letter(col_idx)}2:{get_column_letter(col_idx)}{total_row - 1})"
        cell = ws4.cell(total_row, col_idx, formula)
        cell.font = TOTAL_FONT
        cell.alignment = Alignment(vertical="center", horizontal="center")
        cell.border = TOTAL_BORDER

    avg_formula = f"=AVERAGE({get_column_letter(9)}2:{get_column_letter(9)}{total_row - 1})"
    avg_cell = ws4.cell(total_row, 9, avg_formula)
    avg_cell.font = TOTAL_FONT
    avg_cell.alignment = Alignment(vertical="center", horizontal="center")
    avg_cell.border = TOTAL_BORDER

    ws4.row_dimensions[total_row].height = 24

    ws4.column_dimensions["A"].width = 14
    ws4.column_dimensions["B"].width = 20
    ws4.column_dimensions["C"].width = 18
    ws4.column_dimensions["D"].width = 10
    ws4.column_dimensions["E"].width = 10
    ws4.column_dimensions["F"].width = 10
    ws4.column_dimensions["G"].width = 16
    ws4.column_dimensions["H"].width = 28
    ws4.column_dimensions["I"].width = 24

    wb.save(OUTPUT)
    print(f"\nWrote: {OUTPUT}")
    print(f"  Sheet 1 '{ws1.title}': {len(investigations)} investigations")
    print(f"  Sheet 2 '{ws2.title}': {claim_row_idx - 2} claims")
    print(f"  Sheet 3 '{ws3.title}': {result_row_idx - 2} evaluation rows")
    print(f"  Sheet 4 '{ws4.title}': {summary_row_idx - 2} summary rows + totals")

    target_script = ROOT / "scripts" / "generate_gold_dataset.py"
    if Path(__file__).resolve() != target_script.resolve():
        shutil.copy2(Path(__file__), target_script)
        print(f"Saved reproducible generator script to: {target_script}")


if __name__ == "__main__":
    main()
