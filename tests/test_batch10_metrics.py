"""Tests for the deterministic Batch 10 claim grader.

The claim-level field check is the pass/fail authority for this set, so the
graded branches are pinned here: a source-derived check must always outrank the
lexical proxy, and a prose claim must never be promoted by an easy anchor match.
Claim texts are verbatim from the frozen gold rows so the branches are exercised
on the real data shape rather than invented prose.
"""

from app.batch10_metrics import (
    _mean,
    _term_check,
    abstention_state,
    anchors,
    answer_lines,
    citations_for,
    conflict_note,
    derive_result,
    fact_check,
    match_ratio,
    preservation,
    product_terms,
    requires_abstention,
    scope_text,
    version_tokens,
)

AFFECTED_CLAIM = (
    "Affected nginx resolver builds where the attacker can satisfy the DNS-response prerequisite; "
    "resolve exact versions through the vendor advisory."
)
REMEDIATION_CLAIM = "Apply the vendor-fixed nginx build and review resolver trust/exposure."
SEVERITY_CLAIM = "CVSS 3.1 7.7 HIGH (NVD); CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L."
SEVERITY_VECTOR = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L"
KEV_LISTED_CLAIM = "LISTED in KEV 2026.11.13; added 2022-01-18; catalog due date 2022-02-01."
KEV_UNLISTED_CLAIM = "NOT LISTED in KEV 2026.11.13. This does not establish absence of exploitation."
WEAKNESS_CLAIM = "NVD: CWE-193."
RISK_CLAIM = (
    "HIGH under kev-cvss-v1, using this snapshot; not an official risk category. "
    "ATT&CK: No CVE-specific ATT&CK mapping asserted; do not invent one."
)
GUIDANCE_CLAIM = "NIST SI-2 is remediation context, not an official CVE mapping."
TECHNICAL_CLAIM = "The resolver mishandles a crafted DNS response during name resolution."


def report(cve=None, kev=None, risk=None, citations=None):
    return {
        "cve": {
            "cve_id": "CVE-2021-23017",
            "cvss_version": "3.1",
            "cvss_score": 7.7,
            "severity": "HIGH",
            "cvss_vector": SEVERITY_VECTOR,
            # Lowercase exactly as the report contract declares it (Literal["nvd","cna"]).
            "cvss_source": "nvd",
            **(cve or {}),
        },
        "kev": {
            "status": "known_exploited",
            "date_added": "2022-01-18",
            "due_date": "2022-02-01",
            "catalog_version": "2026.11.13",
            **(kev or {}),
        },
        "risk": {"tier": "HIGH", **(risk or {})},
        "citations": citations if citations is not None else [{"evidence_id": "EV-0001"}],
    }


# --- term extraction ---------------------------------------------------------


def test_version_tokens_ignores_a_bare_year_inside_a_cve_identifier():
    assert version_tokens("CVE-2021-23017 on nginx 1.20.1 build 2022") == ["1.20.1"]


def test_version_tokens_reads_the_cvss_version_and_score_as_versions():
    assert version_tokens(SEVERITY_CLAIM) == ["3.1", "7.7"]


def test_product_terms_requires_only_capitalised_parts_of_a_compound():
    # "DNS-response" makes dns a required term; the lowercase half is ordinary prose.
    # A product the gold writes in lowercase, such as nginx, is not required here.
    assert product_terms(AFFECTED_CLAIM) == ["dns"]


def test_product_terms_drops_generic_verbs_source_labels_and_lowercase_products():
    assert product_terms(REMEDIATION_CLAIM) == []
    assert product_terms("Apply the NVD guidance and verify the module") == []


def test_term_check_falls_back_when_nothing_is_comparable():
    assert _term_check(REMEDIATION_CLAIM, "any answer", "remediation").startswith("n/a -")


def test_term_check_reports_a_missing_version_as_a_mismatch_not_an_absence():
    assert _term_check("release 1.20.1", "nginx needs patching", "affected").startswith("mismatch:")


def test_term_check_reports_a_missing_term_as_absent():
    assert _term_check(AFFECTED_CLAIM, "The nginx resolver needs a fixed build.", "affected") == (
        "absent - affected term(s) dns not stated"
    )


def test_term_check_matches_when_every_extractable_token_is_stated():
    assert _term_check(AFFECTED_CLAIM, "Affected builds are the nginx DNS-response path.", "affected") == "match"


# --- deterministic field checks ---------------------------------------------


def test_severity_field_check_agrees_with_the_structured_report():
    assert fact_check("SEVERITY", SEVERITY_CLAIM, report(), SEVERITY_CLAIM, SEVERITY_CLAIM) == "match"


def test_severity_field_check_calls_out_a_different_score():
    wrong = report(cve={"cvss_score": 9.8})
    assert fact_check("SEVERITY", SEVERITY_CLAIM, wrong, "", "").startswith("mismatch: cvss_score")


def test_severity_field_check_reports_an_absence_when_the_answer_has_no_cvss():
    blank = report(cve={"cvss_version": None, "cvss_score": None, "severity": None, "cvss_vector": None})
    assert fact_check("SEVERITY", SEVERITY_CLAIM, blank, "", "nothing here").startswith("absent -")


def test_exploitation_field_check_compares_listedness_before_dates():
    not_listed = report(kev={"status": "not_listed"})
    assert fact_check("EXPLOITATION", KEV_LISTED_CLAIM, not_listed, "", "") == (
        "mismatch: listedness (gold True, answer False)"
    )


def test_exploitation_field_check_flags_a_wrong_date_added():
    moved = report(kev={"date_added": "2020-01-01"})
    assert "date added" in fact_check("EXPLOITATION", KEV_LISTED_CLAIM, moved, "", "")


def test_exploitation_field_check_is_neutral_when_the_gold_states_no_date():
    listed_without_dates = "LISTED in KEV 2026.11.13 and exploited in the wild."
    assert fact_check("EXPLOITATION", listed_without_dates, report(), "", listed_without_dates).startswith(
        "not-in-reference"
    )


def test_exploitation_field_check_accepts_an_unlisted_agreement():
    assert fact_check("EXPLOITATION", KEV_UNLISTED_CLAIM, report(kev={"status": "not_listed"}), "", "") == "match"


def test_weakness_field_check_calls_out_the_missing_cwe_field():
    # The shipped report schema carries no CWE field, so the gold CWE claims are
    # unanswerable by construction rather than wrong by accident.
    assert fact_check("WEAKNESS", WEAKNESS_CLAIM, report(), "", "a prose answer") == (
        "absent - the shipped report has no CWE field"
    )


def test_weakness_field_check_can_disagree_with_a_stated_identifier():
    assert fact_check("WEAKNESS", WEAKNESS_CLAIM, report(), "", "Weakness is CWE-79.").startswith(
        "mismatch: gold CWE-193"
    )


def test_weakness_field_check_matches_when_the_answer_states_the_same_cwe():
    assert fact_check("WEAKNESS", WEAKNESS_CLAIM, report(), "", "Weakness is CWE-193.") == "match"


def test_project_risk_field_check_names_the_calculated_source():
    disagreeing = report(risk={"tier": "MEDIUM"})
    assert fact_check("PROJECT RISK", RISK_CLAIM, disagreeing, "", "risk MEDIUM") == (
        "mismatch: gold HIGH vs kev-cvss-v1 MEDIUM"
    )


def test_project_risk_field_check_agrees_on_the_tier():
    assert fact_check("PROJECT RISK", RISK_CLAIM, report(), "", RISK_CLAIM) == "match"


def test_prose_families_have_no_field_check():
    assert fact_check("TECHNICAL DETAILS", TECHNICAL_CLAIM, report(), "", "any answer") == "n/a - prose claim"


def test_guidance_field_check_demands_the_named_control():
    assert "si-2" in fact_check("GUIDANCE", GUIDANCE_CLAIM, report(), "", "patch it")
    assert fact_check("GUIDANCE", GUIDANCE_CLAIM, report(), "", GUIDANCE_CLAIM) == "match"


# --- abstention guardrail ----------------------------------------------------


def test_requires_abstention_reads_the_golds_uncertainty_requirement():
    assert requires_abstention(RISK_CLAIM)
    assert requires_abstention("No verified ATT&CK mapping exists; contextual only.")
    assert not requires_abstention(SEVERITY_CLAIM)


def test_abstention_fails_an_answer_that_invents_a_technique_id():
    scope = "Technique T1190 exploits the exposure."
    state, note = abstention_state(RISK_CLAIM, report(), scope, scope)
    assert state == 0 and "unverified" in note


def test_abstention_passes_an_answer_that_carries_the_hedge():
    answer = "No verified ATT&CK mapping is available for this exposure."
    assert abstention_state(RISK_CLAIM, report(), answer, answer) == (1, "")


def test_abstention_fails_a_silent_answer():
    assert abstention_state(RISK_CLAIM, report(), "scope", "all clear") == (
        0,
        "the answer states no uncertainty note for the unverified element",
    )


# --- verdict precedence ------------------------------------------------------


def test_a_field_check_mismatch_outranks_everything_else():
    assert derive_result("mismatch: cvss_score", False, 1, "Y") == ("Fail", "deterministic field check")


def test_a_stated_absence_fails_even_when_the_anchors_look_great():
    assert derive_result("absent - CWE field missing", False, 1, "Y") == (
        "Fail",
        "deterministic field check",
    )


def test_a_clean_field_check_beats_the_lexical_proxy():
    assert derive_result("match", False, 1, "N") == ("Pass", "deterministic field check")


def test_prose_claims_fall_back_to_the_labelled_anchor_proxy():
    assert derive_result("n/a - prose claim", False, 1, "Partial") == ("Partial", "lexical anchor proxy")


def test_broken_abstention_fails_an_otherwise_anchored_claim():
    assert derive_result("n/a - prose claim", True, 0, "Y") == ("Fail", "abstention guardrail")


def test_a_hedged_factual_claim_passes_on_both_guards():
    assert derive_result("match", True, 1, "Y") == (
        "Pass",
        "deterministic field check plus abstention guardrail",
    )


def test_a_hedged_unanswerable_claim_is_reported_as_abstain_not_pass():
    assert derive_result("absent - not stated", True, 1, "N") == ("Abstain", "abstention guardrail")


def test_a_neutral_reference_agreement_can_be_a_pass_basis():
    assert derive_result("not-in-reference - the gold states no KEV date", True, 1, "N") == (
        "Pass",
        "deterministic field check plus abstention guardrail",
    )


# --- anchors, support and scope ---------------------------------------------


def test_anchors_puts_identifiers_first_and_keeps_them_discriminative():
    items, discriminative = anchors(SEVERITY_CLAIM, "CVE-2021-23017")
    # Vector, severity word and version tokens precede the plain prose words, and
    # the CVE carried from column B is appended as a discriminative anchor.
    assert items[0] == SEVERITY_VECTOR
    assert "CVE-2021-23017" in discriminative and "3.1" in discriminative
    assert discriminative.index("CVE-2021-23017") > discriminative.index(SEVERITY_VECTOR)


def test_match_ratio_cannot_reach_y_without_a_discriminative_anchor():
    hit = match_ratio(["module", "resolver"], ["CVE-2021-23017"], "the resolver module")
    assert hit["grade"] == "Partial" and hit["disc_found"] == [] and hit["missing"] == []


def test_match_ratio_grades_full_overlap_with_an_anchor_as_y():
    hit = match_ratio(["dns", "response"], ["CVE-2021-23017"], "CVE-2021-23017 dns response")
    assert hit["grade"] == "Y" and hit["ratio"] == 1.0


def test_match_ratio_reports_no_overlap_as_n():
    assert match_ratio(["alpha", "beta"], [], "nothing alike")["grade"] == "N"


def test_answer_lines_groups_by_the_reports_own_labels():
    assert answer_lines("SUMMARY: one line.\nRISK: HIGH.\nRISK: again.\nnot a label") == {
        "SUMMARY": ["one line."],
        "RISK": ["HIGH.", "again."],
    }


def test_scope_text_narrows_to_the_family_section_when_labelled():
    lines = {"SEVERITY": ["CVSS 3.1 7.7"], "REMEDIATION": ["patch now"]}
    assert scope_text("REMEDIATION", lines, "whole answer") == "patch now"
    assert scope_text("UNKNOWN FAMILY", lines, "whole answer") == "whole answer"


def test_citations_for_ignores_evidence_that_cannot_answer_the_family():
    evidence = [{"evidence_id": "EV-0001", "claim_type": "remediation", "source": "NVD"}]
    assert citations_for("WEAKNESS", report(), evidence) == []


def test_citations_for_keeps_cited_evidence_that_carries_the_family():
    evidence = [{"evidence_id": "EV-0001", "claim_type": "cve_description", "source": "NVD"}]
    assert citations_for("WEAKNESS", report(), evidence) == ["EV-0001"]


def test_citations_for_drops_uncited_eligible_evidence():
    evidence = [{"evidence_id": "EV-0009", "claim_type": "kev", "source": "CISA_KEV"}]
    assert citations_for("EXPLOITATION", report(), evidence) == []


# --- conflict preservation ---------------------------------------------------


def test_conflict_preservation_is_half_credit_when_the_publisher_is_not_rendered():
    score, note = preservation("SEVERITY", SEVERITY_CLAIM, report(), "CVSS 3.1 7.7 HIGH.")
    assert score == 0.5 and "cvss_source=nvd" in note and "not rendered" in note


def test_conflict_preservation_is_full_credit_when_the_publisher_is_named():
    assert preservation("SEVERITY", SEVERITY_CLAIM, report(), "NVD scores this 3.1 7.7 HIGH.") == (
        1,
        "cvss_source=nvd",
    )


def test_conflict_preservation_grades_the_severity_section_not_the_whole_answer():
    # cvss_source is contracted lowercase ("nvd"/"cna"), and half credit here is
    # the measured finding: the severity line never names the publisher even
    # though the report carries it, because cvss_source is not rendered.
    assert preservation("SEVERITY", SEVERITY_CLAIM, report(), "CVSS 3.1 7.7 HIGH, scored by NVD.") == (
        1,
        "cvss_source=nvd",
    )
    assert preservation("SEVERITY", SEVERITY_CLAIM, report(), "CVSS 3.1 7.7 HIGH.")[:1] == (0.5,)


def test_conflict_preservation_notes_an_unstated_kev_catalog_version():
    score, note = preservation("EXPLOITATION", KEV_LISTED_CLAIM, report(), "LISTED in KEV.")
    assert score == 0.5 and "catalog_version=2026.11.13" in note


def test_conflict_preservation_is_untracked_for_prose_families():
    assert preservation("TECHNICAL DETAILS", TECHNICAL_CLAIM, report(), "any") == ("n/a", "")


def test_conflict_note_keeps_the_kev_snapshot_difference_visible():
    note = conflict_note("EXPLOITATION", "LISTED in KEV 2026.11.13.", report(kev={"catalog_version": "2026.11.04"}), "", "")
    assert "gold 2026.11.13" in note and "system 2026.11.04" in note


def test_conflict_note_is_empty_when_nothing_disagrees():
    assert conflict_note("EXPLOITATION", KEV_LISTED_CLAIM, report(), "", "") == ""


def test_mean_rounds_and_stays_honest_about_no_numbers():
    assert _mean([0.12345, 0.5]) == 0.3117
    assert _mean(["n/a", None]) == "n/a"
