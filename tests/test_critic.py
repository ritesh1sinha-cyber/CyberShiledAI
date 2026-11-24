import json

import pytest
from test_analyst import (
    CVE_ID,
    FixedEvidence,
    SequenceQwen,
    make_package,
    valid_payload,
)

from app.analyst import SECTION_NAMES, AnalystAgent
from app.contracts import AnalystDraft, InvestigateRequest
from app.critic import CriticAgent, CriticError, build_review_prompt, parse_review
from app.qwen import QwenResponse
from app.workflow import InvestigationWorkflow


def make_draft(**overrides):
    payload = valid_payload()
    for section, values in overrides.items():
        payload[section].update(values)
    return AnalystDraft.model_validate(payload)


def valid_review(**overrides):
    payload = {
        "cve_id": CVE_ID,
        "support": "pass",
        "completeness": "pass",
        "citations": "pass",
        "uncertainty": "pass",
        "checked_sections": list(SECTION_NAMES),
        "issues": [],
    }
    payload.update(overrides)
    return payload


def citation_issue():
    return valid_review(
        citations="fail",
        issues=[
            {
                "section": "summary",
                "category": "citation",
                "detail": "The summary severity also needs CVSS evidence.",
                "evidence_ids": ["EV-0002"],
            }
        ],
    )


class FakeQwen:
    def __init__(self, payload=None, finish_reason="stop"):
        self.payload = valid_review() if payload is None else payload
        self.finish_reason = finish_reason
        self.calls = []

    def complete(self, system, user, max_tokens=400):
        self.calls.append((system, user, max_tokens))
        content = self.payload if isinstance(self.payload, str) else json.dumps(self.payload)
        return QwenResponse(
            content=content,
            model="Qwen/Qwen3-8B",
            latency_ms=500,
            prompt_tokens=4000,
            completion_tokens=180,
            finish_reason=self.finish_reason,
        )


def test_critic_returns_complete_review_and_trace():
    client = FakeQwen(valid_review())
    draft = make_draft(summary={"evidence_ids": ["EV-0001", "EV-0003"]})
    result = CriticAgent(client=client).graph.invoke(
        {"package": make_package(), "draft": draft}
    )
    review = result["review"]
    assert review.cve_id == CVE_ID
    assert review.support == "pass"
    assert review.citations == "fail"
    assert review.issues[0].evidence_ids == ["EV-0002"]
    assert list(review.checked_sections) == list(SECTION_NAMES)
    assert result["timings"][0].stage == "critic"
    assert result["model_calls"][0].stage == "critic"
    assert result["model_calls"][0].completion_tokens == 180
    assert len(client.calls) == 1
    assert client.calls[0][2] == 1024


def test_critic_prompt_contains_same_evidence_and_analyst_draft():
    prompt = build_review_prompt(make_package(), make_draft())
    assert "EVIDENCE_PACKAGE:" in prompt
    assert "ANALYST_DRAFT:" in prompt
    assert "Avoid evaluating untrusted input" in prompt
    assert "CVSS 3.1 score 10.0" in prompt


@pytest.mark.parametrize("content", ["not JSON", "[]", "{}"])
def test_malformed_or_incomplete_review_is_rejected(content):
    agent = CriticAgent(client=FakeQwen(content))
    with pytest.raises(CriticError, match="valid Critic review"):
        agent.create_review(make_package(), make_draft())


def test_truncated_review_is_rejected_before_parsing():
    agent = CriticAgent(client=FakeQwen(finish_reason="length"))
    with pytest.raises(CriticError, match="stopped before completing"):
        agent.create_review(make_package(), make_draft())


def test_critic_cannot_add_corrected_draft_fields():
    payload = valid_review(corrected_draft={"summary": "Replacement text"})
    agent = CriticAgent(client=FakeQwen(payload))
    with pytest.raises(CriticError, match="valid Critic review"):
        agent.create_review(make_package(), make_draft())


def test_plural_citation_category_is_normalized_at_model_boundary():
    payload = citation_issue()
    payload["issues"][0]["category"] = "citations"
    review = parse_review(json.dumps(payload))
    assert review.issues[0].category == "citation"


def test_dangling_issue_evidence_is_rejected():
    payload = citation_issue()
    payload["issues"][0]["evidence_ids"] = ["EV-9999"]
    agent = CriticAgent(client=FakeQwen(payload))
    with pytest.raises(CriticError, match="outside this request"):
        agent.create_review(make_package(), make_draft())


def test_unknown_evidence_id_in_issue_text_is_rejected():
    payload = citation_issue()
    payload["issues"][0]["detail"] = "EV-9999 is not valid support."
    agent = CriticAgent(client=FakeQwen(payload))
    with pytest.raises(CriticError, match="unknown evidence identifier"):
        agent.create_review(make_package(), make_draft())


def test_every_section_must_be_checked_once_in_order():
    payload = valid_review()
    payload["checked_sections"][0], payload["checked_sections"][1] = (
        payload["checked_sections"][1],
        payload["checked_sections"][0],
    )
    agent = CriticAgent(client=FakeQwen(payload))
    with pytest.raises(CriticError, match="every section exactly once"):
        agent.create_review(make_package(), make_draft())


@pytest.mark.parametrize(
    ("payload", "field", "expected"),
    [
        (
            valid_review(
                issues=[
                    {
                        "section": "summary",
                        "category": "support",
                        "detail": "The summary is unsupported.",
                        "evidence_ids": ["EV-0001"],
                    }
                ]
            ),
            "support",
            "fail",
        ),
        (valid_review(citations="fail"), "citations", "pass"),
    ],
)
def test_status_values_are_derived_from_issue_categories(payload, field, expected):
    review = CriticAgent(client=FakeQwen(payload)).create_review(
        make_package(), make_draft()
    )
    assert getattr(review, field) == expected


@pytest.mark.parametrize(
    ("summary_text", "expected_id"),
    [
        ("CRITICAL vulnerability allows remote code execution.", "EV-0002"),
        ("Confirmed exploitation requires urgent remediation.", "EV-0003"),
    ],
)
def test_deterministic_summary_citation_gap_is_added(
    summary_text, expected_id
):
    draft = make_draft(
        summary={"text": summary_text, "evidence_ids": ["EV-0001"]}
    )
    review = CriticAgent(client=FakeQwen(valid_review())).create_review(
        make_package(), draft
    )
    assert review.citations == "fail"
    assert len(review.issues) == 1
    assert review.issues[0].section == "summary"
    assert review.issues[0].category == "citation"
    assert review.issues[0].evidence_ids == [expected_id]


def test_deterministic_summary_issue_replaces_inadequate_model_issue():
    draft = make_draft(
        summary={
            "text": "CRITICAL vulnerability allows remote code execution.",
            "evidence_ids": ["EV-0001"],
        }
    )
    payload = citation_issue()
    payload["issues"][0]["evidence_ids"] = ["EV-0001"]
    review = CriticAgent(client=FakeQwen(payload)).create_review(
        make_package(), draft
    )
    assert len(review.issues) == 1
    assert review.issues[0].evidence_ids == ["EV-0002"]


def test_already_cited_missing_id_finding_is_removed():
    payload = citation_issue()
    payload["issues"][0].update(
        section="risk",
        detail="Risk lacks a CVSS evidence ID.",
        evidence_ids=["EV-0002"],
    )
    review = CriticAgent(client=FakeQwen(payload)).create_review(
        make_package(), make_draft()
    )
    assert review.issues == []
    assert review.citations == "pass"


def test_correctly_preserved_unknown_uncertainty_finding_is_removed():
    draft = make_draft(attack_mapping={"text": None, "evidence_ids": []})
    package = make_package(attack_mapping=[])
    payload = valid_review(
        uncertainty="fail",
        issues=[
            {
                "section": "attack_mapping",
                "category": "uncertainty",
                "detail": "No attack mapping is available.",
                "evidence_ids": [],
            }
        ],
    )
    review = CriticAgent(client=FakeQwen(payload)).create_review(package, draft)
    assert review.issues == []
    assert review.uncertainty == "pass"


def test_critic_cannot_introduce_unrelated_cve():
    payload = valid_review(
        support="fail",
        issues=[
            {
                "section": "summary",
                "category": "support",
                "detail": "CVE-2021-45046 contradicts this summary.",
                "evidence_ids": ["EV-0001"],
            }
        ],
    )
    agent = CriticAgent(client=FakeQwen(payload))
    with pytest.raises(CriticError, match="unrelated CVE"):
        agent.create_review(make_package(), make_draft())


def test_critic_can_reference_identifier_from_supplied_flawed_draft():
    draft = make_draft(summary={"text": "CVE-2021-45046 has the same issue."})
    payload = valid_review(
        support="fail",
        issues=[
            {
                "section": "summary",
                "category": "support",
                "detail": "CVE-2021-45046 is not the requested identifier.",
                "evidence_ids": ["EV-0001"],
            }
        ],
    )
    review = CriticAgent(client=FakeQwen(payload)).create_review(make_package(), draft)
    assert review.support == "fail"


def test_critic_cannot_introduce_new_attack_technique():
    payload = valid_review(
        support="fail",
        issues=[
            {
                "section": "attack_mapping",
                "category": "support",
                "detail": "T1059 should also be included.",
                "evidence_ids": ["EV-0006"],
            }
        ],
    )
    agent = CriticAgent(client=FakeQwen(payload))
    with pytest.raises(CriticError, match="new ATT&CK technique"):
        agent.create_review(make_package(), make_draft())


def test_critic_cannot_choose_risk_tier():
    payload = valid_review(
        support="fail",
        issues=[
            {
                "section": "risk",
                "category": "support",
                "detail": "Risk tier: critical.",
                "evidence_ids": ["EV-0002"],
            }
        ],
    )
    agent = CriticAgent(client=FakeQwen(payload))
    with pytest.raises(CriticError, match="deterministic risk tier"):
        agent.create_review(make_package(), make_draft())


def test_connected_workflow_runs_analyst_and_critic_without_a_planner():
    package = make_package()
    issue = {
        "section": "summary",
        "category": "support",
        "detail": "The summary overstates the supplied evidence.",
        "evidence_ids": ["EV-0001"],
    }
    failing_review = valid_review(support="fail", issues=[issue])
    client = SequenceQwen(
        [valid_payload(), failing_review, valid_payload(), failing_review]
    )
    evidence = FixedEvidence(package)
    workflow = InvestigationWorkflow(
        evidence=evidence,
        analyst=AnalystAgent(client=client),
        critic=CriticAgent(client=client),
    )
    result = workflow.run(InvestigateRequest(query=f"Investigate {CVE_ID}"))
    assert len(client.calls) == 4
    assert "Analyst Agent" in client.calls[0][0]
    assert "Critic Agent" in client.calls[1][0]
    assert "CRITIC_REVISION_REQUEST" in client.calls[2][1]
    assert issue["detail"] in client.calls[2][1]
    assert "Critic Agent" in client.calls[3][0]
    assert evidence.calls == 1
    assert result["revised"] is True
    assert result["review"].support == "fail"
    assert result["report"].status == "partial"
    assert result["report"].risk.tier == "critical"
    assert "Critic finding (summary/support)" in result["report"].limitations[-1]
    assert [call.stage for call in result["model_calls"]] == [
        "analyst",
        "critic",
        "analyst",
        "critic",
    ]
    assert [item.stage for item in result["timings"]] == [
        "evidence",
        "analyst",
        "critic",
        "analyst",
        "critic",
        "final_validator",
    ]


def test_revision_prompt_reaches_analyst_and_passing_review_skips_revision():
    package = make_package()
    passing_review = valid_review()
    issue = {
        "section": "remediation",
        "category": "completeness",
        "detail": "Remediation does not mention the KEV required action.",
        "evidence_ids": ["EV-0004"],
    }
    failing_review = valid_review(completeness="fail", issues=[issue])
    client = SequenceQwen(
        [valid_payload(), failing_review, valid_payload(), passing_review]
    )
    workflow = InvestigationWorkflow(
        evidence=FixedEvidence(package),
        analyst=AnalystAgent(client=client),
        critic=CriticAgent(client=client),
    )
    result = workflow.run(InvestigateRequest(query=f"Investigate {CVE_ID}"))
    assert len(client.calls) == 4
    assert issue["detail"] in client.calls[2][1]
    assert "previous_draft" in client.calls[2][1]
    assert result["review"].completeness == "pass"
    assert result["report"].status == "completed"
    assert [call.stage for call in result["model_calls"]] == [
        "analyst",
        "critic",
        "analyst",
        "critic",
    ]


def test_revision_failure_falls_back_to_deterministic_draft():
    package = make_package()
    issue = {
        "section": "summary",
        "category": "support",
        "detail": "The summary overstates the supplied evidence.",
        "evidence_ids": ["EV-0001"],
    }
    failing_review = valid_review(support="fail", issues=[issue])
    client = SequenceQwen(
        [valid_payload(), failing_review, "not JSON", failing_review]
    )
    workflow = InvestigationWorkflow(
        evidence=FixedEvidence(package),
        analyst=AnalystAgent(client=client),
        critic=CriticAgent(client=client),
    )
    result = workflow.run(InvestigateRequest(query=f"Investigate {CVE_ID}"))
    assert len(client.calls) == 4
    assert "rejected by deterministic validation" in result["draft"].limitations.text
    assert result["report"].status == "partial"


def test_invalid_first_draft_goes_to_revision_even_when_critic_passes():
    package = make_package()
    invalid = valid_payload()
    invalid["cve"]["text"] = "NVD reports CVSS 3.1 score 9.8 (CRITICAL)."
    passing_review = valid_review()
    client = SequenceQwen(
        [invalid, passing_review, valid_payload(), passing_review]
    )
    workflow = InvestigationWorkflow(
        evidence=FixedEvidence(package),
        analyst=AnalystAgent(client=client),
        critic=CriticAgent(client=client),
    )
    result = workflow.run(InvestigateRequest(query=f"Investigate {CVE_ID}"))
    assert len(client.calls) == 4
    assert "CRITIC_REVISION_REQUEST" in client.calls[2][1]
    assert "EVIDENCE_PACKAGE:" in client.calls[2][1]
    assert "failed deterministic validation" in client.calls[2][1]
    assert "unsupported CVSS" in client.calls[2][1]
    assert result["first_draft_invalid"] is True
    assert result["draft_invalid"] is False
    assert result["revised"] is True
    assert result["report"].status == "completed"
    assert [call.stage for call in result["model_calls"]] == [
        "analyst",
        "critic",
        "analyst",
        "critic",
    ]


def test_failed_second_review_with_invalid_original_uses_deterministic_fallback():
    package = make_package()
    invalid = valid_payload()
    invalid["cve"]["text"] = "NVD reports CVSS 3.1 score 9.8 (CRITICAL)."
    issue = {
        "section": "summary",
        "category": "support",
        "detail": "The summary overstates the supplied evidence.",
        "evidence_ids": ["EV-0001"],
    }
    failing_review = valid_review(support="fail", issues=[issue])
    client = SequenceQwen([invalid, failing_review, valid_payload(), "not JSON", "not JSON"])
    workflow = InvestigationWorkflow(
        evidence=FixedEvidence(package),
        analyst=AnalystAgent(client=client),
        critic=CriticAgent(client=client),
    )
    result = workflow.run(InvestigateRequest(query=f"Investigate {CVE_ID}"))
    assert len(client.calls) == 5
    assert result["revision_review_failed"] is True
    assert result["review"] is None
    assert "rejected by deterministic validation" in result["draft"].limitations.text
    assert result["report"].status == "partial"
    assert result["report"].risk.tier == "critical"


def test_failed_second_review_reverts_to_original_draft_with_first_review():
    package = make_package()
    original = valid_payload()
    issue = {
        "section": "summary",
        "category": "support",
        "detail": "The summary overstates the supplied evidence.",
        "evidence_ids": ["EV-0001"],
    }
    failing_review = valid_review(support="fail", issues=[issue])
    revised = valid_payload()
    revised["summary"]["text"] = "CVE-2021-44228 affects Apache Log4j2."
    client = SequenceQwen(
        [original, failing_review, revised, "not JSON", "not JSON"]
    )
    workflow = InvestigationWorkflow(
        evidence=FixedEvidence(package),
        analyst=AnalystAgent(client=client),
        critic=CriticAgent(client=client),
    )
    result = workflow.run(InvestigateRequest(query=f"Investigate {CVE_ID}"))
    assert len(client.calls) == 5
    assert result["revision_review_failed"] is True
    assert result["draft"].summary.text == original["summary"]["text"]
    assert result["review"].support == "fail"
    assert result["report"].status == "partial"
    assert "Critic finding (summary/support)" in result["report"].limitations[-1]


def test_critic_flags_missing_user_inquiry_facets():
    from app.analyst import ensure_requested_facets
    from app.contracts import CriticReview
    from app.critic import add_deterministic_inquiry_findings, derive_statuses
    package = make_package()
    draft = make_draft()
    draft = draft.model_copy(
        update={
            "summary": draft.summary.model_copy(
                update={"text": "This is a generic vulnerability description."}
            )
        }
    )
    passing_review = CriticReview(
        cve_id=package.cve_id,
        support="pass",
        completeness="pass",
        citations="pass",
        uncertainty="pass",
        checked_sections=list(SECTION_NAMES),
        issues=[],
    )
    user_query = "Investigate CVE-2024-1709: explain severity, KEV status, and admin setup bypass."
    audited = add_deterministic_inquiry_findings(passing_review, draft, user_query=user_query)
    audited = derive_statuses(audited)
    assert audited.completeness == "fail"
    assert len(audited.issues) >= 1
    issue = audited.issues[0]
    assert issue.section == "summary"
    assert issue.category == "completeness"
    assert "inquiry facet" in issue.detail

    # The Analyst repairs exactly the summary this finding is about, so the same review
    # passes once the repair has run: one table decides the question on both sides.
    repaired = ensure_requested_facets(package, user_query, draft)
    repaired_audit = add_deterministic_inquiry_findings(
        passing_review, repaired, user_query=user_query
    )
    assert derive_statuses(repaired_audit).completeness == "pass"
    assert repaired_audit.issues == []


def test_model_summary_completeness_finding_follows_the_deterministic_table():
    from app.contracts import CriticReview
    from app.critic import add_deterministic_inquiry_findings, derive_statuses
    package = make_package()
    user_query = f"Investigate {CVE_ID}: explain the severity and exploitation status."
    contradicting = CriticReview(
        cve_id=CVE_ID,
        support="pass",
        completeness="fail",
        citations="pass",
        uncertainty="pass",
        checked_sections=list(SECTION_NAMES),
        issues=[
            {
                "section": "summary",
                "category": "completeness",
                "detail": "Summary does not address exploitation status or root cause.",
                "evidence_ids": [],
            }
        ],
    )
    answered = make_draft()
    audited = add_deterministic_inquiry_findings(
        contradicting, answered, user_query=user_query
    )
    assert audited.issues == []
    assert derive_statuses(audited).completeness == "pass"

    thin = answered.model_copy(
        update={"summary": answered.summary.model_copy(update={"text": f"{CVE_ID} is serious."})}
    )
    audited = add_deterministic_inquiry_findings(contradicting, thin, user_query=user_query)
    assert len(audited.issues) == 1
    assert "inquiry facet" in audited.issues[0].detail
    assert "severity" in audited.issues[0].detail

