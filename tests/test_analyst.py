import json
from datetime import date, datetime, timezone

import pytest
from pydantic import ValidationError

from app.analyst import (
    MAX_SECTION_CITATIONS,
    SECTION_NAMES,
    AnalystAgent,
    AnalystError,
    build_deterministic_draft,
    build_revision_prompt,
    build_user_prompt,
    cap_citations,
    ensure_requested_facets,
    missing_inquiry_facets,
    section_evidence_ids,
    validate_draft,
)
from app.contracts import (
    AttackMapping,
    AnalystDraft,
    AnalystSection,
    Citation,
    CveFacts,
    Evidence,
    EvidencePackage,
    InvestigateRequest,
    KevStatus,
    RetrievedContext,
    StageTiming,
)
from app.critic import CriticError
from app.qwen import QwenResponse
from app.workflow import InvestigationWorkflow

CVE_ID = "CVE-2021-44228"
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)


def make_package(**overrides):
    rows = [
        Evidence(
            evidence_id="EV-0001",
            claim_type="cve_description",
            claim="Apache Log4j2 JNDI remote code execution.",
            source="NVD",
            source_record_id=CVE_ID,
            source_url=f"https://nvd.nist.gov/vuln/detail/{CVE_ID}",
            retrieved_at=NOW,
            validation_status="verified",
        ),
        Evidence(
            evidence_id="EV-0002",
            claim_type="cvss",
            claim="NVD reports CVSS 3.1 base score 10.0 (CRITICAL).",
            source="NVD",
            source_record_id=CVE_ID,
            source_url=f"https://nvd.nist.gov/vuln/detail/{CVE_ID}",
            retrieved_at=NOW,
            validation_status="verified",
        ),
        Evidence(
            evidence_id="EV-0003",
            claim_type="kev",
            claim=f"{CVE_ID} is listed in CISA KEV as known exploited.",
            source="CISA_KEV",
            source_record_id=CVE_ID,
            source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            retrieved_at=NOW,
            validation_status="verified",
        ),
        Evidence(
            evidence_id="EV-0004",
            claim_type="affected_product",
            claim="Affected product: Apache Log4j2.",
            source="CISA_KEV",
            source_record_id=CVE_ID,
            source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            retrieved_at=NOW,
            validation_status="verified",
        ),
        Evidence(
            evidence_id="EV-0005",
            claim_type="remediation",
            claim="Retrieved passage CWE-917#000 from CWE-917.",
            source="CWE",
            source_record_id="CWE-917#000",
            source_url="https://cwe.mitre.org/data/definitions/917.html",
            retrieved_at=NOW,
            validation_status="retrieved",
        ),
        Evidence(
            evidence_id="EV-0006",
            claim_type="attack",
            claim=f"T1190 Exploit Public-Facing Application explicitly references {CVE_ID}.",
            source="ATTACK",
            source_record_id="T1190",
            source_url="https://attack.mitre.org/techniques/T1190",
            retrieved_at=NOW,
            validation_status="verified",
        ),
    ]
    package = EvidencePackage(
        cve_id=CVE_ID,
        cve=CveFacts(
            cve_id=CVE_ID,
            description="Apache Log4j2 JNDI remote code execution.",
            cvss_version="3.1",
            cvss_score=10.0,
            severity="CRITICAL",
            cvss_vector="CVSS:3.1/AV:N/AC:L",
            cvss_source="nvd",
            published=date(2021, 12, 10),
        ),
        affected_products=["Apache Log4j2"],
        kev=KevStatus(
            status="known_exploited",
            catalog_version="2026.11.04",
            checked_at=NOW,
            date_added=date(2021, 12, 10),
            required_action="Apply updates per vendor instructions.",
        ),
        attack_mapping=[
            AttackMapping(
                technique_id="T1190",
                name="Exploit Public-Facing Application",
                basis="source_reference",
                evidence_id="EV-0006",
                confidence="high",
            )
        ],
        contexts=[
            RetrievedContext(
                evidence_id="EV-0005",
                chunk_id="CWE-917#000",
                title="CWE-917 Improper Neutralization",
                text="Avoid evaluating untrusted input and apply the documented mitigations.",
                score=0.025,
            )
        ],
        evidence=rows,
        citations=[
            Citation(
                evidence_id=item.evidence_id,
                source=item.source,
                source_url=item.source_url,
            )
            for item in rows
        ],
        limitations=["Retrieved passages are ranked context, not independently verified facts."],
        timings=[StageTiming(stage="evidence", ms=20)],
    )
    return package.model_copy(update=overrides)


def section(text, *evidence_ids):
    return {"text": text, "evidence_ids": list(evidence_ids)}


def valid_payload():
    return {
        "cve_id": CVE_ID,
        "summary": section(
            f"{CVE_ID} is CRITICAL with CVSS 3.1 score 10.0 and confirmed exploitation.",
            "EV-0001",
            "EV-0002",
            "EV-0003",
        ),
        "cve": section(
            "NVD describes JNDI remote code execution and reports CVSS 3.1 score 10.0 (CRITICAL).",
            "EV-0001",
            "EV-0002",
        ),
        "affected_products": section("The affected product is Apache Log4j2.", "EV-0004"),
        "kev": section("CISA KEV lists the CVE as known exploited.", "EV-0003"),
        "attack_mapping": section(
            "T1190 Exploit Public-Facing Application explicitly references this CVE.",
            "EV-0006",
        ),
        "remediation": section(
            "Apply the CISA required action and follow the retrieved CWE guidance.",
            "EV-0003",
            "EV-0005",
        ),
        "risk": section(
            "CVSS 10.0 and confirmed exploitation increase urgency; no tier is assigned.",
            "EV-0002",
            "EV-0003",
        ),
        "limitations": section(
            "Retrieved passages are ranked context, not independently verified facts."
        ),
    }


def assert_draft_rejected(payload, package, match=None):
    draft = AnalystDraft.model_validate(payload)
    if match:
        with pytest.raises(AnalystError, match=match):
            validate_draft(draft, package)
    else:
        with pytest.raises(AnalystError):
            validate_draft(draft, package)


class FakeQwen:
    def __init__(self, payload=None, finish_reason="stop"):
        self.payload = valid_payload() if payload is None else payload
        self.finish_reason = finish_reason
        self.calls = []

    def complete(self, system, user, max_tokens=400):
        self.calls.append((system, user, max_tokens))
        content = self.payload if isinstance(self.payload, str) else json.dumps(self.payload)
        return QwenResponse(
            content=content,
            model="Qwen/Qwen3-8B",
            latency_ms=450,
            prompt_tokens=1800,
            completion_tokens=350,
            finish_reason=self.finish_reason,
        )


class SequenceQwen:
    def __init__(self, payloads):
        self.payloads = list(payloads)
        self.calls = []

    def complete(self, system, user, max_tokens=400):
        self.calls.append((system, user, max_tokens))
        payload = self.payloads.pop(0)
        return QwenResponse(
            content=json.dumps(payload),
            model="Qwen/Qwen3-8B",
            latency_ms=100,
            prompt_tokens=500,
            completion_tokens=100,
            finish_reason="stop",
        )


class FixedEvidence:
    def __init__(self, package):
        self.package = package
        self.calls = 0

    def collect(self, state):
        self.calls += 1
        return {"package": self.package}


class FakeCritic:
    def collect(self, state):
        return {
            "review": {
                "cve_id": state["draft"].cve_id,
                "support": "pass",
                "completeness": "pass",
                "citations": "pass",
                "uncertainty": "pass",
                "checked_sections": list(SECTION_NAMES),
                "issues": [],
            },
            "timings": [StageTiming(stage="critic", ms=0)],
        }


def test_analyst_returns_eight_grounded_sections_and_trace():
    client = FakeQwen()
    result = AnalystAgent(client=client).graph.invoke({"package": make_package()})
    draft = result["draft"]
    assert draft.cve_id == CVE_ID
    assert draft.summary.evidence_ids == ["EV-0001", "EV-0002", "EV-0003"]
    assert draft.attack_mapping.text.startswith("T1190")
    assert result["timings"][0].stage == "analyst"
    assert result["model_calls"][0].stage == "analyst"
    assert result["model_calls"][0].completion_tokens == 350
    assert len(client.calls) == 1
    assert client.calls[0][2] == 1024


def test_prompt_contains_only_request_scoped_facts_and_passages():
    package = make_package()
    prompt = build_user_prompt(package)
    assert CVE_ID in prompt
    assert "Avoid evaluating untrusted input" in prompt
    assert "EV-0005" in prompt
    assert "retrieved" in prompt


@pytest.mark.parametrize("content", ["not JSON", "[]", "{}"])
def test_malformed_or_incomplete_output_uses_deterministic_draft(content):
    agent = AnalystAgent(client=FakeQwen(content))
    draft = agent.create_draft(make_package())
    assert draft.cve_id == CVE_ID
    assert "rejected by deterministic validation" in draft.limitations.text
    assert draft.summary.evidence_ids
    assert draft.remediation.evidence_ids


def test_truncated_output_is_rejected_before_parsing():
    agent = AnalystAgent(client=FakeQwen(finish_reason="length"))
    draft = agent.create_draft(make_package())
    assert "rejected by deterministic validation" in draft.limitations.text
    assert "No verified MITRE ATT&CK" not in draft.limitations.text


def test_fallback_states_empty_attack_mapping_explicitly():
    package = make_package(attack_mapping=[])
    draft = AnalystAgent(client=FakeQwen(finish_reason="length")).create_draft(package)
    assert draft.attack_mapping.text is None
    assert "No verified MITRE ATT&CK technique mapping" in draft.limitations.text


def test_dangling_evidence_id_is_rejected():
    payload = valid_payload()
    payload["summary"]["evidence_ids"] = ["EV-9999"]
    assert_draft_rejected(payload, make_package(), "outside this request")


def test_non_null_material_section_requires_a_citation():
    payload = valid_payload()
    payload["remediation"]["evidence_ids"] = []
    assert_draft_rejected(payload, make_package(), "requires evidence")


def test_wrong_section_evidence_type_is_rejected():
    payload = valid_payload()
    payload["affected_products"]["evidence_ids"] = ["EV-0002"]
    assert_draft_rejected(payload, make_package(), "unsuitable evidence")


def test_remediation_must_cite_kev_required_action():
    payload = valid_payload()
    payload["remediation"]["evidence_ids"] = ["EV-0005"]
    assert_draft_rejected(payload, make_package(), "cite the KEV required action")


@pytest.mark.parametrize(
    ("field", "override"),
    [
        ("cve", {"cve": None}),
        ("affected_products", {"affected_products": []}),
        (
            "kev",
            {
                "kev": KevStatus(
                    status="unknown", catalog_version="2026.11.04", checked_at=NOW
                )
            },
        ),
        ("attack_mapping", {"attack_mapping": []}),
    ],
)
def test_analyst_cannot_fill_in_unavailable_facts(field, override):
    assert_draft_rejected(valid_payload(), make_package(**override))


def test_analyst_cannot_change_cve_identity():
    payload = valid_payload()
    payload["summary"]["text"] = "CVE-2021-45046 has the same issue."
    assert_draft_rejected(payload, make_package(), "unrelated CVE")


def test_analyst_cannot_invent_attack_technique():
    payload = valid_payload()
    payload["attack_mapping"]["text"] = "T1059 also maps to this CVE."
    assert_draft_rejected(payload, make_package(), "unverified ATT&CK technique")


def test_analyst_cannot_change_cvss_score():
    payload = valid_payload()
    payload["cve"]["text"] = "NVD reports CVSS 3.1 score 9.8 (CRITICAL)."
    assert_draft_rejected(payload, make_package(), "unsupported CVSS")


def test_analyst_cannot_choose_risk_tier():
    payload = valid_payload()
    payload["risk"]["text"] = "Risk tier: critical."
    assert_draft_rejected(payload, make_package(), "deterministic risk tier")


def test_revision_prompt_includes_package_and_validation_error():
    draft = AnalystDraft.model_validate(valid_payload())
    issues = [
        {
            "section": "cve",
            "category": "support",
            "detail": "The CVE section changed the reported score.",
            "evidence_ids": ["EV-0002"],
        }
    ]
    prompt = build_revision_prompt(
        make_package(),
        draft,
        issues,
        validation_error="Analyst introduced an unsupported CVSS value.",
    )
    assert "EVIDENCE_PACKAGE:" in prompt
    assert "CRITIC_REVISION_REQUEST" in prompt
    assert "previous_draft_rejected_because" in prompt
    assert "unsupported CVSS" in prompt
    assert "EV-0002" in prompt


def test_parsed_but_invalid_first_draft_is_kept_for_critic_revision():
    payload = valid_payload()
    payload["cve"]["text"] = "NVD reports CVSS 3.1 score 9.8 (CRITICAL)."
    result = AnalystAgent(client=FakeQwen(payload)).graph.invoke(
        {"package": make_package()}
    )
    assert result["draft_invalid"] is True
    assert "unsupported CVSS" in result["draft_invalid_reason"]
    assert "rejected by deterministic validation" not in result["draft"].limitations.text


def test_invalid_revision_output_still_uses_deterministic_draft():
    package = make_package()
    payload = valid_payload()
    payload["cve"]["text"] = "NVD reports CVSS 3.1 score 9.8 (CRITICAL)."
    revision = valid_payload()
    revision["risk"]["text"] = "Risk tier: critical."
    issues = [
        {
            "section": "cve",
            "category": "support",
            "detail": "The CVE section changed the reported score.",
            "evidence_ids": ["EV-0002"],
        }
    ]
    result = AnalystAgent(client=SequenceQwen([payload, revision])).graph.invoke(
        {"package": package, "draft": payload, "critic_issues": issues}
    )
    assert "rejected by deterministic validation" in result["draft"].limitations.text
    assert result.get("draft_invalid") is not True


def test_connected_workflow_runs_answer_agent_without_a_planner_call():
    package = make_package()
    client = SequenceQwen([valid_payload()])
    evidence = FixedEvidence(package)
    workflow = InvestigationWorkflow(
        evidence=evidence,
        analyst=AnalystAgent(client=client),
        critic=FakeCritic(),
    )
    result = workflow.run(InvestigateRequest(query=f"Investigate {CVE_ID}"))
    assert len(client.calls) == 1
    assert "Analyst Agent" in client.calls[0][0]
    assert evidence.calls == 1
    assert result["draft"].cve_id == CVE_ID
    assert result["report"].status == "completed"
    assert result["report"].risk.tier == "critical"
    assert [call.stage for call in result["model_calls"]] == ["analyst"]
    assert [item.stage for item in result["timings"]] == [
        "evidence",
        "analyst",
        "critic",
        "final_validator",
    ]


def wide_package(extra_count: int = 30):
    """Same package as make_package() but with many remediation evidence records."""
    package = make_package()
    template = next(item for item in package.evidence if item.evidence_id == "EV-0005")
    extras = [
        template.model_copy(
            update={
                "evidence_id": f"EV-{index:04d}",
                "source_record_id": f"CWE-917#{index:03d}",
            }
        )
        for index in range(7, 7 + extra_count)
    ]
    rows = [*package.evidence, *extras]
    return package.model_copy(
        update={
            "evidence": rows,
            "citations": [
                Citation(evidence_id=row.evidence_id, source=row.source, source_url=row.source_url)
                for row in rows
            ],
        }
    )


class FailingCritic:
    def __init__(self):
        self.calls = 0

    def collect(self, state):
        self.calls += 1
        raise CriticError("Qwen did not return a valid Critic review.")


def test_cap_citations_keeps_priority_ids_and_invents_nothing():
    ids = [f"EV-{index:04d}" for index in range(30)]
    capped, truncated = cap_citations(ids, priority=["EV-0029", "EV-9999"])
    assert truncated is True
    assert len(capped) == MAX_SECTION_CITATIONS
    assert capped[0] == "EV-0029"
    assert "EV-9999" not in capped


def test_citation_cap_matches_the_section_schema_limit():
    within = [f"EV-{index:04d}" for index in range(MAX_SECTION_CITATIONS)]
    AnalystSection(text="cited", evidence_ids=within)
    with pytest.raises(ValidationError):
        AnalystSection(text="cited", evidence_ids=[*within, "EV-9999"])


def test_deterministic_draft_survives_an_evidence_rich_package():
    package = wide_package()
    draft = build_deterministic_draft(package)
    assert len(draft.remediation.evidence_ids) == MAX_SECTION_CITATIONS
    assert "EV-0003" in draft.remediation.evidence_ids
    assert "EV-0005" in draft.remediation.evidence_ids
    assert "citation lists were limited" in draft.limitations.text
    validate_draft(draft, package)


def test_first_critic_review_failure_still_ships_a_report():
    package = make_package()
    client = SequenceQwen([valid_payload()])
    critic = FailingCritic()
    workflow = InvestigationWorkflow(
        evidence=FixedEvidence(package),
        analyst=AnalystAgent(client=client),
        critic=critic,
    )
    result = workflow.run(InvestigateRequest(query=f"Investigate {CVE_ID}"))
    assert critic.calls == 2
    assert result["first_review_failed"] is True
    assert result["review"] is None
    assert result["report"].status == "partial"
    assert "Critic review was unavailable" in " ".join(result["report"].limitations)


def test_the_prompt_lists_the_evidence_ids_each_section_may_cite():
    allowed = section_evidence_ids(make_package())
    assert allowed["affected_products"] == ["EV-0004"]
    assert allowed["risk"] == ["EV-0002", "EV-0003"]
    assert allowed["attack_mapping"] == ["EV-0006"]
    assert allowed["limitations"] == []
    listed = json.loads(
        build_user_prompt(make_package(), user_query="q").split("EVIDENCE_PACKAGE:\n", 1)[1]
    )["section_evidence_ids"]
    assert listed == allowed


def test_every_listed_id_is_one_the_validator_accepts_for_that_section():
    package = make_package()
    draft = AnalystDraft.model_validate(valid_payload())
    for name, ids in section_evidence_ids(package).items():
        if not ids:
            continue
        candidate = draft.model_copy(
            update={
                name: AnalystSection(
                    text=getattr(draft, name).text, evidence_ids=ids
                )
            }
        )
        validate_draft(candidate, package)


INQUIRY = (
    f"Investigate {CVE_ID}: explain the vulnerability, technical mechanism, affected "
    "products and prerequisites, severity, exploitation status, weakness and remediation."
)


def test_the_summary_is_repaired_to_answer_what_was_asked():
    package = make_package()
    draft = AnalystDraft.model_validate(valid_payload())
    thin = draft.model_copy(
        update={
            "summary": AnalystSection(
                text=f"{CVE_ID} is a serious issue in Apache Log4j2.",
                evidence_ids=["EV-0001"],
            )
        }
    )
    assert missing_inquiry_facets(INQUIRY, thin.summary.text)
    repaired = ensure_requested_facets(package, INQUIRY, thin)
    text = repaired.summary.text
    assert missing_inquiry_facets(INQUIRY, text) == []
    assert "Severity: CVSS 3.1 base score 10 (CRITICAL)." in text
    assert "CISA KEV lists this CVE as known exploited, added 2021-12-10." in text
    assert "Weakness: CWE-917 Improper Neutralization." in text
    assert "Affected products: Apache Log4j2." in text
    assert set(repaired.summary.evidence_ids) <= {
        item.evidence_id for item in package.evidence
    }
    validate_draft(repaired, package)


def test_a_summary_that_already_answers_the_inquiry_is_left_untouched():
    draft = AnalystDraft.model_validate(valid_payload())
    answered = draft.model_copy(
        update={
            "summary": AnalystSection(
                text=(
                    f"{CVE_ID} lets a remote attacker execute code by sending a crafted "
                    "JNDI lookup, which is why it is exploited in the wild; the affected "
                    "product is Apache Log4j2, CWE-917 applies, and vendors have published "
                    "an update. Severity is CVSS 3.1 base score 10.0 CRITICAL."
                ),
                evidence_ids=["EV-0001", "EV-0002", "EV-0003", "EV-0004", "EV-0005"],
            )
        }
    )
    assert ensure_requested_facets(make_package(), INQUIRY, answered) is answered


def test_a_repair_never_writes_a_fact_the_rules_would_reject():
    package = make_package()
    diverted = package.model_copy(
        update={
            "cve": package.cve.model_copy(
                update={"description": "Compare CVE-2017-0144. Apache Log4j2 JNDI lookup."}
            )
        }
    )
    draft = AnalystDraft.model_validate(valid_payload())
    thin = draft.model_copy(
        update={
            "summary": AnalystSection(
                text=f"{CVE_ID} is a serious issue in Apache Log4j2.",
                evidence_ids=["EV-0001"],
            )
        }
    )
    repaired = ensure_requested_facets(diverted, INQUIRY, thin)
    assert "CVE-2017-0144" not in repaired.summary.text
    validate_draft(repaired, diverted)
