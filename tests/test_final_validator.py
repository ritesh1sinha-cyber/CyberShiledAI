from datetime import datetime, timezone

import pytest
from test_analyst import CVE_ID, make_package
from test_critic import make_draft, valid_review

from app.contracts import CriticReview
from app.final_validator import (
    FinalValidationError,
    FinalValidator,
    build_report,
    calculate_risk,
    validate_citations,
)

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)


def passed_review():
    return CriticReview.model_validate(valid_review())


def test_final_validator_assembles_completed_report_and_trace():
    result = FinalValidator().graph.invoke(
        {
            "package": make_package(),
            "draft": make_draft(),
            "review": passed_review(),
            "request_id": "CS-1001",
            "generated_at": NOW,
        }
    )
    report = result["report"]
    assert report.request_id == "CS-1001"
    assert report.status == "completed"
    assert report.cve.cve_id == CVE_ID
    assert report.summary_evidence_ids == ["EV-0001", "EV-0002", "EV-0003"]
    assert report.remediation[0].evidence_ids == ["EV-0003", "EV-0005"]
    assert report.risk.tier == "critical"
    assert report.risk.evidence_ids == ["EV-0002", "EV-0003"]
    assert report.generated_at == NOW
    assert result["timings"][0].stage == "final_validator"
    assert "model_calls" not in result


@pytest.mark.parametrize(
    ("score", "severity", "kev_status", "expected"),
    [
        (10.0, "CRITICAL", "known_exploited", "critical"),
        (8.8, "HIGH", "known_exploited", "critical"),
        (9.0, "CRITICAL", "not_listed", "critical"),
        (7.0, "HIGH", "not_listed", "high"),
        (6.9, "MEDIUM", "not_listed", "medium"),
        (0.0, "NONE", "not_listed", "low"),
        (None, None, "known_exploited", "critical"),
        (None, None, "not_listed", "unknown"),
    ],
)
def test_risk_tier_follows_frozen_rules(score, severity, kev_status, expected):
    package = make_package()
    cve = package.cve.model_copy(
        update={"cvss_score": score, "severity": severity}
    )
    kev = package.kev.model_copy(
        update={
            "status": kev_status,
            "date_added": package.kev.date_added if kev_status == "known_exploited" else None,
        }
    )
    package = make_package(cve=cve, kev=kev)
    risk = calculate_risk(package, make_draft())
    assert risk.tier == expected


def test_risk_adds_required_kev_citation_for_critical_tier():
    draft = make_draft(risk={"evidence_ids": ["EV-0002"]})
    report = build_report(
        make_package(), draft, passed_review(), request_id="CS-1002", generated_at=NOW
    )
    assert report.risk.evidence_ids == ["EV-0002", "EV-0003"]
    assert "CISA KEV status: known_exploited." in report.risk.drivers


def test_critic_finding_produces_partial_report_with_visible_limitation():
    review = CriticReview.model_validate(
        valid_review(
            support="fail",
            issues=[
                {
                    "section": "summary",
                    "category": "support",
                    "detail": "The summary overstates the supplied evidence.",
                    "evidence_ids": ["EV-0001"],
                }
            ],
        )
    )
    report = build_report(
        make_package(), make_draft(), review, request_id="CS-1003", generated_at=NOW
    )
    assert report.status == "partial"
    assert "Critic finding (summary/support)" in report.limitations[-1]


def test_missing_core_fact_produces_partial_report_without_hiding_unknown():
    package = make_package(affected_products=[])
    draft = make_draft(affected_products={"text": None, "evidence_ids": []})
    report = build_report(
        package, draft, passed_review(), request_id="CS-1004", generated_at=NOW
    )
    assert report.status == "partial"
    assert report.affected_products == []
    assert "Affected product information is unavailable." in report.limitations


def test_dangling_final_summary_reference_is_rejected():
    report = build_report(
        make_package(), make_draft(), passed_review(), request_id="CS-1005", generated_at=NOW
    )
    report = report.model_copy(update={"summary_evidence_ids": ["EV-9999"]})
    with pytest.raises(FinalValidationError, match="dangling evidence"):
        validate_citations(report, make_package())


def test_citation_set_cannot_drop_or_change_evidence_sources():
    report = build_report(
        make_package(), make_draft(), passed_review(), request_id="CS-1006", generated_at=NOW
    )
    report = report.model_copy(update={"citations": report.citations[:-1]})
    with pytest.raises(FinalValidationError, match="must match"):
        validate_citations(report, make_package())


def test_final_validator_rechecks_model_owned_risk_boundary():
    draft = make_draft(risk={"text": "Risk tier: critical."})
    with pytest.raises(FinalValidationError, match="failed final validation"):
        build_report(
            make_package(), draft, passed_review(), request_id="CS-1007", generated_at=NOW
        )


def test_final_validator_rechecks_review_contract():
    review = passed_review().model_copy(update={"checked_sections": ["summary"]})
    with pytest.raises(FinalValidationError, match="failed final validation"):
        build_report(
            make_package(), make_draft(), review, request_id="CS-1008", generated_at=NOW
        )
