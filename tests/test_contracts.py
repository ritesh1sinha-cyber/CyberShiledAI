from datetime import date, datetime, timezone

import pytest
from pydantic import ValidationError

from app.contracts import (
    CveFacts,
    InvestigateRequest,
    KevStatus,
    RemediationItem,
    Report,
)

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)


def test_request_accepts_sentence_with_cve():
    req = InvestigateRequest(query="Investigate CVE-2021-44228")
    assert req.top_k == 8


def test_request_rejects_blank_and_overlong():
    with pytest.raises(ValidationError):
        InvestigateRequest(query="   ")
    with pytest.raises(ValidationError):
        InvestigateRequest(query="x" * 501)


@pytest.mark.parametrize("bad", ["CVE-21-1", "cve-2021-44228", "CVE-2021-12"])
def test_cve_pattern_rejects_malformed(bad):
    with pytest.raises(ValidationError):
        CveFacts(cve_id=bad)


def test_cvss_fields_are_all_or_nothing():
    with pytest.raises(ValidationError):
        CveFacts(cve_id="CVE-2021-44228", cvss_score=10.0)
    facts = CveFacts(
        cve_id="CVE-2021-44228",
        cvss_version="3.1",
        cvss_score=10.0,
        severity="CRITICAL",
    )
    assert facts.severity == "CRITICAL"


def test_zero_score_is_distinguishable_from_unknown():
    zero = CveFacts(
        cve_id="CVE-2021-44228", cvss_version="3.1", cvss_score=0.0, severity="NONE"
    )
    unknown = CveFacts(cve_id="CVE-2021-44228")
    assert zero.cvss_score == 0.0
    assert unknown.cvss_score is None


def test_kev_listed_requires_date():
    with pytest.raises(ValidationError):
        KevStatus(status="known_exploited", catalog_version="2026.11.04", checked_at=NOW)
    listed = KevStatus(
        status="known_exploited",
        catalog_version="2026.11.04",
        checked_at=NOW,
        date_added=date(2021, 12, 10),
    )
    assert listed.status == "known_exploited"


def test_kev_not_listed_must_not_carry_date():
    with pytest.raises(ValidationError):
        KevStatus(
            status="not_listed",
            catalog_version="2026.11.04",
            checked_at=NOW,
            date_added=date(2021, 12, 10),
        )


def test_remediation_requires_valid_evidence_ids():
    with pytest.raises(ValidationError):
        RemediationItem(text="Patch log4j", evidence_ids=[])
    with pytest.raises(ValidationError):
        RemediationItem(text="Patch log4j", evidence_ids=["EV-1"])
    assert RemediationItem(text="Patch log4j", evidence_ids=["EV-0001", "EV-0002"])


def test_unknown_cvss_serialises_as_null_not_zero():
    report = Report(
        request_id="CS-1001",
        status="partial",
        summary="NVD unavailable.",
        cve=CveFacts(cve_id="CVE-2021-44228"),
        generated_at=NOW,
    )
    dumped = report.model_dump(mode="json")
    assert dumped["cve"]["cvss_score"] is None
    assert dumped["cve"]["severity"] is None
    assert dumped["risk"]["tier"] == "unknown"


def test_extra_fields_are_rejected():
    with pytest.raises(ValidationError):
        InvestigateRequest(query="Investigate CVE-2021-44228", unexpected=True)
