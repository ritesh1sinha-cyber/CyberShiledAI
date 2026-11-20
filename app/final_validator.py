from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from app.analyst import AnalystError, validate_draft
from app.config import settings
from app.contracts import (
    AnalystDraft,
    CriticReview,
    EvidencePackage,
    RemediationItem,
    Report,
    RiskAssessment,
    StageTiming,
)
from app.critic import CriticError, validate_review

SUMMARY_UNAVAILABLE = "Summary unavailable; see limitations."


class FinalValidationState(TypedDict, total=False):
    package: EvidencePackage
    draft: AnalystDraft
    review: CriticReview | None
    request_id: str | None
    review_unavailable: bool
    generated_at: datetime | None
    report: Report
    timings: list[StageTiming]


class FinalValidationError(RuntimeError):
    pass


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def missing_core_limitations(
    package: EvidencePackage, draft: AnalystDraft
) -> list[str]:
    missing = []
    if package.cve is None:
        missing.append("NVD facts are unavailable.")
    elif package.cve.cvss_score is None:
        missing.append("CVSS score is unavailable; risk tier is unknown.")
    if package.kev.status == "unknown":
        missing.append("CISA KEV status is unknown.")
    if not package.affected_products:
        missing.append("Affected product information is unavailable.")
    if draft.summary.text is None:
        missing.append("Summary content is unavailable.")
    if draft.remediation.text is None:
        missing.append("Remediation guidance is unavailable.")
    return missing


def calculate_risk(package: EvidencePackage, draft: AnalystDraft) -> RiskAssessment:
    score = package.cve.cvss_score if package.cve else None
    kev_listed = package.kev.status == "known_exploited"
    if kev_listed or (score is not None and score >= 9.0):
        tier = "critical"
    elif score is None:
        tier = "unknown"
    elif score >= 7.0:
        tier = "high"
    elif score >= 4.0:
        tier = "medium"
    else:
        tier = "low"

    drivers = []
    required_claim_types = set()
    if package.cve and score is not None:
        drivers.append(
            f"CVSS {package.cve.cvss_version} base score {score:.1f} "
            f"({package.cve.severity})."
        )
        required_claim_types.add("cvss")
    else:
        drivers.append("CVSS score unavailable.")
    if kev_listed:
        drivers.append("CISA KEV status: known_exploited.")
        required_claim_types.add("kev")

    evidence_ids = _unique(
        [
            *draft.risk.evidence_ids,
            *(
                item.evidence_id
                for item in package.evidence
                if item.claim_type in required_claim_types
            ),
        ]
    )
    rationale = draft.risk.text
    if rationale is None:
        if tier == "unknown":
            rationale = "Risk is unknown because the CVSS score is unavailable."
        elif score is None:
            rationale = "Derived from CISA KEV known exploitation; CVSS is unavailable."
        else:
            rationale = "Derived deterministically from the supplied CVSS and CISA KEV facts."
    return RiskAssessment(
        tier=tier,
        drivers=drivers,
        rationale=rationale,
        evidence_ids=evidence_ids,
    )


def validate_citations(report: Report, package: EvidencePackage) -> None:
    expected = {item.evidence_id: item for item in package.citations}
    actual = {item.evidence_id: item for item in report.citations}
    if len(actual) != len(report.citations) or actual != expected:
        raise FinalValidationError("Final report citations must match the evidence package.")
    known_ids = set(expected)
    referenced_ids = [
        *report.summary_evidence_ids,
        *report.risk.evidence_ids,
        *(evidence_id for item in report.remediation for evidence_id in item.evidence_ids),
    ]
    if not set(referenced_ids).issubset(known_ids):
        raise FinalValidationError("Final report contains a dangling evidence reference.")
    if report.summary != SUMMARY_UNAVAILABLE and not report.summary_evidence_ids:
        raise FinalValidationError("Final report summary requires supporting evidence.")
    if report.risk.tier != "unknown" and not report.risk.evidence_ids:
        raise FinalValidationError("Final report risk requires supporting evidence.")


def build_report(
    package: EvidencePackage,
    draft: AnalystDraft,
    review: CriticReview | None,
    request_id: str | None = None,
    generated_at: datetime | None = None,
    review_unavailable: bool = False,
) -> Report:
    try:
        validate_draft(draft, package)
        if review is not None:
            validate_review(review, package, draft)
    except (AnalystError, CriticError) as exc:
        raise FinalValidationError("Draft or review failed final validation.") from exc

    generated_at = generated_at or datetime.now(timezone.utc)
    request_id = request_id or f"CS-{generated_at:%Y%m%d%H%M%S%f}"
    missing = missing_core_limitations(package, draft)
    findings = [
        f"Critic finding ({issue.section}/{issue.category}): {issue.detail}"
        for issue in (review.issues if review is not None else [])
    ]
    used_deterministic_fallback = bool(
        draft.limitations.text
        and "model draft was rejected by deterministic validation" in draft.limitations.text
    )
    review_note = (
        [
            "The Critic review was unavailable, so this draft carries no independent "
            "review findings."
        ]
        if review_unavailable
        else []
    )
    status = (
        "completed"
        if not missing and not findings and not used_deterministic_fallback and not review_unavailable
        else "partial"
    )
    remediation = (
        [RemediationItem(text=draft.remediation.text, evidence_ids=draft.remediation.evidence_ids)]
        if draft.remediation.text is not None
        else []
    )
    report = Report(
        request_id=request_id,
        status=status,
        summary=draft.summary.text or SUMMARY_UNAVAILABLE,
        summary_evidence_ids=draft.summary.evidence_ids,
        cve=package.cve,
        affected_products=package.affected_products,
        kev=package.kev,
        attack_mapping=package.attack_mapping,
        remediation=remediation,
        risk=calculate_risk(package, draft),
        limitations=_unique(
            [
                *package.limitations,
                *([draft.limitations.text] if draft.limitations.text else []),
                *missing,
                *findings,
                *review_note,
            ]
        ),
        citations=package.citations,
        generated_at=generated_at,
    )
    validate_citations(report, package)
    return report


class FinalValidator:
    def __init__(self):
        workflow = StateGraph(FinalValidationState)
        workflow.add_node("final_validator", self.collect)
        workflow.add_edge(START, "final_validator")
        workflow.add_edge("final_validator", END)
        self.graph = workflow.compile()

    def collect(self, state: FinalValidationState) -> FinalValidationState:
        started = time.perf_counter()
        package = EvidencePackage.model_validate(state["package"])
        draft = AnalystDraft.model_validate(state["draft"])
        raw_review = state.get("review")
        review = CriticReview.model_validate(raw_review) if raw_review is not None else None
        report = build_report(
            package,
            draft,
            review,
            request_id=state.get("request_id"),
            generated_at=state.get("generated_at"),
            review_unavailable=bool(state.get("review_unavailable")),
        )
        elapsed_ms = max(0, round((time.perf_counter() - started) * 1000))
        return {
            "report": report,
            "timings": [StageTiming(stage="final_validator", ms=elapsed_ms)],
        }

    def create_report(
        self,
        package: EvidencePackage,
        draft: AnalystDraft,
        review: CriticReview | None,
        request_id: str | None = None,
        generated_at: datetime | None = None,
    ) -> Report:
        result = self.graph.invoke(
            {
                "package": package,
                "draft": draft,
                "review": review,
                "request_id": request_id,
                "generated_at": generated_at,
            },
            config={"recursion_limit": settings.max_steps},
        )
        return result["report"]
