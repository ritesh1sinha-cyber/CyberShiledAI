from __future__ import annotations

import re
from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CVE_PATTERN = r"^CVE-\d{4}-\d{4,}$"
TECHNIQUE_PATTERN = r"^T\d{4}(?:\.\d{3})?$"
EVIDENCE_PATTERN = r"^EV-\d{4}$"
URL_PATTERN = r"^https?://\S+$"

Severity = Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
CvssVersion = Literal["4.0", "3.1", "3.0", "2.0"]
EvidenceSource = Literal["NVD", "CISA_KEV", "ATTACK", "OWASP", "NIST", "CWE", "NVD_REF"]
RiskTier = Literal["critical", "high", "medium", "low", "unknown"]
ReportSection = Literal[
    "summary",
    "cve",
    "affected_products",
    "kev",
    "attack_mapping",
    "remediation",
    "risk",
    "limitations",
]
ReviewStatus = Literal["pass", "fail"]
CriticCategory = Literal["support", "completeness", "citation", "uncertainty"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConversationTurn(Strict):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=1600)

    @field_validator("content")
    @classmethod
    def content_not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("conversation content must not be blank")
        return value


class InvestigateRequest(Strict):
    query: str = Field(min_length=3, max_length=500)
    include_attack: bool = True
    top_k: int = Field(default=8, ge=1, le=20)
    conversation_context: list[ConversationTurn] = Field(default_factory=list, max_length=8)
    web_fallback_approved: bool = False

    @field_validator("query")
    @classmethod
    def not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("query must not be blank")
        return value


class CveFacts(Strict):
    cve_id: str = Field(pattern=CVE_PATTERN)
    description: str | None = None
    cvss_version: CvssVersion | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    severity: Severity | None = None
    cvss_vector: str | None = None
    cvss_source: Literal["nvd", "cna"] | None = None
    published: date | None = None
    last_modified: datetime | None = None
    cwe: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def cvss_fields_consistent(self) -> CveFacts:
        present = [
            self.cvss_version is not None,
            self.cvss_score is not None,
            self.severity is not None,
        ]
        if any(present) and not all(present):
            raise ValueError("cvss_version, cvss_score and severity are all-or-nothing")
        return self


class KevStatus(Strict):
    status: Literal["known_exploited", "not_listed", "unknown"]
    catalog_version: str
    checked_at: datetime
    date_added: date | None = None
    due_date: date | None = None
    required_action: str | None = None
    ransomware_use: bool | None = None

    @model_validator(mode="after")
    def listed_requires_date(self) -> KevStatus:
        if self.status == "known_exploited" and self.date_added is None:
            raise ValueError("known_exploited requires date_added")
        if self.status != "known_exploited" and self.date_added is not None:
            raise ValueError("date_added is only valid for known_exploited")
        return self


class Evidence(Strict):
    evidence_id: str = Field(pattern=EVIDENCE_PATTERN)
    claim_type: Literal[
        "cve_description",
        "cvss",
        "kev",
        "affected_product",
        "attack",
        "remediation",
        "risk",
    ]
    claim: str = Field(min_length=1)
    source: EvidenceSource
    source_record_id: str = Field(min_length=1)
    source_url: str = Field(pattern=URL_PATTERN)
    retrieved_at: datetime
    source_updated_at: datetime | None = None
    validation_status: Literal["verified", "retrieved", "analytical", "unverified"]


class AttackMapping(Strict):
    technique_id: str = Field(pattern=TECHNIQUE_PATTERN)
    name: str = Field(min_length=1)
    basis: Literal["curated", "source_reference"]
    evidence_id: str = Field(pattern=EVIDENCE_PATTERN)
    confidence: Literal["low", "medium", "high"]


class RemediationItem(Strict):
    text: str = Field(min_length=1)
    evidence_ids: list[str] = Field(min_length=1)

    @field_validator("evidence_ids")
    @classmethod
    def valid_ids(cls, values: list[str]) -> list[str]:
        for value in values:
            if not re.fullmatch(EVIDENCE_PATTERN, value):
                raise ValueError(f"invalid evidence id: {value}")
        return values


class RiskAssessment(Strict):
    tier: RiskTier = "unknown"
    drivers: list[str] = Field(default_factory=list)
    rationale: str = ""
    evidence_ids: list[str] = Field(default_factory=list)

    @field_validator("evidence_ids")
    @classmethod
    def valid_unique_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("risk evidence ids must be unique")
        for value in values:
            if not re.fullmatch(EVIDENCE_PATTERN, value):
                raise ValueError(f"invalid evidence id: {value}")
        return values


class Citation(Strict):
    evidence_id: str = Field(pattern=EVIDENCE_PATTERN)
    source: EvidenceSource
    source_url: str = Field(pattern=URL_PATTERN)


class AnalystSection(Strict):
    text: str | None = Field(default=None, min_length=1, max_length=1600)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("text")
    @classmethod
    def not_blank(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("section text must not be blank")
        return value

    @field_validator("evidence_ids")
    @classmethod
    def valid_unique_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("section evidence ids must be unique")
        for value in values:
            if not re.fullmatch(EVIDENCE_PATTERN, value):
                raise ValueError(f"invalid evidence id: {value}")
        return values

    @model_validator(mode="after")
    def unknown_has_no_citations(self) -> AnalystSection:
        if self.text is None and self.evidence_ids:
            raise ValueError("an unknown section cannot cite evidence")
        return self


class AnalystDraft(Strict):
    cve_id: str = Field(pattern=CVE_PATTERN)
    summary: AnalystSection
    cve: AnalystSection
    affected_products: AnalystSection
    kev: AnalystSection
    attack_mapping: AnalystSection
    remediation: AnalystSection
    risk: AnalystSection
    limitations: AnalystSection


class CriticIssue(Strict):
    section: ReportSection
    category: CriticCategory
    detail: str = Field(min_length=1, max_length=240)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("detail")
    @classmethod
    def not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("issue detail must not be blank")
        return value

    @field_validator("evidence_ids")
    @classmethod
    def valid_unique_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("issue evidence ids must be unique")
        for value in values:
            if not re.fullmatch(EVIDENCE_PATTERN, value):
                raise ValueError(f"invalid evidence id: {value}")
        return values


class CriticReview(Strict):
    cve_id: str = Field(pattern=CVE_PATTERN)
    support: ReviewStatus
    completeness: ReviewStatus
    citations: ReviewStatus
    uncertainty: ReviewStatus
    checked_sections: list[ReportSection] = Field(min_length=8, max_length=8)
    issues: list[CriticIssue] = Field(default_factory=list, max_length=3)


class Report(Strict):
    request_id: str = Field(pattern=r"^CS-\d{4,}$")
    status: Literal["completed", "partial", "refused", "failed"]
    summary: str
    summary_evidence_ids: list[str] = Field(default_factory=list)
    cve: CveFacts | None = None
    affected_products: list[str] = Field(default_factory=list)
    kev: KevStatus | None = None
    attack_mapping: list[AttackMapping] = Field(default_factory=list)
    remediation: list[RemediationItem] = Field(default_factory=list)
    risk: RiskAssessment = Field(default_factory=RiskAssessment)
    limitations: list[str] = Field(default_factory=list)
    citations: list[Citation] = Field(default_factory=list)
    generated_at: datetime

    @field_validator("summary_evidence_ids")
    @classmethod
    def valid_unique_summary_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("summary evidence ids must be unique")
        for value in values:
            if not re.fullmatch(EVIDENCE_PATTERN, value):
                raise ValueError(f"invalid evidence id: {value}")
        return values


class StageTiming(Strict):
    stage: str = Field(min_length=1)
    ms: int = Field(ge=0)


class ModelCallTrace(Strict):
    stage: str = Field(min_length=1)
    model: str = Field(min_length=1)
    latency_ms: int = Field(ge=0)
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    finish_reason: str | None = None
    max_tokens: int | None = Field(default=None, ge=1, le=1024)


class RetrievedContext(Strict):
    evidence_id: str = Field(pattern=EVIDENCE_PATTERN)
    chunk_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    text: str = Field(min_length=1)
    score: float


class EvidencePackage(Strict):
    cve_id: str = Field(pattern=CVE_PATTERN)
    cve: CveFacts | None = None
    affected_products: list[str] = Field(default_factory=list)
    kev: KevStatus
    attack_mapping: list[AttackMapping] = Field(default_factory=list)
    contexts: list[RetrievedContext] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    citations: list[Citation] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    timings: list[StageTiming] = Field(default_factory=list)

    @model_validator(mode="after")
    def evidence_references_resolve(self) -> EvidencePackage:
        evidence_ids = [item.evidence_id for item in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence ids must be unique")
        known_ids = set(evidence_ids)
        referenced_ids = [item.evidence_id for item in self.attack_mapping]
        referenced_ids.extend(item.evidence_id for item in self.contexts)
        if not set(referenced_ids).issubset(known_ids):
            raise ValueError("all evidence references must resolve")
        citations = {item.evidence_id: item for item in self.citations}
        if len(citations) != len(self.citations) or set(citations) != known_ids:
            raise ValueError("each evidence item requires exactly one citation")
        by_id = {item.evidence_id: item for item in self.evidence}
        for evidence_id, citation in citations.items():
            evidence = by_id[evidence_id]
            if (citation.source, citation.source_url) != (
                evidence.source,
                evidence.source_url,
            ):
                raise ValueError("citation must match its evidence source")
        return self


class InvestigateResponse(Strict):
    report: Report
    trace_id: str = Field(min_length=1)
    timings: list[StageTiming] = Field(default_factory=list)
    critic_review: CriticReview | None = None
    revised: bool = False


class HistoryEntry(Strict):
    trace_id: str = Field(pattern=r"^CS-\d{4,}$")
    request_id: str = Field(pattern=r"^CS-\d{4,}$")
    status: Literal["completed", "partial", "refused", "failed"]
    query: str
    summary: str
    generated_at: datetime
    total_ms: int = Field(ge=0)
    embeddings_model: str | None = None
    index_chunks_sha256: str | None = None


class HealthResponse(Strict):
    status: Literal["ok"] = "ok"
    model: str
    qwen_configured: bool


class TraceDetail(Strict):
    """What one stored investigation actually read: the evidence records, the
    retrieved paragraphs behind them, and which report sections used each."""

    request_id: str = Field(pattern=r"^CS-\d{4,}$")
    queries: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    contexts: list[RetrievedContext] = Field(default_factory=list)
    used_by: dict[str, list[str]] = Field(default_factory=dict)
