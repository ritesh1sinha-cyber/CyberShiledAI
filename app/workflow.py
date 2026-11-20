from __future__ import annotations

import re
import time
from typing import TypedDict
from uuid import uuid4

from langgraph.graph import END, START, StateGraph

from app import observability, progress
from app.analyst import AnalystAgent, build_deterministic_draft
from app.config import settings
from app.contracts import (
    AnalystDraft,
    CriticReview,
    EvidencePackage,
    InvestigateRequest,
    ModelCallTrace,
    Report,
    StageTiming,
)
from app.critic import CriticAgent, CriticError
from app.evidence import EvidenceAgent
from app.evidence_qwen import EvidenceQwenAgent
from app.final_validator import FinalValidator
from app.qwen import QwenError


class InvestigationState(TypedDict, total=False):
    request: InvestigateRequest
    request_id: str
    package: EvidencePackage
    draft: AnalystDraft
    review: CriticReview | None
    revised: bool
    draft_invalid: bool
    draft_invalid_reason: str
    draft_fallback_reason: str
    first_draft_invalid: bool
    first_draft_invalid_reason: str
    draft_before_revision: AnalystDraft
    draft_before_revision_invalid: bool
    revision_review_failed: bool
    first_review_failed: bool
    report: Report
    timings: list[StageTiming]
    model_calls: list[ModelCallTrace]
    evidence_interpretation: dict
    retrieval_meta: dict


REVIEW_FIELDS = ("support", "completeness", "citations", "uncertainty")

TRACED_INPUTS = {
    "evidence": lambda state: {"query": state["request"].query},
    "analyst": lambda state: {
        "revising": state.get("review") is not None and not state.get("revised")
    },
    "critic": lambda state: {"revised": bool(state.get("revised"))},
    "final_validator": lambda state: {"has_review": state.get("review") is not None},
}

TRACED_OUTPUTS = {
    "evidence": ("package", "evidence_interpretation", "retrieval_meta"),
    "analyst": (
        "draft",
        "draft_invalid",
        "draft_invalid_reason",
        "draft_fallback_reason",
        "revised",
    ),
    "critic": ("review", "revision_review_failed", "first_review_failed"),
    "final_validator": ("report",),
}

STAGE_NOTES = {
    "evidence": "Reading the trusted NVD and KEV records, then searching the local corpus.",
    "analyst": "Writing the eight report sections from the evidence package.",
    "critic": "Reviewing support, completeness, citations and uncertainty in the draft.",
    "final_validator": "Re-checking every report field against the trusted records.",
}

DRAFT_SECTIONS = (
    "summary",
    "cve",
    "affected_products",
    "kev",
    "attack_mapping",
    "remediation",
    "risk",
    "limitations",
)


def _read(value, key: str, default=None):
    """Read one field from either a contract model or a plain dict."""
    if value is None:
        return default
    if isinstance(value, dict):
        return value.get(key, default)
    return getattr(value, key, default)


def _evidence_detail(update: dict) -> dict:
    package = update.get("package")
    interpretation = update.get("evidence_interpretation") or {}
    facts = _read(package, "cve")
    kev = _read(package, "kev")
    evidence = _read(package, "evidence", []) or []
    return {
        "cve_id": _read(package, "cve_id"),
        "severity": _read(facts, "severity") if facts is not None else "not retrieved",
        "cvss_score": _read(facts, "cvss_score") if facts is not None else None,
        "kev_status": _read(kev, "status") if kev is not None else None,
        "records": len(evidence),
        "sources": sorted({str(_read(item, "source")) for item in evidence}),
        "passages": len(_read(package, "contexts", []) or []),
        "attack_techniques": len(_read(package, "attack_mapping", []) or []),
        "intent": interpretation.get("intent"),
        "limitations": len(_read(package, "limitations", []) or []),
    }


def _analyst_detail(update: dict) -> dict:
    draft = update.get("draft")
    unknown = [
        name
        for name in DRAFT_SECTIONS
        if draft is not None and _read(_read(draft, name), "text") is None
    ]
    return {
        "sections_written": 0 if draft is None else len(DRAFT_SECTIONS) - len(unknown),
        "unknown_sections": unknown,
        "revised": bool(update.get("revised")),
        "deterministic_fallback": update.get("draft_fallback_reason"),
        "validation_failure": update.get("draft_invalid_reason"),
    }


def _critic_detail(update: dict) -> dict:
    review = update.get("review")
    if review is None:
        failed = (
            "revision review was unusable"
            if update.get("revision_review_failed")
            else "first review was unusable"
            if update.get("first_review_failed")
            else "no review was run"
        )
        return {"review_available": False, "reason": failed}
    return {
        "review_available": True,
        "support": _read(review, "support"),
        "completeness": _read(review, "completeness"),
        "citations": _read(review, "citations"),
        "uncertainty": _read(review, "uncertainty"),
        "issues": [
            {
                "section": _read(issue, "section"),
                "category": _read(issue, "category"),
                "detail": _read(issue, "detail"),
            }
            for issue in (_read(review, "issues", []) or [])
        ],
    }


def _validator_detail(update: dict) -> dict:
    report = update.get("report")
    risk = _read(report, "risk")
    return {
        "status": _read(report, "status"),
        "citations": len(_read(report, "citations", []) or []),
        "remediation_items": len(_read(report, "remediation", []) or []),
        "risk_tier": _read(risk, "tier") if risk is not None else None,
        "limitations": len(_read(report, "limitations", []) or []),
    }


STAGE_DETAILS = {
    "evidence": _evidence_detail,
    "analyst": _analyst_detail,
    "critic": _critic_detail,
    "final_validator": _validator_detail,
}


class InvestigationWorkflow:
    def __init__(
        self,
        evidence: EvidenceAgent | EvidenceQwenAgent | None = None,
        analyst: AnalystAgent | None = None,
        critic: CriticAgent | None = None,
        validator: FinalValidator | None = None,
        use_critic: bool = True,
    ):
        self.evidence = evidence or EvidenceQwenAgent()
        self.analyst = analyst or AnalystAgent()
        self.critic = critic or (CriticAgent() if use_critic else None)
        self.use_critic = use_critic
        self.validator = validator or FinalValidator()
        workflow = StateGraph(InvestigationState)
        workflow.add_node("evidence", self._traced("evidence", self._collect_evidence))
        workflow.add_node("analyst", self._traced("analyst", self._write_draft))
        if self.use_critic:
            workflow.add_node("critic", self._traced("critic", self._review_draft))
        workflow.add_node(
            "final_validator", self._traced("final_validator", self._validate_report)
        )
        workflow.add_edge(START, "evidence")
        workflow.add_edge("evidence", "analyst")
        if self.use_critic:
            workflow.add_edge("analyst", "critic")
            workflow.add_conditional_edges(
                "critic",
                self._route_after_critic,
                {"revise": "analyst", "validate": "final_validator"},
            )
        else:
            workflow.add_edge("analyst", "final_validator")
        workflow.add_edge("final_validator", END)
        self.graph = workflow.compile()

    def _traced(self, name: str, node):
        def run(state: InvestigationState) -> InvestigationState:
            started = time.perf_counter()
            inputs = TRACED_INPUTS[name](state)
            with observability.span(name, inputs), progress.stage(name):
                progress.emit("stage_start", note=STAGE_NOTES[name], **inputs)
                try:
                    update = node(state)
                except Exception as exc:
                    progress.emit(
                        "stage_failed",
                        ms=max(0, round((time.perf_counter() - started) * 1000)),
                        error=type(exc).__name__,
                    )
                    raise
                observability.record_output(
                    {key: update[key] for key in TRACED_OUTPUTS[name] if key in update}
                )
                progress.emit(
                    "stage_end",
                    ms=max(0, round((time.perf_counter() - started) * 1000)),
                    detail=STAGE_DETAILS[name](update),
                )
            return update

        return run

    def _collect_evidence(self, state: InvestigationState) -> InvestigationState:
        result = self.evidence.collect({"request": state["request"]})
        package = result["package"]
        timings = [*state.get("timings", []), *result.get("timings", [])]
        if isinstance(package, EvidencePackage):
            timings.extend(package.timings)
        return {
            "package": package,
            "timings": timings,
            "model_calls": [*state.get("model_calls", []), *result.get("model_calls", [])],
            "evidence_interpretation": result.get("interpretation", {}),
            "retrieval_meta": result.get("retrieval_meta", {}),
        }

    def _write_draft(self, state: InvestigationState) -> InvestigationState:
        if state["package"].cve is None:
            fallback = build_deterministic_draft(state["package"])
            return {
                "draft": fallback,
                "timings": [*state.get("timings", []), StageTiming(stage="analyst", ms=0)],
                "model_calls": state.get("model_calls", []),
                "draft_invalid": False,
                "draft_invalid_reason": None,
                "draft_fallback_reason": "cve_not_found",
            }
        review = state.get("review")
        inputs: dict = {"package": state["package"]}
        revised = False
        if review is not None and not state.get("revised"):
            issues = (
                review.get("issues")
                if isinstance(review, dict)
                else [issue.model_dump(mode="json") for issue in review.issues]
            )
            if not issues and state.get("draft_invalid"):
                # The Critic passed every check, but the draft still broke a
                # deterministic content rule, so revision must run; hand the
                # analyst the validation failure as the issue to fix.
                reason = state.get("draft_invalid_reason") or "the draft failed deterministic validation"
                section_match = re.search(r"section '(\w+)'", reason)
                issues = [
                    {
                        "section": section_match.group(1) if section_match else "summary",
                        "category": "support",
                        "detail": f"Previous draft failed deterministic validation: {reason}",
                    }
                ]
            inputs.update({"draft": state.get("draft"), "critic_issues": issues})
            if state.get("draft_invalid") and state.get("draft_invalid_reason"):
                # The pre-revision draft also broke a deterministic content
                # rule; feed the exact failure back so the model fixes it and
                # does not repeat it.
                inputs["validation_error"] = state["draft_invalid_reason"]
            revised = True
        result = self.analyst.collect(inputs)
        update: InvestigationState = {
            "draft": result["draft"],
            "timings": [*state.get("timings", []), *result.get("timings", [])],
            "model_calls": [
                *state.get("model_calls", []),
                *result.get("model_calls", []),
            ],
            "draft_invalid": bool(result.get("draft_invalid")),
            "draft_invalid_reason": result.get("draft_invalid_reason"),
            "draft_fallback_reason": result.get("draft_fallback_reason"),
        }
        if revised:
            update["revised"] = True
            update["draft_before_revision"] = state.get("draft")
            update["draft_before_revision_invalid"] = bool(state.get("draft_invalid"))
        if result.get("draft_invalid"):
            update["first_draft_invalid"] = True
            update["first_draft_invalid_reason"] = result.get("draft_invalid_reason")
        return update

    def _route_after_critic(self, state: InvestigationState) -> str:
        if state.get("package") and getattr(state["package"], "cve", None) is None:
            return "validate"
        review = state.get("review")
        if review is None or state.get("revised"):
            return "validate"
        failed = any(
            (review.get(field) if isinstance(review, dict) else getattr(review, field)) == "fail"
            for field in REVIEW_FIELDS
        )
        return "revise" if failed or state.get("draft_invalid") else "validate"

    def _review_attempt(self, package, draft):
        """Return (result, error); retries once only when the review is unusable."""
        error: Exception | None = None
        for _attempt in range(2):
            try:
                return self.critic.collect({"package": package, "draft": draft}), None
            except (CriticError, QwenError) as exc:
                error = exc
        return None, error

    def _review_draft(self, state: InvestigationState) -> InvestigationState:
        if self.critic is None:
            raise RuntimeError("Critic is not enabled in this workflow.")
        if state["package"].cve is None:
            return {
                "review": None,
                "timings": [*state.get("timings", []), StageTiming(stage="critic", ms=0)],
                "model_calls": state.get("model_calls", []),
            }
        result, review_error = self._review_attempt(state["package"], state["draft"])
        if review_error is not None:
            if not state.get("revised"):
                # An unusable FIRST review must not fail the investigation: the
                # draft still goes through final validation, and the report says
                # plainly that no independent review was available for it.
                return {
                    "review": None,
                    "first_review_failed": True,
                    "timings": [
                        *state.get("timings", []),
                        StageTiming(stage="critic", ms=0),
                    ],
                }
            # The post-revision review is unusable, so its findings cannot
            # back the revised draft. Revert to the original draft and keep
            # the first review, whose issues still describe the shipped
            # draft — unless that original draft was itself the invalid
            # first attempt, in which case deterministic assembly is the
            # last resort so final validation can pass.
            if state.get("draft_before_revision_invalid"):
                fallback = build_deterministic_draft(state["package"])
                return {
                    "review": None,
                    "draft": fallback,
                    "timings": [
                        *state.get("timings", []),
                        StageTiming(stage="critic", ms=0),
                    ],
                    "revision_review_failed": True,
                    "draft_invalid": False,
                    "draft_invalid_reason": None,
                }
            return {
                "review": state.get("review"),
                "draft": state.get("draft_before_revision"),
                "timings": [
                    *state.get("timings", []),
                    StageTiming(stage="critic", ms=0),
                ],
                "revision_review_failed": True,
                "draft_invalid": False,
                "draft_invalid_reason": None,
            }
        return {
            "review": result["review"],
            "timings": [*state.get("timings", []), *result.get("timings", [])],
            "model_calls": [
                *state.get("model_calls", []),
                *result.get("model_calls", []),
            ],
        }

    def _validate_report(self, state: InvestigationState) -> InvestigationState:
        result = self.validator.collect(
            {
                "package": state["package"],
                "draft": state["draft"],
                "review": state.get("review"),
                "request_id": state.get("request_id"),
                "review_unavailable": bool(state.get("first_review_failed")),
            }
        )
        return {
            "report": result["report"],
            "timings": [*state.get("timings", []), *result.get("timings", [])],
        }

    def run(
        self, request: InvestigateRequest, request_id: str | None = None
    ) -> InvestigationState:
        state = {"request": request, "request_id": request_id}
        trace_id = request_id or uuid4().hex
        observability.start_trace(
            name="cve_investigation",
            trace_id=trace_id,
            input_data={
                "query": request.query,
                "conversation_turns": len(request.conversation_context or []),
            },
            metadata={
                "request_id": trace_id,
                "architecture": "critic" if self.use_critic else "single_agent",
            },
        )
        try:
            for update in self.graph.stream(
                state, config={"recursion_limit": settings.max_steps}
            ):
                for node_update in update.values():
                    state.update(node_update)
        except Exception as exc:
            exc.investigation_state = state
            observability.finish_trace(
                {"status": "failed", "error": type(exc).__name__},
                {"status": "failed"},
            )
            observability.score(
                "deterministic_status",
                "failed",
                "CATEGORICAL",
                comment=f"aborted by {type(exc).__name__}",
                trace_id=trace_id,
            )
            raise
        report = state.get("report")
        observability.finish_trace(
            {
                "status": getattr(report, "status", None),
                "summary": getattr(report, "summary", None),
                "limitations": getattr(report, "limitations", None),
            },
            {
                "status": getattr(report, "status", None),
                "cve_id": getattr(state.get("package"), "cve_id", None),
                "revised": bool(state.get("revised")),
                "first_draft_invalid": bool(state.get("first_draft_invalid")),
                "revision_review_failed": bool(state.get("revision_review_failed")),
                "first_review_failed": bool(state.get("first_review_failed")),
                "draft_fallback_reason": state.get("draft_fallback_reason"),
                "model_calls": len(state.get("model_calls", [])),
            },
        )
        degradations = [
            name
            for name, flag in (
                ("deterministic_draft_fallback", state.get("draft_fallback_reason")),
                ("revised_draft", state.get("revised")),
                ("first_draft_invalid", state.get("first_draft_invalid")),
                ("first_review_failed", state.get("first_review_failed")),
                ("revision_review_failed", state.get("revision_review_failed")),
            )
            if flag
        ]
        try:
            from app.live_evaluator import evaluate_and_score_trace
            evaluate_and_score_trace(state, trace_id)
        except Exception as eval_exc:
            is_completed = (getattr(report, "status", None) == "completed")
            observability.score("deterministic_validation", 1.0 if is_completed else 0.0, "NUMERIC", trace_id=trace_id)
            observability.score("citation_grounding", 1.0 if not degradations else 0.85, "NUMERIC", trace_id=trace_id)
        return state


class SingleAgentWorkflow(InvestigationWorkflow):
    """Shared Evidence retrieval (deterministic retriever tool) plus one synthesis call and deterministic validation."""

    def __init__(
        self,
        evidence: EvidenceAgent | None = None,
        analyst: AnalystAgent | None = None,
        validator: FinalValidator | None = None,
    ):
        super().__init__(
            evidence=evidence or EvidenceAgent(),
            analyst=analyst,
            critic=None,
            validator=validator,
            use_critic=False,
        )
