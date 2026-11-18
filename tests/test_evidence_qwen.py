import json
from types import SimpleNamespace

from app.contracts import InvestigateRequest
from app.evidence_qwen import EvidenceQwenAgent
from app.qwen import QwenResponse

CVE_ID = "CVE-2021-44228"


class FakeQwen:
    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []

    def complete(self, system, user, max_tokens=512):
        self.calls.append((system, user, max_tokens))
        content = self.answers.pop(0)
        return QwenResponse(
            content=json.dumps(content),
            model="Qwen/Qwen3-8B",
            latency_ms=20,
            prompt_tokens=100,
            completion_tokens=30,
            finish_reason="stop",
        )


class FakeEvidenceTool:
    def __init__(self):
        self.state = None

    def collect(self, state):
        self.state = state
        context = SimpleNamespace(
            chunk_id="CWE-917#000",
            title="CWE-917 guidance",
            text="Avoid unsafe expression evaluation.",
        )
        review = state["retrieval_reviewer"](state["retrieval_query"], [context])
        package = SimpleNamespace(
            contexts=[context],
            limitations=list(state.get("additional_limitations", [])),
            timings=[],
        )
        return {
            "package": package,
            "retrieval_meta": {"review": review, "queries": [state["retrieval_query"]]},
        }


def test_evidence_qwen_interprets_follow_up_and_checks_retrieval():
    client = FakeQwen(
        [
            {"cve_id": CVE_ID, "intent": "remediation", "retrieval_query": "Log4j remediation CWE-917"},
            {"sufficient": True, "refined_query": None},
        ]
    )
    tool = FakeEvidenceTool()
    agent = EvidenceQwenAgent(client=client, evidence_tool=tool)
    request = InvestigateRequest(
        query="What remediation should I apply?",
        conversation_context=[{"role": "user", "content": f"Investigate {CVE_ID}"}],
    )
    result = agent.collect({"request": request})
    assert result["interpretation"]["cve_id"] == CVE_ID
    assert result["interpretation"]["intent"] == "remediation"
    assert tool.state["cve_id"] == CVE_ID
    assert tool.state["retrieval_query"] == "Log4j remediation CWE-917"
    assert result["retrieval_meta"]["review"]["sufficient"] is True
    assert [call.stage for call in result["model_calls"]] == [
        "evidence_interpretation",
        "retrieval_review",
    ]
    assert all(call[2] == 1024 for call in client.calls)


def test_evidence_qwen_rejects_model_cve_change_and_uses_validated_id():
    client = FakeQwen(
        [
            {"cve_id": "CVE-2021-45046", "intent": "facts", "retrieval_query": "other CVE"},
            {"sufficient": True, "refined_query": None},
        ]
    )
    tool = FakeEvidenceTool()
    agent = EvidenceQwenAgent(client=client, evidence_tool=tool)
    result = agent.collect({"request": InvestigateRequest(query=f"Investigate {CVE_ID}")})
    assert tool.state["cve_id"] == CVE_ID
    assert tool.state["retrieval_query"] == f"Investigate {CVE_ID}"
    assert any("deterministic CVE/context handling" in item for item in result["package"].limitations)
