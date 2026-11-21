import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from langfuse import Langfuse
from app.config import settings
from streamlit_app import (
    ZERO_SHOT_SYSTEM,
    FEW_SHOT_SYSTEM,
    COT_SYSTEM,
    EVIDENCE_AGENT_SYSTEM,
    WEBSEARCH_AGENT_SYSTEM,
    SINGLE_AGENT_SYSTEM,
)
from app.analyst import SYSTEM_PROMPT as ANALYST_PROMPT
from app.critic import SYSTEM_PROMPT as CRITIC_PROMPT
from app.answer_layers import JUDGE_SYSTEM

lf = Langfuse(
    public_key=settings.langfuse_public_key,
    secret_key=settings.langfuse_secret_key,
    host=settings.langfuse_host,
)

PROMPTS = [
    {
        "name": "prompt_zero_shot",
        "prompt": ZERO_SHOT_SYSTEM,
        "labels": ["production", "baseline", "zero-shot"],
    },
    {
        "name": "prompt_few_shot_json",
        "prompt": FEW_SHOT_SYSTEM,
        "labels": ["production", "baseline", "few-shot"],
    },
    {
        "name": "prompt_chain_of_thought",
        "prompt": COT_SYSTEM,
        "labels": ["production", "baseline", "chain-of-thought"],
    },
    {
        "name": "evidence_agent_system",
        "prompt": EVIDENCE_AGENT_SYSTEM,
        "labels": ["production", "agent", "evidence", "rag"],
    },
    {
        "name": "websearch_agent_system",
        "prompt": WEBSEARCH_AGENT_SYSTEM,
        "labels": ["production", "agent", "websearch", "live-cti"],
    },
    {
        "name": "single_agent_system",
        "prompt": SINGLE_AGENT_SYSTEM,
        "labels": ["production", "agent", "single-agent", "rag"],
    },
    {
        "name": "analyst_agent_system",
        "prompt": ANALYST_PROMPT,
        "labels": ["production", "agent", "analyst", "multi-agent"],
    },
    {
        "name": "critic_agent_system",
        "prompt": CRITIC_PROMPT,
        "labels": ["production", "agent", "critic", "multi-agent"],
    },
    {
        "name": "llm_as_judge_system",
        "prompt": JUDGE_SYSTEM,
        "labels": ["production", "evaluation", "judge"],
    },
]

print("Populating Langfuse Prompt Registry with all 9 production agent & baseline prompt templates...")
success_count = 0
for item in PROMPTS:
    try:
        p = lf.create_prompt(
            name=item["name"],
            prompt=item["prompt"],
            labels=item["labels"],
        )
        print(f"[OK] Created/Updated prompt: {p.name} (version {p.version})")
        success_count += 1
    except Exception as e:
        print(f"[ERROR] Prompt {item['name']}: {e}")

print(f"Finished: {success_count}/{len(PROMPTS)} prompt templates populated in Langfuse Prompt Registry.")
