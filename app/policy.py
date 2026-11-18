from __future__ import annotations

import re

UNSAFE_REQUEST_RE = re.compile(
    r"\b(working exploit|write (?:a )?exploit|exploit for|exploit code|payload|intrusion|credential theft|"
    r"evad(?:e|ing)|unauthori[sz]ed access|print (?:the )?system prompt|"
    r"reveal (?:the )?system prompt|ignore all previous instructions)\b",
    re.IGNORECASE,
)


def refusal_reason(query: str) -> str | None:
    if UNSAFE_REQUEST_RE.search(query):
        return (
            "I cannot provide exploit instructions or hidden system prompts. "
            "I can help with a defensive CVE investigation."
        )
    return None
