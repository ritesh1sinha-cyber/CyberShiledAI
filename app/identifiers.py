import re

from app.contracts import InvestigateRequest

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def extract_single_cve(query: str) -> str:
    cve_ids = {match.upper() for match in CVE_RE.findall(query)}
    if len(cve_ids) != 1:
        raise ValueError("Workflow requires exactly one distinct CVE identifier in the query.")
    return next(iter(cve_ids))


def resolve_request_cve(request: InvestigateRequest) -> str:
    """Resolve a CVE from this question or its most recent user context."""
    current = {match.upper() for match in CVE_RE.findall(request.query)}
    if len(current) == 1:
        return next(iter(current))
    if len(current) > 1:
        raise ValueError("Workflow requires exactly one distinct CVE identifier in the query.")

    for turn in reversed(request.conversation_context):
        if turn.role != "user":
            continue
        candidates = {match.upper() for match in CVE_RE.findall(turn.content)}
        if len(candidates) == 1:
            return next(iter(candidates))
        if len(candidates) > 1:
            raise ValueError("Follow-up context contains multiple distinct CVE identifiers.")
    raise ValueError(
        "Workflow requires exactly one distinct CVE identifier in the query or prior user context."
    )
