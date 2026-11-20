"""Deterministic scoring of one investigation against the Batch 10 gold-claim ledger.

Pure functions over data the system already stores: the shipped report, the
evidence package, the retrieved contexts and the workbook's own claim rows. No
model is called here, so every number in this module is reproducible offline.
ROUGE, embedding similarity and the LLM judge are computed elsewhere and are
explicitly secondary; this module is the claim-level authority.

Rules and thresholds, stated once so a reviewer can disagree with a number
instead of guessing at a procedure:

- ``claim_result`` (the workbook's Pass/Fail/Partial/Abstain column) is decided
  by a source-derived field check whenever the claim family has one:
  SEVERITY against the CVSS fields, EXPLOITATION against KEV listedness,
  ``date_added`` and ``due_date``, WEAKNESS against stated CWE identifiers,
  PROJECT RISK against the ``kev-cvss-v1`` tier, AFFECTED / CONDITIONS and
  REMEDIATION against the version tokens and product terms the gold names,
  GUIDANCE against the control and framework identifiers it names.
  ``match`` gives Pass, ``mismatch`` and ``absent`` give Fail.
- Where no field check exists - the four prose families - the verdict falls back
  to the lexical anchor rule below and ``result_basis`` records
  "lexical anchor proxy" so the column is never read as a verified fact check.
- A gold claim that requires the system to state a non-verification (its text
  says "no verified ... mapping", "not an official ...", "context only") is
  graded on that behaviour and gets Abstain when the answer hedged and stated no
  comparable fact.
- anchors are the identifiers and terms a claim cannot be right without: CVE and
  CWE ids, the CVSS vector, score, and severity word, dates, version numbers,
  ATT&CK technique ids, NIST control ids, product proper nouns, plus the
  remaining significant words.
- coverage and support are the share of those anchors found in a haystack,
  graded ``Y`` at 0.60 and above, ``Partial`` at 0.30, ``N`` below. A ``Y`` also
  needs one discriminative anchor, otherwise any passage naming the CVE would
  pass. Coverage is reported in its own column and does not override a field
  check: a claim can be factually right (Pass) while the answer covers little of
  its wording (low coverage).
- support is judged against the WHOLE retrieved set (all passages plus all
  structured records), which is what "was the gold evidence retrieved" means;
  the locator columns name the single best-matching passage.
- the gold evidence items in this dataset are NOT independently verified
  (column R reads "NOT YET VERIFIED - candidate URL only"), so every
  recall-shaped cell is a proxy computed against the claim's own anchors, and
  the writer labels it as such.
- embeddings are not used for any claim verdict. Measured on this set in an
  ad-hoc offline probe on 17 November 2026 (numbers recorded in ``docs/scope.md``
  D28; the probe's scratch artifact was not retained, and it used the local
  all-MiniLM-L6-v2 model that the hosted bge-small endpoint replaced on 18
  November, so re-run it before quoting it as fresh evidence): cosine between a
  gold claim and its own answer scope versus the same family's scope of another
  CVE separates by -0.003 to +0.068 for the short templated families
  (EXPLOITATION, WEAKNESS, GUIDANCE, PROJECT RISK, SEVERITY) at a chance
  ordering rate of 0.12-0.55, so no threshold could be set there. It separates
  by +0.24 to +0.44 for the long prose families, but that is topic attribution
  (product name plus CVE id), not factual verification, so it is reported only
  as an answer-level relevance signal.
"""

from __future__ import annotations

import re
from typing import Any

CVE_TOKEN_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CWE_TOKEN_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
VECTOR_RE = re.compile(r"CVSS:[0-9.]+/[A-Z0-9/:]+", re.IGNORECASE)
SCORE_RE = re.compile(r"\b(?:[1-9]|10)(?:\.[0-9])?\b")
SEVERITY_WORD_RE = re.compile(r"\b(CRITICAL|HIGH|MEDIUM|LOW)\b")
DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
VERSION_RE = re.compile(r"\b\d+(?:\.\d+){1,3}\b")
CONTROL_RE = re.compile(r"\b(?:SI|SA|AU|IM|AC|IR|CM|RA)-\d+\b")
PROPER_RE = re.compile(r"\b[A-Z][A-Za-z0-9]+(?:[._+-][A-Za-z0-9]+)+\b")
WORD_RE = re.compile(r"[a-z][a-z0-9+./_-]{4,}")

STOP_WORDS = {
    "the", "this", "that", "with", "from", "have", "must", "should", "does", "when",
    "which", "while", "their", "there", "these", "those", "into", "upon", "about",
    "before", "after", "against", "between", "under", "over", "both", "each", "only",
    "also", "than", "then", "been", "being", "will", "would", "could", "cannot",
    "not", "such", "same", "other", "others", "some", "more", "most", "very",
    "because", "however", "therefore", "using", "used", "user", "users", "system",
    "systems", "information", "vulnerability", "vulnerabilities", "affected",
    "affect", "affects", "advisory", "advisories", "source", "sources", "candidate",
    "evidence", "claim", "claims", "reference", "references", "answer", "answers",
    "question", "questions", "verified", "unverified", "security", "attacker",
    "attack", "attacks", "server", "servers", "version", "versions", "product",
    "products", "exact", "specific", "general", "related", "relevant", "important",
    "note", "notes", "conditions", "prerequisites", "mechanism", "weakness",
    "remediation", "guidance", "severity", "exploitation", "status", "summary",
    "technical", "vulnerable", "potentially", "potentially", "impact", "effects",
    "resolve", "requires", "required", "instead", "rather", "without", "within",
}

Y_THRESHOLD = 0.60
PARTIAL_THRESHOLD = 0.30
EXCERPT_CHARS = 400

# Only these gold families have a report line that is specifically theirs; the
# rest are prose restatements of the same facts, so they are scored against the
# whole answer. Scoping a prose claim to the one-line SUMMARY understates
# coverage, because the shipped report has no plain-language section of its own.
NARROW_SCOPES: dict[str, tuple[str, ...]] = {
    "SEVERITY": ("SEVERITY",),
    "EXPLOITATION": ("KEV",),
    "PROJECT RISK": ("PROJECT RISK",),
    "REMEDIATION": ("REMEDIATION", "LIMITATION"),
    "ATT&CK": ("ATT&CK", "LIMITATION"),
}

# The gold statements that require the system to say it did NOT verify
# something, rather than to state a fact.
UNCERTAINTY_RE = re.compile(
    r"no verified|not verified|no\s+\S+\s+mapping|not an official|context(?:ual)?\s+only",
    re.IGNORECASE,
)

# Capitalised words that carry no product identity, so they cannot be required
# terms. Sentence-initial verbs and determiners dominate this list.
GENERIC_CAPITALS = frozenset(
    """
    apply upgrade update review assess enforce follow use keep retain verify refer
    check determine confirm restrict patch rotate remove record include cite note
    the this that these those there a an and or but if then so no not nor only both
    certain different because before after when while under over in on at to for from
    all any some each every other others most very also instead rather without within
    exact specific general related relevant important required requires supported
    multiple potentially separately additionally
    """
    .split()
)

# Names of data sources rather than of an affected product, so they carry no
# claim-specific identity either.
SOURCE_LABELS = frozenset({"nvd", "cna", "cisa", "kev", "cve", "cwe", "mitre"})

# Which evidence records could carry which family, used to pick the citations a
# claim is actually answerable from rather than grading every claim against the
# whole investigation's source list.
FAMILY_CLAIM_TYPES: dict[str, tuple[str, ...]] = {
    "SEVERITY": ("cvss",),
    "EXPLOITATION": ("kev",),
    "AFFECTED / CONDITIONS": ("affected_product", "cve_description"),
    "WEAKNESS": ("cve_description",),
    "REMEDIATION": ("remediation",),
    "PLAIN-LANGUAGE SUMMARY": ("cve_description", "cvss"),
    "TECHNICAL DETAILS": ("cve_description",),
    "PLAIN-LANGUAGE EXPLANATION": ("cve_description",),
    "DISTINCTION": ("cve_description",),
    "GUIDANCE": ("remediation", "cve_description"),
}


def norm(value: object) -> str:
    return " ".join(str(value or "").casefold().split())


def anchors(text: str, cve_id: str = "") -> tuple[list[str], list[str]]:
    """(all anchors, discriminative anchors) for one claim, in first-seen order."""
    source = str(text or "")
    discriminative: list[str] = []

    def add(token: str) -> None:
        token = token.strip()
        if token and token.lower() not in [item.lower() for item in discriminative]:
            discriminative.append(token)

    for pattern in (CVE_TOKEN_RE, CWE_TOKEN_RE, VECTOR_RE, TECHNIQUE_RE, CONTROL_RE, DATE_RE):
        for match in pattern.findall(source):
            add(match if isinstance(match, str) else match[0])
    for word in SEVERITY_WORD_RE.findall(source):
        add(word)
    for match in VERSION_RE.findall(source):
        add(match)
    for match in SCORE_RE.findall(source):
        add(match)
    for match in PROPER_RE.findall(source):
        if match.lower() not in STOP_WORDS:
            add(match)
    if cve_id:
        add(cve_id)

    words = [
        word
        for word in WORD_RE.findall(norm(source))
        if word not in STOP_WORDS and not word.startswith(("cve-", "cwe-"))
    ]
    ordered = list(dict.fromkeys(discriminative))
    return ordered + [word for word in words if word.lower() not in {item.lower() for item in ordered}], ordered


def match_ratio(items: list[str], disc: list[str], haystack: str) -> dict[str, Any]:
    """How much of a claim's anchor set appears in one haystack."""
    pool = norm(haystack)
    found = [item for item in items if norm(item) in pool]
    disc_found = [item for item in disc if norm(item) in pool]
    total = len(items)
    ratio = round(len(found) / total, 4) if total else 0.0
    if not total:
        grade = "N"
    elif ratio >= Y_THRESHOLD and (disc_found or not disc):
        grade = "Y"
    elif ratio >= PARTIAL_THRESHOLD:
        grade = "Partial"
    else:
        grade = "N"
    return {
        "total": total,
        "found": len(found),
        "ratio": ratio,
        "disc_found": disc_found,
        "missing": [item for item in items if item not in found][:12],
        "grade": grade,
    }


def answer_lines(answer_text: str) -> dict[str, list[str]]:
    """Group the rendered report by its own line labels."""
    grouped: dict[str, list[str]] = {}
    for line in str(answer_text or "").splitlines():
        label, separator, rest = line.partition(":")
        label = label.strip().upper()
        if separator and label and label.upper() == label and rest.strip():
            grouped.setdefault(label, []).append(rest.strip())
    return grouped


def scope_text(family: str, lines: dict[str, list[str]], answer_text: str) -> str:
    wanted = NARROW_SCOPES.get(family.upper(), ())
    parts = [value for label in wanted for value in lines.get(label, [])]
    return "\n".join(parts) if parts else str(answer_text or "")


def citations_for(family: str, report: dict, evidence: list[dict]) -> list[str]:
    """Citation ids the shipped report attaches to material this claim depends on."""
    upper = family.upper()
    cited = [str(item.get("evidence_id")) for item in report.get("citations") or []]
    allowed_types = FAMILY_CLAIM_TYPES.get(upper, ())
    eligible = {
        str(item.get("evidence_id"))
        for item in evidence
        if str(item.get("claim_type")) in allowed_types
        or (upper == "WEAKNESS" and "CWE" in str(item.get("source", "")).upper())
        or (upper == "GUIDANCE" and str(item.get("source", "")).upper() in {"NIST", "OWASP"})
    }
    if upper in {"PROJECT RISK", "ATT&CK"}:
        if upper == "PROJECT RISK":
            eligible |= {str(value) for value in (report.get("risk") or {}).get("evidence_ids") or []}
        for item in report.get("attack_mapping") or []:
            if isinstance(item, dict) and item.get("evidence_id"):
                eligible.add(str(item["evidence_id"]))
    if upper in {"PLAIN-LANGUAGE SUMMARY", "DISTINCTION"}:
        eligible |= {str(value) for value in report.get("summary_evidence_ids") or []}
    return [item for item in cited if item in eligible]


def version_tokens(text: str) -> list[str]:
    """Dotted version numbers only; a bare build number cannot be told from a year."""
    return sorted(set(VERSION_RE.findall(str(text or ""))))


def product_terms(claim: str) -> list[str]:
    """Product, component and condition names a claim cannot be right without.

    Only capitalised parts count: a compound such as ``DNS-response`` requires
    ``dns`` but not the lowercase half, which is ordinary prose. Source labels
    and generic verbs are filtered so the requirement stays factual. A product
    the gold writes in lowercase, such as ``nginx``, is therefore not required
    by this rule and that claim falls back to the lexical proxy - recorded in
    ``result_basis`` rather than hidden.
    """
    out: list[str] = []
    for token in re.findall(r"\b[A-Za-z][A-Za-z0-9]*(?:[_+-][A-Za-z0-9]+)*\b", str(claim or "")):
        for part in re.split(r"[_+-]", token):
            if not part[:1].isupper():
                continue
            word = norm(part)
            if word in GENERIC_CAPITALS or word in SOURCE_LABELS or word in STOP_WORDS:
                continue
            if word not in out:
                out.append(word)
    return out


def _term_check(claim: str, haystack: str, label: str) -> str:
    """Deterministic agreement on the versions and product terms in one claim."""
    pool = norm(haystack)
    want_versions = version_tokens(claim)
    want_terms = [term for term in product_terms(claim) if not re.fullmatch(r"\d[\d.]+", term)]
    if not want_versions and not want_terms:
        return "n/a - the claim states no version or capitalised product term to compare"
    missed_versions = [token for token in want_versions if token not in pool]
    missed_terms = [term for term in want_terms if term not in pool]
    if missed_versions:
        return "mismatch: " + label + " version token(s) " + ", ".join(missed_versions) + " not stated"
    if missed_terms:
        return "absent - " + label + " term(s) " + ", ".join(missed_terms) + " not stated"
    return "match"


def fact_check(family: str, claim: str, report: dict, scope: str, answer_text: str) -> str:
    """Deterministic agreement between one gold claim and the shipped answer.

    Verdicts: ``match``, ``mismatch: ...`` (the answer states a different
    value), ``absent - ...`` (the answer states nothing comparable), or
    ``n/a - ...`` (no source-derived field exists for this claim).
    """
    upper = family.upper()
    cve = report.get("cve") or {}
    kev = report.get("kev") or {}
    risk = report.get("risk") or {}
    if upper == "SEVERITY":
        want_version = re.search(r"CVSS\s+([\d.]+)", claim, re.IGNORECASE)
        want_score = re.search(r"CVSS\s+[\d.]+\s+([\d.]+)", claim, re.IGNORECASE)
        want_severity = re.search(r"CVSS\s+[\d.]+\s+[\d.]+\s+([A-Z]+)", claim, re.IGNORECASE)
        want_vector = VECTOR_RE.search(claim)
        parts = {
            "cvss_version": bool(want_version) and want_version.group(1) == str(cve.get("cvss_version")),
            "cvss_score": bool(want_score) and float(want_score.group(1)) == cve.get("cvss_score"),
            "severity": bool(want_severity)
            and want_severity.group(1) == str(cve.get("severity") or "").upper(),
            "cvss_vector": bool(want_vector)
            and norm(want_vector.group(0)) == norm(cve.get("cvss_vector")),
        }
        if all(parts.values()):
            return "match"
        if not any(
            cve.get(key) for key in ("cvss_version", "cvss_score", "severity", "cvss_vector")
        ):
            return "absent - the answer states no CVSS"
        return "mismatch: " + ", ".join(key for key, value in parts.items() if not value)
    if upper == "EXPLOITATION":
        want_listed = "NOT LISTED" not in claim.upper()
        got_listed = kev.get("status") == "known_exploited"
        if want_listed != got_listed:
            return f"mismatch: listedness (gold {want_listed}, answer {got_listed})"
        if not want_listed:
            return "match"
        parts = {}
        for pattern, key, name in (
            (r"added\s+(\d{4}-\d{2}-\d{2})", "date_added", "date added"),
            (r"due date\s+(\d{4}-\d{2}-\d{2})", "due_date", "due date"),
        ):
            want = re.search(pattern, claim, re.IGNORECASE)
            if want is None:
                continue
            parts[name] = (want.group(1), kev.get(key))
        if not parts:
            return "not-in-reference - the gold states no KEV date"
        wrong = [f"{name} {want} vs {got}" for name, (want, got) in parts.items() if want != got]
        missing = [name for name, (_want, got) in parts.items() if got is None]
        if wrong:
            return "mismatch: " + "; ".join(wrong)
        if missing:
            return "absent - the answer states no " + ", ".join(missing)
        return "match"
    if upper == "WEAKNESS":
        want = [item.upper() for item in CWE_TOKEN_RE.findall(claim)]
        want += [item for item in re.findall(r"NVD-CWE-[A-Za-z]+", claim)]
        stated = [item.upper() for item in CWE_TOKEN_RE.findall(answer_text)]
        stated += [item for item in re.findall(r"NVD-CWE-[A-Za-z]+", answer_text)]
        if not want:
            return "n/a - the claim states no CWE identifier"
        if not stated:
            return "absent - the shipped report has no CWE field"
        missed = [item for item in want if item.upper() not in [value.upper() for value in stated]]
        return "match" if not missed else "mismatch: gold " + ", ".join(missed) + " not stated by the answer"
    if upper == "PROJECT RISK":
        want = SEVERITY_WORD_RE.search(claim)
        got = risk.get("tier")
        if not got:
            return "absent - the answer states no risk tier"
        if not want:
            return "n/a - the gold states no tier word"
        return "match" if want.group(1).upper() == str(got).upper() else (
            f"mismatch: gold {want.group(1).upper()} vs kev-cvss-v1 {str(got).upper()}"
        )
    if upper == "AFFECTED / CONDITIONS":
        return _term_check(claim, answer_text, "affected product/version/condition")
    if upper == "REMEDIATION":
        return _term_check(claim, answer_text, "remediation")
    if upper == "GUIDANCE":
        want = [norm(item) for item in CONTROL_RE.findall(claim)]
        want += [item for item in ("nist", "owasp") if item in norm(claim)]
        want = list(dict.fromkeys(want))
        if not want:
            return "n/a - the claim states no control or framework"
        pool = norm(answer_text)
        missed = [item for item in want if item not in pool]
        if missed:
            return "absent - guidance term(s) " + ", ".join(missed) + " not stated"
        return "match"
    return "n/a - prose claim"


def requires_abstention(claim: str) -> bool:
    """Whether the gold claim's requirement is that the system NOT over-claim."""
    return bool(UNCERTAINTY_RE.search(str(claim or "")))


def abstention_state(claim: str, report: dict, scope: str, answer_text: str) -> tuple[int, str]:
    """1 = the answer carries the uncertainty the gold requires, 0 = it does not."""
    pool = norm(answer_text)
    hedge = bool(
        re.search(
            r"no verified|not verified|no\s+\w+\s+mapping|cannot be confirmed|context(?:ual)? only",
            pool,
        )
    )
    invented = bool(
        TECHNIQUE_RE.findall(scope) and not re.search(r"no verified|context", norm(scope))
    )
    if invented:
        return 0, "the answer asserts a specific mapping the gold says is unverified"
    if hedge:
        return 1, ""
    return 0, "the answer states no uncertainty note for the unverified element"


def preservation(family: str, claim: str, report: dict, scope: str) -> tuple[object, str]:
    """Whether the system kept publisher-attributed values instead of collapsing them."""
    upper = family.upper()
    cve = report.get("cve") or {}
    kev = report.get("kev") or {}
    if upper == "SEVERITY":
        publisher = str(cve.get("cvss_source") or "").strip()
        if not publisher:
            return 0, "the report carries no CVSS publisher"
        rendered = bool(re.search(rf"\b{re.escape(publisher)}\b", norm(scope)))
        note = f"cvss_source={publisher}" + ("" if rendered else "; not rendered in the plain-text answer")
        return (1 if rendered else 0.5), note
    if upper == "EXPLOITATION":
        version = str(kev.get("catalog_version") or "").strip()
        if not version:
            return 0, "the report carries no KEV catalog version"
        rendered = version in scope
        note = f"kev.catalog_version={version}" + ("" if rendered else "; not rendered in the plain-text answer")
        return (1 if rendered else 0.5), note
    if upper == "WEAKNESS":
        attributed = bool(re.search(r"nvd:?\s*cwe|cwe.*attributed", norm(scope)))
        stated = bool(CWE_TOKEN_RE.findall(scope))
        if not stated:
            return 0, "no CWE is stated, so no attribution can be preserved"
        return (1 if attributed else 0.5), "CWE stated without a mapping source" if not attributed else ""
    return "n/a", ""


def conflict_note(family: str, claim: str, report: dict, scope: str, pres_note: str) -> str:
    notes: list[str] = []
    gold_kev = re.search(r"KEV\s+(\d{4}\.\d{2}\.\d{2})", claim)
    answer_kev = str((report.get("kev") or {}).get("catalog_version") or "")
    if gold_kev and answer_kev and gold_kev.group(1) != answer_kev:
        notes.append(
            f"KEV snapshot label differs (gold {gold_kev.group(1)}, system {answer_kev}); "
            "listedness is compared separately"
        )
    want_publisher = re.search(r"\((NVD|CNA|AVTECH|[A-Za-z][A-Za-z]+)\)", claim)
    got_publisher = str((report.get("cve") or {}).get("cvss_source") or "")
    if family.upper() == "SEVERITY" and want_publisher and got_publisher:
        if norm(want_publisher.group(1)) != norm(got_publisher):
            notes.append(
                f"gold attributes the score to {want_publisher.group(1)}, the system reports {got_publisher}"
            )
        if norm(want_publisher.group(1)) not in norm(scope):
            notes.append("the plain-text severity line names no publisher (cvss_source is not rendered)")
    if pres_note:
        notes.append(pres_note)
    return "; ".join(notes)


def _best_passage(cases: list[dict], items: list[str], disc: list[str]) -> dict:
    best: dict = {"grade": "N", "ratio": 0.0}
    for case in cases:
        hit = match_ratio(items, disc, case["text"])
        if hit["ratio"] > best["ratio"]:
            best = {**case, **hit}
    return best


def _mean(values: list[Any]) -> Any:
    clean = [float(value) for value in values if isinstance(value, (int, float))]
    return round(sum(clean) / len(clean), 4) if clean else "n/a"


def derive_result(
    exact: str, abstain_required: bool, abstention: object, grade: str
) -> tuple[str, str]:
    """Claim-level result (AF) and the basis a reviewer can audit (appended column).

    A source-derived field check decides whenever one exists; the lexical anchor
    rule is used only where no such check exists, and is labelled as such.
    """
    if exact.startswith("mismatch"):
        return "Fail", "deterministic field check"
    if abstain_required:
        if abstention == 0:
            return "Fail", "abstention guardrail"
        if exact == "match" or exact.startswith("not-in-reference"):
            return "Pass", "deterministic field check plus abstention guardrail"
        return "Abstain", "abstention guardrail"
    if exact == "match" or exact.startswith("not-in-reference"):
        return "Pass", "deterministic field check"
    if exact.startswith("absent"):
        return "Fail", "deterministic field check"
    return {"Y": "Pass", "Partial": "Partial", "N": "Fail"}[grade], "lexical anchor proxy"


def score_investigation(entry: dict, trace: dict, *, answer_text: str) -> dict:
    """Score every gold claim of one investigation and roll the set up."""
    report = (trace.get("response") or {}).get("report") or {}
    report = dict(report)
    if "risk" in report and isinstance(report["risk"], dict):
        cve = report.get("cve") or {}
        kev = report.get("kev") or {}
        score = cve.get("cvss_score")
        kev_listed = kev.get("status") == "known_exploited"
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
        report["risk"] = dict(report["risk"], tier=tier)
    service = trace.get("service_trace") or {}
    contexts = list(service.get("contexts") or [])
    evidence = list(service.get("evidence") or [])
    lines = answer_lines(answer_text)

    passages = [
        {
            "kind": "retrieved_passage",
            "chunk_id": str(context.get("chunk_id") or ""),
            "document_id": str(context.get("chunk_id") or "").split("#")[0],
            "title": str(context.get("title") or ""),
            "text": str(context.get("text") or ""),
            "score": context.get("score"),
            "evidence_id": str(context.get("evidence_id") or ""),
        }
        for context in contexts
    ]
    records = [
        {
            "kind": "structured_record",
            "chunk_id": "",
            "document_id": str(item.get("source") or ""),
            "title": str(item.get("claim_type") or ""),
            "text": f"{item.get('claim_type')} {item.get('source')} {item.get('claim')}",
            "score": None,
            "evidence_id": str(item.get("evidence_id") or ""),
        }
        for item in evidence
    ]
    haystack_all = "\n".join([item["text"] for item in passages] + [item["text"] for item in records])
    evidence_by_id = {str(item.get("evidence_id")): item for item in evidence}

    claims: list[dict] = []
    for claim in entry["claims"]:
        items, disc = anchors(claim.claim_text, entry["cve_id"])
        scope = scope_text(claim.family, lines, answer_text)
        coverage = match_ratio(items, disc, scope)
        support = match_ratio(items, disc, haystack_all)
        best = _best_passage(passages + records, items, disc)
        exact = fact_check(claim.family, claim.claim_text, report, scope, answer_text)
        keep, pres_note = preservation(claim.family, claim.claim_text, report, scope)
        upper = claim.family.upper()
        abstain_required = requires_abstention(claim.claim_text)
        if abstain_required:
            abstention, abstain_note = abstention_state(claim.claim_text, report, scope, answer_text)
        else:
            abstention, abstain_note = "n/a", ""

        attached = citations_for(claim.family, report, evidence)
        supporting = [
            evidence_id
            for evidence_id in attached
            if match_ratio(
                items, disc, str((evidence_by_id.get(evidence_id) or {}).get("claim") or "")
            )["grade"] in {"Y", "Partial"}
        ]

        stated = coverage["grade"] in {"Y", "Partial"}
        result, basis = derive_result(exact, abstain_required, abstention, coverage["grade"])

        claims.append(
            {
                "claim_id": claim.claim_id,
                "workbook_row": claim.row,
                "family": claim.family,
                "generated_claim": scope[:1200],
                "generated_citations": ", ".join(attached),
                "citation_precision": (round(len(supporting) / len(attached), 4) if attached else "n/a"),
                "citation_coverage": (1 if supporting else (0 if attached else "n/a")),
                "supporting_citations": supporting,
                "evidence_supports_claim": support["grade"],
                "support_ratio": support["ratio"],
                "retrieval_method": best.get("kind", "none"),
                "source_document_id": best.get("document_id", "") if best.get("ratio", 0) else "",
                "source_chunk_id": best.get("chunk_id", "") if best.get("ratio", 0) else "",
                "chunk_locator": best.get("title", "")[:200] if best.get("ratio", 0) else "",
                "chunk_text": (best.get("text", "")[:EXCERPT_CHARS] if best.get("ratio", 0) else ""),
                "retriever_rank": (
                    next(
                        (
                            index + 1
                            for index, item in enumerate(passages)
                            if item["chunk_id"] == best.get("chunk_id")
                        ),
                        None,
                    )
                    if best.get("kind") == "retrieved_passage"
                    else None
                ),
                "retrieval_score": best.get("score") if best.get("kind") == "retrieved_passage" else None,
                "structured_record_id": (
                    best.get("evidence_id", "") if best.get("kind") == "structured_record" else ""
                ),
                "claim_coverage": coverage["ratio"],
                "coverage_grade": coverage["grade"],
                "coverage_missing": coverage["missing"],
                "gold_evidence_recall": (
                    1 if support["grade"] == "Y" else (0.5 if support["grade"] == "Partial" else 0)
                ),
                "critical_fact_match": exact,
                "claim_result": result,
                "result_basis": basis,
                "abstention_note": abstain_note,
                "faithfulness": 1 if (stated and support["grade"] in {"Y", "Partial"}) else (
                    0 if stated else "n/a"
                ),
                "unsupported_claim_rate": 1 if (stated and support["grade"] == "N") else (
                    0 if stated else "n/a"
                ),
                "conflict_preservation": keep,
                "abstention_correctness": abstention,
                "conflict_notes": conflict_note(claim.family, claim.claim_text, report, scope, pres_note),
            }
        )

    stated_claims = [item for item in claims if item["claim_result"] != "Abstain"]
    fact_claims = [item for item in claims if not item["critical_fact_match"].startswith("n/a")]
    answered = [item for item in claims if item["faithfulness"] != "n/a"]
    cite_rows = [item for item in claims if item["citation_precision"] != "n/a"]
    correct = sum(1 for item in claims if item["claim_result"] in {"Pass", "Abstain"})

    family_rollup: dict[str, dict[str, int]] = {}
    for item in claims:
        counts = family_rollup.setdefault(item["family"], {})
        counts[item["claim_result"]] = counts.get(item["claim_result"], 0) + 1

    relevant = sum(
        1
        for passage in passages
        if any(
            match_ratio(*anchors(claim.claim_text, entry["cve_id"]), passage["text"])["grade"]
            in {"Y", "Partial"}
            for claim in entry["claims"]
        )
    )

    answer = {
        "eval_id": entry["eval_id"],
        "cve_id": entry["cve_id"],
        "trace_id": report.get("request_id"),
        "report_status": report.get("status"),
        "claims": len(claims),
        "claims_pass": sum(1 for item in claims if item["claim_result"] == "Pass"),
        "claims_partial": sum(1 for item in claims if item["claim_result"] == "Partial"),
        "claims_fail": sum(1 for item in claims if item["claim_result"] == "Fail"),
        "claims_abstain": sum(1 for item in claims if item["claim_result"] == "Abstain"),
        "gold_claim_coverage": (round(correct / len(claims), 4) if claims else "n/a"),
        "anchor_coverage_mean": _mean([item["claim_coverage"] for item in claims]),
        "claims_correct": correct,
        "claim_result_bases": sorted({item["result_basis"] for item in claims}),
        "by_family": family_rollup,
        "gold_evidence_recall": _mean([item["gold_evidence_recall"] for item in claims]),
        "critical_fact_exact_match": (
            round(sum(1 for item in fact_claims if item["critical_fact_match"] == "match") / len(fact_claims), 4)
            if fact_claims
            else "n/a"
        ),
        "fact_claims": len(fact_claims),
        "context_precision": (round(relevant / len(passages), 4) if passages else "n/a"),
        "context_recall": _mean([1 if item["gold_evidence_recall"] else 0 for item in claims]),
        "faithfulness": _mean([item["faithfulness"] for item in answered]),
        "answer_correctness": (
            round(sum(1 for item in stated_claims if item["claim_result"] == "Pass") / len(stated_claims), 4)
            if stated_claims
            else "n/a"
        ),
        "citation_precision": _mean([item["citation_precision"] for item in cite_rows]),
        "citation_coverage": _mean([item["citation_coverage"] for item in cite_rows]),
        "unsupported_claim_rate": _mean([item["unsupported_claim_rate"] for item in claims]),
        "conflict_preservation": _mean([item["conflict_preservation"] for item in claims]),
        "abstention_correctness": _mean([item["abstention_correctness"] for item in claims]),
        "retrieved_contexts": len(contexts),
        "evidence_records": len(evidence),
        "citations": len(report.get("citations") or []),
        "revised": bool(service.get("revised")),
        "first_draft_invalid": bool(service.get("first_draft_invalid")),
        "latency_ms": trace.get("elapsed_ms"),
        "model_calls": len(service.get("model_calls") or []),
        "prompt_tokens": sum(int(item.get("prompt_tokens") or 0) for item in service.get("model_calls") or []),
        "completion_tokens": sum(
            int(item.get("completion_tokens") or 0) for item in service.get("model_calls") or []
        ),
        "top_k": (trace.get("request") or {}).get("top_k"),
    }
    return {"claims": claims, "answer": answer}
