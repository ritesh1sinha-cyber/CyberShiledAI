"""Tests for the per-claim secondary layer of the Batch 10 evaluator.

The claim judge is the part that can lie politely, so these pin the two things
that stop it: the score is computed in code from the model's own quotes, and a
quote the answer does not contain is worth nothing. ``usable`` is here because a
cache that ignores the answer text would report yesterday's judge score on
today's run, which is the failure the 18 November re-run exists to avoid.
"""

import json

import pytest

from scripts.evaluate_batch10 import (
    CLAIM_JUDGE_PROMPT_VERSION,
    JUDGE_PROMPT_VERSION,
    parse_element_judge,
    score_elements,
    sha,
    usable,
)

ANSWER = (
    "SEVERITY: 3.1 | 9.8 | CRITICAL | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n"
    "WEAKNESS: NVD has not attributed a CWE\n"
    "REMEDIATION: upgrade to nginx 1.21.1\n"
)
ELEMENTS = ["CVE-2021-23017", "9.8", "CWE-306", "1.21.1"]

QUOTES = {
    "stated": "upgrade to nginx 1.21.1",
    "contradicted": "SEVERITY: 3.1 | 9.8 | CRITICAL",
    "missing": "",
    "not_verifiable": "",
}


def rows(*statuses: str) -> list[dict]:
    """One judge reply. "invented" is a stated claim whose quote is not in the answer."""
    out: list[dict] = []
    for element, status in zip(ELEMENTS, statuses):
        if status == "invented":
            out.append({"element": element, "status": "stated", "quote": "CVE-2021-99999 is critical"})
        else:
            out.append({"element": element, "status": status, "quote": QUOTES[status]})
    return out


# --- strict reading of the model reply ---------------------------------------


def test_parser_accepts_exactly_one_entry_per_element_in_order():
    content = json.dumps({
        "elements": [
            {"element": item, "status": "stated", "quote": "upgrade to nginx 1.21.1"}
            for item in ELEMENTS
        ]
    })
    parsed = parse_element_judge(content, ELEMENTS)
    assert [item["element"] for item in parsed] == ELEMENTS
    assert all(item["status"] == "stated" for item in parsed)


def test_a_reply_that_drops_an_element_leaves_it_unanswered_rather_than_absolved():
    entry = {"element": ELEMENTS[0], "status": "stated", "quote": "upgrade to nginx 1.21.1"}
    parsed = parse_element_judge(json.dumps({"elements": [entry]}), ELEMENTS)
    assert len(parsed) == len(ELEMENTS)
    assert parsed[0] == {"element": ELEMENTS[0], "status": "stated",
                         "quote": "upgrade to nginx 1.21.1", "judge_omitted": False}
    assert all(row["judge_omitted"] and row["status"] == "missing" for row in parsed[1:])
    scored = score_elements(parsed, ANSWER)
    assert scored["elements_judge_omitted"] == 3
    assert scored["verdict"] == "misses"


def test_a_reply_with_more_entries_than_required_is_refused():
    entry = {"element": "x", "status": "stated", "quote": "upgrade to nginx 1.21.1"}
    with pytest.raises(ValueError, match="entries for"):
        parse_element_judge(json.dumps({"elements": [entry, entry]}), ELEMENTS[:1])


def test_entries_are_matched_on_the_echoed_text_even_when_the_model_reorders_them():
    reply = [
        {"element": ELEMENTS[3], "status": "stated", "quote": "upgrade to nginx 1.21.1"},
        {"element": ELEMENTS[0], "status": "missing", "quote": ""},
        {"element": ELEMENTS[1], "status": "stated", "quote": "9.8"},
        {"element": ELEMENTS[2], "status": "missing", "quote": ""},
    ]
    parsed = parse_element_judge(json.dumps({"elements": reply}), ELEMENTS)
    assert [row["element"] for row in parsed] == ELEMENTS
    assert [row["status"] for row in parsed] == ["missing", "stated", "missing", "stated"]
    assert score_elements(parsed, ANSWER)["elements_stated"] == 2


def test_parser_rejects_an_invented_status_field():
    content = json.dumps({
        "elements": [
            {"element": item, "status": "probably", "quote": ""} for item in ELEMENTS
        ]
    })
    with pytest.raises(ValueError, match="not one of the four allowed values"):
        parse_element_judge(content, ELEMENTS)


# --- the score is arithmetic over quotes, not a model opinion ----------------


def test_a_full_quote_of_every_element_conveys_the_claim():
    scored = score_elements(rows(*["stated"] * 4), ANSWER)
    assert scored["verdict"] == "conveys"
    assert scored["agreement"] == 5
    assert scored["element_share"] == 1.0
    assert scored["elements_unquoted"] == 0


def test_a_paraphrased_quote_counts_as_not_located_rather_than_as_evidence():
    scored = score_elements(rows("stated", "stated", "invented", "invented"), ANSWER)
    assert scored["elements_unquoted"] == 2
    assert scored["elements_stated"] == 2
    assert scored["verdict"] == "partial"
    assert scored["agreement"] == 3


def test_a_contradiction_caps_the_score_even_when_other_elements_are_located():
    scored = score_elements(rows("contradicted", "stated", "stated", "stated"), ANSWER)
    assert scored["elements_contradicted"] == 1
    assert scored["verdict"] == "contradicts"
    assert scored["agreement"] <= 2


def test_a_conceded_non_verification_scores_like_a_stated_element():
    scored = score_elements(rows("not_verifiable", "stated", "not_verifiable", "stated"), ANSWER)
    assert scored["elements_conceded"] == 2
    assert scored["verdict"] == "conveys"
    assert scored["agreement"] == 5


def test_a_claim_with_nothing_located_misses_rather_than_partial():
    scored = score_elements(rows(*["missing"] * 4), ANSWER)
    assert scored["verdict"] == "misses"
    assert scored["agreement"] == 1
    assert scored["element_share"] == 0.0


def test_quoting_is_matched_case_insensitively_and_across_line_wrapping():
    entry = {"element": "x", "status": "stated", "quote": "UPGRADE   TO\nNGINX 1.21.1"}
    assert score_elements([entry], ANSWER)["elements_stated"] == 1


# --- cache reuse needs the reference, the prompt and the answer to match -----


def base_cache(**overrides) -> dict:
    record = {
        "dataset_sha256": "digest",
        "answer_sha256": sha(ANSWER),
        "judge": {"verdict": "conveys"},
    }
    record.update(overrides)
    return record


def test_a_cached_answer_judgement_is_reused_only_for_the_same_prompt_version():
    assert usable(base_cache(judge_prompt_version=JUDGE_PROMPT_VERSION), "digest",
                  JUDGE_PROMPT_VERSION, sha(ANSWER))
    assert not usable(base_cache(judge_prompt_version="b10-0.9"), "digest",
                      JUDGE_PROMPT_VERSION, sha(ANSWER))


def test_a_cached_claim_judgement_is_keyed_on_its_own_prompt_version():
    assert usable(base_cache(prompt_version=CLAIM_JUDGE_PROMPT_VERSION), "digest",
                  CLAIM_JUDGE_PROMPT_VERSION, sha(ANSWER))
    assert not usable(base_cache(prompt_version="b10-claim-1.0"), "digest",
                      CLAIM_JUDGE_PROMPT_VERSION, sha(ANSWER))


def test_a_new_answer_never_inherits_the_previous_runs_judgement():
    old = base_cache(judge_prompt_version=JUDGE_PROMPT_VERSION)
    assert not usable(old, "digest", JUDGE_PROMPT_VERSION, sha("a rewritten answer"))


def test_a_judgement_stored_before_answer_hashing_exists_is_not_reusable():
    legacy = {"dataset_sha256": "digest", "judge_prompt_version": JUDGE_PROMPT_VERSION,
              "judge": {"overall": 5}}
    assert not usable(legacy, "digest", JUDGE_PROMPT_VERSION, sha(ANSWER))


def test_an_empty_cached_judgement_is_not_a_hit():
    assert not usable(base_cache(judge=None), "digest", JUDGE_PROMPT_VERSION, sha(ANSWER))
