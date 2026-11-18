from app.answer_metrics import candidate_text, rouge_scores, tokenize


def test_rouge_is_one_for_identical_reference_and_candidate():
    result = rouge_scores("CVE-2024-55591 patch the product", "CVE-2024-55591 patch the product")
    assert result == {"rouge1_f": 1.0, "rouge2_f": 1.0, "rougeL_f": 1.0}


def test_rouge_detects_no_overlap():
    result = rouge_scores("CVE-2024-55591 patch now", "Apache Log4j2 is affected")
    assert result == {"rouge1_f": 0.0, "rouge2_f": 0.0, "rougeL_f": 0.0}


def test_tokenizer_preserves_cve_identifiers_as_tokens():
    assert "cve-2024-55591" in tokenize("CVE-2024-55591 needs a patch")


def test_candidate_text_keeps_answer_content_and_omits_evidence_ids():
    text = candidate_text({
        "summary": "CVE-2024-55591 affects FortiOS.",
        "summary_evidence_ids": ["EV-0001"],
        "remediation": [{"text": "Apply vendor mitigations.", "evidence_ids": ["EV-0003"]}],
        "citations": [{"evidence_id": "EV-0003", "source": "CISA_KEV"}],
    })
    assert "CVE-2024-55591" in text
    assert "Apply vendor mitigations." in text
    assert "EV-0003" not in text
