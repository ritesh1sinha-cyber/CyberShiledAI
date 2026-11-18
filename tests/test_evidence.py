import json
from datetime import date, datetime, timezone

import pytest

from app.contracts import InvestigateRequest
from app.evidence import EvidenceAgent, EvidenceWriter

CVE_ID = "CVE-2021-44228"
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def nvd_cve():
    return {
        "id": CVE_ID,
        "published": "2021-12-10T10:15:09.143",
        "lastModified": "2026-08-11T19:33:44.513",
        "descriptions": [
            {"lang": "en", "value": "Apache Log4j2 JNDI remote code execution."},
            {"lang": "es", "value": "Descripcion tecnica."},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Secondary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 9.0,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:H",
                    },
                },
                {
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 10.0,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L",
                    },
                },
            ],
            "cvssMetricV2": [
                {
                    "type": "Primary",
                    "cvssData": {"version": "2.0", "baseScore": 9.3},
                    "baseSeverity": "HIGH",
                }
            ],
        },
        "weaknesses": [
            {"source": "nvd@nist.gov", "description": [{"value": "CWE-502"}]}
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                            }
                        ]
                    }
                ]
            }
        ],
    }


class FakeRetriever:
    def __init__(self, results=None):
        self.results = results if results is not None else [
            {
                "chunk_id": "CWE-502#000",
                "doc_id": "CWE-502",
                "source": "cwe",
                "title": "CWE-502 Deserialization of Untrusted Data",
                "text": "Avoid deserializing untrusted data and apply the documented mitigations.",
                "score": 0.025,
            }
        ]
        self.calls = []

    def search(self, query, **kwargs):
        self.calls.append((query, kwargs))
        return self.results


def make_agent(
    tmp_path,
    *,
    released="2026-11-04T20:00:05.774Z",
    kev_rows=None,
    cve=None,
    retriever=None,
):
    processed = tmp_path / "data" / "processed"
    nvd_dir = tmp_path / "data" / "raw" / "nvd"
    manifest = tmp_path / "data" / "manifests" / "sources.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        json.dumps(
            {
                "sources": {
                    "kev": {"catalog_version": "2026.11.04", "released": released}
                }
            }
        ),
        encoding="utf-8",
    )
    if kev_rows is None:
        kev_rows = [
            {
                "cve_id": CVE_ID,
                "vendor": "Apache",
                "product": "Log4j2",
                "date_added": "2021-12-10",
                "due_date": "2021-12-24",
                "required_action": "Apply updates per vendor instructions.",
                "ransomware": "Known",
                "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            }
        ]
    write_jsonl(processed / "kev.jsonl", kev_rows)
    write_jsonl(
        processed / "attack_techniques.jsonl",
        [
            {
                "doc_id": "ATTACK-T1190",
                "technique_id": "T1190",
                "name": "Exploit Public-Facing Application",
                "cve_mentions": [CVE_ID],
                "source_url": "https://attack.mitre.org/techniques/T1190",
            }
        ],
    )
    write_jsonl(
        processed / "cwe.jsonl",
        [
            {
                "doc_id": "CWE-502",
                "cwe_id": "CWE-502",
                "name": "Deserialization of Untrusted Data",
                "mitigations": "::PHASE:Architecture and Design:DESCRIPTION:Avoid untrusted data.::",
                "source_url": "https://cwe.mitre.org/data/definitions/502.html",
            }
        ],
    )
    write_jsonl(processed / "owasp_docs.jsonl", [])
    write_jsonl(processed / "nist_docs.jsonl", [])
    nvd_dir.mkdir(parents=True, exist_ok=True)
    (nvd_dir / f"{CVE_ID}.json").write_text(
        json.dumps({"vulnerabilities": [{"cve": nvd_cve() if cve is None else cve}]}),
        encoding="utf-8",
    )
    retriever = retriever or FakeRetriever()
    agent = EvidenceAgent(
        retriever=retriever,
        nvd_dir=nvd_dir,
        processed_dir=processed,
        manifest_path=manifest,
        clock=lambda: NOW,
    )
    return agent, retriever


def test_single_node_graph_collects_linked_evidence(tmp_path):
    agent, retriever = make_agent(tmp_path)
    result = agent.graph.invoke(
        {"request": InvestigateRequest(query=f"Investigate {CVE_ID}", top_k=3)}
    )
    package = result["package"]
    assert package.cve.cvss_version == "3.1"
    assert package.cve.cvss_score == 10.0
    assert package.cve.cvss_vector == "CVSS:3.1/AV:N/AC:L"
    assert package.cve.severity == "CRITICAL"
    assert package.cve.published == date(2021, 12, 10)
    assert package.affected_products == ["Apache Log4j2"]
    assert package.kev.status == "known_exploited"
    assert package.kev.ransomware_use is True
    kev_evidence = next(item for item in package.evidence if item.claim_type == "kev")
    assert "Required action: Apply updates per vendor instructions." in kev_evidence.claim
    assert package.attack_mapping[0].technique_id == "T1190"
    assert package.attack_mapping[0].basis == "source_reference"
    assert package.contexts[0].chunk_id == "CWE-502#000"
    assert [item.evidence_id for item in package.evidence] == [
        f"EV-{index:04d}" for index in range(1, 7)
    ]
    assert len(package.citations) == len(package.evidence)
    assert package.timings[0].stage == "evidence"
    query, kwargs = retriever.calls[0]
    assert "CWE-502" in query
    assert kwargs == {"k": 3, "mode": "hybrid", "pool": 50, "alpha": 0.5}


def test_every_mapping_and_context_resolves_to_its_source(tmp_path):
    agent, _ = make_agent(tmp_path)
    package = agent.investigate(InvestigateRequest(query=CVE_ID))
    by_id = {item.evidence_id: item for item in package.evidence}
    mapping = package.attack_mapping[0]
    assert by_id[mapping.evidence_id].source == "ATTACK"
    context = package.contexts[0]
    assert by_id[context.evidence_id].source == "CWE"
    assert by_id[context.evidence_id].source_url.endswith("/502.html")


@pytest.mark.parametrize(
    "query",
    ["Investigate Log4Shell", f"Compare {CVE_ID} with CVE-2021-45046"],
)
def test_requires_exactly_one_distinct_cve(tmp_path, query):
    agent, _ = make_agent(tmp_path)
    with pytest.raises(ValueError, match="exactly one distinct CVE"):
        agent.investigate(InvestigateRequest(query=query))


def test_aged_kev_snapshot_is_used_when_dated_before_investigation(tmp_path):
    agent, _ = make_agent(tmp_path, released="2026-10-01T00:00:00Z")
    package = agent.investigate(InvestigateRequest(query=CVE_ID))
    assert package.kev.status == "known_exploited"
    assert package.kev.date_added is not None
    assert package.affected_products == ["Apache Log4j2"]
    assert any(item.source == "CISA_KEV" for item in package.evidence)
    assert not any("stale" in item for item in package.limitations)


def test_fresh_kev_absence_is_not_listed(tmp_path):
    agent, _ = make_agent(tmp_path, kev_rows=[])
    package = agent.investigate(InvestigateRequest(query=CVE_ID))
    assert package.kev.status == "not_listed"
    kev_evidence = next(item for item in package.evidence if item.claim_type == "kev")
    assert "not listed" in kev_evidence.claim
    assert package.affected_products == ["apache log4j"]


def test_retrieval_retries_once_when_relevance_review_rejects_first_results(tmp_path):
    agent, retriever = make_agent(tmp_path)
    reviews = iter(
        [
            {"sufficient": False, "refined_query": "Log4j secure configuration"},
            {"sufficient": True, "refined_query": None},
        ]
    )
    contexts, meta = agent._collect_context(
        InvestigateRequest(query=f"How do I remediate {CVE_ID}?"),
        CVE_ID,
        nvd_cve(),
        EvidenceWriter(NOW),
        [],
        retrieval_reviewer=lambda query, rows: next(reviews),
    )
    assert len(retriever.calls) == 2
    assert len(contexts) == 1
    assert meta["retry_used"] is True
    assert meta["review"]["sufficient"] is True


def test_missing_nvd_cache_does_not_claim_cve_absence(tmp_path):
    agent, retriever = make_agent(tmp_path)
    (tmp_path / "data" / "raw" / "nvd" / f"{CVE_ID}.json").write_text(
        json.dumps({"vulnerabilities": []}), encoding="utf-8"
    )
    package = agent.investigate(InvestigateRequest(query=CVE_ID))
    assert package.cve is None
    assert "does not establish that the CVE does not exist" in package.limitations[0]
    assert package.kev.status == "known_exploited"
    assert len(retriever.calls) == 1


def test_attack_collection_can_be_disabled_without_losing_retrieval(tmp_path):
    agent, _ = make_agent(tmp_path)
    package = agent.investigate(InvestigateRequest(query=CVE_ID, include_attack=False))
    assert package.attack_mapping == []
    assert not any(item.claim_type == "attack" for item in package.evidence)
    assert len(package.contexts) == 1


def reference_chunk(chunk_id="NVDREF-abc123def456#000", cve_ids=None, text=None):
    return {
        "chunk_id": chunk_id,
        "doc_id": chunk_id.split("#")[0],
        "source": "nvd_reference",
        "cve_ids": cve_ids if cve_ids is not None else [CVE_ID],
        "url": "https://www.cisa.gov/news-events/alerts/2021/12/11/apache-log4j2",
        "title": "Apache Log4j2 advisory",
        "ordinal": 0,
        "chunks_in_doc": 1,
        "text": text or "Upgrade Log4j to 2.15.0. Mitigation: restrict JNDI lookups and apply vendor guidance.",
        "start": 0,
        "end": 120,
        "chars": 120,
        "tokens_est": 30,
        "oversized": False,
    }


def write_reference_store(tmp_path, rows):
    write_jsonl(tmp_path / "data" / "processed" / "reference_chunks.jsonl", rows)


def test_reference_chunks_precede_generic_corpus_results(tmp_path):
    write_reference_store(tmp_path, [reference_chunk()])
    agent, retriever = make_agent(tmp_path)
    package = agent.investigate(InvestigateRequest(query=CVE_ID))
    assert package.contexts[0].chunk_id == "NVDREF-abc123def456#000"
    reference_evidence = next(item for item in package.evidence if item.source == "NVD_REF")
    assert reference_evidence.source == "NVD_REF"
    assert reference_evidence.claim_type == "remediation"
    assert reference_evidence.source_url == "https://www.cisa.gov/news-events/alerts/2021/12/11/apache-log4j2"
    assert any("snapshot copies" in item for item in package.limitations)
    assert len(retriever.calls) == 1


def test_reference_store_absent_falls_back_to_generic_only(tmp_path):
    agent, retriever = make_agent(tmp_path)
    package = agent.investigate(InvestigateRequest(query=CVE_ID))
    assert not any(item.source == "NVD_REF" for item in package.evidence)
    assert [item.chunk_id for item in package.contexts] == ["CWE-502#000"]
    assert len(retriever.calls) == 1


def test_reference_chunks_for_other_cves_are_ignored(tmp_path):
    write_reference_store(tmp_path, [reference_chunk(cve_ids=["CVE-9999-0001"])])
    agent, retriever = make_agent(tmp_path)
    package = agent.investigate(InvestigateRequest(query=CVE_ID))
    assert not any(item.source == "NVD_REF" for item in package.evidence)
    assert [item.chunk_id for item in package.contexts] == ["CWE-502#000"]
    assert len(retriever.calls) == 1


def test_reference_retriever_scopes_and_ranks(tmp_path):
    from app.retrieval import ReferenceRetriever

    store = tmp_path / "store.jsonl"
    write_jsonl(
        store,
        [
            reference_chunk(
                chunk_id="NVDREF-a1#000",
                text="Upgrade Log4j to 2.15.0 and restrict JNDI lookups immediately.",
            ),
            reference_chunk(
                chunk_id="NVDREF-b2#000",
                text="The advisory discusses vendor release history only.",
            ),
        ],
    )
    retriever = ReferenceRetriever(store)
    assert retriever.has_cve(CVE_ID) is True
    assert retriever.has_cve("CVE-9999-0001") is False
    ranked = retriever.search_for_cve(CVE_ID, "upgrade log4j JNDI restrict", k=2)
    assert [row["chunk_id"] for row in ranked] == ["NVDREF-a1#000"]
    assert retriever.search_for_cve(CVE_ID, "quantum flute", k=2) == []
    missing = ReferenceRetriever(tmp_path / "not_there.jsonl")
    assert missing.has_cve(CVE_ID) is False
    assert missing.search_for_cve(CVE_ID, "anything", k=2) == []


def test_retrieval_caps_at_three_search_rounds(tmp_path):
    agent, retriever = make_agent(tmp_path)
    counter = iter(range(10))
    reviews = [
        {"sufficient": False, "refined_query": f"refined attempt {next(counter)}"}
        for _ in range(10)
    ]
    reviewer = iter(reviews)
    contexts, meta = agent._collect_context(
        InvestigateRequest(query=f"How do I remediate {CVE_ID}?"),
        CVE_ID,
        nvd_cve(),
        EvidenceWriter(NOW),
        [],
        retrieval_reviewer=lambda query, rows: next(reviewer),
    )
    assert len(retriever.calls) == 3
    assert len(meta["queries"]) == 3
    assert meta["queries"][1:] == ["refined attempt 0", "refined attempt 1"]
    assert meta["retry_used"] is True
    assert meta["review"]["sufficient"] is False


def test_retrieval_caps_at_three_search_rounds_records_limitation(tmp_path):
    agent, retriever = make_agent(tmp_path)
    counter = iter(range(10))
    reviews = iter(
        [
            {"sufficient": False, "refined_query": f"refined attempt {next(counter)}"}
            for _ in range(10)
        ]
    )
    limitations: list[str] = []
    agent._collect_context(
        InvestigateRequest(query=f"How do I remediate {CVE_ID}?"),
        CVE_ID,
        nvd_cve(),
        EvidenceWriter(NOW),
        limitations,
        retrieval_reviewer=lambda query, rows: next(reviews),
    )
    assert any("after 3 search rounds" in item for item in limitations)


def test_retrieval_stops_when_reviewer_repeats_the_same_refined_query(tmp_path):
    agent, retriever = make_agent(tmp_path)
    reviews = iter(
        [{"sufficient": False, "refined_query": "same refined query"} for _ in range(10)]
    )
    contexts, meta = agent._collect_context(
        InvestigateRequest(query=f"How do I remediate {CVE_ID}?"),
        CVE_ID,
        nvd_cve(),
        EvidenceWriter(NOW),
        [],
        retrieval_reviewer=lambda query, rows: next(reviews),
    )
    assert len(retriever.calls) == 2
    assert meta["queries"] == [meta["queries"][0], "same refined query"]
