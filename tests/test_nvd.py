from app.nvd import pick_cvss, preferred_metric


def metric(source, score, severity, metric_type, version="3.1"):
    return {
        "source": source,
        "type": metric_type,
        "cvssData": {
            "version": version,
            "baseScore": score,
            "baseSeverity": severity,
            "vectorString": f"CVSS:{version}/AV:N/AC:L",
        },
    }


def cve(v31=None, v2=None):
    metrics = {}
    if v31 is not None:
        metrics["cvssMetricV31"] = v31
    if v2 is not None:
        metrics["cvssMetricV2"] = v2
    return {"id": "CVE-2000-0001", "metrics": metrics}


def test_primary_entry_wins_regardless_of_position():
    entries = [
        metric("secure@microsoft.com", 5.5, "MEDIUM", "Secondary"),
        metric("nvd@nist.gov", 10.0, "CRITICAL", "Primary"),
    ]
    assert preferred_metric(entries)["type"] == "Primary"
    assert pick_cvss(cve(v31=entries))["cvss_score"] == 10.0


def test_nvd_metric_preferred_when_no_entry_is_primary():
    # Observed for CVE-2020-1472, where both CVSS 3.1 metrics are Secondary.
    entries = [
        metric("secure@microsoft.com", 5.5, "MEDIUM", "Secondary"),
        metric("nvd@nist.gov", 10.0, "CRITICAL", "Secondary"),
    ]
    picked = pick_cvss(cve(v31=entries))
    assert picked["cvss_score"] == 10.0
    assert picked["severity"] == "CRITICAL"


def test_source_matching_ignores_case():
    entries = [
        metric("vendor@example.com", 9.1, "CRITICAL", "Secondary"),
        metric("NVD@nist.gov", 9.8, "CRITICAL", "Secondary"),
    ]
    assert pick_cvss(cve(v31=entries))["cvss_score"] == 9.8


def test_first_entry_kept_when_only_cna_secondaries_exist():
    entries = [
        metric("vendor@example.com", 7.0, "HIGH", "Secondary"),
        metric("other@example.com", 9.0, "CRITICAL", "Secondary"),
    ]
    assert pick_cvss(cve(v31=entries))["cvss_score"] == 7.0


def test_secondary_nvd_metric_in_v31_blocks_fallthrough_to_v2():
    entries = [
        metric("secure@microsoft.com", 9.1, "CRITICAL", "Secondary"),
        metric("nvd@nist.gov", 9.8, "CRITICAL", "Secondary"),
    ]
    picked = pick_cvss(
        cve(v31=entries, v2=[metric("nvd@nist.gov", 9.3, "HIGH", "Primary", version="2")])
    )
    assert picked["metric_key"] == "cvssMetricV31"
    assert picked["cvss_version"] == "3.1"
    assert picked["cvss_score"] == 9.8
