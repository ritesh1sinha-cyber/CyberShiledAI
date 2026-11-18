from collections import Counter


def severity_from_score(version: str, score: float) -> str:
    if version.startswith("2"):
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
    if score == 0.0:
        return "NONE"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


NVD_METRIC_SOURCE = "nvd@nist.gov"


def preferred_metric(entries: list[dict]) -> dict:
    # NVD sometimes lists only Secondary metrics, where entries[0] is the CNA's
    # (usually lower) score; prefer the NVD's own analysis over positional order.
    for is_preferred in (
        lambda m: m.get("type") == "Primary",
        lambda m: (m.get("source") or "").lower() == NVD_METRIC_SOURCE,
    ):
        match = next((entry for entry in entries if is_preferred(entry)), None)
        if match is not None:
            return match
    return entries[0]


def pick_cvss(cve: dict) -> dict | None:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = preferred_metric(entries)
        data = primary.get("cvssData") or {}
        version = str(data.get("version") or "")
        if version == "2":
            version = "2.0"
        score = data.get("baseScore")
        if score is None:
            continue
        severity = data.get("baseSeverity") or primary.get("baseSeverity")
        derived = False
        if not severity:
            severity = severity_from_score(version, float(score))
            derived = True
        return {
            "metric_key": key,
            "cvss_version": version,
            "cvss_score": float(score),
            "severity": severity,
            "cvss_vector": data.get("vectorString"),
            "cvss_source": "nvd" if primary.get("type") == "Primary" else "cna",
            "severity_derived": derived,
        }
    return None


def join_vendor_product(vendor: str, product: str) -> str:
    vendor, product = vendor.strip(), product.strip()
    if not vendor:
        return product
    if not product:
        return vendor
    if product.lower().startswith(vendor.lower()):
        return product
    return f"{vendor} {product}"


def cpe_products(cve: dict) -> list[str]:
    counts: Counter[tuple[str, str]] = Counter()
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable", True):
                    continue
                parts = (match.get("criteria") or "").split(":")
                if len(parts) >= 5 and parts[3] not in {"*", "-"}:
                    vendor = parts[3].replace("_", " ").strip()
                    product = parts[4].replace("_", " ").strip()
                    if product not in {"*", "-"}:
                        counts[(vendor, product)] += 1
    return [
        join_vendor_product(vendor, product)
        for (vendor, product), _ in counts.most_common(5)
    ]


def cwe_candidates(cve: dict) -> list[dict]:
    found: list[dict] = []
    seen = set()
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = desc.get("value") or ""
            if value.startswith("CWE-") and value not in seen:
                seen.add(value)
                found.append({"cwe_id": value, "nvd_source": weakness.get("source")})
    return found


def english_description(cve: dict) -> str | None:
    return next(
        (d["value"] for d in cve.get("descriptions") or [] if d.get("lang") == "en"),
        None,
    )


def select_remediation_cwe(f: dict, cwe: dict[str, dict]) -> tuple[str, dict, str | None]:
    candidates = sorted(
        f["cwe_candidates"], key=lambda item: item["nvd_source"] != "nvd@nist.gov"
    )
    for require_mitigation in (True, False):
        for candidate in candidates:
            row = cwe.get(candidate["cwe_id"])
            if row and (not require_mitigation or row.get("mitigations")):
                return candidate["cwe_id"], row, candidate["nvd_source"]
    candidate = candidates[0]
    return candidate["cwe_id"], {}, candidate["nvd_source"]
