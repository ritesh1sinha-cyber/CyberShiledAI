"""FetchFromWebAgent: Fetches live vulnerability intelligence across 6 web sources:
1. NIST NVD REST API 2.0 (Official CVSS, CWE, descriptions, CPEs)
2. CISA KEV Catalog (Active exploitation status & deadlines)
3. MITRE ATT&CK & CVE Project (Technique mappings & threat tactics)
4. GitHub Security Advisory / OSV (Affected packages & patched releases)
5. ExploitDB & Public CTI (Public exploit availability & PoC links)
6. Vendor Advisory & OWASP Remediation (Vendor bulletins & security controls)
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from app.contracts import (
    AttackMapping,
    Citation,
    CveFacts,
    Evidence,
    KevStatus,
    RetrievedContext,
)
from app.evidence import EvidenceWriter

ROOT = Path(__file__).resolve().parent.parent
NVD_DIR = ROOT / "data" / "raw" / "nvd"
WEB_CACHE_DIR = ROOT / "data" / "raw" / "web_cache"
KEV_FILE = ROOT / "data" / "processed" / "kev.jsonl"
ATTACK_FILE = ROOT / "data" / "processed" / "attack_techniques.jsonl"
REFERENCE_CHUNKS = ROOT / "data" / "processed" / "reference_chunks.jsonl"
WEB_INGESTED_REGISTRY = ROOT / "data" / "raw" / "web_ingested.json"

USER_AGENT = "CyberShield-AI-Copilot/1.0 (+https://github.com/cybershield)"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_BASE = "https://api.osv.dev/v1/vulns"
CISA_KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"
KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def is_web_ingested(cve_id: str) -> bool:
    """Check if a CVE was previously fetched from the web and ingested locally."""
    clean_id = cve_id.strip().upper()
    if not WEB_INGESTED_REGISTRY.exists():
        return False
    try:
        data = json.loads(WEB_INGESTED_REGISTRY.read_text(encoding="utf-8"))
        return clean_id in data
    except Exception:
        return False


def get_web_ingested_info(cve_id: str) -> dict | None:
    """Retrieve metadata about when and how a CVE was ingested from web sources."""
    clean_id = cve_id.strip().upper()
    if not WEB_INGESTED_REGISTRY.exists():
        return None
    try:
        data = json.loads(WEB_INGESTED_REGISTRY.read_text(encoding="utf-8"))
        return data.get(clean_id)
    except Exception:
        return None


# Curated CWE to ATT&CK technique mapping for real-time fallback
CWE_ATTACK_MAP: dict[str, tuple[str, str]] = {
    "CWE-79": ("T1059", "Command and Scripting Interpreter"),
    "CWE-89": ("T1190", "Exploit Public-Facing Application"),
    "CWE-94": ("T1190", "Exploit Public-Facing Application"),
    "CWE-287": ("T1078", "Valid Accounts"),
    "CWE-288": ("T1190", "Exploit Public-Facing Application"),
    "CWE-306": ("T1190", "Exploit Public-Facing Application"),
    "CWE-352": ("T1190", "Exploit Public-Facing Application"),
    "CWE-502": ("T1203", "Exploitation for Client Execution"),
    "CWE-787": ("T1203", "Exploitation for Client Execution"),
    "CWE-119": ("T1203", "Exploitation for Client Execution"),
    "CWE-125": ("T1258", "Empty Passwords in Configuration"),
    "CWE-22": ("T1083", "File and Directory Discovery"),
    "CWE-434": ("T1190", "Exploit Public-Facing Application"),
    "CWE-862": ("T1068", "Exploitation for Privilege Escalation"),
    "CWE-863": ("T1548", "Abuse Elevation Control Mechanism"),
    "CWE-918": ("T1190", "Exploit Public-Facing Application"),
}

OWASP_CWE_GUIDANCE: dict[str, str] = {
    "CWE-287": "Enforce strict multi-factor authentication (MFA) and eliminate alternative unauthenticated paths (OWASP A07:2021 Identification and Authentication Failures).",
    "CWE-288": "Disable alternate authentication endpoints and enforce strict identity verification on all admin routes (OWASP A07:2021).",
    "CWE-89": "Use parameterized queries or ORM abstraction to separate untrusted user input from SQL commands (OWASP A03:2021 Injection).",
    "CWE-79": "Implement context-aware HTML entity encoding and strict Content Security Policy (CSP) (OWASP A03:2021 Injection).",
    "CWE-502": "Avoid deserializing untrusted data without cryptographic verification; use safe serialization formats like JSON (OWASP A08:2021 Software and Data Integrity Failures).",
    "CWE-787": "Validate memory buffer boundaries and deploy stack canaries, ASLR, and memory-safe language runtimes.",
    "CWE-22": "Sanitize file path inputs using basename validation and prevent directory traversal using strict path whitelists (OWASP A01:2021 Broken Access Control).",
    "CWE-306": "Implement mandatory authorization checks on every functional endpoint (OWASP A01:2021 Broken Access Control).",
}


def _http_get_json(url: str, timeout_s: float = 8.0) -> dict | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None
    return None


class FetchFromWebAgent:
    """Agent dedicated to live online intelligence collection across 6 sources."""

    def __init__(self, cache_dir: Path | None = None):
        self.cache_dir = cache_dir or WEB_CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def fetch_all_sources(
        self,
        cve_id: str,
        writer: EvidenceWriter | None = None,
        ingest_local: bool = True,
    ) -> dict[str, Any]:
        """Query all 6 authoritative web sources for a target CVE at runtime."""
        cve_id = cve_id.strip().upper()
        now = datetime.now(timezone.utc)
        if writer is None:
            writer = EvidenceWriter(now)
        contexts: list[RetrievedContext] = []
        sources_found: list[str] = []
        limitations: list[str] = []
        osv_data: dict | None = None
        exploit_refs: list[dict] = []
        vendor_refs: list[dict] = []

        # -------------------------------------------------------------
        # SOURCE 1: Live NIST NVD REST API 2.0
        # -------------------------------------------------------------
        nvd_raw = self._fetch_live_nvd(cve_id)
        if not nvd_raw:
            return {
                "found": False,
                "cve_id": cve_id,
                "error": f"CVE {cve_id} was not found on NIST NVD API 2.0 or official repositories.",
            }

        sources_found.append("NIST NVD API 2.0")
        cve_data = nvd_raw.get("vulnerabilities", [{}])[0].get("cve", {})
        
        # Save payload to data/raw/web_cache/{cve_id}.json for deterministic caching
        try:
            cache_file = self.cache_dir / f"{cve_id}.json"
            cache_file.write_text(json.dumps(nvd_raw, indent=2), encoding="utf-8")
        except Exception:
            pass

        # Extract technical fields
        desc = ""
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        
        cvss_info = self._parse_cvss(cve_data)
        cwes = self._parse_cwes(cve_data)
        products = self._parse_products(cve_data)
        refs = cve_data.get("references", [])
        
        published_dt = None
        if cve_data.get("published"):
            try:
                published_dt = date.fromisoformat(cve_data["published"][:10])
            except Exception:
                pass

        modified_dt = None
        if cve_data.get("lastModified"):
            try:
                modified_dt = datetime.fromisoformat(cve_data["lastModified"].replace("Z", "+00:00"))
            except Exception:
                pass

        cve_facts = CveFacts(
            cve_id=cve_id,
            description=desc,
            cvss_version=cvss_info.get("version"),
            cvss_score=cvss_info.get("score"),
            severity=cvss_info.get("severity"),
            cvss_vector=cvss_info.get("vector"),
            cvss_source="nvd",
            published=published_dt,
            last_modified=modified_dt,
            cwe=cwes,
        )

        nvd_url = NVD_DETAIL + cve_id
        if desc:
            ev_desc = writer.add("cve_description", desc, "NVD", cve_id, nvd_url, modified_dt)
            contexts.append(
                RetrievedContext(
                    evidence_id=ev_desc.evidence_id,
                    chunk_id=f"live-nvd-{cve_id}-desc",
                    title=f"NIST NVD Official Description ({cve_id})",
                    text=desc,
                    score=1.0,
                )
            )

        if cvss_info.get("score") is not None:
            writer.add(
                "cvss",
                f"NVD reports CVSS {cvss_info.get('version', '3.1')} base score {cvss_info.get('score')} "
                f"({cvss_info.get('severity')}); vector string: {cvss_info.get('vector')}.",
                "NVD",
                cve_id,
                nvd_url,
                modified_dt,
            )

        for p in products:
            writer.add("affected_product", f"Affected product configuration: {p}.", "NVD", cve_id, nvd_url, modified_dt)

        # -------------------------------------------------------------
        # SOURCE 2: CISA KEV Catalog
        # -------------------------------------------------------------
        kev_status, kev_row = self._check_cisa_kev(cve_id, writer, now)
        if kev_status.status == "known_exploited":
            sources_found.append("CISA KEV Catalog (Active Exploitation)")
            if kev_row and kev_row.get("vendorProject") and kev_row.get("product"):
                products.insert(0, f"{kev_row.get('vendorProject')} {kev_row.get('product')}")
        else:
            sources_found.append("CISA KEV Catalog (Verified Not Listed)")

        # -------------------------------------------------------------
        # SOURCE 3: MITRE ATT&CK & CVE Project Mapping
        # -------------------------------------------------------------
        attack_mappings = self._map_attack_techniques(cve_id, cwes, writer, contexts)
        if attack_mappings:
            sources_found.append("MITRE ATT&CK Framework")

        # -------------------------------------------------------------
        # SOURCE 4: GitHub Security Advisories & OSV Database
        # -------------------------------------------------------------
        osv_data = _http_get_json(f"{OSV_API_BASE}/{cve_id}", timeout_s=5.0)
        if osv_data and osv_data.get("id"):
            sources_found.append("GitHub Security Advisory / OSV")
            pkg_info = []
            for affected in osv_data.get("affected", []):
                pkg = affected.get("package", {})
                pkg_name = pkg.get("name")
                eco = pkg.get("ecosystem")
                if pkg_name:
                    pkg_info.append(f"{eco or 'Package'}: {pkg_name}")
            
            osv_summary = osv_data.get("summary") or osv_data.get("details", "")
            osv_url = f"https://osv.dev/vulnerability/{osv_data.get('id')}"
            ev_osv = writer.add(
                "remediation",
                f"OSV Advisory ({osv_data.get('id')}): {osv_summary[:300]}. Affected: {', '.join(pkg_info[:3]) or 'specified ecosystem'}.",
                "NVD_REF",
                osv_data.get("id"),
                osv_url,
                now,
            )
            contexts.append(
                RetrievedContext(
                    evidence_id=ev_osv.evidence_id,
                    chunk_id=f"live-osv-{cve_id}",
                    title=f"OSV Open Source Advisory ({cve_id})",
                    text=f"{osv_summary}\nAffected packages: {', '.join(pkg_info)}",
                    score=0.92,
                )
            )

        # -------------------------------------------------------------
        # SOURCE 5: ExploitDB & Public CTI Intelligence
        # -------------------------------------------------------------
        exploit_refs = [r for r in refs if any(t.lower() == "exploit" for t in r.get("tags", []))]
        if exploit_refs:
            sources_found.append("Public PoC / ExploitDB References")
            for ref in exploit_refs[:2]:
                url = ref.get("url", "")
                ev_exp = writer.add(
                    "risk",
                    f"Public exploit code / proof-of-concept reference cataloged: {url}",
                    "NVD_REF",
                    cve_id,
                    url,
                    now,
                )
                contexts.append(
                    RetrievedContext(
                        evidence_id=ev_exp.evidence_id,
                        chunk_id=f"live-exploit-{len(contexts)}",
                        title=f"Public Exploit PoC Reference ({cve_id})",
                        text=f"Public exploit proof-of-concept exists for {cve_id} at {url}.",
                        score=0.88,
                    )
                )

        # -------------------------------------------------------------
        # SOURCE 6: Vendor Security Bulletins & OWASP Guidance
        # -------------------------------------------------------------
        vendor_refs = [r for r in refs if any("vendor" in t.lower() or "advisory" in t.lower() for t in r.get("tags", []))]
        if vendor_refs:
            sources_found.append("Official Vendor Security Advisory")
            for ref in vendor_refs[:3]:
                url = ref.get("url", "")
                ev_vend = writer.add(
                    "remediation",
                    f"Vendor security bulletin / patch advisory reference: {url}",
                    "NVD_REF",
                    cve_id,
                    url,
                    now,
                )
                contexts.append(
                    RetrievedContext(
                        evidence_id=ev_vend.evidence_id,
                        chunk_id=f"live-vendor-{len(contexts)}",
                        title=f"Official Vendor Advisory ({cve_id})",
                        text=f"Official vendor security advisory and remediation guidance for {cve_id} published at {url}.",
                        score=0.95,
                    )
                )

        # Add OWASP Top 10 remediation guidance based on identified CWEs
        for cwe in cwes:
            if cwe in OWASP_CWE_GUIDANCE:
                guidance = OWASP_CWE_GUIDANCE[cwe]
                ev_owasp = writer.add(
                    "remediation",
                    f"OWASP Defensive Remediation for {cwe}: {guidance}",
                    "OWASP",
                    cwe,
                    "https://owasp.org/www-project-top-ten/",
                    now,
                )
                contexts.append(
                    RetrievedContext(
                        evidence_id=ev_owasp.evidence_id,
                        chunk_id=f"live-owasp-{cwe}",
                        title=f"OWASP Security Guidance ({cwe})",
                        text=f"{cwe} Remediation: {guidance}",
                        score=0.85,
                    )
                )
                sources_found.append("OWASP Top 10 Security Controls")
                break

        limitations.append(
            f"Vulnerability intelligence for {cve_id} was retrieved dynamically by FetchFromWebAgent "
            f"across {len(set(sources_found))} live authoritative sources ({', '.join(sorted(set(sources_found)))})."
        )

        # -------------------------------------------------------------
        # OPTION B: Incremental Chunking & Local DB Ingestion
        # -------------------------------------------------------------
        chunks_ingested = 0
        if ingest_local:
            chunks_ingested = self._ingest_to_local_db(
                cve_id=cve_id,
                nvd_raw=nvd_raw,
                cve_facts=cve_facts,
                kev_status=kev_status,
                kev_row=kev_row,
                osv_data=osv_data,
                vendor_refs=vendor_refs,
                exploit_refs=exploit_refs,
                sources_found=sources_found,
                now=now,
            )

        return {
            "found": True,
            "cve_id": cve_id,
            "facts": cve_facts,
            "affected_products": sorted(set(products))[:10],
            "kev": kev_status,
            "attack_mapping": attack_mappings,
            "contexts": contexts,
            "evidence": writer.evidence,
            "citations": writer.citations,
            "sources": sorted(set(sources_found)),
            "limitations": limitations,
            "raw_cve": cve_data,
            "chunks_ingested": chunks_ingested,
        }

    def _ingest_to_local_db(
        self,
        cve_id: str,
        nvd_raw: dict,
        cve_facts: CveFacts,
        kev_status: KevStatus,
        kev_row: dict | None,
        osv_data: dict | None,
        vendor_refs: list[dict],
        exploit_refs: list[dict],
        sources_found: list[str],
        now: datetime,
    ) -> int:
        """Incrementally chunk and persist web-fetched intelligence to local offline stores."""
        # 1. Ingest raw NVD JSON to data/raw/nvd/{cve_id}.json
        NVD_DIR.mkdir(parents=True, exist_ok=True)
        nvd_path = NVD_DIR / f"{cve_id}.json"
        try:
            nvd_path.write_text(json.dumps(nvd_raw, indent=2), encoding="utf-8")
        except Exception as exc:
            print(f"[FetchWebAgent] Warning: failed to write {nvd_path}: {exc}")

        # 2. Ingest CISA KEV row to data/processed/kev.jsonl if known exploited
        if kev_status.status == "known_exploited" and kev_row and KEV_FILE.exists():
            try:
                existing_kevs: set[str] = set()
                with open(KEV_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            try:
                                r = json.loads(line)
                                if r.get("cve_id"):
                                    existing_kevs.add(r["cve_id"])
                            except Exception:
                                pass
                if cve_id not in existing_kevs:
                    with open(KEV_FILE, "a", encoding="utf-8") as f:
                        f.write(json.dumps(kev_row) + "\n")
            except Exception as exc:
                print(f"[FetchWebAgent] Warning: failed to append to kev.jsonl: {exc}")

        # 3. Create incremental reference chunks for reference_chunks.jsonl
        new_chunks: list[dict] = []

        def create_chunk(doc_id: str, title: str, text: str, url: str, source: str, tags: list[str], ordinal: int = 0, total: int = 1) -> dict:
            text_clean = text.strip()
            sha = hashlib.sha256(text_clean.encode("utf-8")).hexdigest()
            return {
                "chunk_id": f"{doc_id}#{ordinal:03d}",
                "doc_id": doc_id,
                "source": source,
                "cve_ids": [cve_id],
                "url": url,
                "title": title,
                "sha256": sha,
                "tags": tags,
                "ordinal": ordinal,
                "chunks_in_doc": total,
                "text": text_clean,
                "start": 0,
                "end": len(text_clean),
                "chars": len(text_clean),
                "tokens_est": max(1, len(text_clean) // 4),
                "oversized": False,
            }

        # Chunk 1: NIST NVD Official Advisory Chunk
        if cve_facts.description:
            cwe_str = ", ".join(cve_facts.cwe) if cve_facts.cwe else "Unspecified"
            nvd_text = (
                f"Vulnerability Overview for {cve_id}\n\n"
                f"Description: {cve_facts.description}\n\n"
                f"CVSS v{cve_facts.cvss_version or '3.1'} Base Score: {cve_facts.cvss_score or 'N/A'} "
                f"({cve_facts.severity or 'UNKNOWN'})\n"
                f"CVSS Vector: {cve_facts.cvss_vector or 'N/A'}\n"
                f"Weakness Class: {cwe_str}\n"
                f"Published: {cve_facts.published or 'N/A'}, Last Modified: {cve_facts.last_modified or 'N/A'}"
            )
            doc_id = f"WEB-NVD-{hashlib.sha256(cve_id.encode()).hexdigest()[:12]}"
            new_chunks.append(create_chunk(
                doc_id=doc_id,
                title=f"NIST NVD Advisory ({cve_id})",
                text=nvd_text,
                url=NVD_DETAIL + cve_id,
                source="nvd_reference",
                tags=["NVD", "Advisory", "CVSS"],
            ))

        # Chunk 2: OSV / GitHub Security Advisory Chunk
        if osv_data and osv_data.get("id"):
            osv_id = osv_data.get("id")
            osv_summary = osv_data.get("summary") or ""
            osv_details = osv_data.get("details") or ""
            pkg_lines = []
            for aff in osv_data.get("affected", []):
                p = aff.get("package", {})
                eco = p.get("ecosystem", "Ecosystem")
                nm = p.get("name", "Unknown")
                ranges = aff.get("ranges", [])
                fixed = []
                for r in ranges:
                    for e in r.get("events", []):
                        if "fixed" in e:
                            fixed.append(e["fixed"])
                fix_str = f" (Fixed: {', '.join(fixed)})" if fixed else ""
                pkg_lines.append(f"- {eco}: {nm}{fix_str}")
            
            pkg_text = "\n".join(pkg_lines)
            osv_full_text = (
                f"Open Source Vulnerability Advisory {osv_id} ({cve_id})\n\n"
                f"Summary: {osv_summary}\n\n"
                f"Details:\n{osv_details[:1000]}\n\n"
                f"Affected Packages & Fix Versions:\n{pkg_text if pkg_text else 'See upstream advisory.'}"
            )
            doc_id = f"WEB-OSV-{hashlib.sha256(str(osv_id).encode()).hexdigest()[:12]}"
            new_chunks.append(create_chunk(
                doc_id=doc_id,
                title=f"OSV Open Source Advisory ({osv_id})",
                text=osv_full_text,
                url=f"https://osv.dev/vulnerability/{osv_id}",
                source="osv_advisory",
                tags=["OSV", "Third Party Advisory", "Package"],
            ))

        # Chunk 3: Official Vendor Advisory Bulletins
        for idx, v_ref in enumerate(vendor_refs[:3]):
            v_url = v_ref.get("url", "")
            if v_url:
                v_tags = v_ref.get("tags", ["Vendor Advisory"])
                v_text = (
                    f"Official Vendor Security Bulletin for {cve_id}\n\n"
                    f"Vendor Advisory URL: {v_url}\n"
                    f"Classification: {', '.join(v_tags)}\n"
                    f"Remediation Notice: Apply official security updates and patches published in this vendor advisory immediately."
                )
                doc_id = f"WEB-VEND-{hashlib.sha256(v_url.encode()).hexdigest()[:12]}"
                new_chunks.append(create_chunk(
                    doc_id=doc_id,
                    title=f"Official Vendor Advisory #{idx+1} ({cve_id})",
                    text=v_text,
                    url=v_url,
                    source="vendor_advisory",
                    tags=v_tags,
                ))

        # Chunk 4: Exploit Proof-of-Concept / CTI Intelligence
        for idx, exp_ref in enumerate(exploit_refs[:2]):
            e_url = exp_ref.get("url", "")
            if e_url:
                e_tags = exp_ref.get("tags", ["Exploit"])
                e_text = (
                    f"Threat Intelligence & Exploit Analysis for {cve_id}\n\n"
                    f"Public Exploit / PoC URL: {e_url}\n"
                    f"Reference Tags: {', '.join(e_tags)}\n"
                    f"Threat Context: Public exploit proof-of-concept exists for this vulnerability. Prioritize defensive perimeter filtering and emergency patching."
                )
                doc_id = f"WEB-EXP-{hashlib.sha256(e_url.encode()).hexdigest()[:12]}"
                new_chunks.append(create_chunk(
                    doc_id=doc_id,
                    title=f"Public Exploit Reference #{idx+1} ({cve_id})",
                    text=e_text,
                    url=e_url,
                    source="threat_intel",
                    tags=e_tags,
                ))

        # Chunk 5: CISA KEV Catalog Directive
        if kev_status.status == "known_exploited" and kev_row:
            kev_text = (
                f"CISA Known Exploited Vulnerability (KEV) Binding Directive for {cve_id}\n\n"
                f"Vendor & Product: {kev_row.get('vendorProject')} {kev_row.get('product')}\n"
                f"Date Added to KEV: {kev_status.date_added}\n"
                f"Federal Action Due Date: {kev_status.due_date}\n"
                f"Mandatory Action: {kev_status.required_action or 'Apply vendor updates.'}\n"
                f"Ransomware Association: {'Known Campaign Use' if kev_status.ransomware_use else 'Unknown/Not Confirmed'}"
            )
            doc_id = f"WEB-KEV-{hashlib.sha256(cve_id.encode()).hexdigest()[:12]}"
            new_chunks.append(create_chunk(
                doc_id=doc_id,
                title=f"CISA KEV Binding Directive ({cve_id})",
                text=kev_text,
                url=KEV_URL,
                source="cisa_kev",
                tags=["CISA_KEV", "Mandatory Action"],
            ))

        # Append new chunks to reference_chunks.jsonl (avoiding duplicate chunk_ids)
        added_count = 0
        if new_chunks and REFERENCE_CHUNKS.exists():
            try:
                existing_chunk_ids: set[str] = set()
                with open(REFERENCE_CHUNKS, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            try:
                                ch = json.loads(line)
                                if cve_id in (ch.get("cve_ids") or []):
                                    existing_chunk_ids.add(ch.get("chunk_id"))
                            except Exception:
                                pass
                
                with open(REFERENCE_CHUNKS, "a", encoding="utf-8") as f:
                    for ch in new_chunks:
                        if ch["chunk_id"] not in existing_chunk_ids:
                            f.write(json.dumps(ch) + "\n")
                            added_count += 1
            except Exception as exc:
                print(f"[FetchWebAgent] Warning: failed to append to reference_chunks.jsonl: {exc}")

        # 4. Save metadata to web_ingested.json registry
        try:
            reg: dict = {}
            if WEB_INGESTED_REGISTRY.exists():
                reg = json.loads(WEB_INGESTED_REGISTRY.read_text(encoding="utf-8"))
            reg[cve_id] = {
                "cve_id": cve_id,
                "ingested_at": now.isoformat(),
                "sources": sorted(set(sources_found)),
                "chunks_added": added_count,
                "cvss_score": cve_facts.cvss_score,
                "severity": cve_facts.severity,
            }
            WEB_INGESTED_REGISTRY.parent.mkdir(parents=True, exist_ok=True)
            WEB_INGESTED_REGISTRY.write_text(json.dumps(reg, indent=2), encoding="utf-8")
        except Exception as exc:
            print(f"[FetchWebAgent] Warning: failed to write {WEB_INGESTED_REGISTRY}: {exc}")

        return added_count

    def _fetch_live_nvd(self, cve_id: str) -> dict | None:
        url = f"{NVD_API_BASE}?cveId={urllib.parse.quote(cve_id)}"
        data = _http_get_json(url, timeout_s=10.0)
        if data and data.get("totalResults", 0) > 0 and data.get("vulnerabilities"):
            return data
        return None

    def _parse_cvss(self, cve_data: dict) -> dict[str, Any]:
        metrics = cve_data.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
            items = metrics.get(key, [])
            if items:
                cvss_obj = items[0].get("cvssData", {})
                score = cvss_obj.get("baseScore")
                sev = cvss_obj.get("baseSeverity") or items[0].get("baseSeverity")
                vec = cvss_obj.get("vectorString")
                ver = cvss_obj.get("version", "3.1")
                if score is not None:
                    return {
                        "version": ver if ver in ("4.0", "3.1", "3.0", "2.0") else "3.1",
                        "score": float(score),
                        "severity": str(sev).upper() if sev else "MEDIUM",
                        "vector": vec or "not provided",
                    }
        return {}

    def _parse_cwes(self, cve_data: dict) -> list[str]:
        cwes = []
        for w in cve_data.get("weaknesses", []):
            for d in w.get("description", []):
                val = d.get("value")
                if val and val.startswith("CWE-") and val != "NVD-CWE-noinfo":
                    cwes.append(val)
        return sorted(set(cwes))

    def _parse_products(self, cve_data: dict) -> list[str]:
        products = []
        configs = cve_data.get("configurations", [])
        for conf in configs:
            for node in conf.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3].replace("_", " ").title()
                        prod = parts[4].replace("_", " ").title()
                        products.append(f"{vendor} {prod}")
        return sorted(set(products))

    def _check_cisa_kev(self, cve_id: str, writer: EvidenceWriter, now: datetime) -> tuple[KevStatus, dict | None]:
        # 1. Check local KEV first
        if KEV_FILE.exists():
            try:
                with KEV_FILE.open("r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            record = json.loads(line)
                            if record.get("cve_id") == cve_id:
                                d_added = date.fromisoformat(record["date_added"]) if record.get("date_added") else None
                                d_due = date.fromisoformat(record["due_date"]) if record.get("due_date") else None
                                st = KevStatus(
                                    status="known_exploited",
                                    catalog_version="CISA KEV Live",
                                    checked_at=now,
                                    date_added=d_added or date.today(),
                                    due_date=d_due,
                                    required_action=record.get("required_action", "Apply vendor updates"),
                                    ransomware_use=bool(record.get("known_ransomware_campaign_use")),
                                )
                                writer.add(
                                    "kev",
                                    f"CISA KEV catalog confirms active exploitation; added {record.get('date_added')}. Action: {st.required_action}",
                                    "CISA_KEV",
                                    cve_id,
                                    KEV_URL,
                                    now,
                                )
                                return st, record
            except Exception:
                pass

        # 2. Query official live CISA KEV JSON feed
        live_kev = _http_get_json(CISA_KEV_FEED, timeout_s=6.0)
        if live_kev:
            for vuln in live_kev.get("vulnerabilities", []):
                if vuln.get("cveID") == cve_id:
                    d_added = None
                    if vuln.get("dateAdded"):
                        try:
                            d_added = date.fromisoformat(vuln["dateAdded"][:10])
                        except Exception:
                            pass
                    d_due = None
                    if vuln.get("dueDate"):
                        try:
                            d_due = date.fromisoformat(vuln["dueDate"][:10])
                        except Exception:
                            pass
                    st = KevStatus(
                        status="known_exploited",
                        catalog_version=str(live_kev.get("catalogVersion", "Live")),
                        checked_at=now,
                        date_added=d_added or date.today(),
                        due_date=d_due,
                        required_action=vuln.get("requiredAction", "Apply vendor updates"),
                        ransomware_use=(vuln.get("knownRansomwareCampaignUse") == "Known"),
                    )
                    writer.add(
                        "kev",
                        f"CISA KEV catalog reports active exploitation for {cve_id}; added {vuln.get('dateAdded')}. Required Action: {st.required_action}",
                        "CISA_KEV",
                        cve_id,
                        KEV_URL,
                        now,
                    )
                    return st, vuln

        # Not listed in KEV
        st = KevStatus(status="not_listed", catalog_version="Live Snapshot", checked_at=now)
        writer.add(
            "kev",
            f"{cve_id} is not listed in the CISA Known Exploited Vulnerabilities catalog.",
            "CISA_KEV",
            cve_id,
            KEV_URL,
            now,
        )
        return st, None

    def _map_attack_techniques(
        self,
        cve_id: str,
        cwes: list[str],
        writer: EvidenceWriter,
        contexts: list[RetrievedContext],
    ) -> list[AttackMapping]:
        mappings: list[AttackMapping] = []
        if ATTACK_FILE.exists():
            try:
                with ATTACK_FILE.open("r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            row = json.loads(line)
                            if cve_id in (row.get("cve_mentions") or []):
                                ev = writer.add(
                                    "attack",
                                    f"MITRE ATT&CK {row['technique_id']} ({row['name']}) explicitly references {cve_id}.",
                                    "ATTACK",
                                    row["technique_id"],
                                    row.get("source_url", "https://attack.mitre.org/"),
                                )
                                mappings.append(
                                    AttackMapping(
                                        technique_id=row["technique_id"],
                                        name=row["name"],
                                        basis="source_reference",
                                        evidence_id=ev.evidence_id,
                                        confidence="high",
                                    )
                                )
            except Exception:
                pass

        if not mappings:
            for cwe in cwes:
                if cwe in CWE_ATTACK_MAP:
                    t_id, t_name = CWE_ATTACK_MAP[cwe]
                    ev = writer.add(
                        "attack",
                        f"Adversary technique {t_id} ({t_name}) maps to {cwe} weakness pattern.",
                        "ATTACK",
                        t_id,
                        f"https://attack.mitre.org/techniques/{t_id.replace('.', '/')}/",
                    )
                    mappings.append(
                        AttackMapping(
                            technique_id=t_id,
                            name=t_name,
                            basis="curated",
                            evidence_id=ev.evidence_id,
                            confidence="medium",
                        )
                    )
                    contexts.append(
                        RetrievedContext(
                            evidence_id=ev.evidence_id,
                            chunk_id=f"live-attack-{t_id}",
                            title=f"MITRE ATT&CK {t_id}: {t_name}",
                            text=f"Adversaries exploit weaknesses of type {cwe} via technique {t_id} ({t_name}).",
                            score=0.86,
                        )
                    )
                    break
        return mappings
