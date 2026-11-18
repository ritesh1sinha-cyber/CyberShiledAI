"""Download, hash and normalise the static corpora the gold set depends on."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import sys
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
PROC = ROOT / "data" / "processed"
MAN = ROOT / "data" / "manifests"

SOURCES = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "attack": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "owasp": "https://codeload.github.com/OWASP/CheatSheetSeries/tar.gz/refs/heads/master",
    "cwe": "https://cwe.mitre.org/data/csv/1000.csv.zip",
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def download(url: str, dest: Path) -> None:
    if dest.exists() and dest.stat().st_size > 0:
        print(f"  cached  {dest.name} ({dest.stat().st_size / 1e6:.1f} MB)")
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    print(f"  fetching {dest.name} ...", end="", flush=True)
    with httpx.stream("GET", url, follow_redirects=True, timeout=180.0) as resp:
        resp.raise_for_status()
        with open(tmp, "wb") as handle:
            for chunk in resp.iter_bytes(65536):
                handle.write(chunk)
    tmp.replace(dest)
    print(f" {dest.stat().st_size / 1e6:.1f} MB")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_jsonl(path: Path, rows: list[dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return len(rows)


def process_kev() -> tuple[list[dict], dict]:
    data = json.loads((RAW / "kev" / "known_exploited_vulnerabilities.json").read_text("utf-8"))
    rows = []
    for item in data["vulnerabilities"]:
        rows.append(
            {
                "cve_id": item["cveID"],
                "vendor": item.get("vendorProject", ""),
                "product": item.get("product", ""),
                "name": item.get("vulnerabilityName", ""),
                "date_added": item.get("dateAdded"),
                "short_description": item.get("shortDescription", ""),
                "required_action": item.get("requiredAction", ""),
                "due_date": item.get("dueDate"),
                "ransomware": item.get("knownRansomwareCampaignUse", "Unknown"),
                "cwes": [c.strip() for c in (item.get("cwes") or []) if c.strip()],
                "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            }
        )
    version = {
        "catalog_version": data.get("catalogVersion"),
        "released": data.get("dateReleased"),
        "count": len(rows),
    }
    return rows, version


def process_attack() -> tuple[list[dict], dict]:
    bundle = json.loads((RAW / "attack" / "enterprise-attack.json").read_text("utf-8"))
    rows = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        refs = obj.get("external_references") or []
        ext = next((r for r in refs if r.get("source_name") == "mitre-attack"), None)
        if not ext or not ext.get("external_id"):
            continue
        technique_id = ext["external_id"]
        description = obj.get("description", "")
        tactics = [
            p.get("phase_name")
            for p in obj.get("kill_chain_phases") or []
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        rows.append(
            {
                "doc_id": f"ATTACK-{technique_id}",
                "technique_id": technique_id,
                "name": obj.get("name", ""),
                "description": description,
                "tactics": tactics,
                "platforms": obj.get("x_mitre_platforms") or [],
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
                "cve_mentions": sorted(set(CVE_RE.findall(description))),
                "source_url": ext.get("url")
                or f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
            }
        )
    rows.sort(key=lambda r: r["technique_id"])
    version = {
        "spec_version": bundle.get("spec_version"),
        "collection": bundle.get("id"),
        "count": len(rows),
        "techniques_with_cve_mentions": sum(1 for r in rows if r["cve_mentions"]),
    }
    return rows, version


def process_owasp() -> tuple[list[dict], dict]:
    archive = RAW / "owasp" / "cheatsheets.tar.gz"
    rows = []
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or not member.name.endswith(".md"):
                continue
            if "/cheatsheets/" not in member.name:
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            text = handle.read().decode("utf-8", errors="replace").strip()
            stem = Path(member.name).stem
            if not text or stem.lower() in {"index", "_template"}:
                continue
            title = next(
                (line[2:].strip() for line in text.splitlines() if line.startswith("# ")),
                stem.replace("_", " "),
            )
            rows.append(
                {
                    "doc_id": f"OWASP-{stem}",
                    "title": title,
                    "text": text,
                    "char_count": len(text),
                    "source_url": f"https://cheatsheetseries.owasp.org/cheatsheets/{stem}.html",
                }
            )
    rows.sort(key=lambda r: r["doc_id"])
    return rows, {"count": len(rows)}


def process_cwe() -> tuple[list[dict], dict]:
    archive = RAW / "cwe" / "1000.csv.zip"
    with zipfile.ZipFile(archive) as zf:
        name = next(n for n in zf.namelist() if n.lower().endswith(".csv"))
        text = zf.read(name).decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    rows = []
    for item in reader:
        status = (item.get("Status") or "").strip()
        if status.lower().startswith("deprecated"):
            continue
        cwe_id = (item.get("CWE-ID") or "").strip()
        if not cwe_id.isdigit():
            continue
        rows.append(
            {
                "doc_id": f"CWE-{cwe_id}",
                "cwe_id": f"CWE-{cwe_id}",
                "name": (item.get("Name") or "").strip(),
                "description": (item.get("Description") or "").strip(),
                "extended_description": (item.get("Extended Description") or "").strip(),
                "mitigations": (item.get("Potential Mitigations") or "").strip(),
                "status": status,
                "source_url": f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
            }
        )
    rows.sort(key=lambda r: int(r["cwe_id"].split("-")[1]))
    return rows, {"count": len(rows)}


def main() -> int:
    print("snapshot: downloading")
    for name, url in SOURCES.items():
        suffix = Path(url.split("?")[0]).suffix
        if name == "owasp":
            dest = RAW / name / "cheatsheets.tar.gz"
        elif name == "cwe":
            dest = RAW / name / "1000.csv.zip"
        elif name == "kev":
            dest = RAW / name / "known_exploited_vulnerabilities.json"
        else:
            dest = RAW / name / "enterprise-attack.json"
        print(f"- {name} ({suffix or 'tar.gz'})")
        download(url, dest)

    print("snapshot: normalising")
    kev_rows, kev_version = process_kev()
    attack_rows, attack_version = process_attack()
    owasp_rows, owasp_version = process_owasp()
    cwe_rows, cwe_version = process_cwe()

    counts = {
        "kev": write_jsonl(PROC / "kev.jsonl", kev_rows),
        "attack": write_jsonl(PROC / "attack_techniques.jsonl", attack_rows),
        "owasp": write_jsonl(PROC / "owasp_docs.jsonl", owasp_rows),
        "cwe": write_jsonl(PROC / "cwe.jsonl", cwe_rows),
    }
    nist_manifest = MAN / "nist.json"
    nist = json.loads(nist_manifest.read_text("utf-8")) if nist_manifest.exists() else None
    if nist:
        counts["nist"] = nist["count"]

    MAN.mkdir(parents=True, exist_ok=True)
    manifest = {
        "generated_at": now(),
        "sources": {
            "kev": {
                "url": SOURCES["kev"],
                "sha256": sha256(RAW / "kev" / "known_exploited_vulnerabilities.json"),
                **kev_version,
            },
            "attack": {
                "url": SOURCES["attack"],
                "sha256": sha256(RAW / "attack" / "enterprise-attack.json"),
                **attack_version,
            },
            "owasp": {
                "url": SOURCES["owasp"],
                "sha256": sha256(RAW / "owasp" / "cheatsheets.tar.gz"),
                **owasp_version,
                "license": "CC BY-SA 4.0 (verify before redistributing text)",
            },
            "cwe": {
                "url": SOURCES["cwe"],
                "sha256": sha256(RAW / "cwe" / "1000.csv.zip"),
                **cwe_version,
                "license": "CWE terms of use (MITRE)",
            },
        },
        "derived_documents": counts,
    }
    if nist:
        manifest["sources"]["nist"] = {
            "url": "https://csrc.nist.gov/publications (PDFs on nvlpubs.nist.gov)",
            "count": nist["count"],
            "pages": nist["total_pages"],
            "chars": nist["total_chars"],
            "sha256_note": "per-file hashes in data/manifests/nist.json",
        }
    (MAN / "sources.json").write_text(json.dumps(manifest, indent=2), "utf-8")

    for name, count in counts.items():
        print(f"  {name:<7} {count:>5} documents")
    print(f"  manifest data/manifests/sources.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
