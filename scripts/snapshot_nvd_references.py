"""Download every http(s) reference URL found in the saved NVD CVE snapshots.

Scope change 2026-11-16: NVD's own references are treated as first-class sources.
The pages behind the links are now fetched and stored, so a later retrieval step
can rank them before falling back to the generic corpora. Each URL is saved once
with its bytes, hash and fetch status; a run can be resumed and will only retry
URLs that did not previously succeed.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
NVD_DIR = ROOT / "data" / "raw" / "nvd"
OUT_DIR = ROOT / "data" / "raw" / "nvd_references"
INDEX_PATH = OUT_DIR / "references_index.jsonl"
MANIFEST = ROOT / "data" / "manifests" / "nvd_references.json"

USER_AGENT = "CyberShieldAI-capstone/1.0 (local research snapshot of NVD-cited references)"
DELAY_S = 0.5
TIMEOUT_S = 10.0
MAX_BYTES = 10 * 1024 * 1024

EXTENSIONS = {
    "text/html": ".html",
    "application/pdf": ".pdf",
    "application/json": ".json",
    "text/plain": ".txt",
    "text/xml": ".xml",
    "application/xml": ".xml",
    "text/markdown": ".md",
}


def load_existing_index() -> dict[str, dict]:
    if not INDEX_PATH.exists():
        return {}
    rows = {}
    for line in INDEX_PATH.read_text("utf-8").splitlines():
        if line:
            row = json.loads(line)
            rows[row["url"]] = row
    return rows


def collect_references() -> dict[str, dict]:
    references: dict[str, dict] = {}
    skipped = []
    for path in sorted(NVD_DIR.glob("*.json")):
        payload = json.loads(path.read_text("utf-8"))
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id") or path.stem
            for reference in cve.get("references", []):
                url = reference.get("url") or ""
                if not url.startswith(("http://", "https://")):
                    skipped.append({"url": url, "cve": cve_id, "reason": "not http(s)"})
                    continue
                row = references.setdefault(url, {"url": url, "cves": [], "tags": []})
                if cve_id not in row["cves"]:
                    row["cves"].append(cve_id)
                for tag in reference.get("tags") or []:
                    if tag not in row["tags"]:
                        row["tags"].append(tag)
    return references, skipped


def extension_for(content_type: str, url: str) -> str:
    base = content_type.split(";")[0].strip().lower()
    if base in EXTENSIONS:
        return EXTENSIONS[base]
    suffix = Path(url.split("?", 1)[0]).suffix.lower()
    return suffix if suffix in {".html", ".pdf", ".json", ".txt", ".xml", ".md", ".png", ".jpg"} else ".bin"


def fetch_one(client: httpx.Client, url: str, entry: dict) -> dict:
    url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    row = {
        "url": url,
        "url_hash": url_hash,
        "cves": entry["cves"],
        "tags": entry["tags"],
        "fetched_at": None,
        "status": "error",
        "http_status": None,
        "content_type": None,
        "bytes": 0,
        "truncated": False,
        "sha256": None,
        "final_url": None,
        "filename": None,
        "error": None,
    }
    try:
        with client.stream("GET", url) as response:
            row["http_status"] = response.status_code
            row["final_url"] = str(response.url)
            row["content_type"] = response.headers.get("content-type", "")
            chunks = []
            total = 0
            truncated = False
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > MAX_BYTES:
                    truncated = True
                    break
                chunks.append(chunk)
            if response.status_code != 200:
                row["status"] = "http_error"
                row["error"] = f"HTTP {response.status_code}"
                return row
            content = b"".join(chunks)
            row["bytes"] = len(content)
            row["truncated"] = truncated
            row["status"] = "ok"
            row["sha256"] = hashlib.sha256(content).hexdigest()
            row["filename"] = url_hash + extension_for(row["content_type"], url)
            (OUT_DIR / row["filename"]).write_bytes(content)
    except Exception as exc:  # noqa: BLE001 - every failure is recorded, never raised
        row["status"] = "error"
        row["error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
    return row


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    references, skipped = collect_references()
    existing = load_existing_index()
    pending = [entry for url, entry in sorted(references.items()) if existing.get(url, {}).get("status") != "ok"]
    print(f"{len(references)} unique http(s) references; {len(existing)} previously indexed; {len(pending)} to fetch", flush=True)

    rows = []
    ok = 0
    started = time.time()
    with httpx.Client(
        headers={"User-Agent": USER_AGENT},
        timeout=httpx.Timeout(TIMEOUT_S, read=TIMEOUT_S),
        follow_redirects=True,
        verify=True,
    ) as client:
        for index, entry in enumerate(pending, start=1):
            row = fetch_one(client, entry["url"], entry)
            rows.append(row)
            ok += row["status"] == "ok"
            if index % 25 == 0 or index == len(pending):
                rate = (time.time() - started) / index
                print(f"fetched {index}/{len(pending)} (ok={ok}) — {rate:.1f}s per URL", flush=True)
            with INDEX_PATH.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            time.sleep(DELAY_S)

    merged: dict[str, dict] = dict(existing)
    for row in rows:
        merged[row["url"]] = row
    all_rows = list(merged.values())
    statuses: dict[str, int] = {}
    domain_fail: dict[str, int] = {}
    for row in all_rows:
        statuses[row["status"]] = statuses.get(row["status"], 0) + 1
        if row["status"] != "ok":
            domain = row["url"].split("/")[2] if "://" in row["url"] else "unknown"
            domain_fail[domain] = domain_fail.get(domain, 0) + 1
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "nvd_files_scanned": len(list(NVD_DIR.glob("*.json"))),
        "unique_http_references": len(references),
        "skipped_non_http": len(skipped),
        "statuses": statuses,
        "failed_by_domain": dict(sorted(domain_fail.items(), key=lambda kv: -kv[1])),
        "index_file": INDEX_PATH.relative_to(ROOT).as_posix(),
        "storage_dir": OUT_DIR.relative_to(ROOT).as_posix(),
        "notes": "References are stored as downloaded bytes; retrieval integration is a later step. ftp:// and other non-http schemes are recorded but not fetched.",
    }
    MANIFEST.write_text(json.dumps(manifest, indent=1, ensure_ascii=False), "utf-8")
    skipped_path = OUT_DIR / "skipped_non_http.json"
    skipped_path.write_text(json.dumps(skipped, indent=1, ensure_ascii=False), "utf-8")
    print(f"done: ok={ok} of {len(pending)} attempted; statuses={statuses}", flush=True)
    print(f"wrote {MANIFEST}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
