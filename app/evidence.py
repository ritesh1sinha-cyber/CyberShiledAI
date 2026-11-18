from __future__ import annotations

import json
import time
from datetime import date, datetime, timezone
from pathlib import Path
from collections.abc import Callable
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from app.contracts import (
    AttackMapping,
    Citation,
    CveFacts,
    Evidence,
    EvidencePackage,
    EvidenceSource,
    InvestigateRequest,
    KevStatus,
    RetrievedContext,
    StageTiming,
)
from app.identifiers import resolve_request_cve
from app.nvd import (
    cpe_products,
    cwe_candidates,
    english_description,
    join_vendor_product,
    pick_cvss,
    select_remediation_cwe,
)
from app.retrieval import ReferenceRetriever, Retriever

ROOT = Path(__file__).resolve().parent.parent
NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"
KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
SOURCE_FILES = (
    "attack_techniques.jsonl",
    "owasp_docs.jsonl",
    "cwe.jsonl",
    "nist_docs.jsonl",
)
SOURCE_NAMES = {
    "attack": "ATTACK",
    "owasp": "OWASP",
    "cwe": "CWE",
    "nist": "NIST",
    "nvd_reference": "NVD_REF",
}

# Total generic-corpus search rounds per investigation: the initial query plus
# up to two reviewer-driven refinements. Each round costs one Qwen review call,
# so the cap bounds latency and model spend.
MAX_RAG_CALLS = 3


class EvidenceState(TypedDict, total=False):
    request: InvestigateRequest
    package: EvidencePackage
    cve_id: str
    retrieval_query: str
    retrieval_reviewer: Callable
    additional_limitations: list[str]


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


class EvidenceWriter:
    def __init__(self, retrieved_at: datetime):
        self.retrieved_at = retrieved_at
        self.evidence: list[Evidence] = []
        self.citations: list[Citation] = []

    def add(
        self,
        claim_type: str,
        claim: str,
        source: EvidenceSource,
        source_record_id: str,
        source_url: str,
        source_updated_at: datetime | None = None,
        validation_status: str = "verified",
    ) -> Evidence:
        evidence = Evidence(
            evidence_id=f"EV-{len(self.evidence) + 1:04d}",
            claim_type=claim_type,
            claim=claim,
            source=source,
            source_record_id=source_record_id,
            source_url=source_url,
            retrieved_at=self.retrieved_at,
            source_updated_at=source_updated_at,
            validation_status=validation_status,
        )
        self.evidence.append(evidence)
        self.citations.append(
            Citation(
                evidence_id=evidence.evidence_id,
                source=evidence.source,
                source_url=evidence.source_url,
            )
        )
        return evidence


class EvidenceAgent:
    def __init__(
        self,
        retriever: Retriever | None = None,
        nvd_dir: Path = ROOT / "data" / "raw" / "nvd",
        processed_dir: Path = ROOT / "data" / "processed",
        manifest_path: Path | None = None,
        clock: Callable[[], datetime] | None = None,
    ):
        self.retriever = retriever
        self.nvd_dir = nvd_dir
        self.processed_dir = processed_dir
        self.manifest_path = manifest_path or processed_dir.parent / "manifests" / "sources.json"
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.document_urls = self._load_document_urls()
        self.reference_retriever = ReferenceRetriever(
            processed_dir / "reference_chunks.jsonl"
        )
        self.attack_rows = read_jsonl(processed_dir / "attack_techniques.jsonl")
        self.cwe_rows = {
            row["cwe_id"]: row
            for row in read_jsonl(processed_dir / "cwe.jsonl")
            if row.get("cwe_id")
        }
        workflow = StateGraph(EvidenceState)
        workflow.add_node("collect_evidence", self.collect)
        workflow.add_edge(START, "collect_evidence")
        workflow.add_edge("collect_evidence", END)
        self.graph = workflow.compile()

    def _load_document_urls(self) -> dict[str, str]:
        urls = {}
        for filename in SOURCE_FILES:
            for row in read_jsonl(self.processed_dir / filename):
                urls[row["doc_id"]] = row["source_url"]
        return urls

    def _load_nvd(self, cve_id: str) -> dict | None:
        path = self.nvd_dir / f"{cve_id}.json"
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        vulnerabilities = payload.get("vulnerabilities") or []
        if not vulnerabilities:
            return None
        return vulnerabilities[0].get("cve")

    def _collect_nvd(
        self,
        cve_id: str,
        writer: EvidenceWriter,
        limitations: list[str],
    ) -> tuple[CveFacts | None, dict | None]:
        cve = self._load_nvd(cve_id)
        if cve is None:
            limitations.append(
                "No cached NVD record was available; this does not establish that the CVE does not exist."
            )
            return None, None
        description = english_description(cve)
        cvss = pick_cvss(cve) or {}
        modified = parse_datetime(cve.get("lastModified"))
        published = date.fromisoformat(cve["published"][:10]) if cve.get("published") else None
        facts = CveFacts(
            cve_id=cve_id,
            description=description,
            cvss_version=cvss.get("cvss_version"),
            cvss_score=cvss.get("cvss_score"),
            severity=cvss.get("severity"),
            cvss_vector=cvss.get("cvss_vector"),
            cvss_source=cvss.get("cvss_source"),
            published=published,
            last_modified=modified,
        )
        url = NVD_DETAIL + cve_id
        if description:
            writer.add(
                "cve_description",
                description,
                "NVD",
                cve_id,
                url,
                modified,
            )
        if cvss:
            writer.add(
                "cvss",
                (
                    f"NVD reports CVSS {cvss['cvss_version']} base score "
                    f"{cvss['cvss_score']} ({cvss['severity']}); vector "
                    f"{cvss.get('cvss_vector') or 'not provided'}."
                ),
                "NVD",
                cve_id,
                url,
                modified,
            )
        else:
            limitations.append("NVD provided no supported CVSS v3.1, v3.0, or v2 metric.")
        return facts, cve

    def _collect_kev(
        self,
        cve_id: str,
        checked_at: datetime,
        writer: EvidenceWriter,
        limitations: list[str],
    ) -> tuple[KevStatus, dict | None]:
        catalog_version = "unknown"
        released = None
        row = None
        try:
            manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            metadata = manifest["sources"]["kev"]
            catalog_version = str(metadata["catalog_version"])
            released = parse_datetime(metadata["released"])
            rows = read_jsonl(self.processed_dir / "kev.jsonl")
            row = next((item for item in rows if item.get("cve_id") == cve_id), None)
        except (OSError, KeyError, TypeError, ValueError):
            limitations.append("CISA KEV snapshot metadata could not be read; KEV status is unknown.")
            return KevStatus(
                status="unknown", catalog_version=catalog_version, checked_at=checked_at
            ), None
        if released is None or released > checked_at:
            limitations.append("CISA KEV snapshot is undated or newer than the investigation time; KEV status is unknown.")
            return KevStatus(
                status="unknown", catalog_version=catalog_version, checked_at=checked_at
            ), None
        if row is None:
            status = KevStatus(status="not_listed", catalog_version=catalog_version, checked_at=checked_at)
            writer.add(
                "kev",
                f"{cve_id} is not listed in CISA KEV catalog {catalog_version}.",
                "CISA_KEV",
                cve_id,
                KEV_URL,
                released,
            )
            return status, None
        status = KevStatus(
            status="known_exploited",
            catalog_version=catalog_version,
            checked_at=checked_at,
            date_added=date.fromisoformat(row["date_added"]),
            due_date=date.fromisoformat(row["due_date"]) if row.get("due_date") else None,
            required_action=row.get("required_action"),
            ransomware_use=(
                row["ransomware"] == "Known" if row.get("ransomware") in {"Known", "Unknown"} else None
            ),
        )
        writer.add(
            "kev",
            (
                f"{cve_id} is listed in CISA KEV as known exploited; added "
                f"{status.date_added}, due {status.due_date}. Required action: "
                f"{status.required_action or 'not provided'}."
            ),
            "CISA_KEV",
            cve_id,
            row.get("source_url") or KEV_URL,
            released,
        )
        return status, row

    def _collect_products(
        self,
        cve_id: str,
        cve: dict | None,
        kev_status: KevStatus,
        kev_row: dict | None,
        writer: EvidenceWriter,
    ) -> list[str]:
        kev_label = ""
        if kev_status.status == "known_exploited" and kev_row:
            kev_label = join_vendor_product(kev_row.get("vendor") or "", kev_row.get("product") or "")
        products = [kev_label] if kev_label else (cpe_products(cve) if cve else [])
        modified = parse_datetime((cve or {}).get("lastModified"))
        for product in products:
            from_kev = bool(kev_label)
            writer.add(
                "affected_product",
                f"Affected product: {product}.",
                "CISA_KEV" if from_kev else "NVD",
                cve_id,
                (kev_row.get("source_url") or KEV_URL) if from_kev else NVD_DETAIL + cve_id,
                None if from_kev else modified,
            )
        return products

    def _collect_attack(
        self,
        cve_id: str,
        writer: EvidenceWriter,
    ) -> list[AttackMapping]:
        mappings = []
        for row in self.attack_rows:
            if cve_id not in (row.get("cve_mentions") or []):
                continue
            evidence = writer.add(
                "attack",
                f"{row['technique_id']} {row['name']} explicitly references {cve_id}.",
                "ATTACK",
                row["technique_id"],
                row["source_url"],
            )
            mappings.append(
                AttackMapping(
                    technique_id=row["technique_id"],
                    name=row["name"],
                    basis="source_reference",
                    evidence_id=evidence.evidence_id,
                    confidence="high",
                )
            )
        return mappings

    def _collect_context(
        self,
        request: InvestigateRequest,
        cve_id: str,
        cve: dict | None,
        writer: EvidenceWriter,
        limitations: list[str],
        retrieval_query: str | None = None,
        retrieval_reviewer: Callable | None = None,
    ) -> tuple[list[RetrievedContext], dict]:
        if self.retriever is None:
            self.retriever = Retriever()
        query_parts = [retrieval_query or request.query]
        if cve:
            candidates = cwe_candidates(cve)
            if candidates:
                cwe_id, cwe_row, _ = select_remediation_cwe(
                    {"cwe_candidates": candidates}, self.cwe_rows
                )
                query_parts.extend([cwe_id, cwe_row.get("name") or ""])
            else:
                query_parts.append(english_description(cve) or "")
        query_parts.append("remediation mitigation security controls")
        primary_query = " ".join(part for part in query_parts if part)
        contexts = []
        missing_urls = 0
        reference_used = 0

        def add_results(rows: list[dict]) -> None:
            nonlocal missing_urls, reference_used
            existing = {item.chunk_id for item in contexts}
            for chunk in rows:
                if chunk["chunk_id"] in existing:
                    continue
                source_url = self.document_urls.get(chunk.get("doc_id", "")) or chunk.get("url")
                source = SOURCE_NAMES.get(chunk.get("source", ""))
                text = (chunk.get("text") or "").strip()
                if not source_url or not source or not text:
                    missing_urls += 1
                    continue
                title = chunk.get("title") or chunk["doc_id"]
                evidence = writer.add(
                    "attack" if source == "ATTACK" else "remediation",
                    f"Retrieved passage {chunk['chunk_id']} from {title}.",
                    source,
                    chunk["chunk_id"],
                    source_url,
                    validation_status="retrieved",
                )
                contexts.append(
                    RetrievedContext(
                        evidence_id=evidence.evidence_id,
                        chunk_id=chunk["chunk_id"],
                        title=title,
                        text=text,
                        score=float(chunk.get("score", 0.0)),
                    )
                )
                existing.add(chunk["chunk_id"])
                if source == "NVD_REF":
                    reference_used += 1

        # Reference-first: the fetched pages the NVD record itself cites are
        # searched before the generic corpus and land ahead of it in the
        # context list, so citations prefer the vendor's own advisory. The CVE
        # id is added to the query because advisories normally state it while
        # the CWE/generic terms may not appear on the page.
        if self.reference_retriever.has_cve(cve_id):
            reference_query = " ".join([primary_query, cve_id])
            add_results(
                self.reference_retriever.search_for_cve(cve_id, reference_query, k=request.top_k)
            )
        attempts: list[str] = []
        review: dict = {"sufficient": bool(contexts), "refined_query": None}
        next_query = primary_query
        refine = False
        while next_query and len(attempts) < MAX_RAG_CALLS:
            query = next_query
            if refine:
                query = " ".join([query, *([cve["id"]] if cve and cve.get("id") else [])])
            attempts.append(next_query)
            results = self.retriever.search(
                query,
                k=request.top_k,
                mode="hybrid",
                pool=50,
                alpha=0.5,
            )
            add_results(results)
            review = {"sufficient": bool(contexts), "refined_query": None}
            if retrieval_reviewer:
                review = retrieval_reviewer(query, contexts)
            if review.get("sufficient"):
                break
            refined = (review.get("refined_query") or "").strip()[:600]
            next_query = refined if refined and refined not in attempts else None
            refine = True
        if retrieval_reviewer and attempts and not review.get("sufficient") and len(attempts) >= MAX_RAG_CALLS:
            limitations.append(
                f"Retrieval review still judged the passages insufficient after {MAX_RAG_CALLS} search rounds."
            )
        if missing_urls:
            limitations.append(f"Skipped {missing_urls} retrieved chunks with incomplete source metadata.")
        if reference_used:
            limitations.append(
                f"Included {reference_used} passages from the CVE's own NVD-cited reference pages; "
                "these are snapshot copies fetched locally, so page content may have changed since."
            )
        if contexts:
            limitations.append("Retrieved passages are ranked context, not independently verified facts.")
        else:
            limitations.append("Hybrid retrieval returned no usable supporting passages.")
        return contexts, {"queries": attempts, "review": review, "retry_used": len(attempts) > 1}

    def collect(self, state: EvidenceState) -> EvidenceState:
        started = time.perf_counter()
        request = InvestigateRequest.model_validate(state["request"])
        cve_id = state.get("cve_id") or resolve_request_cve(request)
        now = as_utc(self.clock())
        writer = EvidenceWriter(now)
        limitations: list[str] = []
        facts, raw_cve = self._collect_nvd(cve_id, writer, limitations)
        kev_status, kev_row = self._collect_kev(cve_id, now, writer, limitations)
        products = self._collect_products(cve_id, raw_cve, kev_status, kev_row, writer)
        mappings = self._collect_attack(cve_id, writer) if request.include_attack else []
        if request.include_attack and not mappings:
            limitations.append(
                "No verified MITRE ATT&CK technique mapping was found for this CVE in the available snapshot."
            )
        limitations.extend(state.get("additional_limitations", []))
        contexts, retrieval_meta = self._collect_context(
            request,
            cve_id,
            raw_cve,
            writer,
            limitations,
            retrieval_query=state.get("retrieval_query"),
            retrieval_reviewer=state.get("retrieval_reviewer"),
        )
        elapsed_ms = max(0, round((time.perf_counter() - started) * 1000))
        package = EvidencePackage(
            cve_id=cve_id,
            cve=facts,
            affected_products=products,
            kev=kev_status,
            attack_mapping=mappings,
            contexts=contexts,
            evidence=writer.evidence,
            citations=writer.citations,
            limitations=limitations,
            timings=[StageTiming(stage="evidence", ms=elapsed_ms)],
        )
        return {"package": package, "retrieval_meta": retrieval_meta}

    def investigate(self, request: InvestigateRequest) -> EvidencePackage:
        return self.graph.invoke({"request": request})["package"]
