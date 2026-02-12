from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from webforti_common.knowledge_store import build_embedder, with_embedding
from webforti_common.settings import load_settings


NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"


@dataclass(frozen=True, slots=True)
class CuratedCve:
    cve_id: str
    category: str
    family: str
    note: str = ""


CURATED_CVES: tuple[CuratedCve, ...] = (
    CuratedCve("CVE-2026-3854", "High-impact web application CVEs", "Remote Code Execution"),
    CuratedCve("CVE-2026-40322", "High-impact web application CVEs", "Remote Code Execution"),
    CuratedCve("CVE-2026-42311", "High-impact web application CVEs", "Remote Code Execution"),
    CuratedCve("CVE-2025-55182", "High-impact web application CVEs", "Remote Code Execution"),
    CuratedCve("CVE-2025-15503", "High-impact web application CVEs", "Remote Code Execution"),
    CuratedCve("CVE-2024-1212", "High-impact web application CVEs", "Remote Code Execution"),
    CuratedCve("CVE-2024-35373", "High-impact web application CVEs", "Remote Code Execution"),
    CuratedCve("CVE-2024-35374", "High-impact web application CVEs", "Remote Code Execution"),
    CuratedCve("CVE-2024-22899", "High-impact web application CVEs", "Remote Code Execution"),
    CuratedCve("CVE-2024-22900", "High-impact web application CVEs", "Remote Code Execution"),
    CuratedCve("CVE-2024-31819", "High-impact web application CVEs", "Remote Code Execution"),
    CuratedCve("CVE-2026-8114", "High-impact web application CVEs", "SQL Injection"),
    CuratedCve("CVE-2026-21643", "High-impact web application CVEs", "SQL Injection"),
    CuratedCve("CVE-2025-47204", "High-impact web application CVEs", "SQL Injection"),
    CuratedCve("CVE-2024-6671", "High-impact web application CVEs", "SQL Injection"),
    CuratedCve("CVE-2024-30922", "High-impact web application CVEs", "SQL Injection"),
    CuratedCve("CVE-2024-30923", "High-impact web application CVEs", "SQL Injection"),
    CuratedCve("CVE-2024-30928", "High-impact web application CVEs", "SQL Injection"),
    CuratedCve("CVE-2021-44427", "High-impact web application CVEs", "SQL Injection"),
    CuratedCve("CVE-2026-8113", "High-impact web application CVEs", "Path Traversal / File Upload"),
    CuratedCve("CVE-2026-25691", "High-impact web application CVEs", "Path Traversal / File Upload"),
    CuratedCve("CVE-2026-39813", "High-impact web application CVEs", "Path Traversal / File Upload"),
    CuratedCve("CVE-2026-43975", "High-impact web application CVEs", "Path Traversal / File Upload"),
    CuratedCve("CVE-2026-43870", "High-impact web application CVEs", "Path Traversal / File Upload"),
    CuratedCve("CVE-2025-57728", "High-impact web application CVEs", "Path Traversal / File Upload"),
    CuratedCve("CVE-2024-7399", "High-impact web application CVEs", "Path Traversal / File Upload"),
    CuratedCve("CVE-2024-31818", "High-impact web application CVEs", "Path Traversal / File Upload"),
    CuratedCve("CVE-2024-30920", "High-impact web application CVEs", "Path Traversal / File Upload"),
    CuratedCve("CVE-2026-4670", "High-impact web application CVEs", "Authentication / Bypass"),
    CuratedCve("CVE-2026-42560", "High-impact web application CVEs", "Authentication / Bypass"),
    CuratedCve("CVE-2026-25939", "High-impact web application CVEs", "Authentication / Bypass"),
    CuratedCve("CVE-2026-4649", "High-impact web application CVEs", "Authentication / Bypass"),
    CuratedCve("CVE-2026-6857", "High-impact web application CVEs", "Authentication / Bypass"),
    CuratedCve("CVE-2025-57726", "High-impact web application CVEs", "Authentication / Bypass"),
    CuratedCve("CVE-2025-56132", "High-impact web application CVEs", "Authentication / Bypass"),
    CuratedCve("CVE-2024-22901", "High-impact web application CVEs", "Authentication / Bypass"),
    CuratedCve("CVE-2026-8106", "High-impact web application CVEs", "XSS & Client-Side"),
    CuratedCve("CVE-2025-47204", "High-impact web application CVEs", "XSS & Client-Side"),
    CuratedCve("CVE-2024-9007", "High-impact web application CVEs", "XSS & Client-Side"),
    CuratedCve("CVE-2024-30920", "High-impact web application CVEs", "XSS & Client-Side"),
    CuratedCve("CVE-2024-30921", "High-impact web application CVEs", "XSS & Client-Side"),
    CuratedCve("CVE-2024-30924", "High-impact web application CVEs", "XSS & Client-Side"),
    CuratedCve("CVE-2024-30925", "High-impact web application CVEs", "XSS & Client-Side"),
    CuratedCve("CVE-2024-30929", "High-impact web application CVEs", "XSS & Client-Side"),
    CuratedCve("CVE-2026-27654", "Web server specific CVEs", "Nginx"),
    CuratedCve("CVE-2026-27784", "Web server specific CVEs", "Nginx"),
    CuratedCve("CVE-2026-32647", "Web server specific CVEs", "Nginx"),
    CuratedCve("CVE-2026-27651", "Web server specific CVEs", "Nginx"),
    CuratedCve("CVE-2026-28753", "Web server specific CVEs", "Nginx"),
    CuratedCve("CVE-2026-28755", "Web server specific CVEs", "Nginx"),
    CuratedCve("CVE-2026-1642", "Web server specific CVEs", "Nginx"),
    CuratedCve("CVE-2025-53859", "Web server specific CVEs", "Nginx"),
    CuratedCve("CVE-2025-23419", "Web server specific CVEs", "Nginx"),
    CuratedCve("CVE-2024-7347", "Web server specific CVEs", "Nginx"),
    CuratedCve("CVE-2024-32760", "Web server specific CVEs", "Nginx"),
    CuratedCve("CVE-2024-31079", "Web server specific CVEs", "Nginx"),
    CuratedCve("CVE-2026-6857", "Web server specific CVEs", "Apache"),
    CuratedCve("CVE-2026-6840", "Web server specific CVEs", "Apache"),
    CuratedCve("CVE-2026-43870", "Web server specific CVEs", "Apache"),
    CuratedCve("CVE-2026-43869", "Web server specific CVEs", "Apache"),
    CuratedCve("CVE-2026-43868", "Web server specific CVEs", "Apache"),
    CuratedCve("CVE-2026-43646", "Web server specific CVEs", "Apache"),
    CuratedCve("CVE-2026-42812", "Web server specific CVEs", "Apache"),
    CuratedCve("CVE-2026-42811", "Web server specific CVEs", "Apache"),
    CuratedCve("CVE-2026-42810", "Web server specific CVEs", "Apache"),
    CuratedCve("CVE-2024-28000", "CMS & Plugin Vulnerabilities", "WordPress plugin", "LiteSpeed Cache"),
    CuratedCve("CVE-2024-50550", "CMS & Plugin Vulnerabilities", "WordPress plugin", "WordPress Automatic"),
    CuratedCve("CVE-2024-1071", "CMS & Plugin Vulnerabilities", "WordPress plugin", "GiveWP"),
    CuratedCve("CVE-2024-44000", "CMS & Plugin Vulnerabilities", "WordPress plugin", "Really Simple SSL"),
    CuratedCve("CVE-2024-5080", "CMS & Plugin Vulnerabilities", "WordPress plugin", "Startklar Elementor"),
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate and ingest curated web CVEs into MongoDB Atlas.")
    parser.add_argument("--report", default="tmp/curated_web_cve_ingest_report.json")
    parser.add_argument("--delay-seconds", type=float, default=0.8)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--only", nargs="*", help="Optional CVE IDs to ingest from the curated set.")
    parser.add_argument("--skip-epss", action="store_true")
    parser.add_argument("--skip-kev", action="store_true")
    args = parser.parse_args()

    settings = load_settings()
    candidates = dedupe_candidates(CURATED_CVES)
    if args.only:
        requested = {item.upper() for item in args.only}
        candidates = [item for item in candidates if item.cve_id in requested]
    kev = {} if args.skip_kev else load_kev(timeout_seconds=args.timeout_seconds)
    epss = {} if args.skip_epss else load_epss([item.cve_id for item in candidates], timeout_seconds=args.timeout_seconds)

    print(f"Validating {len(candidates)} unique CVEs with NVD.")
    records: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for index, candidate in enumerate(candidates, start=1):
        print(f"[{index:02d}/{len(candidates):02d}] {candidate.cve_id}", flush=True)
        payload, error = fetch_nvd_cve(candidate.cve_id, timeout_seconds=args.timeout_seconds)
        if error:
            skipped.append({"cve_id": candidate.cve_id, "reason": error})
        else:
            record = build_corpus_record(payload, candidate, kev.get(candidate.cve_id), epss.get(candidate.cve_id))
            if record:
                records.append(record)
            else:
                skipped.append({"cve_id": candidate.cve_id, "reason": "not_found_in_nvd"})
        if index < len(candidates) and args.delay_seconds > 0:
            time.sleep(args.delay_seconds)

    upserted = upsert_records(settings, records)
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "source": {
            "nvd": NVD_CVE_API_URL,
            "cisa_kev": None if args.skip_kev else CISA_KEV_URL,
            "epss": None if args.skip_epss else EPSS_API_URL,
        },
        "requested_count": len(CURATED_CVES),
        "unique_requested_count": len(candidates),
        "valid_nvd_count": len(records),
        "upserted_count": upserted,
        "skipped_count": len(skipped),
        "valid_cves": sorted(item["cve_id"] for item in records),
        "skipped": skipped,
        "counts_by_family": count_by(records, "curated_family"),
        "counts_by_category": count_by(records, "curated_category"),
    }
    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ["unique_requested_count", "valid_nvd_count", "upserted_count", "skipped_count"]}, indent=2))
    print(f"Report written to {report_path}")


def dedupe_candidates(candidates: tuple[CuratedCve, ...]) -> list[CuratedCve]:
    merged: dict[str, CuratedCve] = {}
    notes: dict[str, list[str]] = {}
    for candidate in candidates:
        cve_id = candidate.cve_id.upper()
        detail = candidate.family if not candidate.note else f"{candidate.family}: {candidate.note}"
        notes.setdefault(cve_id, []).append(detail)
        if cve_id not in merged:
            merged[cve_id] = CuratedCve(cve_id, candidate.category, candidate.family, candidate.note)
    return [
        CuratedCve(item.cve_id, item.category, item.family, "; ".join(dict.fromkeys(notes[item.cve_id])))
        for item in merged.values()
    ]


def fetch_nvd_cve(cve_id: str, *, timeout_seconds: float) -> tuple[dict[str, Any] | None, str | None]:
    url = f"{NVD_CVE_API_URL}?{urlencode({'cveId': cve_id})}"
    last_error = "nvd_unknown_error"
    for attempt in range(4):
        try:
            payload = request_json(url, timeout_seconds=timeout_seconds)
            if int(payload.get("totalResults") or 0) == 0:
                return None, "not_found_in_nvd"
            return payload, None
        except HTTPError as exc:
            if exc.code == 404:
                return None, "not_found_in_nvd"
            if exc.code in {403, 429}:
                last_error = f"nvd_rate_limited:http_{exc.code}"
                time.sleep(3 * (attempt + 1))
                continue
            return None, f"nvd_http_{exc.code}"
        except (TimeoutError, URLError) as exc:
            last_error = f"nvd_network_error:{type(exc).__name__}"
            time.sleep(2 * (attempt + 1))
        except json.JSONDecodeError:
            return None, "nvd_malformed_json"
    return None, last_error


def request_json(url: str, *, timeout_seconds: float, headers: dict[str, str] | None = None) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": "WebForti-CVE-Ingest/1.0", **(headers or {})})
    with urlopen(request, timeout=timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8"))


def build_corpus_record(
    nvd_payload: dict[str, Any],
    candidate: CuratedCve,
    kev: dict[str, Any] | None,
    epss: dict[str, Any] | None,
) -> dict[str, Any] | None:
    vulnerabilities = nvd_payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return None
    cve = vulnerabilities[0].get("cve") or {}
    cve_id = str(cve.get("id") or candidate.cve_id).upper()
    description = english_description(cve.get("descriptions") or [])
    metrics = parse_metrics(cve.get("metrics") or {})
    cwes = parse_cwes(cve.get("weaknesses") or [])
    references = parse_references(cve.get("references") or {})
    affected = parse_affected_products(cve.get("configurations") or [])
    title = title_from_description(cve_id, description)
    retrieval_text = build_retrieval_text(
        cve_id=cve_id,
        title=title,
        description=description,
        category=candidate.category,
        family=candidate.family,
        note=candidate.note,
        metrics=metrics,
        cwes=cwes,
        references=references,
        affected=affected,
        kev=kev,
        epss=epss,
    )
    return {
        "id": f"nvd-{cve_id.lower()}",
        "cve_id": cve_id,
        "title": title,
        "text": retrieval_text,
        "description": description,
        "source": "nvd-curated-web-cve",
        "source_url": f"{NVD_CVE_API_URL}?cveId={cve_id}",
        "curated_category": candidate.category,
        "curated_family": candidate.family,
        "curated_note": candidate.note,
        "published_at": cve.get("published"),
        "last_modified_at": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "severity": metrics.get("severity"),
        "cvss_score": metrics.get("score"),
        "cvss_vector": metrics.get("vector"),
        "cwe_ids": cwes,
        "affected_products": affected,
        "references": references,
        "kev": kev,
        "epss": epss,
        "ingested_at": datetime.now(UTC).isoformat(),
    }


def english_description(descriptions: list[dict[str, Any]]) -> str:
    for item in descriptions:
        if item.get("lang") == "en" and item.get("value"):
            return str(item["value"]).strip()
    return str(descriptions[0].get("value", "")).strip() if descriptions else ""


def parse_metrics(metrics: dict[str, Any]) -> dict[str, Any]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values:
            continue
        metric = values[0]
        cvss = metric.get("cvssData") or {}
        severity = metric.get("baseSeverity") or cvss.get("baseSeverity")
        return {
            "version": cvss.get("version"),
            "score": cvss.get("baseScore"),
            "severity": severity,
            "vector": cvss.get("vectorString"),
        }
    return {}


def parse_cwes(weaknesses: list[dict[str, Any]]) -> list[str]:
    cwes: list[str] = []
    for weakness in weaknesses:
        for description in weakness.get("description") or []:
            value = description.get("value")
            if value and value not in cwes:
                cwes.append(value)
    return cwes


def parse_references(references: dict[str, Any] | list[dict[str, Any]]) -> list[dict[str, Any]]:
    parsed = []
    if isinstance(references, dict):
        reference_items = references.get("referenceData") or []
    else:
        reference_items = references
    for item in reference_items:
        url = item.get("url")
        if not url:
            continue
        parsed.append(
            {
                "url": url,
                "source": item.get("source"),
                "tags": item.get("tags") or [],
            }
        )
    return parsed[:25]


def parse_affected_products(configurations: list[dict[str, Any]]) -> list[str]:
    products: set[str] = set()
    stack = list(configurations)
    while stack:
        node = stack.pop()
        stack.extend(node.get("nodes") or [])
        for match in node.get("cpeMatch") or []:
            criteria = match.get("criteria")
            if not criteria:
                continue
            parts = criteria.split(":")
            if len(parts) >= 6:
                vendor, product = parts[3], parts[4]
                products.add(f"{vendor}:{product}")
    return sorted(products)[:20]


def title_from_description(cve_id: str, description: str) -> str:
    first_sentence = description.split(". ")[0].strip().rstrip(".")
    if not first_sentence:
        return cve_id
    return f"{cve_id}: {first_sentence[:140]}"


def build_retrieval_text(**kwargs: Any) -> str:
    references = kwargs["references"]
    reference_urls = ", ".join(item["url"] for item in references[:8])
    affected = ", ".join(kwargs["affected"])
    cwes = ", ".join(kwargs["cwes"])
    kev = kwargs["kev"] or {}
    epss = kwargs["epss"] or {}
    parts = [
        f"CVE: {kwargs['cve_id']}",
        f"Title: {kwargs['title']}",
        f"Description: {kwargs['description']}",
        f"Curated category: {kwargs['category']}",
        f"Curated family: {kwargs['family']}",
        f"Curated note: {kwargs['note']}",
        f"Severity: {kwargs['metrics'].get('severity')}",
        f"CVSS score: {kwargs['metrics'].get('score')}",
        f"CVSS vector: {kwargs['metrics'].get('vector')}",
        f"CWE: {cwes}",
        f"Affected products: {affected}",
        f"CISA KEV: {bool(kev)}",
        f"EPSS probability: {epss.get('epss')}",
        f"References: {reference_urls}",
    ]
    return "\n".join(part for part in parts if part and not part.endswith(": "))


def load_kev(*, timeout_seconds: float) -> dict[str, dict[str, Any]]:
    try:
        payload = request_json(CISA_KEV_URL, timeout_seconds=timeout_seconds)
    except Exception as exc:  # noqa: BLE001
        print(f"CISA KEV enrichment skipped: {type(exc).__name__}")
        return {}
    indexed = {}
    for item in payload.get("vulnerabilities") or []:
        cve_id = str(item.get("cveID") or "").upper()
        if cve_id:
            indexed[cve_id] = item
    return indexed


def load_epss(cve_ids: list[str], *, timeout_seconds: float) -> dict[str, dict[str, Any]]:
    if not cve_ids:
        return {}
    url = f"{EPSS_API_URL}?{urlencode({'cve': ','.join(cve_ids)})}"
    try:
        payload = request_json(url, timeout_seconds=timeout_seconds)
    except Exception as exc:  # noqa: BLE001
        print(f"EPSS enrichment skipped: {type(exc).__name__}")
        return {}
    indexed = {}
    for item in payload.get("data") or []:
        cve_id = str(item.get("cve") or "").upper()
        if cve_id:
            indexed[cve_id] = item
    return indexed


def upsert_records(settings, records: list[dict[str, Any]]) -> int:
    if not records:
        return 0
    try:
        from pymongo import MongoClient
    except ImportError as exc:
        raise RuntimeError("pymongo is required for MongoDB ingestion") from exc

    client = MongoClient(settings.mongo_uri)
    db = client[settings.mongo_database]
    knowledge_collection = db["knowledge_documents"]
    corpus_collection = db["cve_corpus"]
    corpus_collection.create_index("cve_id", unique=True)
    corpus_collection.create_index("curated_family")
    corpus_collection.create_index("severity")
    corpus_collection.create_index("source")
    knowledge_collection.create_index("id", unique=True)
    knowledge_collection.create_index("cve_id")
    knowledge_collection.create_index("source")
    knowledge_collection.create_index("embedding_model")

    embedder = build_embedder(settings)
    upserted = 0
    for record in records:
        embedded = with_embedding(record, embedder)
        knowledge_collection.update_one({"id": embedded["id"]}, {"$set": embedded}, upsert=True)
        corpus_collection.update_one({"cve_id": embedded["cve_id"]}, {"$set": embedded}, upsert=True)
        upserted += 1
    return upserted


def count_by(records: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        key = str(record.get(field) or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


if __name__ == "__main__":
    main()
