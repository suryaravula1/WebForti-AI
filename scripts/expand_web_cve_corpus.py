from __future__ import annotations

import argparse
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode

from scripts.ingest_curated_web_cves import (
    NVD_CVE_API_URL,
    CuratedCve,
    build_corpus_record,
    count_by,
    load_epss,
    load_kev,
    request_json,
    upsert_records,
)
from webforti_common.settings import load_settings


KEYWORD_QUERIES: tuple[tuple[str, str], ...] = (
    ("SQL injection", "SQL Injection"),
    ("cross-site scripting", "XSS & Client-Side"),
    ("path traversal", "Path Traversal / File Upload"),
    ("directory traversal", "Path Traversal / File Upload"),
    ("file upload vulnerability", "Path Traversal / File Upload"),
    ("authentication bypass", "Authentication / Bypass"),
    ("authorization bypass", "Authentication / Bypass"),
    ("remote code execution web", "Remote Code Execution"),
    ("command injection web", "Remote Code Execution"),
    ("server-side request forgery", "SSRF"),
    ("deserialization vulnerability web", "Remote Code Execution"),
    ("WordPress plugin vulnerability", "WordPress plugin"),
    ("Drupal vulnerability", "CMS"),
    ("Joomla vulnerability", "CMS"),
    ("Apache HTTP Server vulnerability", "Apache"),
    ("nginx vulnerability", "Nginx"),
    ("Apache Tomcat vulnerability", "Tomcat"),
    ("Spring Framework vulnerability", "Java web framework"),
    ("Laravel vulnerability", "PHP web framework"),
    ("Django vulnerability", "Python web framework"),
    ("Node.js web vulnerability", "Node.js web framework"),
)

WEB_CWE_IDS = {
    "CWE-22",
    "CWE-23",
    "CWE-35",
    "CWE-73",
    "CWE-74",
    "CWE-77",
    "CWE-78",
    "CWE-79",
    "CWE-80",
    "CWE-89",
    "CWE-90",
    "CWE-94",
    "CWE-98",
    "CWE-113",
    "CWE-200",
    "CWE-287",
    "CWE-306",
    "CWE-352",
    "CWE-434",
    "CWE-502",
    "CWE-611",
    "CWE-639",
    "CWE-798",
    "CWE-862",
    "CWE-863",
    "CWE-918",
}

WEB_TEXT_MARKERS = (
    "web",
    "http",
    "https",
    "browser",
    "cookie",
    "session",
    "url",
    "uri",
    "endpoint",
    "api",
    "rest",
    "html",
    "javascript",
    "wordpress",
    "plugin",
    "drupal",
    "joomla",
    "apache",
    "nginx",
    "tomcat",
    "spring",
    "django",
    "laravel",
    "php",
    "node.js",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Expand the WebForti MongoDB RAG CVE corpus from NVD keyword searches.")
    parser.add_argument("--target-total", type=int, default=430, help="Target total CVE-tagged RAG documents.")
    parser.add_argument("--per-keyword-limit", type=int, default=250)
    parser.add_argument("--report", default="tmp/expanded_web_cve_corpus_report.json")
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--delay-seconds", type=float, default=0.8)
    parser.add_argument("--skip-epss", action="store_true")
    parser.add_argument("--skip-kev", action="store_true")
    args = parser.parse_args()

    settings = load_settings()
    existing_cves = load_existing_cves(settings)
    needed = max(args.target_total - len(existing_cves), 0)
    print(f"Existing CVE-tagged RAG docs: {len(existing_cves)}")
    print(f"Target total: {args.target_total}; new CVEs needed: {needed}")
    if needed == 0:
        write_report(args.report, [], [], existing_cves, args.target_total)
        return

    candidates, query_stats = collect_candidates(
        existing_cves=existing_cves,
        per_keyword_limit=args.per_keyword_limit,
        timeout_seconds=args.timeout_seconds,
        delay_seconds=args.delay_seconds,
    )
    selected = select_candidates(candidates, limit=needed)
    selected_ids = [item["record"]["cve_id"] for item in selected]
    kev = {} if args.skip_kev else load_kev(timeout_seconds=args.timeout_seconds)
    epss = {} if args.skip_epss else load_epss(selected_ids, timeout_seconds=args.timeout_seconds)

    records = []
    for item in selected:
        candidate = CuratedCve(
            item["record"]["cve_id"],
            "Expanded NVD web corpus",
            item["family"],
            f"NVD keyword: {item['keyword']}",
        )
        record = build_corpus_record(
            {"vulnerabilities": [item["vulnerability"]]},
            candidate,
            kev.get(candidate.cve_id),
            epss.get(candidate.cve_id),
        )
        if not record:
            continue
        record["source"] = "nvd-expanded-web-cve"
        record["curated_category"] = "Expanded NVD web corpus"
        record["curated_family"] = item["family"]
        record["curated_note"] = f"NVD keyword: {item['keyword']}"
        record["selection_score"] = item["selection_score"]
        records.append(record)

    upserted = upsert_records(settings, records)
    final_cves = existing_cves | {item["cve_id"] for item in records}
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "source": {"nvd": NVD_CVE_API_URL},
        "target_total": args.target_total,
        "initial_cve_tagged_rag_docs": len(existing_cves),
        "candidate_count": len(candidates),
        "selected_count": len(records),
        "upserted_count": upserted,
        "final_estimated_cve_tagged_rag_docs": len(final_cves),
        "query_stats": query_stats,
        "counts_by_family": count_by(records, "curated_family"),
        "selected_cves": sorted(item["cve_id"] for item in records),
    }
    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "candidate_count": len(candidates),
                "selected_count": len(records),
                "upserted_count": upserted,
                "final_estimated_cve_tagged_rag_docs": len(final_cves),
            },
            indent=2,
        )
    )
    print(f"Report written to {report_path}")


def load_existing_cves(settings) -> set[str]:
    from pymongo import MongoClient

    collection = MongoClient(settings.mongo_uri)[settings.mongo_database]["knowledge_documents"]
    return {
        str(item["cve_id"]).upper()
        for item in collection.find({"cve_id": {"$exists": True, "$ne": ""}}, {"_id": 0, "cve_id": 1})
    }


def collect_candidates(
    *,
    existing_cves: set[str],
    per_keyword_limit: int,
    timeout_seconds: float,
    delay_seconds: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    candidates_by_cve: dict[str, dict[str, Any]] = {}
    query_stats = []
    for index, (keyword, fallback_family) in enumerate(KEYWORD_QUERIES, start=1):
        try:
            vulnerabilities, total = fetch_latest_keyword_results(
                keyword,
                limit=per_keyword_limit,
                timeout_seconds=timeout_seconds,
            )
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            query_stats.append({"keyword": keyword, "error": describe_error(exc)})
            print(f"[{index:02d}/{len(KEYWORD_QUERIES):02d}] {keyword}: error={describe_error(exc)}", flush=True)
            continue
        accepted = 0
        for vulnerability in vulnerabilities:
            record = summarize_vulnerability(vulnerability, fallback_family, keyword)
            if not record or record["cve_id"] in existing_cves:
                continue
            current = candidates_by_cve.get(record["cve_id"])
            if current is None or record["selection_score"] > current["selection_score"]:
                candidates_by_cve[record["cve_id"]] = {
                    "vulnerability": vulnerability,
                    "record": record,
                    "keyword": keyword,
                    "family": record["family"],
                    "selection_score": record["selection_score"],
                }
            accepted += 1
        query_stats.append(
            {
                "keyword": keyword,
                "nvd_total": total,
                "fetched": len(vulnerabilities),
                "accepted_after_filter": accepted,
            }
        )
        print(f"[{index:02d}/{len(KEYWORD_QUERIES):02d}] {keyword}: fetched={len(vulnerabilities)} accepted={accepted}", flush=True)
        if delay_seconds > 0:
            time.sleep(delay_seconds)
    return list(candidates_by_cve.values()), query_stats


def fetch_latest_keyword_results(keyword: str, *, limit: int, timeout_seconds: float) -> tuple[list[dict[str, Any]], int]:
    total_url = f"{NVD_CVE_API_URL}?{urlencode({'keywordSearch': keyword, 'resultsPerPage': 1})}"
    total_payload = request_json_with_retry(total_url, timeout_seconds=timeout_seconds)
    total = int(total_payload.get("totalResults") or 0)
    if total == 0:
        return [], total
    page_size = min(max(limit, 1), total)
    start_index = max(total - page_size, 0)
    page_url = f"{NVD_CVE_API_URL}?{urlencode({'keywordSearch': keyword, 'resultsPerPage': page_size, 'startIndex': start_index})}"
    page_payload = request_json_with_retry(page_url, timeout_seconds=timeout_seconds)
    return page_payload.get("vulnerabilities") or [], total


def request_json_with_retry(url: str, *, timeout_seconds: float) -> dict[str, Any]:
    for attempt in range(5):
        try:
            return request_json(url, timeout_seconds=timeout_seconds)
        except HTTPError as exc:
            if exc.code not in {403, 429} or attempt == 4:
                raise
            time.sleep(8 * (attempt + 1))
        except (URLError, TimeoutError):
            if attempt == 4:
                raise
            time.sleep(4 * (attempt + 1))
    raise RuntimeError("unreachable retry state")


def describe_error(exc: Exception) -> str:
    if isinstance(exc, HTTPError):
        return f"HTTPError:{exc.code}"
    return type(exc).__name__


def summarize_vulnerability(vulnerability: dict[str, Any], fallback_family: str, keyword: str) -> dict[str, Any] | None:
    cve = vulnerability.get("cve") or {}
    cve_id = str(cve.get("id") or "").upper()
    if not cve_id:
        return None
    status = str(cve.get("vulnStatus") or "")
    descriptions = cve.get("descriptions") or []
    description = ""
    for item in descriptions:
        if item.get("lang") == "en":
            description = str(item.get("value") or "")
            break
    text = f"{cve_id} {description} {keyword}".lower()
    if "rejected reason" in text or status.upper() == "REJECTED":
        return None
    cwes = extract_cwes(cve.get("weaknesses") or [])
    if not is_web_relevant(text, cwes):
        return None
    metrics = parse_score(cve.get("metrics") or {})
    family = classify_family(text, cwes, fallback_family)
    published = str(cve.get("published") or "")
    selection_score = score_candidate(metrics, cwes, text, published)
    return {
        "cve_id": cve_id,
        "family": family,
        "selection_score": selection_score,
        "published": published,
        "severity": metrics.get("severity"),
        "score": metrics.get("score"),
    }


def extract_cwes(weaknesses: list[dict[str, Any]]) -> set[str]:
    cwes: set[str] = set()
    for weakness in weaknesses:
        for description in weakness.get("description") or []:
            value = description.get("value")
            if value:
                cwes.add(str(value).upper())
    return cwes


def parse_score(metrics: dict[str, Any]) -> dict[str, Any]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values:
            continue
        metric = values[0]
        cvss = metric.get("cvssData") or {}
        return {
            "score": float(cvss.get("baseScore") or 0.0),
            "severity": metric.get("baseSeverity") or cvss.get("baseSeverity"),
        }
    return {"score": 0.0, "severity": None}


def is_web_relevant(text: str, cwes: set[str]) -> bool:
    if cwes & WEB_CWE_IDS:
        return True
    return any(marker in text for marker in WEB_TEXT_MARKERS)


def classify_family(text: str, cwes: set[str], fallback: str) -> str:
    if "CWE-89" in cwes or "sql injection" in text:
        return "SQL Injection"
    if "CWE-79" in cwes or "cross-site scripting" in text or "xss" in text:
        return "XSS & Client-Side"
    if {"CWE-22", "CWE-23", "CWE-35", "CWE-73"} & cwes or "path traversal" in text or "directory traversal" in text:
        return "Path Traversal / File Upload"
    if "CWE-434" in cwes or "file upload" in text:
        return "Path Traversal / File Upload"
    if {"CWE-287", "CWE-306", "CWE-639", "CWE-862", "CWE-863"} & cwes or "authentication bypass" in text:
        return "Authentication / Bypass"
    if "CWE-918" in cwes or "server-side request forgery" in text or "ssrf" in text:
        return "SSRF"
    if {"CWE-78", "CWE-94", "CWE-502"} & cwes or "remote code execution" in text or "command injection" in text:
        return "Remote Code Execution"
    if "wordpress" in text or "plugin" in text:
        return "WordPress plugin"
    if "apache http server" in text:
        return "Apache"
    if "nginx" in text:
        return "Nginx"
    return fallback


def score_candidate(metrics: dict[str, Any], cwes: set[str], text: str, published: str) -> float:
    score = float(metrics.get("score") or 0.0) * 10
    severity = str(metrics.get("severity") or "").upper()
    if severity == "CRITICAL":
        score += 35
    elif severity == "HIGH":
        score += 20
    elif severity == "MEDIUM":
        score += 5
    if cwes & WEB_CWE_IDS:
        score += 15
    for marker in ("wordpress", "apache", "nginx", "tomcat", "sql injection", "cross-site scripting", "remote code execution"):
        if marker in text:
            score += 3
    try:
        year = int(published[:4])
    except ValueError:
        year = 0
    if year >= 2024:
        score += 12
    elif year >= 2021:
        score += 6
    return score


def select_candidates(candidates: list[dict[str, Any]], *, limit: int) -> list[dict[str, Any]]:
    return sorted(
        candidates,
        key=lambda item: (
            item["selection_score"],
            item["record"].get("published") or "",
            item["record"]["cve_id"],
        ),
        reverse=True,
    )[:limit]


def write_report(path: str, records: list[dict[str, Any]], query_stats: list[dict[str, Any]], existing_cves: set[str], target: int) -> None:
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "target_total": target,
        "initial_cve_tagged_rag_docs": len(existing_cves),
        "selected_count": len(records),
        "query_stats": query_stats,
    }
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Report written to {report_path}")


if __name__ == "__main__":
    main()
