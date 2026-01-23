from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from webforti_common.models import CVERecord
from webforti_common.seed_data import SEED_CVES


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve(cve_id: str, *, prefer_seed: bool = False) -> CVERecord:
    if prefer_seed and cve_id in SEED_CVES:
        return SEED_CVES[cve_id]
    try:
        return fetch_cve_from_nvd(cve_id)
    except Exception:
        if cve_id in SEED_CVES:
            return SEED_CVES[cve_id]
        raise


def fetch_cve_from_nvd(cve_id: str) -> CVERecord:
    query = urllib.parse.urlencode({"cveId": cve_id})
    request = urllib.request.Request(
        f"{NVD_API_BASE}?{query}",
        headers={"User-Agent": "WebForti research prototype"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise RuntimeError(f"NVD request failed for {cve_id}: {exc}") from exc

    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        raise ValueError(f"CVE not found in NVD: {cve_id}")

    cve = vulnerabilities[0]["cve"]
    descriptions = cve.get("descriptions", [])
    description = next((item["value"] for item in descriptions if item.get("lang") == "en"), "")
    metrics = cve.get("metrics", {})
    cvss_score = None
    severity = "UNKNOWN"
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            metric = metrics[key][0]
            cvss_data = metric.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = metric.get("baseSeverity") or cvss_data.get("baseSeverity") or severity
            break

    record = CVERecord(
        cve_id=cve["id"],
        title=description.split(". ")[0][:180] if description else cve["id"],
        description=description,
        severity=severity,
        cvss_score=cvss_score,
        published_at=cve.get("published"),
        raw=payload,
    )
    record.validate()
    return record
