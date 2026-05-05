from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend" / "shared"))

from services.gateway.pipeline import run_job
from services.gateway.state import InMemoryJobStore
from webforti_common.models import JobStatus
from webforti_common.settings import load_settings


def main() -> int:
    fixture_path = Path(os.getenv("WEBFORTI_BENCHMARK_FIXTURES", ROOT / "benchmarks" / "fixtures" / "cves.json"))
    fixtures = json.loads(fixture_path.read_text(encoding="utf-8"))
    settings = load_settings()
    store = InMemoryJobStore()
    results = []

    started = time.perf_counter()
    for item in fixtures:
        record = store.create(item["cve_id"], submitted_by="benchmark")
        job_started = time.perf_counter()
        record = run_job(record.job.job_id, store, settings, prefer_seed=True)
        elapsed = time.perf_counter() - job_started
        status = record.result.status.value if record.result else "error"
        bundle = record.bundle
        evidence = record.result.evidence if record.result else {}
        snort_validation = evidence.get("snort_validation", {})
        snort_pcap_detection = evidence.get("snort_pcap_detection", {})
        snort_live_request_detection = evidence.get("snort_live_request_detection", {})
        results.append(
            {
                "cve_id": item["cve_id"],
                "job_status": record.job.status.value,
                "verification_status": status,
                "expected_status": item.get("expected_status"),
                "elapsed_seconds": round(elapsed, 4),
                "snort_rule_valid": bool(bundle and bundle.rule.is_valid),
                "exploit_script_valid": bool(bundle and bundle.exploit.is_valid),
                "docker_spec_valid": bool(bundle and bundle.docker_spec.is_valid),
                "effectiveness_score": record.result.effectiveness_score if record.result else 0.0,
                "snort3_syntax_valid": bool(snort_validation.get("valid")),
                "snort3_runtime_alerted": bool(evidence.get("snort_runtime_alerted")),
                "snort3_pcap_alerted": bool(snort_pcap_detection.get("alerted")),
                "snort3_live_alerted": bool(evidence.get("snort_live_alerted")),
                "snort3_interface_alerted": bool(evidence.get("snort_interface_alerted")),
                "snort3_inline_alerted": bool(evidence.get("snort_inline_alerted")),
                "snort3_inline_blocked": bool(evidence.get("snort_inline_blocked")),
                "snort3_live_request_alerted": bool(snort_live_request_detection.get("alerted")),
                "proxy_alerted": bool(evidence.get("proxy_alerted")),
            }
        )

    total_elapsed = time.perf_counter() - started
    completed = sum(1 for row in results if row["job_status"] == JobStatus.COMPLETED.value)
    verification_passed = sum(1 for row in results if row["verification_status"] == "pass")
    snort_valid = sum(1 for row in results if row["snort_rule_valid"])
    exploit_valid = sum(1 for row in results if row["exploit_script_valid"])
    docker_valid = sum(1 for row in results if row["docker_spec_valid"])
    snort3_syntax_valid = sum(1 for row in results if row["snort3_syntax_valid"])
    snort3_runtime_alerted = sum(1 for row in results if row["snort3_runtime_alerted"])
    snort3_pcap_alerted = sum(1 for row in results if row["snort3_pcap_alerted"])
    snort3_live_alerted = sum(1 for row in results if row["snort3_live_alerted"])
    snort3_interface_alerted = sum(1 for row in results if row["snort3_interface_alerted"])
    snort3_inline_alerted = sum(1 for row in results if row["snort3_inline_alerted"])
    snort3_inline_blocked = sum(1 for row in results if row["snort3_inline_blocked"])
    snort3_live_request_alerted = sum(1 for row in results if row["snort3_live_request_alerted"])
    proxy_alerted = sum(1 for row in results if row["proxy_alerted"])
    total = len(results)
    report = {
        "mode": {
            "model_provider": settings.model_provider,
            "model_name": settings.model_name,
            "verification_mode": settings.verification_mode,
        },
        "summary": {
            "total_cves": total,
            "completed_jobs": completed,
            "average_response_seconds": round(sum(row["elapsed_seconds"] for row in results) / max(total, 1), 4),
            "total_elapsed_seconds": round(total_elapsed, 4),
            "snort_rule_syntactic_correctness": round(snort_valid / max(total, 1), 4),
            "exploit_script_validation_rate": round(exploit_valid / max(total, 1), 4),
            "docker_spec_validation_rate": round(docker_valid / max(total, 1), 4),
            "snort3_syntax_validation_rate": round(snort3_syntax_valid / max(total, 1), 4),
            "snort3_runtime_alert_rate": round(snort3_runtime_alerted / max(total, 1), 4),
            "snort3_pcap_alert_rate": round(snort3_pcap_alerted / max(total, 1), 4),
            "snort3_live_alert_rate": round(snort3_live_alerted / max(total, 1), 4),
            "snort3_interface_alert_rate": round(snort3_interface_alerted / max(total, 1), 4),
            "snort3_inline_alert_rate": round(snort3_inline_alerted / max(total, 1), 4),
            "snort3_inline_block_rate": round(snort3_inline_blocked / max(total, 1), 4),
            "snort3_live_request_alert_rate": round(snort3_live_request_alerted / max(total, 1), 4),
            "proxy_alert_rate": round(proxy_alerted / max(total, 1), 4),
            "purple_team_verification_pass_rate": round(verification_passed / max(total, 1), 4),
        },
        "results": results,
    }
    print(json.dumps(report, indent=2))
    return 0 if completed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
