from __future__ import annotations

import ast
from pathlib import Path
import urllib.parse

from services.orchestrator.docker_adapter import DockerVerificationConfig, verify_bundle_with_docker
from webforti_common.models import ArtifactBundle, VerificationResult
from webforti_common.scoring import score_verification


def verify_bundle(bundle: ArtifactBundle, *, mode: str = "mock", timeout_seconds: int = 60) -> VerificationResult:
    if not bundle.is_complete():
        errors = {
            "exploit_errors": bundle.exploit.validation_errors,
            "rule_errors": bundle.rule.validation_errors,
            "docker_errors": bundle.docker_spec.validation_errors,
        }
        return score_verification(
            cve_id=bundle.cve_id,
            exploit_executed=False,
            exploit_succeeded=False,
            rule_alerted=False,
            blocked=False,
            environment_error="artifact validation failed",
            evidence=errors,
        )

    if mode == "docker":
        repo_root = Path(__file__).resolve().parents[2]
        return verify_bundle_with_docker(
            bundle,
            DockerVerificationConfig(repo_root=repo_root, timeout_seconds=timeout_seconds),
        )

    return mock_verify_bundle(bundle)


def mock_verify_bundle(bundle: ArtifactBundle) -> VerificationResult:
    script = bundle.exploit.content
    rule = bundle.rule.content
    payload_candidates = []
    for line in script.splitlines():
        if line.strip().startswith("payload = "):
            payload_candidates.append(ast.literal_eval(line.split("=", 1)[1].strip()))
    payload = payload_candidates[0] if payload_candidates else bundle.cve_id

    exploit_executed = "__main__" in script and "urllib.request" in script
    encoded_payload = urllib.parse.quote(payload, safe="/.%_-") if payload.startswith("/") else urllib.parse.quote(payload)
    rule_alerted = payload in rule or encoded_payload in rule
    exploit_succeeded = exploit_executed and not rule_alerted
    blocked = exploit_executed and rule_alerted

    return score_verification(
        cve_id=bundle.cve_id,
        exploit_executed=exploit_executed,
        exploit_succeeded=exploit_succeeded,
        rule_alerted=rule_alerted,
        blocked=blocked,
        evidence={
            "mode": "mock",
            "payload": payload,
            "encoded_payload": encoded_payload,
            "rule_hash": bundle.rule.content_hash,
            "exploit_hash": bundle.exploit.content_hash,
        },
    )
