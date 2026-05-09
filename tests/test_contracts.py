from __future__ import annotations

from webforti_common.models import GenerationPlan
from webforti_common.scoring import score_verification
from webforti_common.security import validate_dockerfile, validate_snort_rule
from services.agents.service import encode_payload_for_http_probe, generate_dockerfile


def test_generation_plan_requires_assertions() -> None:
    try:
        GenerationPlan.from_mapping(
            {
                "cve_id": "CVE-2099-0001",
                "target_service": "demo",
                "vulnerable_version": "1.0",
                "attack_vector": "http",
                "expected_payload": "probe",
                "defense_strategy": "detect",
                "snort_rule_requirements": ["content match"],
                "environment_requirements": ["isolated"],
                "verification_assertions": [],
            }
        )
    except ValueError as exc:
        assert "verification assertions" in str(exc)
    else:
        raise AssertionError("GenerationPlan accepted an incomplete plan")


def test_snort_rule_validation_requires_detection_fields() -> None:
    errors = validate_snort_rule("alert tcp any any -> any any (msg:\"x\"; sid:1; rev:1;)")
    assert "Snort rule must include content or pcre match" in errors


def test_dockerfile_blocks_egress_install_by_default() -> None:
    errors = validate_dockerfile("FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y apache2\n")
    assert any("package installation" in error for error in errors)


def test_scoring_distinguishes_detection_from_blocking() -> None:
    result = score_verification(
        cve_id="CVE-2099-0001",
        exploit_executed=True,
        exploit_succeeded=True,
        rule_alerted=True,
        blocked=False,
    )
    assert result.status.value == "fail"
    assert result.rule_alerted is True
    assert result.blocked is False


def test_apache_cve_uses_real_httpd_target() -> None:
    plan = GenerationPlan.from_mapping(
        {
            "cve_id": "CVE-2021-41773",
            "target_service": "apache-httpd",
            "vulnerable_version": "2.4.49",
            "attack_vector": "path traversal",
            "expected_payload": "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
            "defense_strategy": "detect traversal",
            "snort_rule_requirements": ["match traversal"],
            "environment_requirements": ["isolated docker"],
            "verification_assertions": ["alert is raised"],
        }
    )

    dockerfile = generate_dockerfile(plan)

    assert dockerfile.startswith("FROM webforti/sandbox-apache-ubuntu:latest")
    assert 'WEBFORTI_VULNERABLE_VERSION="2.4.49"' in dockerfile


def test_snort_rule_payload_matches_transmitted_uri_encoding() -> None:
    assert encode_payload_for_http_probe("Benign <script>alert(1)</script>") == "Benign%20%3Cscript%3Ealert%281%29%3C/script%3E"
    assert encode_payload_for_http_probe("/cgi-bin/.%2e/bin/sh") == "/cgi-bin/.%2e/bin/sh"
