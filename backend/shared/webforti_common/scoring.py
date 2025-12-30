from __future__ import annotations

from webforti_common.models import VerificationResult, VerificationStatus


def score_verification(
    *,
    cve_id: str,
    exploit_executed: bool,
    exploit_succeeded: bool,
    rule_alerted: bool,
    blocked: bool,
    environment_error: str | None = None,
    evidence: dict | None = None,
) -> VerificationResult:
    if environment_error:
        return VerificationResult(
            cve_id=cve_id,
            status=VerificationStatus.ERROR,
            exploit_executed=exploit_executed,
            exploit_succeeded=exploit_succeeded,
            rule_alerted=rule_alerted,
            blocked=blocked,
            effectiveness_score=0.0,
            confidence_score=0.2,
            evidence={**(evidence or {}), "environment_error": environment_error},
        )

    detection_score = 0.45 if rule_alerted else 0.0
    mitigation_score = 0.45 if blocked or (exploit_executed and not exploit_succeeded) else 0.0
    execution_score = 0.10 if exploit_executed else 0.0
    total = round(detection_score + mitigation_score + execution_score, 2)
    passed = exploit_executed and rule_alerted and (blocked or not exploit_succeeded)

    return VerificationResult(
        cve_id=cve_id,
        status=VerificationStatus.PASS if passed else VerificationStatus.FAIL,
        exploit_executed=exploit_executed,
        exploit_succeeded=exploit_succeeded,
        rule_alerted=rule_alerted,
        blocked=blocked,
        effectiveness_score=total,
        confidence_score=0.85 if exploit_executed else 0.35,
        evidence=evidence or {},
    )
