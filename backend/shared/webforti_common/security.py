from __future__ import annotations

import hashlib
import re

from webforti_common.models import Artifact, ArtifactType


BLOCKED_SCRIPT_PATTERNS = [
    r"\bos\.system\s*\(",
    r"\bsubprocess\.",
    r"\bsocket\.socket\s*\(",
    r"\bparamiko\b",
    r"\bscapy\b",
    r"\bshutil\.rmtree\s*\(",
    r"\bopen\s*\(\s*['\"]/(etc|var|usr|bin|sbin|System|Users)",
]

BLOCKED_DOCKERFILE_PATTERNS = [
    r"--privileged",
    r"\bADD\s+https?://",
    r"\bRUN\s+curl\b",
    r"\bRUN\s+wget\b",
    r"\bUSER\s+root\b.*\b--privileged\b",
    r"/var/run/docker\.sock",
    r"\bmount\b",
]


def sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def validate_python_verification_script(content: str) -> list[str]:
    errors: list[str] = []
    for pattern in BLOCKED_SCRIPT_PATTERNS:
        if re.search(pattern, content):
            errors.append(f"blocked script pattern: {pattern}")
    if "requests." not in content and "urllib.request" not in content:
        errors.append("verification script must use HTTP client traffic")
    if "__main__" not in content:
        errors.append("verification script must expose a __main__ entry point")
    return errors


def validate_snort_rule(content: str) -> list[str]:
    errors: list[str] = []
    normalized = content.strip()
    if not normalized.startswith("alert "):
        errors.append("Snort rule must start with alert")
    if "sid:" not in normalized:
        errors.append("Snort rule must include sid")
    if "rev:" not in normalized:
        errors.append("Snort rule must include rev")
    if "msg:" not in normalized:
        errors.append("Snort rule must include msg")
    if "content:" not in normalized and "pcre:" not in normalized:
        errors.append("Snort rule must include content or pcre match")
    return errors


def validate_dockerfile(content: str, allow_egress: bool = False) -> list[str]:
    errors: list[str] = []
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    if not lines or not lines[0].startswith("FROM "):
        errors.append("Dockerfile must start with FROM")
    for pattern in BLOCKED_DOCKERFILE_PATTERNS:
        if re.search(pattern, content, flags=re.IGNORECASE):
            errors.append(f"blocked Dockerfile pattern: {pattern}")
    if not allow_egress and re.search(r"\b(apt-get|apk|yum|dnf|pip)\s+.*install\b", content):
        errors.append("package installation requires egress allowlist or prebuilt base image")
    return errors


def make_artifact(artifact_type: ArtifactType, content: str, language: str, allow_egress: bool = False) -> Artifact:
    if artifact_type == ArtifactType.EXPLOIT_SCRIPT:
        errors = validate_python_verification_script(content)
    elif artifact_type == ArtifactType.SNORT_RULE:
        errors = validate_snort_rule(content)
    elif artifact_type == ArtifactType.DOCKER_SPEC:
        errors = validate_dockerfile(content, allow_egress=allow_egress)
    else:
        errors = []
    return Artifact(
        artifact_type=artifact_type,
        content=content,
        language=language,
        content_hash=sha256_text(content),
        validation_errors=errors,
    )
