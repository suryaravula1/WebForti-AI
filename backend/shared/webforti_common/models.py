from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class JobStatus(str, Enum):
    QUEUED = "queued"
    INGESTING = "ingesting"
    RETRIEVING_CONTEXT = "retrieving_context"
    PLANNING = "planning"
    GENERATING_ARTIFACTS = "generating_artifacts"
    VALIDATING_ARTIFACTS = "validating_artifacts"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"


class ArtifactType(str, Enum):
    EXPLOIT_SCRIPT = "exploit_script"
    SNORT_RULE = "snort_rule"
    DOCKER_SPEC = "docker_spec"
    REPORT = "report"


class VerificationStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


@dataclass(slots=True)
class CVERecord:
    cve_id: str
    title: str
    description: str
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    published_at: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.cve_id.startswith("CVE-"):
            raise ValueError("cve_id must start with CVE-")
        if not self.description.strip():
            raise ValueError("description is required")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Job:
    job_id: str
    cve_id: str
    status: JobStatus = JobStatus.QUEUED
    current_stage: str = "queued"
    submitted_by: str = "local"
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    @classmethod
    def create(cls, cve_id: str, submitted_by: str = "local") -> "Job":
        return cls(job_id=str(uuid4()), cve_id=cve_id, submitted_by=submitted_by)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["created_at"] = self.created_at.isoformat()
        data["updated_at"] = self.updated_at.isoformat()
        return data


@dataclass(slots=True)
class JobEvent:
    job_id: str
    stage: JobStatus
    message: str
    created_at: datetime = field(default_factory=utc_now)
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["stage"] = self.stage.value
        data["created_at"] = self.created_at.isoformat()
        return data


@dataclass(slots=True)
class GenerationPlan:
    cve_id: str
    target_service: str
    vulnerable_version: str
    attack_vector: str
    expected_payload: str
    defense_strategy: str
    snort_rule_requirements: list[str]
    environment_requirements: list[str]
    verification_assertions: list[str]
    source_context_ids: list[str] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "GenerationPlan":
        list_fields = [
            "snort_rule_requirements",
            "environment_requirements",
            "verification_assertions",
        ]
        normalized = dict(data)
        for key in list_fields:
            value = normalized.get(key)
            if isinstance(value, str):
                normalized[key] = [value]
            elif value is None:
                normalized[key] = []
        plan = cls(**normalized)
        plan.validate()
        return plan

    def validate(self) -> None:
        required = [
            self.cve_id,
            self.target_service,
            self.vulnerable_version,
            self.attack_vector,
            self.expected_payload,
            self.defense_strategy,
        ]
        if any(not str(value).strip() for value in required):
            raise ValueError("generation plan contains empty required fields")
        if len(self.verification_assertions) == 0:
            raise ValueError("generation plan must include verification assertions")
        if len(self.snort_rule_requirements) == 0:
            raise ValueError("generation plan must include Snort requirements")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Artifact:
    artifact_type: ArtifactType
    content: str
    language: str
    content_hash: str
    validation_errors: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not self.validation_errors

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "Artifact":
        return cls(
            artifact_type=ArtifactType(data["artifact_type"]),
            content=data["content"],
            language=data["language"],
            content_hash=data["content_hash"],
            validation_errors=list(data.get("validation_errors", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["artifact_type"] = self.artifact_type.value
        return data


@dataclass(slots=True)
class ArtifactBundle:
    cve_id: str
    exploit: Artifact
    rule: Artifact
    docker_spec: Artifact

    def is_complete(self) -> bool:
        return all([self.exploit.is_valid, self.rule.is_valid, self.docker_spec.is_valid])

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ArtifactBundle":
        return cls(
            cve_id=data["cve_id"],
            exploit=Artifact.from_mapping(data["exploit"]),
            rule=Artifact.from_mapping(data["rule"]),
            docker_spec=Artifact.from_mapping(data["docker_spec"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "exploit": self.exploit.to_dict(),
            "rule": self.rule.to_dict(),
            "docker_spec": self.docker_spec.to_dict(),
            "complete": self.is_complete(),
        }


@dataclass(slots=True)
class VerificationResult:
    cve_id: str
    status: VerificationStatus
    exploit_executed: bool
    exploit_succeeded: bool
    rule_alerted: bool
    blocked: bool
    effectiveness_score: float
    confidence_score: float
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data
