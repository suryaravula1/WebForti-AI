from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest

from services.orchestrator.docker_adapter import (
    DockerVerificationConfig,
    detect_rule_with_snort_pcap,
    extract_request_path_from_sensor_logs,
    parse_snort_content_terms,
    request_path_for_payload,
    validate_rule_with_snort,
)


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=15).returncode == 0


def test_parse_snort_content_terms() -> None:
    rule = 'alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"x"; content:"/.%2e/"; http_uri; sid:1; rev:1;)'
    assert parse_snort_content_terms(rule) == ["/.%2e/"]


def test_request_path_helpers() -> None:
    logs = 'WEBFORTI_SENSOR_LOG "GET /?probe=class.module.classLoader HTTP/1.1" 403 -'
    inline_logs = 'WEBFORTI_INLINE_REQUEST "GET /cgi-bin/.%2e/bin/sh HTTP/1.1"'

    assert request_path_for_payload("class.module.classLoader") == "/?probe=class.module.classLoader"
    assert request_path_for_payload("/cgi-bin/.%2e/bin/sh") == "/cgi-bin/.%2e/bin/sh"
    assert extract_request_path_from_sensor_logs(logs) == "/?probe=class.module.classLoader"
    assert extract_request_path_from_sensor_logs(inline_logs) == "/cgi-bin/.%2e/bin/sh"


def test_validate_rule_with_snort_when_docker_available(tmp_path: Path) -> None:
    if not docker_available():
        pytest.skip("Docker daemon is not available")
    rule = 'alert tcp any any -> $HOME_NET $HTTP_PORTS (msg:"x"; content:"/.%2e/"; http_uri; sid:9141773; rev:1;)'
    result = validate_rule_with_snort(
        rule,
        DockerVerificationConfig(repo_root=Path.cwd(), timeout_seconds=60),
        tmp_path,
    )
    assert result["valid"], result["output_tail"]


def test_detect_rule_with_snort_pcap_when_docker_available(tmp_path: Path) -> None:
    if not docker_available():
        pytest.skip("Docker daemon is not available")
    rule = 'alert tcp any any -> any any (msg:"WEBFORTI test"; flow:to_server,established; content:"probe-token"; sid:9000001; rev:1;)'
    result = detect_rule_with_snort_pcap(
        rule,
        "probe-token",
        DockerVerificationConfig(repo_root=Path.cwd(), timeout_seconds=60),
        tmp_path,
    )
    assert result["alerted"], result["output_tail"]
