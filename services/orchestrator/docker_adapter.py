from __future__ import annotations

import os
import ast
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from webforti_common.models import ArtifactBundle, VerificationResult
from webforti_common.scoring import score_verification


CONTENT_RE = re.compile(r'content:"((?:\\.|[^"\\])*)"', re.IGNORECASE)
SENSOR_REQUEST_RE = re.compile(r'WEBFORTI_(?:SENSOR_LOG|INLINE_REQUEST) "([A-Z]+) ([^ ]+) HTTP/[0-9.]+"')


@dataclass(frozen=True, slots=True)
class DockerVerificationConfig:
    repo_root: Path
    timeout_seconds: int = 60
    block_on_alert: bool = True
    keep_images: bool = False
    snort_image: str = "openeuler/snort3:3.9.5.0-oe2403sp1"


def parse_snort_content_terms(rule: str) -> list[str]:
    return [bytes(match.group(1), "utf-8").decode("unicode_escape") for match in CONTENT_RE.finditer(rule)]


def verify_bundle_with_docker(bundle: ArtifactBundle, config: DockerVerificationConfig) -> VerificationResult:
    if not shutil.which("docker"):
        return _environment_error(bundle, "docker CLI is not installed")

    suffix = uuid4().hex[:12]
    attacker_network = f"webforti-attacker-net-{suffix}"
    target_network = f"webforti-target-net-{suffix}"
    target_container = f"webforti-target-{suffix}"
    sensor_container = f"webforti-ips-{suffix}"
    target_image = f"webforti-target:{suffix}"
    sensor_image = "webforti/snort-inline-ips:latest"
    attacker_image = f"webforti-kali-attacker:{suffix}"
    base_image = "webforti/sandbox-target:latest"
    apache_base_image = "webforti/sandbox-apache-ubuntu:latest"
    temp_dir = Path(tempfile.mkdtemp(prefix="webforti-verify-"))
    cleanup_containers = [target_container, sensor_container]
    cleanup_images = [target_image, attacker_image]

    try:
        _docker(["info"], timeout=15)
        snort_validation = validate_rule_with_snort(bundle.rule.content, config, temp_dir / "snort-validation")
        if not snort_validation["valid"]:
            return score_verification(
                cve_id=bundle.cve_id,
                exploit_executed=False,
                exploit_succeeded=False,
                rule_alerted=False,
                blocked=False,
                environment_error="Snort 3 rule validation failed",
                evidence={"mode": "docker", "snort_validation": snort_validation},
            )
        payload = extract_payload_from_script(bundle.exploit.content) or (parse_snort_content_terms(bundle.rule.content)[0] if parse_snort_content_terms(bundle.rule.content) else bundle.cve_id)
        snort_pcap_detection = detect_rule_with_snort_pcap(
            bundle.rule.content,
            payload,
            config,
            temp_dir / "snort-pcap",
        )
        _ensure_base_image(base_image, config.repo_root)
        _ensure_apache_base_image(apache_base_image, config.repo_root, bundle.docker_spec.content)
        _ensure_sensor_image(sensor_image, config.repo_root)

        target_dir = temp_dir / "target"
        attacker_dir = temp_dir / "attacker"
        target_dir.mkdir()
        attacker_dir.mkdir()
        (target_dir / "Dockerfile").write_text(bundle.docker_spec.content, encoding="utf-8")
        (attacker_dir / "Dockerfile").write_text(
            "FROM kalilinux/kali-rolling\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates && rm -rf /var/lib/apt/lists/*\n"
            "WORKDIR /app\n"
            "COPY exploit.py /app/exploit.py\n"
            "ENTRYPOINT [\"python3\", \"/app/exploit.py\"]\n",
            encoding="utf-8",
        )
        (attacker_dir / "exploit.py").write_text(bundle.exploit.content, encoding="utf-8")

        _docker(["network", "create", "--internal", attacker_network], timeout=15)
        _docker(["network", "create", "--internal", target_network], timeout=15)
        _docker(["build", "-q", "-t", target_image, str(target_dir)], timeout=config.timeout_seconds)
        _docker(["build", "-q", "-t", attacker_image, str(attacker_dir)], timeout=config.timeout_seconds)

        _docker(
            ["run", "-d", "--name", target_container, "--network", target_network, "--network-alias", "target", target_image],
            timeout=15,
        )
        time.sleep(1.0)
        _docker(
            [
                "run",
                "-d",
                "--name",
                sensor_container,
                "--network", attacker_network,
                "--network-alias", "ips",
                "--cap-add",
                "NET_RAW",
                "--cap-add",
                "NET_ADMIN",
                "-e",
                "TARGET_URL=http://target:8080",
                "-e",
                f"SNORT_RULE={bundle.rule.content}",
                "-e",
                f"BLOCK_ON_ALERT={str(config.block_on_alert).lower()}",
                sensor_image,
            ],
            timeout=15,
        )
        _docker(["network", "connect", "--alias", "ips-target", target_network, sensor_container], timeout=15)
        time.sleep(1.0)

        attacker = _docker(
            ["run", "--rm", "--network", attacker_network, attacker_image, "http://ips:8080"],
            timeout=config.timeout_seconds,
            check=False,
        )
        sensor_logs = _docker(["logs", sensor_container], timeout=15, check=False).stdout
        live_request_path = extract_request_path_from_sensor_logs(sensor_logs)
        snort_live_request_detection = detect_rule_with_snort_request_path(
            bundle.rule.content,
            live_request_path,
            config,
            temp_dir / "snort-live-request",
        ) if live_request_path else {
            "alerted": False,
            "request_path": None,
            "reason": "no live sensor request path captured",
        }

        exploit_executed = attacker.returncode in {0, 1} or bool(attacker.stdout or attacker.stderr)
        inline_ips_alerted = "WEBFORTI_INLINE_SNORT_ALERT" in sensor_logs
        snort_interface_alerted = False
        snort_live_alerted = bool(snort_interface_alerted or snort_live_request_detection["alerted"])
        snort_runtime_alerted = bool(snort_pcap_detection["alerted"] or snort_live_alerted or inline_ips_alerted)
        rule_alerted = snort_runtime_alerted
        blocked = "WEBFORTI_INLINE_BLOCKED" in sensor_logs or "http_error=403" in attacker.stdout
        exploit_succeeded = "body_contains_payload=true" in attacker.stdout.lower() and not blocked
        environment_error = None
        if attacker.returncode not in {0, 1}:
            environment_error = f"attacker exited with code {attacker.returncode}"
        if "WEBFORTI_INLINE_ERROR" in sensor_logs:
            environment_error = "inline bridge upstream error"

        return score_verification(
            cve_id=bundle.cve_id,
            exploit_executed=exploit_executed,
            exploit_succeeded=exploit_succeeded,
            rule_alerted=rule_alerted,
            blocked=blocked,
            environment_error=environment_error,
            evidence={
                "mode": "docker",
                "topology": ["kali-attacker", "snort-inline-ips-bridge", "ubuntu-target"],
                "attacker_image_family": "kalilinux/kali-rolling",
                "target_image_family": "ubuntu:24.04",
                "inline_ips_bridge": True,
                "network_internal": True,
                "networks": {
                    "attacker_network": attacker_network,
                    "target_network": target_network,
                },
                "snort_validation": snort_validation,
                "snort_runtime_alerted": snort_runtime_alerted,
                "snort_live_alerted": snort_live_alerted,
                "snort_interface_alerted": snort_interface_alerted,
                "snort_inline_alerted": inline_ips_alerted,
                "snort_inline_blocked": blocked,
                "snort_pcap_detection": snort_pcap_detection,
                "snort_live_request_detection": snort_live_request_detection,
                "proxy_alerted": False,
                "snort_content_terms": parse_snort_content_terms(bundle.rule.content),
                "attacker_stdout": attacker.stdout[-4000:],
                "attacker_stderr": attacker.stderr[-4000:],
                "sensor_logs": sensor_logs[-4000:],
            },
        )
    except Exception as exc:
        return _environment_error(bundle, str(exc))
    finally:
        for container in cleanup_containers:
            _docker(["rm", "-f", container], timeout=15, check=False)
        _docker(["network", "rm", attacker_network], timeout=15, check=False)
        _docker(["network", "rm", target_network], timeout=15, check=False)
        if not config.keep_images:
            for image in cleanup_images:
                _docker(["rmi", "-f", image], timeout=30, check=False)
        shutil.rmtree(temp_dir, ignore_errors=True)


def _ensure_base_image(image: str, repo_root: Path) -> None:
    if _docker(["image", "inspect", image], timeout=15, check=False).returncode == 0:
        return
    _docker(["build", "-q", "-f", str(repo_root / "infrastructure/docker/Dockerfile.sandbox-target"), "-t", image, str(repo_root)], timeout=180)


def _ensure_apache_base_image(image: str, repo_root: Path, docker_spec: str) -> None:
    if image not in docker_spec:
        return
    if _docker(["image", "inspect", image], timeout=15, check=False).returncode == 0:
        return
    _docker(["build", "-q", "-f", str(repo_root / "infrastructure/docker/Dockerfile.sandbox-apache-ubuntu"), "-t", image, str(repo_root)], timeout=240)


def _ensure_sensor_image(image: str, repo_root: Path) -> None:
    _docker(["build", "-q", "-f", str(repo_root / "infrastructure/docker/Dockerfile.snort-runtime-sensor"), "-t", image, str(repo_root)], timeout=180)


def validate_rule_with_snort(rule: str, config: DockerVerificationConfig, work_dir: Path) -> dict:
    work_dir.mkdir(parents=True, exist_ok=True)
    rules_file = work_dir / "webforti.rules"
    rules_file.write_text(rule.strip() + "\n", encoding="utf-8")
    result = _docker(
        [
            "run",
            "--rm",
            "-e",
            "LD_LIBRARY_PATH=/usr/local/lib",
            "-v",
            f"{work_dir}:/rules:ro",
            config.snort_image,
            "bash",
            "-lc",
            "snort --daq-dir /usr/local/lib/daq -c /snort3/lua/snort.lua -R /rules/webforti.rules -T",
        ],
        timeout=config.timeout_seconds,
        check=False,
    )
    output = (result.stdout + "\n" + result.stderr).strip()
    return {
        "valid": result.returncode == 0 and "successfully validated" in output.lower(),
        "image": config.snort_image,
        "exit_code": result.returncode,
        "output_tail": output[-4000:],
    }


def detect_rule_with_snort_pcap(rule: str, payload: str, config: DockerVerificationConfig, work_dir: Path) -> dict:
    return detect_rule_with_snort_request_path(rule, request_path_for_payload(payload), config, work_dir, payload=payload)


def detect_rule_with_snort_request_path(
    rule: str,
    request_path: str,
    config: DockerVerificationConfig,
    work_dir: Path,
    *,
    payload: str | None = None,
) -> dict:
    work_dir.mkdir(parents=True, exist_ok=True)
    rules_file = work_dir / "webforti.rules"
    pcap_file = work_dir / "webforti-probe.pcap"
    rules_file.write_text(rule.strip() + "\n", encoding="utf-8")
    write_http_request_path_pcap(pcap_file, request_path)
    result = _docker(
        [
            "run",
            "--rm",
            "-e",
            "LD_LIBRARY_PATH=/usr/local/lib",
            "-v",
            f"{work_dir}:/rules:ro",
            config.snort_image,
            "bash",
            "-lc",
            "snort --daq-dir /usr/local/lib/daq -c /snort3/lua/snort.lua -R /rules/webforti.rules -r /rules/webforti-probe.pcap -A alert_fast",
        ],
        timeout=config.timeout_seconds,
        check=False,
    )
    output = (result.stdout + "\n" + result.stderr).strip()
    return {
        "alerted": result.returncode == 0 and _snort_output_has_alert(output),
        "image": config.snort_image,
        "exit_code": result.returncode,
        "payload": payload,
        "request_path": request_path,
        "pcap": "webforti-probe.pcap",
        "output_tail": output[-4000:],
    }


def extract_payload_from_script(script: str) -> str | None:
    for line in script.splitlines():
        stripped = line.strip()
        if stripped.startswith("payload = "):
            return str(ast.literal_eval(stripped.split("=", 1)[1].strip()))
    return None


def extract_request_path_from_sensor_logs(sensor_logs: str) -> str | None:
    matches = SENSOR_REQUEST_RE.findall(sensor_logs)
    if not matches:
        return None
    return matches[-1][1]


def request_path_for_payload(payload: str) -> str:
    if payload.startswith("/"):
        return urllib.parse.quote(payload, safe="/.%_-")
    return "/?probe=" + urllib.parse.quote(payload)


def write_http_probe_pcap(path: Path, payload: str) -> None:
    write_http_request_path_pcap(path, request_path_for_payload(payload))


def write_http_request_path_pcap(path: Path, request_path: str) -> None:
    http_payload = (
        f"GET {request_path} HTTP/1.1\r\n"
        "Host: target\r\n"
        "User-Agent: WebFortiVerifier/0.1\r\n"
        "Connection: close\r\n\r\n"
    ).encode("utf-8")
    src_ip = "10.10.0.2"
    dst_ip = "10.10.0.3"
    src_port = 44444
    dst_port = 8080
    client_seq = 1000
    server_seq = 5000
    packets = [
        _ethernet_ipv4_tcp_frame(src_ip, dst_ip, src_port, dst_port, client_seq, 0, 0x02, b"", 1),
        _ethernet_ipv4_tcp_frame(dst_ip, src_ip, dst_port, src_port, server_seq, client_seq + 1, 0x12, b"", 2),
        _ethernet_ipv4_tcp_frame(src_ip, dst_ip, src_port, dst_port, client_seq + 1, server_seq + 1, 0x18, http_payload, 3),
    ]
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        timestamp = int(time.time())
        for index, packet in enumerate(packets):
            handle.write(struct.pack("<IIII", timestamp, index * 1000, len(packet), len(packet)))
            handle.write(packet)


def _ethernet_ipv4_tcp_frame(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
    ident: int,
) -> bytes:
    src_mac = bytes.fromhex("020000000002")
    dst_mac = bytes.fromhex("020000000003")
    ethernet = dst_mac + src_mac + struct.pack("!H", 0x0800)
    tcp_header = _tcp_header(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)
    ip_header = _ipv4_header(src_ip, dst_ip, len(tcp_header) + len(payload), ident)
    return ethernet + ip_header + tcp_header + payload


def _ipv4_header(src_ip: str, dst_ip: str, payload_len: int, ident: int) -> bytes:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + payload_len, ident, 0x4000, 64, 6, 0, src, dst)
    checksum = _checksum(header)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + payload_len, ident, 0x4000, 64, 6, checksum, src, dst)


def _tcp_header(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    header = struct.pack("!HHLLBBHHH", src_port, dst_port, seq, ack, 5 << 4, flags, 64240, 0, 0)
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    checksum = _checksum(pseudo + header + payload)
    return struct.pack("!HHLLBBHHH", src_port, dst_port, seq, ack, 5 << 4, flags, 64240, checksum, 0)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _snort_output_has_alert(output: str) -> bool:
    return bool(
        re.search(r"\blogged:\s*[1-9]", output)
        or re.search(r"\balert:\s*[1-9]", output)
        or "WEBFORTI" in output
        or "[**]" in output
    )


def _docker(args: list[str], *, timeout: int, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "DOCKER_BUILDKIT": "1"}
    result = subprocess.run(
        ["docker", *args],
        text=True,
        capture_output=True,
        timeout=timeout,
        env=env,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            "docker command failed: docker "
            + " ".join(args)
            + f"\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def _environment_error(bundle: ArtifactBundle, error: str) -> VerificationResult:
    return score_verification(
        cve_id=bundle.cve_id,
        exploit_executed=False,
        exploit_succeeded=False,
        rule_alerted=False,
        blocked=False,
        environment_error=error,
        evidence={"mode": "docker"},
    )
