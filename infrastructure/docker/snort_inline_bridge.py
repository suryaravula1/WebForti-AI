from __future__ import annotations

import os
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


SNORT_RULE = os.getenv("SNORT_RULE", "")
TARGET_URL = os.getenv("TARGET_URL", "http://target:8080").rstrip("/")
BLOCK_ON_ALERT = os.getenv("BLOCK_ON_ALERT", "true").lower() == "true"
SNORT_CONFIG = os.getenv("SNORT_CONFIG", "/snort3/lua/snort.lua")
SNORT_DAQ_DIR = os.getenv("SNORT_DAQ_DIR", "/usr/local/lib/daq")


class SnortInlineBridge(BaseHTTPRequestHandler):
    server_version = "WebFortiSnortInlineBridge/0.1"

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def log_message(self, fmt: str, *args: object) -> None:
        print("WEBFORTI_INLINE_REQUEST " + fmt % args, flush=True)

    def _handle(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        print(f'WEBFORTI_INLINE_REQUEST "{self.command} {self.path} HTTP/1.1"', flush=True)
        snort_result = evaluate_with_snort(self.path, body)
        if snort_result["alerted"]:
            print("WEBFORTI_INLINE_SNORT_ALERT output=" + repr(snort_result["output_tail"]), flush=True)
            if BLOCK_ON_ALERT:
                print("WEBFORTI_INLINE_BLOCKED reason=snort_alert", flush=True)
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"blocked by WebForti Snort inline bridge\n")
                return

        request = urllib.request.Request(
            TARGET_URL + self.path,
            data=body if self.command == "POST" else None,
            headers={"User-Agent": self.headers.get("User-Agent", "WebFortiInlineBridge")},
            method=self.command,
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                response_body = response.read()
                self.send_response(response.status)
                self.end_headers()
                self.wfile.write(response_body)
        except urllib.error.HTTPError as exc:
            self.send_response(exc.code)
            self.end_headers()
            self.wfile.write(exc.read())
        except Exception as exc:
            print("WEBFORTI_INLINE_ERROR " + exc.__class__.__name__ + ":" + str(exc), flush=True)
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b"inline bridge upstream error\n")


def evaluate_with_snort(request_path: str, body: bytes) -> dict:
    with tempfile.TemporaryDirectory(prefix="webforti-inline-") as tmp:
        work_dir = Path(tmp)
        rules_file = work_dir / "webforti.rules"
        pcap_file = work_dir / "webforti-live.pcap"
        rules_file.write_text(SNORT_RULE.strip() + "\n", encoding="utf-8")
        write_http_request_path_pcap(pcap_file, request_path, body)
        result = subprocess.run(
            [
                "snort",
                "--daq-dir",
                SNORT_DAQ_DIR,
                "-c",
                SNORT_CONFIG,
                "-R",
                str(rules_file),
                "-r",
                str(pcap_file),
                "-A",
                "alert_fast",
            ],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    output = (result.stdout + "\n" + result.stderr).strip()
    return {
        "alerted": result.returncode == 0 and snort_output_has_alert(output),
        "exit_code": result.returncode,
        "output_tail": output[-1200:],
    }


def write_http_request_path_pcap(path: Path, request_path: str, body: bytes) -> None:
    method = "POST" if body else "GET"
    http_payload = (
        f"{method} {request_path} HTTP/1.1\r\n"
        "Host: target\r\n"
        "User-Agent: WebFortiVerifier/0.1\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("utf-8") + body
    src_ip = "10.10.0.2"
    dst_ip = "10.10.0.3"
    src_port = 44444
    dst_port = 8080
    client_seq = 1000
    server_seq = 5000
    packets = [
        ethernet_ipv4_tcp_frame(src_ip, dst_ip, src_port, dst_port, client_seq, 0, 0x02, b"", 1),
        ethernet_ipv4_tcp_frame(dst_ip, src_ip, dst_port, src_port, server_seq, client_seq + 1, 0x12, b"", 2),
        ethernet_ipv4_tcp_frame(src_ip, dst_ip, src_port, dst_port, client_seq + 1, server_seq + 1, 0x18, http_payload, 3),
    ]
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        timestamp = int(time.time())
        for index, packet in enumerate(packets):
            handle.write(struct.pack("<IIII", timestamp, index * 1000, len(packet), len(packet)))
            handle.write(packet)


def ethernet_ipv4_tcp_frame(
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
    tcp_header = make_tcp_header(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)
    ip_header = make_ipv4_header(src_ip, dst_ip, len(tcp_header) + len(payload), ident)
    return ethernet + ip_header + tcp_header + payload


def make_ipv4_header(src_ip: str, dst_ip: str, payload_len: int, ident: int) -> bytes:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + payload_len, ident, 0x4000, 64, 6, 0, src, dst)
    checksum = internet_checksum(header)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + payload_len, ident, 0x4000, 64, 6, checksum, src, dst)


def make_tcp_header(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    header = struct.pack("!HHLLBBHHH", src_port, dst_port, seq, ack, 5 << 4, flags, 64240, 0, 0)
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    checksum = internet_checksum(pseudo + header + payload)
    return struct.pack("!HHLLBBHHH", src_port, dst_port, seq, ack, 5 << 4, flags, 64240, checksum, 0)


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def snort_output_has_alert(output: str) -> bool:
    lowered = output.lower()
    return "webforti" in output or "[**]" in output or "logged: 1" in lowered or "alert: 1" in lowered


def main() -> int:
    print(f"WEBFORTI_INLINE_READY target={TARGET_URL} block_on_alert={BLOCK_ON_ALERT}", flush=True)
    server = ThreadingHTTPServer(("0.0.0.0", 8080), SnortInlineBridge)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
