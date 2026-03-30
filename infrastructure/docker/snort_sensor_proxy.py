from __future__ import annotations

import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


CONTENT_RE = re.compile(r'content:"((?:\\.|[^"\\])*)"', re.IGNORECASE)


def parse_content_terms(rule: str) -> list[str]:
    terms: list[str] = []
    for match in CONTENT_RE.finditer(rule):
        raw = match.group(1)
        terms.append(bytes(raw, "utf-8").decode("unicode_escape"))
    return terms


SNORT_RULE = os.getenv("SNORT_RULE", "")
TARGET_URL = os.getenv("TARGET_URL", "http://target:8080").rstrip("/")
BLOCK_ON_ALERT = os.getenv("BLOCK_ON_ALERT", "true").lower() == "true"
CONTENT_TERMS = parse_content_terms(SNORT_RULE)


class SensorProxy(BaseHTTPRequestHandler):
    server_version = "WebFortiSnortSensor/0.1"

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def log_message(self, fmt: str, *args: object) -> None:
        print("WEBFORTI_SENSOR_LOG " + fmt % args, flush=True)

    def _handle(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        decoded_path = urllib.parse.unquote(self.path)
        evidence = self.path + "\n" + decoded_path + "\n" + body.decode("utf-8", errors="ignore")
        matched = [term for term in CONTENT_TERMS if term and term in evidence]
        if matched:
            print("WEBFORTI_ALERT matched=" + repr(matched), flush=True)
            if BLOCK_ON_ALERT:
                print("WEBFORTI_BLOCKED reason=content_match", flush=True)
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"blocked by WebForti Snort sensor\n")
                return

        request = urllib.request.Request(
            TARGET_URL + self.path,
            data=body if self.command == "POST" else None,
            headers={"User-Agent": self.headers.get("User-Agent", "WebFortiSensor")},
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
            print("WEBFORTI_SENSOR_ERROR " + exc.__class__.__name__ + ":" + str(exc), flush=True)
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b"sensor upstream error\n")


def main() -> int:
    print("WEBFORTI_SENSOR_READY target=" + TARGET_URL + " terms=" + repr(CONTENT_TERMS), flush=True)
    server = ThreadingHTTPServer(("0.0.0.0", 8080), SensorProxy)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
