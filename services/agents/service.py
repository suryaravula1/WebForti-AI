from __future__ import annotations

import re
import urllib.parse

from webforti_common.models import ArtifactBundle, ArtifactType, GenerationPlan
from webforti_common.security import make_artifact


def generate_artifacts(plan: GenerationPlan, *, allow_egress: bool = False) -> ArtifactBundle:
    exploit = make_artifact(
        ArtifactType.EXPLOIT_SCRIPT,
        generate_verification_script(plan),
        "python",
        allow_egress=allow_egress,
    )
    rule = make_artifact(
        ArtifactType.SNORT_RULE,
        generate_snort_rule(plan),
        "snort",
        allow_egress=allow_egress,
    )
    docker_spec = make_artifact(
        ArtifactType.DOCKER_SPEC,
        generate_dockerfile(plan),
        "dockerfile",
        allow_egress=allow_egress,
    )
    return ArtifactBundle(cve_id=plan.cve_id, exploit=exploit, rule=rule, docker_spec=docker_spec)


def generate_verification_script(plan: GenerationPlan) -> str:
    payload = plan.expected_payload.replace("\\", "\\\\").replace('"', '\\"')
    return f'''import sys
import urllib.error
import urllib.parse
import urllib.request


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "http://target:8080"
    payload = "{payload}"
    if payload.startswith("/"):
        url = target.rstrip("/") + urllib.parse.quote(payload, safe="/.%_-")
    else:
        url = target.rstrip("/") + "/?probe=" + urllib.parse.quote(payload)
    request = urllib.request.Request(url, headers={{"User-Agent": "WebFortiVerifier/0.1"}})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            body = response.read().decode("utf-8", errors="ignore")
            print("status=" + str(response.status))
            success_marker_seen = payload in body or "root:" in body or "uid=" in body
            print("body_contains_payload=" + str(success_marker_seen).lower())
            return 0
    except urllib.error.HTTPError as exc:
        print("http_error=" + str(exc.code))
        return 0
    except Exception as exc:
        print("error=" + exc.__class__.__name__ + ":" + str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
'''


def generate_snort_rule(plan: GenerationPlan) -> str:
    sid = stable_sid(plan.cve_id)
    msg = f"WEBFORTI {plan.cve_id} {plan.target_service} exploit indicator"
    payload = encode_payload_for_http_probe(plan.expected_payload).replace("\\", "\\\\").replace('"', '\\"')
    return (
        f'alert tcp any any -> any any '
        f'(msg:"{msg}"; flow:to_server,established; content:"{payload}"; '
        f'classtype:web-application-attack; sid:{sid}; rev:1;)'
    )


def encode_payload_for_http_probe(payload: str) -> str:
    if payload.startswith("/"):
        return urllib.parse.quote(payload, safe="/.%_-")
    return urllib.parse.quote(payload)


def generate_dockerfile(plan: GenerationPlan) -> str:
    if plan.cve_id == "CVE-2021-41773" or "apache" in plan.target_service.lower():
        safe_cve = re.sub(r"[^a-zA-Z0-9_.:-]", "-", plan.cve_id)[:80]
        safe_version = re.sub(r"[^a-zA-Z0-9_.:-]", "-", plan.vulnerable_version)[:80]
        return f'''FROM webforti/sandbox-apache-ubuntu:latest
LABEL org.webforti.cve="{safe_cve}"
ENV WEBFORTI_TARGET_SERVICE="apache"
ENV WEBFORTI_VULNERABLE_VERSION="{safe_version}"
EXPOSE 8080
CMD ["apachectl", "-D", "FOREGROUND"]
'''

    safe_service = re.sub(r"[^a-zA-Z0-9_.:-]", "-", plan.target_service)[:80]
    safe_version = re.sub(r"[^a-zA-Z0-9_.:-]", "-", plan.vulnerable_version)[:80]
    return f'''FROM webforti/sandbox-target:latest
LABEL org.webforti.cve="{plan.cve_id}"
ENV WEBFORTI_TARGET_SERVICE="{safe_service}"
ENV WEBFORTI_VULNERABLE_VERSION="{safe_version}"
EXPOSE 8080
CMD ["python3", "-m", "http.server", "8080"]
'''


def stable_sid(cve_id: str) -> int:
    digits = "".join(ch for ch in cve_id if ch.isdigit())
    return 9000000 + (int(digits[-6:] or "1") % 999999)
