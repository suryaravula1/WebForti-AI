from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol

from webforti_common.models import CVERecord
from webforti_common.serialization import extract_json_object
from webforti_common.settings import Settings


class ModelClient(Protocol):
    def create_generation_plan(self, cve: CVERecord, context: list[dict]) -> dict:
        ...


@dataclass(slots=True)
class MockModelClient:
    model_name: str = "mock-security-planner"

    def create_generation_plan(self, cve: CVERecord, context: list[dict]) -> dict:
        if cve.cve_id in MOCK_PLAN_HINTS:
            target, version, payload, attack = MOCK_PLAN_HINTS[cve.cve_id]
            return self._plan(cve, context, target, version, payload, attack)

        lower = cve.description.lower()
        if "apache" in lower:
            target = "apache-httpd"
            version = "2.4.49"
            payload = "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
            attack = "path traversal request against Apache HTTP Server"
        elif "spring" in lower or "rce" in lower:
            target = "spring-web"
            version = "5.x"
            payload = "class.module.classLoader"
            attack = "HTTP parameter injection request"
        else:
            target = "generic-web-service"
            version = "vulnerable"
            payload = cve.cve_id
            attack = "HTTP request containing CVE-specific exploit indicator"

        return self._plan(cve, context, target, version, payload, attack)

    def _plan(
        self,
        cve: CVERecord,
        context: list[dict],
        target: str,
        version: str,
        payload: str,
        attack: str,
    ) -> dict:
        return {
            "cve_id": cve.cve_id,
            "target_service": target,
            "vulnerable_version": version,
            "attack_vector": attack,
            "expected_payload": payload,
            "defense_strategy": "detect exploit-specific HTTP payload and preserve evidence before analyst review",
            "snort_rule_requirements": [
                "alert on HTTP traffic to protected web service",
                "match the exploit payload indicator",
                "include unique sid and revision",
            ],
            "environment_requirements": [
                "isolated Docker bridge network",
                "attacker container, target container, and separate Snort sensor",
                "no external network egress during verification",
            ],
            "verification_assertions": [
                "exploit script exits successfully",
                "Snort raises an alert for the payload",
                "exploit objective is blocked or does not succeed",
            ],
            "source_context_ids": [str(item.get("id", "")) for item in context],
        }


MOCK_PLAN_HINTS: dict[str, tuple[str, str, str, str]] = {
    "CVE-2021-41773": (
        "apache-httpd",
        "2.4.49",
        "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
        "path traversal request against Apache HTTP Server",
    ),
    "CVE-2021-42013": (
        "apache-httpd",
        "2.4.50",
        "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
        "path traversal and command execution request against Apache HTTP Server",
    ),
    "CVE-2022-22965": (
        "spring-web",
        "5.x",
        "class.module.classLoader",
        "HTTP parameter injection request",
    ),
    "CVE-2023-29489": (
        "cpanel-web",
        "11.x",
        "\"><script>alert(1)</script>",
        "reflected XSS probe in an HTTP parameter",
    ),
    "CVE-2022-1388": (
        "f5-big-ip-icontrol",
        "vulnerable",
        "/mgmt/tm/util/bash",
        "iControl REST management endpoint request",
    ),
    "CVE-2019-19781": (
        "citrix-adc",
        "vulnerable",
        "/vpn/../vpns/cfg/smb.conf",
        "Citrix ADC path traversal request",
    ),
    "CVE-2021-44228": (
        "java-log4j-app",
        "2.0-2.14.1",
        "${jndi:ldap://127.0.0.1/a}",
        "Log4j lookup injection in an HTTP value",
    ),
    "CVE-2020-5902": (
        "f5-big-ip-tmui",
        "vulnerable",
        "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp",
        "TMUI path traversal request",
    ),
}


@dataclass(slots=True)
class OpenAICompatibleModelClient:
    base_url: str
    api_key: str
    model_name: str
    extra_headers: dict[str, str] | None = None

    def create_generation_plan(self, cve: CVERecord, context: list[dict]) -> dict:
        prompt = build_generation_plan_prompt(cve, context)
        payload = self._payload(prompt, include_response_format=True)
        try:
            result = self._post_chat_completion(payload)
        except RuntimeError as exc:
            if not _looks_like_response_format_error(str(exc)):
                raise
            result = self._post_chat_completion(self._payload(prompt, include_response_format=False))
        content = result["choices"][0]["message"]["content"]
        return extract_json_object(content)

    def _payload(self, prompt: str, *, include_response_format: bool) -> bytes:
        payload: dict[str, Any] = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": "Return only valid JSON matching the requested schema."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
        }
        if include_response_format:
            payload["response_format"] = {"type": "json_object"}
        return json.dumps(payload).encode("utf-8")

    def _post_chat_completion(self, payload: bytes) -> dict[str, Any]:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            **(self.extra_headers or {}),
        }
        request = urllib.request.Request(
            f"{self.base_url.rstrip('/')}/chat/completions",
            data=payload,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = _safe_error_body(exc)
            raise RuntimeError(f"OpenAI-compatible request failed with HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"OpenAI-compatible request failed: {exc}") from exc


def build_generation_plan_prompt(cve: CVERecord, context: list[dict]) -> str:
    schema = {
        "cve_id": "string",
        "target_service": "string",
        "vulnerable_version": "string",
        "attack_vector": "string",
        "expected_payload": "string",
        "defense_strategy": "string",
        "snort_rule_requirements": ["string"],
        "environment_requirements": ["string"],
        "verification_assertions": ["string"],
        "source_context_ids": ["string"],
    }
    return (
        "Create a constrained WebForti generation plan for controlled sandbox verification.\n"
        "Do not include hidden reasoning. Do not generate exploit code here.\n"
        f"Required JSON schema: {json.dumps(schema)}\n"
        f"CVE: {json.dumps(cve.to_dict())}\n"
        f"Retrieved context: {json.dumps(context)}"
    )


def build_model_client(settings: Settings) -> ModelClient:
    provider = settings.model_provider.lower()
    if provider == "openrouter":
        if not settings.openai_api_key:
            raise ValueError("OPENAI_API_KEY is required for OpenRouter model provider")
        base_url = settings.openai_compatible_url
        if base_url == "https://api.openai.com/v1":
            base_url = "https://openrouter.ai/api/v1"
        return OpenAICompatibleModelClient(
            base_url,
            settings.openai_api_key,
            settings.model_name,
            extra_headers={
                "HTTP-Referer": settings.openrouter_site_url,
                "X-Title": settings.openrouter_app_title,
            },
        )
    return MockModelClient(settings.model_name)


def _safe_error_body(exc: urllib.error.HTTPError) -> str:
    try:
        body = exc.read().decode("utf-8", errors="replace")
    except Exception:
        return "<unavailable>"
    return body[:1000]


def _looks_like_response_format_error(message: str) -> bool:
    lowered = message.lower()
    return "response_format" in lowered or "json_schema" in lowered or "json object" in lowered
