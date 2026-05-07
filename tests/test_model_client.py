from __future__ import annotations

import io
import json
import urllib.error
from unittest.mock import patch

from webforti_common.model_client import OpenAICompatibleModelClient, build_model_client
from webforti_common.models import CVERecord
from webforti_common.settings import Settings


class _Response:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


def _valid_completion() -> dict:
    return {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "cve_id": "CVE-2099-0001",
                            "target_service": "demo",
                            "vulnerable_version": "1.0",
                            "attack_vector": "http",
                            "expected_payload": "probe",
                            "defense_strategy": "detect probe",
                            "snort_rule_requirements": ["match probe"],
                            "environment_requirements": ["isolated"],
                            "verification_assertions": ["alert is raised"],
                            "source_context_ids": [],
                        }
                    )
                }
            }
        ]
    }


def test_openrouter_provider_sets_base_url_and_headers() -> None:
    client = build_model_client(
        Settings(
            model_provider="openrouter",
            model_name="qwen/test",
            openai_api_key="secret",
            openrouter_site_url="http://localhost:8000",
            openrouter_app_title="WebForti Test",
        )
    )

    assert isinstance(client, OpenAICompatibleModelClient)
    assert client.base_url == "https://openrouter.ai/api/v1"
    assert client.extra_headers == {
        "HTTP-Referer": "http://localhost:8000",
        "X-Title": "WebForti Test",
    }


def test_openai_compatible_retries_without_response_format() -> None:
    cve = CVERecord(cve_id="CVE-2099-0001", title="demo", description="demo vulnerability")
    calls = []

    def fake_urlopen(request, timeout):  # type: ignore[no-untyped-def]
        calls.append(json.loads(request.data.decode("utf-8")))
        if len(calls) == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                400,
                "Bad Request",
                {},
                io.BytesIO(b'{"error":"response_format is not supported"}'),
            )
        return _Response(_valid_completion())

    client = OpenAICompatibleModelClient("https://example.test/v1", "secret", "qwen/test")
    with patch("urllib.request.urlopen", fake_urlopen):
        plan = client.create_generation_plan(cve, [])

    assert plan["cve_id"] == "CVE-2099-0001"
    assert "response_format" in calls[0]
    assert "response_format" not in calls[1]
