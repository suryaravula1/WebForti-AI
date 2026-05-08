from __future__ import annotations

from fastapi.testclient import TestClient

from services.gateway import main as gateway_main
from webforti_common.settings import Settings


def test_gateway_auth_protects_job_routes(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(gateway_main, "settings", Settings(gateway_api_key="expected"))
    client = TestClient(gateway_main.app)

    assert client.get("/health").status_code == 200
    assert client.get("/jobs").status_code == 401
    assert client.get("/jobs", headers={"X-WebForti-API-Key": "wrong"}).status_code == 401
    assert client.get("/jobs", headers={"X-WebForti-API-Key": "expected"}).status_code == 200
