from __future__ import annotations

import hmac

from fastapi import HTTPException

from webforti_common.settings import Settings


API_KEY_HEADER = "X-WebForti-API-Key"


def verify_gateway_api_key(settings: Settings, provided_key: str | None) -> None:
    if not settings.gateway_api_key:
        return
    if not provided_key or not hmac.compare_digest(provided_key, settings.gateway_api_key):
        raise HTTPException(status_code=401, detail="invalid API key")
