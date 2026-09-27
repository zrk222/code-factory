"""Verify Clerk OAuth access tokens using the provider's live introspection API."""

from __future__ import annotations

from base64 import b64encode
import time
from typing import Any

import httpx


class ClerkTokenError(Exception):
    """The access token could not be verified or is not authorized."""


def verify_clerk_oauth_token(
    token: str, endpoint: str, client_id: str, client_secret: str
) -> dict[str, Any]:
    """Require an active token from the one configured OAuth client.

    Clerk's OAuth JWT lifetime is one day and access tokens need not contain
    tenant_id, groups, or aud. Introspection pins the issuing client and checks
    revocation on every call. No token or provider error body is logged.
    """
    if not token or len(token) > 8192 or not client_id or not client_secret:
        raise ClerkTokenError("access token could not be verified")
    credentials = b64encode(f"{client_id}:{client_secret}".encode()).decode()
    try:
        response = httpx.post(
            endpoint,
            data={"token": token},
            headers={"Authorization": f"Basic {credentials}"},
            timeout=5,
            follow_redirects=False,
        )
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError):
        raise ClerkTokenError("access token could not be verified") from None
    if not isinstance(payload, dict) or payload.get("active") is not True:
        raise ClerkTokenError("access token is inactive")
    if payload.get("client_id") != client_id:
        raise ClerkTokenError("access token client does not match")
    if not isinstance(payload.get("sub"), str) or not payload["sub"]:
        raise ClerkTokenError("access token subject is invalid")
    if not isinstance(payload.get("scope"), str):
        raise ClerkTokenError("access token scopes are invalid")
    now = int(time.time())
    return {
        "signature_verified": True,
        "sub": payload["sub"],
        "scope": payload["scope"],
        # Active status comes from the provider, rather than a local JWT TTL.
        "iat": now,
        "exp": now + 1,
    }
