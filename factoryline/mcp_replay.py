"""Deterministic retry and cache hints for one-shot MCP responses.

The hints are client-facing metadata only.  They do not create a replay
ledger, deduplicate requests on the server, or change the read-only MCP
authority boundary.
"""

from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any


DEFAULT_CACHE_TTL_SECONDS = 300
MAX_CACHE_TTL_SECONDS = 900
_REQUEST_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_AUTHORITY = {
    "execution": False,
    "approval": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


class McpReplayHintsError(ValueError):
    """Raised when replay metadata input is outside the bounded contract."""

    def __init__(self, message: str, marker: str = "MCP_REPLAY_HINTS_INVALID"):
        super().__init__(message)
        self.marker = marker


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _response_digest(response: object) -> str | None:
    if response is None:
        return None
    try:
        encoded = _canonical(response).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise McpReplayHintsError("response must be JSON-serializable") from exc
    return f"sha256:{sha256(encoded).hexdigest()}"


def build_stateless_replay_hints(
    request_sha256: str,
    response: object,
    *,
    ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
) -> dict[str, Any]:
    """Return bounded, deterministic client retry and cache metadata.

    ``request_sha256`` is the digest already bound to the stateless request.
    A successful response may be cached by a client for the short TTL; error
    and notification responses are not cacheable.  Fresh requests remain the
    only freshness mechanism because this adapter stores no replay state.
    """
    if not isinstance(request_sha256, str) or not _REQUEST_DIGEST.fullmatch(
        request_sha256
    ):
        raise McpReplayHintsError("request_sha256 must be a lowercase SHA-256 digest")
    if type(ttl_seconds) is not int or not 0 <= ttl_seconds <= MAX_CACHE_TTL_SECONDS:
        raise McpReplayHintsError(
            f"ttl_seconds must be an integer between 0 and {MAX_CACHE_TTL_SECONDS}"
        )

    response_digest = _response_digest(response)
    is_error = isinstance(response, dict) and isinstance(response.get("error"), dict)
    cacheable = response is not None and not is_error
    effective_ttl = ttl_seconds if cacheable else 0
    return {
        "schema": "factory.mcp.replay-hints.v1",
        "marker": "MCP_STATELESS_REPLAY_HINTS",
        "requestKey": f"sha256:{request_sha256}",
        "responseSha256": response_digest,
        "retry": {
            "safe": True,
            "scope": "one_request",
            "serverReplayStore": False,
            "duplicateExecution": False,
            "requiresFreshRequest": True,
        },
        "cache": {
            "mode": "client_hint_only",
            "cacheable": cacheable,
            "ttlSeconds": effective_ttl,
            "revalidate": "Repeat the request and compare responseSha256; no server cache or replay state exists.",
        },
        "authority": dict(_AUTHORITY),
        "claimBoundary": "Retry and cache metadata only; no server-side idempotency ledger, deduplication, execution, approval, publication, deployment, signing, credential, connector, or provider action ran.",
    }
