"""Bounded HTTPS transport and rotating JWKS cache for the hosted adapter."""
from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlsplit

from .pr_assurance import PRAssuranceError


NETWORK_TIMEOUT_SECONDS = 5.0
JWKS_TTL_SECONDS = 300
JWKS_MAX_STALE_SECONDS = 900


class HttpResponse(Protocol):
    """Minimal response contract used by identity and GitHub adapters."""

    status_code: int

    def json(self) -> Any:
        """Return the decoded JSON response body."""
        ...


class HttpTransport(Protocol):
    """Injectable bounded HTTP contract that keeps tests network-free."""

    def request(
        self, method: str, url: str, *, headers: Mapping[str, str] | None = None, json: Any = None
    ) -> HttpResponse:
        """Send one bounded HTTPS request and return a minimal response."""
        ...


class HttpxTransport:
    """Production HTTPS transport with fixed timeout and redirects disabled."""

    def __init__(self, *, timeout_seconds: float = NETWORK_TIMEOUT_SECONDS):
        if timeout_seconds != NETWORK_TIMEOUT_SECONDS:
            raise PRAssuranceError("E_HTTP_CONFIG", "hosted transport timeout must be exactly 5 seconds")
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - optional install
            raise PRAssuranceError("E_HOSTED_DEPENDENCY", "install factoryline-code-factory[hosted]") from exc
        self._client = httpx.Client(timeout=timeout_seconds, follow_redirects=False)

    def request(
        self, method: str, url: str, *, headers: Mapping[str, str] | None = None, json: Any = None
    ) -> HttpResponse:
        """Send one request only to HTTPS without redirects or secret logging."""
        if urlsplit(url).scheme != "https":
            raise PRAssuranceError("E_HTTP_SCHEME", "hosted network destinations must use HTTPS")
        try:
            return self._client.request(method, url, headers=dict(headers or {}), json=json)
        except Exception as exc:
            raise PRAssuranceError("E_HTTP_UNAVAILABLE", "hosted HTTPS request failed") from exc


@dataclass
class JwksCache:
    """Freshness-bounded JWKS cache that never accepts indefinitely stale keys."""

    url: str
    transport: HttpTransport
    clock: Callable[[], float] = time.time
    _value: dict[str, Any] | None = None
    _loaded_at: float = 0.0

    def __post_init__(self) -> None:
        parts = urlsplit(self.url)
        if parts.scheme != "https" or not parts.netloc or parts.username or parts.password:
            raise PRAssuranceError("E_JWKS_URL", "JWKS URL must be credential-free HTTPS")

    def get(self) -> dict[str, Any]:
        """Return fresh JWKS, refresh at 300 seconds, and reject beyond 900 seconds."""
        now = self.clock()
        age = now - self._loaded_at
        if self._value is not None and age < JWKS_TTL_SECONDS:
            return self._value
        try:
            return self._refresh(now)
        except PRAssuranceError:
            if self._value is not None and age <= JWKS_MAX_STALE_SECONDS:
                return self._value
            raise
        except Exception as exc:
            if self._value is not None and age <= JWKS_MAX_STALE_SECONDS:
                return self._value
            raise PRAssuranceError("E_JWKS_UNAVAILABLE", "JWKS refresh failed without usable cache") from exc

    def _refresh(self, now: float) -> dict[str, Any]:
        response = self.transport.request("GET", self.url, headers={"Accept": "application/json"})
        if response.status_code != 200:
            raise PRAssuranceError("E_JWKS_HTTP", "JWKS endpoint did not return HTTP 200")
        value = response.json()
        if not isinstance(value, dict) or not isinstance(value.get("keys"), list) or not value["keys"]:
            raise PRAssuranceError("E_JWKS_SHAPE", "JWKS response must contain a non-empty keys list")
        self._value = value
        self._loaded_at = now
        return value


def get_jwks(cache: JwksCache) -> dict[str, Any]:
    """Return freshness-bounded JWKS or raise a classified identity refusal."""
    return cache.get()
