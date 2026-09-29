"""Bounded HTTPS transport and rotating JWKS cache for the hosted adapter."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
import socket
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
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        json: Any = None,
    ) -> HttpResponse:
        """Send one bounded HTTPS request and return a minimal response."""
        ...


class HttpxTransport:
    """Production HTTPS transport with public-address pinning and host allowlists."""

    def __init__(self, *, timeout_seconds: float = NETWORK_TIMEOUT_SECONDS):
        if timeout_seconds != NETWORK_TIMEOUT_SECONDS:
            raise PRAssuranceError(
                "E_HTTP_CONFIG", "hosted transport timeout must be exactly 5 seconds"
            )
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - optional install
            raise PRAssuranceError(
                "E_HOSTED_DEPENDENCY", "install factoryline-code-factory[hosted]"
            ) from exc
        self._client = httpx.Client(
            timeout=timeout_seconds, follow_redirects=False, trust_env=False
        )

    @staticmethod
    def _is_public_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return address.is_global and not address.is_multicast

    @staticmethod
    def _validate_https_destination(url: str) -> tuple[str, str]:
        parts = urlsplit(url)
        host = (parts.hostname or "").rstrip(".").lower()
        if (
            not host
            or parts.username
            or parts.password
            or parts.port not in (None, 443)
        ):
            raise PRAssuranceError("E_HTTP_DESTINATION", "HTTPS host is invalid")
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            allowed = {"api.github.com"}
            allowed.update(
                item.strip().rstrip(".").lower()
                for item in os.environ.get(
                    "FACTORY_HOSTED_JWKS_ALLOWED_HOSTS", ""
                ).split(",")
                if item.strip()
            )
            if host not in allowed:
                raise PRAssuranceError(
                    "E_HTTP_DESTINATION",
                    "HTTPS hostname is not in the deployment allowlist",
                )
            try:
                resolved = socket.getaddrinfo(
                    host, parts.port or 443, type=socket.SOCK_STREAM
                )
                addresses = list(
                    dict.fromkeys(ipaddress.ip_address(item[4][0]) for item in resolved)
                )
            except (OSError, ValueError, IndexError) as exc:
                raise PRAssuranceError(
                    "E_HTTP_DESTINATION", "HTTPS hostname did not resolve safely"
                ) from exc
            if (
                not addresses
                or len(addresses) > 16
                or any(
                    not HttpxTransport._is_public_ip(address) for address in addresses
                )
            ):
                raise PRAssuranceError(
                    "E_HTTP_DESTINATION",
                    "HTTPS hostname resolves to a non-public address",
                )
            return host, str(addresses[0])
        else:
            if not HttpxTransport._is_public_ip(literal):
                raise PRAssuranceError(
                    "E_HTTP_DESTINATION", "HTTPS IP address is not globally routable"
                )
            return host, str(literal)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        json: Any = None,
    ) -> HttpResponse:
        """Send one request only to HTTPS without redirects or secret logging."""
        if urlsplit(url).scheme != "https":
            raise PRAssuranceError(
                "E_HTTP_SCHEME", "hosted network destinations must use HTTPS"
            )
        host, address = self._validate_https_destination(url)
        try:
            parts = urlsplit(url)
            pinned_host = f"[{address}]" if ":" in address else address
            pinned_netloc = (
                f"{pinned_host}:{parts.port}" if parts.port is not None else pinned_host
            )
            pinned_url = parts._replace(netloc=pinned_netloc).geturl()
            request_headers = dict(headers or {})
            host_header_name = host.encode("idna").decode("ascii")
            host_header = (
                f"[{host_header_name}]" if ":" in host_header_name else host_header_name
            )
            if parts.port is not None:
                host_header = f"{host_header}:{parts.port}"
            request_headers["Host"] = host_header
            request = self._client.build_request(
                method, pinned_url, headers=request_headers, json=json
            )
            try:
                ipaddress.ip_address(host)
            except ValueError:
                request.extensions["sni_hostname"] = host_header_name
            return self._client.send(request)
        except Exception as exc:
            raise PRAssuranceError(
                "E_HTTP_UNAVAILABLE", "hosted HTTPS request failed"
            ) from exc


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
        if (
            parts.scheme != "https"
            or not parts.netloc
            or parts.username
            or parts.password
        ):
            raise PRAssuranceError(
                "E_JWKS_URL", "JWKS URL must be credential-free HTTPS"
            )

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
            raise PRAssuranceError(
                "E_JWKS_UNAVAILABLE", "JWKS refresh failed without usable cache"
            ) from exc

    def _refresh(self, now: float) -> dict[str, Any]:
        response = self.transport.request(
            "GET", self.url, headers={"Accept": "application/json"}
        )
        if response.status_code != 200:
            raise PRAssuranceError(
                "E_JWKS_HTTP", "JWKS endpoint did not return HTTP 200"
            )
        value = response.json()
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("keys"), list)
            or not value["keys"]
        ):
            raise PRAssuranceError(
                "E_JWKS_SHAPE", "JWKS response must contain a non-empty keys list"
            )
        self._value = value
        self._loaded_at = now
        return value


def get_jwks(cache: JwksCache) -> dict[str, Any]:
    """Return freshness-bounded JWKS or raise a classified identity refusal."""
    return cache.get()
