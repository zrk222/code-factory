"""Explicitly authorized GitHub App Check publisher for hosted PR assurance."""
from __future__ import annotations

import base64
import json
import re
import time
from typing import Any, Callable
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .hosted_identity import HttpTransport
from .pr_assurance import PRAssuranceError


REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
GITHUB_API_VERSION = "2022-11-28"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _app_jwt(app_id: int, private_key_pem: str, now: int) -> str:
    header = _b64(b'{"alg":"RS256","typ":"JWT"}')
    payload = _b64(json.dumps({"iat": now - 30, "exp": now + 570, "iss": str(app_id)}, separators=(",", ":")).encode())
    try:
        key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        signature = key.sign(f"{header}.{payload}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    except (TypeError, ValueError) as exc:
        raise PRAssuranceError("E_GITHUB_KEY", "GitHub App private key is invalid") from exc
    return f"{header}.{payload}.{_b64(signature)}"


class GitHubAppPublisher:
    """Mint short-lived installation credentials and publish bound Check requests."""

    def __init__(
        self,
        *,
        app_id: int,
        private_key_pem: str,
        transport: HttpTransport,
        api_base: str = "https://api.github.com",
        clock: Callable[[], float] = time.time,
    ):
        if app_id <= 0 or "PRIVATE KEY" not in private_key_pem:
            raise PRAssuranceError("E_GITHUB_CONFIG", "positive app id and PEM private key are required")
        parts = urlsplit(api_base)
        if parts.scheme != "https" or not parts.netloc or parts.path not in {"", "/"}:
            raise PRAssuranceError("E_GITHUB_CONFIG", "GitHub API base must be an HTTPS origin")
        self.app_id = app_id
        self.private_key_pem = private_key_pem
        self.transport = transport
        self.api_base = api_base.rstrip("/")
        self.clock = clock

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }

    def publish(self, installation_id: int, repository: str, request: dict[str, Any]) -> int:
        """Exchange an App JWT, publish one Check, and return its positive remote id."""
        if installation_id <= 0 or not REPOSITORY_RE.fullmatch(repository):
            raise PRAssuranceError("E_GITHUB_TARGET", "GitHub installation and repository are invalid")
        installation_token = self._installation_token(installation_id)
        payload = {key: value for key, value in request.items() if key not in {"schema", "marker"}}
        published = self.transport.request(
            "POST", f"{self.api_base}/repos/{repository}/check-runs",
            headers=self._headers(installation_token), json=payload,
        )
        return self._check_id(published)

    def _installation_token(self, installation_id: int) -> str:
        app_token = _app_jwt(self.app_id, self.private_key_pem, int(self.clock()))
        response = self.transport.request(
            "POST", f"{self.api_base}/app/installations/{installation_id}/access_tokens",
            headers=self._headers(app_token), json={},
        )
        if response.status_code != 201:
            raise PRAssuranceError("E_GITHUB_TOKEN", "GitHub installation token exchange failed")
        body = response.json()
        installation_token = body.get("token") if isinstance(body, dict) else None
        if not isinstance(installation_token, str) or not installation_token:
            raise PRAssuranceError("E_GITHUB_TOKEN", "GitHub token response omitted the credential")
        return installation_token

    @staticmethod
    def _check_id(published: Any) -> int:
        if published.status_code != 201:
            raise PRAssuranceError("E_GITHUB_PUBLISH", "GitHub Check publication failed")
        result = published.json()
        check_id = result.get("id") if isinstance(result, dict) else None
        if not isinstance(check_id, int) or check_id <= 0:
            raise PRAssuranceError("E_GITHUB_RESPONSE", "GitHub Check response omitted a positive id")
        return check_id


def publish_check(
    publisher: GitHubAppPublisher, installation_id: int, repository: str, request: dict[str, Any]
) -> int:
    """Publish one bound Check through explicit GitHub App authority or refuse it."""
    return publisher.publish(installation_id, repository, request)
