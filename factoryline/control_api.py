"""Dependency-free REST adapter for the local control-plane contract.

The WSGI application deliberately does not authenticate headers. A deployment
adapter must verify its OIDC, SSO, or SCM credential first and then pass the
verified subject, tenant, and roles in the explicit headers below. Missing or
unverified identity data is rejected; no anonymous tenant is created.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote, urlsplit

from .control_plane import ControlPlaneError, EvidenceStore, Principal


IDENTITY_HEADERS = (
    "HTTP_X_FACTORY_SUBJECT",
    "HTTP_X_FACTORY_TENANT",
    "HTTP_X_FACTORY_ROLES",
)


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode(
        "utf-8"
    )


def _finish(start_response: Callable, status: str, value: Any) -> list[bytes]:
    body = _json_bytes(value)
    start_response(
        status,
        [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
    )
    return [body]


def _principal(environ: dict[str, Any]) -> Principal:
    missing = [name for name in IDENTITY_HEADERS if not environ.get(name)]
    if missing:
        raise ControlPlaneError(
            "E_IDENTITY_REQUIRED",
            "verified subject, tenant, and roles headers are required",
        )
    roles = tuple(
        sorted(
            {
                item.strip()
                for item in environ[IDENTITY_HEADERS[2]].split(",")
                if item.strip()
            }
        )
    )
    return Principal(
        subject=str(environ[IDENTITY_HEADERS[0]]),
        tenant_id=str(environ[IDENTITY_HEADERS[1]]),
        roles=roles,
    )


def _body(environ: dict[str, Any]) -> dict[str, Any]:
    try:
        length = int(environ.get("CONTENT_LENGTH") or "0")
        raw = environ["wsgi.input"].read(length)
        value = json.loads(raw.decode("utf-8"))
    except (KeyError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControlPlaneError(
            "E_INVALID_JSON", "request body must be a JSON object"
        ) from exc
    if not isinstance(value, dict):
        raise ControlPlaneError("E_INVALID_JSON", "request body must be a JSON object")
    return value


class ControlPlaneAPI:
    """Small REST surface over :class:`EvidenceStore` for local integration tests."""

    def __init__(self, db_path: Path):
        self.store = EvidenceStore(Path(db_path))

    def _health_route(
        self, method: str, path: list[str], start_response: Callable
    ) -> list[bytes] | None:
        if method != "GET" or path != ["healthz"]:
            return None
        return _finish(
            start_response,
            "200 OK",
            {"schema": "factory.control-plane.health.v1", "ok": True},
        )

    def _evidence_route(
        self,
        method: str,
        path: list[str],
        principal: Principal,
        environ: dict[str, Any],
        start_response: Callable,
    ) -> list[bytes] | None:
        if method == "POST" and path == ["v1", "evidence"]:
            return _finish(
                start_response, "201 Created", self.store.put(principal, _body(environ))
            )
        if method == "GET" and len(path) == 3 and path[2] != "":
            return _finish(
                start_response,
                "200 OK",
                self.store.get(principal, principal.tenant_id, path[2]),
            )
        if method == "GET" and path == ["v1", "evidence"]:
            return _finish(
                start_response,
                "200 OK",
                {
                    "schema": "factory.evidence.list.v1",
                    "tenant_id": principal.tenant_id,
                    "records": self.store.list(principal, principal.tenant_id),
                },
            )
        return None

    def _approval_route(
        self,
        method: str,
        path: list[str],
        principal: Principal,
        environ: dict[str, Any],
        start_response: Callable,
    ) -> list[bytes] | None:
        if method == "POST" and len(path) == 4 and path[2] == "approvals":
            body = _body(environ)
            return _finish(
                start_response,
                "201 Created",
                self.store.request_approval(
                    principal,
                    principal.tenant_id,
                    path[3],
                    str(body.get("reason", "")),
                ),
            )
        if (
            method == "POST"
            and len(path) == 5
            and path[2] == "approvals"
            and path[4] == "decision"
        ):
            body = _body(environ)
            return _finish(
                start_response,
                "200 OK",
                self.store.decide_approval(
                    principal,
                    principal.tenant_id,
                    path[3],
                    str(body.get("decision", "")),
                    str(body.get("reason", "")),
                ),
            )
        return None

    def _audit_route(
        self,
        method: str,
        path: list[str],
        principal: Principal,
        _environ: dict[str, Any],
        start_response: Callable,
    ) -> list[bytes] | None:
        if method != "GET" or path != ["v1", "audit"]:
            return None
        return _finish(
            start_response,
            "200 OK",
            self.store.verify_audit(principal, principal.tenant_id),
        )

    def _dispatch(
        self,
        method: str,
        path: list[str],
        environ: dict[str, Any],
        start_response: Callable,
    ) -> list[bytes]:
        health = self._health_route(method, path, start_response)
        if health is not None:
            return health
        if len(path) < 2 or path[0] != "v1" or path[1] not in {"evidence", "audit"}:
            raise ControlPlaneError("E_NOT_FOUND", "route not found")
        principal = _principal(environ)
        for handler in (self._evidence_route, self._approval_route, self._audit_route):
            response = handler(method, path, principal, environ, start_response)
            if response is not None:
                return response
        raise ControlPlaneError("E_NOT_FOUND", "route not found")

    def _error_response(
        self, exc: ControlPlaneError, start_response: Callable
    ) -> list[bytes]:
        status = _control_status(exc.code)
        return _finish(
            start_response,
            status,
            {
                "schema": "factory.control-plane.result.v1",
                "verdict": "ERROR",
                "error": {"code": exc.code, "message": exc.message},
            },
        )

    def __call__(
        self, environ: dict[str, Any], start_response: Callable
    ) -> list[bytes]:
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        path = [
            unquote(part)
            for part in urlsplit(str(environ.get("PATH_INFO", "/"))).path.split("/")
            if part
        ]
        try:
            return self._dispatch(method, path, environ, start_response)
        except ControlPlaneError as exc:
            return self._error_response(exc, start_response)


def _control_status(code: str) -> str:
    if code == "E_NOT_FOUND":
        return "404 Not Found"
    if code in {"E_ACTION_DENIED", "E_TENANT_BOUNDARY"}:
        return "403 Forbidden"
    return "400 Bad Request"


def create_app(db_path: Path) -> ControlPlaneAPI:
    """Return a WSGI app; deployment owns the server and authentication adapter."""
    return ControlPlaneAPI(Path(db_path))
