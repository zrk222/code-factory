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
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")


def _finish(start_response: Callable, status: str, value: Any) -> list[bytes]:
    body = _json_bytes(value)
    start_response(status, [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
    return [body]


def _principal(environ: dict[str, Any]) -> Principal:
    missing = [name for name in IDENTITY_HEADERS if not environ.get(name)]
    if missing:
        raise ControlPlaneError("E_IDENTITY_REQUIRED", "verified subject, tenant, and roles headers are required")
    roles = tuple(sorted({item.strip() for item in environ[IDENTITY_HEADERS[2]].split(",") if item.strip()}))
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
        raise ControlPlaneError("E_INVALID_JSON", "request body must be a JSON object") from exc
    if not isinstance(value, dict):
        raise ControlPlaneError("E_INVALID_JSON", "request body must be a JSON object")
    return value


class ControlPlaneAPI:
    """Small REST surface over :class:`EvidenceStore` for local integration tests."""

    def __init__(self, db_path: Path):
        self.store = EvidenceStore(Path(db_path))

    def __call__(self, environ: dict[str, Any], start_response: Callable) -> list[bytes]:
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        path = [unquote(part) for part in urlsplit(str(environ.get("PATH_INFO", "/"))).path.split("/") if part]
        try:
            if method == "GET" and path == ["healthz"]:
                return _finish(start_response, "200 OK", {"schema": "factory.control-plane.health.v1", "ok": True})
            if len(path) < 2 or path[0] != "v1" or path[1] not in {"evidence", "audit"}:
                raise ControlPlaneError("E_NOT_FOUND", "route not found")
            principal = _principal(environ)
            if method == "POST" and path == ["v1", "evidence"]:
                return _finish(start_response, "201 Created", self.store.put(principal, _body(environ)))
            if method == "GET" and len(path) == 3 and path[2] != "":
                return _finish(start_response, "200 OK", self.store.get(principal, principal.tenant_id, path[2]))
            if method == "GET" and path == ["v1", "evidence"]:
                return _finish(start_response, "200 OK", {
                    "schema": "factory.evidence.list.v1",
                    "tenant_id": principal.tenant_id,
                    "records": self.store.list(principal, principal.tenant_id),
                })
            if method == "POST" and len(path) == 4 and path[2] == "approvals":
                body = _body(environ)
                return _finish(start_response, "201 Created", self.store.request_approval(
                    principal, principal.tenant_id, path[3], str(body.get("reason", ""))
                ))
            if method == "POST" and len(path) == 5 and path[2] == "approvals" and path[4] == "decision":
                body = _body(environ)
                return _finish(start_response, "200 OK", self.store.decide_approval(
                    principal, principal.tenant_id, path[3], str(body.get("decision", "")), str(body.get("reason", ""))
                ))
            if method == "GET" and path == ["v1", "audit"]:
                return _finish(start_response, "200 OK", self.store.verify_audit(principal, principal.tenant_id))
            raise ControlPlaneError("E_NOT_FOUND", "route not found")
        except ControlPlaneError as exc:
            status = "404 Not Found" if exc.code == "E_NOT_FOUND" else "403 Forbidden" if exc.code in {"E_ACTION_DENIED", "E_TENANT_BOUNDARY"} else "400 Bad Request"
            return _finish(start_response, status, {
                "schema": "factory.control-plane.result.v1",
                "verdict": "ERROR",
                "error": {"code": exc.code, "message": exc.message},
            })


def create_app(db_path: Path) -> ControlPlaneAPI:
    """Return a WSGI app; deployment owns the server and authentication adapter."""
    return ControlPlaneAPI(Path(db_path))
