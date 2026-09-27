"""Vercel's Python WSGI entrypoint for the isolated Meta connector project."""

from __future__ import annotations

from hmac import compare_digest
import json
import os
from typing import Any, Callable, Mapping

from factoryline.meta_connector_api import app as connector_app
from factoryline.meta_connector_api import create_meta_connector_app_from_env


def app(environ: Mapping[str, Any], start_response: Callable) -> list[bytes]:
    """Remove only Vercel's /api mount prefix before core route dispatch."""
    path = str(environ.get("PATH_INFO", "/"))
    if path == "/api/internal/retention":
        secret = os.environ.get("CRON_SECRET", "")
        token = str(environ.get("HTTP_AUTHORIZATION", ""))
        if not secret or len(secret) < 32 or not compare_digest(token, f"Bearer {secret}"):
            body, status = b'{"error":"unauthorized"}', "401 Unauthorized"
        elif environ.get("REQUEST_METHOD") != "GET":
            body, status = b'{"error":"not found"}', "404 Not Found"
        else:
            deleted = create_meta_connector_app_from_env().purge_expired()
            body = json.dumps({"schema": "factory.meta.retention.v1", "deleted": deleted}).encode()
            status = "200 OK"
        start_response(status, [("Content-Type", "application/json"), ("Cache-Control", "no-store")])
        return [body]
    if path == "/api":
        path = "/"
    elif path.startswith("/api/"):
        path = path[4:]
    mounted = dict(environ)
    mounted["PATH_INFO"] = path
    return connector_app(mounted, start_response)
