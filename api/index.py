"""Vercel's Python WSGI entrypoint for the isolated Meta connector project."""

from __future__ import annotations

from typing import Any, Callable, Mapping

from factoryline.meta_connector_api import app as connector_app


def app(environ: Mapping[str, Any], start_response: Callable) -> list[bytes]:
    """Remove only Vercel's /api mount prefix before core route dispatch."""
    path = str(environ.get("PATH_INFO", "/"))
    if path == "/api":
        path = "/"
    elif path.startswith("/api/"):
        path = path[4:]
    mounted = dict(environ)
    mounted["PATH_INFO"] = path
    return connector_app(mounted, start_response)
