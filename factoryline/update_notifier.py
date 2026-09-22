"""Read-only local update notifications for Code Factory clients."""

from __future__ import annotations

from hashlib import sha256
import json
import re
from pathlib import Path
from typing import Any


UPDATE_MANIFEST_SCHEMA = "factory.update-manifest.v1"
UPDATE_NOTICE_SCHEMA = "factory.update-notice.v1"
_VERSION = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:[-+][0-9A-Za-z.-]+)?$")


class UpdateNotifierError(ValueError):
    """Invalid or unverifiable local update metadata."""


def _version(value: object, field: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise UpdateNotifierError(f"{field} must be a semantic version like 0.46.7")
    parts = value.split("-", 1)[0].split("+", 1)[0].split(".")
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


def _text(value: object, field: str, maximum: int = 300) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum:
        raise UpdateNotifierError(f"{field} must be bounded text")
    return value.strip()


def _digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_manifest(manifest: object) -> dict[str, Any]:
    """Validate a local release manifest without contacting a provider."""
    if not isinstance(manifest, dict) or manifest.get("schema") != UPDATE_MANIFEST_SCHEMA:
        raise UpdateNotifierError(f"manifest must use {UPDATE_MANIFEST_SCHEMA}")
    channel = _text(manifest.get("channel", "stable"), "channel", 40)
    releases = manifest.get("releases")
    if not isinstance(releases, list) or not releases:
        raise UpdateNotifierError("manifest releases must be a non-empty list")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for release in releases:
        if not isinstance(release, dict):
            raise UpdateNotifierError("each release must be an object")
        version = _text(release.get("version"), "release.version", 40)
        _version(version, "release.version")
        if version in seen:
            raise UpdateNotifierError("release versions must be unique")
        seen.add(version)
        normalized.append({
            "version": version,
            "released_at": _text(release.get("released_at"), "release.released_at", 80),
            "summary": _text(release.get("summary"), "release.summary", 512),
        })
    normalized.sort(key=lambda item: _version(item["version"], "release.version"), reverse=True)
    return {"schema": UPDATE_MANIFEST_SCHEMA, "channel": channel, "releases": normalized}


def check_for_update(installed_version: str, manifest: object, *, channel: str = "stable") -> dict[str, Any]:
    """Return a deterministic notice for the newest local release, if any."""
    installed = _text(installed_version, "installed_version", 40)
    installed_tuple = _version(installed, "installed_version")
    normalized = validate_manifest(manifest)
    if normalized["channel"] != channel:
        raise UpdateNotifierError("requested channel does not match manifest channel")
    newer = [release for release in normalized["releases"] if _version(release["version"], "release.version") > installed_tuple]
    latest = newer[0] if newer else None
    status = "UPDATE_AVAILABLE" if latest else "UP_TO_DATE"
    core = {
        "schema": UPDATE_NOTICE_SCHEMA,
        "marker": status,
        "channel": channel,
        "installed_version": installed,
        "latest_version": latest["version"] if latest else installed,
        "release": latest,
        "manifest_sha256": _digest(normalized),
        "authority": {"download": False, "install": False, "restart": False, "publish": False},
        "claim_boundary": "Local manifest comparison only; no provider request, download, installation, restart, or release action ran.",
    }
    return {**core, "notice_sha256": _digest(core)}


def read_manifest(path: Path) -> dict[str, Any]:
    """Read and validate a JSON release manifest from a local path."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateNotifierError(f"unable to read update manifest: {exc}") from exc
    return validate_manifest(value)
