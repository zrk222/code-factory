"""Tell the user a newer version exists. Never install it for them.

WHY THIS IS A NOTIFIER AND NOT AN AUTO-UPDATER
----------------------------------------------
Two reasons, and the second is the real one.

First, mechanically: pip is pull-only. Nothing can push code into an already
installed Python environment. Any "auto-update" for a PyPI package means the
package silently modifying the user's environment from inside itself, which is a
self-modifying supply chain and is treated as an anti-pattern for good reason.

Second, and this decides it: this product's central claim is that nothing
consequential happens without approval. Shipping a component that rewrites a
user's installed software without asking would contradict the thing being sold,
in the one place a security-minded buyer would look hardest.

So this module reports and stops. It prints the command; a human runs it.

PRIVACY
-------
Interactive checks use one plain GET to the public PyPI JSON endpoint. The
request contains no project path, account identifier, usage data, or telemetry.
The result is cached per user so repeated runs stay offline. Failure is silent:
a version check must never break a build, and an air-gapped install must not be
nagged.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import platform
import re
import tempfile
import urllib.error
import urllib.request

from . import __version__

PACKAGE = "factoryline-code-factory"
PYPI_JSON = f"https://pypi.org/pypi/{PACKAGE}/json"
CACHE_TTL_HOURS = 24
TIMEOUT_SECONDS = 5
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_VERSION_PATTERN = re.compile(r"\A[0-9]+(?:\.[0-9]+){1,3}(?:[A-Za-z][A-Za-z0-9.]*)?\Z")
_CACHE_STATUSES = {"current", "update_available", "ahead_of_index", "unavailable"}


def _cache_path(root: Path) -> Path:
    return Path(root).resolve() / ".factory" / "update-check.json"


def user_cache_path(
    *,
    environ: dict[str, str] | None = None,
    system: str | None = None,
    home: Path | None = None,
) -> Path:
    """Return a per-user cache path without consulting the current project."""
    env = os.environ if environ is None else environ
    os_name = platform.system() if system is None else system
    user_home = Path.home() if home is None else Path(home)
    if os_name == "Windows":
        base = Path(env.get("LOCALAPPDATA") or user_home / "AppData" / "Local")
        return base / "CodeFactory" / "cache" / "update-check.json"
    if os_name == "Darwin":
        return user_home / "Library" / "Caches" / "CodeFactory" / "update-check.json"
    base = Path(env.get("XDG_CACHE_HOME") or user_home / ".cache")
    return base / "code-factory" / "update-check.json"


def _parse_version(value: str) -> tuple[int, ...]:
    """Best-effort numeric tuple for comparison.

    Deliberately simple. Non-numeric suffixes are dropped rather than guessed at,
    because a wrong ordering here would tell someone to downgrade.
    """
    parts: list[int] = []
    for chunk in value.split("."):
        # Leading digits only. Stripping every digit from "3rc1" would yield 31,
        # turning a release candidate into a version 28 releases ahead and
        # telling the user to "upgrade" to it.
        digits = ""
        for char in chunk:
            if not char.isdigit():
                break
            digits += char
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def _valid_version(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= 64
        and bool(_VERSION_PATTERN.fullmatch(value))
    )


def _make_result(latest: str | None, checked_at: str, *, cached: bool) -> dict:
    result: dict = {
        "package": PACKAGE,
        "installed": __version__,
        "latest": latest,
        "status": "unavailable",
        "action": None,
        "checked_at": checked_at,
        "cached": cached,
        "note": "This check reports only. It never installs or sends project or usage data.",
    }
    if latest is None:
        result["note"] = (
            "Version index unreachable; skipping quietly. This is not an error."
        )
        return result

    installed_v, latest_v = _parse_version(__version__), _parse_version(latest)
    width = max(len(installed_v), len(latest_v))
    installed_order = installed_v + (0,) * (width - len(installed_v))
    latest_order = latest_v + (0,) * (width - len(latest_v))
    if latest_order > installed_order:
        result["status"] = "update_available"
        result["action"] = f"pip install --upgrade {PACKAGE}=={latest}"
    elif latest_order < installed_order:
        result["status"] = "ahead_of_index"
        result["note"] = (
            f"Installed {__version__} is newer than the published {latest}. "
            "This usually means a release was tagged but never published."
        )
    else:
        result["status"] = "current"
    return result


def _read_cache(path: Path, installed_version: str = __version__) -> dict | None:
    try:
        cache_file = Path(path)
        if cache_file.stat().st_size > 16_384:
            return None
        payload = json.loads(cache_file.read_text(encoding="utf-8"))
        if (
            not isinstance(payload, dict)
            or payload.get("package") != PACKAGE
            or payload.get("installed") != installed_version
            or payload.get("status") not in _CACHE_STATUSES
            or not isinstance(payload.get("checked_at"), str)
        ):
            return None
        latest = payload.get("latest")
        if latest is not None and not _valid_version(latest):
            return None
        checked = datetime.fromisoformat(payload["checked_at"])
        if checked.tzinfo is None:
            return None
        checked = checked.astimezone(timezone.utc)
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValueError,
    ):
        return None
    age = datetime.now(timezone.utc) - checked
    if age < timedelta(minutes=-5):
        return None
    if age > timedelta(hours=CACHE_TTL_HOURS):
        return None
    result = _make_result(latest, checked.isoformat(), cached=True)
    if result["status"] != payload["status"]:
        return None
    return result


def _write_cache(path: Path, result: dict) -> None:
    try:
        cache_file = Path(path)
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=cache_file.parent,
            prefix=f"{cache_file.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(result, handle, indent=2)
        os.replace(temporary, cache_file)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except (OSError, UnboundLocalError):
            pass  # A read-only cache must never prevent a command from running.


def check_for_update(
    root: Path = Path("."),
    *,
    force: bool = False,
    cache_path: Path | None = None,
) -> dict:
    """Report whether a newer published release exists. Installs nothing.

    Returns a dict with ``status`` one of: ``current``, ``update_available``,
    ``ahead_of_index``, ``unavailable``. Never raises on network failure — an
    offline or air-gapped install gets ``unavailable`` and no nagging.
    """
    cache_file = Path(cache_path) if cache_path is not None else _cache_path(root)
    if not force:
        cached = _read_cache(cache_file)
        if cached:
            return cached

    checked_at = datetime.now(timezone.utc).isoformat()
    latest = None
    try:
        request = urllib.request.Request(
            PYPI_JSON, headers={"Accept": "application/json"}
        )
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError("version index response exceeded the size limit")
            payload = json.loads(body.decode("utf-8"))
            latest = payload["info"]["version"]
            if not _valid_version(latest):
                raise ValueError("version index returned an invalid package version")
    except (
        urllib.error.URLError,
        TimeoutError,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        OSError,
    ):
        latest = None

    result = _make_result(latest, checked_at, cached=False)
    _write_cache(cache_file, result)
    return result


def render(result: dict) -> str:
    """Format a check result as one short human line."""
    if result["status"] == "update_available":
        return (
            f"A newer Code Factory is available: {result['installed']} -> {result['latest']}\n"
            f"  {result['action']}\n"
            f"  Nothing was changed. Run that when you're ready."
        )
    if result["status"] == "ahead_of_index":
        return f"Installed {result['installed']}; published latest is {result['latest']}.\n  {result['note']}"
    if result["status"] == "current":
        return f"Code Factory {result['installed']} is the latest published release."
    return f"Could not reach the version index. {result['note']}"
