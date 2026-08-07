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
Off unless invoked. One plain GET to the public PyPI JSON endpoint, carrying no
identifiers, no usage data, no telemetry, and no query parameters. The result is
cached so repeated runs stay offline. Failure is silent: a version check must
never break a build, and an air-gapped install must not be nagged.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import urllib.error
import urllib.request

from . import __version__

PACKAGE = "factoryline-code-factory"
PYPI_JSON = f"https://pypi.org/pypi/{PACKAGE}/json"
CACHE_TTL_HOURS = 24
TIMEOUT_SECONDS = 5


def _cache_path(root: Path) -> Path:
    return Path(root).resolve() / ".factory" / "update-check.json"


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


def _read_cache(root: Path) -> dict | None:
    try:
        payload = json.loads(_cache_path(root).read_text(encoding="utf-8"))
        checked = datetime.fromisoformat(payload["checked_at"])
    except (OSError, json.JSONDecodeError, KeyError, ValueError):
        return None
    if datetime.now(timezone.utc) - checked > timedelta(hours=CACHE_TTL_HOURS):
        return None
    return payload


def check_for_update(root: Path = Path("."), *, force: bool = False) -> dict:
    """Report whether a newer published release exists. Installs nothing.

    Returns a dict with ``status`` one of: ``current``, ``update_available``,
    ``ahead_of_index``, ``unavailable``. Never raises on network failure — an
    offline or air-gapped install gets ``unavailable`` and no nagging.
    """
    if not force:
        cached = _read_cache(root)
        if cached:
            return {**cached, "cached": True}

    result: dict = {
        "package": PACKAGE,
        "installed": __version__,
        "latest": None,
        "status": "unavailable",
        "action": None,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "cached": False,
        "note": "This check reports only. It never installs, and it sends no identifiers.",
    }

    try:
        request = urllib.request.Request(PYPI_JSON, headers={"Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            latest = json.loads(response.read().decode())["info"]["version"]
    except (urllib.error.URLError, TimeoutError, KeyError, json.JSONDecodeError, OSError):
        result["note"] = "Version index unreachable; skipping quietly. This is not an error."
        return result

    result["latest"] = latest
    installed_v, latest_v = _parse_version(__version__), _parse_version(latest)

    if latest_v > installed_v:
        result["status"] = "update_available"
        result["action"] = f"pip install --upgrade {PACKAGE}=={latest}"
    elif latest_v < installed_v:
        # A local build ahead of the index. Say so plainly rather than claiming
        # everything is current, because it usually means a release never shipped.
        result["status"] = "ahead_of_index"
        result["note"] = (
            f"Installed {__version__} is newer than the published {latest}. "
            "This usually means a release was tagged but never published."
        )
    else:
        result["status"] = "current"

    try:
        path = _cache_path(root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    except OSError:
        pass  # a read-only install must still be able to check
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
