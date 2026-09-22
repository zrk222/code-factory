"""Deterministic architecture-health measurements and regression policy.

This module deliberately does not pretend that a large existing surface is
healthy.  It separates *baseline debt* (reported for review) from *new
regressions* (which can block CI).  The policy is data-driven so a human can
review an intentional architectural change instead of an agent silently
redefining the gate.
"""

from __future__ import annotations

import json
import hashlib
import fnmatch
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


DEFAULT_POLICY_NAME = "architecture-policy.json"
DOCUMENTATION_INDEX_NAME = "docs/DOCUMENTATION_INDEX.json"
RELEASE_TRAIN_NAME = "release-train.json"
_VERSION_RE = re.compile(
    r"^(?:version|__version__)\s*=\s*[\"']([^\"']+)[\"']", re.MULTILINE
)


class ArchitectureHealthError(ValueError):
    """Raised when an architecture policy or repository cannot be measured."""

    code = "E_ARCHITECTURE_HEALTH"


def _tracked_files(root: Path) -> list[Path]:
    """Return repository files when possible, otherwise bounded source files."""
    root = root.resolve()
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        completed = None
    if completed is not None:
        names = [
            item
            for item in completed.stdout.decode("utf-8", "replace").split("\0")
            if item
        ]
        return [root / name for name in names]
    ignored = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}
    return [
        p for p in root.rglob("*") if p.is_file() and not ignored.intersection(p.parts)
    ]


def _version(root: Path) -> str | None:
    for relative in ("pyproject.toml", "factoryline/__init__.py"):
        path = root / relative
        if path.exists():
            match = _VERSION_RE.search(path.read_text(encoding="utf-8"))
            if match:
                return match.group(1)
    return None


def _changelog_contains_version(root: Path, version: str | None) -> bool:
    """Require the current package version to have a human-readable release entry."""
    if not version:
        return False
    changelog = root / "CHANGELOG.md"
    if not changelog.is_file():
        return False
    try:
        content = changelog.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    return bool(re.search(rf"^##\s+{re.escape(version)}(?:\s|$)", content, re.MULTILINE))


def _module_classification(
    root: Path, relative: list[str]
) -> tuple[dict[str, int], dict[str, str]]:
    """Classify implementation modules and retain each module's domain.

    The manifest is intentionally authoritative for specialist boundaries.  A
    missing or invalid manifest keeps every implementation module in ``core``
    for measurement, while the returned domain counts still surface the
    manifest problem as a blocking contract finding.
    """
    manifest_path = root / "architecture-boundaries.json"
    implementation = [
        path
        for path in relative
        if path.startswith("factoryline/")
        and path.endswith(".py")
        and not path.endswith("/__init__.py")
    ]
    if not manifest_path.exists():
        return {"manifest_missing": 1}, {path: "core" for path in implementation}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"manifest_invalid": 1}, {path: "core" for path in implementation}
    if manifest.get("schema") != "factory.module-boundaries.v1":
        return {"manifest_invalid": 1}, {path: "core" for path in implementation}
    domains: dict[str, int] = {}
    patterns = manifest.get("domains", {})
    if not isinstance(patterns, dict) or any(
        not isinstance(domain, str)
        or not isinstance(globs, list)
        or not globs
        or not all(isinstance(pattern, str) and pattern for pattern in globs)
        for domain, globs in patterns.items()
    ):
        return {"manifest_invalid": 1}, {path: "core" for path in implementation}
    owners = manifest.get("owners")
    if owners is not None and (
        not isinstance(owners, dict)
        or any(
            not isinstance(owner, str) or not owner.strip()
            for domain, owner in owners.items()
            if domain in patterns
        )
        or any(domain not in owners for domain in patterns)
    ):
        return {"manifest_invalid": 1}, {path: "core" for path in implementation}
    experimental = manifest.get("experimental", [])
    if not isinstance(experimental, list) or not all(
        isinstance(path, str)
        and path.startswith("factoryline/")
        and not Path(path).is_absolute()
        for path in experimental
    ):
        return {"manifest_invalid": 1}, {path: "core" for path in implementation}
    for name in patterns:
        domains[name] = 0
    default = manifest.get("defaultDomain", "unclassified")
    domains.setdefault(default, 0)
    assignments: dict[str, str] = {}
    for path in implementation:
        assigned = default
        for domain, globs in patterns.items():
            if any(fnmatch.fnmatch(path, pattern) for pattern in globs):
                assigned = domain
                break
        assignments[path] = assigned
        domains[assigned] = domains.get(assigned, 0) + 1
    return domains, assignments


def _module_domains(root: Path, relative: list[str]) -> dict[str, int]:
    """Classify implementation modules using the reviewed boundary manifest."""
    return _module_classification(root, relative)[0]


def _documentation_index(root: Path, relative: list[str]) -> dict[str, Any]:
    """Validate the repository's canonical and historical Markdown index."""
    markdown = [name for name in relative if name.lower().endswith(".md")]
    index_path = root / DOCUMENTATION_INDEX_NAME
    if not markdown and not index_path.exists():
        return {"status": "not_applicable", "canonical_count": 0, "unmatched": []}
    if not index_path.is_file():
        return {
            "status": "missing",
            "canonical_count": 0,
            "unmatched": markdown,
        }
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {"status": "invalid", "canonical_count": 0, "unmatched": markdown}
    if index.get("schema") != "factory.documentation-index.v1":
        return {"status": "invalid", "canonical_count": 0, "unmatched": markdown}
    canonical = index.get("canonical")
    coverage = index.get("coverage")
    rules = index.get("rules")
    if (
        not isinstance(canonical, list)
        or not isinstance(coverage, list)
        or not isinstance(rules, dict)
        or not rules.get("canonical_paths_must_exist")
        or not rules.get("canonical_entries_require_executable_or_decision")
        or not rules.get("evidence_refs_must_exist")
    ):
        return {"status": "invalid", "canonical_count": 0, "unmatched": markdown}
    canonical_paths: set[str] = set()
    for entry in canonical:
        if not isinstance(entry, dict):
            return {"status": "invalid", "canonical_count": 0, "unmatched": markdown}
        path = entry.get("path")
        if (
            not isinstance(path, str)
            or path in canonical_paths
            or path not in relative
            or not path.lower().endswith(".md")
            or not any(
                isinstance(entry.get(key), str) and entry[key].strip()
                for key in ("executable", "decision")
            )
        ):
            return {"status": "invalid", "canonical_count": 0, "unmatched": markdown}
        evidence_refs = [
            entry.get(key)
            for key in ("executable", "decision")
            if isinstance(entry.get(key), str) and entry[key].strip()
        ]
        if not any(ref in relative for ref in evidence_refs):
            return {"status": "invalid", "canonical_count": 0, "unmatched": markdown}
        canonical_paths.add(path)
    patterns: list[str] = []
    for entry in coverage:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("glob"), str)
            or not entry["glob"]
            or not isinstance(entry.get("status"), str)
            or entry["status"] not in {"canonical", "historical", "indexed"}
        ):
            return {"status": "invalid", "canonical_count": 0, "unmatched": markdown}
        patterns.append(entry["glob"])
    unmatched = [name for name in markdown if not any(fnmatch.fnmatch(name, pattern) for pattern in patterns)]
    return {
        "status": "valid" if not unmatched else "incomplete",
        "canonical_count": len(canonical_paths),
        "coverage_patterns": len(patterns),
        "unmatched": unmatched,
    }


def _release_train(root: Path, relative: list[str]) -> dict[str, Any]:
    """Validate the release-train contract without touching providers."""
    path = root / RELEASE_TRAIN_NAME
    if not path.is_file():
        return {"status": "missing", "channels": 0}
    try:
        train = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {"status": "invalid", "channels": 0}
    cadence = train.get("cadence")
    channels = train.get("channels")
    states = train.get("publication_states")
    required_states = {
        "prepared",
        "verified",
        "uploaded",
        "processing",
        "published",
        "pending_review",
        "blocked",
        "not_configured",
    }
    valid_channels = isinstance(channels, list) and bool(channels) and all(
        isinstance(channel, dict)
        and isinstance(channel.get("id"), str)
        and isinstance(channel.get("version_source"), str)
        and isinstance(channel.get("changelog"), str)
        and isinstance(channel.get("artifact"), str)
        for channel in channels
    )
    valid_sources = valid_channels and all(
        channel["version_source"] in relative and channel["changelog"] in relative
        for channel in channels
    )
    max_releases = cadence.get("max_releases_30d") if isinstance(cadence, dict) else None
    minimum_days = (
        cadence.get("minimum_days_between_releases")
        if isinstance(cadence, dict)
        else None
    )
    valid = (
        train.get("schema") == "factory.release-train.v1"
        and isinstance(train.get("train_id"), str)
        and isinstance(train.get("owner"), str)
        and valid_sources
        and isinstance(cadence, dict)
        and type(max_releases) is int
        and max_releases > 0
        and type(minimum_days) is int
        and minimum_days > 0
        and cadence.get("exception_requires") == "human-release-authority"
        and cadence.get("requires_changelog_entry") is True
        and isinstance(states, list)
        and required_states.issubset(states)
    )
    return {
        "status": "valid" if valid else "invalid",
        "channels": len(channels) if isinstance(channels, list) else 0,
        "cadence": {
            "max_releases_30d": max_releases,
            "minimum_days_between_releases": minimum_days,
            "exception_requires": cadence.get("exception_requires"),
            "requires_changelog_entry": cadence.get("requires_changelog_entry"),
        },
    }


def _cadence_projection(
    releases: list[tuple[str, datetime]],
    *,
    now: datetime,
    max_releases_30d: int = 4,
    minimum_days_between_releases: int = 7,
) -> dict[str, Any]:
    """Project a deterministic future release admission decision.

    Historical tags remain immutable evidence.  This projection turns the
    observed history into a forward-looking guard: a release is eligible only
    when both the inter-release cooldown and the rolling 30-day budget pass.
    It never deletes, rewrites, or reclassifies historical tags.
    """
    releases = sorted(releases, key=lambda item: item[1], reverse=True)
    recent = [
        item for item in releases if now - item[1] <= timedelta(days=30)
    ]
    latest = releases[0] if releases else None
    cooldown_until = (
        latest[1] + timedelta(days=minimum_days_between_releases)
        if latest
        else None
    )
    window_until = None
    if len(recent) >= max_releases_30d:
        # The fourth-newest tag must age out before a fifth release is allowed.
        # `now - tag <= 30 days` includes the exact boundary, so move the
        # admission time forward by one clock tick to avoid an off-by-one hold.
        window_until = (
            recent[max_releases_30d - 1][1]
            + timedelta(days=30, microseconds=1)
        )
    candidates = [value for value in (cooldown_until, window_until) if value]
    next_eligible = max(candidates) if candidates else now
    if not releases:
        state = "no_tags"
        reason = "No version tags were observed; the release train is eligible."
    elif len(recent) >= max_releases_30d:
        state = "rate_limited"
        reason = (
            f"{len(recent)} version tags are inside the rolling 30-day budget "
            f"of {max_releases_30d}."
        )
    elif cooldown_until and now < cooldown_until:
        state = "cooldown"
        reason = (
            f"The minimum {minimum_days_between_releases}-day interval since "
            f"{latest[0]} has not elapsed."
        )
    else:
        state = "eligible"
        reason = "The observed release history satisfies the configured cadence."
    interval = (
        (releases[0][1] - releases[1][1]).total_seconds() / 86400
        if len(releases) > 1
        else None
    )
    def iso(value: datetime | None) -> str | None:
        return value.isoformat().replace("+00:00", "Z") if value else None
    return {
        "available": True,
        "recent_count": len(recent),
        "max_releases_30d": max_releases_30d,
        "minimum_days_between_releases": minimum_days_between_releases,
        "latest_tag": latest[0] if latest else None,
        "latest_release_at": iso(latest[1]) if latest else None,
        "latest_interval_days": round(interval, 2) if interval is not None else None,
        "cooldown_until": iso(cooldown_until),
        "window_budget_until": iso(window_until),
        "next_eligible_at": iso(next_eligible),
        "admission": state == "eligible",
        "state": state,
        "reason": reason,
    }


def _recent_release_tags(
    root: Path,
    now: datetime | None = None,
    *,
    max_releases_30d: int = 4,
    minimum_days_between_releases: int = 7,
) -> dict[str, Any]:
    """Measure release-tag cadence and expose a forward release guard."""
    now = now or datetime.now(timezone.utc)
    try:
        completed = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "for-each-ref",
                "refs/tags/v*",
                "--format=%(refname:short)\t%(creatordate:iso-strict)",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return {"available": False, "recent_count": None, "latest_interval_days": None}
    releases: list[tuple[str, datetime]] = []
    for line in completed.stdout.splitlines():
        try:
            name, stamp = line.split("\t", 1)
            releases.append(
                (
                    name,
                    datetime.fromisoformat(stamp.strip().replace("Z", "+00:00")).astimezone(
                        timezone.utc
                    ),
                )
            )
        except (ValueError, IndexError):
            continue
    return _cadence_projection(
        releases,
        now=now,
        max_releases_30d=max_releases_30d,
        minimum_days_between_releases=minimum_days_between_releases,
    )


def release_cadence_status(
    root: Path, now: datetime | None = None
) -> dict[str, Any]:
    """Return release-train validity and its tag-derived admission projection."""
    root = Path(root).resolve()
    relative = [
        path.relative_to(root).as_posix()
        for path in _tracked_files(root)
        if path.exists()
    ]
    train = _release_train(root, relative)
    cadence = train.get("cadence", {})
    if train.get("status") != "valid":
        return {
            "available": False,
            "admission": False,
            "state": "release_train_invalid",
            "reason": "A valid release-train.json is required for release admission.",
            "release_train_status": train.get("status"),
            "recent_count": None,
            "latest_interval_days": None,
        }
    policy_path = root / DEFAULT_POLICY_NAME
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        policy_cadence = policy["release"]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
        policy_cadence = None
    if not isinstance(policy_cadence, dict) or any(
        policy_cadence.get(key) != cadence.get(key)
        for key in (
            "max_releases_30d",
            "minimum_days_between_releases",
            "exception_requires",
            "requires_changelog_entry",
        )
    ):
        return {
            "available": False,
            "admission": False,
            "state": "release_policy_mismatch",
            "reason": "architecture-policy.json and release-train.json cadence rules must match exactly.",
            "release_train_status": train["status"],
            "recent_count": None,
            "latest_interval_days": None,
        }
    projection = _recent_release_tags(
        root,
        now,
        max_releases_30d=cadence["max_releases_30d"],
        minimum_days_between_releases=cadence["minimum_days_between_releases"],
    )
    projection["release_train_status"] = train["status"]
    if not projection.get("available"):
        projection.update(
            admission=False,
            state="unavailable",
            reason="Git tag history could not be read; release admission fails closed.",
        )
    return projection


def collect_architecture_health(root: Path) -> dict[str, Any]:
    """Collect stable, explainable architecture metrics for ``root``."""
    root = root.resolve()
    files = _tracked_files(root)
    relative = [path.relative_to(root).as_posix() for path in files if path.exists()]
    markdown = [name for name in relative if name.lower().endswith(".md")]
    python = [name for name in relative if name.lower().endswith(".py")]
    implementation_modules = [
        name
        for name in python
        if name.startswith("factoryline/")
        and not name.rsplit("/", 1)[-1].startswith("__init__")
    ]
    module_domains, module_assignments = _module_classification(root, relative)
    core_modules = [
        name
        for name in implementation_modules
        if module_assignments.get(name, "core") == "core"
    ]
    cli_path = root / "factoryline" / "cli.py"
    cli_lines = (
        len(cli_path.read_text(encoding="utf-8").splitlines())
        if cli_path.exists()
        else 0
    )
    cli_command_declarations = 0
    if cli_path.exists():
        cli_command_declarations = len(
            re.findall(r"\.add_parser\(", cli_path.read_text(encoding="utf-8"))
        )
    ratio = round(len(markdown) / len(python), 4) if python else None
    release_train = _release_train(root, relative)
    cadence = release_cadence_status(root)
    return {
        "schema": "factory.architecture-health.v1",
        "root": str(root),
        "metrics": {
            "markdown_files": len(markdown),
            "python_files": len(python),
            "markdown_python_ratio": ratio,
            "cli_lines": cli_lines,
            "cli_command_declarations": cli_command_declarations,
            "core_modules": len(core_modules),
            "total_factoryline_modules": len(implementation_modules),
            "module_domains": module_domains,
            "documentation_index": _documentation_index(root, relative),
            "release_train": release_train,
            "version": _version(root),
            "tracked_files": len(relative),
        },
        "release_cadence": cadence,
    }


def _finding(
    code: str, severity: str, message: str, action: str, *, blocking: bool = False
) -> dict[str, Any]:
    return {
        "code": code,
        "severity": severity,
        "blocking": blocking,
        "message": message,
        "next_action": action,
    }


_ACCEPTED_METRIC_FOR_CODE = {
    "E_ARCH_MARKDOWN_FILES_GROWTH": "markdown_files",
    "E_ARCH_PYTHON_FILES_GROWTH": "python_files",
    "E_ARCH_CLI_LINES_GROWTH": "cli_lines",
    "E_ARCH_CLI_COMMAND_DECLARATIONS_GROWTH": "cli_command_declarations",
    "E_ARCH_CORE_MODULES_GROWTH": "core_modules",
    "E_ARCH_DOC_CODE_RATIO_GROWTH": "markdown_python_ratio",
    "ARCH_CLI_MONOLITH": "cli_lines",
    "ARCH_CLI_COMMAND_SURFACE": "cli_command_declarations",
    "ARCH_CORE_SURFACE": "core_modules",
    "ARCH_DOC_CODE_RATIO": "markdown_python_ratio",
}


def _accepted_debt(
    policy: dict[str, Any], metrics: dict[str, Any], cadence: dict[str, Any]
) -> tuple[dict[str, Any] | None, str | None]:
    """Validate an explicit, expiring acceptance of measured architecture debt."""
    value = policy.get("accepted_debt")
    if value is None:
        return None, None
    if not isinstance(value, dict):
        return None, "accepted_debt must be an object"
    required = {"decision_id", "owner", "expires_at", "reason", "codes", "metrics"}
    if set(value) != required:
        return (
            None,
            "accepted_debt must contain decision_id, owner, expires_at, reason, codes, and metrics",
        )
    if not all(
        isinstance(value.get(key), str) and value[key].strip()
        for key in ("decision_id", "owner", "reason")
    ):
        return (
            None,
            "accepted_debt decision_id, owner, and reason must be non-empty strings",
        )
    try:
        expires = datetime.fromisoformat(
            str(value["expires_at"]).replace("Z", "+00:00")
        )
        if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
            return (
                None,
                "accepted_debt expires_at must be a future timezone-aware timestamp",
            )
    except ValueError:
        return None, "accepted_debt expires_at must be an ISO-8601 timestamp"
    codes = value.get("codes")
    if (
        not isinstance(codes, list)
        or not codes
        or len(codes) != len(set(codes))
        or not all(
            isinstance(code, str) and code in _ACCEPTED_METRIC_FOR_CODE
            for code in codes
        )
    ):
        return (
            None,
            "accepted_debt codes must be a unique non-empty list of known debt codes",
        )
    accepted_metrics = value.get("metrics")
    if not isinstance(accepted_metrics, dict):
        return None, "accepted_debt metrics must be an object"
    observed = {**metrics, "release_recent_count": cadence.get("recent_count")}
    for code in codes:
        metric = _ACCEPTED_METRIC_FOR_CODE[code]
        if metric not in accepted_metrics or accepted_metrics[metric] != observed.get(
            metric
        ):
            return (
                None,
                f"accepted_debt metric {metric} must exactly match the measured value",
            )
    return {
        "decision_id": value["decision_id"],
        "owner": value["owner"],
        "expires_at": value["expires_at"],
        "reason": value["reason"],
        "codes": list(codes),
        "metrics": dict(accepted_metrics),
    }, None


def evaluate_architecture_health(
    root: Path, policy_path: Path | None = None, *, strict: bool = False
) -> dict[str, Any]:
    """Evaluate metrics against a human-reviewed policy.

    Existing debt is reported as ``REVIEW_REQUIRED``.  Only a metric exceeding
    its explicit budget is ``BLOCKED``; this makes the check useful immediately
    on the current repository and strict on every subsequent change.
    """
    root = root.resolve()
    policy_path = (policy_path or (root / DEFAULT_POLICY_NAME)).resolve()
    if not policy_path.exists():
        raise ArchitectureHealthError(f"architecture policy not found: {policy_path}")
    try:
        policy_bytes = policy_path.read_bytes()
        policy = json.loads(policy_bytes.decode("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArchitectureHealthError(f"invalid architecture policy: {exc}") from exc
    if policy.get("schema") != "factory.architecture-policy.v1":
        raise ArchitectureHealthError("unsupported architecture policy schema")
    snapshot = collect_architecture_health(root)
    metrics = snapshot["metrics"]
    baseline = policy.get("baseline", {})
    budgets = policy.get("budgets", {})
    regressions: list[dict[str, Any]] = []
    for key, budget_key in (
        ("markdown_files", "max_markdown_files"),
        ("python_files", "max_python_files"),
        ("cli_lines", "max_cli_lines"),
        ("cli_command_declarations", "max_cli_command_declarations"),
        ("core_modules", "max_core_modules"),
    ):
        value = metrics[key]
        limit = budgets.get(budget_key)
        if isinstance(value, int) and isinstance(limit, int) and value > limit:
            regressions.append(
                _finding(
                    f"E_ARCH_{key.upper()}_GROWTH",
                    "BLOCKER",
                    f"{key} grew to {value}; policy maximum is {limit}.",
                    f"Remove unrelated {key} growth or update the reviewed policy with an architecture decision.",
                    blocking=True,
                )
            )
    ratio = metrics["markdown_python_ratio"]
    ratio_limit = budgets.get("max_markdown_python_ratio")
    if (
        isinstance(ratio, (int, float))
        and isinstance(ratio_limit, (int, float))
        and ratio > ratio_limit
    ):
        regressions.append(
            _finding(
                "E_ARCH_DOC_CODE_RATIO_GROWTH",
                "BLOCKER",
                f"Markdown/Python ratio is {ratio}; policy maximum is {ratio_limit}.",
                "Add executable coverage or consolidate stale documentation before adding more narrative surface.",
                blocking=True,
            )
        )

    debt: list[dict[str, Any]] = []
    domains = metrics.get("module_domains", {})
    if domains.get("manifest_invalid"):
        regressions.append(
            _finding(
                "E_ARCH_BOUNDARY_MANIFEST_INVALID",
                "BLOCKER",
                "architecture-boundaries.json is malformed or uses an unsupported schema.",
                "Restore the reviewed factory.module-boundaries.v1 manifest before merging architecture changes.",
                blocking=True,
            )
        )
    elif domains.get("manifest_missing"):
        debt.append(
            _finding(
                "ARCH_BOUNDARY_MANIFEST_MISSING",
                "MEDIUM",
                "No architecture-boundaries.json manifest was found for the measured repository.",
                "Add a reviewed core-versus-specialist boundary manifest before expanding the module surface.",
            )
        )
    documentation_index = metrics.get("documentation_index", {})
    if policy.get("documentation", {}).get("require_index") and documentation_index.get(
        "status"
    ) in {"missing", "invalid", "incomplete"}:
        regressions.append(
            _finding(
                "E_ARCH_DOCUMENTATION_INDEX_INVALID",
                "BLOCKER",
                "Documentation index is missing, malformed, or leaves Markdown files unclassified.",
                "Repair docs/DOCUMENTATION_INDEX.json before adding or publishing narrative documentation.",
                blocking=True,
            )
        )
    release_train = metrics.get("release_train", {})
    if policy.get("release", {}).get("require_train") and release_train.get(
        "status"
    ) in {"missing", "invalid"}:
        regressions.append(
            _finding(
                "E_ARCH_RELEASE_TRAIN_INVALID",
                "BLOCKER",
                "release-train.json is missing or does not describe the governed release channels.",
                "Restore the reviewed release-train.v1 contract before creating a release artifact.",
                blocking=True,
            )
        )
    if metrics["cli_lines"] > policy.get("review_thresholds", {}).get(
        "cli_lines", 5000
    ):
        debt.append(
            _finding(
                "ARCH_CLI_MONOLITH",
                "HIGH",
                f"factoryline/cli.py is {metrics['cli_lines']} lines and owns parser/dispatch assembly.",
                "Extract command registration and dispatch into bounded command modules; retain cli.py as a compatibility entry point.",
            )
        )
    if metrics["cli_command_declarations"] > policy.get("review_thresholds", {}).get(
        "cli_command_declarations", 300
    ):
        debt.append(
            _finding(
                "ARCH_CLI_COMMAND_SURFACE",
                "HIGH",
                f"factoryline/cli.py declares {metrics['cli_command_declarations']} parser commands and subcommands.",
                "Group commands by bounded domain and expose a stable compatibility index instead of adding more parser branches.",
            )
        )
    if metrics["core_modules"] > policy.get("review_thresholds", {}).get(
        "core_modules", 150
    ):
        debt.append(
            _finding(
                "ARCH_CORE_SURFACE",
                "HIGH",
                f"factoryline contains {metrics['core_modules']} implementation modules.",
                "Publish a supported-module manifest and move experimental adapters behind explicit package boundaries.",
            )
        )
    if ratio is not None and ratio > policy.get("review_thresholds", {}).get(
        "markdown_python_ratio", 1.5
    ):
        debt.append(
            _finding(
                "ARCH_DOC_CODE_RATIO",
                "MEDIUM",
                f"There are {metrics['markdown_files']} Markdown files for {metrics['python_files']} Python files (ratio {ratio}).",
                "Index canonical docs, archive superseded narratives, and require each new document to link to executable behavior or a decision.",
            )
        )
    cadence = snapshot["release_cadence"]
    cadence_policy = policy.get("release", {})
    if cadence_policy.get("requires_changelog_entry") and not _changelog_contains_version(
        root, metrics.get("version")
    ):
        regressions.append(
            _finding(
                "E_ARCH_RELEASE_CHANGELOG_MISSING",
                "BLOCKER",
                f"Current version {metrics.get('version') or 'unknown'} has no CHANGELOG.md release entry.",
                "Add a human-readable changelog heading for the exact current version before release.",
                blocking=True,
            )
        )
    accepted, acceptance_error = _accepted_debt(policy, metrics, cadence)
    if acceptance_error:
        regressions.append(
            _finding(
                "E_ARCH_ACCEPTANCE_INVALID",
                "BLOCKER",
                acceptance_error,
                "Remove the acceptance or renew it with a named owner, future expiry, and exact measured values.",
                blocking=True,
            )
        )
    accepted_codes = set(accepted["codes"]) if accepted else set()
    accepted_baseline_debt = [item for item in debt if item["code"] in accepted_codes]
    debt = [item for item in debt if item["code"] not in accepted_codes]
    accepted_regressions = [
        item for item in regressions if item["code"] in accepted_codes
    ]
    regressions = [item for item in regressions if item["code"] not in accepted_codes]

    decision = (
        "BLOCKED"
        if regressions or (strict and debt)
        else ("REVIEW_REQUIRED" if debt else "HEALTHY")
    )
    cadence_action = ""
    if snapshot["release_cadence"].get("admission") is False:
        cadence = snapshot["release_cadence"]
        next_eligible = cadence.get("next_eligible_at")
        cadence_action = (
            " Release admission is blocked by the cadence guard: "
            f"{cadence.get('reason', 'cadence evidence unavailable')}"
        )
        if next_eligible:
            cadence_action += f" Next eligible at {next_eligible}."
    return {
        **snapshot,
        "policy": {
            "path": str(policy_path),
            "baseline": baseline,
            "budgets": budgets,
            "sha256": "sha256:" + hashlib.sha256(policy_bytes).hexdigest(),
        },
        "baseline_debt": debt,
        "accepted_baseline_debt": accepted_baseline_debt,
        "accepted_regressions": accepted_regressions,
        "accepted_debt": accepted,
        "regressions": regressions,
        "decision": decision,
        "next_action": (
            "Stop and resolve architecture budget regressions before merge."
            if regressions
            else "Strict mode requires an approved decomposition plan for all baseline debt."
            if strict and debt
            else "Keep the existing debt visible and execute the bounded decomposition plan."
            if debt
            else "Architecture budgets are within policy." + cadence_action
        ),
    }
