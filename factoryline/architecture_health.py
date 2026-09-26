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
    return bool(
        re.search(rf"^##\s+{re.escape(version)}(?:\s|$)", content, re.MULTILINE)
    )


def _parse_timestamp(value: Any) -> datetime | None:
    """Read a timezone-aware ISO timestamp without guessing a local zone."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def _implementation_modules(relative: list[str]) -> list[str]:
    return [
        path
        for path in relative
        if path.startswith("factoryline/")
        and path.endswith(".py")
        and not path.endswith("/__init__.py")
    ]


def _core_module_assignments(
    implementation: list[str], status: str
) -> tuple[dict[str, int], dict[str, str]]:
    return {status: 1}, {path: "core" for path in implementation}


def _valid_boundary_patterns(patterns: Any) -> bool:
    return isinstance(patterns, dict) and all(
        isinstance(domain, str)
        and isinstance(globs, list)
        and bool(globs)
        and all(isinstance(pattern, str) and pattern for pattern in globs)
        for domain, globs in patterns.items()
    )


def _valid_boundary_owners(owners: Any, patterns: dict[str, Any]) -> bool:
    if owners is None:
        return True
    return (
        isinstance(owners, dict)
        and all(
            isinstance(owner, str) and owner.strip()
            for domain, owner in owners.items()
            if domain in patterns
        )
        and all(domain in owners for domain in patterns)
    )


def _valid_experimental_paths(experimental: Any) -> bool:
    return isinstance(experimental, list) and all(
        isinstance(path, str)
        and path.startswith("factoryline/")
        and not Path(path).is_absolute()
        for path in experimental
    )


def _assign_module_domains(
    implementation: list[str], patterns: dict[str, list[str]], default: str
) -> tuple[dict[str, int], dict[str, str]]:
    domains = {name: 0 for name in patterns}
    domains.setdefault(default, 0)
    assignments = {}
    for path in implementation:
        assigned = next(
            (
                domain
                for domain, globs in patterns.items()
                if any(fnmatch.fnmatch(path, pattern) for pattern in globs)
            ),
            default,
        )
        assignments[path] = assigned
        domains[assigned] = domains.get(assigned, 0) + 1
    return domains, assignments


def _module_classification(
    root: Path, relative: list[str]
) -> tuple[dict[str, int], dict[str, str]]:
    """Classify implementation modules using the authoritative boundary manifest."""
    implementation = _implementation_modules(relative)
    path = root / "architecture-boundaries.json"
    if not path.exists():
        return _core_module_assignments(implementation, "manifest_missing")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _core_module_assignments(implementation, "manifest_invalid")
    patterns = manifest.get("domains", {})
    if manifest.get(
        "schema"
    ) != "factory.module-boundaries.v1" or not _valid_boundary_patterns(patterns):
        return _core_module_assignments(implementation, "manifest_invalid")
    if not _valid_boundary_owners(manifest.get("owners"), patterns):
        return _core_module_assignments(implementation, "manifest_invalid")
    if not _valid_experimental_paths(manifest.get("experimental", [])):
        return _core_module_assignments(implementation, "manifest_invalid")
    return _assign_module_domains(
        implementation, patterns, manifest.get("defaultDomain", "unclassified")
    )


def _module_domains(root: Path, relative: list[str]) -> dict[str, int]:
    """Classify implementation modules using the reviewed boundary manifest."""
    return _module_classification(root, relative)[0]


def _invalid_documentation_index(markdown: list[str]) -> dict[str, Any]:
    return {"status": "invalid", "canonical_count": 0, "unmatched": markdown}


def _valid_documentation_rules(rules: Any) -> bool:
    required = (
        "canonical_paths_must_exist",
        "canonical_entries_require_executable_or_decision",
        "evidence_refs_must_exist",
    )
    return isinstance(rules, dict) and all(rules.get(key) for key in required)


def _canonical_documentation_paths(
    canonical: list[Any], relative: list[str]
) -> set[str] | None:
    paths: set[str] = set()
    for entry in canonical:
        if not isinstance(entry, dict):
            return None
        path = entry.get("path")
        if not _valid_canonical_entry(entry, path, paths, relative):
            return None
        if not _has_existing_evidence(entry, relative):
            return None
        paths.add(path)
    return paths


def _valid_canonical_entry(
    entry: dict[str, Any], path: Any, paths: set[str], relative: list[str]
) -> bool:
    return (
        isinstance(path, str)
        and path not in paths
        and path in relative
        and path.lower().endswith(".md")
        and any(
            isinstance(entry.get(key), str) and entry[key].strip()
            for key in ("executable", "decision")
        )
    )


def _has_existing_evidence(entry: dict[str, Any], relative: list[str]) -> bool:
    references = [
        entry.get(key)
        for key in ("executable", "decision")
        if isinstance(entry.get(key), str) and entry[key].strip()
    ]
    return any(reference in relative for reference in references)


def _documentation_coverage_patterns(coverage: list[Any]) -> list[str] | None:
    patterns = []
    for entry in coverage:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("glob"), str)
            or not entry["glob"]
        ):
            return None
        if not isinstance(entry.get("status"), str) or entry["status"] not in {
            "canonical",
            "historical",
            "indexed",
        }:
            return None
        patterns.append(entry["glob"])
    return patterns


def _read_documentation_index(
    root: Path, markdown: list[str]
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    index_path = root / DOCUMENTATION_INDEX_NAME
    if not markdown and not index_path.exists():
        return None, {"status": "not_applicable", "canonical_count": 0, "unmatched": []}
    if not index_path.is_file():
        return None, {"status": "missing", "canonical_count": 0, "unmatched": markdown}
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None, _invalid_documentation_index(markdown)
    if index.get("schema") != "factory.documentation-index.v1":
        return None, _invalid_documentation_index(markdown)
    return index, None


def _document_index_coverage_result(
    markdown: list[str], canonical_paths: set[str], patterns: list[str]
) -> dict[str, Any]:
    unmatched = [
        name
        for name in markdown
        if not any(fnmatch.fnmatch(name, pattern) for pattern in patterns)
    ]
    return {
        "status": "valid" if not unmatched else "incomplete",
        "canonical_count": len(canonical_paths),
        "coverage_patterns": len(patterns),
        "unmatched": unmatched,
    }


def _documentation_index(root: Path, relative: list[str]) -> dict[str, Any]:
    """Validate the repository's canonical and historical Markdown index."""
    markdown = [name for name in relative if name.lower().endswith(".md")]
    index, early_result = _read_documentation_index(root, markdown)
    if early_result is not None:
        return early_result
    canonical, coverage, rules = (
        index.get("canonical"),
        index.get("coverage"),
        index.get("rules"),
    )
    if (
        not isinstance(canonical, list)
        or not isinstance(coverage, list)
        or not _valid_documentation_rules(rules)
    ):
        return _invalid_documentation_index(markdown)
    canonical_paths = _canonical_documentation_paths(canonical, relative)
    patterns = _documentation_coverage_patterns(coverage)
    if canonical_paths is None or patterns is None:
        return _invalid_documentation_index(markdown)
    return _document_index_coverage_result(markdown, canonical_paths, patterns)


def _valid_release_channels(channels: Any, relative: list[str]) -> bool:
    if not isinstance(channels, list) or not channels:
        return False
    required = ("id", "version_source", "changelog", "artifact")
    if not all(
        isinstance(channel, dict)
        and all(isinstance(channel.get(key), str) for key in required)
        for channel in channels
    ):
        return False
    return all(
        channel["version_source"] in relative and channel["changelog"] in relative
        for channel in channels
    )


def _valid_release_train_identity(train: dict[str, Any]) -> bool:
    return (
        train.get("schema") == "factory.release-train.v1"
        and isinstance(train.get("train_id"), str)
        and isinstance(train.get("owner"), str)
    )


def _valid_release_cadence_contract(
    cadence: Any,
    max_releases: Any,
    minimum_days: Any,
    effective_time: datetime | None,
) -> bool:
    return (
        isinstance(cadence, dict)
        and type(max_releases) is int
        and max_releases > 0
        and type(minimum_days) is int
        and minimum_days > 0
        and effective_time is not None
        and cadence.get("exception_requires") == "human-release-authority"
        and cadence.get("requires_changelog_entry") is True
    )


def _valid_publication_states(train: dict[str, Any]) -> bool:
    required = {
        "prepared",
        "verified",
        "uploaded",
        "processing",
        "published",
        "pending_review",
        "blocked",
        "not_configured",
    }
    states = train.get("publication_states")
    return isinstance(states, list) and required.issubset(states)


def _release_train_is_valid(
    train: dict[str, Any],
    channels_valid: bool,
    cadence: Any,
    max_releases: Any,
    minimum_days: Any,
    effective_time: datetime | None,
) -> bool:
    return all(
        (
            _valid_release_train_identity(train),
            channels_valid,
            _valid_release_cadence_contract(
                cadence, max_releases, minimum_days, effective_time
            ),
            _valid_publication_states(train),
        )
    )


def _release_cadence_summary(
    cadence: Any,
    effective_time: datetime | None,
) -> dict[str, Any]:
    if not isinstance(cadence, dict):
        cadence = {}
    effective_at = cadence.get("effective_at")
    return {
        "max_releases_30d": cadence.get("max_releases_30d"),
        "minimum_days_between_releases": cadence.get("minimum_days_between_releases"),
        "effective_at": effective_time.isoformat().replace("+00:00", "Z")
        if effective_time
        else effective_at,
        "exception_requires": cadence.get("exception_requires"),
        "requires_changelog_entry": cadence.get("requires_changelog_entry"),
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
    cadence, channels = train.get("cadence"), train.get("channels")
    max_releases = (
        cadence.get("max_releases_30d") if isinstance(cadence, dict) else None
    )
    minimum_days = (
        cadence.get("minimum_days_between_releases")
        if isinstance(cadence, dict)
        else None
    )
    effective_at = cadence.get("effective_at") if isinstance(cadence, dict) else None
    effective_time = _parse_timestamp(effective_at)
    valid = _release_train_is_valid(
        train,
        _valid_release_channels(channels, relative),
        cadence,
        max_releases,
        minimum_days,
        effective_time,
    )
    return {
        "status": "valid" if valid else "invalid",
        "channels": len(channels) if isinstance(channels, list) else 0,
        "cadence": _release_cadence_summary(cadence, effective_time),
    }


def _cadence_releases_after_effective_date(
    releases: list[tuple[str, datetime]],
    effective_at: datetime | None,
) -> tuple[list[tuple[str, datetime]], int, datetime | None]:
    if effective_at is None:
        return releases, 0, None
    effective_at = effective_at.astimezone(timezone.utc)
    pre_policy_count = sum(1 for _, stamp in releases if stamp < effective_at)
    return (
        [item for item in releases if item[1] >= effective_at],
        pre_policy_count,
        effective_at,
    )


def _cadence_window_deadline(
    recent: list[tuple[str, datetime]],
    max_releases_30d: int,
) -> datetime | None:
    if len(recent) < max_releases_30d:
        return None
    # The budget boundary is inclusive; advance one tick before admitting.
    return recent[max_releases_30d - 1][1] + timedelta(days=30, microseconds=1)


def _cadence_next_eligible(
    now: datetime,
    effective_at: datetime | None,
    cooldown_until: datetime | None,
    window_until: datetime | None,
) -> datetime:
    candidates = [value for value in (cooldown_until, window_until) if value]
    if effective_at is not None and now < effective_at:
        candidates.append(effective_at)
    return max(candidates) if candidates else now


def _cadence_state_and_reason(
    releases: list[tuple[str, datetime]],
    recent: list[tuple[str, datetime]],
    now: datetime,
    effective_at: datetime | None,
    pre_policy_count: int,
    max_releases_30d: int,
    minimum_days_between_releases: int,
    cooldown_until: datetime | None,
) -> tuple[str, str]:
    if not releases and effective_at is not None and now < effective_at:
        return (
            "not_yet_effective",
            f"Release cadence begins at {effective_at.isoformat()}.",
        )
    if not releases:
        if effective_at and pre_policy_count:
            return (
                "no_tags",
                f"No version tags have been created since {effective_at.isoformat()}; the release train is eligible.",
            )
        return (
            "no_tags",
            "No version tags were observed; the release train is eligible.",
        )
    if len(recent) >= max_releases_30d:
        reason = f"{len(recent)} version tags are inside the rolling 30-day budget of {max_releases_30d}."
        return "rate_limited", reason
    if cooldown_until and now < cooldown_until:
        reason = f"The minimum {minimum_days_between_releases}-day interval since {releases[0][0]} has not elapsed."
        return "cooldown", reason
    return "eligible", "The observed release history satisfies the configured cadence."


def _iso_timestamp(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


def _cadence_projection_result(
    releases: list[tuple[str, datetime]],
    recent: list[tuple[str, datetime]],
    pre_policy_count: int,
    effective_at: datetime | None,
    max_releases_30d: int,
    minimum_days_between_releases: int,
    cooldown_until: datetime | None,
    window_until: datetime | None,
    next_eligible: datetime,
    state: str,
    reason: str,
) -> dict[str, Any]:
    latest = releases[0] if releases else None
    interval = (
        (releases[0][1] - releases[1][1]).total_seconds() / 86400
        if len(releases) > 1
        else None
    )
    return {
        "available": True,
        "recent_count": len(recent),
        "pre_policy_release_count": pre_policy_count,
        "effective_at": _iso_timestamp(effective_at),
        "max_releases_30d": max_releases_30d,
        "minimum_days_between_releases": minimum_days_between_releases,
        "latest_tag": latest[0] if latest else None,
        "latest_release_at": _iso_timestamp(latest[1]) if latest else None,
        "latest_interval_days": round(interval, 2) if interval is not None else None,
        "cooldown_until": _iso_timestamp(cooldown_until),
        "window_budget_until": _iso_timestamp(window_until),
        "next_eligible_at": _iso_timestamp(next_eligible),
        "admission": state in {"eligible", "no_tags"},
        "state": state,
        "reason": reason,
    }


def _cadence_projection(
    releases: list[tuple[str, datetime]],
    *,
    now: datetime,
    max_releases_30d: int = 4,
    minimum_days_between_releases: int = 7,
    effective_at: datetime | None = None,
) -> dict[str, Any]:
    """Project a deterministic future release admission decision.

    Historical tags remain immutable evidence.  This projection turns the
    observed history into a forward-looking guard: a release is eligible only
    when both the inter-release cooldown and the rolling 30-day budget pass.
    It never deletes, rewrites, or reclassifies historical tags.
    """
    releases = sorted(releases, key=lambda item: item[1], reverse=True)
    releases, pre_policy_count, effective_at = _cadence_releases_after_effective_date(
        releases, effective_at
    )
    recent = [item for item in releases if now - item[1] <= timedelta(days=30)]
    latest = releases[0] if releases else None
    cooldown_until = (
        latest[1] + timedelta(days=minimum_days_between_releases) if latest else None
    )
    window_until = _cadence_window_deadline(recent, max_releases_30d)
    next_eligible = _cadence_next_eligible(
        now, effective_at, cooldown_until, window_until
    )
    state, reason = _cadence_state_and_reason(
        releases,
        recent,
        now,
        effective_at,
        pre_policy_count,
        max_releases_30d,
        minimum_days_between_releases,
        cooldown_until,
    )
    return _cadence_projection_result(
        releases,
        recent,
        pre_policy_count,
        effective_at,
        max_releases_30d,
        minimum_days_between_releases,
        cooldown_until,
        window_until,
        next_eligible,
        state,
        reason,
    )


def _recent_release_tags(
    root: Path,
    now: datetime | None = None,
    *,
    max_releases_30d: int = 4,
    minimum_days_between_releases: int = 7,
    effective_at: datetime | None = None,
    candidate_tag: str | None = None,
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
            if name == candidate_tag:
                continue
            releases.append(
                (
                    name,
                    datetime.fromisoformat(
                        stamp.strip().replace("Z", "+00:00")
                    ).astimezone(timezone.utc),
                )
            )
        except (ValueError, IndexError):
            continue
    return _cadence_projection(
        releases,
        now=now,
        max_releases_30d=max_releases_30d,
        minimum_days_between_releases=minimum_days_between_releases,
        effective_at=effective_at,
    )


def release_cadence_status(
    root: Path, now: datetime | None = None, *, candidate_tag: str | None = None
) -> dict[str, Any]:
    """Return release-train validity and its tag-derived admission projection."""
    root = Path(root).resolve()
    if candidate_tag is not None:
        if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", candidate_tag):
            raise ValueError("candidate tag must use vMAJOR.MINOR.PATCH")

        def commit(ref: str) -> str:
            return subprocess.run(
                ["git", "-C", str(root), "rev-parse", "--verify", ref],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()

        if commit(f"refs/tags/{candidate_tag}^{{commit}}") != commit("HEAD"):
            raise ValueError("candidate tag must identify the checked-out commit")
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
            "effective_at",
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
        effective_at=_parse_timestamp(cadence["effective_at"]),
        candidate_tag=candidate_tag,
    )
    projection["excluded_candidate_tag"] = candidate_tag
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
    policy: dict[str, Any],
    metrics: dict[str, Any],
    cadence: dict[str, Any],
    active_finding_codes: set[str],
) -> tuple[dict[str, Any] | None, str | None]:
    """Validate an explicit, expiring acceptance of measured architecture debt."""
    value = policy.get("accepted_debt")
    if value is None:
        return None, None
    error = _accepted_debt_shape_error(value)
    if error:
        return None, error
    _, error = _accepted_debt_expiry(value)
    if error:
        return None, error
    codes = _accepted_debt_codes(value.get("codes"))
    if codes is None:
        return (
            None,
            "accepted_debt codes must be a unique non-empty list of known debt codes",
        )
    accepted_metrics = value.get("metrics")
    if not isinstance(accepted_metrics, dict):
        return None, "accepted_debt metrics must be an object"
    active_codes = [code for code in codes if code in active_finding_codes]
    error = _accepted_metric_error(active_codes, accepted_metrics, metrics, cadence)
    if error:
        return None, error
    if not active_codes:
        return None, None
    return _accepted_debt_receipt(
        value, codes, active_codes, active_finding_codes, accepted_metrics
    ), None


def _accepted_debt_shape_error(value: Any) -> str | None:
    if not isinstance(value, dict):
        return "accepted_debt must be an object"
    required = {"decision_id", "owner", "expires_at", "reason", "codes", "metrics"}
    if set(value) != required:
        return "accepted_debt must contain decision_id, owner, expires_at, reason, codes, and metrics"
    if not all(
        isinstance(value.get(key), str) and value[key].strip()
        for key in ("decision_id", "owner", "reason")
    ):
        return "accepted_debt decision_id, owner, and reason must be non-empty strings"
    return None


def _accepted_debt_expiry(value: dict[str, Any]) -> tuple[datetime | None, str | None]:
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
    return expires, None


def _accepted_debt_codes(value: Any) -> list[str] | None:
    if (
        not isinstance(value, list)
        or not value
        or not all(
            isinstance(code, str) and code in _ACCEPTED_METRIC_FOR_CODE
            for code in value
        )
    ):
        return None
    return value if len(value) == len(set(value)) else None


def _accepted_metric_error(
    active_codes: list[str],
    accepted_metrics: dict[str, Any],
    metrics: dict[str, Any],
    cadence: dict[str, Any],
) -> str | None:
    observed = {**metrics, "release_recent_count": cadence.get("recent_count")}
    for code in active_codes:
        metric = _ACCEPTED_METRIC_FOR_CODE[code]
        if metric not in accepted_metrics or accepted_metrics[metric] != observed.get(
            metric
        ):
            return (
                f"accepted_debt metric {metric} must exactly match the measured value"
            )
    return None


def _accepted_debt_receipt(
    value: dict[str, Any],
    codes: list[str],
    active_codes: list[str],
    active_finding_codes: set[str],
    accepted_metrics: dict[str, Any],
) -> dict[str, Any]:
    return {
        "decision_id": value["decision_id"],
        "owner": value["owner"],
        "expires_at": value["expires_at"],
        "reason": value["reason"],
        "codes": active_codes,
        "retired_codes": [code for code in codes if code not in active_finding_codes],
        "metrics": {
            _ACCEPTED_METRIC_FOR_CODE[code]: accepted_metrics[
                _ACCEPTED_METRIC_FOR_CODE[code]
            ]
            for code in active_codes
        },
    }


def _load_architecture_policy(
    policy_path: Path,
) -> tuple[bytes, dict[str, Any]]:
    if not policy_path.exists():
        raise ArchitectureHealthError(f"architecture policy not found: {policy_path}")
    try:
        policy_bytes = policy_path.read_bytes()
        policy = json.loads(policy_bytes.decode("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArchitectureHealthError(f"invalid architecture policy: {exc}") from exc
    if policy.get("schema") != "factory.architecture-policy.v1":
        raise ArchitectureHealthError("unsupported architecture policy schema")
    return policy_bytes, policy


def _budget_regressions(
    metrics: dict[str, Any], budgets: dict[str, Any]
) -> list[dict[str, Any]]:
    findings = []
    for key, budget_key in (
        ("markdown_files", "max_markdown_files"),
        ("python_files", "max_python_files"),
        ("cli_lines", "max_cli_lines"),
        ("cli_command_declarations", "max_cli_command_declarations"),
        ("core_modules", "max_core_modules"),
    ):
        value, limit = metrics[key], budgets.get(budget_key)
        if isinstance(value, int) and isinstance(limit, int) and value > limit:
            findings.append(
                _finding(
                    f"E_ARCH_{key.upper()}_GROWTH",
                    "BLOCKER",
                    f"{key} grew to {value}; policy maximum is {limit}.",
                    f"Remove unrelated {key} growth or update the reviewed policy with an architecture decision.",
                    blocking=True,
                )
            )
    ratio, limit = (
        metrics["markdown_python_ratio"],
        budgets.get("max_markdown_python_ratio"),
    )
    if (
        isinstance(ratio, (int, float))
        and isinstance(limit, (int, float))
        and ratio > limit
    ):
        findings.append(
            _finding(
                "E_ARCH_DOC_CODE_RATIO_GROWTH",
                "BLOCKER",
                f"Markdown/Python ratio is {ratio}; policy maximum is {limit}.",
                "Add executable coverage or consolidate stale documentation before adding more narrative surface.",
                blocking=True,
            )
        )
    return findings


def _integrity_regressions(
    metrics: dict[str, Any], policy: dict[str, Any]
) -> list[dict[str, Any]]:
    findings = []
    domains = metrics.get("module_domains", {})
    if domains.get("manifest_invalid"):
        findings.append(
            _finding(
                "E_ARCH_BOUNDARY_MANIFEST_INVALID",
                "BLOCKER",
                "architecture-boundaries.json is malformed or uses an unsupported schema.",
                "Restore the reviewed factory.module-boundaries.v1 manifest before merging architecture changes.",
                blocking=True,
            )
        )
    docs = metrics.get("documentation_index", {})
    if policy.get("documentation", {}).get("require_index") and docs.get("status") in {
        "missing",
        "invalid",
        "incomplete",
    }:
        findings.append(
            _finding(
                "E_ARCH_DOCUMENTATION_INDEX_INVALID",
                "BLOCKER",
                "Documentation index is missing, malformed, or leaves Markdown files unclassified.",
                "Repair docs/DOCUMENTATION_INDEX.json before adding or publishing narrative documentation.",
                blocking=True,
            )
        )
    train = metrics.get("release_train", {})
    if policy.get("release", {}).get("require_train") and train.get("status") in {
        "missing",
        "invalid",
    }:
        findings.append(
            _finding(
                "E_ARCH_RELEASE_TRAIN_INVALID",
                "BLOCKER",
                "release-train.json is missing or does not describe the governed release channels.",
                "Restore the reviewed release-train.v1 contract before creating a release artifact.",
                blocking=True,
            )
        )
    return findings


def _surface_baseline_debt(
    metrics: dict[str, Any], policy: dict[str, Any]
) -> list[dict[str, Any]]:
    findings = []
    domains = metrics.get("module_domains", {})
    if domains.get("manifest_missing") and not domains.get("manifest_invalid"):
        findings.append(
            _finding(
                "ARCH_BOUNDARY_MANIFEST_MISSING",
                "MEDIUM",
                "No architecture-boundaries.json manifest was found for the measured repository.",
                "Add a reviewed core-versus-specialist boundary manifest before expanding the module surface.",
            )
        )
    thresholds = policy.get("review_thresholds", {})
    if metrics["cli_lines"] > thresholds.get("cli_lines", 5000):
        findings.append(
            _finding(
                "ARCH_CLI_MONOLITH",
                "HIGH",
                f"factoryline/cli.py is {metrics['cli_lines']} lines and owns parser/dispatch assembly.",
                "Extract command registration and dispatch into bounded command modules; retain cli.py as a compatibility entry point.",
            )
        )
    if metrics["cli_command_declarations"] > thresholds.get(
        "cli_command_declarations", 300
    ):
        findings.append(
            _finding(
                "ARCH_CLI_COMMAND_SURFACE",
                "HIGH",
                f"factoryline/cli.py declares {metrics['cli_command_declarations']} parser commands and subcommands.",
                "Group commands by bounded domain and expose a stable compatibility index instead of adding more parser branches.",
            )
        )
    if metrics["core_modules"] > thresholds.get("core_modules", 150):
        findings.append(
            _finding(
                "ARCH_CORE_SURFACE",
                "HIGH",
                f"factoryline contains {metrics['core_modules']} implementation modules.",
                "Publish a supported-module manifest and move experimental adapters behind explicit package boundaries.",
            )
        )
    ratio = metrics["markdown_python_ratio"]
    if ratio is not None and ratio > thresholds.get("markdown_python_ratio", 1.5):
        findings.append(
            _finding(
                "ARCH_DOC_CODE_RATIO",
                "MEDIUM",
                f"There are {metrics['markdown_files']} Markdown files for {metrics['python_files']} Python files (ratio {ratio}).",
                "Index canonical docs, archive superseded narratives, and require each new document to link to executable behavior or a decision.",
            )
        )
    return findings


def _changelog_regressions(
    root: Path, metrics: dict[str, Any], policy: dict[str, Any]
) -> list[dict[str, Any]]:
    if not policy.get("release", {}).get(
        "requires_changelog_entry"
    ) or _changelog_contains_version(root, metrics.get("version")):
        return []
    return [
        _finding(
            "E_ARCH_RELEASE_CHANGELOG_MISSING",
            "BLOCKER",
            f"Current version {metrics.get('version') or 'unknown'} has no CHANGELOG.md release entry.",
            "Add a human-readable changelog heading for the exact current version before release.",
            blocking=True,
        )
    ]


def _apply_accepted_debt(
    policy: dict[str, Any],
    metrics: dict[str, Any],
    cadence: dict[str, Any],
    regressions: list[dict[str, Any]],
    debt: list[dict[str, Any]],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any] | None,
]:
    active_codes = {item["code"] for item in [*regressions, *debt]}
    accepted, error = _accepted_debt(policy, metrics, cadence, active_codes)
    if error:
        regressions.append(
            _finding(
                "E_ARCH_ACCEPTANCE_INVALID",
                "BLOCKER",
                error,
                "Remove the acceptance or renew it with a named owner, future expiry, and exact measured values.",
                blocking=True,
            )
        )
    accepted_codes = set(accepted["codes"]) if accepted else set()
    accepted_debt = [item for item in debt if item["code"] in accepted_codes]
    accepted_regressions = [
        item for item in regressions if item["code"] in accepted_codes
    ]
    return (
        [item for item in debt if item["code"] not in accepted_codes],
        [item for item in regressions if item["code"] not in accepted_codes],
        accepted_debt,
        accepted_regressions,
        accepted,
    )


def _architecture_decision(
    regressions: list[dict[str, Any]], debt: list[dict[str, Any]], strict: bool
) -> str:
    if regressions or (strict and debt):
        return "BLOCKED"
    return "REVIEW_REQUIRED" if debt else "HEALTHY"


def _architecture_next_action(
    regressions: list[dict[str, Any]],
    debt: list[dict[str, Any]],
    strict: bool,
    cadence: dict[str, Any],
) -> str:
    if regressions:
        return "Stop and resolve architecture budget regressions before merge."
    if strict and debt:
        return (
            "Strict mode requires an approved decomposition plan for all baseline debt."
        )
    if debt:
        return (
            "Keep the existing debt visible and execute the bounded decomposition plan."
        )
    action = "Architecture budgets are within policy."
    if cadence.get("admission") is not False:
        return action
    action += " Release admission is blocked by the cadence guard: "
    action += cadence.get("reason", "cadence evidence unavailable")
    if cadence.get("next_eligible_at"):
        action += f" Next eligible at {cadence['next_eligible_at']}."
    return action


def evaluate_architecture_health(
    root: Path, policy_path: Path | None = None, *, strict: bool = False
) -> dict[str, Any]:
    """Evaluate metrics against a human-reviewed policy."""
    root = root.resolve()
    policy_path = (policy_path or (root / DEFAULT_POLICY_NAME)).resolve()
    policy_bytes, policy = _load_architecture_policy(policy_path)
    snapshot = collect_architecture_health(root)
    metrics = snapshot["metrics"]
    budgets = policy.get("budgets", {})
    regressions = _budget_regressions(metrics, budgets)
    regressions.extend(_integrity_regressions(metrics, policy))
    regressions.extend(_changelog_regressions(root, metrics, policy))
    debt = _surface_baseline_debt(metrics, policy)
    cadence = snapshot["release_cadence"]
    debt, regressions, accepted_debt, accepted_regressions, accepted = (
        _apply_accepted_debt(policy, metrics, cadence, regressions, debt)
    )
    return {
        **snapshot,
        "policy": {
            "path": str(policy_path),
            "baseline": policy.get("baseline", {}),
            "budgets": budgets,
            "sha256": "sha256:" + hashlib.sha256(policy_bytes).hexdigest(),
        },
        "baseline_debt": debt,
        "accepted_baseline_debt": accepted_debt,
        "accepted_regressions": accepted_regressions,
        "accepted_debt": accepted,
        "regressions": regressions,
        "decision": _architecture_decision(regressions, debt, strict),
        "next_action": _architecture_next_action(regressions, debt, strict, cadence),
    }
