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
_VERSION_RE = re.compile(r"^(?:version|__version__)\s*=\s*[\"']([^\"']+)[\"']", re.MULTILINE)


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
        names = [item for item in completed.stdout.decode("utf-8", "replace").split("\0") if item]
        return [root / name for name in names]
    ignored = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}
    return [p for p in root.rglob("*") if p.is_file() and not ignored.intersection(p.parts)]


def _version(root: Path) -> str | None:
    for relative in ("pyproject.toml", "factoryline/__init__.py"):
        path = root / relative
        if path.exists():
            match = _VERSION_RE.search(path.read_text(encoding="utf-8"))
            if match:
                return match.group(1)
    return None


def _module_domains(root: Path, relative: list[str]) -> dict[str, int]:
    """Classify implementation modules using the reviewed boundary manifest."""
    manifest_path = root / "architecture-boundaries.json"
    if not manifest_path.exists():
        return {"manifest_missing": 1}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"manifest_invalid": 1}
    if manifest.get("schema") != "factory.module-boundaries.v1":
        return {"manifest_invalid": 1}
    domains: dict[str, int] = {}
    patterns = manifest.get("domains", {})
    for name in patterns:
        domains[name] = 0
    default = manifest.get("defaultDomain", "unclassified")
    domains.setdefault(default, 0)
    for path in relative:
        if not path.startswith("factoryline/") or not path.endswith(".py") or path.endswith("/__init__.py"):
            continue
        assigned = default
        for domain, globs in patterns.items():
            if any(fnmatch.fnmatch(path, pattern) for pattern in globs):
                assigned = domain
                break
        domains[assigned] = domains.get(assigned, 0) + 1
    return domains


def _recent_release_tags(root: Path, now: datetime | None = None) -> dict[str, Any]:
    """Measure release-tag cadence without making the check network-dependent."""
    now = now or datetime.now(timezone.utc)
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "for-each-ref", "refs/tags/v*", "--format=%(creatordate:iso-strict)"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return {"available": False, "recent_count": None, "latest_interval_days": None}
    dates: list[datetime] = []
    for line in completed.stdout.splitlines():
        try:
            dates.append(datetime.fromisoformat(line.strip().replace("Z", "+00:00")).astimezone(timezone.utc))
        except ValueError:
            continue
    dates.sort(reverse=True)
    recent = [stamp for stamp in dates if now - stamp <= timedelta(days=30)]
    interval = (dates[0] - dates[1]).total_seconds() / 86400 if len(dates) > 1 else None
    return {
        "available": True,
        "recent_count": len(recent),
        "latest_interval_days": round(interval, 2) if interval is not None else None,
    }


def collect_architecture_health(root: Path) -> dict[str, Any]:
    """Collect stable, explainable architecture metrics for ``root``."""
    root = root.resolve()
    files = _tracked_files(root)
    relative = [path.relative_to(root).as_posix() for path in files if path.exists()]
    markdown = [name for name in relative if name.lower().endswith(".md")]
    python = [name for name in relative if name.lower().endswith(".py")]
    core_modules = [
        name for name in python
        if name.startswith("factoryline/") and not name.rsplit("/", 1)[-1].startswith("__init__")
    ]
    cli_path = root / "factoryline" / "cli.py"
    cli_lines = len(cli_path.read_text(encoding="utf-8").splitlines()) if cli_path.exists() else 0
    cli_command_declarations = 0
    if cli_path.exists():
        cli_command_declarations = len(re.findall(r"\.add_parser\(", cli_path.read_text(encoding="utf-8")))
    ratio = round(len(markdown) / len(python), 4) if python else None
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
            "module_domains": _module_domains(root, relative),
            "version": _version(root),
            "tracked_files": len(relative),
        },
        "release_cadence": _recent_release_tags(root),
    }


def _finding(code: str, severity: str, message: str, action: str, *, blocking: bool = False) -> dict[str, Any]:
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
    "ARCH_RELEASE_CHURN": "release_recent_count",
}


def _accepted_debt(policy: dict[str, Any], metrics: dict[str, Any], cadence: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """Validate an explicit, expiring acceptance of measured architecture debt."""
    value = policy.get("accepted_debt")
    if value is None:
        return None, None
    if not isinstance(value, dict):
        return None, "accepted_debt must be an object"
    required = {"decision_id", "owner", "expires_at", "reason", "codes", "metrics"}
    if set(value) != required:
        return None, "accepted_debt must contain decision_id, owner, expires_at, reason, codes, and metrics"
    if not all(isinstance(value.get(key), str) and value[key].strip() for key in ("decision_id", "owner", "reason")):
        return None, "accepted_debt decision_id, owner, and reason must be non-empty strings"
    try:
        expires = datetime.fromisoformat(str(value["expires_at"]).replace("Z", "+00:00"))
        if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
            return None, "accepted_debt expires_at must be a future timezone-aware timestamp"
    except ValueError:
        return None, "accepted_debt expires_at must be an ISO-8601 timestamp"
    codes = value.get("codes")
    if not isinstance(codes, list) or not codes or len(codes) != len(set(codes)) or not all(isinstance(code, str) and code in _ACCEPTED_METRIC_FOR_CODE for code in codes):
        return None, "accepted_debt codes must be a unique non-empty list of known debt codes"
    accepted_metrics = value.get("metrics")
    if not isinstance(accepted_metrics, dict):
        return None, "accepted_debt metrics must be an object"
    observed = {**metrics, "release_recent_count": cadence.get("recent_count")}
    for code in codes:
        metric = _ACCEPTED_METRIC_FOR_CODE[code]
        if metric not in accepted_metrics or accepted_metrics[metric] != observed.get(metric):
            return None, f"accepted_debt metric {metric} must exactly match the measured value"
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
            regressions.append(_finding(
                f"E_ARCH_{key.upper()}_GROWTH", "BLOCKER",
                f"{key} grew to {value}; policy maximum is {limit}.",
                f"Remove unrelated {key} growth or update the reviewed policy with an architecture decision.",
                blocking=True,
            ))
    ratio = metrics["markdown_python_ratio"]
    ratio_limit = budgets.get("max_markdown_python_ratio")
    if isinstance(ratio, (int, float)) and isinstance(ratio_limit, (int, float)) and ratio > ratio_limit:
        regressions.append(_finding(
            "E_ARCH_DOC_CODE_RATIO_GROWTH", "BLOCKER",
            f"Markdown/Python ratio is {ratio}; policy maximum is {ratio_limit}.",
            "Add executable coverage or consolidate stale documentation before adding more narrative surface.",
            blocking=True,
        ))

    debt: list[dict[str, Any]] = []
    domains = metrics.get("module_domains", {})
    if domains.get("manifest_invalid"):
        regressions.append(_finding(
            "E_ARCH_BOUNDARY_MANIFEST_INVALID", "BLOCKER",
            "architecture-boundaries.json is malformed or uses an unsupported schema.",
            "Restore the reviewed factory.module-boundaries.v1 manifest before merging architecture changes.",
            blocking=True,
        ))
    elif domains.get("manifest_missing"):
        debt.append(_finding(
            "ARCH_BOUNDARY_MANIFEST_MISSING", "MEDIUM",
            "No architecture-boundaries.json manifest was found for the measured repository.",
            "Add a reviewed core-versus-specialist boundary manifest before expanding the module surface.",
        ))
    if metrics["cli_lines"] > policy.get("review_thresholds", {}).get("cli_lines", 5000):
        debt.append(_finding(
            "ARCH_CLI_MONOLITH", "HIGH",
            f"factoryline/cli.py is {metrics['cli_lines']} lines and owns parser/dispatch assembly.",
            "Extract command registration and dispatch into bounded command modules; retain cli.py as a compatibility entry point.",
        ))
    if metrics["cli_command_declarations"] > policy.get("review_thresholds", {}).get("cli_command_declarations", 300):
        debt.append(_finding(
            "ARCH_CLI_COMMAND_SURFACE", "HIGH",
            f"factoryline/cli.py declares {metrics['cli_command_declarations']} parser commands and subcommands.",
            "Group commands by bounded domain and expose a stable compatibility index instead of adding more parser branches.",
        ))
    if metrics["core_modules"] > policy.get("review_thresholds", {}).get("core_modules", 150):
        debt.append(_finding(
            "ARCH_CORE_SURFACE", "HIGH",
            f"factoryline contains {metrics['core_modules']} implementation modules.",
            "Publish a supported-module manifest and move experimental adapters behind explicit package boundaries.",
        ))
    if ratio is not None and ratio > policy.get("review_thresholds", {}).get("markdown_python_ratio", 1.5):
        debt.append(_finding(
            "ARCH_DOC_CODE_RATIO", "MEDIUM",
            f"There are {metrics['markdown_files']} Markdown files for {metrics['python_files']} Python files (ratio {ratio}).",
            "Index canonical docs, archive superseded narratives, and require each new document to link to executable behavior or a decision.",
        ))
    cadence = snapshot["release_cadence"]
    cadence_policy = policy.get("release", {})
    if cadence.get("available") and cadence.get("recent_count") is not None:
        if cadence["recent_count"] > cadence_policy.get("max_releases_30d", 4):
            debt.append(_finding(
                "ARCH_RELEASE_CHURN", "MEDIUM",
                f"{cadence['recent_count']} version tags were created in the last 30 days.",
                "Use a release train and changelog entry; reserve patch releases for externally observable fixes.",
            ))

    accepted, acceptance_error = _accepted_debt(policy, metrics, cadence)
    if acceptance_error:
        regressions.append(_finding(
            "E_ARCH_ACCEPTANCE_INVALID", "BLOCKER", acceptance_error,
            "Remove the acceptance or renew it with a named owner, future expiry, and exact measured values.",
            blocking=True,
        ))
    accepted_codes = set(accepted["codes"]) if accepted else set()
    accepted_baseline_debt = [item for item in debt if item["code"] in accepted_codes]
    debt = [item for item in debt if item["code"] not in accepted_codes]
    accepted_regressions = [item for item in regressions if item["code"] in accepted_codes]
    regressions = [item for item in regressions if item["code"] not in accepted_codes]

    decision = "BLOCKED" if regressions or (strict and debt) else ("REVIEW_REQUIRED" if debt else "HEALTHY")
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
            if regressions else
            "Strict mode requires an approved decomposition plan for all baseline debt."
            if strict and debt else
            "Keep the existing debt visible and execute the bounded decomposition plan."
            if debt else
            "Architecture budgets are within policy."
        ),
    }
