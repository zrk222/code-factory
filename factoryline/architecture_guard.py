"""Pin Code Factory's own size guard while allowing installed CLI usage."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

SIZE_COVERAGE_MAX_LINES = 6_000
SIZE_COVERAGE_MAX_BYTES = 240_000
_SELF_SIZE_GUARD_SHA256 = (
    "80802ffec4a0252c7a94bcf5783e95813a5eabfb00998275decbf86aa3e01629"
)


def is_code_factory_root(root: Path) -> bool:
    """Identify Code Factory by independent source, package or policy anchors."""
    if (root / "factoryline/architecture_health.py").is_file():
        return True
    try:
        document = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        document = {}
    project = document.get("project")
    if isinstance(project, dict) and project.get("name") == "factoryline-code-factory":
        return True
    try:
        default_policy = json.loads(
            (root / "architecture-policy.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return isinstance(default_policy, dict) and file_size_guard_is_pinned(
        default_policy.get("file_size_guard")
    )


def file_size_guard_is_pinned(guard: object) -> bool:
    """Check the exact inventory and the independent discovery limits."""
    if not isinstance(guard, dict) or guard.get("required") is not True:
        return False
    budgets = guard.get("files")
    paths = guard.get("required_paths")
    if (
        not isinstance(budgets, dict)
        or not budgets
        or not isinstance(paths, list)
        or any(not isinstance(path, str) for path in paths)
        or len(set(paths)) != len(paths)
        or set(paths) != set(budgets)
    ):
        return False
    try:
        inventory = sorted(
            (path, budgets[path]["max_lines"], budgets[path]["max_bytes"])
            for path in paths
        )
    except (KeyError, TypeError):
        return False
    digest = hashlib.sha256(
        repr((inventory, SIZE_COVERAGE_MAX_LINES, SIZE_COVERAGE_MAX_BYTES)).encode()
    ).hexdigest()
    return digest == _SELF_SIZE_GUARD_SHA256


def large_module_coverage_gaps(
    root: Path, tracked_paths: list[Path], covered_paths: set[str]
) -> list[dict[str, int | str]]:
    """Find tracked production modules above discovery limits but outside the pin."""
    root = root.resolve()
    gaps: list[dict[str, int | str]] = []
    for path in tracked_paths:
        try:
            candidate = path if path.is_absolute() else root / path
            relative = candidate.relative_to(root).as_posix()
        except (OSError, ValueError):
            if "factoryline" in path.parts and path.suffix == ".py":
                gaps.append({"path": path.as_posix(), "error": "outside_root"})
            continue
        if (
            not relative.startswith("factoryline/")
            or not relative.endswith(".py")
            or relative in covered_paths
        ):
            continue
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
            text = resolved.read_bytes().decode("utf-8")
            lines = len(text.splitlines())
            normalized = text.replace("\r\n", "\n").replace("\r", "\n")
            size_bytes = len(normalized.encode("utf-8"))
        except (OSError, UnicodeDecodeError, RuntimeError, ValueError):
            gaps.append({"path": relative, "error": "unreadable"})
            continue
        if lines > SIZE_COVERAGE_MAX_LINES or size_bytes > SIZE_COVERAGE_MAX_BYTES:
            gaps.append({"path": relative, "lines": lines, "bytes": size_bytes})
    return gaps


def file_size_report(
    root: Path,
    policy: dict,
    *,
    tracked_paths: list[Path],
    finding,
) -> tuple[dict, list[dict]]:
    """Measure pinned files and block invalid or incomplete size inventories."""
    guard = policy.get("file_size_guard")
    findings: list[dict] = []
    guard = guard if isinstance(guard, dict) else {}
    budgets = guard.get("files")
    required_paths = guard.get("required_paths")
    factory_root = is_code_factory_root(root)
    if (
        guard.get("required") is not True
        or not isinstance(budgets, dict)
        or not budgets
        or not isinstance(required_paths, list)
        or any(not isinstance(path, str) for path in required_paths)
        or len(set(required_paths)) != len(required_paths)
        or set(required_paths) != set(budgets)
        or (
            factory_root
            and (
                not file_size_guard_is_pinned(guard)
                or not default_policy_guard_is_pinned(root)
            )
        )
    ):
        return {"enforced": False, "files": {}, "coverage_gaps": []}, [
            finding(
                "E_ARCH_FILE_SIZE_POLICY_INVALID",
                "BLOCKER",
                "Per-file size guard inventory is invalid.",
                "Restore pinned paths and line/byte ceilings.",
                blocking=True,
            )
        ]

    covered_paths = set(required_paths)
    coverage_gaps = large_module_coverage_gaps(root, tracked_paths, covered_paths)
    for gap in coverage_gaps:
        findings.append(
            finding(
                "E_ARCH_FILE_SIZE_COVERAGE_GAP",
                "BLOCKER",
                f"Tracked production module exceeds or cannot be checked against the size-guard discovery limits: {gap}.",
                "Add this module to the pinned size guard with explicit line and byte ceilings, or reduce it below both discovery limits.",
                blocking=True,
            )
        )

    measurements: dict[str, dict[str, int]] = {}
    for raw_path, entry in budgets.items():
        relative = PurePosixPath(raw_path) if isinstance(raw_path, str) else None
        valid_path = (
            relative is not None
            and not relative.is_absolute()
            and "\\" not in raw_path
            and bool(relative.parts)
            and all(part not in {".", ".."} for part in relative.parts)
            and relative.as_posix() == raw_path
        )
        max_lines = entry.get("max_lines") if isinstance(entry, dict) else None
        max_bytes = entry.get("max_bytes") if isinstance(entry, dict) else None
        rationale = entry.get("rationale") if isinstance(entry, dict) else None
        if (
            not valid_path
            or type(max_lines) is not int
            or max_lines < 1
            or type(max_bytes) is not int
            or max_bytes < 1
            or not isinstance(rationale, str)
            or not rationale.strip()
        ):
            findings.append(
                finding(
                    "E_ARCH_FILE_SIZE_POLICY_INVALID",
                    "BLOCKER",
                    f"Invalid file size budget entry for {raw_path!r}.",
                    "Use a repository-relative path, positive max_lines and max_bytes, and a review rationale.",
                    blocking=True,
                )
            )
            continue

        target = root.joinpath(*relative.parts).resolve()
        if not target.is_relative_to(root.resolve()) or not target.is_file():
            findings.append(
                finding(
                    "E_ARCH_FILE_SIZE_TARGET_MISSING",
                    "BLOCKER",
                    f"Budgeted source file is missing or escapes the repository: {raw_path}.",
                    "Restore the source file at its reviewed repository path or update the policy through architecture review.",
                    blocking=True,
                )
            )
            continue
        try:
            text = target.read_bytes().decode("utf-8")
            lines = len(text.splitlines())
            normalized_text = text.replace("\r\n", "\n").replace("\r", "\n")
            size_bytes = len(normalized_text.encode("utf-8"))
        except (OSError, UnicodeDecodeError):
            findings.append(
                finding(
                    "E_ARCH_FILE_SIZE_TARGET_UNREADABLE",
                    "BLOCKER",
                    f"Budgeted source file could not be measured as UTF-8: {raw_path}.",
                    "Restore a readable UTF-8 source file before architecture health can pass.",
                    blocking=True,
                )
            )
            continue

        measurements[raw_path] = {
            "lines": lines,
            "bytes": size_bytes,
            "max_lines": max_lines,
            "max_bytes": max_bytes,
        }
        if lines > max_lines:
            findings.append(
                finding(
                    "E_ARCH_FILE_LINES_GROWTH",
                    "BLOCKER",
                    f"{raw_path} grew to {lines} lines; its frozen ceiling is {max_lines}.",
                    "Split or shrink this file before expanding it; do not raise its ceiling without a reviewed architecture decision.",
                    blocking=True,
                )
            )
        if size_bytes > max_bytes:
            findings.append(
                finding(
                    "E_ARCH_FILE_BYTES_GROWTH",
                    "BLOCKER",
                    f"{raw_path} grew to {size_bytes} normalized UTF-8 bytes; its frozen ceiling is {max_bytes}.",
                    "Reduce or split this file before increasing its byte size; do not raise its ceiling without a reviewed architecture decision.",
                    blocking=True,
                )
            )

    return {
        "enforced": True,
        "files": measurements,
        "coverage_thresholds": {
            "max_lines": SIZE_COVERAGE_MAX_LINES,
            "max_bytes": SIZE_COVERAGE_MAX_BYTES,
        },
        "coverage_gaps": coverage_gaps,
    }, findings


def default_policy_guard_is_pinned(root: Path) -> bool:
    """Require the checkout's canonical policy even when an override is used."""
    try:
        policy = json.loads(
            (root / "architecture-policy.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return isinstance(policy, dict) and file_size_guard_is_pinned(
        policy.get("file_size_guard")
    )
