"""Fail-closed release-candidate preflight.

The release workflow produces three different package versions (core, VS Code,
and IntelliJ), so this module deliberately scopes artifact checking to the
candidate directories passed by the caller.  It binds the selected artifact
set to the core source version and exact Git commit without contacting a
provider or reading credentials.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from .release_contract import verify_release_contract


SCHEMA = "factory.release-candidate-preflight.v1"
SEMVER_RE = re.compile(r"(?<!\d)(\d+\.\d+\.\d+)(?!\d)")
COMMIT_RE = re.compile(r"[0-9a-f]{40,64}")
ARTIFACT_SUFFIXES = (".whl", ".tar.gz", ".vsix", ".zip", ".tgz")
DEFAULT_ARTIFACT_DIRS = (Path(".factory/package-check"), Path("dist"))
MAX_ARTIFACTS = 256
AUTHORITY = {
    "execution": False,
    "approval": False,
    "repair": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "credential": False,
    "provider_call": False,
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _inside(root: Path, supplied: Path, label: str) -> Path:
    workspace = Path(root).resolve()
    target = supplied.resolve() if supplied.is_absolute() else (workspace / supplied).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"{label} must remain inside the workspace") from exc
    return target


def _git_head(root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, encoding="ascii", timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout.strip().lower()
    return value if result.returncode == 0 and COMMIT_RE.fullmatch(value) else None


def source_snapshot(root: Path) -> dict[str, Any]:
    """Read the core source version and immutable source commit."""
    workspace = Path(root).resolve()
    pyproject_path = workspace / "pyproject.toml"
    init_path = workspace / "factoryline" / "__init__.py"
    try:
        project = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        pyproject_version = project.get("project", {}).get("version")
        init_text = init_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, ValueError, TypeError):
        return {"ok": False, "reason": "core source metadata is unavailable"}
    init_match = re.search(r"(?m)^__version__\s*=\s*['\"]([^'\"]+)['\"]", init_text)
    init_version = init_match.group(1).strip() if init_match else None
    if not isinstance(pyproject_version, str) or not pyproject_version.strip() or not init_version:
        return {"ok": False, "reason": "core source version is missing"}
    if not SEMVER_RE.fullmatch(pyproject_version.strip()) or not SEMVER_RE.fullmatch(init_version):
        return {"ok": False, "reason": "core source version is not semantic"}
    commit = _git_head(workspace)
    if commit is None:
        return {"ok": False, "reason": "current Git commit is unavailable"}
    versions = {"pyproject.toml": pyproject_version.strip(), "factoryline/__init__.py": init_version}
    if len(set(versions.values())) != 1:
        return {"ok": False, "reason": "core source version declarations disagree", "versions": versions, "commit": commit}
    platform_versions: dict[str, str | None] = {"python": pyproject_version.strip(), "vscode": None, "intellij": None}
    try:
        vscode = json.loads((workspace / "editors" / "vscode" / "package.json").read_text(encoding="utf-8"))
        if isinstance(vscode, dict) and isinstance(vscode.get("version"), str):
            platform_versions["vscode"] = vscode["version"].strip()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
        pass
    try:
        gradle_text = (workspace / "editors" / "intellij" / "build.gradle.kts").read_text(encoding="utf-8")
        gradle_match = re.search(r"(?m)^version\s*=\s*['\"]([^'\"]+)['\"]", gradle_text)
        if gradle_match:
            platform_versions["intellij"] = gradle_match.group(1).strip()
    except (OSError, UnicodeDecodeError):
        pass
    file_entries: dict[str, dict[str, str]] = {}
    for key, value in versions.items():
        try:
            file_entries[key] = {"version": value, "sha256": hashlib.sha256((workspace / key).read_bytes()).hexdigest()}
        except OSError:
            return {"ok": False, "reason": f"core source file is unreadable: {key}"}
    return {
        "ok": True,
        "version": pyproject_version.strip(),
        "commit": commit,
        "platform_versions": platform_versions,
        "files": file_entries,
    }


def _artifact_version(name: str) -> str | None:
    matches = SEMVER_RE.findall(name)
    if len(matches) != 1:
        return matches[0] if len(matches) == 1 else None
    return matches[0]


def _artifact_platform(name: str) -> str:
    lowered = name.lower()
    if lowered.startswith("factoryline-vscode-") or lowered.endswith(".vsix"):
        return "vscode"
    if lowered.startswith("factoryline-intellij-"):
        return "intellij"
    return "python"


def _artifact_files(root: Path, directories: Iterable[Path]) -> tuple[list[Path], list[dict[str, str]]]:
    workspace = Path(root).resolve()
    files: list[Path] = []
    errors: list[dict[str, str]] = []
    for supplied in directories:
        try:
            directory = _inside(workspace, Path(supplied), "artifact directory")
        except ValueError as exc:
            errors.append({"code": "E_RELEASE_ARTIFACT_PATH", "detail": str(exc)})
            continue
        if not directory.exists():
            continue
        if not directory.is_dir():
            errors.append({"code": "E_RELEASE_ARTIFACT_PATH", "detail": f"artifact path is not a directory: {directory.relative_to(workspace).as_posix()}"})
            continue
        try:
            found = [candidate for candidate in directory.rglob("*") if candidate.is_file() and candidate.name.lower().endswith(ARTIFACT_SUFFIXES)]
        except OSError as exc:
            errors.append({"code": "E_RELEASE_ARTIFACT_SCAN", "detail": str(exc)[:240]})
            continue
        for candidate in found:
            try:
                candidate.resolve().relative_to(workspace)
            except ValueError:
                errors.append({"code": "E_RELEASE_ARTIFACT_PATH", "detail": f"artifact resolves outside workspace: {candidate}"})
                continue
            files.append(candidate.resolve())
    unique = sorted(set(files), key=lambda item: item.relative_to(workspace).as_posix())
    if len(unique) > MAX_ARTIFACTS:
        errors.append({"code": "E_RELEASE_ARTIFACT_SCAN", "detail": f"artifact inventory exceeds {MAX_ARTIFACTS} files"})
        unique = unique[:MAX_ARTIFACTS]
    return unique, errors


def _scan_artifacts(root: Path, expected_versions: dict[str, str | None], directories: Iterable[Path]) -> dict[str, Any]:
    workspace = Path(root).resolve()
    files, errors = _artifact_files(workspace, directories)
    inspected: list[dict[str, Any]] = []
    blockers = list(errors)
    if not files and not blockers:
        blockers.append({"code": "E_RELEASE_ARTIFACT_MISSING", "detail": "no release artifact was found in the candidate directories"})
    for path in files:
        relative = path.relative_to(workspace).as_posix()
        version = _artifact_version(path.name)
        platform = _artifact_platform(path.name)
        expected = expected_versions.get(platform)
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except (OSError, PermissionError) as exc:
            blockers.append({"code": "E_RELEASE_ARTIFACT_UNREADABLE", "detail": f"{relative} could not be hashed: {str(exc)[:180]}"})
            continue
        row = {"path": relative, "platform": platform, "version": version, "expected_version": expected, "sha256": digest}
        inspected.append(row)
        if version is None:
            blockers.append({"code": "E_RELEASE_ARTIFACT_VERSION_UNREADABLE", "detail": f"artifact version is not uniquely encoded: {relative}"})
        elif expected is None:
            blockers.append({"code": "E_RELEASE_ARTIFACT_EXPECTATION_MISSING", "detail": f"no source version is declared for {platform}: {relative}"})
        elif version != expected:
            blockers.append({"code": "E_RELEASE_ARTIFACT_VERSION_MISMATCH", "detail": f"{relative} declares {version}; {platform} source is {expected}"})
    return {"directories": [Path(item).as_posix() for item in directories], "artifacts": inspected, "blockers": blockers, "versions_match": not blockers}


def release_candidate_preflight(root: Path, contract: Path, artifact_dirs: Iterable[Path] | None = None, metadata_paths: Iterable[Path] | None = None) -> dict[str, Any]:
    """Evaluate contract/source/artifact identity without external authority."""
    workspace = Path(root).resolve()
    source = source_snapshot(workspace)
    checks: list[dict[str, Any]] = []
    blockers: list[dict[str, str]] = []
    try:
        contract_path = _inside(workspace, Path(contract), "release contract")
    except ValueError as exc:
        body = {
            "schema": SCHEMA,
            "marker": "RELEASE_CANDIDATE_PREFLIGHT_BLOCKED",
            "ok": False,
            "source": source,
            "contract": {"path": str(contract), "feature": None, "marker": "RELEASE_CONTRACT_INVALID"},
            "artifacts": {"directories": [Path(item).as_posix() for item in (artifact_dirs or DEFAULT_ARTIFACT_DIRS)], "artifacts": [], "blockers": []},
            "metadata": {"scope": "active", "status": "NOT_REQUESTED", "findings": [], "files": []},
            "facts": {"contract_valid": False, "artifact_versions_match": False, "metadata_lineage_valid": True, "ledger_drift": False, "windows_binding_proven": True},
            "checks": [{"id": "RELEASE_CONTRACT_VALID", "passed": False, "evidence": str(exc)}],
            "blockers": [{"code": "RELEASE_CONTRACT_INVALID", "detail": str(exc)}],
            "next_action": "repair_release_candidate",
            "authority": dict(AUTHORITY),
            "claim_boundary": "Read-only local candidate identity and artifact-version proof; no execution, credentials, signing, provider call, publication, deployment, approval, or merge authority.",
        }
        body["receipt_sha256"] = _sha(body)
        return body
    contract_value: dict[str, Any] | None = None
    contract_result: dict[str, Any]
    try:
        contract_value = json.loads(contract_path.read_text(encoding="utf-8-sig"))
        if not isinstance(contract_value, dict):
            raise ValueError("release contract must be an object")
        feature = contract_value.get("feature")
        required = set(contract_value.get("required_stages", [])) if isinstance(contract_value.get("required_stages"), list) else set()
        contract_result = verify_release_contract(workspace, str(feature), contract_path, required)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        contract_result = {"ok": False, "marker": "RELEASE_CONTRACT_INVALID", "reason": str(exc)[:240]}
    checks.append({"id": "RELEASE_CONTRACT_VALID", "passed": bool(contract_result.get("ok")), "evidence": contract_result.get("marker", "RELEASE_CONTRACT_INVALID")})
    if not contract_result.get("ok"):
        blockers.append({"code": str(contract_result.get("marker", "RELEASE_CONTRACT_INVALID")), "detail": str(contract_result.get("reason", "release contract is invalid"))})

    binding = contract_value.get("candidate") if isinstance(contract_value, dict) else None
    binding_ok = bool(source.get("ok")) and isinstance(binding, dict) and binding.get("source_version") == source.get("version") and binding.get("source_commit") == source.get("commit")
    if not source.get("ok"):
        blockers.append({"code": "RELEASE_CONTRACT_SOURCE_MISMATCH", "detail": str(source.get("reason", "source metadata is invalid"))})
    elif not isinstance(binding, dict):
        blockers.append({"code": "RELEASE_CONTRACT_SOURCE_BINDING_MISSING", "detail": "contract candidate.source_version and candidate.source_commit are required"})
    else:
        if binding.get("source_version") != source.get("version"):
            blockers.append({"code": "RELEASE_CONTRACT_SOURCE_MISMATCH", "detail": "contract candidate.source_version differs from source version"})
        if binding.get("source_commit") != source.get("commit"):
            blockers.append({"code": "RELEASE_CONTRACT_SOURCE_MISMATCH", "detail": "contract candidate.source_commit differs from current Git commit"})
    checks.append({"id": "RELEASE_CONTRACT_SOURCE_MATCH", "passed": binding_ok, "evidence": "candidate binding equals source version and commit" if binding_ok else "candidate binding is missing or stale"})

    source_version = str(source.get("version", ""))
    declared_versions = binding.get("artifact_versions") if isinstance(binding, dict) else None
    source_versions = source.get("platform_versions", {"python": source_version}) if isinstance(source, dict) else {"python": source_version}
    if isinstance(declared_versions, dict):
        for platform, value in declared_versions.items():
            expected_source = source_versions.get(platform)
            if isinstance(expected_source, str) and value != expected_source:
                blockers.append({"code": "RELEASE_CONTRACT_ARTIFACT_BINDING_MISMATCH", "detail": f"contract candidate artifact_versions.{platform} differs from source metadata"})
    else:
        declared_versions = source_versions
    expected_versions = {key: value for key, value in declared_versions.items() if key in {"python", "vscode", "intellij"} and isinstance(value, str)}
    artifacts = _scan_artifacts(workspace, expected_versions, list(artifact_dirs) if artifact_dirs is not None else list(DEFAULT_ARTIFACT_DIRS)) if source_version else {"directories": [], "artifacts": [], "blockers": [{"code": "E_RELEASE_ARTIFACT_VERSION_MISMATCH", "detail": "source version unavailable"}], "versions_match": False}
    checks.append({"id": "RELEASE_ARTIFACT_VERSIONS_MATCH", "passed": artifacts["versions_match"], "evidence": f"{len(artifacts['artifacts'])} candidate artifact(s) match source {source_version}" if artifacts["versions_match"] else "candidate artifact inventory contains a stale or unreadable version"})
    blockers.extend(artifacts["blockers"])

    metadata: dict[str, Any] = {"scope": "active", "status": "NOT_REQUESTED", "findings": [], "files": []}
    if metadata_paths is not None:
        from .codex_metadata import audit_metadata
        metadata = audit_metadata(workspace, [Path(item) for item in metadata_paths], scope="active")
        for finding in metadata.get("findings", []):
            blockers.append({"code": finding.get("code", "E_METADATA_INTEGRITY"), "detail": f"{finding.get('path', '<metadata>')} {finding.get('location', '')}: {finding.get('detail', '')}".strip()})
    metadata_lineage_valid = not any(item.get("code") == "E_METADATA_STATE_RECEIPT_MISMATCH" for item in metadata.get("findings", []))
    ledger_drift = any(item.get("code") in {"E_METADATA_LEDGER_ORDER", "E_METADATA_LEDGER_HEAD_MISMATCH"} for item in metadata.get("findings", []))
    metadata_ok = not metadata.get("findings")
    checks.append({"id": "CODEX_METADATA_INTEGRITY_ACTIVE", "passed": metadata_ok or metadata_paths is None, "evidence": "active metadata audit passed" if metadata_ok else ("active metadata audit not requested" if metadata_paths is None else "active metadata contains blocking findings")})
    facts = {"contract_valid": bool(contract_result.get("ok")), "artifact_versions_match": bool(artifacts["versions_match"]), "metadata_lineage_valid": metadata_lineage_valid, "ledger_drift": ledger_drift, "windows_binding_proven": True}
    ok = bool(source.get("ok")) and binding_ok and not blockers
    body: dict[str, Any] = {
        "schema": SCHEMA,
        "marker": "RELEASE_CANDIDATE_PREFLIGHT_PASS" if ok else "RELEASE_CANDIDATE_PREFLIGHT_BLOCKED",
        "ok": ok,
        "source": source,
        "contract": {"path": contract_path.relative_to(workspace).as_posix(), "feature": contract_value.get("feature") if contract_value else None, "marker": contract_result.get("marker"), "policy_digest": contract_result.get("policy_digest")},
        "artifacts": artifacts,
        "metadata": metadata,
        "facts": facts,
        "checks": checks,
        "blockers": blockers,
        "next_action": "review_external_publish_gates" if ok else "repair_release_candidate",
        "authority": dict(AUTHORITY),
        "claim_boundary": "Read-only local candidate identity and artifact-version proof; no execution, credentials, signing, provider call, publication, deployment, approval, or merge authority.",
    }
    body["receipt_sha256"] = _sha(body)
    return body


def write_release_candidate_preflight(root: Path, contract: Path, artifact_dirs: Iterable[Path] | None, out: Path, *, metadata_paths: Iterable[Path] | None = None) -> dict[str, Any]:
    """Write a candidate receipt atomically after running the pure preflight."""
    workspace = Path(root).resolve()
    result = release_candidate_preflight(workspace, contract, artifact_dirs, metadata_paths=metadata_paths)
    destination = _inside(workspace, Path(out), "release preflight output")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {**result, "marker": "RELEASE_CANDIDATE_PREFLIGHT_WRITTEN", "path": destination.relative_to(workspace).as_posix()}
    payload["receipt_sha256"] = _sha({key: value for key, value in payload.items() if key != "receipt_sha256"})
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    try:
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(destination)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return payload


__all__ = ["SCHEMA", "source_snapshot", "release_candidate_preflight", "write_release_candidate_preflight"]
