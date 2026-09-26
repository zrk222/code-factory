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
from .intake_parameters import verify_intake_binding
from .architecture_health import (
    ArchitectureHealthError,
    evaluate_architecture_health,
    release_cadence_status,
)


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
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _inside(root: Path, supplied: Path, label: str) -> Path:
    workspace = Path(root).resolve()
    target = (
        supplied.resolve()
        if supplied.is_absolute()
        else (workspace / supplied).resolve()
    )
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"{label} must remain inside the workspace") from exc
    return target


def _git_head(root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="ascii",
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout.strip().lower()
    return value if result.returncode == 0 and COMMIT_RE.fullmatch(value) else None


def _platform_source_versions(
    workspace: Path, python_version: str
) -> dict[str, str | None]:
    """Read optional editor versions without promoting them to core source authority."""
    versions: dict[str, str | None] = {
        "python": python_version,
        "vscode": None,
        "intellij": None,
    }
    try:
        vscode = json.loads(
            (workspace / "editors" / "vscode" / "package.json").read_text(
                encoding="utf-8"
            )
        )
        if isinstance(vscode, dict) and isinstance(vscode.get("version"), str):
            versions["vscode"] = vscode["version"].strip()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
        pass
    try:
        gradle_text = (
            workspace / "editors" / "intellij" / "build.gradle.kts"
        ).read_text(encoding="utf-8")
        match = re.search(r"(?m)^version\s*=\s*['\"]([^'\"]+)['\"]", gradle_text)
        if match:
            versions["intellij"] = match.group(1).strip()
    except (OSError, UnicodeDecodeError):
        pass
    return versions


def _core_source_files(
    workspace: Path, versions: dict[str, str]
) -> tuple[dict[str, dict[str, str]], str | None]:
    """Bind each authoritative version declaration to its exact source bytes."""
    entries = {}
    for key, value in versions.items():
        try:
            entries[key] = {
                "version": value,
                "sha256": hashlib.sha256((workspace / key).read_bytes()).hexdigest(),
            }
        except OSError:
            return {}, key
    return entries, None


def _source_versions_present(pyproject_version: Any, init_version: str | None) -> bool:
    """Reject missing declarations before applying semantic-version checks."""
    return (
        isinstance(pyproject_version, str)
        and bool(pyproject_version.strip())
        and bool(init_version)
    )


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
    if not _source_versions_present(pyproject_version, init_version):
        return {"ok": False, "reason": "core source version is missing"}
    if not SEMVER_RE.fullmatch(pyproject_version.strip()) or not SEMVER_RE.fullmatch(
        init_version
    ):
        return {"ok": False, "reason": "core source version is not semantic"}
    commit = _git_head(workspace)
    if commit is None:
        return {"ok": False, "reason": "current Git commit is unavailable"}
    versions = {
        "pyproject.toml": pyproject_version.strip(),
        "factoryline/__init__.py": init_version,
    }
    if len(set(versions.values())) != 1:
        return {
            "ok": False,
            "reason": "core source version declarations disagree",
            "versions": versions,
            "commit": commit,
        }
    platform_versions = _platform_source_versions(workspace, pyproject_version.strip())
    file_entries, unreadable = _core_source_files(workspace, versions)
    if unreadable is not None:
        return {"ok": False, "reason": f"core source file is unreadable: {unreadable}"}
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


def _artifact_files(
    root: Path, directories: Iterable[Path]
) -> tuple[list[Path], list[dict[str, str]]]:
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
            errors.append(
                {
                    "code": "E_RELEASE_ARTIFACT_PATH",
                    "detail": f"artifact path is not a directory: {directory.relative_to(workspace).as_posix()}",
                }
            )
            continue
        try:
            found = [
                candidate
                for candidate in directory.rglob("*")
                if candidate.is_file()
                and candidate.name.lower().endswith(ARTIFACT_SUFFIXES)
            ]
        except OSError as exc:
            errors.append({"code": "E_RELEASE_ARTIFACT_SCAN", "detail": str(exc)[:240]})
            continue
        for candidate in found:
            try:
                candidate.resolve().relative_to(workspace)
            except ValueError:
                errors.append(
                    {
                        "code": "E_RELEASE_ARTIFACT_PATH",
                        "detail": f"artifact resolves outside workspace: {candidate}",
                    }
                )
                continue
            files.append(candidate.resolve())
    unique = sorted(set(files), key=lambda item: item.relative_to(workspace).as_posix())
    if len(unique) > MAX_ARTIFACTS:
        errors.append(
            {
                "code": "E_RELEASE_ARTIFACT_SCAN",
                "detail": f"artifact inventory exceeds {MAX_ARTIFACTS} files",
            }
        )
        unique = unique[:MAX_ARTIFACTS]
    return unique, errors


def _scan_artifacts(
    root: Path, expected_versions: dict[str, str | None], directories: Iterable[Path]
) -> dict[str, Any]:
    workspace = Path(root).resolve()
    files, errors = _artifact_files(workspace, directories)
    inspected: list[dict[str, Any]] = []
    blockers = list(errors)
    if not files and not blockers:
        blockers.append(
            {
                "code": "E_RELEASE_ARTIFACT_MISSING",
                "detail": "no release artifact was found in the candidate directories",
            }
        )
    for path in files:
        relative = path.relative_to(workspace).as_posix()
        version = _artifact_version(path.name)
        platform = _artifact_platform(path.name)
        expected = expected_versions.get(platform)
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except (OSError, PermissionError) as exc:
            blockers.append(
                {
                    "code": "E_RELEASE_ARTIFACT_UNREADABLE",
                    "detail": f"{relative} could not be hashed: {str(exc)[:180]}",
                }
            )
            continue
        row = {
            "path": relative,
            "platform": platform,
            "version": version,
            "expected_version": expected,
            "sha256": digest,
        }
        inspected.append(row)
        if version is None:
            blockers.append(
                {
                    "code": "E_RELEASE_ARTIFACT_VERSION_UNREADABLE",
                    "detail": f"artifact version is not uniquely encoded: {relative}",
                }
            )
        elif expected is None:
            blockers.append(
                {
                    "code": "E_RELEASE_ARTIFACT_EXPECTATION_MISSING",
                    "detail": f"no source version is declared for {platform}: {relative}",
                }
            )
        elif version != expected:
            blockers.append(
                {
                    "code": "E_RELEASE_ARTIFACT_VERSION_MISMATCH",
                    "detail": f"{relative} declares {version}; {platform} source is {expected}",
                }
            )
    return {
        "directories": [Path(item).as_posix() for item in directories],
        "artifacts": inspected,
        "blockers": blockers,
        "versions_match": not blockers,
    }


def _architecture_preflight(
    workspace: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str] | None]:
    """Translate strict architecture policy into one release check and blocker."""
    try:
        health = evaluate_architecture_health(workspace, strict=True)
    except (
        ArchitectureHealthError,
        OSError,
        TypeError,
        ValueError,
        AttributeError,
    ) as exc:
        health = {
            "decision": "BLOCKED",
            "regressions": [
                {"code": "E_ARCH_POLICY_UNAVAILABLE", "detail": str(exc)[:240]}
            ],
            "baseline_debt": [],
        }
    codes = [
        str(item.get("code", "E_ARCH_UNKNOWN"))
        for group in ("regressions", "baseline_debt")
        for item in health.get(group, [])
        if isinstance(item, dict)
    ]
    admitted = health.get("decision") == "HEALTHY"
    check = {
        "id": "STRICT_ARCHITECTURE_HEALTH",
        "passed": admitted,
        "evidence": health.get("decision", "BLOCKED")
        + (f" ({', '.join(codes)})" if codes else ""),
    }
    blocker = (
        None
        if admitted
        else {
            "code": "E_RELEASE_ARCHITECTURE_HEALTH_BLOCKED",
            "detail": "strict architecture health is "
            f"{health.get('decision', 'BLOCKED')}; resolve: "
            + (", ".join(codes) or "policy unavailable"),
        }
    )
    return health, check, blocker


def _cadence_preflight(
    cadence: dict[str, Any],
) -> tuple[bool, dict[str, Any], dict[str, str] | None]:
    """Require the effective release train to admit this exact candidate."""
    admitted = (
        cadence.get("release_train_status") == "valid"
        and cadence.get("available") is True
        and cadence.get("admission") is True
    )
    check = {
        "id": "RELEASE_CADENCE_ADMISSION",
        "passed": admitted,
        "evidence": cadence.get("reason", "release cadence unavailable"),
    }
    if admitted:
        return True, check, None
    detail = str(cadence.get("reason", "release cadence unavailable"))
    if cadence.get("next_eligible_at"):
        detail += f" Next eligible at {cadence['next_eligible_at']}."
    return False, check, {"code": "E_RELEASE_CADENCE_BLOCKED", "detail": detail}


def _contract_preflight(
    workspace: Path, path: Path
) -> tuple[
    dict[str, Any] | None, dict[str, Any], dict[str, Any], dict[str, str] | None
]:
    """Parse the contract and verify its declared stages against local proof."""
    value: dict[str, Any] | None = None
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(value, dict):
            raise ValueError("release contract must be an object")
        required = (
            set(value.get("required_stages", []))
            if isinstance(value.get("required_stages"), list)
            else set()
        )
        result = verify_release_contract(
            workspace, str(value.get("feature")), path, required
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        result = {
            "ok": False,
            "marker": "RELEASE_CONTRACT_INVALID",
            "reason": str(exc)[:240],
        }
    check = {
        "id": "RELEASE_CONTRACT_VALID",
        "passed": bool(result.get("ok")),
        "evidence": result.get("marker", "RELEASE_CONTRACT_INVALID"),
    }
    blocker = (
        None
        if result.get("ok")
        else {
            "code": str(result.get("marker", "RELEASE_CONTRACT_INVALID")),
            "detail": str(result.get("reason", "release contract is invalid")),
        }
    )
    return value, result, check, blocker


def _source_binding_errors(
    source: dict[str, Any], binding: Any
) -> list[dict[str, str]]:
    """Describe each missing or stale candidate identity field."""
    errors: list[dict[str, str]] = []
    if not source.get("ok"):
        errors.append(
            {
                "code": "RELEASE_CONTRACT_SOURCE_MISMATCH",
                "detail": str(source.get("reason", "source metadata is invalid")),
            }
        )
    elif not isinstance(binding, dict):
        errors.append(
            {
                "code": "RELEASE_CONTRACT_SOURCE_BINDING_MISSING",
                "detail": "contract candidate.source_version and candidate.source_commit are required",
            }
        )
    else:
        for field, detail in (
            (
                "source_version",
                "contract candidate.source_version differs from source version",
            ),
            (
                "source_commit",
                "contract candidate.source_commit differs from current Git commit",
            ),
        ):
            expected = (
                source.get("version")
                if field == "source_version"
                else source.get("commit")
            )
            if binding.get(field) != expected:
                errors.append(
                    {"code": "RELEASE_CONTRACT_SOURCE_MISMATCH", "detail": detail}
                )
    return errors


def _source_binding_preflight(
    source: dict[str, Any], contract_value: dict[str, Any] | None
) -> tuple[dict[str, Any] | None, bool, dict[str, Any], list[dict[str, str]]]:
    """Match contract candidate identity to source version and Git commit."""
    binding = (
        contract_value.get("candidate") if isinstance(contract_value, dict) else None
    )
    errors = _source_binding_errors(source, binding)
    binding_ok = not errors
    check = {
        "id": "RELEASE_CONTRACT_SOURCE_MATCH",
        "passed": binding_ok,
        "evidence": "candidate binding equals source version and commit"
        if binding_ok
        else "candidate binding is missing or stale",
    }
    return binding if isinstance(binding, dict) else None, binding_ok, check, errors


def _expected_artifact_versions(
    source: dict[str, Any], binding: dict[str, Any] | None
) -> tuple[dict[str, str], list[dict[str, str]]]:
    """Resolve declared platform versions and reject contract/source drift."""
    source_version = str(source.get("version", ""))
    source_versions = source.get("platform_versions", {"python": source_version})
    declared = binding.get("artifact_versions") if isinstance(binding, dict) else None
    errors: list[dict[str, str]] = []
    if isinstance(declared, dict):
        for platform, value in declared.items():
            expected = source_versions.get(platform)
            if isinstance(expected, str) and value != expected:
                errors.append(
                    {
                        "code": "RELEASE_CONTRACT_ARTIFACT_BINDING_MISMATCH",
                        "detail": f"contract candidate artifact_versions.{platform} differs from source metadata",
                    }
                )
    else:
        declared = source_versions
    selected = {
        key: value
        for key, value in declared.items()
        if key in {"python", "vscode", "intellij"} and isinstance(value, str)
    }
    return selected, errors


def _artifact_preflight(
    workspace: Path,
    source: dict[str, Any],
    binding: dict[str, Any] | None,
    artifact_dirs: Iterable[Path] | None,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, str]]]:
    """Inventory candidate artifacts against source and declared versions."""
    source_version = str(source.get("version", ""))
    expected, errors = _expected_artifact_versions(source, binding)
    if source_version:
        directories = (
            list(artifact_dirs)
            if artifact_dirs is not None
            else list(DEFAULT_ARTIFACT_DIRS)
        )
        artifacts = _scan_artifacts(workspace, expected, directories)
    else:
        artifacts = {
            "directories": [],
            "artifacts": [],
            "blockers": [
                {
                    "code": "E_RELEASE_ARTIFACT_VERSION_MISMATCH",
                    "detail": "source version unavailable",
                }
            ],
            "versions_match": False,
        }
    check = {
        "id": "RELEASE_ARTIFACT_VERSIONS_MATCH",
        "passed": artifacts["versions_match"],
        "evidence": f"{len(artifacts['artifacts'])} candidate artifact(s) match source {source_version}"
        if artifacts["versions_match"]
        else "candidate artifact inventory contains a stale or unreadable version",
    }
    return artifacts, check, errors + artifacts["blockers"]


def _metadata_preflight(
    workspace: Path, paths: Iterable[Path] | None
) -> tuple[dict[str, Any], bool, bool, dict[str, Any], list[dict[str, str]]]:
    """Keep active metadata integrity and lineage drift in one bounded lane."""
    metadata: dict[str, Any] = {
        "scope": "active",
        "status": "NOT_REQUESTED",
        "findings": [],
        "files": [],
    }
    if paths is not None:
        from .codex_metadata import audit_metadata

        metadata = audit_metadata(
            workspace, [Path(item) for item in paths], scope="active"
        )
    findings = metadata.get("findings", [])
    blockers = (
        [
            {
                "code": finding.get("code", "E_METADATA_INTEGRITY"),
                "detail": f"{finding.get('path', '<metadata>')} {finding.get('location', '')}: {finding.get('detail', '')}".strip(),
            }
            for finding in findings
        ]
        if paths is not None
        else []
    )
    lineage_valid = not any(
        item.get("code") == "E_METADATA_STATE_RECEIPT_MISMATCH" for item in findings
    )
    ledger_drift = any(
        item.get("code")
        in {"E_METADATA_LEDGER_ORDER", "E_METADATA_LEDGER_HEAD_MISMATCH"}
        for item in findings
    )
    metadata_ok = not findings
    check = {
        "id": "CODEX_METADATA_INTEGRITY_ACTIVE",
        "passed": metadata_ok or paths is None,
        "evidence": "active metadata audit passed"
        if metadata_ok
        else (
            "active metadata audit not requested"
            if paths is None
            else "active metadata contains blocking findings"
        ),
    }
    return metadata, lineage_valid, ledger_drift, check, blockers


def _supply_chain_preflight(
    workspace: Path, manifest: Path | None
) -> tuple[dict[str, Any], dict[str, Any] | None, list[dict[str, str]]]:
    """Verify optional supply-chain evidence without granting release authority."""
    if manifest is None:
        return {"status": "NOT_REQUESTED"}, None, []
    from .supply_chain import evaluate_supply_chain

    try:
        path = _inside(workspace, Path(manifest), "supply-chain manifest")
        value = json.loads(path.read_text(encoding="utf-8"))
        result = evaluate_supply_chain(workspace, value)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        result = {
            "schema": "factory.supply-chain-receipt.v1",
            "decision": "BLOCKED",
            "blockers": [{"code": "E_SUPPLY_CHAIN_INPUT", "detail": str(exc)[:240]}],
            "authority": "none",
            "release_approval": False,
        }
    passed = result.get("decision") == "PASS"
    check = {
        "id": "SUPPLY_CHAIN_INTEGRITY",
        "passed": passed,
        "evidence": "source, lockfiles, SBOM, VEX, licences, reproducible builds and artifact scan passed"
        if passed
        else "supply-chain evidence is blocked",
    }
    return result, check, result.get("blockers", [])


def _intake_preflight(
    workspace: Path, parameters: Path | None, required: bool
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, str]]]:
    """Keep authoritative intake binding distinct from optional release inputs."""
    result: dict[str, Any] = {"status": "NOT_REQUESTED"}
    blockers: list[dict[str, str]] = []
    if parameters is None:
        if required:
            result = {
                "status": "BLOCKED",
                "errors": [
                    {
                        "code": "E_INTAKE_BINDING_REQUIRED",
                        "detail": "strict release preflight requires an authoritative intake-parameter envelope",
                    }
                ],
            }
            blockers.extend(result["errors"])
    else:
        try:
            result = verify_intake_binding(workspace, Path(parameters))
        except (OSError, TypeError, ValueError) as exc:
            result = {
                "status": "BLOCKED",
                "ok": False,
                "errors": [
                    {"code": "E_INTAKE_BINDING_INVALID", "detail": str(exc)[:240]}
                ],
            }
        if not result.get("ok"):
            blockers.extend(
                result.get(
                    "errors",
                    [
                        {
                            "code": "E_INTAKE_PARAMETER_DRIFT",
                            "detail": "intake binding failed",
                        }
                    ],
                )
            )
    check = {
        "id": "INTAKE_PARAMETERS_AUTHORITATIVE",
        "passed": (parameters is None and not required) or bool(result.get("ok")),
        "evidence": "authoritative intake binding verified"
        if result.get("ok")
        else (
            "not requested"
            if parameters is None and not required
            else "intake binding is blocked"
        ),
    }
    return result, check, blockers


def _invalid_contract_receipt(
    contract: Path,
    artifact_dirs: Iterable[Path] | None,
    source: dict[str, Any],
    cadence: dict[str, Any],
    health: dict[str, Any],
    architecture_blocker: dict[str, str] | None,
    error: ValueError,
) -> dict[str, Any]:
    """Preserve the blocked receipt even when the contract path is unsafe."""
    admitted = health.get("decision") == "HEALTHY"
    body = {
        "schema": SCHEMA,
        "marker": "RELEASE_CANDIDATE_PREFLIGHT_BLOCKED",
        "ok": False,
        "source": source,
        "contract": {
            "path": str(contract),
            "feature": None,
            "marker": "RELEASE_CONTRACT_INVALID",
        },
        "artifacts": {
            "directories": [
                Path(item).as_posix()
                for item in (artifact_dirs or DEFAULT_ARTIFACT_DIRS)
            ],
            "artifacts": [],
            "blockers": [],
        },
        "metadata": {
            "scope": "active",
            "status": "NOT_REQUESTED",
            "findings": [],
            "files": [],
        },
        "supply_chain": {"status": "NOT_REQUESTED"},
        "release_cadence": cadence,
        "architecture_health": health,
        "facts": {
            "contract_valid": False,
            "artifact_versions_match": False,
            "metadata_lineage_valid": True,
            "ledger_drift": False,
            "windows_binding_proven": True,
            "supply_chain_verified": None,
            "intake_binding_verified": False,
            "release_cadence_admissible": False,
            "architecture_health_admissible": admitted,
        },
        "checks": [
            {"id": "RELEASE_CONTRACT_VALID", "passed": False, "evidence": str(error)},
            {
                "id": "STRICT_ARCHITECTURE_HEALTH",
                "passed": admitted,
                "evidence": health.get("decision", "BLOCKED"),
            },
            {
                "id": "RELEASE_CADENCE_ADMISSION",
                "passed": False,
                "evidence": cadence.get("reason", "cadence unavailable"),
            },
        ],
        "blockers": [
            {"code": "RELEASE_CONTRACT_INVALID", "detail": str(error)},
            *([architecture_blocker] if architecture_blocker else []),
            {
                "code": "E_RELEASE_CADENCE_BLOCKED",
                "detail": cadence.get("reason", "release cadence unavailable"),
            },
        ],
        "next_action": "repair_release_candidate",
        "authority": dict(AUTHORITY),
        "claim_boundary": "Read-only local candidate identity and artifact-version proof; no execution, credentials, signing, provider call, publication, deployment, approval, or merge authority.",
    }
    body["receipt_sha256"] = _sha(body)
    return body


def _final_preflight_receipt(
    workspace: Path,
    evidence: dict[str, Any],
    flags: dict[str, Any],
    checks: list[dict[str, Any]],
    blockers: list[dict[str, str]],
) -> dict[str, Any]:
    """Seal the evaluated lanes into one non-authorizing candidate receipt."""
    source = evidence["source"]
    contract_result = evidence["contract_result"]
    artifacts = evidence["artifacts"]
    supply_chain = evidence["supply_chain"]
    intake_result = evidence["intake_result"]
    facts = {
        "contract_valid": bool(contract_result.get("ok")),
        "artifact_versions_match": bool(artifacts["versions_match"]),
        "metadata_lineage_valid": flags["metadata_lineage_valid"],
        "ledger_drift": flags["ledger_drift"],
        "windows_binding_proven": True,
        "supply_chain_verified": None
        if not flags["supply_chain_requested"]
        else supply_chain.get("decision") == "PASS",
        "intake_binding_verified": None
        if not flags["intake_requested"]
        else bool(intake_result.get("ok")),
        "release_cadence_admissible": flags["cadence_admitted"],
        "architecture_health_admissible": flags["architecture_admitted"],
    }
    ok = bool(source.get("ok")) and flags["binding_ok"] and not blockers
    contract_value = evidence["contract_value"]
    body: dict[str, Any] = {
        "schema": SCHEMA,
        "marker": "RELEASE_CANDIDATE_PREFLIGHT_PASS"
        if ok
        else "RELEASE_CANDIDATE_PREFLIGHT_BLOCKED",
        "ok": ok,
        "source": source,
        "contract": {
            "path": evidence["contract_path"].relative_to(workspace).as_posix(),
            "feature": contract_value.get("feature") if contract_value else None,
            "marker": contract_result.get("marker"),
            "policy_digest": contract_result.get("policy_digest"),
        },
        "artifacts": artifacts,
        "metadata": evidence["metadata"],
        "supply_chain": supply_chain,
        "release_cadence": evidence["release_cadence"],
        "architecture_health": evidence["architecture_health"],
        "intake_parameters": intake_result,
        "facts": facts,
        "checks": checks,
        "blockers": blockers,
        "next_action": "review_external_publish_gates"
        if ok
        else "repair_release_candidate",
        "authority": dict(AUTHORITY),
        "claim_boundary": "Read-only local candidate identity and artifact-version proof; no execution, credentials, signing, provider call, publication, deployment, approval, or merge authority.",
    }
    body["receipt_sha256"] = _sha(body)
    return body


def release_candidate_preflight(
    root: Path,
    contract: Path,
    artifact_dirs: Iterable[Path] | None = None,
    metadata_paths: Iterable[Path] | None = None,
    *,
    supply_chain_manifest: Path | None = None,
    intake_parameters: Path | None = None,
    require_intake: bool = False,
    candidate_tag: str | None = None,
) -> dict[str, Any]:
    """Evaluate contract/source/artifact identity without external authority."""
    workspace = Path(root).resolve()
    source = source_snapshot(workspace)
    if candidate_tag is not None and candidate_tag != f"v{source.get('version')}":
        raise ValueError("candidate tag must match the source package version")
    release_cadence = (
        release_cadence_status(workspace, candidate_tag=candidate_tag)
        if candidate_tag is not None
        else release_cadence_status(workspace)
    )
    architecture_health, architecture_check, architecture_blocker = (
        _architecture_preflight(workspace)
    )
    architecture_admitted = architecture_check["passed"]
    checks: list[dict[str, Any]] = [architecture_check]
    blockers: list[dict[str, str]] = (
        [architecture_blocker] if architecture_blocker else []
    )
    try:
        contract_path = _inside(workspace, Path(contract), "release contract")
    except ValueError as exc:
        return _invalid_contract_receipt(
            Path(contract),
            artifact_dirs,
            source,
            release_cadence,
            architecture_health,
            architecture_blocker,
            exc,
        )
    cadence_admitted, cadence_check, cadence_blocker = _cadence_preflight(
        release_cadence
    )
    checks.append(cadence_check)
    if cadence_blocker:
        blockers.append(cadence_blocker)
    contract_value, contract_result, contract_check, contract_blocker = (
        _contract_preflight(workspace, contract_path)
    )
    checks.append(contract_check)
    if contract_blocker:
        blockers.append(contract_blocker)

    binding, binding_ok, binding_check, binding_blockers = _source_binding_preflight(
        source, contract_value
    )
    checks.append(binding_check)
    blockers.extend(binding_blockers)

    artifacts, artifact_check, artifact_blockers = _artifact_preflight(
        workspace, source, binding, artifact_dirs
    )
    checks.append(artifact_check)
    blockers.extend(artifact_blockers)

    (
        metadata,
        metadata_lineage_valid,
        ledger_drift,
        metadata_check,
        metadata_blockers,
    ) = _metadata_preflight(workspace, metadata_paths)
    checks.append(metadata_check)
    blockers.extend(metadata_blockers)
    supply_chain, supply_check, supply_blockers = _supply_chain_preflight(
        workspace, supply_chain_manifest
    )
    if supply_check:
        checks.append(supply_check)
    blockers.extend(supply_blockers)
    intake_result, intake_check, intake_blockers = _intake_preflight(
        workspace, intake_parameters, require_intake
    )
    checks.append(intake_check)
    blockers.extend(intake_blockers)
    evidence = {
        "source": source,
        "contract_path": contract_path,
        "contract_value": contract_value,
        "contract_result": contract_result,
        "artifacts": artifacts,
        "metadata": metadata,
        "supply_chain": supply_chain,
        "release_cadence": release_cadence,
        "architecture_health": architecture_health,
        "intake_result": intake_result,
    }
    flags = {
        "metadata_lineage_valid": metadata_lineage_valid,
        "ledger_drift": ledger_drift,
        "supply_chain_requested": supply_chain_manifest is not None,
        "intake_requested": intake_parameters is not None or require_intake,
        "cadence_admitted": cadence_admitted,
        "architecture_admitted": architecture_admitted,
        "binding_ok": binding_ok,
    }
    return _final_preflight_receipt(workspace, evidence, flags, checks, blockers)


def write_release_candidate_preflight(
    root: Path,
    contract: Path,
    artifact_dirs: Iterable[Path] | None,
    out: Path,
    *,
    metadata_paths: Iterable[Path] | None = None,
    supply_chain_manifest: Path | None = None,
    intake_parameters: Path | None = None,
    require_intake: bool = False,
    candidate_tag: str | None = None,
) -> dict[str, Any]:
    """Write a candidate receipt atomically after running the pure preflight."""
    workspace = Path(root).resolve()
    result = release_candidate_preflight(
        workspace,
        contract,
        artifact_dirs,
        metadata_paths=metadata_paths,
        supply_chain_manifest=supply_chain_manifest,
        intake_parameters=intake_parameters,
        require_intake=require_intake,
        candidate_tag=candidate_tag,
    )
    destination = _inside(workspace, Path(out), "release preflight output")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        **result,
        "marker": "RELEASE_CANDIDATE_PREFLIGHT_WRITTEN",
        "path": destination.relative_to(workspace).as_posix(),
    }
    payload["receipt_sha256"] = _sha(
        {key: value for key, value in payload.items() if key != "receipt_sha256"}
    )
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    try:
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(destination)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return payload


__all__ = [
    "SCHEMA",
    "source_snapshot",
    "release_candidate_preflight",
    "write_release_candidate_preflight",
]
