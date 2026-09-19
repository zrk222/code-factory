"""Cross-artifact candidate continuity checks for graph and audit evidence.

The verifier proves that a current Oracle contract, deep-audit receipt, and
graph lineage receipt all describe one candidate digest.  It never executes a
graph, analyzer, repair, approval, or release action.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .deep_audit import _read_receipt
from .graph_forensics import verify_graph_lineage
from .oracle_firewall import verify_oracle_contract


SCHEMA = "factory.candidate-lineage-input.v1"
RESULT_SCHEMA = "factory.candidate-lineage-verification.v1"
MAX_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE = 8
_SHA = re.compile(r"^[0-9a-f]{64}$")
_KINDS = {"deep_audit", "graph_lineage"}
_AUTHORITY = {
    "execution": False,
    "checkpoint_mutation": False,
    "approval": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


class CandidateLineageError(ValueError):
    """Stable, fail-closed continuity error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise CandidateLineageError(
            "E_CANDIDATE_LINEAGE_SCHEMA", f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def _text(value: object, field: str, maximum: int = 160) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise CandidateLineageError(
            "E_CANDIDATE_LINEAGE_SCHEMA",
            f"{field} must be non-empty and at most {maximum} characters",
        )
    return value.strip()


def _path(root: Path, value: object, field: str) -> tuple[Path, str]:
    if isinstance(value, Path):
        candidate = value
        raw = candidate if candidate.is_absolute() else root / candidate
        if raw.is_symlink():
            raise CandidateLineageError(
                "E_CANDIDATE_LINEAGE_PATH", f"{field}.path must be a regular file"
            )
        resolved = raw.resolve()
        try:
            relative = resolved.relative_to(root).as_posix()
        except ValueError as exc:
            raise CandidateLineageError(
                "E_CANDIDATE_LINEAGE_PATH", f"{field}.path escapes the workspace"
            ) from exc
    else:
        relative = _text(value, f"{field}.path", 512).replace("\\", "/")
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise CandidateLineageError(
                "E_CANDIDATE_LINEAGE_PATH",
                f"{field}.path must stay inside the workspace",
            )
        raw = root / candidate
        if raw.is_symlink():
            raise CandidateLineageError(
                "E_CANDIDATE_LINEAGE_PATH", f"{field}.path must be a regular file"
            )
        resolved = raw.resolve()
    try:
        normalized = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise CandidateLineageError(
            "E_CANDIDATE_LINEAGE_PATH", f"{field}.path escapes the workspace"
        ) from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise CandidateLineageError(
            "E_CANDIDATE_LINEAGE_PATH", f"{field}.path must be a regular file"
        )
    try:
        if resolved.stat().st_size > MAX_BYTES:
            raise CandidateLineageError(
                "E_CANDIDATE_LINEAGE_BOUNDS", f"{field}.path exceeds the 2 MiB bound"
            )
    except OSError as exc:
        raise CandidateLineageError(
            "E_CANDIDATE_LINEAGE_PATH", f"{field}.path is unreadable"
        ) from exc
    return resolved, normalized


def _load_manifest(root: Path, source: Path) -> tuple[dict[str, Any], str]:
    path, relative = _path(root, source, "manifest")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateLineageError(
            "E_CANDIDATE_LINEAGE_SCHEMA", "manifest must be UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise CandidateLineageError(
            "E_CANDIDATE_LINEAGE_SCHEMA", "manifest must be one JSON object"
        )
    return value, relative


def _oracle(root: Path, value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"path", "contract_sha256"}:
        raise CandidateLineageError(
            "E_CANDIDATE_LINEAGE_ORACLE",
            "oracle_contract must contain path and contract_sha256",
        )
    _, relative = _path(root, value["path"], "oracle_contract")
    expected = _sha(value["contract_sha256"], "oracle_contract.contract_sha256")
    checked = verify_oracle_contract(root, Path(relative))
    if (
        not checked.get("ok")
        or checked.get("contract", {}).get("contract_sha256") != expected
    ):
        raise CandidateLineageError(
            "E_CANDIDATE_LINEAGE_ORACLE",
            "oracle contract is invalid, stale, or not the declared digest",
        )
    return {"path": checked["path"], "contract_sha256": expected}


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateLineageError(
            "E_CANDIDATE_LINEAGE_EVIDENCE", "evidence must be readable UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise CandidateLineageError(
            "E_CANDIDATE_LINEAGE_EVIDENCE", "evidence must be a JSON object"
        )
    return value


def _evidence(root: Path, rows: object, candidate: str) -> list[dict[str, str]]:
    if not isinstance(rows, list) or not 2 <= len(rows) <= MAX_EVIDENCE:
        raise CandidateLineageError(
            "E_CANDIDATE_LINEAGE_EVIDENCE", "evidence must contain 2 through 8 rows"
        )
    normalized: list[dict[str, str]] = []
    ids: set[str] = set()
    paths: set[str] = set()
    kinds: set[str] = set()
    for index, raw in enumerate(rows):
        if not isinstance(raw, dict) or set(raw) != {"id", "kind", "path", "sha256"}:
            raise CandidateLineageError(
                "E_CANDIDATE_LINEAGE_SCHEMA",
                f"evidence[{index}] has unsupported or missing fields",
            )
        identifier = _text(raw["id"], f"evidence[{index}].id")
        kind = _text(raw["kind"], f"evidence[{index}].kind", 40)
        if kind not in _KINDS:
            raise CandidateLineageError(
                "E_CANDIDATE_LINEAGE_SCHEMA", f"evidence[{index}].kind is unsupported"
            )
        path, relative = _path(root, raw["path"], f"evidence[{index}]")
        expected_file_sha = _sha(raw["sha256"], f"evidence[{index}].sha256")
        if _sha_file(path) != expected_file_sha:
            raise CandidateLineageError(
                "E_CANDIDATE_LINEAGE_EVIDENCE",
                f"evidence[{index}] file digest is stale",
            )
        value = _json(path)
        if kind == "deep_audit":
            try:
                receipt, receipt_sha, _ = _read_receipt(root, path)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                raise CandidateLineageError(
                    "E_CANDIDATE_LINEAGE_EVIDENCE",
                    "deep-audit evidence is not self-hash valid",
                ) from exc
            if receipt.get(
                "schema"
            ) != "factory.deep-audit-receipt.v1" or receipt_sha != value.get(
                "receipt_sha256"
            ):
                raise CandidateLineageError(
                    "E_CANDIDATE_LINEAGE_EVIDENCE",
                    "deep-audit evidence has an invalid receipt seal",
                )
            value = receipt
        elif kind == "graph_lineage":
            checked = verify_graph_lineage(path, expected_candidate_sha256=candidate)
            if not checked["valid"]:
                raise CandidateLineageError(
                    "E_CANDIDATE_LINEAGE_GRAPH", "; ".join(checked["errors"][:2])
                )
        declared = value.get("candidate_sha256")
        if not isinstance(declared, str) or not _SHA.fullmatch(declared):
            raise CandidateLineageError(
                "E_CANDIDATE_LINEAGE_UNBOUND",
                f"evidence[{index}] does not declare candidate_sha256",
            )
        if declared != candidate:
            raise CandidateLineageError(
                "E_CANDIDATE_LINEAGE_MISMATCH",
                f"evidence[{index}] targets a different candidate",
            )
        if identifier in ids or relative in paths:
            raise CandidateLineageError(
                "E_CANDIDATE_LINEAGE_SCHEMA",
                "evidence identifiers and paths must be unique",
            )
        ids.add(identifier)
        paths.add(relative)
        kinds.add(kind)
        normalized.append(
            {
                "id": identifier,
                "kind": kind,
                "path": relative,
                "sha256": expected_file_sha,
                "candidate_sha256": declared,
            }
        )
    if kinds != _KINDS:
        raise CandidateLineageError(
            "E_CANDIDATE_LINEAGE_INCOMPLETE",
            "both deep_audit and graph_lineage evidence are required",
        )
    return sorted(normalized, key=lambda item: item["id"])


def verify_candidate_lineage(
    root: Path,
    manifest_path: Path,
    required_kinds: tuple[str, ...] = ("deep_audit", "graph_lineage"),
) -> dict[str, Any]:
    """Verify Oracle, deep-audit, and graph evidence share one candidate digest."""
    workspace = Path(root).resolve()
    try:
        manifest, manifest_relative = _load_manifest(workspace, manifest_path)
        if (
            set(manifest)
            != {
                "schema",
                "id",
                "candidate_sha256",
                "oracle_contract",
                "evidence",
                "authority",
            }
            or manifest.get("schema") != SCHEMA
        ):
            raise CandidateLineageError(
                "E_CANDIDATE_LINEAGE_SCHEMA", f"manifest must use exact {SCHEMA} fields"
            )
        identifier = _text(manifest["id"], "id")
        candidate = _sha(manifest["candidate_sha256"], "candidate_sha256")
        if tuple(required_kinds) != ("deep_audit", "graph_lineage"):
            raise CandidateLineageError(
                "E_CANDIDATE_LINEAGE_SCHEMA",
                "required_kinds is fixed to deep_audit and graph_lineage",
            )
        oracle = _oracle(workspace, manifest["oracle_contract"])
        evidence = _evidence(workspace, manifest["evidence"], candidate)
        if manifest["authority"] != "none":
            raise CandidateLineageError(
                "E_CANDIDATE_LINEAGE_AUTHORITY", "authority must remain none"
            )
        return {
            "schema": RESULT_SCHEMA,
            "marker": "CANDIDATE_LINEAGE_VERIFIED",
            "state": "VERIFIED",
            "id": identifier,
            "candidate_sha256": candidate,
            "oracle_contract": oracle,
            "evidence": evidence,
            "evidence_kinds": sorted({item["kind"] for item in evidence}),
            "manifest_path": manifest_relative,
            "authority": dict(_AUTHORITY),
            "release_approval": False,
            "claim_boundary": "Local candidate continuity only; it does not execute, authenticate external producers, repair, approve, publish, deploy, sign, or prove semantic correctness.",
        }
    except CandidateLineageError:
        raise
    except (OSError, TypeError, ValueError, KeyError) as exc:
        raise CandidateLineageError(
            "E_CANDIDATE_LINEAGE_EVIDENCE", "candidate lineage could not be verified"
        ) from exc
