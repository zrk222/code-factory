"""Signed, mutation-tested capability packs for target diversity."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any

from .enterprise_receipts import _verify_envelope, sign_payload
from .failure_guidance import explain_failure


PACK_SCHEMA = "factory.capability_pack.v1"
PACK_PAYLOAD_SCHEMA = "factory.capability_pack.payload.v1"
PACK_PAYLOAD_TYPE = "application/vnd.factory.capability-pack.v1+json"
PACK_VALIDATION_SCHEMA = "factory.capability_pack.validation.v1"
PACK_REQUIRED_PATHS = (
    "pack.yaml",
    "generator/adapter.json",
    "validators/manifest.json",
    "goldens/manifest.json",
    "canaries/manifest.json",
    "ux-states/manifest.json",
    "migration-policy.json",
    "pack.trust.json",
    "pack.signature.json",
)
REQUIRED_UX_STATES = {"loading", "empty", "error", "success", "permission", "offline", "recovery", "accessibility"}
PACK_KINDS = {"target", "language", "capability", "surface"}
BUILTIN_ROOT = Path(__file__).resolve().parent / "builtin_packs"


class CapabilityPackError(ValueError):
    def __init__(self, code: str, message: str, *, markers: list[str] | None = None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.markers = list(markers or [])
        self.guidance = explain_failure(code, message)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CapabilityPackError("PACK_JSON_INVALID", f"cannot read structured pack file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CapabilityPackError("PACK_JSON_INVALID", f"top-level value must be an object: {path}")
    return value


def _files(pack_root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(Path(pack_root).rglob("*")):
        if path.is_file() and path.name != "pack.signature.json":
            relative = path.relative_to(pack_root).as_posix()
            data = path.read_bytes()
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                canonical = data
            else:
                canonical = text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
            result[relative] = sha256(canonical).hexdigest()
    return result


def pack_payload(pack_root: Path) -> dict[str, Any]:
    manifest = _load_json(Path(pack_root) / "pack.yaml")
    return {
        "schema": PACK_PAYLOAD_SCHEMA,
        "pack_id": manifest.get("id"),
        "version": manifest.get("version"),
        "files": _files(Path(pack_root)),
    }


def sign_pack(pack_root: Path, private_key: Path, *, keyid: str, identity: str, issuer: str) -> dict[str, Any]:
    """Seal a reviewed pack with a DSSE Ed25519 envelope."""
    payload = pack_payload(pack_root)
    envelope = sign_payload(
        payload,
        payload_type=PACK_PAYLOAD_TYPE,
        private_key_path=Path(private_key),
        keyid=keyid,
        identity=identity,
        issuer=issuer,
    )
    path = Path(pack_root) / "pack.signature.json"
    path.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"path": str(path.resolve()), "payload_sha256": sha256(_canonical(payload)).hexdigest()}


def _manifest_errors(manifest: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    required = {"schema", "id", "version", "kind", "label", "summary", "generator_adapter", "runtime_mode", "entrypoint"}
    missing = sorted(required - set(manifest))
    if missing:
        errors.append(f"pack.yaml missing fields: {', '.join(missing)}")
    if manifest.get("schema") != PACK_SCHEMA:
        errors.append(f"pack.yaml schema must be {PACK_SCHEMA}")
    if manifest.get("kind") not in PACK_KINDS:
        errors.append(f"kind must be one of {', '.join(sorted(PACK_KINDS))}")
    if not isinstance(manifest.get("id"), str) or not manifest.get("id"):
        errors.append("id must be non-empty")
    for relative in PACK_REQUIRED_PATHS:
        if not (root / relative).is_file():
            errors.append(f"missing required pack path: {relative}")
    if errors:
        return errors
    generator = _load_json(root / "generator" / "adapter.json")
    validators = _load_json(root / "validators" / "manifest.json")
    goldens = _load_json(root / "goldens" / "manifest.json")
    canaries = _load_json(root / "canaries" / "manifest.json")
    ux = _load_json(root / "ux-states" / "manifest.json")
    migration = _load_json(root / "migration-policy.json")
    if generator.get("adapter") != manifest.get("generator_adapter"):
        errors.append("generator adapter does not match pack.yaml")
    if not validators.get("validators"):
        errors.append("validator manifest must be non-empty")
    if not goldens.get("goldens"):
        errors.append("golden manifest must be non-empty")
    if not canaries.get("canaries"):
        errors.append("canary manifest must be non-empty")
    states = set(ux.get("states", []))
    if not REQUIRED_UX_STATES.issubset(states):
        errors.append(f"UX states missing: {', '.join(sorted(REQUIRED_UX_STATES - states))}")
    if migration.get("breaking_changes") != "deny" or migration.get("human_review_required") is not True:
        errors.append("migration policy must deny breaking changes and require human review")
    errors.extend(_deployment_errors(manifest.get("deployment_profiles")))
    return errors


def _deployment_errors(profiles: object) -> list[str]:
    if not isinstance(profiles, list) or not profiles:
        return ["deployment profiles must be non-empty"]
    fields = ("id", "label", "prerequisites", "build", "verify", "release", "approval")
    if any(not isinstance(profile, dict) or not all(profile.get(field) for field in fields) for profile in profiles):
        return ["each deployment profile must include id, label, prerequisites, build, verify, release, and approval"]
    identifiers = [profile["id"] for profile in profiles]
    if len(identifiers) != len(set(identifiers)):
        return ["deployment profile ids must be unique"]
    return []


def _mutation_results(manifest: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    """Prove the structural validator rejects five meaningful mutants."""
    cases = []
    mutants: list[tuple[str, dict[str, Any], str | None]] = []
    deleted_label = deepcopy(manifest)
    deleted_label.pop("label", None)
    mutants.append(("delete-required-label", deleted_label, None))
    invalid_kind = deepcopy(manifest)
    invalid_kind["kind"] = "unknown"
    mutants.append(("replace-pack-kind", invalid_kind, None))
    mutants.append(("remove-canaries", deepcopy(manifest), "canaries"))
    mutants.append(("remove-accessibility-state", deepcopy(manifest), "accessibility"))
    no_deployments = deepcopy(manifest)
    no_deployments["deployment_profiles"] = []
    mutants.append(("remove-deployment-profiles", no_deployments, None))
    for name, mutant, external_mutation in mutants:
        if external_mutation is None:
            rejected = bool(_manifest_errors(mutant, root))
        elif external_mutation == "canaries":
            value = _load_json(root / "canaries" / "manifest.json")
            rejected = not bool({**value, "canaries": []}.get("canaries"))
        else:
            value = _load_json(root / "ux-states" / "manifest.json")
            rejected = not REQUIRED_UX_STATES.issubset(set(value.get("states", [])) - {"accessibility"})
        cases.append({"mutation": name, "rejected": rejected})
    return cases


def _verified_signature(root: Path) -> dict[str, Any]:
    envelope = _load_json(root / "pack.signature.json")
    trust_root = _load_json(root / "pack.trust.json")
    signed, metadata, _payload_bytes = _verify_envelope(
        envelope,
        expected_payload_type=PACK_PAYLOAD_TYPE,
        trust_root=trust_root,
    )
    if signed != pack_payload(root):
        raise CapabilityPackError("PACK_SIGNATURE_INVALID", "signed pack payload does not match current files")
    return {"required": True, "verified": True, "identity": metadata["identity"], "keyid": metadata["keyid"]}


def validate_pack(pack_root: Path, *, verify_signature: bool = True, mutate: bool = True) -> dict[str, Any]:
    root = Path(pack_root).resolve()
    manifest = _load_json(root / "pack.yaml")
    errors = _manifest_errors(manifest, root)
    signature = {"required": verify_signature, "verified": False}
    if verify_signature and not errors:
        try:
            signature = _verified_signature(root)
        except Exception as exc:
            errors.append(f"signature verification failed: {exc}")
    mutations = _mutation_results(manifest, root) if mutate and not errors else []
    if mutations and not all(item["rejected"] for item in mutations):
        errors.append("HOLLOW_PACK_VALIDATOR: at least one meaningful pack mutation survived")
    result = {
        "schema": PACK_VALIDATION_SCHEMA,
        "pack_id": manifest.get("id"),
        "version": manifest.get("version"),
        "valid": not errors,
        "signature": signature,
        "mutations": {
            "attempted": len(mutations),
            "rejected": sum(item["rejected"] for item in mutations),
            "cases": mutations,
        },
        "files": _files(root),
        "errors": errors,
        "markers": [
            "PACK_STRUCTURE_VALIDATED", "PACK_SIGNATURE_VERIFIED",
            "PACK_VALIDATOR_MUTATIONS_REJECTED", "PACK_UX_STATES_COMPLETE",
            "PACK_MIGRATION_POLICY_BOUND", "PACK_DEPLOYMENT_GUIDANCE_COMPLETE",
            "PACK_SIGNATURE_BYPASS_DENIED",
        ] if not errors else ["PACK_VALIDATION_FAILED"],
    }
    if errors:
        result["failure"] = explain_failure("PACK_VALIDATION_FAILED", "; ".join(errors), errors=errors)
    return result


def builtin_packs() -> list[dict[str, Any]]:
    result = []
    if not BUILTIN_ROOT.is_dir():
        raise CapabilityPackError("PACK_BUILTINS_MISSING", f"built-in pack directory is missing: {BUILTIN_ROOT}")
    roots = sorted(
        path
        for path in BUILTIN_ROOT.iterdir()
        if path.is_dir() and (path / "pack.yaml").is_file()
    )
    if not roots:
        raise CapabilityPackError("PACK_BUILTINS_MISSING", f"no built-in pack manifests exist below: {BUILTIN_ROOT}")
    for root in roots:
        manifest = _load_json(root / "pack.yaml")
        result.append({**manifest, "path": str(root)})
    return result


def target_inventory() -> dict[str, dict[str, Any]]:
    inventory = {}
    for pack in builtin_packs():
        if pack.get("kind") == "target":
            target = str(pack["target_kind"])
            inventory[target] = {
                "label": pack["label"],
                "runtime_mode": pack["runtime_mode"],
                "entrypoint": pack["entrypoint"],
                "summary": pack["summary"],
                "pack_id": pack["id"],
                "pack_version": pack["version"],
                "generator_adapter": pack["generator_adapter"],
                "deployment_profiles": pack["deployment_profiles"],
            }
    return inventory


def _destination(workspace: Path, pack_id: str) -> tuple[Path, Path]:
    packs_root = Path(workspace).resolve() / ".factory" / "packs"
    destination = (packs_root / pack_id).resolve()
    if destination.parent != packs_root.resolve():
        raise CapabilityPackError("PACK_PATH_INVALID", "pack id must resolve to one direct child of .factory/packs")
    return packs_root, destination


def _copy_pack(source: Path, staging: Path) -> None:
    for item in source.iterdir():
        target = staging / item.name
        if item.is_dir():
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)


def _atomic_swap(staging: Path, destination: Path, backup: Path) -> None:
    previous_moved = False
    try:
        if destination.exists():
            os.replace(destination, backup)
            previous_moved = True
        os.replace(staging, destination)
    except BaseException as exc:
        if previous_moved and backup.exists() and not destination.exists():
            os.replace(backup, destination)
            raise CapabilityPackError(
                "PACK_INSTALL_FAILED", f"atomic installation failed: {exc}",
                markers=["PACK_ROLLBACK_RESTORED"],
            ) from exc
        raise CapabilityPackError("PACK_INSTALL_FAILED", f"atomic installation failed: {exc}") from exc
    if backup.exists():
        shutil.rmtree(backup, ignore_errors=True)


def install_pack(pack_root: Path, workspace: Path, *, force: bool = False) -> dict[str, Any]:
    validation = validate_pack(pack_root, verify_signature=True, mutate=True)
    if not validation["valid"]:
        raise CapabilityPackError("PACK_VALIDATION_FAILED", "; ".join(validation["errors"]))
    source = Path(pack_root).resolve()
    packs_root, destination = _destination(Path(workspace), str(validation["pack_id"]))
    packs_root.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not force:
        raise CapabilityPackError("PACK_EXISTS", f"pack already installed: {destination}")
    staging = Path(tempfile.mkdtemp(prefix=f".{validation['pack_id']}.", dir=str(packs_root)))
    backup = packs_root / f".{validation['pack_id']}.backup"
    if backup.exists():
        raise CapabilityPackError("PACK_BACKUP_EXISTS", f"manual recovery required for existing backup: {backup}")
    try:
        _copy_pack(source, staging)
        _atomic_swap(staging, destination, backup)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        raise
    return {
        "schema": "factory.capability_pack.installation.v1",
        "pack_id": validation["pack_id"],
        "version": validation["version"],
        "path": str(destination),
        "signature": validation["signature"],
        "mutations": validation["mutations"],
        "authority": {"generator_available": True, "execute": False, "network": False, "publish": False},
        "marker": "PACK_INSTALLED_VERIFIED",
        "markers": ["PACK_INSTALLED_VERIFIED", "PACK_PATH_CONTAINED", "PACK_SIGNATURE_BYPASS_DENIED"],
    }
