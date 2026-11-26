"""Fail-closed local readiness decisions over receipt-backed factory stages.

``shippable`` means every required local gate has a current passing receipt. It
does not mean an external provider accepted, deployed, signed, or approved a
release. Incomplete pipelines therefore stay non-shippable.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PureWindowsPath
from typing import Any

from .assembly import rollup_receipts
from .contract import Receipt
from .protocol import ASSEMBLY_STAGE_KEYS, BASE_REQUIRED_MODULES, CONDITIONAL_STAGE_KEYS


LABELS = {
    "specline": "SPEC",
    "forgeline": "FORGE",
    "hsf": "COMPILE",
    "prestige": "DESIGN",
}
BASE_REQUIRED = {
    owner: frozenset(
        stage
        for module, stage in ASSEMBLY_STAGE_KEYS
        if module == owner and (module, stage) not in CONDITIONAL_STAGE_KEYS
    )
    for owner in BASE_REQUIRED_MODULES
}


def _release_declares(root: Path, feature: str, path: Path | None, stage: str) -> bool:
    """Read one declared required stage without treating the file as valid.

    Strict verification subsequently validates the whole Oracle-bound release
    contract.  This early, bounded read only ensures a declared UI/compiler
    gate cannot be silently omitted while that validation is underway.
    """
    source = path or root / ".factory" / "release-contracts" / f"{feature}.json"
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    stages = value.get("required_stages") if isinstance(value, dict) else None
    return isinstance(stages, list) and stage in stages


def _declares_ui(
    root: Path, feature: str, rows: list[dict[str, Any]], declared: set[str]
) -> bool:
    return (
        (root / "smoke" / f"{feature}.ui").is_file()
        or any(row["module"] == "prestige" for row in rows)
        or "prestige:score" in declared
    )


def _declares_hsf(
    root: Path, feature: str, rows: list[dict[str, Any]], declared: set[str]
) -> bool:
    from .assembly import decision_source

    return (
        decision_source(root, feature) is not None
        or any(row["module"] == "hsf" and row["stage"] == "compile" for row in rows)
        or "hsf:compile" in declared
    )


def _declares_harness(root: Path, rows: list[dict[str, Any]], declared: set[str]) -> bool:
    return (root / "harness" / "harness.yaml").is_file() or "hsf:harness-check" in declared


def _declares_evidence(root: Path, feature: str, rows: list[dict[str, Any]], declared: set[str]) -> bool:
    return (
        (root / ".factory" / "workflow-audit-contract.json").is_file()
        or any(row["module"] == "specline" and row["stage"] == "evidence" for row in rows)
        or "specline:evidence" in declared
    )


def _required_stages(
    root: Path,
    feature: str,
    rows: list[dict[str, Any]],
    declared: set[str] | None = None,
) -> dict[str, frozenset[str]]:
    required = dict(BASE_REQUIRED)
    declared = declared or set()
    if _declares_ui(root, feature, rows, declared):
        required["prestige"] = frozenset({"score"})
    if _declares_hsf(root, feature, rows, declared):
        required["hsf"] = frozenset({"compile"})
    if _declares_harness(root, rows, declared):
        required["hsf"] = required.get("hsf", frozenset()) | {"harness-check"}
    if _declares_evidence(root, feature, rows, declared):
        required["specline"] = required["specline"] | {"evidence"}
    return required


def _ship_intent_failure(rows: list[dict[str, Any]]) -> dict[str, str] | None:
    ships = [
        row for row in rows if row["module"] == "forgeline" and row["stage"] == "ship"
    ]
    if not ships:
        return {
            "code": "REQUIRED_STAGE_MISSING",
            "detail": "forgeline:ship receipt is missing",
        }
    outputs = ships[-1].get("outputs")
    if not isinstance(outputs, dict):
        return {
            "code": "INTENT_TRACE_MISSING",
            "detail": "ship receipt outputs are not an object",
        }
    trace = outputs.get("intent_trace")
    if not isinstance(trace, dict):
        return {
            "code": "INTENT_TRACE_MISSING",
            "detail": "ship receipt lacks a bound intent trace",
        }
    if trace.get("intent_traceable") is not True or trace.get("shipped") is not True:
        return {
            "code": "INTENT_TRACE_UNVERIFIED",
            "detail": "ship receipt does not prove traceable intent",
        }
    return None


def _stages_by_module(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by_module = {module: [] for module in LABELS}
    for stage in rows:
        by_module.setdefault(stage["module"], []).append(stage)
    return by_module


def _snapshot_blockers(rollup: dict[str, Any]) -> list[dict[str, str]]:
    snapshot = rollup.get("receipt_snapshot", {})
    blockers = []
    if snapshot.get("truncated"):
        blockers.append(
            {
                "code": "RECEIPT_SNAPSHOT_TRUNCATED",
                "detail": "receipt scan was bounded before the complete evidence set was observed",
            }
        )
    blockers.extend(
        {"code": "RECEIPT_INVALID", "detail": f"{item['path']}: {item['reason']}"}
        for item in snapshot.get("invalid", [])
    )
    return blockers


def _module_result(
    module: str, label: str, rows: list[dict[str, Any]], expected: frozenset[str]
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    failed = [
        row
        for row in rows
        if row["status"] == "failed"
        or (row.get("rate") is not None and row["rate"] < 1.0)
    ]
    passing = {row["stage"] for row in rows if row["status"] == "ok"}
    missing = sorted(expected - passing)
    blockers = _module_blockers(module, failed, missing)
    status = _module_status(failed, missing, expected)
    return {
        "module": module,
        "label": label,
        "required": sorted(expected),
        "missing": missing,
        "status": status,
        "stages": rows,
    }, blockers


def _module_blockers(
    module: str, failed: list[dict[str, Any]], missing: list[str]
) -> list[dict[str, str]]:
    blockers = [
        {
            "code": "REQUIRED_STAGE_MISSING",
            "detail": f"{module}:{stage} receipt is missing or non-passing",
        }
        for stage in missing
    ]
    blockers.extend(
        {"code": "STAGE_FAILED", "detail": f"{module}:{row['stage']} is failing"}
        for row in failed
    )
    return blockers


def _module_status(
    failed: list[dict[str, Any]], missing: list[str], expected: frozenset[str]
) -> str:
    if failed:
        return "failed"
    if missing:
        return "incomplete"
    return "passed" if expected else "not_applicable"


def _module_audit(
    by_module: dict[str, list[dict[str, Any]]], required: dict[str, frozenset[str]]
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    modules, blockers = [], []
    for module, label in LABELS.items():
        result, module_blockers = _module_result(
            module, label, by_module[module], required.get(module, frozenset())
        )
        modules.append(result)
        blockers.extend(module_blockers)
    return modules, blockers


def _stage_contract_binding_blockers(
    module: str,
    stage: str,
    rows: list[dict[str, Any]],
    expected_oracle: Any,
    expected_policy: Any,
) -> list[dict[str, str]]:
    matches = [
        row for row in rows if row.get("stage") == stage and row.get("status") == "ok"
    ][-1:]
    blockers = []
    for row in matches:
        inputs = row.get("inputs")
        if not isinstance(inputs, dict):
            return [
                {
                    "code": "RECEIPT_ORACLE_BINDING_MISSING",
                    "detail": f"{module}:{stage} receipt inputs are not an object",
                }
            ]
        if inputs.get("oracle_contract_sha256") != expected_oracle:
            blockers.append(
                {
                    "code": "RECEIPT_ORACLE_BINDING_MISMATCH",
                    "detail": f"{module}:{stage} is not bound to the current Oracle contract",
                }
            )
        if inputs.get("release_contract_policy_digest") != expected_policy:
            blockers.append(
                {
                    "code": "RECEIPT_POLICY_BINDING_MISMATCH",
                    "detail": f"{module}:{stage} is not bound to the current release policy",
                }
            )
    return blockers


def _contract_binding_blockers(
    required: dict[str, frozenset[str]],
    by_module: dict[str, list[dict[str, Any]]],
    release_contract: dict[str, Any],
) -> list[dict[str, str]]:
    blockers = []
    oracle, policy = (
        release_contract.get("oracle_contract_sha256"),
        release_contract.get("policy_digest"),
    )
    for module, stages in required.items():
        for stage in stages:
            blockers.extend(
                _stage_contract_binding_blockers(
                    module, stage, by_module.get(module, []), oracle, policy
                )
            )
    return blockers


def _strict_release_contract(
    workspace: Path,
    feature: str,
    contract_path: Path,
    declared_stage_ids: set[str],
    required: dict[str, frozenset[str]],
    by_module: dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    from .release_contract import verify_release_contract

    result = verify_release_contract(
        workspace, feature, contract_path, declared_stage_ids
    )
    if not result.get("ok"):
        return result, [
            {
                "code": str(result.get("marker", "RELEASE_CONTRACT_INVALID")),
                "detail": str(result.get("reason", "release contract is not valid")),
            }
        ]
    return result, _contract_binding_blockers(required, by_module, result)


def _next_verify_action(
    workspace: Path,
    feature: str,
    rollup: dict[str, Any],
    blockers: list[dict[str, str]],
) -> str:
    if rollup.get("earliest_failing_stage"):
        return f"factory risk-diff --root {workspace} --changed <changed-path>"
    if blockers:
        return f"factory assemble {feature} --root {workspace}"
    return f"factory trace {feature} --root {workspace}"


def _stage_evidence_audit(by_module, rows, required):
    modules, blockers = _module_audit(by_module, required)
    intent_failure = _ship_intent_failure(rows)
    if intent_failure is not None:
        blockers.append(intent_failure)
    return modules, blockers


def _declared_release_stages(workspace, feature, contract_path, strict_release):
    if not strict_release:
        return set()
    return {
        stage
        for stage in ("prestige:score", "hsf:compile")
        if _release_declares(workspace, feature, contract_path, stage)
    }


def _verify_selected_run(
    workspace, feature, run_id, required, stage_ids, release_contract
):
    """Audit the selected run against its own native gates and contract bindings."""
    sequence = verify_sequence(workspace, feature, run_id, stage_ids)
    if not sequence["ok"]:
        return sequence, sequence["blockers"]

    from .assembly import rollup_attributions

    rows = rollup_attributions(sequence["stages"])["stages"]
    by_module = _stages_by_module(rows)
    _, blockers = _stage_evidence_audit(by_module, rows, required)
    if release_contract.get("ok"):
        blockers.extend(
            _contract_binding_blockers(required, by_module, release_contract)
        )
    return sequence, blockers


def verify_feature(
    root: Path,
    feature: str,
    *,
    strict_release: bool = False,
    release_contract_path: Path | None = None,
    strict_sequence: bool = False,
    sequence_run_id: str | None = None,
) -> dict:
    """Fail closed for absent, failed, malformed, or incomplete gate evidence."""
    strict_sequence = strict_sequence or sequence_run_id is not None
    workspace = Path(root)
    rollup = rollup_receipts(workspace, feature)
    rows = rollup["stages"]
    by_module = _stages_by_module(rows)
    contract_path = (
        release_contract_path
        or workspace / ".factory" / "release-contracts" / f"{feature}.json"
    )
    required = _required_stages(
        workspace,
        feature,
        rows,
        _declared_release_stages(
            workspace,
            feature,
            contract_path,
            strict_release,
        ),
    )
    blockers = _snapshot_blockers(rollup)
    modules, stage_blockers = _stage_evidence_audit(by_module, rows, required)
    blockers.extend(stage_blockers)
    declared_stage_ids = {
        f"{module}:{stage}" for module, stages in required.items() for stage in stages
    }
    release_contract: dict[str, Any] = {"status": "not_requested"}
    if strict_release:
        release_contract, contract_blockers = _strict_release_contract(
            workspace,
            feature,
            contract_path,
            declared_stage_ids,
            required,
            by_module,
        )
        blockers.extend(contract_blockers)
    whole_run = _select_sequence(workspace, feature, declared_stage_ids, rows)
    sequence: dict[str, Any] = {"status": "not_requested", "ok": False}
    if strict_sequence:
        sequence, sequence_blockers = _verify_selected_run(
            workspace,
            feature,
            sequence_run_id or "",
            required,
            declared_stage_ids,
            release_contract,
        )
    else:
        sequence_blockers = whole_run["blockers"]
    blockers.extend(sequence_blockers)
    next_action = _next_verify_action(workspace, feature, rollup, blockers)
    shippable = bool(rows) and not rollup.get("earliest_failing_stage") and not blockers
    return {
        "schema": "factory.verify.v2",
        "feature": feature,
        "root": str(workspace),
        "shippable": shippable,
        "release_ready": shippable
        and (not strict_release or release_contract.get("ok") is True),
        "strict_sequence": strict_sequence,
        "sequence": sequence,
        "whole_run": whole_run,
        "strict_release": strict_release,
        "release_contract": release_contract,
        "modules": modules,
        "rollup": rollup,
        "blockers": blockers,
        "next_action": next_action,
        "scope_limits": [
            "Evaluates stable local receipt evidence only; it does not run missing gates.",
            "A passing local decision is not an external deployment, signing, publication, provider-state readback, or approval.",
            "AppForge is required only when the feature declares a mobile decision spec; Prestige is required only when UI scope is declared.",
        ],
    }


# Whole-run evidence

SEQUENCE_SCHEMA = "factory.run-sequence.v1"
MAX_BYTES = 1_048_576
MAX_STAGES = 512


def _id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value
    ):
        raise ValueError("feature and run IDs must be safe single path components")
    return value


def _feature_component(feature: str) -> str:
    if (
        not isinstance(feature, str)
        or feature in {"", ".", ".."}
        or any(char in '/\\:*?"<>|' or ord(char) < 32 for char in feature)
    ):
        raise ValueError("feature must be a safe name")
    if PureWindowsPath(feature).is_reserved() or feature.endswith((".", " ")):
        return "~" + hashlib.sha256(feature.encode("utf-8")).hexdigest()
    try:
        return _id(feature)
    except ValueError:
        return "~" + hashlib.sha256(feature.encode("utf-8")).hexdigest()


def _directory(root: Path, feature: str, run_id: str) -> Path:
    root = Path(root).resolve()
    path = (
        root / ".factory" / "run-sequences" / _feature_component(feature) / _id(run_id)
    )
    if any(
        parent.is_symlink()
        for parent in (path, *path.parents)
        if parent != root and root in parent.parents
    ):
        raise ValueError("sequence paths cannot contain symlinks")
    if path.resolve() != path:
        raise ValueError("sequence paths cannot contain redirected directories")
    return path


def _hash(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    ).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be an offset-aware ISO string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp needs a UTC offset")
    return parsed


def _read_snapshot(path: Path) -> tuple[dict, str]:
    if path.is_symlink():
        raise ValueError("evidence symlinks are not accepted")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
        raise ValueError("sequence evidence exceeds size limit")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("sequence evidence exceeds size limit")
    after = path.stat()
    if (before.st_ino, before.st_mtime_ns, before.st_size) != (
        after.st_ino,
        after.st_mtime_ns,
        after.st_size,
    ):
        raise ValueError("evidence changed while being read")
    try:
        value = json.loads(raw)
    except RecursionError as error:
        raise ValueError("sequence evidence nesting is too deep") from error
    if not isinstance(value, dict):
        raise ValueError("evidence must be an object")
    return value, hashlib.sha256(raw).hexdigest()


def _read(path: Path) -> dict:
    return _read_snapshot(path)[0]


def _create(path: Path, value: dict) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation: these helpers never rewrite an earlier event.
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return value


def _manifest(root: Path, feature: str, run_id: str) -> tuple[Path, dict]:
    directory = _directory(root, feature, run_id)
    value = _read(directory / "manifest.json")
    if (
        value.get("schema") != SEQUENCE_SCHEMA
        or value.get("feature") != feature
        or value.get("run_id") != run_id
    ):
        raise ValueError("manifest identity/schema mismatch")
    stages = value.get("stages")
    if not isinstance(stages, list) or not 1 <= len(stages) <= MAX_STAGES:
        raise ValueError("manifest requires 1..512 ordered stage IDs")
    if any(
        not isinstance(stage, str) or not re.fullmatch(r"[a-z0-9-]+:[a-z0-9-]+", stage)
        for stage in stages
    ):
        raise ValueError("invalid stage ID")
    _time(value.get("declared_at"))
    return directory, value


def declare_sequence(root: Path, feature: str, run_id: str, stages: list[str]) -> dict:
    """Call before the first stage starts. Never derive a plan from past receipts."""
    directory = _directory(root, feature, run_id)
    if (
        not isinstance(stages, list)
        or not 1 <= len(stages) <= MAX_STAGES
        or any(
            not isinstance(stage, str)
            or not re.fullmatch(r"[a-z0-9-]+:[a-z0-9-]+", stage)
            for stage in stages
        )
    ):
        raise ValueError("stages must contain 1..512 ordered module:stage IDs")
    return _create(
        directory / "manifest.json",
        {
            "schema": SEQUENCE_SCHEMA,
            "feature": feature,
            "run_id": run_id,
            "stages": list(stages),
            "declared_at": _now(),
        },
    )


def sequence_binding(manifest: dict, position: int) -> dict:
    """Include this binding in the native receipt's inputs at execution time."""
    if type(position) is not int or not 1 <= position <= len(manifest["stages"]):
        raise ValueError("position is outside declared sequence")
    return {
        "sequence_run_id": manifest["run_id"],
        "sequence_position": position,
        "sequence_manifest_sha256": _hash(manifest),
    }


def record_intent(root: Path, feature: str, run_id: str, position: int) -> dict:
    """Call immediately before executing the declared stage, not after it."""
    directory, manifest = _manifest(root, feature, run_id)
    binding = sequence_binding(manifest, position)
    return _create(
        directory / f"{position:04d}.intent.json",
        {
            **binding,
            "schema": SEQUENCE_SCHEMA,
            "feature": feature,
            "kind": "intent",
            "stage": manifest["stages"][position - 1],
            "recorded_at": _now(),
        },
    )


def record_outcome(
    root: Path, feature: str, run_id: str, position: int, receipt_path: Path
) -> dict:
    """Call after the native stage receipt has been durably written."""
    directory, manifest = _manifest(root, feature, run_id)
    binding = sequence_binding(manifest, position)
    intent = _read(directory / f"{position:04d}.intent.json")
    receipt_path = Path(receipt_path).resolve()
    receipt_dir = (Path(root) / "receipts").resolve()
    if receipt_path.parent != receipt_dir:
        raise ValueError(
            "outcome must reference a native receipt directly in receipts/"
        )
    payload = _read(receipt_path)
    receipt = Receipt.from_dict(payload)
    stage = manifest["stages"][position - 1]
    if receipt.feature != feature or f"{receipt.module}:{receipt.stage}" != stage:
        raise ValueError("native receipt does not match declared feature/stage")
    if any(receipt.inputs.get(key) != value for key, value in binding.items()):
        raise ValueError("native receipt lacks execution-time sequence binding")
    return _create(
        directory / f"{position:04d}.outcome.json",
        {
            **binding,
            "schema": SEQUENCE_SCHEMA,
            "feature": feature,
            "kind": "outcome",
            "stage": stage,
            "recorded_at": _now(),
            "intent_sha256": _hash(intent),
            "receipt_path": receipt_path.name,
            "receipt_sha256": _hash(payload),
        },
    )


def _event(value: dict, manifest: dict, position: int, kind: str) -> datetime:
    expected = {
        **sequence_binding(manifest, position),
        "schema": SEQUENCE_SCHEMA,
        "feature": manifest["feature"],
        "kind": kind,
        "stage": manifest["stages"][position - 1],
    }
    if any(
        type(value.get(key)) is not type(item) or value.get(key) != item
        for key, item in expected.items()
    ):
        raise ValueError(f"{kind} identity/binding mismatch at position {position}")
    return _time(value.get("recorded_at"))


def _check_sequence_files(directory: Path, count: int, quarantined: bool) -> None:
    expected = {"manifest.json"} | {
        f"{position:04d}.{kind}.json"
        for position in range(1, count + 1)
        for kind in ("intent", "outcome")
    }
    if quarantined:
        expected.add("quarantine.json")
    for path in directory.iterdir():
        if path.name not in expected or path.is_symlink() or not path.is_file():
            raise ValueError("unexpected sequence evidence file")


def _sequence_events(directory, manifest, position, previous):
    intent_path = directory / f"{position:04d}.intent.json"
    outcome_path = directory / f"{position:04d}.outcome.json"
    intent = _read(intent_path) if intent_path.exists() else None
    outcome = _read(outcome_path) if outcome_path.exists() else None
    intent_time = (
        _event(intent, manifest, position, "intent") if intent is not None else None
    )
    outcome_time = (
        _event(outcome, manifest, position, "outcome") if outcome is not None else None
    )
    if intent_time is not None and intent_time <= previous:
        raise ValueError(f"plan/sequence chronology invalid at position {position}")
    if outcome_time is not None and (
        outcome_time <= previous
        or (intent_time is not None and outcome_time < intent_time)
    ):
        raise ValueError(f"outcome chronology invalid at position {position}")
    return intent, outcome, intent_time, outcome_time


def _sequence_native_row(root, manifest, position, events, receipts_seen):
    intent, outcome, intent_time, outcome_time = events
    name = outcome.get("receipt_path")
    if not isinstance(name, str) or Path(name).name != name or name in receipts_seen:
        raise ValueError("invalid or reused native receipt reference")
    receipts_seen.add(name)
    receipt_dir = Path(root) / "receipts"
    native_path = receipt_dir / name
    if native_path.resolve().parent != receipt_dir.resolve():
        raise ValueError("native receipt reference escapes receipts/")
    payload, raw_sha256 = _read_snapshot(native_path)
    receipt = Receipt.from_dict(payload)
    if (
        receipt.feature != manifest["feature"]
        or f"{receipt.module}:{receipt.stage}" != manifest["stages"][position - 1]
    ):
        raise ValueError("native receipt feature/stage mismatch")
    binding = sequence_binding(manifest, position)
    if any(
        type(receipt.inputs.get(key)) is not type(value)
        or receipt.inputs.get(key) != value
        for key, value in binding.items()
    ):
        raise ValueError("native receipt sequence binding mismatch")
    native_time = _time(receipt.ts)
    if (
        native_time <= _time(manifest["declared_at"])
        or native_time > outcome_time
        or (intent_time is not None and native_time < intent_time)
    ):
        raise ValueError("native receipt chronology invalid")
    if outcome.get("receipt_sha256") != _hash(payload):
        raise ValueError("native receipt hash mismatch")
    if intent is not None and outcome.get("intent_sha256") != _hash(intent):
        raise ValueError("outcome does not bind its paired intent")
    return {
        "module": receipt.module,
        "stage": receipt.stage,
        "status": "ok" if receipt.ok else "failed",
        "inputs": receipt.inputs,
        "outputs": receipt.outputs,
        "attribution": receipt.attribution,
        "receipt_path": name,
        "receipt_sha256": raw_sha256,
    }


def _verify_sequence_positions(root, directory, manifest, result) -> None:
    previous = _time(manifest["declared_at"])
    receipts_seen: set[str] = set()
    for position, stage in enumerate(manifest["stages"], 1):
        events = _sequence_events(directory, manifest, position, previous)
        intent, outcome, intent_time, outcome_time = events
        missing = [
            kind
            for kind, value in (("intent", intent), ("outcome", outcome))
            if value is None
        ]
        if missing:
            result["missing_positions"].append(
                {"position": position, "stage": stage, "missing": missing}
            )
        if outcome is not None:
            row = _sequence_native_row(root, manifest, position, events, receipts_seen)
            result["stages"].append(row)
            if row["status"] == "failed":
                result["blockers"].append(
                    {
                        "code": "SEQUENCE_STAGE_FAILED",
                        "detail": f"position {position}: {stage}",
                    }
                )
        previous = outcome_time or intent_time or previous


def verify_sequence(
    root: Path, feature: str, run_id: str, required_stages: set[str]
) -> dict:
    """Check selected run only. Missing pairs are incomplete, bad plans unverifiable."""
    result: dict[str, Any] = {
        "schema": SEQUENCE_SCHEMA,
        "run_id": run_id,
        "status": "unverifiable",
        "ok": False,
        "missing_positions": [],
        "stages": [],
        "blockers": [],
        "claim_boundary": "Local producer-asserted evidence only. Hashes and timestamps do not prove authentic intent, trusted chronology, or independent execution.",
    }

    def block(code: str, detail: str) -> None:
        result["blockers"].append({"code": code, "detail": detail})

    try:
        directory = _directory(root, feature, run_id)
        result["quarantined"] = _quarantine(directory, feature, run_id)
        _, manifest = _manifest(root, feature, run_id)
        stages = manifest["stages"]
        if not required_stages.issubset(set(stages)):
            raise ValueError("plan omits required native gates")
        _check_sequence_files(directory, len(stages), result["quarantined"])
        _verify_sequence_positions(root, directory, manifest, result)
        if result["missing_positions"]:
            result["status"] = "incomplete"
            block(
                "SEQUENCE_EVIDENCE_MISSING",
                "declared positions lack paired intent/outcome evidence",
            )
        else:
            result["status"] = "failed" if result["blockers"] else "passed"
        result["ok"] = result["status"] == "passed"
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        UnicodeDecodeError,
        OverflowError,
    ) as exc:
        block("SEQUENCE_UNVERIFIABLE", str(exc))
        result["status"] = "unverifiable"
    return result


def _sequence_error(report: dict, stage: str, error: Exception) -> None:
    report["halted_at"] = stage
    report["sequence_error"] = {
        "code": "SEQUENCE_EVIDENCE_ERROR",
        "detail": str(error)[:240],
    }


def _assembly_scope_requirements(root, feature):
    rows = rollup_receipts(root, feature)["stages"]
    return {
        f"{module}:{stage}"
        for module, stages in _required_stages(root, feature, rows).items()
        if module not in BASE_REQUIRED_MODULES
        for stage in stages
    }


def _begin_assembly_sequence(root, feature, run_id, stages, report) -> bool:
    """Declare required and applicable native stages before assembly runs them."""

    from .assembly import decision_source, forge_stage_skippable

    def applies(stage):
        if forge_stage_skippable(root, feature, stage)[0]:
            return False  # assembly skips it; it is not part of this run's declared sequence
        if stage.required:
            return True
        if (stage.module, stage.name) in CONDITIONAL_STAGE_KEYS:
            return stage.present and (root / ".factory" / "workflow-audit-contract.json").is_file()
        if stage.module in BASE_REQUIRED_MODULES:
            return True
        if stage.module == "prestige":
            return stage.present and (root / "smoke" / f"{feature}.ui").is_file()
        if stage.module == "hsf" and stage.name == "compile":
            return stage.present and decision_source(root, feature) is not None
        if stage.module == "hsf" and stage.name == "harness-check":
            return stage.present and (root / "harness" / "harness.yaml").is_file()
        return stage.present

    planned = [stage.stage_id for stage in stages if applies(stage)]
    report["sequence_run_id"] = run_id
    report["sequence_recorded"] = False
    if not planned:
        return True
    try:
        declare_sequence(root, feature, run_id, planned)
    except (OSError, ValueError) as error:
        _sequence_error(report, "sequence:manifest", error)
        return False
    report["sequence_recorded"] = True
    return True


def _assembly_intent(root, feature, run_id, stage_id, report) -> dict | None:
    """Record the positional intent before a native stage starts."""
    try:
        directory, manifest = _manifest(root, feature, run_id)
        position = next(
            p
            for p in range(1, len(manifest["stages"]) + 1)
            if not (directory / f"{p:04d}.intent.json").exists()
        )
        if manifest["stages"][position - 1] != stage_id:
            raise ValueError("executed stage differs from recorded plan")
        record_intent(root, feature, run_id, position)
        return sequence_binding(manifest, position)
    except (OSError, ValueError, StopIteration) as error:
        _sequence_error(report, stage_id, error)
        return None


def _assembly_outcome(root, feature, run_id, binding, receipt_path, report) -> bool:
    """Bind the durable native receipt before the next stage can start."""
    try:
        record_outcome(
            root, feature, run_id, binding["sequence_position"], receipt_path
        )
    except (OSError, ValueError) as error:
        _sequence_error(report, "sequence:outcome", error)
        return False
    return True


def _quarantine(directory: Path, feature: str, run_id: str) -> bool:
    path = directory / "quarantine.json"
    if not path.exists() and not path.is_symlink():
        return False
    note = _read(path)
    digest = note.get("manifest_sha256")
    if (
        set(note)
        != {"schema", "feature", "run_id", "reason", "recorded_at", "manifest_sha256"}
        or (
            digest is not None
            and (
                not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            )
        )
        or note.get("schema") != SEQUENCE_SCHEMA
        or note.get("feature") != feature
        or note.get("run_id") != run_id
        or not isinstance(note.get("reason"), str)
        or not 1 <= len(note["reason"].strip()) <= 500
    ):
        raise ValueError("invalid sequence quarantine record")
    _time(note.get("recorded_at"))
    return True


def quarantine_sequence(root: Path, feature: str, run_id: str, reason: str) -> dict:
    """Retain a damaged run and explicitly exclude it from basis selection."""
    directory = _directory(root, feature, run_id)
    if not directory.is_dir() or not 1 <= len(reason.strip()) <= 500:
        raise ValueError(
            "an existing sequence and a reason of 1..500 characters are required"
        )
    if _quarantine(directory, feature, run_id):
        raise FileExistsError("run is already quarantined")
    if verify_sequence(root, feature, run_id, set())["status"] != "unverifiable":
        raise ValueError("quarantine requires an unverifiable run")
    try:
        _, manifest = _manifest(root, feature, run_id)
        digest = _hash(manifest)
    except (OSError, ValueError):
        digest = None
    return _create(
        directory / "quarantine.json",
        {
            "schema": SEQUENCE_SCHEMA,
            "feature": feature,
            "run_id": run_id,
            "reason": reason.strip(),
            "recorded_at": _now(),
            "manifest_sha256": digest,
        },
    )


def _basis_inventory(root, feature, required, result):
    runs = _directory(root, feature, "manifest-probe").parent
    if not runs.exists():
        return None, False
    newest = None
    base_stages = {
        f"{owner}:{stage}"
        for owner, stages in BASE_REQUIRED.items()
        for stage in stages
    }
    has_whole_attempt = False
    for count, directory in enumerate(runs.iterdir(), 1):
        if count > 2048 or directory.is_symlink() or not directory.is_dir():
            raise ValueError("invalid or oversized sequence inventory")
        run_id = _id(directory.name)
        directory = _directory(root, feature, run_id)
        if _quarantine(directory, feature, run_id):
            result["recovered"].append(run_id)
            continue
        _, manifest = _manifest(root, feature, run_id)
        key = (_time(manifest["declared_at"]), run_id)
        planned = set(manifest["stages"])
        has_whole_attempt = has_whole_attempt or base_stages <= planned
        if required <= planned and (newest is None or key > newest):
            newest = key
    result["recovered"].sort()
    return newest[1] if newest else None, has_whole_attempt


def _select_sequence(
    root: Path, feature: str, required: set[str], rows: list[dict]
) -> dict:
    """Require one current whole-run basis whenever a qualifying plan exists."""
    result = {
        "assured": False,
        "basis": None,
        "status": "not_evaluated",
        "limit": "Gate-only legacy evidence.",
        "blockers": [],
        "recovered": [],
    }
    try:
        basis, has_whole_attempt = _basis_inventory(root, feature, required, result)
    except (OSError, ValueError, TypeError, OverflowError) as error:
        return result | {
            "status": "unverifiable",
            "limit": "Sequence inventory is invalid.",
            "blockers": [{"code": "SEQUENCE_UNVERIFIABLE", "detail": str(error)}],
        }
    if basis is None:
        if has_whole_attempt or result["recovered"]:
            result.update(
                status="incomplete",
                limit="A fresh whole run must cover all current required gates.",
                blockers=[
                    {
                        "code": "SEQUENCE_EVIDENCE_MISSING",
                        "detail": "No recorded basis covers all current required gates.",
                    }
                ],
            )
        return result
    verdict = verify_sequence(root, feature, basis, required)
    result.update(
        basis=basis,
        status=verdict["status"],
        blockers=verdict["blockers"],
        missing_positions=verdict["missing_positions"],
        limit=verdict["claim_boundary"],
    )
    if not verdict["ok"]:
        return result
    owned = {}
    for row in verdict["stages"]:
        key = f"{row['module']}:{row['stage'].replace('_', '-')}"
        owned.setdefault(key, set()).add((row["receipt_path"], row["receipt_sha256"]))
    current = {
        f"{row['module']}:{row['stage']}": (row["receipt_path"], row["receipt_sha256"])
        for row in rows
    }
    superseded = sorted(
        key for key in required if current.get(key) not in owned.get(key, ())
    )
    if superseded:
        result.update(
            status="superseded",
            blockers=[
                {
                    "code": "SEQUENCE_BASIS_SUPERSEDED",
                    "detail": ", ".join(superseded),
                }
            ],
        )
    else:
        result["assured"] = True
    return result


def _whole_run_projection(verification: dict) -> dict:
    """Expose the evidence boundary on release decision surfaces."""
    whole = verification.get("whole_run", {})
    return {
        "whole_run_assured": whole.get("assured") is True,
        "whole_run_basis": whole.get("basis"),
        "whole_run_limit": whole.get("limit", "Whole-run evidence was not evaluated."),
    }


def _print_sequence_status(result: dict) -> None:
    """Display explicit and default sequence evidence without changing gate outputs."""
    whole = result["whole_run"]
    if result.get("strict_sequence"):
        print(f"SEQUENCE {result['sequence']['status'].upper()}")
    elif whole["basis"]:
        print(f"SEQUENCE {whole['status'].upper()} (run {whole['basis']})")
    else:
        status = whole["status"].replace("_", " ").upper()
        print(f"SEQUENCE {status} ({whole['limit']})")
    if whole["recovered"]:
        print("SEQUENCE RECOVERED (quarantined: " + ", ".join(whole["recovered"]) + ")")


def _quarantine_command(args) -> int:
    """Persist a one-way quarantine record without deleting any evidence."""
    try:
        value = quarantine_sequence(
            Path(args.root), args.feature, args.run_id, args.reason
        )
    except (OSError, ValueError) as error:
        print(json.dumps({"code": "SEQUENCE_UNVERIFIABLE", "detail": str(error)}))
        return 1
    print(json.dumps(value, indent=2))
    return 0
