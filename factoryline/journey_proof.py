"""Provider-neutral journey, workflow, failure, and healing proof primitives."""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from .attribution import FailureClass
from .e2e_proof import run_supervised_command


AUTHORITY = {
    "repair": False,
    "approval": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}
RECEIPT_DIR = Path(".factory/journey-proof")
_HEX = frozenset("0123456789abcdef")
_SKIP_DIRS = {".git", ".factory", ".pytest_cache", ".mypy_cache", "__pycache__", "node_modules", "dist", "build"}


class JourneyProofError(ValueError):
    """Stable fail-closed input error."""

    def __init__(self, message: str, code: str = "JOURNEY_INPUT_REJECTED") -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _sha_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        missing = sorted(fields - set(value)) if isinstance(value, dict) else sorted(fields)
        extra = sorted(set(value) - fields) if isinstance(value, dict) else []
        raise JourneyProofError(f"{label} fields are not exact; missing={missing}, unknown={extra}")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise JourneyProofError(f"{label} must be a non-empty string")
    return value.strip()


def _sha(value: object, label: str) -> str:
    text = _string(value, label).lower()
    if len(text) != 64 or any(char not in _HEX for char in text):
        raise JourneyProofError(f"{label} must be a lowercase SHA-256")
    return text


def _list(value: object, label: str, *, maximum: int = 512) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise JourneyProofError(f"{label} must be a list with at most {maximum} items")
    return value


def _strings(value: object, label: str, *, maximum: int = 512) -> list[str]:
    items = [_string(item, f"{label} item") for item in _list(value, label, maximum=maximum)]
    if len(items) != len(set(items)):
        raise JourneyProofError(f"{label} must not contain duplicates")
    return items


def _root(root: Path | str) -> Path:
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise JourneyProofError("root must be an existing directory")
    return workspace


def _contained(workspace: Path, value: object, label: str, *, must_exist: bool = True) -> tuple[Path, str]:
    relative = Path(_string(value, label))
    if relative.is_absolute():
        raise JourneyProofError(f"{label} must be workspace-relative")
    target = (workspace / relative).resolve()
    try:
        normalized = target.relative_to(workspace).as_posix()
    except ValueError as error:
        raise JourneyProofError(f"{label} escapes the workspace") from error
    if must_exist and not target.is_file():
        raise JourneyProofError(f"{label} does not identify an existing file")
    return target, normalized


def _load(workspace: Path, value: Path | str, schema: str, fields: set[str]) -> tuple[dict[str, Any], str]:
    path, relative = _contained(workspace, str(value), "input path")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise JourneyProofError(f"input is not valid UTF-8 JSON: {relative}") from error
    data = _exact(payload, fields, schema)
    if data.get("schema") != schema:
        raise JourneyProofError(f"schema must equal {schema}")
    return data, _sha_file(path)


def _artifact(workspace: Path, value: object, label: str) -> dict[str, Any]:
    item = _exact(value, {"path", "sha256", "kind"}, label)
    path, relative = _contained(workspace, item["path"], f"{label}.path")
    expected = _sha(item["sha256"], f"{label}.sha256")
    actual = _sha_file(path)
    return {"path": relative, "kind": _string(item["kind"], f"{label}.kind"), "sha256": expected, "actual_sha256": actual, "current": actual == expected}


def _write_text_atomic(target: Path, payload: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _write(workspace: Path, value: dict[str, Any], out: Path | str | None, default_name: str) -> tuple[dict[str, Any], Path]:
    target_value = str(out) if out is not None else (RECEIPT_DIR / default_name).as_posix()
    target, relative = _contained(workspace, target_value, "output path", must_exist=False)
    if not (target == workspace / RECEIPT_DIR / target.name or RECEIPT_DIR in target.relative_to(workspace).parents):
        raise JourneyProofError("output path must be below .factory/journey-proof")
    core = {**value, "markers": sorted(set([*value.get("markers", []), "JOURNEY_RECEIPT_WRITTEN"]))}
    receipt = {**core, "receipt_sha256": _digest(core)}
    payload = json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    _write_text_atomic(target, payload)
    return {**receipt, "receipt_path": relative}, target


def _ids(values: object, label: str) -> list[str]:
    normalized = [_string(value, f"{label} id").casefold() for value in _list(values, label)]
    if len(normalized) != len(set(normalized)):
        raise JourneyProofError(f"{label} must not contain duplicate normalized ids")
    return sorted(normalized)


def _journey_common(value: dict[str, Any], label: str) -> None:
    _string(value["project_id"], f"{label}.project_id")
    _string(value["journey_id"], f"{label}.journey_id")
    _strings(value["requirements"], f"{label}.requirements")
    _strings(value["outcomes"], f"{label}.outcomes")


def _compile_reality_graph(root: Path, declaration_path: Path, observation_path: Path, out: Path | None = None) -> dict[str, Any]:
    """Compare explicit declared and observed journey sets without inference."""
    workspace = _root(root)
    declaration, declaration_sha = _load(workspace, declaration_path, "factory.journey-declaration.v1", {"schema", "project_id", "journey_id", "states", "transitions", "requirements", "outcomes"})
    observation, observation_sha = _load(workspace, observation_path, "factory.journey-observation.v1", {"schema", "project_id", "journey_id", "run_id", "code_version", "environment", "states", "transitions", "requirements", "outcomes", "observed_at"})
    _journey_common(declaration, "declaration")
    _journey_common(observation, "observation")
    if declaration["project_id"] != observation["project_id"] or declaration["journey_id"] != observation["journey_id"]:
        raise JourneyProofError("project_id and journey_id must match")
    declared_states = [_exact(item, {"id", "requirements", "outcome"}, "declared state") for item in _list(declaration["states"], "states")]
    observed_states = [_exact(item, {"id"}, "observed state") for item in _list(observation["states"], "states")]
    declared_transitions = [_exact(item, {"id", "from", "to", "requirements"}, "declared transition") for item in _list(declaration["transitions"], "transitions")]
    observed_transitions = [_exact(item, {"id", "from", "to", "artifacts"}, "observed transition") for item in _list(observation["transitions"], "transitions")]
    for state in declared_states:
        _strings(state["requirements"], "declared state.requirements")
        if not isinstance(state["outcome"], bool):
            raise JourneyProofError("declared state.outcome must be boolean")
    for transition in declared_transitions:
        _string(transition["from"], "declared transition.from")
        _string(transition["to"], "declared transition.to")
        _strings(transition["requirements"], "declared transition.requirements")
    categories = {
        "states": (_ids([item["id"] for item in declared_states], "declared states"), _ids([item["id"] for item in observed_states], "observed states")),
        "transitions": (_ids([item["id"] for item in declared_transitions], "declared transitions"), _ids([item["id"] for item in observed_transitions], "observed transitions")),
        "requirements": (_ids(declaration["requirements"], "declared requirements"), _ids(observation["requirements"], "observed requirements")),
        "outcomes": (_ids(declaration["outcomes"], "declared outcomes"), _ids(observation["outcomes"], "observed outcomes")),
    }
    artifacts = []
    for transition_index, transition in enumerate(observed_transitions):
        _string(transition["from"], "observed transition.from")
        _string(transition["to"], "observed transition.to")
        for artifact_index, item in enumerate(_list(transition["artifacts"], "transition artifacts", maximum=256)):
            artifacts.append(_artifact(workspace, item, f"transition[{transition_index}].artifact[{artifact_index}]"))
    deltas = {name: {"missing": sorted(set(declared) - set(observed)), "unexpected": sorted(set(observed) - set(declared))} for name, (declared, observed) in categories.items()}
    stale = sorted({item["path"] for item in artifacts if not item["current"]})
    equal = not stale and all(not delta["missing"] and not delta["unexpected"] for delta in deltas.values())
    marker = "JOURNEY_REALITY_MATCHED" if equal else "JOURNEY_REALITY_REVIEW_REQUIRED"
    result = {
        "schema": "factory.journey-reality-receipt.v1", "marker": marker, "markers": ["JOURNEY_INPUT_ACCEPTED", marker],
        "project_id": declaration["project_id"], "journey_id": declaration["journey_id"], "run_id": _string(observation["run_id"], "run_id"),
        "decision": "matched" if equal else "review_required", "facts": {"input_contract_valid": True, "journey_sets_equal": equal},
        "deltas": {**deltas, "stale_artifact_hashes": stale}, "artifacts": artifacts,
        "bindings": {"declaration_sha256": declaration_sha, "observation_sha256": observation_sha, "code_version": _string(observation["code_version"], "code_version"), "environment": observation["environment"], "observed_at": _string(observation["observed_at"], "observed_at")},
        "authority": AUTHORITY,
    }
    return _write(workspace, result, out, f"reality-{_digest([declaration_sha, observation_sha])[:16]}.json")[0]


def _create_failure_capsule(root: Path, input_path: Path, out: Path | None = None) -> dict[str, Any]:
    """Bind one failed step and bounded adjacent evidence into JSON and Markdown."""
    workspace = _root(root)
    data, input_sha = _load(workspace, input_path, "factory.failure-capsule-input.v1", {"schema", "project_id", "journey_id", "run_id", "code_version", "environment", "classification", "hypothesis", "suggested_repair", "failed_step_index", "steps", "artifacts", "reproduction_argv", "observed_at"})
    classification = _string(data["classification"], "classification")
    if classification not in {kind.value for kind in FailureClass}:
        raise JourneyProofError("classification must use the closed FailureClass taxonomy")
    steps = [_exact(item, {"index", "label", "status"}, "step") for item in _list(data["steps"], "steps", maximum=256)]
    if any(not isinstance(item["index"], int) or isinstance(item["index"], bool) for item in steps):
        raise JourneyProofError("step indexes must be integers")
    indexes = [item["index"] for item in steps]
    if indexes != sorted(indexes) or len(indexes) != len(set(indexes)):
        raise JourneyProofError("step indexes must be unique and ordered")
    failed_index = data["failed_step_index"]
    if not isinstance(failed_index, int) or isinstance(failed_index, bool) or failed_index not in indexes:
        raise JourneyProofError("failed_step_index must name an existing step")
    failed_position = indexes.index(failed_index)
    context = steps[max(0, failed_position - 1):failed_position + 2]
    for step in context:
        _string(step["label"], "step.label")
        _string(step["status"], "step.status")
    artifacts = []
    for index, raw in enumerate(_list(data["artifacts"], "artifacts", maximum=256)):
        item = _exact(raw, {"path", "sha256", "kind", "step_index"}, "artifact")
        verified = _artifact(workspace, {key: item[key] for key in ("path", "sha256", "kind")}, f"artifact[{index}]")
        if not verified["current"]:
            raise JourneyProofError(f"artifact hash is stale: {verified['path']}")
        if item["step_index"] not in indexes:
            raise JourneyProofError("artifact.step_index must name an existing step")
        artifacts.append({**verified, "step_index": item["step_index"]})
    argv = _strings(data["reproduction_argv"], "reproduction_argv", maximum=64)
    if not argv:
        raise JourneyProofError("reproduction_argv must not be empty")
    result = {
        "schema": "factory.failure-capsule.v1", "marker": "FAILURE_CAPSULE_BOUND", "markers": ["JOURNEY_INPUT_ACCEPTED", "FAILURE_CAPSULE_BOUND"],
        "project_id": _string(data["project_id"], "project_id"), "journey_id": _string(data["journey_id"], "journey_id"), "run_id": _string(data["run_id"], "run_id"),
        "decision": "review_required", "classification": classification, "failed_step_index": failed_index, "step_context": context, "artifacts": sorted(artifacts, key=lambda item: (item["step_index"], item["path"])),
        "hypothesis": {"trust": "unverified", "text": _string(data["hypothesis"], "hypothesis")}, "suggested_repair": {"trust": "unverified", "text": _string(data["suggested_repair"], "suggested_repair")},
        "reproduction_argv": argv, "bindings": {"input_sha256": input_sha, "code_version": _string(data["code_version"], "code_version"), "environment": data["environment"], "observed_at": _string(data["observed_at"], "observed_at")}, "authority": AUTHORITY,
    }
    receipt, target = _write(workspace, result, out, f"capsule-{input_sha[:16]}.json")
    markdown = [f"# Failure Capsule: {receipt['journey_id']}", "", f"- Classification: `{classification}`", "- Hypothesis trust: `unverified`", f"- Receipt SHA-256: `{receipt['receipt_sha256']}`", "", "## Bounded step context", ""]
    markdown.extend(f"- {step['index']}: {step['label']} (`{step['status']}`)" for step in context)
    markdown.extend(["", "## Hypothesis", "", receipt["hypothesis"]["text"], "", "## Suggested repair", "", receipt["suggested_repair"]["text"], ""])
    _write_text_atomic(target.with_suffix(".md"), "\n".join(markdown))
    return {**receipt, "markdown_path": target.with_suffix(".md").relative_to(workspace).as_posix()}


def _workflow_graph(tests: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], bool]:
    by_id: dict[str, dict[str, Any]] = {}
    for item in tests:
        test_id = _string(item["id"], "test.id")
        if test_id in by_id:
            raise JourneyProofError("test ids must be unique")
        by_id[test_id] = item
    indegree = {test_id: 0 for test_id in by_id}
    children = {test_id: [] for test_id in by_id}
    for test_id, item in by_id.items():
        for dependency in _strings(item["depends_on"], "depends_on"):
            if dependency not in by_id or dependency == test_id:
                raise JourneyProofError("dependencies must name different existing tests")
            indegree[test_id] += 1
            children[dependency].append(test_id)
    queue = sorted(test_id for test_id, count in indegree.items() if count == 0)
    visited = []
    while queue:
        current = queue.pop(0)
        visited.append(current)
        for child in sorted(children[current]):
            indegree[child] -= 1
            if indegree[child] == 0:
                queue.append(child)
                queue.sort()
    return by_id, len(visited) == len(by_id)


def _verify_stateful_workflow(root: Path, input_path: Path, out: Path | None = None) -> dict[str, Any]:
    """Prove DAG state flow and cleanup outcomes from explicit run results."""
    workspace = _root(root)
    data, input_sha = _load(workspace, input_path, "factory.stateful-workflow-input.v1", {"schema", "project_id", "workflow_id", "run_id", "code_version", "environment", "tests", "results", "observed_at"})
    test_fields = {"id", "index", "depends_on", "produces", "consumes", "side_effects", "cleanup_for", "is_cleanup"}
    result_fields = {"test_id", "status", "produced", "consumed", "side_effects_created", "cleanup_completed", "idempotency_probe_passed"}
    tests = [_exact(item, test_fields, "test") for item in _list(data["tests"], "tests", maximum=256)]
    results = [_exact(item, result_fields, "result") for item in _list(data["results"], "results", maximum=256)]
    by_id, acyclic = _workflow_graph(tests)
    indexes: dict[str, int] = {}
    for test_id, item in by_id.items():
        if not isinstance(item["index"], int) or isinstance(item["index"], bool):
            raise JourneyProofError("test.index must be an integer")
        indexes[test_id] = item["index"]
        _strings(item["produces"], "produces"); _strings(item["consumes"], "consumes"); _strings(item["side_effects"], "side_effects"); _strings(item["cleanup_for"], "cleanup_for")
        if not isinstance(item["is_cleanup"], bool):
            raise JourneyProofError("is_cleanup must be boolean")
    if len(set(indexes.values())) != len(indexes):
        raise JourneyProofError("test indexes must be unique")
    result_map: dict[str, dict[str, Any]] = {}
    for item in results:
        test_id = _string(item["test_id"], "result.test_id")
        if test_id not in by_id or test_id in result_map:
            raise JourneyProofError("results must name unique existing tests")
        if not isinstance(item["produced"], dict) or not isinstance(item["consumed"], dict):
            raise JourneyProofError("produced and consumed results must be objects")
        for key, value in [*item["produced"].items(), *item["consumed"].items()]:
            _string(key, "state value name"); _sha(value, "state value hash")
        _strings(item["side_effects_created"], "side_effects_created"); _strings(item["cleanup_completed"], "cleanup_completed")
        if item["idempotency_probe_passed"] is not None and not isinstance(item["idempotency_probe_passed"], bool):
            raise JourneyProofError("idempotency_probe_passed must be boolean or null")
        result_map[test_id] = item
    reason_codes: set[str] = set()
    if not acyclic:
        reason_codes.add("WORKFLOW_CYCLE_DETECTED")
    if set(result_map) != set(by_id) or any(item["status"] != "passed" for item in result_map.values()):
        reason_codes.add("WORKFLOW_EXECUTION_INCOMPLETE")
    producers: dict[str, list[tuple[str, str]]] = {}
    for test_id, test in by_id.items():
        result = result_map.get(test_id, {})
        for name in test["produces"]:
            if name in result.get("produced", {}):
                producers.setdefault(name, []).append((test_id, result["produced"][name]))
    value_edges = []
    for test_id, test in by_id.items():
        consumed = result_map.get(test_id, {}).get("consumed", {})
        for name in test["consumes"]:
            matches = producers.get(name, [])
            if len(matches) != 1 or name not in consumed:
                reason_codes.add("WORKFLOW_VALUE_PRODUCER_INVALID")
                continue
            producer_id, produced_hash = matches[0]
            if indexes[producer_id] >= indexes[test_id] or produced_hash != consumed[name]:
                reason_codes.add("WORKFLOW_VALUE_HASH_MISMATCH")
            value_edges.append({"producer": producer_id, "consumer": test_id, "value": name, "sha256": produced_hash})
    for test_id, result in result_map.items():
        test = by_id[test_id]
        if set(result["produced"]) != set(test["produces"]) or set(result["consumed"]) != set(test["consumes"]):
            reason_codes.add("WORKFLOW_VALUE_DECLARATION_MISMATCH")
        if set(result["side_effects_created"]) != set(test["side_effects"]):
            reason_codes.add("WORKFLOW_CLEANUP_MISSING")
        if test["is_cleanup"] and set(result["cleanup_completed"]) != set(test["cleanup_for"]):
            reason_codes.add("WORKFLOW_CLEANUP_MISSING")
        for effect in result["side_effects_created"]:
            matches = [cleanup_id for cleanup_id, cleanup in by_id.items() if cleanup["is_cleanup"] and effect in cleanup["cleanup_for"] and indexes[cleanup_id] > indexes[test_id] and result_map.get(cleanup_id, {}).get("status") == "passed" and effect in result_map[cleanup_id]["cleanup_completed"] and result_map[cleanup_id]["idempotency_probe_passed"] is True]
            if not matches:
                reason_codes.add("WORKFLOW_CLEANUP_MISSING")
    for test_id, test in by_id.items():
        if test["is_cleanup"] and result_map.get(test_id, {}).get("idempotency_probe_passed") is not True:
            reason_codes.add("WORKFLOW_CLEANUP_IDEMPOTENCY_FAILED")
    values_valid = not any(code.startswith("WORKFLOW_VALUE") or code == "WORKFLOW_EXECUTION_INCOMPLETE" for code in reason_codes)
    cleanup_valid = not any(code.startswith("WORKFLOW_CLEANUP") for code in reason_codes)
    passed = acyclic and values_valid and cleanup_valid and not reason_codes
    marker = "WORKFLOW_PROOF_PASSED" if passed else "WORKFLOW_PROOF_FAILED"
    receipt = {"schema": "factory.stateful-workflow-receipt.v1", "marker": marker, "markers": sorted({"JOURNEY_INPUT_ACCEPTED", marker, *reason_codes}), "project_id": _string(data["project_id"], "project_id"), "workflow_id": _string(data["workflow_id"], "workflow_id"), "run_id": _string(data["run_id"], "run_id"), "decision": "passed" if passed else "failed", "facts": {"input_contract_valid": True, "workflow_acyclic": acyclic, "workflow_values_valid": values_valid, "workflow_cleanup_valid": cleanup_valid}, "reason_codes": sorted(reason_codes), "value_edges": sorted(value_edges, key=lambda item: (item["producer"], item["consumer"], item["value"])), "bindings": {"input_sha256": input_sha, "code_version": _string(data["code_version"], "code_version"), "environment": data["environment"], "observed_at": _string(data["observed_at"], "observed_at")}, "authority": AUTHORITY}
    return _write(workspace, receipt, out, f"workflow-{input_sha[:16]}.json")[0]


def _snapshot(workspace: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for path in sorted(workspace.rglob("*")):
        relative = path.relative_to(workspace)
        if path.is_symlink() or not path.is_file() or any(part in _SKIP_DIRS for part in relative.parts):
            continue
        values[relative.as_posix()] = _sha_file(path)
        if len(values) > 20_000:
            raise JourneyProofError("workspace snapshot exceeds 20000 files", "HEALING_AGENT_AUDIT_FAILED")
    return values


def _snapshot_digest(snapshot: dict[str, str]) -> str:
    return _digest(snapshot)


def _changed(before: dict[str, str], after: dict[str, str]) -> list[str]:
    return sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))


def _allowed(path: str, allowlist: list[str]) -> bool:
    return any(path == allowed or path.startswith(allowed.rstrip("/") + "/") for allowed in allowlist)


def _run(argv: list[str], workspace: Path, timeout: int) -> dict[str, Any]:
    return run_supervised_command(argv, cwd=workspace, timeout_seconds=timeout)


def _agent_contract(value: object, review_mode: str) -> dict[str, Any] | None:
    if review_mode == "human_controlled":
        if value is not None:
            raise JourneyProofError("human_controlled mode forbids an agent command", "HEALING_REVIEW_MODE_INVALID")
        return None
    agent = _exact(value, {"identity", "argv", "max_attempts", "timeout_seconds"}, "agent")
    identity = _exact(agent["identity"], {"provider", "subject", "display_name"}, "agent.identity")
    for key in identity:
        _string(identity[key], f"agent.identity.{key}")
    argv = _strings(agent["argv"], "agent.argv", maximum=64)
    attempts, timeout = agent["max_attempts"], agent["timeout_seconds"]
    if not argv or not isinstance(attempts, int) or isinstance(attempts, bool) or not 1 <= attempts <= 3 or not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 900:
        raise JourneyProofError("supervised_auto requires argv, max_attempts 1..3, and timeout_seconds 1..900", "HEALING_REVIEW_MODE_INVALID")
    return {"identity": identity, "argv": argv, "max_attempts": attempts, "timeout_seconds": timeout}


def _anchors(value: object, label: str) -> dict[str, str]:
    anchors = _exact(value, {"role", "label", "route", "state"}, label)
    return {key: _string(anchors[key], f"{label}.{key}") for key in sorted(anchors)}


def _agent_outcome(scope_ok: bool, agent_result: dict[str, Any] | None, positive: dict[str, Any] | None, negative: dict[str, Any] | None) -> tuple[str, FailureClass | None]:
    if not scope_ok:
        return "scope_escape", FailureClass.SCOPE_ESCAPE
    if agent_result is None:
        return "not_started", FailureClass.HOLLOW_MANIFEST
    if agent_result and agent_result.get("timed_out"):
        return "agent_timeout", FailureClass.RUNTIME_TIMEOUT
    if agent_result and agent_result.get("exit_code") != 0:
        return "agent_failed", FailureClass.RUNTIME_CRASH
    if positive and positive.get("exit_code") != 0:
        return "positive_failed", FailureClass.WRONG_OUTPUT
    if negative and negative.get("exit_code") == 0:
        return "hollow_negative", FailureClass.HOLLOW_TEST
    return "passed", None


def _verify_proof_gated_healing(root: Path, input_path: Path, out: Path | None = None, timeout_seconds: int = 300) -> dict[str, Any]:
    """Run bounded proof commands and independently audit an optional agent attempt."""
    workspace = _root(root)
    data, input_sha = _load(workspace, input_path, "factory.proof-gated-healing-input.v1", {"schema", "healing_id", "review_mode", "agent", "patch", "allowed_paths", "semantic_identity", "coverage_before", "coverage_after", "positive_argv", "negative_argv"})
    review_mode = _string(data["review_mode"], "review_mode")
    if review_mode not in {"human_controlled", "supervised_auto"}:
        raise JourneyProofError("review_mode must be human_controlled or supervised_auto", "HEALING_REVIEW_MODE_INVALID")
    agent = _agent_contract(data["agent"], review_mode)
    patch = _exact(data["patch"], {"path", "sha256", "changed_paths"}, "patch")
    patch_path, patch_relative = _contained(workspace, patch["path"], "patch.path")
    patch_current = _sha_file(patch_path) == _sha(patch["sha256"], "patch.sha256")
    allowlist = sorted(_contained(workspace, value, "allowed path", must_exist=False)[1] for value in _strings(data["allowed_paths"], "allowed_paths"))
    declared_changed = sorted(_contained(workspace, value, "changed path", must_exist=False)[1] for value in _strings(patch["changed_paths"], "patch.changed_paths"))
    if not allowlist or not declared_changed:
        raise JourneyProofError("allowed_paths and patch.changed_paths must not be empty")
    scope_valid = patch_current and all(_allowed(path, allowlist) for path in declared_changed)
    semantic = _exact(data["semantic_identity"], {"before", "after"}, "semantic_identity")
    before_anchors, after_anchors = _anchors(semantic["before"], "before"), _anchors(semantic["after"], "after")
    semantic_valid = before_anchors == after_anchors
    coverage_before = set(_strings(data["coverage_before"], "coverage_before"))
    coverage_after = set(_strings(data["coverage_after"], "coverage_after"))
    coverage_preserved = coverage_before <= coverage_after
    positive_argv = _strings(data["positive_argv"], "positive_argv", maximum=64)
    negative_argv = _strings(data["negative_argv"], "negative_argv", maximum=64)
    if not positive_argv or not negative_argv or not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 900:
        raise JourneyProofError("positive and negative argv and timeout 1..900 are required")
    attempts: list[dict[str, Any]] = []
    actual_changed: list[str] = []
    agent_scope_valid = True
    agent_exit_zero = review_mode == "human_controlled"
    first_snapshot = _snapshot(workspace)
    last_snapshot = first_snapshot
    if agent is not None and scope_valid and semantic_valid and coverage_preserved:
        for number in range(1, agent["max_attempts"] + 1):
            before = _snapshot(workspace)
            run = _run(agent["argv"], workspace, agent["timeout_seconds"])
            after = _snapshot(workspace)
            changed = _changed(before, after)
            attempt_scope = all(_allowed(path, allowlist) for path in changed)
            attempts.append({"attempt": number, "before_workspace_sha256": _snapshot_digest(before), "after_workspace_sha256": _snapshot_digest(after), "changed_paths": changed, "scope_valid": attempt_scope, "result": run})
            actual_changed = sorted(set(actual_changed) | set(changed))
            last_snapshot = after
            if not attempt_scope:
                agent_scope_valid = False
                break
            if run.get("exit_code") == 0:
                agent_exit_zero = True
                break
    precheck = scope_valid and semantic_valid and coverage_preserved and agent_scope_valid and (review_mode == "human_controlled" or agent_exit_zero)
    positive = _run(positive_argv, workspace, timeout_seconds) if precheck else None
    negative = _run(negative_argv, workspace, timeout_seconds) if positive and positive.get("exit_code") == 0 else None
    positive_ok = bool(positive and positive.get("exit_code") == 0)
    negative_ok = bool(negative and negative.get("exit_code") not in {None, 0})
    markers = {"JOURNEY_INPUT_ACCEPTED"}
    agent_audit = None
    audit_valid = review_mode == "human_controlled"
    if agent is not None:
        last_run = attempts[-1]["result"] if attempts else None
        outcome, failure_classification = _agent_outcome(agent_scope_valid, last_run, positive, negative)
        audit_core = {"schema": "factory.agent-work-audit.v1", "marker": "AGENT_WORK_AUDITED", "healing_id": _string(data["healing_id"], "healing_id"), "agent_identity": agent["identity"], "command_sha256": _digest(agent["argv"]), "before_workspace_sha256": _snapshot_digest(first_snapshot), "after_workspace_sha256": _snapshot_digest(last_snapshot), "changed_paths": actual_changed, "scope_valid": agent_scope_valid, "agent_result": last_run, "positive_result": positive, "negative_mutation_result": negative, "outcome_classification": outcome, "failure_classification": failure_classification.value if failure_classification else None, "worker_approval": False, "authority": AUTHORITY}
        try:
            audit_receipt, _ = _write(workspace, audit_core, None, f"agent-audit-{input_sha[:16]}.json")
        except (JourneyProofError, OSError) as error:
            raise JourneyProofError("FactoryLine could not bind the agent work audit", "HEALING_AGENT_AUDIT_FAILED") from error
        agent_audit = {"path": audit_receipt["receipt_path"], "sha256": audit_receipt["receipt_sha256"], "marker": audit_receipt["marker"]}
        audit_valid = audit_receipt["marker"] == "AGENT_WORK_AUDITED" and audit_receipt["authority"] == AUTHORITY and audit_receipt["worker_approval"] is False
        markers.add("AGENT_WORK_AUDITED")
    if not scope_valid or not semantic_valid or not coverage_preserved:
        markers.add("HEALING_PRECHECK_REJECTED")
    elif not agent_scope_valid:
        markers.add("HEALING_AGENT_SCOPE_ESCAPE")
    elif review_mode == "supervised_auto" and not agent_exit_zero:
        markers.add("HEALING_AGENT_FAILED")
    elif not audit_valid:
        markers.add("HEALING_AGENT_AUDIT_FAILED")
    elif not positive_ok:
        markers.add("HEALING_POSITIVE_FAILED")
    elif not negative_ok:
        markers.add("HOLLOW_HEALING_PROOF")
    else:
        markers.update({"HEALING_PROOF_ADMISSIBLE", "HEALING_HUMAN_REVIEW_REQUIRED" if review_mode == "human_controlled" else "HEALING_AUTO_AWAITING_PROMOTION"})
    admissible = "HEALING_PROOF_ADMISSIBLE" in markers
    primary = "HEALING_PROOF_ADMISSIBLE" if admissible else next(marker for marker in ("HEALING_PRECHECK_REJECTED", "HEALING_AGENT_SCOPE_ESCAPE", "HEALING_AGENT_FAILED", "HEALING_AGENT_AUDIT_FAILED", "HEALING_POSITIVE_FAILED", "HOLLOW_HEALING_PROOF") if marker in markers)
    receipt = {"schema": "factory.proof-gated-healing-receipt.v1", "marker": primary, "markers": sorted(markers), "healing_id": data["healing_id"], "review_mode": review_mode, "decision": "admissible_for_human_review" if admissible else "rejected", "facts": {"input_contract_valid": True, "review_mode_valid": True, "healing_scope_valid": scope_valid, "semantic_identity_valid": semantic_valid, "coverage_preserved": coverage_preserved, "agent_scope_valid": agent_scope_valid, "agent_command_exit_zero": agent_exit_zero, "agent_audit_valid": audit_valid, "positive_exit_zero": positive_ok, "negative_exit_nonzero": negative_ok, "final_approval": False}, "patch": {"path": patch_relative, "sha256": patch["sha256"], "changed_paths": declared_changed}, "semantic_identity": {"before": before_anchors, "after": after_anchors}, "coverage": {"before": sorted(coverage_before), "after": sorted(coverage_after)}, "agent_attempts": attempts, "agent_audit": agent_audit, "positive_result": positive, "negative_mutation_result": negative, "bindings": {"input_sha256": input_sha}, "authority": AUTHORITY}
    return _write(workspace, receipt, out, f"healing-{input_sha[:16]}.json")[0]


def compile_reality_graph(root: Path, declaration_path: Path, observation_path: Path, out: Path | None = None) -> dict[str, Any]:
    """Compare explicit declared and observed journey sets without inference."""
    return _compile_reality_graph(root, declaration_path, observation_path, out)


def create_failure_capsule(root: Path, input_path: Path, out: Path | None = None) -> dict[str, Any]:
    """Bind one failed step and bounded adjacent evidence into JSON and Markdown."""
    return _create_failure_capsule(root, input_path, out)


def verify_stateful_workflow(root: Path, input_path: Path, out: Path | None = None) -> dict[str, Any]:
    """Prove DAG state flow and cleanup outcomes from explicit run results."""
    return _verify_stateful_workflow(root, input_path, out)


def verify_proof_gated_healing(root: Path, input_path: Path, out: Path | None = None, timeout_seconds: int = 300) -> dict[str, Any]:
    """Run bounded proof commands and independently audit an optional agent attempt."""
    return _verify_proof_gated_healing(root, input_path, out, timeout_seconds)


def _verify_receipt(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("receipt_sha256"), str):
        return None
    core = {key: value for key, value in payload.items() if key != "receipt_sha256"}
    return payload if _digest(core) == payload["receipt_sha256"] else None


def journey_proof_status(root: Path) -> dict[str, Any]:
    """Project only verified local Journey Proof receipts without execution."""
    workspace = _root(root)
    directory = workspace / RECEIPT_DIR
    receipts, invalid = [], []
    for path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
        receipt = _verify_receipt(path)
        relative = path.relative_to(workspace).as_posix()
        if receipt is None:
            invalid.append(relative)
            continue
        receipts.append({
            "path": relative,
            "schema": receipt.get("schema"),
            "marker": receipt.get("marker"),
            "decision": receipt.get("decision"),
            "receipt_sha256": receipt["receipt_sha256"],
            "journey_id": receipt.get("journey_id"),
            "workflow_id": receipt.get("workflow_id"),
            "healing_id": receipt.get("healing_id"),
            "review_mode": receipt.get("review_mode"),
        })
    return {"schema": "factory.journey-proof-status.v1", "marker": "JOURNEY_STATUS_READ_ONLY", "receipts": receipts, "invalid_receipts": invalid, "facts": {"verified_count": len(receipts), "invalid_count": len(invalid)}, "authority": AUTHORITY}
