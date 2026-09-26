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
_SKIP_DIRS = {
    ".git",
    ".factory",
    ".pytest_cache",
    ".mypy_cache",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
}


class JourneyProofError(ValueError):
    """Stable fail-closed input error."""

    def __init__(self, message: str, code: str = "JOURNEY_INPUT_REJECTED") -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


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
        missing = (
            sorted(fields - set(value)) if isinstance(value, dict) else sorted(fields)
        )
        extra = sorted(set(value) - fields) if isinstance(value, dict) else []
        raise JourneyProofError(
            f"{label} fields are not exact; missing={missing}, unknown={extra}"
        )
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
    items = [
        _string(item, f"{label} item") for item in _list(value, label, maximum=maximum)
    ]
    if len(items) != len(set(items)):
        raise JourneyProofError(f"{label} must not contain duplicates")
    return items


def _root(root: Path | str) -> Path:
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise JourneyProofError("root must be an existing directory")
    return workspace


def _contained(
    workspace: Path, value: object, label: str, *, must_exist: bool = True
) -> tuple[Path, str]:
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


def _load(
    workspace: Path, value: Path | str, schema: str, fields: set[str]
) -> tuple[dict[str, Any], str]:
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
    return {
        "path": relative,
        "kind": _string(item["kind"], f"{label}.kind"),
        "sha256": expected,
        "actual_sha256": actual,
        "current": actual == expected,
    }


def _write_text_atomic(target: Path, payload: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _write(
    workspace: Path, value: dict[str, Any], out: Path | str | None, default_name: str
) -> tuple[dict[str, Any], Path]:
    target_value = (
        str(out) if out is not None else (RECEIPT_DIR / default_name).as_posix()
    )
    target, relative = _contained(
        workspace, target_value, "output path", must_exist=False
    )
    if not (
        target == workspace / RECEIPT_DIR / target.name
        or RECEIPT_DIR in target.relative_to(workspace).parents
    ):
        raise JourneyProofError("output path must be below .factory/journey-proof")
    core = {
        **value,
        "markers": sorted(set([*value.get("markers", []), "JOURNEY_RECEIPT_WRITTEN"])),
    }
    receipt = {**core, "receipt_sha256": _digest(core)}
    payload = json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    _write_text_atomic(target, payload)
    return {**receipt, "receipt_path": relative}, target


def _ids(values: object, label: str) -> list[str]:
    normalized = [
        _string(value, f"{label} id").casefold() for value in _list(values, label)
    ]
    if len(normalized) != len(set(normalized)):
        raise JourneyProofError(f"{label} must not contain duplicate normalized ids")
    return sorted(normalized)


def _journey_common(value: dict[str, Any], label: str) -> None:
    _string(value["project_id"], f"{label}.project_id")
    _string(value["journey_id"], f"{label}.journey_id")
    _strings(value["requirements"], f"{label}.requirements")
    _strings(value["outcomes"], f"{label}.outcomes")


def _reality_inputs(
    workspace: Path, declaration_path: Path, observation_path: Path
) -> tuple[dict[str, Any], str, dict[str, Any], str]:
    declaration, declaration_sha = _load(
        workspace,
        declaration_path,
        "factory.journey-declaration.v1",
        {
            "schema",
            "project_id",
            "journey_id",
            "states",
            "transitions",
            "requirements",
            "outcomes",
        },
    )
    observation, observation_sha = _load(
        workspace,
        observation_path,
        "factory.journey-observation.v1",
        {
            "schema",
            "project_id",
            "journey_id",
            "run_id",
            "code_version",
            "environment",
            "states",
            "transitions",
            "requirements",
            "outcomes",
            "observed_at",
        },
    )
    _journey_common(declaration, "declaration")
    _journey_common(observation, "observation")
    if (
        declaration["project_id"] != observation["project_id"]
        or declaration["journey_id"] != observation["journey_id"]
    ):
        raise JourneyProofError("project_id and journey_id must match")
    return declaration, declaration_sha, observation, observation_sha


def _reality_rows(
    declaration: dict[str, Any], observation: dict[str, Any]
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    declared_states = [
        _exact(item, {"id", "requirements", "outcome"}, "declared state")
        for item in _list(declaration["states"], "states")
    ]
    observed_states = [
        _exact(item, {"id"}, "observed state")
        for item in _list(observation["states"], "states")
    ]
    declared_transitions = [
        _exact(item, {"id", "from", "to", "requirements"}, "declared transition")
        for item in _list(declaration["transitions"], "transitions")
    ]
    observed_transitions = [
        _exact(item, {"id", "from", "to", "artifacts"}, "observed transition")
        for item in _list(observation["transitions"], "transitions")
    ]
    _validate_declared_states(declared_states)
    _validate_declared_transitions(declared_transitions)
    return declared_states, observed_states, declared_transitions, observed_transitions


def _validate_declared_states(states: list[dict[str, Any]]) -> None:
    for state in states:
        _strings(state["requirements"], "declared state.requirements")
        if not isinstance(state["outcome"], bool):
            raise JourneyProofError("declared state.outcome must be boolean")


def _validate_declared_transitions(transitions: list[dict[str, Any]]) -> None:
    for transition in transitions:
        _string(transition["from"], "declared transition.from")
        _string(transition["to"], "declared transition.to")
        _strings(transition["requirements"], "declared transition.requirements")


def _reality_categories(
    declaration: dict[str, Any],
    observation: dict[str, Any],
    declared_states: list[dict[str, Any]],
    observed_states: list[dict[str, Any]],
    declared_transitions: list[dict[str, Any]],
    observed_transitions: list[dict[str, Any]],
) -> dict[str, tuple[list[str], list[str]]]:
    return {
        "states": (
            _ids([item["id"] for item in declared_states], "declared states"),
            _ids([item["id"] for item in observed_states], "observed states"),
        ),
        "transitions": (
            _ids([item["id"] for item in declared_transitions], "declared transitions"),
            _ids([item["id"] for item in observed_transitions], "observed transitions"),
        ),
        "requirements": (
            _ids(declaration["requirements"], "declared requirements"),
            _ids(observation["requirements"], "observed requirements"),
        ),
        "outcomes": (
            _ids(declaration["outcomes"], "declared outcomes"),
            _ids(observation["outcomes"], "observed outcomes"),
        ),
    }


def _reality_artifacts(
    workspace: Path, observed_transitions: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    artifacts = []
    for transition_index, transition in enumerate(observed_transitions):
        _string(transition["from"], "observed transition.from")
        _string(transition["to"], "observed transition.to")
        for artifact_index, item in enumerate(
            _list(transition["artifacts"], "transition artifacts", maximum=256)
        ):
            artifacts.append(
                _artifact(
                    workspace,
                    item,
                    f"transition[{transition_index}].artifact[{artifact_index}]",
                )
            )
    return artifacts


def _reality_deltas(
    categories: dict[str, tuple[list[str], list[str]]],
    artifacts: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[str], bool]:
    deltas = {
        name: {
            "missing": sorted(set(declared) - set(observed)),
            "unexpected": sorted(set(observed) - set(declared)),
        }
        for name, (declared, observed) in categories.items()
    }
    stale = sorted({item["path"] for item in artifacts if not item["current"]})
    equal = not stale and all(
        not delta["missing"] and not delta["unexpected"] for delta in deltas.values()
    )
    return deltas, stale, equal


def _write_reality_receipt(
    workspace: Path,
    declaration: dict[str, Any],
    declaration_sha: str,
    observation: dict[str, Any],
    observation_sha: str,
    artifacts: list[dict[str, Any]],
    deltas: dict[str, Any],
    stale: list[str],
    equal: bool,
    out: Path | None,
) -> dict[str, Any]:
    marker = "JOURNEY_REALITY_MATCHED" if equal else "JOURNEY_REALITY_REVIEW_REQUIRED"
    result = {
        "schema": "factory.journey-reality-receipt.v1",
        "marker": marker,
        "markers": ["JOURNEY_INPUT_ACCEPTED", marker],
        "project_id": declaration["project_id"],
        "journey_id": declaration["journey_id"],
        "run_id": _string(observation["run_id"], "run_id"),
        "decision": "matched" if equal else "review_required",
        "facts": {"input_contract_valid": True, "journey_sets_equal": equal},
        "deltas": {**deltas, "stale_artifact_hashes": stale},
        "artifacts": artifacts,
        "bindings": {
            "declaration_sha256": declaration_sha,
            "observation_sha256": observation_sha,
            "code_version": _string(observation["code_version"], "code_version"),
            "environment": observation["environment"],
            "observed_at": _string(observation["observed_at"], "observed_at"),
        },
        "authority": AUTHORITY,
    }
    return _write(
        workspace,
        result,
        out,
        f"reality-{_digest([declaration_sha, observation_sha])[:16]}.json",
    )[0]


def _compile_reality_graph(
    root: Path, declaration_path: Path, observation_path: Path, out: Path | None = None
) -> dict[str, Any]:
    """Compare explicit declared and observed journey sets without inference."""
    workspace = _root(root)
    declaration, declaration_sha, observation, observation_sha = _reality_inputs(
        workspace, declaration_path, observation_path
    )
    declared_states, observed_states, declared_transitions, observed_transitions = (
        _reality_rows(declaration, observation)
    )
    categories = _reality_categories(
        declaration,
        observation,
        declared_states,
        observed_states,
        declared_transitions,
        observed_transitions,
    )
    artifacts = _reality_artifacts(workspace, observed_transitions)
    deltas, stale, equal = _reality_deltas(categories, artifacts)
    return _write_reality_receipt(
        workspace,
        declaration,
        declaration_sha,
        observation,
        observation_sha,
        artifacts,
        deltas,
        stale,
        equal,
        out,
    )


def _failure_capsule_input(
    workspace: Path, input_path: Path
) -> tuple[dict[str, Any], str, str]:
    data, input_sha = _load(
        workspace,
        input_path,
        "factory.failure-capsule-input.v1",
        {
            "schema",
            "project_id",
            "journey_id",
            "run_id",
            "code_version",
            "environment",
            "classification",
            "hypothesis",
            "suggested_repair",
            "failed_step_index",
            "steps",
            "artifacts",
            "reproduction_argv",
            "observed_at",
        },
    )
    classification = _string(data["classification"], "classification")
    if classification not in {kind.value for kind in FailureClass}:
        raise JourneyProofError(
            "classification must use the closed FailureClass taxonomy"
        )
    return data, input_sha, classification


def _failure_step_context(
    data: dict[str, Any],
) -> tuple[list[dict[str, Any]], int, list[int]]:
    steps = [
        _exact(item, {"index", "label", "status"}, "step")
        for item in _list(data["steps"], "steps", maximum=256)
    ]
    if any(
        not isinstance(item["index"], int) or isinstance(item["index"], bool)
        for item in steps
    ):
        raise JourneyProofError("step indexes must be integers")
    indexes = [item["index"] for item in steps]
    if indexes != sorted(indexes) or len(indexes) != len(set(indexes)):
        raise JourneyProofError("step indexes must be unique and ordered")
    failed_index = data["failed_step_index"]
    if (
        not isinstance(failed_index, int)
        or isinstance(failed_index, bool)
        or failed_index not in indexes
    ):
        raise JourneyProofError("failed_step_index must name an existing step")
    failed_position = indexes.index(failed_index)
    context = steps[max(0, failed_position - 1) : failed_position + 2]
    for step in context:
        _string(step["label"], "step.label")
        _string(step["status"], "step.status")
    return context, failed_index, indexes


def _failure_artifacts(
    workspace: Path, data: dict[str, Any], indexes: list[int]
) -> list[dict[str, Any]]:
    artifacts = []
    for index, raw in enumerate(_list(data["artifacts"], "artifacts", maximum=256)):
        item = _exact(raw, {"path", "sha256", "kind", "step_index"}, "artifact")
        verified = _artifact(
            workspace,
            {key: item[key] for key in ("path", "sha256", "kind")},
            f"artifact[{index}]",
        )
        if not verified["current"]:
            raise JourneyProofError(f"artifact hash is stale: {verified['path']}")
        if item["step_index"] not in indexes:
            raise JourneyProofError("artifact.step_index must name an existing step")
        artifacts.append({**verified, "step_index": item["step_index"]})
    return artifacts


def _failure_reproduction(data: dict[str, Any]) -> list[str]:
    argv = _strings(data["reproduction_argv"], "reproduction_argv", maximum=64)
    if not argv:
        raise JourneyProofError("reproduction_argv must not be empty")
    return argv


def _write_failure_capsule(
    workspace: Path,
    data: dict[str, Any],
    input_sha: str,
    classification: str,
    failed_index: int,
    context: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    argv: list[str],
    out: Path | None,
) -> dict[str, Any]:
    result = {
        "schema": "factory.failure-capsule.v1",
        "marker": "FAILURE_CAPSULE_BOUND",
        "markers": ["JOURNEY_INPUT_ACCEPTED", "FAILURE_CAPSULE_BOUND"],
        "project_id": _string(data["project_id"], "project_id"),
        "journey_id": _string(data["journey_id"], "journey_id"),
        "run_id": _string(data["run_id"], "run_id"),
        "decision": "review_required",
        "classification": classification,
        "failed_step_index": failed_index,
        "step_context": context,
        "artifacts": sorted(
            artifacts, key=lambda item: (item["step_index"], item["path"])
        ),
        "hypothesis": {
            "trust": "unverified",
            "text": _string(data["hypothesis"], "hypothesis"),
        },
        "suggested_repair": {
            "trust": "unverified",
            "text": _string(data["suggested_repair"], "suggested_repair"),
        },
        "reproduction_argv": argv,
        "bindings": {
            "input_sha256": input_sha,
            "code_version": _string(data["code_version"], "code_version"),
            "environment": data["environment"],
            "observed_at": _string(data["observed_at"], "observed_at"),
        },
        "authority": AUTHORITY,
    }
    receipt, target = _write(workspace, result, out, f"capsule-{input_sha[:16]}.json")
    markdown = [
        f"# Failure Capsule: {receipt['journey_id']}",
        "",
        f"- Classification: `{classification}`",
        "- Hypothesis trust: `unverified`",
        f"- Receipt SHA-256: `{receipt['receipt_sha256']}`",
        "",
        "## Bounded step context",
        "",
    ]
    markdown.extend(
        f"- {step['index']}: {step['label']} (`{step['status']}`)" for step in context
    )
    markdown.extend(
        [
            "",
            "## Hypothesis",
            "",
            receipt["hypothesis"]["text"],
            "",
            "## Suggested repair",
            "",
            receipt["suggested_repair"]["text"],
            "",
        ]
    )
    _write_text_atomic(target.with_suffix(".md"), "\n".join(markdown))
    return {
        **receipt,
        "markdown_path": target.with_suffix(".md").relative_to(workspace).as_posix(),
    }


def _create_failure_capsule(
    root: Path, input_path: Path, out: Path | None = None
) -> dict[str, Any]:
    """Bind one failed step and bounded adjacent evidence into JSON and Markdown."""
    workspace = _root(root)
    data, input_sha, classification = _failure_capsule_input(workspace, input_path)
    context, failed_index, indexes = _failure_step_context(data)
    artifacts = _failure_artifacts(workspace, data, indexes)
    argv = _failure_reproduction(data)
    return _write_failure_capsule(
        workspace,
        data,
        input_sha,
        classification,
        failed_index,
        context,
        artifacts,
        argv,
        out,
    )


def _workflow_graph(
    tests: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], bool]:
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
                raise JourneyProofError(
                    "dependencies must name different existing tests"
                )
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


def _workflow_input(workspace: Path, input_path: Path) -> tuple[dict[str, Any], str]:
    return _load(
        workspace,
        input_path,
        "factory.stateful-workflow-input.v1",
        {
            "schema",
            "project_id",
            "workflow_id",
            "run_id",
            "code_version",
            "environment",
            "tests",
            "results",
            "observed_at",
        },
    )


def _workflow_rows(
    data: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, dict[str, Any]],
    bool,
    dict[str, int],
]:
    test_fields = {
        "id",
        "index",
        "depends_on",
        "produces",
        "consumes",
        "side_effects",
        "cleanup_for",
        "is_cleanup",
    }
    result_fields = {
        "test_id",
        "status",
        "produced",
        "consumed",
        "side_effects_created",
        "cleanup_completed",
        "idempotency_probe_passed",
    }
    tests = [
        _exact(item, test_fields, "test")
        for item in _list(data["tests"], "tests", maximum=256)
    ]
    results = [
        _exact(item, result_fields, "result")
        for item in _list(data["results"], "results", maximum=256)
    ]
    by_id, acyclic = _workflow_graph(tests)
    indexes: dict[str, int] = {}
    for test_id, item in by_id.items():
        if not isinstance(item["index"], int) or isinstance(item["index"], bool):
            raise JourneyProofError("test.index must be an integer")
        indexes[test_id] = item["index"]
        _strings(item["produces"], "produces")
        _strings(item["consumes"], "consumes")
        _strings(item["side_effects"], "side_effects")
        _strings(item["cleanup_for"], "cleanup_for")
        if not isinstance(item["is_cleanup"], bool):
            raise JourneyProofError("is_cleanup must be boolean")
    if len(set(indexes.values())) != len(indexes):
        raise JourneyProofError("test indexes must be unique")
    return tests, results, by_id, acyclic, indexes


def _workflow_result_map(
    results: list[dict[str, Any]], by_id: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    result_map: dict[str, dict[str, Any]] = {}
    for item in results:
        test_id = _string(item["test_id"], "result.test_id")
        if test_id not in by_id or test_id in result_map:
            raise JourneyProofError("results must name unique existing tests")
        if not isinstance(item["produced"], dict) or not isinstance(
            item["consumed"], dict
        ):
            raise JourneyProofError("produced and consumed results must be objects")
        for key, value in [*item["produced"].items(), *item["consumed"].items()]:
            _string(key, "state value name")
            _sha(value, "state value hash")
        _strings(item["side_effects_created"], "side_effects_created")
        _strings(item["cleanup_completed"], "cleanup_completed")
        if item["idempotency_probe_passed"] is not None and not isinstance(
            item["idempotency_probe_passed"], bool
        ):
            raise JourneyProofError("idempotency_probe_passed must be boolean or null")
        result_map[test_id] = item
    return result_map


def _workflow_initial_reasons(
    by_id: dict[str, dict[str, Any]],
    result_map: dict[str, dict[str, Any]],
    acyclic: bool,
) -> set[str]:
    reason_codes: set[str] = set()
    if not acyclic:
        reason_codes.add("WORKFLOW_CYCLE_DETECTED")
    if set(result_map) != set(by_id) or any(
        item["status"] != "passed" for item in result_map.values()
    ):
        reason_codes.add("WORKFLOW_EXECUTION_INCOMPLETE")
    return reason_codes


def _workflow_producers(
    by_id: dict[str, dict[str, Any]], result_map: dict[str, dict[str, Any]]
) -> dict[str, list[tuple[str, str]]]:
    producers: dict[str, list[tuple[str, str]]] = {}
    for test_id, test in by_id.items():
        result = result_map.get(test_id, {})
        for name in test["produces"]:
            if name in result.get("produced", {}):
                producers.setdefault(name, []).append(
                    (test_id, result["produced"][name])
                )
    return producers


def _workflow_value_edges(
    by_id: dict[str, dict[str, Any]],
    indexes: dict[str, int],
    result_map: dict[str, dict[str, Any]],
    producers: dict[str, list[tuple[str, str]]],
    reason_codes: set[str],
) -> list[dict[str, str]]:
    value_edges = []
    for test_id, test in by_id.items():
        consumed = result_map.get(test_id, {}).get("consumed", {})
        for name in test["consumes"]:
            matches = producers.get(name, [])
            if len(matches) != 1 or name not in consumed:
                reason_codes.add("WORKFLOW_VALUE_PRODUCER_INVALID")
                continue
            producer_id, produced_hash = matches[0]
            if (
                indexes[producer_id] >= indexes[test_id]
                or produced_hash != consumed[name]
            ):
                reason_codes.add("WORKFLOW_VALUE_HASH_MISMATCH")
            value_edges.append(
                {
                    "producer": producer_id,
                    "consumer": test_id,
                    "value": name,
                    "sha256": produced_hash,
                }
            )
    return value_edges


def _workflow_declaration_reasons(
    by_id: dict[str, dict[str, Any]],
    result_map: dict[str, dict[str, Any]],
    reason_codes: set[str],
) -> None:
    for test_id, result in result_map.items():
        test = by_id[test_id]
        if set(result["produced"]) != set(test["produces"]) or set(
            result["consumed"]
        ) != set(test["consumes"]):
            reason_codes.add("WORKFLOW_VALUE_DECLARATION_MISMATCH")
        if set(result["side_effects_created"]) != set(test["side_effects"]):
            reason_codes.add("WORKFLOW_CLEANUP_MISSING")
        if test["is_cleanup"] and set(result["cleanup_completed"]) != set(
            test["cleanup_for"]
        ):
            reason_codes.add("WORKFLOW_CLEANUP_MISSING")


def _effect_cleanup_matches(
    effect: str,
    test_id: str,
    by_id: dict[str, dict[str, Any]],
    indexes: dict[str, int],
    result_map: dict[str, dict[str, Any]],
) -> list[str]:
    matches = []
    for cleanup_id, cleanup in by_id.items():
        if not cleanup["is_cleanup"] or effect not in cleanup["cleanup_for"]:
            continue
        if indexes[cleanup_id] <= indexes[test_id]:
            continue
        cleanup_result = result_map.get(cleanup_id, {})
        if cleanup_result.get("status") != "passed":
            continue
        if effect not in cleanup_result.get("cleanup_completed", []):
            continue
        if cleanup_result.get("idempotency_probe_passed") is not True:
            continue
        matches.append(cleanup_id)
    return matches


def _workflow_effect_cleanup_reasons(
    by_id: dict[str, dict[str, Any]],
    indexes: dict[str, int],
    result_map: dict[str, dict[str, Any]],
    reason_codes: set[str],
) -> None:
    for test_id, result in result_map.items():
        for effect in result["side_effects_created"]:
            if not _effect_cleanup_matches(effect, test_id, by_id, indexes, result_map):
                reason_codes.add("WORKFLOW_CLEANUP_MISSING")


def _workflow_idempotency_reasons(
    by_id: dict[str, dict[str, Any]],
    result_map: dict[str, dict[str, Any]],
    reason_codes: set[str],
) -> None:
    for test_id, test in by_id.items():
        if (
            test["is_cleanup"]
            and result_map.get(test_id, {}).get("idempotency_probe_passed") is not True
        ):
            reason_codes.add("WORKFLOW_CLEANUP_IDEMPOTENCY_FAILED")


def _workflow_validity(
    acyclic: bool, reason_codes: set[str]
) -> tuple[bool, bool, bool]:
    values_valid = not any(
        code.startswith("WORKFLOW_VALUE") or code == "WORKFLOW_EXECUTION_INCOMPLETE"
        for code in reason_codes
    )
    cleanup_valid = not any(
        code.startswith("WORKFLOW_CLEANUP") for code in reason_codes
    )
    passed = acyclic and values_valid and cleanup_valid and not reason_codes
    return values_valid, cleanup_valid, passed


def _write_workflow_receipt(
    workspace: Path,
    data: dict[str, Any],
    input_sha: str,
    acyclic: bool,
    values_valid: bool,
    cleanup_valid: bool,
    passed: bool,
    reason_codes: set[str],
    value_edges: list[dict[str, str]],
    out: Path | None,
) -> dict[str, Any]:
    marker = "WORKFLOW_PROOF_PASSED" if passed else "WORKFLOW_PROOF_FAILED"
    receipt = {
        "schema": "factory.stateful-workflow-receipt.v1",
        "marker": marker,
        "markers": sorted({"JOURNEY_INPUT_ACCEPTED", marker, *reason_codes}),
        "project_id": _string(data["project_id"], "project_id"),
        "workflow_id": _string(data["workflow_id"], "workflow_id"),
        "run_id": _string(data["run_id"], "run_id"),
        "decision": "passed" if passed else "failed",
        "facts": {
            "input_contract_valid": True,
            "workflow_acyclic": acyclic,
            "workflow_values_valid": values_valid,
            "workflow_cleanup_valid": cleanup_valid,
        },
        "reason_codes": sorted(reason_codes),
        "value_edges": sorted(
            value_edges,
            key=lambda item: (item["producer"], item["consumer"], item["value"]),
        ),
        "bindings": {
            "input_sha256": input_sha,
            "code_version": _string(data["code_version"], "code_version"),
            "environment": data["environment"],
            "observed_at": _string(data["observed_at"], "observed_at"),
        },
        "authority": AUTHORITY,
    }
    return _write(workspace, receipt, out, f"workflow-{input_sha[:16]}.json")[0]


def _verify_stateful_workflow(
    root: Path, input_path: Path, out: Path | None = None
) -> dict[str, Any]:
    """Prove DAG state flow and cleanup outcomes from explicit run results."""
    workspace = _root(root)
    data, input_sha = _workflow_input(workspace, input_path)
    _, results, by_id, acyclic, indexes = _workflow_rows(data)
    result_map = _workflow_result_map(results, by_id)
    reason_codes = _workflow_initial_reasons(by_id, result_map, acyclic)
    producers = _workflow_producers(by_id, result_map)
    value_edges = _workflow_value_edges(
        by_id, indexes, result_map, producers, reason_codes
    )
    _workflow_declaration_reasons(by_id, result_map, reason_codes)
    _workflow_effect_cleanup_reasons(by_id, indexes, result_map, reason_codes)
    _workflow_idempotency_reasons(by_id, result_map, reason_codes)
    values_valid, cleanup_valid, passed = _workflow_validity(acyclic, reason_codes)
    return _write_workflow_receipt(
        workspace,
        data,
        input_sha,
        acyclic,
        values_valid,
        cleanup_valid,
        passed,
        reason_codes,
        value_edges,
        out,
    )


def _snapshot(workspace: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for path in sorted(workspace.rglob("*")):
        relative = path.relative_to(workspace)
        if (
            path.is_symlink()
            or not path.is_file()
            or any(part in _SKIP_DIRS for part in relative.parts)
        ):
            continue
        values[relative.as_posix()] = _sha_file(path)
        if len(values) > 20_000:
            raise JourneyProofError(
                "workspace snapshot exceeds 20000 files", "HEALING_AGENT_AUDIT_FAILED"
            )
    return values


def _snapshot_digest(snapshot: dict[str, str]) -> str:
    return _digest(snapshot)


def _changed(before: dict[str, str], after: dict[str, str]) -> list[str]:
    return sorted(
        path for path in set(before) | set(after) if before.get(path) != after.get(path)
    )


def _allowed(path: str, allowlist: list[str]) -> bool:
    return any(
        path == allowed or path.startswith(allowed.rstrip("/") + "/")
        for allowed in allowlist
    )


def _run(argv: list[str], workspace: Path, timeout: int) -> dict[str, Any]:
    return run_supervised_command(argv, cwd=workspace, timeout_seconds=timeout)


def _human_agent_contract(value: object) -> None:
    if value is not None:
        raise JourneyProofError(
            "human_controlled mode forbids an agent command",
            "HEALING_REVIEW_MODE_INVALID",
        )


def _agent_identity(agent: dict[str, Any]) -> dict[str, Any]:
    identity = _exact(
        agent["identity"], {"provider", "subject", "display_name"}, "agent.identity"
    )
    for key in identity:
        _string(identity[key], f"agent.identity.{key}")
    return identity


def _agent_execution_contract(agent: dict[str, Any]) -> tuple[list[str], int, int]:
    argv = _strings(agent["argv"], "agent.argv", maximum=64)
    attempts, timeout = agent["max_attempts"], agent["timeout_seconds"]
    if (
        not argv
        or not isinstance(attempts, int)
        or isinstance(attempts, bool)
        or not 1 <= attempts <= 3
        or not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or not 1 <= timeout <= 900
    ):
        raise JourneyProofError(
            "supervised_auto requires argv, max_attempts 1..3, and timeout_seconds 1..900",
            "HEALING_REVIEW_MODE_INVALID",
        )
    return argv, attempts, timeout


def _agent_contract(value: object, review_mode: str) -> dict[str, Any] | None:
    if review_mode == "human_controlled":
        _human_agent_contract(value)
        return None
    agent = _exact(
        value, {"identity", "argv", "max_attempts", "timeout_seconds"}, "agent"
    )
    identity = _agent_identity(agent)
    argv, attempts, timeout = _agent_execution_contract(agent)
    return {
        "identity": identity,
        "argv": argv,
        "max_attempts": attempts,
        "timeout_seconds": timeout,
    }


def _anchors(value: object, label: str) -> dict[str, str]:
    anchors = _exact(value, {"role", "label", "route", "state"}, label)
    return {key: _string(anchors[key], f"{label}.{key}") for key in sorted(anchors)}


def _agent_outcome(
    scope_ok: bool,
    agent_result: dict[str, Any] | None,
    positive: dict[str, Any] | None,
    negative: dict[str, Any] | None,
) -> tuple[str, FailureClass | None]:
    if not scope_ok:
        return "scope_escape", FailureClass.SCOPE_ESCAPE
    execution = _agent_execution_outcome(agent_result)
    if execution is not None:
        return execution
    if positive and positive.get("exit_code") != 0:
        return "positive_failed", FailureClass.WRONG_OUTPUT
    if negative and negative.get("exit_code") == 0:
        return "hollow_negative", FailureClass.HOLLOW_TEST
    return "passed", None


def _agent_execution_outcome(
    agent_result: dict[str, Any] | None,
) -> tuple[str, FailureClass] | None:
    if agent_result is None:
        return "not_started", FailureClass.HOLLOW_MANIFEST
    if agent_result and agent_result.get("timed_out"):
        return "agent_timeout", FailureClass.RUNTIME_TIMEOUT
    if agent_result and agent_result.get("exit_code") != 0:
        return "agent_failed", FailureClass.RUNTIME_CRASH
    return None


def _healing_input(workspace: Path, input_path: Path) -> tuple[dict[str, Any], str]:
    return _load(
        workspace,
        input_path,
        "factory.proof-gated-healing-input.v1",
        {
            "schema",
            "healing_id",
            "review_mode",
            "agent",
            "patch",
            "allowed_paths",
            "semantic_identity",
            "coverage_before",
            "coverage_after",
            "positive_argv",
            "negative_argv",
        },
    )


def _healing_review_mode(data: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    review_mode = _string(data["review_mode"], "review_mode")
    if review_mode not in {"human_controlled", "supervised_auto"}:
        raise JourneyProofError(
            "review_mode must be human_controlled or supervised_auto",
            "HEALING_REVIEW_MODE_INVALID",
        )
    agent = _agent_contract(data["agent"], review_mode)
    return review_mode, agent


def _healing_scope(
    workspace: Path, data: dict[str, Any]
) -> tuple[dict[str, Any], str, list[str], list[str], bool]:
    patch = _exact(data["patch"], {"path", "sha256", "changed_paths"}, "patch")
    patch_path, patch_relative = _contained(workspace, patch["path"], "patch.path")
    patch_current = _sha_file(patch_path) == _sha(patch["sha256"], "patch.sha256")
    allowlist = sorted(
        _contained(workspace, value, "allowed path", must_exist=False)[1]
        for value in _strings(data["allowed_paths"], "allowed_paths")
    )
    declared_changed = sorted(
        _contained(workspace, value, "changed path", must_exist=False)[1]
        for value in _strings(patch["changed_paths"], "patch.changed_paths")
    )
    if not allowlist or not declared_changed:
        raise JourneyProofError(
            "allowed_paths and patch.changed_paths must not be empty"
        )
    scope_valid = patch_current and all(
        _allowed(path, allowlist) for path in declared_changed
    )
    return patch, patch_relative, allowlist, declared_changed, scope_valid


def _healing_semantics(
    data: dict[str, Any],
) -> tuple[dict[str, str], dict[str, str], bool, set[str], set[str], bool]:
    semantic = _exact(
        data["semantic_identity"], {"before", "after"}, "semantic_identity"
    )
    before_anchors, after_anchors = (
        _anchors(semantic["before"], "before"),
        _anchors(semantic["after"], "after"),
    )
    semantic_valid = before_anchors == after_anchors
    coverage_before = set(_strings(data["coverage_before"], "coverage_before"))
    coverage_after = set(_strings(data["coverage_after"], "coverage_after"))
    coverage_preserved = coverage_before <= coverage_after
    return (
        before_anchors,
        after_anchors,
        semantic_valid,
        coverage_before,
        coverage_after,
        coverage_preserved,
    )


def _healing_commands(
    data: dict[str, Any], timeout_seconds: int
) -> tuple[list[str], list[str]]:
    positive_argv = _strings(data["positive_argv"], "positive_argv", maximum=64)
    negative_argv = _strings(data["negative_argv"], "negative_argv", maximum=64)
    if (
        not positive_argv
        or not negative_argv
        or not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or not 1 <= timeout_seconds <= 900
    ):
        raise JourneyProofError(
            "positive and negative argv and timeout 1..900 are required"
        )
    return positive_argv, negative_argv


def _run_agent_attempts(
    workspace: Path,
    agent: dict[str, Any] | None,
    review_mode: str,
    scope_valid: bool,
    semantic_valid: bool,
    coverage_preserved: bool,
    allowlist: list[str],
) -> tuple[list[dict[str, Any]], list[str], bool, bool, dict[str, str], dict[str, str]]:
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
            attempts.append(
                {
                    "attempt": number,
                    "before_workspace_sha256": _snapshot_digest(before),
                    "after_workspace_sha256": _snapshot_digest(after),
                    "changed_paths": changed,
                    "scope_valid": attempt_scope,
                    "result": run,
                }
            )
            actual_changed = sorted(set(actual_changed) | set(changed))
            last_snapshot = after
            if not attempt_scope:
                agent_scope_valid = False
                break
            if run.get("exit_code") == 0:
                agent_exit_zero = True
                break
    return (
        attempts,
        actual_changed,
        agent_scope_valid,
        agent_exit_zero,
        first_snapshot,
        last_snapshot,
    )


def _healing_precheck(
    scope_valid: bool,
    semantic_valid: bool,
    coverage_preserved: bool,
    agent_scope_valid: bool,
    review_mode: str,
    agent_exit_zero: bool,
) -> bool:
    precheck = (
        scope_valid
        and semantic_valid
        and coverage_preserved
        and agent_scope_valid
        and (review_mode == "human_controlled" or agent_exit_zero)
    )
    return precheck


def _run_healing_proofs(
    workspace: Path,
    positive_argv: list[str],
    negative_argv: list[str],
    timeout_seconds: int,
    precheck: bool,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, bool, bool]:
    positive = _run(positive_argv, workspace, timeout_seconds) if precheck else None
    negative = (
        _run(negative_argv, workspace, timeout_seconds)
        if positive and positive.get("exit_code") == 0
        else None
    )
    positive_ok = bool(positive and positive.get("exit_code") == 0)
    negative_ok = bool(negative and negative.get("exit_code") not in {None, 0})
    return positive, negative, positive_ok, negative_ok


def _agent_audit_core(
    data: dict[str, Any],
    input_sha: str,
    agent: dict[str, Any],
    attempts: list[dict[str, Any]],
    first_snapshot: dict[str, str],
    last_snapshot: dict[str, str],
    actual_changed: list[str],
    agent_scope_valid: bool,
    positive: dict[str, Any] | None,
    negative: dict[str, Any] | None,
) -> dict[str, Any]:
    last_run = attempts[-1]["result"] if attempts else None
    outcome, failure_classification = _agent_outcome(
        agent_scope_valid, last_run, positive, negative
    )
    return {
        "schema": "factory.agent-work-audit.v1",
        "marker": "AGENT_WORK_AUDITED",
        "healing_id": _string(data["healing_id"], "healing_id"),
        "agent_identity": agent["identity"],
        "command_sha256": _digest(agent["argv"]),
        "before_workspace_sha256": _snapshot_digest(first_snapshot),
        "after_workspace_sha256": _snapshot_digest(last_snapshot),
        "changed_paths": actual_changed,
        "scope_valid": agent_scope_valid,
        "agent_result": last_run,
        "positive_result": positive,
        "negative_mutation_result": negative,
        "outcome_classification": outcome,
        "failure_classification": failure_classification.value
        if failure_classification
        else None,
        "worker_approval": False,
        "authority": AUTHORITY,
    }


def _write_agent_audit(
    workspace: Path, input_sha: str, audit_core: dict[str, Any]
) -> dict[str, Any]:
    try:
        audit_receipt, _ = _write(
            workspace, audit_core, None, f"agent-audit-{input_sha[:16]}.json"
        )
    except (JourneyProofError, OSError) as error:
        raise JourneyProofError(
            "FactoryLine could not bind the agent work audit",
            "HEALING_AGENT_AUDIT_FAILED",
        ) from error
    return {
        "path": audit_receipt["receipt_path"],
        "sha256": audit_receipt["receipt_sha256"],
        "marker": audit_receipt["marker"],
        "authority": audit_receipt["authority"],
        "worker_approval": audit_receipt["worker_approval"],
    }


def _agent_audit(
    workspace: Path,
    data: dict[str, Any],
    input_sha: str,
    review_mode: str,
    agent: dict[str, Any] | None,
    attempts: list[dict[str, Any]],
    first_snapshot: dict[str, str],
    last_snapshot: dict[str, str],
    actual_changed: list[str],
    agent_scope_valid: bool,
    positive: dict[str, Any] | None,
    negative: dict[str, Any] | None,
    markers: set[str],
) -> tuple[dict[str, str] | None, bool]:
    if agent is None:
        return None, review_mode == "human_controlled"
    audit_core = _agent_audit_core(
        data,
        input_sha,
        agent,
        attempts,
        first_snapshot,
        last_snapshot,
        actual_changed,
        agent_scope_valid,
        positive,
        negative,
    )
    audit = _write_agent_audit(workspace, input_sha, audit_core)
    audit_valid = (
        audit["marker"] == "AGENT_WORK_AUDITED"
        and audit["authority"] == AUTHORITY
        and audit["worker_approval"] is False
    )
    markers.add("AGENT_WORK_AUDITED")
    return {key: audit[key] for key in ("path", "sha256", "marker")}, audit_valid


def _early_healing_marker(
    markers: set[str],
    review_mode: str,
    scope_valid: bool,
    semantic_valid: bool,
    coverage_preserved: bool,
    agent_scope_valid: bool,
    agent_exit_zero: bool,
) -> bool:
    if not scope_valid or not semantic_valid or not coverage_preserved:
        markers.add("HEALING_PRECHECK_REJECTED")
        return True
    if not agent_scope_valid:
        markers.add("HEALING_AGENT_SCOPE_ESCAPE")
        return True
    if review_mode == "supervised_auto" and not agent_exit_zero:
        markers.add("HEALING_AGENT_FAILED")
        return True
    return False


def _proof_status_marker(
    markers: set[str],
    review_mode: str,
    audit_valid: bool,
    positive_ok: bool,
    negative_ok: bool,
) -> None:
    if not audit_valid:
        markers.add("HEALING_AGENT_AUDIT_FAILED")
    elif not positive_ok:
        markers.add("HEALING_POSITIVE_FAILED")
    elif not negative_ok:
        markers.add("HOLLOW_HEALING_PROOF")
    else:
        markers.update(
            {
                "HEALING_PROOF_ADMISSIBLE",
                "HEALING_HUMAN_REVIEW_REQUIRED"
                if review_mode == "human_controlled"
                else "HEALING_AUTO_AWAITING_PROMOTION",
            }
        )


def _apply_healing_markers(
    markers: set[str],
    review_mode: str,
    scope_valid: bool,
    semantic_valid: bool,
    coverage_preserved: bool,
    agent_scope_valid: bool,
    agent_exit_zero: bool,
    audit_valid: bool,
    positive_ok: bool,
    negative_ok: bool,
) -> None:
    if _early_healing_marker(
        markers,
        review_mode,
        scope_valid,
        semantic_valid,
        coverage_preserved,
        agent_scope_valid,
        agent_exit_zero,
    ):
        return
    _proof_status_marker(markers, review_mode, audit_valid, positive_ok, negative_ok)


def _primary_healing_marker(markers: set[str]) -> str:
    if "HEALING_PROOF_ADMISSIBLE" in markers:
        return "HEALING_PROOF_ADMISSIBLE"
    return next(
        marker
        for marker in (
            "HEALING_PRECHECK_REJECTED",
            "HEALING_AGENT_SCOPE_ESCAPE",
            "HEALING_AGENT_FAILED",
            "HEALING_AGENT_AUDIT_FAILED",
            "HEALING_POSITIVE_FAILED",
            "HOLLOW_HEALING_PROOF",
        )
        if marker in markers
    )


def _write_healing_receipt(
    workspace: Path,
    data: dict[str, Any],
    input_sha: str,
    review_mode: str,
    patch: dict[str, Any],
    patch_relative: str,
    declared_changed: list[str],
    before_anchors: dict[str, str],
    after_anchors: dict[str, str],
    coverage_before: set[str],
    coverage_after: set[str],
    scope_valid: bool,
    semantic_valid: bool,
    coverage_preserved: bool,
    agent_scope_valid: bool,
    agent_exit_zero: bool,
    audit_valid: bool,
    positive_ok: bool,
    negative_ok: bool,
    attempts: list[dict[str, Any]],
    agent_audit: dict[str, str] | None,
    positive: dict[str, Any] | None,
    negative: dict[str, Any] | None,
    markers: set[str],
    out: Path | None,
) -> dict[str, Any]:
    admissible = "HEALING_PROOF_ADMISSIBLE" in markers
    primary = _primary_healing_marker(markers)
    receipt = {
        "schema": "factory.proof-gated-healing-receipt.v1",
        "marker": primary,
        "markers": sorted(markers),
        "healing_id": data["healing_id"],
        "review_mode": review_mode,
        "decision": "admissible_for_human_review" if admissible else "rejected",
        "facts": {
            "input_contract_valid": True,
            "review_mode_valid": True,
            "healing_scope_valid": scope_valid,
            "semantic_identity_valid": semantic_valid,
            "coverage_preserved": coverage_preserved,
            "agent_scope_valid": agent_scope_valid,
            "agent_command_exit_zero": agent_exit_zero,
            "agent_audit_valid": audit_valid,
            "positive_exit_zero": positive_ok,
            "negative_exit_nonzero": negative_ok,
            "final_approval": False,
        },
        "patch": {
            "path": patch_relative,
            "sha256": patch["sha256"],
            "changed_paths": declared_changed,
        },
        "semantic_identity": {"before": before_anchors, "after": after_anchors},
        "coverage": {
            "before": sorted(coverage_before),
            "after": sorted(coverage_after),
        },
        "agent_attempts": attempts,
        "agent_audit": agent_audit,
        "positive_result": positive,
        "negative_mutation_result": negative,
        "bindings": {"input_sha256": input_sha},
        "authority": AUTHORITY,
    }
    return _write(workspace, receipt, out, f"healing-{input_sha[:16]}.json")[0]


def _verify_proof_gated_healing(
    root: Path, input_path: Path, out: Path | None = None, timeout_seconds: int = 300
) -> dict[str, Any]:
    """Run bounded proof commands and independently audit an optional agent attempt."""
    workspace = _root(root)
    data, input_sha = _healing_input(workspace, input_path)
    review_mode, agent = _healing_review_mode(data)
    patch, patch_relative, allowlist, declared_changed, scope_valid = _healing_scope(
        workspace, data
    )
    (
        before_anchors,
        after_anchors,
        semantic_valid,
        coverage_before,
        coverage_after,
        coverage_preserved,
    ) = _healing_semantics(data)
    positive_argv, negative_argv = _healing_commands(data, timeout_seconds)
    (
        attempts,
        actual_changed,
        agent_scope_valid,
        agent_exit_zero,
        first_snapshot,
        last_snapshot,
    ) = _run_agent_attempts(
        workspace,
        agent,
        review_mode,
        scope_valid,
        semantic_valid,
        coverage_preserved,
        allowlist,
    )
    precheck = _healing_precheck(
        scope_valid,
        semantic_valid,
        coverage_preserved,
        agent_scope_valid,
        review_mode,
        agent_exit_zero,
    )
    positive, negative, positive_ok, negative_ok = _run_healing_proofs(
        workspace, positive_argv, negative_argv, timeout_seconds, precheck
    )
    markers = {"JOURNEY_INPUT_ACCEPTED"}
    agent_audit, audit_valid = _agent_audit(
        workspace,
        data,
        input_sha,
        review_mode,
        agent,
        attempts,
        first_snapshot,
        last_snapshot,
        actual_changed,
        agent_scope_valid,
        positive,
        negative,
        markers,
    )
    _apply_healing_markers(
        markers,
        review_mode,
        scope_valid,
        semantic_valid,
        coverage_preserved,
        agent_scope_valid,
        agent_exit_zero,
        audit_valid,
        positive_ok,
        negative_ok,
    )
    return _write_healing_receipt(
        workspace,
        data,
        input_sha,
        review_mode,
        patch,
        patch_relative,
        declared_changed,
        before_anchors,
        after_anchors,
        coverage_before,
        coverage_after,
        scope_valid,
        semantic_valid,
        coverage_preserved,
        agent_scope_valid,
        agent_exit_zero,
        audit_valid,
        positive_ok,
        negative_ok,
        attempts,
        agent_audit,
        positive,
        negative,
        markers,
        out,
    )


def compile_reality_graph(
    root: Path, declaration_path: Path, observation_path: Path, out: Path | None = None
) -> dict[str, Any]:
    """Compare explicit declared and observed journey sets without inference."""
    return _compile_reality_graph(root, declaration_path, observation_path, out)


def create_failure_capsule(
    root: Path, input_path: Path, out: Path | None = None
) -> dict[str, Any]:
    """Bind one failed step and bounded adjacent evidence into JSON and Markdown."""
    return _create_failure_capsule(root, input_path, out)


def _validate_failure_capsule_identity(data: dict[str, Any]) -> None:
    if (
        data["schema"] != "factory.failure-capsule.v1"
        or data["marker"] != "FAILURE_CAPSULE_BOUND"
    ):
        raise JourneyProofError("failure capsule schema or marker is invalid")
    if data["markers"] != [
        "FAILURE_CAPSULE_BOUND",
        "JOURNEY_INPUT_ACCEPTED",
        "JOURNEY_RECEIPT_WRITTEN",
    ]:
        raise JourneyProofError("failure capsule markers are invalid")
    if data["decision"] != "review_required" or data["authority"] != AUTHORITY:
        raise JourneyProofError("failure capsule authority boundary is invalid")
    if _digest(
        {key: item for key, item in data.items() if key != "receipt_sha256"}
    ) != _sha(data["receipt_sha256"], "receipt_sha256"):
        raise JourneyProofError("failure capsule receipt hash does not match")
    if _string(data["classification"], "classification") not in {
        kind.value for kind in FailureClass
    }:
        raise JourneyProofError("failure capsule classification is invalid")
    if not isinstance(data["failed_step_index"], int) or isinstance(
        data["failed_step_index"], bool
    ):
        raise JourneyProofError("failure capsule failed_step_index is invalid")


def _validate_failure_step_context(data: dict[str, Any]) -> list[int]:
    context = [
        _exact(item, {"index", "label", "status"}, "failure capsule step")
        for item in _list(data["step_context"], "step_context", maximum=3)
    ]
    indexes = [item["index"] for item in context]
    if (
        not context
        or indexes != sorted(indexes)
        or data["failed_step_index"] not in indexes
    ):
        raise JourneyProofError("failure capsule step context is invalid")
    for item in context:
        if not isinstance(item["index"], int) or isinstance(item["index"], bool):
            raise JourneyProofError("failure capsule step index is invalid")
        _string(item["label"], "failure capsule step label")
        _string(item["status"], "failure capsule step status")
    return indexes


def _validate_failure_artifacts(
    workspace: Path, data: dict[str, Any], indexes: list[int]
) -> None:
    for index, artifact in enumerate(
        _list(data["artifacts"], "artifacts", maximum=256)
    ):
        item = _exact(
            artifact,
            {"path", "sha256", "actual_sha256", "kind", "current", "step_index"},
            "failure capsule artifact",
        )
        if (
            item["current"] is not True
            or item["actual_sha256"] != item["sha256"]
            or item["step_index"] not in indexes
        ):
            raise JourneyProofError(
                "failure capsule artifact is not current or not bound to context"
            )
        verified = _artifact(
            workspace,
            {key: item[key] for key in ("path", "sha256", "kind")},
            f"failure capsule artifact[{index}]",
        )
        if not verified["current"]:
            raise JourneyProofError("failure capsule artifact hash is stale")


def _validate_failure_claims(data: dict[str, Any]) -> None:
    for label in ("project_id", "journey_id", "run_id"):
        _string(data[label], f"failure capsule {label}")
    if (
        not isinstance(data["hypothesis"], dict)
        or data["hypothesis"].get("trust") != "unverified"
    ):
        raise JourneyProofError("failure capsule hypothesis trust is invalid")
    if (
        not isinstance(data["suggested_repair"], dict)
        or data["suggested_repair"].get("trust") != "unverified"
    ):
        raise JourneyProofError("failure capsule suggested repair trust is invalid")
    _string(data["hypothesis"].get("text"), "failure capsule hypothesis")
    _string(data["suggested_repair"].get("text"), "failure capsule suggested repair")
    if not isinstance(data["bindings"], dict) or set(data["bindings"]) != {
        "input_sha256",
        "code_version",
        "environment",
        "observed_at",
    }:
        raise JourneyProofError("failure capsule bindings are invalid")
    _sha(data["bindings"]["input_sha256"], "failure capsule input_sha256")
    _string(data["bindings"]["code_version"], "failure capsule code_version")
    _string(data["bindings"]["observed_at"], "failure capsule observed_at")
    if not isinstance(data["bindings"]["environment"], dict):
        raise JourneyProofError("failure capsule environment binding is invalid")
    if not _strings(
        data["reproduction_argv"], "failure capsule reproduction_argv", maximum=64
    ):
        raise JourneyProofError("failure capsule reproduction argv is empty")


def validate_failure_capsule(root: Path, value: object) -> dict[str, Any]:
    """Validate an immutable, locally bound failure capsule before it is reused.

    This deliberately re-checks the receipt digest *and* the current artifact
    hashes. A marker-shaped document or stale supporting evidence is not
    admissible as reproduction evidence for another control-plane decision.
    """
    workspace = _root(root)
    fields = {
        "schema",
        "marker",
        "markers",
        "project_id",
        "journey_id",
        "run_id",
        "decision",
        "classification",
        "failed_step_index",
        "step_context",
        "artifacts",
        "hypothesis",
        "suggested_repair",
        "reproduction_argv",
        "bindings",
        "authority",
        "receipt_sha256",
    }
    data = _exact(value, fields, "factory.failure-capsule.v1")
    _validate_failure_capsule_identity(data)
    indexes = _validate_failure_step_context(data)
    _validate_failure_artifacts(workspace, data, indexes)
    _validate_failure_claims(data)
    return data


def verify_stateful_workflow(
    root: Path, input_path: Path, out: Path | None = None
) -> dict[str, Any]:
    """Prove DAG state flow and cleanup outcomes from explicit run results."""
    return _verify_stateful_workflow(root, input_path, out)


def verify_proof_gated_healing(
    root: Path, input_path: Path, out: Path | None = None, timeout_seconds: int = 300
) -> dict[str, Any]:
    """Run bounded proof commands and independently audit an optional agent attempt."""
    return _verify_proof_gated_healing(root, input_path, out, timeout_seconds)


def _verify_receipt(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or not isinstance(
        payload.get("receipt_sha256"), str
    ):
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
        receipts.append(
            {
                "path": relative,
                "schema": receipt.get("schema"),
                "marker": receipt.get("marker"),
                "decision": receipt.get("decision"),
                "receipt_sha256": receipt["receipt_sha256"],
                "journey_id": receipt.get("journey_id"),
                "workflow_id": receipt.get("workflow_id"),
                "healing_id": receipt.get("healing_id"),
                "review_mode": receipt.get("review_mode"),
            }
        )
    return {
        "schema": "factory.journey-proof-status.v1",
        "marker": "JOURNEY_STATUS_READ_ONLY",
        "receipts": receipts,
        "invalid_receipts": invalid,
        "facts": {"verified_count": len(receipts), "invalid_count": len(invalid)},
        "authority": AUTHORITY,
    }
