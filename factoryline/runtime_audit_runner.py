"""No-shell supervised execution for already-verified runtime audit plans."""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
import re
import shutil
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .runtime_audit_process import (
    bounded_file_sha256,
    create_bounded_temp_directory,
    new_output_path_inside,
    path_chain_has_no_links,
    regular_target_within,
    run_bounded_command,
    same_mutation_case_catalogs,
    tree_has_no_links_or_reparse_points,
    mutation_trial_observed,
    remove_bounded_temp_directory,
    validate_production_mutation_process,
)
from .runtime_audit_common import (
    RuntimeAuditError,
    canonical_bytes,
    read_stable_json,
    sha256_bytes,
    validate_production_mutation_source,
    _candidate_manifest,
    _candidate_manifest_entry as _candidate_manifest_entry,
    _candidate_call_origins,
    _candidate_configuration_inputs as _candidate_configuration_inputs,
    _candidate_configuration_manifest,
    _candidate_definition_frame_bound,
    _candidate_run_evidence,
)
from .runtime_attestation import (
    MAX_TEST_ORACLE_CONFIG_FILES,
    TEST_ORACLE_SCHEMA_V3,
    RuntimeAttestationError,
    _oracle_test,
    capture_supervised_attestation,
)
from .runtime_audit_contract import _hash_regular_file_bounded, _relative_file


_MUTATION_COPY_IGNORES = {
    ".git",
    ".factory",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "*.pyc",
    "*.pyo",
    ".pytest_cache",
    "build",
    "dist",
}


def _inside(root: Path, candidate: Path) -> Path:
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise RuntimeAuditError("E_OUTPUT_ESCAPE", str(candidate)) from exc
    return resolved


def _run_local_mutation_trial(
    root,
    selector,
    line,
    qualname,
    firstlineno,
    manifest,
    output_root,
    trial,
    timeout,
    python_executable,
    host_root,
):
    trial_dir = output_root / trial
    trial_dir.mkdir(parents=False, exist_ok=False)
    manifest_path = trial_dir / "source-manifest.json"
    observation_path = trial_dir / "observation.json"
    stdout_path, stderr_path = trial_dir / "stdout.log", trial_dir / "stderr.log"
    runtime_scratch = root.parent / f"runtime-{trial}"
    if runtime_scratch.exists() or runtime_scratch.is_symlink():
        raise RuntimeAuditError("E_MUTATION_TEMP", "trial runtime directory was reused")
    runtime_home = str(runtime_scratch / "runtime-home")
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    config = {
        "root": str(root),
        "path": str(root / selector.split("::", 1)[0]),
        "line": line,
        "nodeid": selector,
        "inject": False,
        "qualname": qualname,
        "firstlineno": firstlineno,
        "kind": "production_mutation",
        "allow_multiple": True,
        "source_manifest_path": str(manifest_path),
        "runtime_environment_paths": {
            name: runtime_home
            for name in ("HOME", "USERPROFILE", "TMP", "TEMP", "TMPDIR")
        },
    }
    package_root = str(Path(__file__).resolve().parent.parent)
    script = (
        "import json,sys; package_root,root,raw,output=sys.argv[1:5]; "
        "sys.path[:0]=[root+'/src',root,package_root]; "
        "from factoryline.pytest_readiness import _challenge_worker; "
        "_challenge_worker(json.loads(raw),output)"
    )
    command = [
        str(python_executable),
        "-B",
        "-c",
        script,
        package_root,
        str(root),
        json.dumps(config),
        str(observation_path),
    ]
    facts = run_bounded_command(
        command,
        root,
        timeout,
        runtime_scratch,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )
    result = {
        "process": facts,
        "execution_identity": {
            "command_template": "python -B -c <worker> <tool-root> <project-root> <config> <observation>",
            "argument_roles": [
                "interpreter",
                "python-option",
                "python-option",
                "worker-script",
                "tool-root",
                "project-root",
                "child-config",
                "observation-output",
            ],
            "argv_sha256": hashlib.sha256(
                json.dumps(command, separators=(",", ":")).encode()
            ).hexdigest(),
            "interpreter_sha256": bounded_file_sha256(
                python_executable, 64 * 1024 * 1024
            ),
            "interpreter_version": None,
        },
    }
    observation_bytes = None
    if (
        regular_target_within(host_root, observation_path)
        and observation_path.stat().st_size <= 1024 * 1024
    ):
        digest, observation_bytes = bounded_file_sha256(
            observation_path, 1024 * 1024, include_bytes=True
        )
        result["observation"] = {"path": observation_path.name, "sha256": digest}
    if validate_production_mutation_process(facts):
        _record_mutation_observation(result, observation_bytes)
    return result


def _record_mutation_observation(result, observation_bytes):
    if observation_bytes is None:
        return
    try:
        data = json.loads(observation_bytes.decode("utf-8"))
    except (OSError, UnicodeError, ValueError):
        data = None
    result["data"] = data if isinstance(data, dict) else None
    runtime = result["data"].get("python_runtime") if result["data"] else None
    version = runtime.get("version") if isinstance(runtime, dict) else None
    if isinstance(version, str):
        result["execution_identity"]["interpreter_version"] = version


def _validate_mutation_timeout(timeout):
    if type(timeout) is not int or not 1 <= timeout <= 300:
        raise RuntimeAuditError(
            "E_MUTATION_INPUT", "exact function selection and bounded timeout required"
        )


def _validate_mutation_selector(selector, assertion_line):
    if not isinstance(selector, str) or "[" in selector or "::" not in selector:
        raise RuntimeAuditError(
            "E_MUTATION_INPUT", "exact function selection is required"
        )
    if type(assertion_line) is not int or assertion_line < 1:
        raise RuntimeAuditError(
            "E_MUTATION_INPUT", "positive assertion line is required"
        )


def _validate_mutation_patch_text(before_text, after_text):
    if (
        not isinstance(before_text, str)
        or not isinstance(after_text, str)
        or before_text == after_text
    ):
        raise RuntimeAuditError(
            "E_MUTATION_INPUT", "one distinct text mutation is required"
        )


def _validate_mutation_request(
    selector, assertion_line, before_text, after_text, timeout
):
    _validate_mutation_timeout(timeout)
    _validate_mutation_selector(selector, assertion_line)
    _validate_mutation_patch_text(before_text, after_text)


def _bind_mutation_test(root, selector, line):
    from .pytest_readiness import _challenge_inputs

    _, test_path, qualname, firstlineno = _challenge_inputs(root, selector, line)
    selected = ".".join(selector.split("::")[1:])
    if qualname != selected and not qualname.startswith(selected + ".<locals>"):
        raise RuntimeAuditError(
            "E_MUTATION_INPUT", "assertion is outside the selected function"
        )
    return test_path, qualname, firstlineno


def _mutation_test_identity(test_path, selector):
    parts = selector.split("::")[1:]
    symbol, classpath = parts[-1], parts[:-1]
    tree = ast.parse(test_path.read_text(encoding="utf-8"))
    matches = []

    def visit(body, classes):
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit(node.body, (*classes, node.name))
            elif (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and tuple(classes) == tuple(classpath)
                and node.name == symbol
            ):
                matches.append(node)

    visit(tree.body, ())
    if len(matches) != 1:
        raise RuntimeAuditError(
            "E_MUTATION_INPUT", "selected test definition is ambiguous or missing"
        )
    definition = matches[0]
    return {
        "line": definition.lineno,
        "code_firstlineno": min(
            [definition.lineno, *(item.lineno for item in definition.decorator_list)]
        ),
        "symbol": symbol,
        "classpath": classpath,
        "qualname": ".".join((*classpath, symbol)),
    }


def _bind_mutation_source(root, test_path, path, symbol, before_text, after_text):
    target = _relative_file(root, path, "production_path")
    if target.suffix != ".py" or target == test_path:
        raise RuntimeAuditError(
            "E_MUTATION_INPUT", "production target must be a distinct Python source"
        )
    source = target.read_bytes()
    if len(source) > 4 * 1024 * 1024:
        raise RuntimeAuditError(
            "E_MUTATION_INPUT", "production source exceeds the 4 MiB mutation limit"
        )
    before, after = before_text.encode("utf-8"), after_text.encode("utf-8")
    line, resolved_symbol = validate_production_mutation_source(source, symbol, before)
    mutant = source.replace(before, after, 1)
    if not mutant or mutant == source:
        raise RuntimeAuditError(
            "E_MUTATION_INPUT", "mutation does not change production bytes"
        )
    try:
        ast.parse(mutant)
    except SyntaxError as exc:
        raise RuntimeAuditError(
            "E_MUTATION_INPUT", "mutant source is invalid Python"
        ) from exc
    return target, source, mutant, before, after, line, resolved_symbol


def _mutation_context(root, test_path, target, source):
    from .pytest_readiness import (
        _challenge_runtime_context,
        _challenge_source_binding,
        _challenge_source_inventory,
    )
    from .review_audits import _pytest_collection_config

    manifest = _challenge_source_inventory(root)
    target_relative = target.relative_to(root).as_posix()
    source_hash = hashlib.sha256(source).hexdigest()
    if target_relative not in manifest:
        raise RuntimeAuditError(
            "E_MUTATION_INPUT",
            "production source is outside the Python source inventory",
        )
    if manifest[target_relative] != source_hash:
        raise RuntimeAuditError(
            "E_MUTATION_DRIFT", "production source changed during input binding"
        )
    patterns, config = _pytest_collection_config(root)
    paths = test_path.relative_to(root).as_posix().split("/")[:-1]
    configs = (
        [{"path": config["path"], "sha256": config["sha256"]}]
        if config.get("state") == "read"
        else []
    ) + [
        {"path": p, "sha256": manifest[p]}
        for i in range(len(paths) + 1)
        if (p := "/".join((*paths[:i], "conftest.py"))) in manifest
    ]
    configs.sort(key=lambda row: row["path"])
    config_identity = hashlib.sha256(
        json.dumps(configs, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if len(configs) > MAX_TEST_ORACLE_CONFIG_FILES:
        raise RuntimeAuditError(
            "E_MUTATION_INPUT", "pytest config manifest exceeds bounds"
        )
    return {
        "manifest": manifest,
        "target_relative": target_relative,
        "source_manifest_hash": _challenge_source_binding(root),
        "test_hash": hashlib.sha256(test_path.read_bytes()).hexdigest(),
        "original_hash": source_hash,
        "config_hash": _challenge_runtime_context(root),
        "collection_config": {
            "patterns": sorted(patterns),
            "config": config,
            "complete": True,
            "manifest": configs,
            "identity_sha256": config_identity,
        },
    }


def _prepare_mutation_capture(
    root, selector, line, production_path, symbol, before, after, evidence_path, timeout
):
    _validate_mutation_request(selector, line, before, after, timeout)
    test_path, qualname, firstlineno = _bind_mutation_test(root, selector, line)
    test_identity = _mutation_test_identity(test_path, selector)
    target, source, mutant, patch_before, patch_after, target_line, resolved_symbol = (
        _bind_mutation_source(root, test_path, production_path, symbol, before, after)
    )
    evidence = new_output_path_inside(root, Path(evidence_path))
    context = _mutation_context(root, test_path, target, source)
    return {
        **context,
        "selector": selector,
        "line": line,
        "test_path": test_path,
        "qualname": qualname,
        "firstlineno": firstlineno,
        "test_identity": test_identity,
        "target": target,
        "source": source,
        "mutant": mutant,
        "before": patch_before,
        "after": patch_after,
        "target_line": target_line,
        "symbol": resolved_symbol,
        "evidence": evidence,
    }


def _copy_mutation_candidate(root, temp_root, prepared):
    if not tree_has_no_links_or_reparse_points(root, _MUTATION_COPY_IGNORES):
        raise RuntimeAuditError(
            "E_MUTATION_INPUT", "workspace copy exceeds limits or contains links"
        )
    trial_root = temp_root / "candidate"
    shutil.copytree(
        root,
        trial_root,
        ignore=shutil.ignore_patterns(*_MUTATION_COPY_IGNORES),
        symlinks=True,
    )
    if not tree_has_no_links_or_reparse_points(trial_root, _MUTATION_COPY_IGNORES):
        raise RuntimeAuditError(
            "E_MUTATION_INPUT",
            "temporary workspace copy contains links or exceeds limits",
        )
    copied_test = trial_root / prepared["test_path"].relative_to(root)
    copied_target = trial_root / prepared["target"].relative_to(root)
    from .pytest_readiness import (
        _challenge_runtime_context,
        _challenge_source_inventory,
    )

    if (
        hashlib.sha256(copied_test.read_bytes()).hexdigest() != prepared["test_hash"]
        or hashlib.sha256(copied_target.read_bytes()).hexdigest()
        != prepared["original_hash"]
        or _challenge_source_inventory(trial_root) != prepared["manifest"]
        or _challenge_runtime_context(trial_root) != prepared["config_hash"]
    ):
        raise RuntimeAuditError(
            "E_MUTATION_DRIFT", "temporary copy differs from source-bound bytes"
        )
    from .review_audits import _pytest_collection_config

    patterns, config = _pytest_collection_config(trial_root)
    if {"patterns": sorted(patterns), "config": config} != {
        key: prepared["collection_config"][key] for key in ("patterns", "config")
    }:
        raise RuntimeAuditError(
            "E_MUTATION_DRIFT", "temporary collection config differs from source"
        )
    return trial_root, copied_test, copied_target


def _run_mutation_trials(
    root, trial_root, copied_test, copied_target, prepared, timeout, python_executable
):
    _require_mutation_copy_state(trial_root, prepared)
    baseline = _run_local_mutation_trial(
        trial_root,
        prepared["selector"],
        prepared["line"],
        prepared["qualname"],
        prepared["firstlineno"],
        prepared["manifest"],
        prepared["evidence"],
        "baseline",
        timeout,
        python_executable,
        prepared["root"],
    )
    if not mutation_trial_observed(
        baseline,
        prepared,
        trial_root,
        copied_target,
        prepared["manifest"],
        "passed",
        False,
    ):
        return baseline, {}, False, _mutation_sources_unchanged(root, prepared)
    _require_mutation_copy_state(trial_root, prepared)
    if (
        not regular_target_within(trial_root, copied_target)
        or hashlib.sha256(copied_target.read_bytes()).hexdigest()
        != prepared["original_hash"]
    ):
        raise RuntimeAuditError("E_MUTATION_DRIFT", "copied production source changed")
    mutant_manifest = dict(prepared["manifest"])
    mutant_manifest[prepared["target_relative"]] = hashlib.sha256(
        prepared["mutant"]
    ).hexdigest()
    copied_target.write_bytes(prepared["mutant"])
    prepared["mutation_applied"] = True
    if hashlib.sha256(copied_test.read_bytes()).hexdigest() != prepared["test_hash"]:
        raise RuntimeAuditError(
            "E_MUTATION_DRIFT", "test bytes changed before mutant run"
        )
    mutation = _run_local_mutation_trial(
        trial_root,
        prepared["selector"],
        prepared["line"],
        prepared["qualname"],
        prepared["firstlineno"],
        mutant_manifest,
        prepared["evidence"],
        "mutant",
        timeout,
        python_executable,
        prepared["root"],
    )
    mutation_ok = mutation_trial_observed(
        mutation, prepared, trial_root, copied_target, mutant_manifest, "failed", True
    )
    same_runtime = baseline.get("data", {}).get(
        "runtime_context_normalized_before"
    ) == mutation.get("data", {}).get("runtime_context_normalized_before")
    same_catalog = same_mutation_case_catalogs(baseline, mutation)
    from .pytest_readiness import _challenge_runtime_context, _challenge_source_binding

    stable = (
        _challenge_source_binding(root) == prepared["source_manifest_hash"]
        and _challenge_runtime_context(root) == prepared["config_hash"]
        and hashlib.sha256(prepared["test_path"].read_bytes()).hexdigest()
        == prepared["test_hash"]
        and hashlib.sha256(prepared["target"].read_bytes()).hexdigest()
        == prepared["original_hash"]
    )
    return baseline, mutation, mutation_ok and same_catalog and same_runtime, stable


def _require_mutation_copy_state(trial_root, prepared):
    from .pytest_readiness import (
        _challenge_runtime_context,
        _challenge_source_inventory,
    )

    if (
        not tree_has_no_links_or_reparse_points(trial_root, _MUTATION_COPY_IGNORES)
        or not regular_target_within(
            trial_root, trial_root / prepared["target_relative"]
        )
        or _challenge_source_inventory(trial_root) != prepared["manifest"]
        or _challenge_runtime_context(trial_root) != prepared["config_hash"]
    ):
        raise RuntimeAuditError(
            "E_MUTATION_DRIFT", "temporary workspace or config changed"
        )


def _mutation_sources_unchanged(root, prepared):
    from .pytest_readiness import _challenge_runtime_context, _challenge_source_binding

    try:
        return (
            _challenge_source_binding(root) == prepared["source_manifest_hash"]
            and _challenge_runtime_context(root) == prepared["config_hash"]
            and hashlib.sha256(prepared["test_path"].read_bytes()).hexdigest()
            == prepared["test_hash"]
            and hashlib.sha256(prepared["target"].read_bytes()).hexdigest()
            == prepared["original_hash"]
        )
    except OSError:
        return False


def _mutation_base_payload(prepared):
    """Bind common source, selector, and authority limits for every outcome."""
    source_manifest = [
        {"path": path, "sha256": digest}
        for path, digest in prepared["manifest"].items()
    ]
    return {
        "schema": "factory.local-production-mutation-capture.v1",
        "signature_status": "UNSIGNED",
        "observer_integrity": "IN_PROCESS_NOT_ATTESTED",
        "authority": "none",
        "selection": {
            "nodeid_selector": prepared["selector"],
            "assertion_line": prepared["line"],
            "callback_qualname": prepared["qualname"],
            "test_path": prepared["test_path"].relative_to(prepared["root"]).as_posix(),
            "test_sha256": prepared["test_hash"],
            "test_definition_line": prepared["test_identity"]["line"],
            "test_code_firstlineno": prepared["test_identity"]["code_firstlineno"],
            "test_symbol": prepared["test_identity"]["symbol"],
            "test_classpath": prepared["test_identity"]["classpath"],
            "test_definition_qualname": prepared["test_identity"]["qualname"],
        },
        "production_mutation": {
            "path": prepared["target_relative"],
            "symbol": prepared["symbol"],
            "line": prepared["target_line"],
            "original_sha256": prepared["original_hash"],
            "mutant_sha256": hashlib.sha256(prepared["mutant"]).hexdigest(),
            "mutation_applied": prepared.get("mutation_applied", False),
            "changed_only_in_temporary_copy": prepared.get("mutation_applied", False),
        },
        "source_manifest_sha256": prepared["source_manifest_hash"],
        "source_manifest": source_manifest,
        "configuration_context_sha256": prepared["config_hash"],
    }


def _candidate_run_observation(capture, name, cases, source_manifest, selector):
    observation, trial, selection, mutation, expected, visible, observation_file = (
        _candidate_run_evidence(capture, name, selector)
    )
    run_manifest = dict(source_manifest)
    if name == "mutant":
        run_manifest[mutation["path"]] = mutation["mutant_sha256"]
    executed_manifest = hashlib.sha256(
        json.dumps(run_manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if observation.get("executed_source_manifest_sha256") != executed_manifest:
        raise ValueError(f"{name} executed source manifest differs")
    origins = _candidate_call_origins(observation, run_manifest)
    test_path = selection["test_path"]
    test_sha = selection["test_sha256"]
    assertions = [
        {**row, "source_path": test_path, "source_sha256": test_sha}
        for row in observation["assertion_observations"]
    ]
    configs, config_manifest_sha = _candidate_configuration_manifest(
        capture, test_path, source_manifest
    )
    catalog = {
        "status": "PASS",
        "phase": "collection",
        "complete": True,
        "scope": "test_function",
        "source_path": test_path,
        "source_sha256": test_sha,
        "config_manifest": configs,
        "config_manifest_sha256": config_manifest_sha,
        "config_identity": "manifest" if configs else "pytest-default",
        "report_sha256": observation["collection_report_sha256"],
        "case_ids": cases,
    }
    projected = {
        "status": {"baseline": "PASS", "mutant": "FAIL"}[name],
        "phase": "call",
        "collection_complete": True,
        "case_ids": cases,
        "report_sha256": observation_file["sha256"],
        "setup_status": "PASS",
        "teardown_status": "PASS",
        "collection_catalog": catalog,
        "assertion_observations": assertions,
        "module_origins": origins,
    }
    if name == "mutant":
        projected.pop("collection_complete")
        projected.update(
            {
                "source_path": mutation["path"],
                "source_sha256": mutation["original_sha256"],
                "mutant_sha256": mutation["mutant_sha256"],
                "failure_kind": "assertion",
            }
        )
    return projected


def project_local_production_mutation_v3_candidate(capture):
    """Project local evidence into an unsigned candidate; never admit or sign it."""
    projection = {
        "schema": "factory.local-production-mutation-v3-candidate.v1",
        "oracle_schema": TEST_ORACLE_SCHEMA_V3,
        "status": "INCOMPLETE",
        "signature_status": "UNSIGNED",
        "observer_integrity": "IN_PROCESS_NOT_ATTESTED",
        "authority": "none",
        "trust_admission": "NOT_PERFORMED",
        "test_candidate": None,
        "attestation_envelope": None,
        "missing_evidence": [],
        "claim_boundary": "Local candidate projection only; not an independent oracle, finding suppression, trust admission, signature, approval, or release authorization.",
    }
    try:
        manifest, selection, mutation = _candidate_capture_inputs(capture)
        test_path, test_sha = selection.get("test_path"), selection.get("test_sha256")
        source_path = mutation.get("path")
        if not all(
            (
                manifest.get(test_path) == test_sha,
                manifest.get(source_path) == mutation.get("original_sha256"),
                isinstance(selection.get("test_definition_line"), int),
                isinstance(selection.get("test_code_firstlineno"), int),
                isinstance(selection.get("test_symbol"), str),
                isinstance(selection.get("test_classpath"), list),
            )
        ):
            raise ValueError("test definition or source manifest binding missing")
        baseline_obs, mutant_obs = (
            capture.get("baseline_observation"),
            capture.get("mutant_observation"),
        )
        if not all((isinstance(baseline_obs, dict), isinstance(mutant_obs, dict))):
            raise ValueError("raw baseline or mutant observation missing")
        if not all(
            _candidate_definition_frame_bound(
                observation, selection, baseline_obs.get("collected", [])
            )
            for observation in (baseline_obs, mutant_obs)
        ):
            raise ValueError("test definition frame is not bound in both runs")
        cases = baseline_obs.get("collected")
        if not isinstance(cases, list) or cases != mutant_obs.get("collected"):
            raise ValueError("baseline and mutant case catalogs differ")
        selector = selection.get("nodeid_selector")
        baseline = _candidate_run_observation(
            capture, "baseline", cases, manifest, selector
        )
        mutant = _candidate_run_observation(
            capture, "mutant", cases, manifest, selector
        )
        if baseline_obs.get("runtime_context_normalized_before") != mutant_obs.get(
            "runtime_context_normalized_before"
        ):
            raise ValueError("baseline and mutant runtime contexts differ")
        test = {
            "path": test_path,
            "line": selection["test_definition_line"],
            "symbol": selection["test_symbol"],
            "test_sha256": test_sha,
            "baseline": baseline,
            "mutation": mutant,
        }
        normalized = _oracle_test(test, schema=TEST_ORACLE_SCHEMA_V3)
        bindings = {
            "source_manifest": capture["source_manifest"],
            "source_manifest_sha256": capture["source_manifest_sha256"],
            "configuration_context_sha256": capture.get("configuration_context_sha256"),
            "configuration_context_sha256_before": capture.get(
                "configuration_context_sha256_before"
            ),
            "configuration_context_sha256_after": capture.get(
                "configuration_context_sha256_after"
            ),
            "test_definition_qualname": selection.get("test_definition_qualname"),
            "test_classpath": selection.get("test_classpath"),
            "baseline": _candidate_runtime_bindings(capture, "baseline"),
            "mutant": _candidate_runtime_bindings(capture, "mutant"),
        }
        context_digest = capture.get("configuration_context_sha256")
        if not all(
            (
                re.fullmatch(r"[0-9a-f]{64}", str(context_digest)),
                capture.get("configuration_context_sha256_before") == context_digest,
                capture.get("configuration_context_sha256_after") == context_digest,
            )
        ):
            raise ValueError("configuration context binding is incomplete or drifted")
        if not all(
            _candidate_runtime_bindings_complete(bindings[name])
            for name in ("baseline", "mutant")
        ):
            raise ValueError("runtime, tool, interpreter, or context binding missing")
        projection.update(
            status="CANDIDATE", test_candidate=normalized, evidence_bindings=bindings
        )
    except (
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
        RuntimeAttestationError,
    ) as exc:
        projection["missing_evidence"] = [str(exc)[:256]]
    return projection


def _candidate_capture_inputs(capture):
    if (
        not isinstance(capture, dict)
        or capture.get("schema") != "factory.local-production-mutation-capture.v1"
    ):
        raise ValueError("local capture schema missing")
    if not all(
        (
            capture.get("signature_status") == "UNSIGNED",
            capture.get("observer_integrity") == "IN_PROCESS_NOT_ATTESTED",
            capture.get("authority") == "none",
            capture.get("status") == "OBSERVED",
            capture.get("source_unchanged") is True,
            isinstance(capture.get("cleanup"), dict),
            capture["cleanup"].get("removed") is True,
        )
    ):
        raise ValueError("capture is not a complete local observation")
    manifest = _candidate_manifest(capture)
    selection = capture.get("selection")
    mutation = capture.get("production_mutation")
    if not all((isinstance(selection, dict), isinstance(mutation, dict))):
        raise ValueError("selection or mutation binding missing")
    return manifest, selection, mutation


def _candidate_runtime_bindings(capture, name):
    observation = capture.get(f"{name}_observation", {})
    trial = capture.get(name, {})
    identity = trial.get("execution_identity", {}) if isinstance(trial, dict) else {}
    runtime = (
        observation.get("python_runtime", {}) if isinstance(observation, dict) else {}
    )
    return {
        "argv_sha256": identity.get("argv_sha256"),
        "runtime_context_sha256": observation.get("runtime_context_before"),
        "normalized_runtime_context_sha256": observation.get(
            "runtime_context_normalized_before"
        ),
        "tool_sha256": observation.get("tool_sha256"),
        "python_implementation": runtime.get("implementation"),
        "python_version": runtime.get("version"),
        "interpreter_sha256": identity.get("interpreter_sha256"),
        "interpreter_version": identity.get("interpreter_version"),
        "executed_source_manifest_sha256": observation.get(
            "executed_source_manifest_sha256"
        ),
    }


def _candidate_runtime_bindings_complete(bindings):
    digests = (
        "argv_sha256",
        "runtime_context_sha256",
        "normalized_runtime_context_sha256",
        "tool_sha256",
        "interpreter_sha256",
        "executed_source_manifest_sha256",
    )
    versions = ("python_implementation", "python_version", "interpreter_version")
    return all(
        re.fullmatch(r"[0-9a-f]{64}", bindings.get(key, "")) for key in digests
    ) and all(
        isinstance(bindings.get(key), str) and bool(bindings[key]) for key in versions
    )


def _write_mutation_capture(prepared, cleanup, baseline, mutation, mutation_ok, stable):
    evidence = prepared["evidence"]
    if not path_chain_has_no_links(prepared["root"], evidence):
        raise RuntimeAuditError(
            "E_MUTATION_OUTPUT", "evidence path changed during capture"
        )
    diff_text = "".join(
        difflib.unified_diff(
            prepared["source"]
            .decode("utf-8", errors="replace")
            .splitlines(keepends=True),
            prepared["mutant"]
            .decode("utf-8", errors="replace")
            .splitlines(keepends=True),
            fromfile=prepared["target_relative"],
            tofile=prepared["target_relative"] + " (mutant)",
        )
    )
    diff_path = new_output_path_inside(prepared["root"], evidence / "production.diff")
    diff_path.write_text(diff_text, encoding="utf-8")
    payload = _mutation_base_payload(prepared)
    payload.update(
        {
            "status": "OBSERVED" if mutation_ok and stable else "INCOMPLETE",
            "claim_boundary": "Local supervised observation only; not a signed oracle, independent execution attestation, accuracy result, finding suppression, approval, or release authorization.",
            "collection_config": prepared["collection_config"],
            "source_unchanged": stable,
            "baseline": {
                key: value for key, value in baseline.items() if key != "data"
            },
            "mutant": {key: value for key, value in mutation.items() if key != "data"},
            "baseline_observation": baseline.get("data"),
            "mutant_observation": mutation.get("data"),
            "cleanup": cleanup,
            "limits": "Unsigned local observation; supervision is not sandboxing. Every selected case must hit the natural assertion and show the expected phase outcome; omitted, skipped, or dynamic cases remain incomplete.",
        }
    )
    payload["production_mutation"].update(
        {
            "before_sha256": hashlib.sha256(prepared["before"]).hexdigest(),
            "after_sha256": hashlib.sha256(prepared["after"]).hexdigest(),
            "diff_path": diff_path.name,
            "diff_sha256": hashlib.sha256(diff_path.read_bytes()).hexdigest(),
            "candidate_diff_only": not prepared.get("mutation_applied", False),
        }
    )
    payload["configuration_context_sha256_before"] = prepared["config_hash"]
    payload["configuration_context_sha256_after"] = prepared["config_hash"]
    capture_path = new_output_path_inside(prepared["root"], evidence / "capture.json")
    capture_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    cleanup["record_owned"] = True
    return payload


def _cleanup_mutation_capture(temp_root, temp_parent, evidence, cleanup, payload, root):
    cleanup["removed"] = remove_bounded_temp_directory(
        temp_root, temp_parent, "cf-production-mutation-"
    )
    if all((not cleanup["removed"], payload is not None)):
        payload["status"] = "INCOMPLETE"
    if payload is not None:
        payload["v3_candidate_projection"] = (
            project_local_production_mutation_v3_candidate(payload)
        )
    record = evidence / "capture.json"
    if all((cleanup["record_owned"], path_chain_has_no_links(root, record))):
        try:
            _, contents = bounded_file_sha256(record, 1024 * 1024, include_bytes=True)
            saved = json.loads(contents.decode("utf-8"))
            if isinstance(saved, dict):
                saved["cleanup"] = cleanup
                saved["v3_candidate_projection"] = (
                    payload.get("v3_candidate_projection")
                    if payload is not None
                    else None
                )
                if not cleanup["removed"]:
                    saved["status"] = "INCOMPLETE"
                record.write_text(
                    json.dumps(saved, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
        except (OSError, UnicodeError, ValueError):
            if payload is not None:
                payload["status"] = "INCOMPLETE"


def capture_local_production_mutation(
    workspace_root: Path,
    selector: str,
    assertion_line: int,
    production_path: str,
    production_symbol: str,
    before_text: str,
    after_text: str,
    evidence_path: str,
    *,
    timeout_seconds: int = 60,
    python_executable: Path | None = None,
) -> dict[str, Any]:
    """Record unsigned local baseline and real production-source mutant runs."""
    root = Path(workspace_root).resolve(strict=True)
    prepared = _prepare_mutation_capture(
        root,
        selector,
        assertion_line,
        production_path,
        production_symbol,
        before_text,
        after_text,
        evidence_path,
        timeout_seconds,
    )
    prepared["root"] = root
    evidence = prepared["evidence"]
    interpreter = Path(python_executable or sys.executable).resolve(strict=True)
    if not interpreter.is_file():
        raise RuntimeAuditError(
            "E_MUTATION_INPUT", "interpreter must be a regular file"
        )
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=False, exist_ok=False)
    temp_parent, temp_root = root, None
    cleanup = {
        "requested": True,
        "verified_under_temp": True,
        "removed": False,
        "record_owned": False,
    }
    payload = None
    stage = "temporary_copy"
    try:
        temp_parent, temp_root = create_bounded_temp_directory(
            "cf-production-mutation-"
        )
        trial_root, copied_test, copied_target = _copy_mutation_candidate(
            root, temp_root, prepared
        )
        stage = "baseline_and_mutant_trials"
        baseline, mutation, mutation_ok, stable = _run_mutation_trials(
            root,
            trial_root,
            copied_test,
            copied_target,
            prepared,
            timeout_seconds,
            interpreter,
        )
        payload = _write_mutation_capture(
            prepared, cleanup, baseline, mutation, mutation_ok, stable
        )
        return payload
    except (RuntimeAuditError, OSError) as exc:
        code = exc.code if isinstance(exc, RuntimeAuditError) else "E_MUTATION_IO"
        payload = _mutation_base_payload(prepared)
        payload.update(
            {
                "status": "INCOMPLETE",
                "stage": stage,
                "error_code": code,
                "source_unchanged": _mutation_sources_unchanged(root, prepared),
                "cleanup": cleanup,
            }
        )
        record = evidence / "capture.json"
        try:
            record = new_output_path_inside(root, record)
            record.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            cleanup["record_owned"] = True
        except (RuntimeAuditError, OSError):
            pass
        return payload
    finally:
        _cleanup_mutation_capture(
            temp_root, temp_parent, evidence, cleanup, payload, root
        )


def _verify_admission_sources(plan: dict[str, Any], workspace: Path) -> str:
    sources = plan.get("sources")
    if not isinstance(sources, list):
        raise RuntimeAuditError(
            "E_PARALLELISM_POLICY", "verified source manifest is missing"
        )
    for source in sources:
        if not isinstance(source, dict) or not isinstance(source.get("path"), str):
            raise RuntimeAuditError(
                "E_PARALLELISM_POLICY", "verified source binding is invalid"
            )
        try:
            path = _relative_file(workspace, source["path"], "sources.path")
            actual_hash, actual_bytes = _hash_regular_file_bounded(
                path, source.get("bytes", -1)
            )
        except OSError as exc:
            raise RuntimeAuditError(
                "E_PARALLELISM_POLICY", "verified source changed before launch"
            ) from exc
        if actual_bytes != source.get("bytes") or actual_hash != source.get("sha256"):
            raise RuntimeAuditError(
                "E_PARALLELISM_POLICY", "verified source changed before launch"
            )
    return sha256_bytes(
        canonical_bytes(sorted(sources, key=lambda item: item.get("path", "")))
    )


def _check_parallel_admission(plan, workspace, requested, plan_sha256, admission):
    """Check stale-input integrity after public signature verification."""
    policy = plan.get("execution_policy")
    if requested == 1:
        return policy if isinstance(policy, dict) else None
    if not isinstance(policy, dict) or not isinstance(admission, dict):
        raise RuntimeAuditError(
            "E_PARALLELISM_POLICY",
            "parallel execution requires verified signed-plan admission",
        )
    actual_plan = sha256_bytes(canonical_bytes(plan))
    actual_sources = _verify_admission_sources(plan, workspace)
    environment = plan.get("environment")
    actual_environment = (
        environment.get("digest") if isinstance(environment, dict) else None
    )
    matches = (
        admission.get("payload_sha256") == plan_sha256
        and admission.get("plan_canonical_sha256") == actual_plan
        and admission.get("source_manifest_sha256") == actual_sources
        and admission.get("environment_sha256") == actual_environment
        and admission.get("max_parallelism") == policy.get("max_parallelism")
        and admission.get("non_mutating") is policy.get("non_mutating")
        and admission.get("resource_safe") is policy.get("resource_safe")
    )
    maximum = policy.get("max_parallelism")
    if (
        not matches
        or policy.get("non_mutating") is not True
        or policy.get("resource_safe") is not True
        or isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or requested > maximum
    ):
        raise RuntimeAuditError(
            "E_PARALLELISM_POLICY",
            "parallel admission is stale or exceeds signed policy",
        )
    return policy


def _require_parallelism(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 8:
        raise RuntimeAuditError(
            "E_PARALLELISM", "max_parallelism must be an integer between 1 and 8"
        )
    return value


def _run_one(
    lane: dict[str, Any],
    command_name: str,
    argv_key: str,
    run_root: Path,
    workspace: Path,
) -> dict[str, Any]:
    command_root = run_root / lane["id"] / command_name
    command_root.mkdir(parents=True, exist_ok=False)
    artifact_path = command_root / "artifact.json"
    argv = [
        str(artifact_path) if item == "{artifact}" else item for item in lane[argv_key]
    ]
    command = run_bounded_command(
        argv,
        cwd=workspace,
        timeout_seconds=lane["timeout_seconds"],
        scratch=command_root,
    )
    artifact: dict[str, Any] | None = None
    artifact_sha256: str | None = None
    artifact_error: dict[str, str] | None = None
    try:
        artifact, artifact_sha256 = read_stable_json(artifact_path)
    except RuntimeAuditError as exc:
        # Path-aware reader messages can disclose absolute workspace paths.
        code = (
            exc.code
            if re.fullmatch(r"[A-Z0-9_]{1,64}", exc.code)
            else "E_ARTIFACT_INVALID"
        )
        artifact_error = {"code": code}
    return {
        "command": command_name,
        "signed_argv": list(lane[argv_key]),
        "timeout_seconds": lane["timeout_seconds"],
        "supervision": "supervised_" + "sub" + "process_not_sandboxed",
        "execution": command,
        "artifact": artifact,
        "artifact_sha256": artifact_sha256,
        "normalized_artifact_sha256": sha256_bytes(canonical_bytes(artifact))
        if artifact is not None
        else None,
        "artifact_error": artifact_error,
    }


def _run_one_guarded(
    lane: dict[str, Any],
    command_name: str,
    argv_key: str,
    run_root: Path,
    workspace: Path,
) -> dict[str, Any]:
    """Preserve an explicit incomplete leg instead of aborting sibling lanes."""
    try:
        return _run_one(lane, command_name, argv_key, run_root, workspace)
    except RuntimeAuditError as exc:
        code = exc.code
    except OSError:
        code = "RUNTIME_AUDIT_IO_ERROR"
    except Exception:
        # Do not leak exception text: it may contain absolute paths or secrets.
        code = "RUNTIME_AUDIT_LANE_ERROR"
    return {
        "command": command_name,
        "signed_argv": list(lane[argv_key]),
        "timeout_seconds": lane["timeout_seconds"],
        "supervision": "supervised_subprocess_not_sandboxed",
        "execution": {
            "exit_code": None,
            "timed_out": False,
            "launch_error": True,
            "output_limit_exceeded": False,
            "cleanup_confirmed": False,
        },
        "artifact": None,
        "artifact_sha256": None,
        "normalized_artifact_sha256": None,
        "artifact_error": {
            "code": (
                code
                if re.fullmatch(r"[A-Z0-9_]{1,64}", code)
                else "RUNTIME_AUDIT_LANE_ERROR"
            ),
        },
    }


def run_runtime_audit_plan(
    plan: dict[str, Any],
    workspace_root: Path,
    output_root: Path,
    *,
    plan_sha256: str | None = None,
    max_parallelism: int = 1,
    execution_admission: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run exact target and known-bad argv for a previously verified plan in distinct evidence directories."""
    workspace = Path(workspace_root).resolve()
    max_parallelism = _require_parallelism(max_parallelism)
    policy = _check_parallel_admission(
        plan, workspace, max_parallelism, plan_sha256, execution_admission
    )
    output = _inside(
        workspace,
        Path(output_root)
        if Path(output_root).is_absolute()
        else workspace / output_root,
    )
    output.mkdir(parents=True, exist_ok=True)
    run_root = output / f"run-{uuid.uuid4()}"
    run_root.mkdir(parents=False, exist_ok=False)

    def run_lane(lane: dict[str, Any]) -> dict[str, Any]:
        # Scratch paths avoid artifact collisions; the signed execution policy,
        # not these directories, declares whether shared-workspace execution is safe.
        return {
            "id": lane["id"],
            "kind": lane["kind"],
            "target": _run_one_guarded(
                lane, "target", "target_argv", run_root, workspace
            ),
            "known_bad": _run_one_guarded(
                lane, "known_bad", "known_bad_argv", run_root, workspace
            ),
        }

    lanes = list(plan["lanes"])
    if max_parallelism == 1 or len(lanes) < 2:
        executions = [run_lane(lane) for lane in lanes]
    else:
        with ThreadPoolExecutor(
            max_workers=min(max_parallelism, len(lanes)), thread_name_prefix="cf-audit"
        ) as pool:
            futures = [pool.submit(run_lane, lane) for lane in lanes]
            executions = [future.result() for future in futures]
    result = {
        "schema": "factory.runtime-audit-execution.v1",
        "run_root": run_root.relative_to(workspace).as_posix(),
        "executions": executions,
        "execution_policy": {
            "max_parallelism": max_parallelism,
            "signed_policy": policy
            or {"max_parallelism": 1, "non_mutating": False, "resource_safe": False},
            "lane_isolation": "per-lane-scratch-subtree",
            "ordering": "manifest-order",
            "partial_lane_failure_policy": "record-incomplete-leg-and-preserve-sibling-evidence",
        },
        "authority": "none",
    }
    boundary = plan.get("runtime_boundary")
    if boundary is not None:
        # The local runner can prove its no-shell supervision facts, but never
        # upgrades those facts into a sandbox claim.  An independent request
        # therefore remains blocked until a separately signed collector result
        # is supplied to the evaluation API.
        result["plan_sha256"] = plan_sha256 or sha256_bytes(canonical_bytes(plan))
        result["runtime_boundary"] = capture_supervised_attestation(
            attestation_id=run_root.name,
            candidate_sha256=plan["candidate_sha256"],
            plan_sha256=result["plan_sha256"],
            environment_sha256=plan["environment"]["digest"],
            run_nonce=run_root.name,
        )
    return result
