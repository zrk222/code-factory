"""Read-only checks for Code Factory release workflow topology."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import subprocess
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from .release_route_integrity import _needs_include, release_route_checks


SCHEMA = "factory.release_integrity.v1"
FORGELINE_REASSESSMENT_VERSION = "0.10.8"
REASSESSMENT_SCHEMA = "factory.forgeline_reassessment.v1"
REASSESSMENT_POLICY_FILES = (
    "architecture-policy.json",
    "architecture-boundaries.json",
    ".factory/repository-scope.json",
    "pyproject.toml",
    "CONTRIBUTING.md",
    "docs/RELEASE_CHANNELS.md",
)
AUTHORITY = {
    "execution": False,
    "approval": False,
    "repair": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


def _read_workflow(root: Path, name: str) -> str:
    path = Path(root) / ".github" / "workflows" / name
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _read_source(root: Path, relative: str) -> str:
    try:
        return (Path(root) / relative).read_text(encoding="utf-8")
    except OSError:
        return ""


def _job(workflow: str, name: str) -> str:
    match = re.search(rf"(?m)^  {re.escape(name)}:\n", workflow)
    if match is None:
        return ""
    start = match.end()
    next_job = re.search(r"(?m)^  [A-Za-z_][A-Za-z0-9_-]*:\n", workflow[start:])
    return workflow[start : start + next_job.start()] if next_job else workflow[start:]


def _check(check_id: str, passed: bool, evidence: str) -> dict[str, Any]:
    return {"id": check_id, "passed": passed, "evidence": evidence}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sequence(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _checkout_uses_requested_tag(job: Any) -> bool:
    if not isinstance(job, dict):
        return False
    steps = job.get("steps", [])
    if not isinstance(steps, list):
        return False
    return any(
        isinstance(step, dict)
        and step.get("uses")
        == "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09"
        and isinstance(step.get("with"), dict)
        and step["with"].get("ref") == "${{ needs.guard.outputs.candidate_commit }}"
        for step in steps
    )


def _validator_has_tagged_artifact(job: Any, artifact_name: str) -> bool:
    if not isinstance(job, dict):
        return False
    steps = job.get("steps", [])
    if not isinstance(steps, list):
        return False
    return any(
        isinstance(step, dict)
        and step.get("uses")
        == "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
        and isinstance(step.get("with"), dict)
        and step["with"].get("name") == artifact_name
        for step in steps
    )


def _fan_in_context(workflow: str) -> dict[str, Any]:
    try:
        document = yaml.load(workflow, Loader=yaml.BaseLoader)
    except yaml.YAMLError:
        document = None

    document = _mapping(document)
    triggers = _mapping(document.get("on"))
    dispatch = _mapping(triggers.get("workflow_dispatch"))
    inputs = _mapping(dispatch.get("inputs"))
    release_tag_input = _mapping(inputs.get("release_tag"))
    jobs = _mapping(document.get("jobs"))
    validator_names = ("validate_python", "validate_vscode", "validate_intellij")
    validator_jobs = [jobs.get(name, {}) for name in validator_names]
    artifact_names = (
        "release-python-${{ inputs.release_tag }}",
        "release-vscode-${{ inputs.release_tag }}",
        "release-intellij-${{ inputs.release_tag }}",
    )
    publish_job = jobs.get("publish", {})
    publish_steps = _sequence(publish_job.get("steps", []))
    step_content = [
        step.get("uses", step.get("run", ""))
        for step in publish_steps
        if isinstance(step, dict)
    ]
    guard = jobs.get("guard", {})
    guard_steps = guard.get("steps", []) if isinstance(guard, dict) else []
    guard_script = "\n".join(
        step.get("run", "") for step in guard_steps if isinstance(step, dict)
    )
    publish_permissions = _mapping(publish_job.get("permissions", {}))
    publish_environment = publish_job.get("environment", {})
    if isinstance(publish_environment, dict):
        publish_environment = publish_environment.get("name", "")
    downloaded_artifacts = [
        step.get("with", {}).get("name")
        for step in publish_steps
        if isinstance(step, dict)
        and step.get("uses")
        == "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
        and isinstance(step.get("with"), dict)
    ]
    pypi_position = next(
        (
            index
            for index, content in enumerate(step_content)
            if content
            == "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33"
        ),
        -1,
    )
    public_release_position = next(
        (
            index
            for index, content in enumerate(step_content)
            if 'gh release edit "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --draft=false'
            in content
        ),
        -1,
    )
    return {
        "document": document,
        "triggers": triggers,
        "release_tag_input": release_tag_input,
        "jobs": jobs,
        "validator_names": validator_names,
        "validator_jobs": validator_jobs,
        "artifact_names": artifact_names,
        "publish_job": publish_job,
        "publish_steps": publish_steps,
        "guard": guard,
        "guard_script": guard_script,
        "publish_permissions": publish_permissions,
        "publish_environment": publish_environment,
        "downloaded_artifacts": downloaded_artifacts,
        "pypi_position": pypi_position,
        "public_release_position": public_release_position,
    }


def _dispatch_rules_pass(context: dict[str, Any]) -> bool:
    document = context["document"]
    triggers = context["triggers"]
    release_tag_input = context["release_tag_input"]
    return (
        set(triggers) == {"workflow_dispatch"}
        and document.get("concurrency", {}).get("group") == "publish-release-train"
        and document.get("concurrency", {}).get("cancel-in-progress") == "false"
        and release_tag_input.get("required") == "true"
        and release_tag_input.get("type") == "string"
    )


def _guard_rules_pass(context: dict[str, Any]) -> bool:
    guard = context["guard"]
    guard_script = context["guard_script"]
    return (
        isinstance(guard, dict)
        and '[[ "$GITHUB_REF" == "refs/heads/main" ]]' in guard_script
        and r'[[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]' in guard_script
        and 'gh release view "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --json isDraft --jq \'.isDraft\''
        in guard_script
        and '[[ "$is_draft" == "true" ]]' in guard_script
        and 'git merge-base --is-ancestor "$candidate_commit" origin/main'
        in guard_script
        and 'item["published_at"]' in guard_script
        and guard.get("outputs", {}).get("candidate_commit")
        == "${{ steps.candidate.outputs.commit }}"
    )


def _validator_jobs_pass(context: dict[str, Any]) -> bool:
    jobs = context["jobs"]
    names = context["validator_names"]
    artifacts = context["artifact_names"]
    return set(jobs) >= {"guard", *names, "publish"} and all(
        isinstance(job, dict)
        and job.get("needs") == ["guard"]
        and _checkout_uses_requested_tag(job)
        and _validator_has_tagged_artifact(job, artifact)
        for job, artifact in zip(context["validator_jobs"], artifacts, strict=True)
    )


def _publish_job_passes(context: dict[str, Any]) -> bool:
    publish_job = context["publish_job"]
    publish_steps = context["publish_steps"]
    validator_names = context["validator_names"]
    artifact_names = context["artifact_names"]
    return (
        isinstance(publish_job, dict)
        and publish_job.get("needs") == ["guard", *validator_names]
        and context["publish_environment"] == "pypi"
        and context["publish_permissions"].get("contents") == "write"
        and context["publish_permissions"].get("id-token") == "write"
        and _checkout_uses_requested_tag(publish_job)
        and context["downloaded_artifacts"] == list(artifact_names)
        and context["pypi_position"] >= 0
        and context["public_release_position"] > context["pypi_position"]
        and _publish_tag_guards_pass(publish_steps)
    )


def _publish_tag_guards_pass(publish_steps: list[Any]) -> bool:
    action_scripts = (
        ("gh release upload", "gh release upload"),
        ("gh release edit", "gh release edit"),
    )
    for search, action in action_scripts:
        step = next(
            (item for item in publish_steps if search in str(item.get("run", ""))),
            {},
        )
        if not _tag_guard_precedes(step, action):
            return False
    return True


def _fan_in_check(workflow: str) -> dict[str, Any]:
    """Check the reviewed, draft-first publication path and its artifact fan-in."""
    context = _fan_in_context(workflow)
    passed = (
        _dispatch_rules_pass(context)
        and _guard_rules_pass(context)
        and _validator_jobs_pass(context)
        and _publish_job_passes(context)
    )
    return _check(
        "RELEASE_FAN_IN_EXACT",
        passed,
        "draft-only dispatch, immutable tag builds, exact artifact fan-in, protected PyPI publish, and delayed public release",
    )


def _tag_guard_precedes(step: dict, action: str) -> bool:
    script = str(step.get("run", ""))
    fetch = 'git fetch --no-tags origin "refs/tags/${RELEASE_TAG}"'
    comparison = (
        '[[ "$(git rev-parse \'FETCH_HEAD^{commit}\')" == "$EXPECTED_COMMIT" ]] || {'
    )
    return (
        fetch in script
        and comparison in script
        and "exit 1" in script
        and script.index(fetch)
        < script.index(comparison)
        < script.index("exit 1")
        < script.index(action)
        and step.get("env", {}).get("EXPECTED_COMMIT")
        == "${{ needs.guard.outputs.candidate_commit }}"
    )


def _candidate_preflight_marker(publish: str, marker: str) -> bool:
    return bool(publish) and marker in publish


def _candidate_contract_path_required(publish: str) -> bool:
    return (
        "RELEASE_CONTRACT_PATH" in publish
        and 'test -n "$RELEASE_CONTRACT_PATH"' in publish
        and 'test -f "$RELEASE_CONTRACT_PATH"' in publish
    )


def _candidate_preflight_command_bound(publish: str, command: str) -> bool:
    return (
        command in publish
        and '--contract "$RELEASE_CONTRACT_PATH"' in publish
        and "--artifact-dir release-bundle/python" in publish
        and "--artifact-dir release-bundle/editors" in publish
        and "--metadata-path context/PROGRESS.md" in publish
    )


def _candidate_preflight_ordered(publish: str, marker: str) -> bool:
    try:
        gate_index = publish.index(marker)
        upload_index = publish.index("gh release upload")
        pypi_index = publish.index("pypa/gh-action-pypi-publish")
    except ValueError:
        gate_index = upload_index = pypi_index = -1
    ordered = (
        gate_index >= 0
        and upload_index >= 0
        and pypi_index >= 0
        and gate_index < upload_index
        and gate_index < pypi_index
    )
    no_bypass = ordered and "continue-on-error" not in publish[gate_index:upload_index]
    return ordered and no_bypass


def _candidate_preflight_check(workflow: str) -> dict[str, Any]:
    """Require the release owner to supply a sealed candidate receipt before upload.

    A green language-specific build is not a release identity proof.  The
    publication job must therefore fail closed when the protected environment
    has not supplied a workspace-contained release contract, and it must run
    the exact candidate preflight before the first external upload step.
    """
    publish = _job(workflow, "publish")
    marker = "Require sealed release candidate preflight before external publication"
    command = "python -m factoryline.cli release preflight"
    passed = (
        _candidate_preflight_marker(publish, marker)
        and _candidate_contract_path_required(publish)
        and _candidate_preflight_command_bound(publish, command)
        and _candidate_preflight_ordered(publish, marker)
    )
    return _check(
        "RELEASE_CANDIDATE_PREFLIGHT_REQUIRED",
        passed,
        "sealed source/commit/artifact preflight is mandatory before external release upload",
    )


def _partition_check(workflow: str) -> dict[str, Any]:
    python_job = _job(workflow, "validate_python")
    vscode_job = _job(workflow, "validate_vscode")
    intellij_job = _job(workflow, "validate_intellij")
    passed = (
        all(
            value in python_job
            for value in (
                "python -m pytest -q",
                "python -m build",
                "python -m twine check dist/*",
                "Clean wheel smoke",
            )
        )
        and all(
            value in vscode_job
            for value in ("npm ci", "npm run audit", "npm test", "vsce package")
        )
        and all(
            value in intellij_job
            for value in (
                "./gradlew check guardianReleaseGate",
                "setup-java",
                "setup-gradle",
            )
        )
        and "npm ci" not in python_job + intellij_job
        and "./gradlew" not in python_job + vscode_job
    )
    return _check(
        "RELEASE_VALIDATION_PARTITIONED",
        passed,
        "language-specific validation stays in its own job",
    )


def _openvsx_authorization_passes(authorize: str) -> bool:
    return (
        "if: inputs.publish == true" in authorize
        and "environment: openvsx" in authorize
        and "Require the scoped Open VSX publisher token before candidate work"
        in authorize
    )


def _openvsx_dependency_passes(validate: str, publish: str) -> bool:
    return (
        _needs_include(validate, {"authorize"})
        and "inputs.publish == false || needs.authorize.result == 'success'" in validate
        and _needs_include(publish, {"authorize", "validate"})
        and "needs.authorize.result == 'success'" in publish
    )


def _openvsx_preflight_passes(workflow: str, validate: str, publish: str) -> bool:
    exception_guard = validate.find("Validate one-time cadence exception request")
    preflight_step = validate.find("Require the sealed candidate preflight")
    exception_gate = validate[exception_guard:preflight_step]
    preflight_gate = validate[preflight_step:]
    return (
        "release_contract:" in workflow
        and "cadence_exception_reason:" in workflow
        and 0 <= exception_guard < preflight_step
        and 'test "$PUBLISH" = true' in exception_gate
        and 'test "$RELEASE_REF" = vscode-v1.1.4+build.1' in exception_gate
        and "require('./package.json').version\")\" = 1.1.4" in exception_gate
        and 'test "${#EXCEPTION_REASON}" -ge 12 && test "${#EXCEPTION_REASON}" -le 500'
        in exception_gate
        and 'if [[ -n "$EXCEPTION_REASON" ]]; then' in preflight_gate
        and "GITHUB_RUN_ID: ${{ github.run_id }}" in preflight_gate
        and "GITHUB_RUN_ATTEMPT: ${{ github.run_attempt }}" in preflight_gate
        and "exception_args=(--cadence-exception .factory/release-cadence-exception.json)"
        in preflight_gate
        and '"${exception_args[@]}"' in preflight_gate
        and '"workflow_run_attempt": os.environ["GITHUB_RUN_ATTEMPT"]' in preflight_gate
        and "python -m factoryline.cli release preflight" in validate
        and "--metadata-path context/PROGRESS.md" in validate
        and "scripts/verify_release_preflight.py" in validate
        and "scripts/verify_release_preflight.py" in publish
        and "openvsx-preflight.json" in publish
    )


def _openvsx_check(workflow: str) -> dict[str, Any]:
    authorize = _job(workflow, "authorize")
    validate = _job(workflow, "validate")
    publish = _job(workflow, "publish")
    passed = (
        _openvsx_authorization_passes(authorize)
        and _openvsx_dependency_passes(validate, publish)
        and "OPENVSX_TOKEN" in authorize
        and _openvsx_preflight_passes(workflow, validate, publish)
    )
    return _check(
        "OPENVSX_AUTHORIZATION_EARLY",
        passed,
        "protected publication is authorized before candidate validation",
    )


def _pypi_check(workflow: str) -> dict[str, Any]:
    publish = _job(workflow, "publish")
    passed = (
        "environment: pypi" in publish
        and "id-token: write" in publish
        and "PYPI_TOKEN" not in workflow
    )
    return _check(
        "PYPI_TRUSTED_PUBLISHING",
        passed,
        "PyPI uses protected OIDC without a stored PyPI token",
    )


def _jetbrains_check(workflow: str) -> dict[str, Any]:
    guard = "Require an open Marketplace binary-update slot"
    passed = (
        guard in workflow
        and "--require-upload-slot" in workflow
        and workflow.index(guard)
        < workflow.index("actions/setup-java@b6effb05e454b25005698d916606bdc6ffcbf961")
        and workflow.index(guard)
        < workflow.index(
            "gradle/actions/setup-gradle@3f131e8634966bd73d06cc69884922b02e6faf92"
        )
    )
    return _check(
        "JETBRAINS_APPROVAL_GUARD",
        passed,
        "an occupied Marketplace binary-update slot blocks before Java or Gradle setup",
    )


def _intellij_compatibility_check(root: Path) -> dict[str, Any]:
    actions = _read_source(
        root,
        "editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineActions.kt",
    )
    settings = _read_source(root, "editors/intellij/settings.gradle.kts")
    build = _read_source(root, "editors/intellij/build.gradle.kts")
    passed = (
        "Messages.showChooseDialog" not in actions
        and actions.count("Messages.showDialog(") >= 4
        and all(
            value in actions
            for value in (
                "options, 0, Messages.getQuestionIcon()",
                "graphEvents, 0, Messages.getQuestionIcon()",
                "roles, 0, Messages.getQuestionIcon()",
                "risks, 1, Messages.getQuestionIcon()",
            )
        )
        and 'FactoryLineExecutionConfirmation.confirm(project, "Prepare Repair Scope")'
        in actions
        and 'id("org.jetbrains.kotlin.jvm") version "2.4.10"' in settings
        and "jvmDefault.set(JvmDefaultMode.NO_COMPATIBILITY)" in build
    )
    return _check(
        "INTELLIJ_COMPATIBILITY_DECLARED",
        passed,
        "supported chooser calls and Kotlin JVM-default configuration are declared",
    )


def _huggingface_metadata_check(root: Path) -> dict[str, Any]:
    workflow = _read_workflow(root, "huggingface-space.yml")
    readme = _read_source(root, "deploy/huggingface/README.md")
    match = re.search(r"(?m)^short_description:\s*(.+)$", readme)
    short_description = match.group(1).strip().strip("\"'") if match else ""
    validate = "Validate static Space metadata before remote upload"
    passed = (
        bool(match)
        and len(short_description) <= 60
        and "python scripts/huggingface_space_metadata.py --readme deploy/huggingface/README.md --json"
        in workflow
        and workflow.index(validate)
        < workflow.index("Install Hugging Face CLI")
        < workflow.index("Publish static Space")
    )
    return _check(
        "HUGGINGFACE_METADATA_PREFLIGHT",
        passed,
        "Space-card metadata is bounded before remote upload",
    )


def _python_package_data_check(root: Path) -> dict[str, Any]:
    project = _read_source(root, "pyproject.toml")
    passed = (
        "include-package-data = false" in project
        and 'factoryline = ["builtin_packs/**/*.json", "builtin_packs/**/*.yaml", "data/*.json", "hosted_console.html", "graph_ops.html"]'
        in project
        and "[tool.setuptools.exclude-package-data]" in project
        and 'factoryline = ["**/__pycache__/*", "**/*.py[cod]"]' in project
    )
    return _check(
        "PYTHON_PACKAGE_DATA_EXPLICIT",
        passed,
        "wheel package data is explicit, source formats are allowlisted, and bytecode is excluded",
    )


def _checks(root: Path) -> list[dict[str, Any]]:
    publish = _read_workflow(root, "publish.yml")
    openvsx = _read_workflow(root, "openvsx.yml")
    return [
        _fan_in_check(publish),
        _candidate_preflight_check(publish),
        _partition_check(publish),
        _openvsx_check(openvsx),
        *release_route_checks(root),
        _pypi_check(publish),
        _jetbrains_check(_read_workflow(root, "jetbrains-marketplace.yml")),
        _intellij_compatibility_check(root),
        _huggingface_metadata_check(root),
        _python_package_data_check(root),
    ]


def release_integrity(root: Path) -> dict[str, Any]:
    """Inspect declared release safety boundaries without running a workflow."""
    workspace = Path(root).resolve()
    checks = _checks(workspace)
    failures = [item["id"] for item in checks if not item["passed"]]
    ok = not failures
    return {
        "schema": SCHEMA,
        "marker": "RELEASE_INTEGRITY_READ_ONLY" if ok else "RELEASE_INTEGRITY_FAILURE",
        "markers": ["RELEASE_INTEGRITY_READ_ONLY"]
        + ([] if ok else ["RELEASE_INTEGRITY_FAILURE"]),
        "root": str(workspace),
        "ok": ok,
        "checks": checks,
        "failed_check_ids": failures,
        "next_action": {
            "action": "review_external_publish_gates"
            if ok
            else "repair_release_workflow",
            "reason": "workflow topology is complete"
            if ok
            else "required workflow boundaries are missing",
        },
        "external_requirements": [
            "Open VSX publication still requires OPENVSX_TOKEN in the protected openvsx environment.",
            "Visual Studio Marketplace publication still requires VSCE_PAT in the protected vscode-marketplace environment.",
            "JetBrains publication still requires JETBRAINS_MARKETPLACE_TOKEN in the protected jetbrains-marketplace environment.",
            "JetBrains publication still requires Marketplace approval to clear before a new update.",
            "Hugging Face Space publication still requires the configured HF_TOKEN GitHub Actions secret.",
        ],
        "authority": AUTHORITY,
    }


def render_release_integrity(result: dict[str, Any]) -> str:
    """Render the exact local integrity result without implying publication readiness."""
    state = (
        "ready for external-gate review" if result["ok"] else "workflow repair required"
    )
    lines = [f"release integrity: {state}"]
    lines.extend(
        f"- {'PASS' if item['passed'] else 'FAIL'} {item['id']}: {item['evidence']}"
        for item in result["checks"]
    )
    lines.append(f"next: {result['next_action']['action']}")
    lines.append(
        "authority: no execution, publication, credential, or approval authority"
    )
    return "\n".join(lines)


def _resolve_git_base(root: Path, base: str) -> tuple[str | None, str | None]:
    try:
        resolved = subprocess.run(
            ["git", "rev-parse", "--verify", "--end-of-options", f"{base}^{{commit}}"],
            cwd=root,
            capture_output=True,
            timeout=10,
            check=False,
        )
        oid = resolved.stdout.decode("ascii").strip()
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        return None, "Git history could not be inspected."
    if resolved.returncode or not re.fullmatch(r"[a-fA-F0-9]{40,64}", oid):
        return None, "Git base does not resolve to one commit."
    return oid, None


def _git_evidence_delta(root: Path, oid: str) -> tuple[bytes, str | None]:
    try:
        result = subprocess.run(
            [
                "git",
                "diff",
                "--name-status",
                "--no-renames",
                "-z",
                oid,
                "--",
                "evidence/self-audit",
            ],
            cwd=root,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        return b"", "Git history could not be inspected."
    if result.returncode or len(result.stdout) > 1_000_000:
        return b"", "Git delta is unavailable or exceeds the review bound."
    return result.stdout, None


def _changed_evidence_paths(output: bytes) -> tuple[list[tuple[str, str]], str | None]:
    if not output:
        return [], None
    try:
        parts = output.decode("utf-8").rstrip("\0").split("\0")
    except UnicodeError:
        return [], "Git delta contains a non-UTF-8 path."
    if len(parts) % 2:
        return [], "Git delta has an unexpected name-status shape."
    changed = [
        (status, path)
        for status, path in zip(parts[::2], parts[1::2])
        if re.search(r"\d{4}-\d{2}-\d{2}.*\.json$", path)
    ]
    return changed, None


def _review_git_delta(
    root: Path, base: str
) -> tuple[list[tuple[str, str]], str | None, str | None]:
    """Read a bounded Git delta without interpreting file content as instructions."""
    if not isinstance(base, str) or not base or len(base) > 200 or "\0" in base:
        return [], None, "Git base is missing or invalid."
    oid, error = _resolve_git_base(root, base)
    if error:
        return [], None, error
    output, error = _git_evidence_delta(root, oid)
    if error:
        return [], oid, error
    changed, error = _changed_evidence_paths(output)
    return changed, oid, error


def _retired_evidence_digests(root: Path) -> tuple[dict[str, str], str | None]:
    """Read explicit hash receipts for historical self-audits retired from the tree."""
    path = root / ".factory" / "evidence-retirement.json"
    try:
        if path.stat().st_size > 64_000:
            return {}, "Evidence retirement manifest exceeds the review bound."
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}, None
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}, "Evidence retirement manifest is unreadable or invalid JSON."
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != "factory.evidence_retirement.v1"
    ):
        return {}, "Evidence retirement manifest has an unsupported schema."
    entries = payload.get("retirements")
    if not isinstance(entries, list) or len(entries) > 32:
        return {}, "Evidence retirement manifest has an invalid retirement list."
    result: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "reason"}:
            return (
                {},
                "Evidence retirement entries must declare path, sha256, and reason.",
            )
        relative = entry["path"]
        digest = entry["sha256"]
        reason = entry["reason"]
        if (
            not isinstance(relative, str)
            or not re.fullmatch(
                r"evidence/self-audit/[^/]*\d{4}-\d{2}-\d{2}[^/]*\.json", relative
            )
            or not isinstance(digest, str)
            or not re.fullmatch(r"[a-f0-9]{64}", digest)
            or not isinstance(reason, str)
            or not reason.strip()
            or len(reason) > 500
            or relative in result
        ):
            return (
                {},
                "Evidence retirement entry is malformed, duplicated, or out of scope.",
            )
        result[relative] = digest
    return result, None


def _git_blob_sha256(
    root: Path, oid: str, relative: str
) -> tuple[str | None, str | None]:
    try:
        result = subprocess.run(
            ["git", "show", f"{oid}:{relative}"],
            cwd=root,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, "Historical evidence blob could not be read."
    if result.returncode or len(result.stdout) > 2_000_000:
        return (
            None,
            "Historical evidence blob is unavailable or exceeds the review bound.",
        )
    return hashlib.sha256(result.stdout).hexdigest(), None


def _fresh_reassessment_date(root: Path, relative: str) -> str | None:
    reassessment_date = _reassessment_date_from_path(relative)
    if reassessment_date is None:
        return None
    return _verify_fresh_reassessment(root, relative, reassessment_date)


def _reassessment_date_from_path(relative: str) -> str | None:
    match = re.search(r"(\d{4}-\d{2}-\d{2})[^/]*\.json$", relative)
    if not match or not relative.startswith("evidence/self-audit/"):
        return None
    reassessment_date = match.group(1)
    try:
        parsed_date = date.fromisoformat(reassessment_date)
        if parsed_date.isoformat() != reassessment_date or parsed_date > date.today():
            return None
    except ValueError:
        return None
    return reassessment_date


def _verify_fresh_reassessment(
    root: Path, relative: str, reassessment_date: str
) -> str | None:
    path = root / relative
    try:
        with path.open("rb") as stream:
            raw = stream.read(2_000_001)
        if len(raw) > 2_000_000:
            return None
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not _valid_reassessment_envelope(payload):
        return None
    report = payload["report"]
    source_digest = _source_snapshot_digest(
        root, report["metrics"]["scope"]["code_files"]
    )
    if source_digest is None or source_digest != payload.get("source_sha256"):
        return None
    measured = _run_forgeline_reassessment(root)
    if measured is None:
        return None
    try:
        matches = _canonical_json(measured) == _canonical_json(report)
    except (TypeError, ValueError):
        return None
    if not matches:
        return None
    return reassessment_date


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _source_snapshot_digest(root: Path, code_files: list[str]) -> str | None:
    paths = set(code_files)
    paths.update(REASSESSMENT_POLICY_FILES)
    digest = hashlib.sha256()
    total_bytes = 0
    for relative in sorted(paths):
        if (
            not isinstance(relative, str)
            or not relative
            or Path(relative).is_absolute()
            or ".." in relative.replace("\\", "/").split("/")
        ):
            return None
        path = root / relative
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
                return None
            raw_size = resolved.stat().st_size
            total_bytes += raw_size
            if raw_size > 50_000_000 or total_bytes > 500_000_000:
                return None
            # Git's text checkout may use CRLF on Windows and LF in CI. Bind
            # canonical text bytes so the same committed source is portable.
            content = resolved.read_bytes().replace(b"\r\n", b"\n")
            size = len(content)
            if size > 50_000_000:
                return None
            path_hash = hashlib.sha256(content)
        except OSError:
            return None
        digest.update(os.fsencode(relative))
        digest.update(b"\0")
        digest.update(size.to_bytes(8, "big"))
        digest.update(path_hash.digest())
    return digest.hexdigest()


def _run_forgeline_reassessment(root: Path) -> dict[str, Any] | None:
    try:
        provenance_result = subprocess.run(
            ["forge", "--version", "--json"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        provenance = json.loads(provenance_result.stdout)
        if (
            provenance_result.returncode != 0
            or not isinstance(provenance, dict)
            or provenance.get("package") != "code-factory-2-forge"
            or provenance.get("version") != FORGELINE_REASSESSMENT_VERSION
            or provenance.get("identity_complete") is not True
        ):
            return None
        result = subprocess.run(
            ["forge", "qa", "--repo-wide", "--root", str(root), "--strict"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=240,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None
    if result.returncode != 0 or len(result.stdout.encode("utf-8")) > 2_000_000:
        return None
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    return report if _valid_quality_reassessment(report) else None


def _finite_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _valid_reassessment_metrics(metrics: Any) -> bool:
    if not isinstance(metrics, dict):
        return False
    scope = metrics.get("scope")
    if not isinstance(scope, dict) or scope.get("kind") != "repo_wide":
        return False
    code_files = scope.get("code_files")
    if (
        not isinstance(code_files, list)
        or not code_files
        or any(not isinstance(item, str) or not item for item in code_files)
        or len(set(code_files)) != len(code_files)
    ):
        return False
    if not _valid_reassessment_quality_flags(metrics):
        return False
    for key in ("coverage_intent", "doc_ratio"):
        value = metrics.get(key)
        if not _finite_number(value) or not 0 <= value <= 1:
            return False
    if not _valid_reassessment_scores(metrics):
        return False
    complexity = metrics.get("max_complexity")
    if not isinstance(complexity, int) or isinstance(complexity, bool):
        return False
    return 0 <= complexity <= 10


def _valid_reassessment_quality_flags(metrics: dict[str, Any]) -> bool:
    return (
        metrics.get("skipped_paths") == []
        and metrics.get("complexity_policy") == "hard"
        and metrics.get("coverage_assessment") == "measured"
        and metrics.get("behavioral_proof_status") == "available"
    )


def _valid_reassessment_scores(metrics: dict[str, Any]) -> bool:
    for key in ("composite", "security_score"):
        value = metrics.get(key)
        if not _finite_number(value) or not 95 <= value <= 100:
            return False
    return True


def _valid_reassessment_units(units: Any, checked: int, passed: int) -> bool:
    if not isinstance(units, list) or len(units) != checked:
        return False
    unit_passes = 0
    for unit in units:
        if not isinstance(unit, dict) or unit.get("stage") != "qa_audit":
            return False
        unit_id = unit.get("unit")
        if not isinstance(unit_id, str) or not unit_id:
            return False
        if not isinstance(unit.get("passed"), bool):
            return False
        if not isinstance(unit.get("evidence"), str) or not unit["evidence"].strip():
            return False
        failure_class = unit.get("failure_class")
        if failure_class is not None and (
            not isinstance(failure_class, str) or not failure_class
        ):
            return False
        unit_passes += unit["passed"]
    return unit_passes == passed


def _valid_reassessment_attribution(attribution: Any) -> bool:
    if not isinstance(attribution, dict) or attribution.get("stage") != "qa_audit":
        return False
    checked = attribution.get("n_checked")
    passed = attribution.get("n_passed")
    if not isinstance(checked, int) or isinstance(checked, bool) or checked <= 0:
        return False
    if (
        not isinstance(passed, int)
        or isinstance(passed, bool)
        or not 0 <= passed <= checked
    ):
        return False
    if not _valid_reassessment_units(attribution.get("units"), checked, passed):
        return False
    rate = attribution.get("rate")
    return (
        _finite_number(rate)
        and 0 <= rate <= 1
        and math.isclose(rate, passed / checked, rel_tol=0, abs_tol=1e-9)
    )


def _valid_quality_reassessment(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("grade") != "A" or payload.get("passed") is not True:
        return False
    return (
        payload.get("findings") == []
        and _valid_reassessment_metrics(payload.get("metrics"))
        and _valid_reassessment_attribution(payload.get("attribution"))
    )


def _valid_reassessment_envelope(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    tool = payload.get("tool")
    return (
        payload.get("schema") == REASSESSMENT_SCHEMA
        and isinstance(tool, dict)
        and tool.get("package") == "code-factory-2-forge"
        and tool.get("version") == FORGELINE_REASSESSMENT_VERSION
        and tool.get("identity_complete") is True
        and isinstance(payload.get("source_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", payload["source_sha256"]) is not None
        and _valid_quality_reassessment(payload.get("report"))
    )


def _validate_historical_evidence_changes(
    root: Path,
    base_oid: str | None,
    historical: list[tuple[str, str]],
    retirements: dict[str, str],
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[str]]:
    findings: list[dict[str, str]] = []
    retired: list[dict[str, str]] = []
    gaps: list[str] = []
    reassessment_dates: list[str] = []
    retired_dates: list[str] = []
    for status, relative in historical:
        if status == "A":
            fresh_date = _fresh_reassessment_date(root, relative)
            if fresh_date:
                reassessment_dates.append(fresh_date)
            continue
        expected_digest = retirements.get(relative)
        if status == "D" and expected_digest is not None and base_oid is not None:
            actual_digest, error = _git_blob_sha256(root, base_oid, relative)
            if error:
                gaps.append(error)
            elif actual_digest == expected_digest:
                retired.append({"path": relative, "sha256": actual_digest or ""})
                date_match = re.search(r"(\d{4}-\d{2}-\d{2})[^/]*\.json$", relative)
                if date_match:
                    retired_dates.append(date_match.group(1))
                retirements.pop(relative)
                continue
            else:
                findings.append(
                    {
                        "code": "EVIDENCE_RETIREMENT_DIGEST_MISMATCH",
                        "path": relative,
                        "action": "Retain the original evidence or correct the hash-only retirement record.",
                    }
                )
                retirements.pop(relative)
                continue
        findings.append(
            {
                "code": "HISTORICAL_EVIDENCE_MUTATED",
                "path": relative,
                "action": "Restore the historical receipt or retire it with an exact base-blob SHA-256 record and a new dated reassessment.",
            }
        )
        retirements.pop(relative, None)
    if retirements:
        findings.append(
            {
                "code": "UNMATCHED_EVIDENCE_RETIREMENT",
                "path": ".factory/evidence-retirement.json",
                "action": "Remove retirement entries that do not exactly match a deleted historical evidence blob.",
            }
        )
    if retired and (
        not reassessment_dates
        or max(reassessment_dates) <= max(retired_dates, default="0000-00-00")
    ):
        findings.append(
            {
                "code": "EVIDENCE_RETIREMENT_WITHOUT_REASSESSMENT",
                "path": "evidence/self-audit",
                "action": "Add a valid, newer dated ForgeLine reassessment when retiring historical audit evidence.",
            }
        )
    return findings, retired, gaps


def _release_review_conflict(root: Path) -> tuple[bool, str | None]:
    documents = []
    for relative in ("CONTRIBUTING.md", "docs/RELEASE_CHANNELS.md"):
        path = root / relative
        try:
            if path.stat().st_size > 1_000_000:
                return False, f"{relative} exceeds the review bound."
            documents.append(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError):
            return False, f"{relative} could not be read."
    combined = "\n".join(documents)
    requires = bool(
        re.search(
            r"\b(?:every|each|all)\s+(?:public\s+)?releases?\s+requires?\s+approval\s+by\s+"
            r"(?:a\s+)?human\s+other\s+than\b|(?<!longer )(?<!not )\brequires?\s+(?:a\s+)?second\s+human\b",
            combined,
            re.IGNORECASE,
        )
    )
    waives = bool(
        re.search(
            r"\bno\s+longer\s+require\s+(?:a\s+)?second\s+human\b",
            combined,
            re.IGNORECASE,
        )
    )
    return requires and waives, None


def review_regression_audit(root: Path, base: str) -> dict[str, Any]:
    """Catch dated-evidence rewrites and conflicting release-review rules in a PR."""
    workspace = Path(root).resolve()
    historical, base_oid, git_error = _review_git_delta(workspace, base)
    conflict, document_error = _release_review_conflict(workspace)
    retirements, retirement_error = _retired_evidence_digests(workspace)
    findings, retired, retirement_gaps = _validate_historical_evidence_changes(
        workspace, base_oid, historical, retirements
    )
    if conflict:
        findings.append(
            {
                "code": "RELEASE_REVIEW_POLICY_CONFLICT",
                "path": "CONTRIBUTING.md; docs/RELEASE_CHANNELS.md",
                "action": "Align both documents with the selected reviewer and provider gates.",
            }
        )
    gaps = [
        item
        for item in (git_error, document_error, retirement_error, *retirement_gaps)
        if item
    ]
    return {
        "schema": "factory.review-regression-audit.v1",
        "state": "INCOMPLETE" if gaps else "BLOCKED" if findings else "CLEAN",
        "base": base,
        "root": str(workspace),
        "findings": findings,
        "retired_evidence": retired,
        "gaps": gaps,
        "scope": "Dated self-audit JSON history, hash-verified evidence retirement, and two release-review documents; text matching is bounded.",
        "behavioral_checks": "Muse receipt freshness, ignored-policy binding, HMAC tampering, and on-demand lifecycle require adversarial tests in tests/test_langchain_plugin.py; this static check does not execute them.",
        "authority": "Read-only diagnostic; no approval, merge, publication, or security certification.",
    }
