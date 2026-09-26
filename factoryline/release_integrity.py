"""Read-only checks for Code Factory release workflow topology."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from .release_route_integrity import release_route_checks


SCHEMA = "factory.release_integrity.v1"
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
    next_job = re.search(r"(?m)^  [A-Za-z_][A-Za-z0-9_]*:\n", workflow[start:])
    return workflow[start : start + next_job.start()] if next_job else workflow[start:]


def _check(check_id: str, passed: bool, evidence: str) -> dict[str, Any]:
    return {"id": check_id, "passed": passed, "evidence": evidence}


def _fan_in_check(workflow: str) -> dict[str, Any]:
    """Check the reviewed, draft-first publication path and its artifact fan-in."""
    try:
        document = yaml.load(workflow, Loader=yaml.BaseLoader)
    except yaml.YAMLError:
        document = None

    document = document if isinstance(document, dict) else {}
    triggers = document.get("on", {})
    triggers = triggers if isinstance(triggers, dict) else {}
    dispatch = triggers.get("workflow_dispatch", {})
    dispatch = dispatch if isinstance(dispatch, dict) else {}
    inputs = dispatch.get("inputs", {})
    inputs = inputs if isinstance(inputs, dict) else {}
    release_tag_input = inputs.get("release_tag", {})
    release_tag_input = release_tag_input if isinstance(release_tag_input, dict) else {}

    jobs = document.get("jobs", {})
    jobs = jobs if isinstance(jobs, dict) else {}
    validator_names = ("validate_python", "validate_vscode", "validate_intellij")
    validator_jobs = [jobs.get(name, {}) for name in validator_names]
    artifact_names = (
        "release-python-${{ inputs.release_tag }}",
        "release-vscode-${{ inputs.release_tag }}",
        "release-intellij-${{ inputs.release_tag }}",
    )
    publish_job = jobs.get("publish", {})
    publish_steps = publish_job.get("steps", [])
    publish_steps = publish_steps if isinstance(publish_steps, list) else []
    step_content = [
        step.get("uses", step.get("run", ""))
        for step in publish_steps
        if isinstance(step, dict)
    ]

    def checkout_uses_requested_tag(job: Any) -> bool:
        if not isinstance(job, dict):
            return False
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            return False
        return any(
            isinstance(step, dict)
            and step.get("uses") == "actions/checkout@v5"
            and isinstance(step.get("with"), dict)
            and step["with"].get("ref") == "${{ needs.guard.outputs.candidate_commit }}"
            for step in steps
        )

    def validator_has_tagged_artifact(job: Any, artifact_name: str) -> bool:
        if not isinstance(job, dict):
            return False
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            return False
        return any(
            isinstance(step, dict)
            and step.get("uses") == "actions/upload-artifact@v7.0.1"
            and isinstance(step.get("with"), dict)
            and step["with"].get("name") == artifact_name
            for step in steps
        )

    guard = jobs.get("guard", {})
    guard_steps = guard.get("steps", []) if isinstance(guard, dict) else []
    guard_script = "\n".join(
        step.get("run", "") for step in guard_steps if isinstance(step, dict)
    )
    publish_permissions = publish_job.get("permissions", {})
    publish_permissions = (
        publish_permissions if isinstance(publish_permissions, dict) else {}
    )
    publish_environment = publish_job.get("environment", {})
    if isinstance(publish_environment, dict):
        publish_environment = publish_environment.get("name", "")
    downloaded_artifacts = [
        step.get("with", {}).get("name")
        for step in publish_steps
        if isinstance(step, dict)
        and step.get("uses") == "actions/download-artifact@v8.0.1"
        and isinstance(step.get("with"), dict)
    ]
    pypi_position = next(
        (
            index
            for index, content in enumerate(step_content)
            if content == "pypa/gh-action-pypi-publish@release/v1"
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

    passed = (
        set(triggers) == {"workflow_dispatch"}
        and document.get("concurrency", {}).get("group") == "publish-release-train"
        and document.get("concurrency", {}).get("cancel-in-progress") == "false"
        and release_tag_input.get("required") == "true"
        and release_tag_input.get("type") == "string"
        and set(jobs) >= {"guard", *validator_names, "publish"}
        and isinstance(guard, dict)
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
        and all(
            isinstance(job, dict)
            and job.get("needs") == ["guard"]
            and checkout_uses_requested_tag(job)
            and validator_has_tagged_artifact(job, artifact)
            for job, artifact in zip(validator_jobs, artifact_names, strict=True)
        )
        and isinstance(publish_job, dict)
        and publish_job.get("needs") == ["guard", *validator_names]
        and publish_environment == "pypi"
        and publish_permissions.get("contents") == "write"
        and publish_permissions.get("id-token") == "write"
        and checkout_uses_requested_tag(publish_job)
        and downloaded_artifacts == list(artifact_names)
        and pypi_position >= 0
        and public_release_position > pypi_position
        and all(
            _tag_guard_precedes(step, action)
            for step, action in (
                (
                    next(
                        (
                            item
                            for item in publish_steps
                            if "gh release upload" in str(item.get("run", ""))
                        ),
                        {},
                    ),
                    "gh release upload",
                ),
                (
                    next(
                        (
                            item
                            for item in publish_steps
                            if "gh release edit" in str(item.get("run", ""))
                        ),
                        {},
                    ),
                    "gh release edit",
                ),
            )
        )
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
    passed = (
        bool(publish)
        and marker in publish
        and "RELEASE_CONTRACT_PATH" in publish
        and 'test -n "$RELEASE_CONTRACT_PATH"' in publish
        and 'test -f "$RELEASE_CONTRACT_PATH"' in publish
        and command in publish
        and '--contract "$RELEASE_CONTRACT_PATH"' in publish
        and "--artifact-dir release-bundle/python" in publish
        and "--artifact-dir release-bundle/editors" in publish
        and "--metadata-path context/PROGRESS.md" in publish
        and ordered
        and no_bypass
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


def _openvsx_check(workflow: str) -> dict[str, Any]:
    authorize = _job(workflow, "authorize")
    validate = _job(workflow, "validate")
    publish = _job(workflow, "publish")
    passed = (
        "if: inputs.publish == true" in authorize
        and "environment: openvsx" in authorize
        and "Require the scoped Open VSX publisher token before candidate work"
        in authorize
        and "needs: authorize" in validate
        and "inputs.publish == false || needs.authorize.result == 'success'" in validate
        and "needs: [authorize, validate]" in publish
        and "needs.authorize.result == 'success'" in publish
        and "OPENVSX_TOKEN" in authorize
        and "release_contract:" in workflow
        and "python -m factoryline.cli release preflight" in validate
        and "--metadata-path context/PROGRESS.md" in validate
        and "scripts/verify_release_preflight.py" in validate
        and "scripts/verify_release_preflight.py" in publish
        and "openvsx-preflight.json" in publish
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
        and workflow.index(guard) < workflow.index("actions/setup-java@v5")
        and workflow.index(guard) < workflow.index("gradle/actions/setup-gradle@v6.2.0")
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
