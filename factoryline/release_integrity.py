"""Read-only checks for Code Factory release workflow topology."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any


SCHEMA = "factory.release_integrity.v1"
AUTHORITY = {
    "execution": False,
    "approval": False,
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
    return workflow[start:start + next_job.start()] if next_job else workflow[start:]


def _check(check_id: str, passed: bool, evidence: str) -> dict[str, Any]:
    return {"id": check_id, "passed": passed, "evidence": evidence}


def _fan_in_check(workflow: str) -> dict[str, Any]:
    validator_names = ("validate_python", "validate_vscode", "validate_intellij")
    validator_jobs = [_job(workflow, name) for name in validator_names]
    artifact_names = (
        "release-python-${{ github.event.release.tag_name }}",
        "release-vscode-${{ github.event.release.tag_name }}",
        "release-intellij-${{ github.event.release.tag_name }}",
    )
    publish_job = _job(workflow, "publish")
    passed = (
        all(validator_jobs)
        and all("needs:" not in job for job in validator_jobs)
        and "needs: [validate_python, validate_vscode, validate_intellij]" in publish_job
        and all(name in workflow for name in artifact_names)
        and "path: release-bundle/python" in publish_job
        and publish_job.count("path: release-bundle/editors") == 2
    )
    return _check("RELEASE_FAN_IN_EXACT", passed, "three independent validators with exact artifact fan-in")


def _partition_check(workflow: str) -> dict[str, Any]:
    python_job = _job(workflow, "validate_python")
    vscode_job = _job(workflow, "validate_vscode")
    intellij_job = _job(workflow, "validate_intellij")
    passed = (
        all(value in python_job for value in ("python -m pytest -q", "python -m build", "python -m twine check dist/*", "Clean wheel smoke"))
        and all(value in vscode_job for value in ("npm ci", "npm run audit", "npm test", "vsce package"))
        and all(value in intellij_job for value in ("./gradlew check buildPlugin verifyPlugin marketplacePreflight", "setup-java", "setup-gradle"))
        and "npm ci" not in python_job + intellij_job
        and "./gradlew" not in python_job + vscode_job
    )
    return _check("RELEASE_VALIDATION_PARTITIONED", passed, "language-specific validation stays in its own job")


def _openvsx_check(workflow: str) -> dict[str, Any]:
    authorize = _job(workflow, "authorize")
    validate = _job(workflow, "validate")
    publish = _job(workflow, "publish")
    passed = (
        "if: inputs.publish == true" in authorize
        and "environment: openvsx" in authorize
        and "Require the scoped Open VSX publisher token before candidate work" in authorize
        and "needs: authorize" in validate
        and "inputs.publish == false || needs.authorize.result == 'success'" in validate
        and "needs: [authorize, validate]" in publish
        and "needs.authorize.result == 'success'" in publish
        and "OPENVSX_TOKEN" in authorize
    )
    return _check("OPENVSX_AUTHORIZATION_EARLY", passed, "protected publication is authorized before candidate validation")


def _pypi_check(workflow: str) -> dict[str, Any]:
    publish = _job(workflow, "publish")
    passed = "environment: pypi" in publish and "id-token: write" in publish and "PYPI_TOKEN" not in workflow
    return _check("PYPI_TRUSTED_PUBLISHING", passed, "PyPI uses protected OIDC without a stored PyPI token")


def _jetbrains_check(workflow: str) -> dict[str, Any]:
    guard = "Require the previous Marketplace update to be clear"
    passed = (
        guard in workflow
        and "--require-clear" in workflow
        and workflow.index(guard) < workflow.index("actions/setup-java@v5")
        and workflow.index(guard) < workflow.index("gradle/actions/setup-gradle@v6.2.0")
    )
    return _check("JETBRAINS_APPROVAL_GUARD", passed, "pending Marketplace approval blocks before Java or Gradle setup")


def _intellij_compatibility_check(root: Path) -> dict[str, Any]:
    actions = _read_source(root, "editors/intellij/src/main/kotlin/app/factoryline/intellij/FactoryLineActions.kt")
    settings = _read_source(root, "editors/intellij/settings.gradle.kts")
    build = _read_source(root, "editors/intellij/build.gradle.kts")
    passed = (
        "Messages.showChooseDialog" not in actions
        and actions.count("Messages.showDialog(") == 4
        and all(value in actions for value in ("options, 0, Messages.getQuestionIcon()", "graphEvents, 0, Messages.getQuestionIcon()", "roles, 0, Messages.getQuestionIcon()", "risks, 1, Messages.getQuestionIcon()"))
        and 'id("org.jetbrains.kotlin.jvm") version "2.4.10"' in settings
        and "jvmDefault.set(JvmDefaultMode.NO_COMPATIBILITY)" in build
    )
    return _check("INTELLIJ_COMPATIBILITY_DECLARED", passed, "supported chooser calls and Kotlin JVM-default configuration are declared")


def _huggingface_metadata_check(root: Path) -> dict[str, Any]:
    workflow = _read_workflow(root, "huggingface-space.yml")
    readme = _read_source(root, "deploy/huggingface/README.md")
    match = re.search(r"(?m)^short_description:\s*(.+)$", readme)
    short_description = match.group(1).strip().strip('"\'') if match else ""
    validate = "Validate static Space metadata before remote upload"
    passed = (
        bool(match)
        and len(short_description) <= 60
        and "python scripts/huggingface_space_metadata.py --readme deploy/huggingface/README.md --json" in workflow
        and workflow.index(validate) < workflow.index("Install Hugging Face CLI") < workflow.index("Publish static Space")
    )
    return _check("HUGGINGFACE_METADATA_PREFLIGHT", passed, "Space-card metadata is bounded before remote upload")


def _python_package_data_check(root: Path) -> dict[str, Any]:
    project = _read_source(root, "pyproject.toml")
    passed = (
        "include-package-data = false" in project
        and 'factoryline = ["builtin_packs/**/*", "data/*.json", "hosted_console.html", "graph_ops.html"]' in project
    )
    return _check("PYTHON_PACKAGE_DATA_EXPLICIT", passed, "wheel package data is explicit instead of inferred from source directories")


def _checks(root: Path) -> list[dict[str, Any]]:
    publish = _read_workflow(root, "publish.yml")
    openvsx = _read_workflow(root, "openvsx.yml")
    jetbrains = _read_workflow(root, "jetbrains-marketplace.yml")
    return [
        _fan_in_check(publish),
        _partition_check(publish),
        _openvsx_check(openvsx),
        _pypi_check(publish),
        _jetbrains_check(jetbrains),
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
        "markers": ["RELEASE_INTEGRITY_READ_ONLY"] + ([] if ok else ["RELEASE_INTEGRITY_FAILURE"]),
        "root": str(workspace),
        "ok": ok,
        "checks": checks,
        "failed_check_ids": failures,
        "next_action": {
            "action": "review_external_publish_gates" if ok else "repair_release_workflow",
            "reason": "workflow topology is complete" if ok else "required workflow boundaries are missing",
        },
        "external_requirements": [
            "Open VSX publication still requires OPENVSX_TOKEN in the protected openvsx environment.",
            "JetBrains publication still requires Marketplace approval to clear before a new update.",
        ],
        "authority": AUTHORITY,
    }


def render_release_integrity(result: dict[str, Any]) -> str:
    """Render the exact local integrity result without implying publication readiness."""
    state = "ready for external-gate review" if result["ok"] else "workflow repair required"
    lines = [f"release integrity: {state}"]
    lines.extend(f"- {'PASS' if item['passed'] else 'FAIL'} {item['id']}: {item['evidence']}" for item in result["checks"])
    lines.append(f"next: {result['next_action']['action']}")
    lines.append("authority: no execution, publication, credential, or approval authority")
    return "\n".join(lines)
