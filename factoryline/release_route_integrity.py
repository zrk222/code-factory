"""Static, read-only preflight checks for protected release routes."""
from __future__ import annotations

from pathlib import Path
import re
from typing import Any


def _check(check_id: str, passed: bool, evidence: str) -> dict[str, Any]:
    return {"id": check_id, "passed": passed, "evidence": evidence}


def _workflow(root: Path, name: str) -> str:
    try:
        return (Path(root) / ".github" / "workflows" / name).read_bytes().decode().replace("\r\n", "\n")
    except (OSError, UnicodeDecodeError):
        return ""


def _job(workflow: str, name: str) -> str:
    match = re.search(rf"(?m)^  {re.escape(name)}:\n", workflow)
    if match is None:
        return ""
    start = match.end()
    next_job = re.search(r"(?m)^  [A-Za-z_][A-Za-z0-9_]*:\n", workflow[start:])
    return workflow[start:start + next_job.start()] if next_job else workflow[start:]


def _vscode_marketplace_authorization_check(workflow: str) -> dict[str, Any]:
    authorize = _job(workflow, "authorize")
    validate = _job(workflow, "validate")
    publish = _job(workflow, "publish")
    passed = (
        "if: inputs.publish == true" in authorize
        and "environment: vscode-marketplace" in authorize
        and "VSCE_PAT" in authorize
        and "needs: authorize" in validate
        and "inputs.publish == false || needs.authorize.result == 'success'" in validate
        and "needs: [authorize, validate]" in publish
        and "needs.authorize.result == 'success'" in publish
    )
    return _check(
        "VSCODE_MARKETPLACE_AUTHORIZATION_EARLY",
        passed,
        "protected VS Code Marketplace authorization is required before candidate validation",
    )


def _vscode_marketplace_candidate_check(workflow: str) -> dict[str, Any]:
    validate = _job(workflow, "validate")
    publish = _job(workflow, "publish")
    passed = (
        "sha256sum factoryline-vscode.vsix >" in validate
        and "publisher=zrk222" in validate
        and "extension=factoryline-vscode" in validate
        and "sha256sum --check SHA256SUMS.txt" in publish
        and "test -f manifest.txt" in publish
        and "test -f factoryline-vscode.vsix" in publish
        and "grep -Fx 'publisher=zrk222' manifest.txt" in publish
        and "grep -Fx 'extension=factoryline-vscode' manifest.txt" in publish
        and "@vscode/vsce@3.9.1 publish" in publish
    )
    return _check(
        "VSCODE_MARKETPLACE_CANDIDATE_SEALED",
        passed,
        "VS Code Marketplace publish verifies the sealed VSIX checksum and declared identity",
    )


def _jetbrains_marketplace_authorization_check(root: Path) -> dict[str, Any]:
    workflow = _workflow(root, "jetbrains-marketplace.yml")
    authorize = _job(workflow, "authorize")
    validate = _job(workflow, "validate")
    publish = _job(workflow, "publish")
    passed = (
        "environment: jetbrains-marketplace" in authorize
        and "JETBRAINS_MARKETPLACE_TOKEN" in authorize
        and 'test -n "$PUBLISH_TOKEN"' in authorize
        and "needs: authorize" in validate
        and "needs: [authorize, validate, compatibility]" in publish
    )
    return _check(
        "JETBRAINS_MARKETPLACE_AUTHORIZATION_EARLY",
        passed,
        "protected JetBrains Marketplace authorization is required before candidate validation",
    )


def _action_blocks(workflow: str, action: str) -> list[str]:
    pattern = rf"(?ms)^      - uses: {re.escape(action)}\n(?:(?!^      - ).)*"
    return re.findall(pattern, workflow)


def _jetbrains_jdk21_check(root: Path) -> dict[str, Any]:
    workflows = (_workflow(root, "intellij-plugin.yml"), _workflow(root, "jetbrains-marketplace.yml"))
    blocks = [block for workflow in workflows for block in _action_blocks(workflow, "actions/setup-java@v5")]
    versions = [re.findall(r'(?m)^          java-version:\s*["\']?([^\s#"\']+)', block) for block in blocks]
    passed = bool(blocks) and all(items == ["21"] for items in versions)
    return _check(
        "JETBRAINS_JDK21_EXACT",
        passed,
        "every declared IntelliJ Gradle Java setup step pins Java 21",
    )


def _huggingface_space_authorization_check(root: Path) -> dict[str, Any]:
    workflow = _workflow(root, "huggingface-space.yml")
    token_check = 'test -n "$HF_TOKEN"'
    candidate_markers = (
        "actions/checkout@v4",
        "actions/setup-python@v5",
        "Validate static Space metadata before remote upload",
        "Install Hugging Face CLI",
        'HfApi(token=os.environ["HF_TOKEN"]).upload_folder',
    )
    passed = (
        "HF_TOKEN: ${{ secrets.HF_TOKEN }}" in workflow
        and token_check in workflow
        and "HF_TOKEN is required before Hugging Face Space candidate work." in workflow
        and all(marker in workflow for marker in candidate_markers)
        and workflow.index(token_check) < min(workflow.index(marker) for marker in candidate_markers)
    )
    return _check(
        "HUGGINGFACE_AUTHORIZATION_EARLY",
        passed,
        "Hugging Face credential admission is declared before Space candidate work",
    )


def release_route_checks(root: Path) -> list[dict[str, Any]]:
    """Return declared route checks without inspecting credentials or providers."""
    vscode_marketplace = _workflow(root, "vscode-marketplace.yml")
    return [
        _vscode_marketplace_authorization_check(vscode_marketplace),
        _vscode_marketplace_candidate_check(vscode_marketplace),
        _jetbrains_marketplace_authorization_check(root),
        _jetbrains_jdk21_check(root),
        _huggingface_space_authorization_check(root),
    ]
