from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_vscode_marketplace_workflow_is_guarded_and_seals_candidate():
    workflow = (ROOT / ".github" / "workflows" / "vscode-marketplace.yml").read_text(encoding="utf-8")

    assert "name: Publish VS Code Marketplace extension" in workflow
    assert "release_ref:" in workflow
    assert "publish:" in workflow
    assert "environment: vscode-marketplace" in workflow
    assert "VSCE_PAT: ${{ secrets.VSCE_PAT }}" in workflow
    assert "npm ci" in workflow
    assert "npm run audit" in workflow
    assert "npm test" in workflow
    assert "sha256sum factoryline-vscode.vsix" in workflow
    assert "sha256sum --check SHA256SUMS.txt" in workflow
    assert "--packagePath vscode-marketplace-candidate/factoryline-vscode.vsix" in workflow


def test_vscode_marketplace_docs_keep_publication_boundary_explicit():
    docs = (ROOT / "docs" / "VSCODE_MARKETPLACE.md").read_text(encoding="utf-8")

    assert "candidate prepared" in docs
    assert "VSCE_PAT" in docs
    assert "code.visualstudio.com/api/working-with-extensions/publishing-extension" in docs


def test_github_marketplace_action_is_rooted_and_fail_closed():
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    docs = (ROOT / "docs" / "GITHUB_MARKETPLACE_ACTION.md").read_text(encoding="utf-8")

    assert "using: composite" in action
    assert "factory verify \"$FACTORY_FEATURE\" --root \"$FACTORY_ROOT\" --json" in action
    assert "actions/upload-artifact@v4" in action
    assert "FACTORY_VERIFY_EXIT" in action
    assert "if: always()" in action
    assert "github.com/en/actions/how-tos/create-and-publish-actions/publish-in-github-marketplace" in docs
