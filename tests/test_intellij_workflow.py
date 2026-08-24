from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def test_intellij_required_checks_are_emitted_for_every_pull_request() -> None:
    workflow = (ROOT / ".github" / "workflows" / "intellij-plugin.yml").read_text(encoding="utf-8")

    assert "  pull_request:\n  workflow_dispatch:" in workflow
    assert "  changes:" in workflow
    assert "    needs: changes\n    runs-on: ubuntu-latest" in workflow
    assert "  test-package:\n    needs: [changes, test-package-verify]" in workflow
    assert "  compatibility:\n    needs: [changes, test-package-verify]" in workflow
    assert "Mark package verification not applicable" in workflow
    assert "Mark compatibility not applicable" in workflow
    assert "defaults:\n      run:\n        working-directory: editors/intellij" not in workflow
    assert workflow.count("working-directory: editors/intellij") == 4


def test_intellij_heavy_validation_is_scoped_without_suppressing_required_statuses() -> None:
    workflow = (ROOT / ".github" / "workflows" / "intellij-plugin.yml").read_text(encoding="utf-8")

    assert "^(editors/intellij/|\\.github/workflows/intellij-plugin\\.yml$)" in workflow
    assert workflow.count("if: needs.changes.outputs.intellij == 'true'") >= 10
    assert "needs.changes.outputs.intellij != 'true'" in workflow
    assert "paths:" not in workflow.split("jobs:", maxsplit=1)[0]
