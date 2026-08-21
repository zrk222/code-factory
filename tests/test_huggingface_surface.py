import json
import subprocess
import sys
from pathlib import Path

from scripts.huggingface_space_metadata import inspect


ROOT = Path(__file__).resolve().parents[1]
SPACE = ROOT / "deploy" / "huggingface"


def test_huggingface_space_has_static_metadata_and_canonical_release_links() -> None:
    readme = (SPACE / "README.md").read_text(encoding="utf-8")
    page = (SPACE / "index.html").read_text(encoding="utf-8")

    assert "sdk: static" in readme
    assert "app_file: index.html" in readme
    short_description = next(
        line.removeprefix("short_description: ")
        for line in readme.splitlines()
        if line.startswith("short_description: ")
    )
    assert len(short_description) <= 60
    assert "factoryline-code-factory" in page
    assert "github.com/zrk222/code-factory/releases/tag/v0.41.0" in page
    assert "doi.org/10.5281/zenodo.21381405" in page
    assert "Actual product capture set" in page
    assert '<meta name="viewport"' in page
    assert "Catch the test that could never fail." in page
    assert "Catch AI-generated tests that could never fail — before review." in readme
    assert "Free, local proof for code built with AI." in page
    assert "Read or star on GitHub" in page
    assert "thumbnail: https://raw.githubusercontent.com/zrk222/code-factory/main/docs/assets/github-social-preview-1280x640.png" in readme
    assert "developer-tools" in readme
    assert "ai-agents" in readme
    assert "devops" in readme
    assert "design-review" in readme
    assert "ui-quality" in readme
    assert "model-context-protocol" in readme
    assert "cursor" in readme
    assert "opencode" in readme
    assert "Cursor or OpenCode" in readme
    assert "Observed Marketplace downloads: 46" not in page
    assert "Unique installs: not exposed by the listing" in page
    assert 'id="first-run"' in page
    assert "Run your first local proof" in page
    assert "See actual Factory Studio" in page
    assert "Explore FactoryLine for JetBrains" in page
    assert "JETBRAINS_MARKETPLACE_ACQUISITION_KIT.md" in page
    assert "Local by default" in page
    assert "No source upload" in page
    assert "Human decides what may be applied" in page
    assert "Unified Graph Ops" in page
    assert "factory graph ops --root . --json" in page
    assert "PRD Grill" in readme
    assert "factory prd grill PRD.md --root . --mode quick" in page
    assert "factory-studio-mvp-1280x800.png" in page
    assert "graph-ops-studio-1280x800.png" in page
    assert "factoryline-logo-480.png" in page
    assert "code-factory-quickstart-v0171.mp4" not in page
    assert "how-it-works/" not in page
    assert "New in 0." not in page
    assert "pip install factoryline-code-factory==0.31.0" not in page
    assert "prefers-reduced-motion" in page
    assert "Skip to product proof" in page
    assert 'class="brand" href="#main"' in page
    assert "Use AI review suggestions and deterministic proof on the same PR." in page
    assert "CodeRabbit or another reviewer" in page
    assert "GitHub Proof Review" in readme
    assert "LangGraph Assurance Bridge" in readme
    assert "factory langgraph replay-verify" in page
    assert "Prestige Design Review" in readme
    assert "Design is part of the review" in page
    assert "See the design review lane" in page
    assert "Supervised proof of survival" in page
    assert "Gauntlet" in page
    assert "Survival Card" in page


def test_huggingface_workflow_uses_secret_and_scoped_source_directory() -> None:
    workflow = (ROOT / ".github" / "workflows" / "huggingface-space.yml").read_text(
        encoding="utf-8"
    )

    assert "secrets.HF_TOKEN" in workflow
    assert 'repo_id="zrk222/code-factory"' in workflow
    assert 'repo_type="space"' in workflow
    assert 'folder_path="deploy/huggingface"' in workflow
    validate = workflow.index("Validate static Space metadata before remote upload")
    install = workflow.index("Install Hugging Face CLI")
    publish = workflow.index("Publish static Space")
    assert validate < install < publish
    assert "scripts/huggingface_space_metadata.py" in workflow


def test_huggingface_metadata_inspection_rejects_the_remote_api_limit_locally(tmp_path: Path) -> None:
    valid_result = inspect(SPACE / "README.md")
    assert valid_result["ok"] is True
    assert valid_result["marker"] == "HUGGINGFACE_SPACE_METADATA_VALID"
    assert valid_result["short_description_length"] == 57

    invalid_readme = tmp_path / "README.md"
    invalid_readme.write_text(
        (SPACE / "README.md").read_text(encoding="utf-8").replace(
            "short_description: Catch tests that could never fail. Prove AI code locally.",
            f"short_description: {'x' * 61}",
        ),
        encoding="utf-8",
    )
    result = inspect(invalid_readme)
    assert result["ok"] is False
    assert result["marker"] == "HUGGINGFACE_SPACE_METADATA_INVALID"
    assert result["short_description_length"] == 61


def test_huggingface_metadata_preflight_cli_reports_the_local_result(tmp_path: Path) -> None:
    script = ROOT / "scripts" / "huggingface_space_metadata.py"
    valid = subprocess.run(
        [sys.executable, str(script), "--readme", str(SPACE / "README.md"), "--json"],
        capture_output=True,
        check=False,
        text=True,
    )
    assert valid.returncode == 0
    assert json.loads(valid.stdout)["marker"] == "HUGGINGFACE_SPACE_METADATA_VALID"

    invalid_readme = tmp_path / "invalid-README.md"
    invalid_readme.write_text(
        (SPACE / "README.md").read_text(encoding="utf-8").replace(
            "short_description: Catch tests that could never fail. Prove AI code locally.",
            f"short_description: {'x' * 61}",
        ),
        encoding="utf-8",
    )
    invalid = subprocess.run(
        [sys.executable, str(script), "--readme", str(invalid_readme), "--json"],
        capture_output=True,
        check=False,
        text=True,
    )
    assert invalid.returncode == 1
    invalid_result = json.loads(invalid.stdout)
    assert invalid_result["marker"] == "HUGGINGFACE_SPACE_METADATA_INVALID"
    assert invalid_result["short_description_length"] == 61
