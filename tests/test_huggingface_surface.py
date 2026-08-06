from pathlib import Path


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
    assert "github.com/zrk222/code-factory/releases/tag/v0.24.3" in page
    assert "doi.org/10.5281/zenodo.21381405" in page
    assert "not UI screenshots or measured outcome evidence" in page
    assert '<meta name="viewport"' in page
    assert "Describe the outcome. See what is proved." in page
    assert "Why pay for opaque app generators?" in readme
    assert "Why pay for opaque app generators?" in page
    assert "Inspect or star on GitHub" in page
    assert "thumbnail: https://raw.githubusercontent.com/zrk222/code-factory/main/docs/assets/github-social-preview-1280x640.png" in readme
    assert "developer-tools" in readme
    assert "ai-agents" in readme
    assert "devops" in readme
    assert 'id="first-run"' in page
    assert "Start free with pip" in page
    assert "Watch the exact 60-second UI" in page
    assert "Install free in JetBrains" in page
    assert "JETBRAINS_MARKETPLACE_ACQUISITION_KIT.md" in page
    assert "Release test suite passed" in page
    assert "Verified release checks" in page
    assert "Unified Graph Ops" in page
    assert "factory graph ops --root . --json" in page
    assert "PRD Grill" in readme
    assert "factory prd grill PRD.md --root . --mode quick" in page
    assert "factory-studio-mvp-1280x800.png" in page
    assert "graph-ops-studio-1280x800.png" in page
    assert "prefers-reduced-motion" in page
    assert "Skip to product proof" in page
    assert 'class="brand" href="#main"' in page


def test_huggingface_workflow_uses_secret_and_scoped_source_directory() -> None:
    workflow = (ROOT / ".github" / "workflows" / "huggingface-space.yml").read_text(
        encoding="utf-8"
    )

    assert "secrets.HF_TOKEN" in workflow
    assert 'repo_id="zrk222/code-factory"' in workflow
    assert 'repo_type="space"' in workflow
    assert 'folder_path="deploy/huggingface"' in workflow
