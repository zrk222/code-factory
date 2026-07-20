from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPACE = ROOT / "deploy" / "huggingface"


def test_huggingface_space_has_static_metadata_and_canonical_release_links() -> None:
    readme = (SPACE / "README.md").read_text(encoding="utf-8")
    page = (SPACE / "index.html").read_text(encoding="utf-8")

    assert "sdk: static" in readme
    assert "app_file: index.html" in readme
    assert "factoryline-code-factory" in page
    assert "github.com/zrk222/code-factory/releases/tag/v0.19.0" in page
    assert "doi.org/10.5281/zenodo.21442598" in page
    assert "not UI screenshots or measured outcome evidence" in page
    assert '<meta name="viewport"' in page


def test_huggingface_workflow_uses_secret_and_scoped_source_directory() -> None:
    workflow = (ROOT / ".github" / "workflows" / "huggingface-space.yml").read_text(
        encoding="utf-8"
    )

    assert "secrets.HF_TOKEN" in workflow
    assert 'repo_id="zrk222/code-factory"' in workflow
    assert 'repo_type="space"' in workflow
    assert 'folder_path="deploy/huggingface"' in workflow
