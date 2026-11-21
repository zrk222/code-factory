import json
import re
import subprocess
import sys
from pathlib import Path

from factoryline import __version__
from scripts.huggingface_space_metadata import inspect


ROOT = Path(__file__).resolve().parents[1]
SPACE = ROOT / "deploy" / "huggingface"


def test_preview_separates_candidate_regressions_from_accuracy_and_review() -> None:
    page = (SPACE / "index.html").read_text(encoding="utf-8")
    readme = (SPACE / "README.md").read_text(encoding="utf-8")
    assert "Seeded finding example:" in page
    assert "sample tenant-read inputs illustrate a finding and repaired case" in page
    assert (
        "First Proof uses a generated sandbox to check the demonstration, not your repository."
        in readme
    )
    assert "Candidate CI verification and human review are still required." in page
    assert "not a live scan, tenant-isolation proof" in page
    assert "accuracy benchmark or independent review" in page
    assert "Not a customer case or independent certification." in page
    assert "does not approve its result" in page
    assert "not code correctness or release readiness" in page
    assert "not a hosted repository scanner" in page
    assert "The quick security scanner inspects Python ASTs" in page
    assert "Core 0.50.0 and plugins 1.3.6 are the prepared release line" in page
    assert "12-language native security" in page
    assert "Six languages had insufficient precision samples" in page
    assert (
        "AI labels are not twelve-language accuracy or independent human validation"
        in page
    )
    assert "38/40 decided default-tier alerts (95%; Wilson 83.5–98.6%)" in page
    assert "12 additional unclear" in page
    assert "23/40 (57.5%), plus 3 unclear" in page and "Advisory recall: 0/161" in page
    assert f"Code Factory {__version__} · Static workflow overview" in page
    assert "Provider availability tracked separately" in page
    assert all(name in page for name in ("FactoryLine", "ForgeLine", "SpecLine"))
    assert "88.24% decided actionable precision" not in page
    assert "83.33% among 36 decided alerts" not in page
    assert "6 true positives" not in page + readme
    assert "2 true negatives" not in page + readme
    assert "false positives or false negatives" not in page + readme
    assert "latest local strict ForgeLine report" not in page + readme
    assert "Local tests do not establish live provider support" in readme
    assert f"https://pypi.org/project/factoryline-code-factory/{__version__}/" in page
    assert f"https://github.com/zrk222/code-factory/releases/tag/v{__version__}" in page


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
    assert "Static workflow overview" in page
    assert (
        f'href="https://github.com/zrk222/code-factory/releases/tag/v{__version__}"'
        in page
    )
    assert "Audit depth depends on language, policy and supplied evidence." in readme
    assert "Missing evidence stays incomplete." in readme
    assert "doi.org/10.5281/zenodo.21381405" in page
    assert '<meta name="viewport"' in page
    assert 'id="story-video"' in page
    assert 'aria-label="From requirements to WMM: Code Factory walkthrough"' in page
    assert 'id="seeded-demo"' in page
    assert 'poster="cf-story-v5-poster.jpg"' in page
    assert 'src="cf-story-v5-narrated.mp4"' in page
    assert (SPACE / "cf-story-v5-poster.jpg").is_file()
    assert (SPACE / "cf-story-v5-narrated.mp4").is_file()
    assert "57-second narrated walkthrough" in page
    assert "Not a customer case or independent certification." in page
    assert "not a hosted repository scanner" in page
    assert "It does not approve its result." in page
    assert (
        "Local tests do not establish marketplace availability or live provider compatibility."
        in page
    )
    assert (
        "No native Blitzy or Mastra integration or live compatibility test is claimed."
        in page
    )
    assert (
        "First Proof uses a generated sandbox to check the demonstration, not your repository."
        in readme
    )
    # Check the media actually linked by the concise preview, not retired captures.
    for name in ("cf-operations-pr354-poster.png", "cf-operations-pr354-105s.mp4"):
        assert f'="{name}"' in page
        assert (SPACE / name).is_file()
    assert "not a screen recording or live Devin session" in page
    assert "Skip to product proof" in page
    assert 'class="brand" href="#main"' in page

    external_anchors = re.findall(r'<a\b[^>]*href="https://[^>]+>', page)
    assert external_anchors
    for anchor in external_anchors:
        assert 'target="_blank"' in anchor
        assert 'rel="noopener noreferrer"' in anchor


def test_huggingface_workflow_uses_secret_and_scoped_source_directory() -> None:
    workflow = (ROOT / ".github" / "workflows" / "huggingface-space.yml").read_text(
        encoding="utf-8"
    )

    assert "secrets.HF_TOKEN" in workflow
    assert 'test -n "$HF_TOKEN"' in workflow
    assert 'repo_id="zrk222/code-factory"' in workflow
    assert 'repo_type="space"' in workflow
    assert 'folder_path="deploy/huggingface"' in workflow
    token = workflow.index('test -n "$HF_TOKEN"')
    checkout = workflow.index(
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    )
    validate = workflow.index("Validate static Space metadata before remote upload")
    install = workflow.index("Install Hugging Face CLI")
    publish = workflow.index("Publish static Space")
    assert token < checkout < validate < install < publish
    assert "scripts/huggingface_space_metadata.py" in workflow


def test_huggingface_metadata_inspection_rejects_the_remote_api_limit_locally(
    tmp_path: Path,
) -> None:
    valid_result = inspect(SPACE / "README.md")
    assert valid_result["ok"] is True
    assert valid_result["marker"] == "HUGGINGFACE_SPACE_METADATA_VALID"
    assert valid_result["short_description_length"] == 45

    invalid_readme = tmp_path / "README.md"
    invalid_readme.write_text(
        (SPACE / "README.md")
        .read_text(encoding="utf-8")
        .replace(
            "short_description: Polyglot code evidence for AI-assisted teams.",
            f"short_description: {'x' * 61}",
        ),
        encoding="utf-8",
    )
    result = inspect(invalid_readme)
    assert result["ok"] is False
    assert result["marker"] == "HUGGINGFACE_SPACE_METADATA_INVALID"
    assert result["short_description_length"] == 61


def test_huggingface_metadata_preflight_cli_reports_the_local_result(
    tmp_path: Path,
) -> None:
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
        (SPACE / "README.md")
        .read_text(encoding="utf-8")
        .replace(
            "short_description: Polyglot code evidence for AI-assisted teams.",
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
