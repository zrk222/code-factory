from __future__ import annotations

import json
import re
try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised by the Python 3.10 CI lane
    import tomli as tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _match(path: Path, pattern: str) -> str:
    match = re.search(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
    assert match, f"missing expected metadata in {path.name}"
    return match.group(1)


def test_publication_versions_and_citation_are_synchronized():
    pyproject_version = _match(ROOT / "pyproject.toml", r'^version = "([^"]+)"$')
    package_version = _match(ROOT / "factoryline" / "__init__.py", r'^__version__ = "([^"]+)"$')
    citation_version = _match(ROOT / "CITATION.cff", r"^version: ([^\s]+)$")

    assert pyproject_version == package_version == citation_version
    assert _match(ROOT / "CITATION.cff", r"^date-released: (\d{4}-\d{2}-\d{2})$") == "2026-08-01"


def test_pypi_storefront_has_identity_and_canonical_links():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    identity = [{"name": "Richard Katz"}, {"email": "rkatz22@gmail.com"}]
    assert project["authors"] == identity
    assert project["maintainers"] == identity
    assert project["urls"] == {
        "Homepage": "https://github.com/zrk222/code-factory",
        "Documentation": "https://github.com/zrk222/code-factory#readme",
        "Source": "https://github.com/zrk222/code-factory",
        "Issues": "https://github.com/zrk222/code-factory/issues",
        "Changelog": "https://github.com/zrk222/code-factory/releases",
    }


def test_publish_workflow_uses_trusted_publishing_without_stored_credentials():
    workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")

    assert "permissions:\n  contents: read" in workflow
    assert "  validate:" in workflow
    assert "  publish:" in workflow
    assert "needs: validate" in workflow
    assert "environment: pypi" in workflow
    assert "id-token: write" in workflow
    assert "actions/setup-node@v7.0.0" in workflow
    assert "actions/upload-artifact@v7.0.1" in workflow
    assert "actions/download-artifact@v8.0.1" in workflow
    assert "actions/setup-node@v4" not in workflow
    assert "actions/upload-artifact@v4" not in workflow
    assert "actions/download-artifact@v4" not in workflow
    assert "packages-dir: release-bundle/python/" in workflow
    assert "pypa/gh-action-pypi-publish@release/v1" in workflow
    assert "attestations: true" in workflow
    assert "gradle/actions/setup-gradle@v6.2.0" in workflow
    assert '.[dev,enterprise,hosted]' in workflow
    for forbidden in (
        "PYPI_TOKEN",
        "API_TOKEN",
        "user: __token__",
        "password:",
    ):
        assert forbidden not in workflow


def test_vscode_supply_chain_is_patched_and_audited_before_tests():
    package = json.loads((ROOT / "editors" / "vscode" / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((ROOT / "editors" / "vscode" / "package-lock.json").read_text(encoding="utf-8"))

    assert package["scripts"]["audit"] == "npm audit --audit-level=high"
    assert package["overrides"] == {
        "brace-expansion": "5.0.9",
        "fast-uri": "3.1.5",
    }
    assert lock["packages"]["node_modules/brace-expansion"]["version"] == "5.0.9"
    assert lock["packages"]["node_modules/fast-uri"]["version"] == "3.1.5"
    assert "dependencies" not in package

    for relative in ("vscode-extension.yml", "publish.yml"):
        workflow = (ROOT / ".github" / "workflows" / relative).read_text(encoding="utf-8")
        install = workflow.index("npm ci")
        audit = workflow.index("npm run audit", install)
        tests = workflow.index("npm test", audit)
        assert install < audit < tests


def test_marketplace_workflow_uses_current_gradle_action_and_scoped_secret():
    workflow = (ROOT / ".github" / "workflows" / "jetbrains-marketplace.yml").read_text(encoding="utf-8")

    assert "  validate:" in workflow
    assert "  publish:" in workflow
    assert "needs: validate" in workflow
    assert "environment: jetbrains-marketplace" in workflow
    assert "gradle/actions/setup-gradle@v6.2.0" in workflow
    assert "gradle/actions/setup-gradle@v4" not in workflow
    assert "secrets.JETBRAINS_MARKETPLACE_TOKEN" in workflow
    assert "Test, verify, and check Marketplace package metadata" in workflow
    assert "jetbrains_release_artifact.py" in workflow
    assert "actions/upload-artifact@v7.0.1" in workflow
    assert "actions/download-artifact@v8.0.1" in workflow
    assert "factorylineMarketplaceArchive" in workflow
    assert "Publish verified plugin update" in workflow
    assert workflow.count("chmod +x gradlew") == 2


def test_intellij_workflow_avoids_duplicate_feature_branch_runs():
    workflow = (ROOT / ".github" / "workflows" / "intellij-plugin.yml").read_text(encoding="utf-8")

    assert "push:\n    branches: [main]" in workflow
    assert "pull_request:" in workflow
    assert "group: intellij-" in workflow
    assert "cancel-in-progress: true" in workflow


def test_hosted_release_and_editor_versions_are_declared():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    vscode = json.loads((ROOT / "editors" / "vscode" / "package.json").read_text(encoding="utf-8"))
    gradle = (ROOT / "editors" / "intellij" / "build.gradle.kts").read_text(encoding="utf-8")
    hosted_workflow = (ROOT / ".github" / "workflows" / "hosted-adapter.yml").read_text(encoding="utf-8")

    assert project["version"] == "0.23.2"
    assert "hosted" in project["optional-dependencies"]
    assert vscode["version"] == "0.7.0"
    assert 'version = "0.7.2"' in gradle
    assert "postgres:17" in hosted_workflow
    assert "FACTORY_TEST_POSTGRES_DSN" in hosted_workflow


def test_jetbrains_listing_is_outcome_led_and_first_proof_is_discoverable():
    plugin_xml = (ROOT / "editors" / "intellij" / "src" / "main" / "resources" / "META-INF" / "plugin.xml").read_text(encoding="utf-8")
    screenshot_brief = (ROOT / "docs" / "JETBRAINS_MARKETPLACE_SCREENSHOTS.md").read_text(encoding="utf-8")

    assert "<id>app.factoryline</id>" in plugin_xml
    assert "<name>FactoryLine AI Proof</name>" in plugin_xml
    assert "<p>Verify AI code before you ship.</p>" in plugin_xml
    assert 'id="app.factoryline.intellij.firstProof"' in plugin_xml
    assert "Run First Proof" in plugin_xml
    assert "Use real plugin UI, not concept art." in screenshot_brief
    assert "1200x760" in screenshot_brief


def test_jetbrains_price_is_owner_locked_reproducible_and_not_claimed_live():
    sample = json.loads((ROOT / "docs" / "JETBRAINS_PRICING_BENCHMARK.json").read_text(encoding="utf-8"))
    prices = [entry["monthly_price"] for entry in sample["comparables"]]

    average = sum(prices) / len(prices)
    assert round(average, 2) == sample["sample_average"]
    assert sample["owner_approved_monthly_price"] == 4.95
    assert round((average - 4.95) / average, 10) == sample["discount_from_sample_average"]
    assert sample["status"] == "owner_approved_future_price_not_active_on_marketplace"
    assert sample["free_through"] == "2026-12-31"


def test_jetbrains_paid_launch_is_complete_but_cannot_activate_early():
    plan = json.loads((ROOT / "docs" / "JETBRAINS_MONETIZATION_2027.json").read_text(encoding="utf-8"))
    runbook = (ROOT / "docs" / "JETBRAINS_MONETIZATION_2027.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    active_xml = (ROOT / "editors" / "intellij" / "src" / "main" / "resources" / "META-INF" / "plugin.xml").read_text(encoding="utf-8")
    staged_xml = (ROOT / "editors" / "intellij" / "monetization" / "plugin-product-descriptor-2027.xml").read_text(encoding="utf-8")

    assert plan["offer"]["monthly_price_usd"] == 4.95
    assert plan["offer"]["monthly_price_status"] == "owner_approved"
    assert plan["offer"]["paid_from"] == "2027-01-01"
    assert plan["paid_descriptor"] == {
        "product_code": "PFACTORYLINE",
        "product_code_status": "proposed_not_registered",
        "release_date": "20270101",
        "release_version": "20271",
        "optional": False,
        "active_descriptor_contains_product_descriptor": False,
        "staging_template": "editors/intellij/monetization/plugin-product-descriptor-2027.xml",
    }
    assert "<product-descriptor" not in active_xml
    assert "$4.95 USD per month" in active_xml
    assert "$4.95 USD per month" in readme
    assert 'code="PFACTORYLINE"' in staged_xml
    assert 'release-date="20270101"' in staged_xml
    assert 'release-version="20271"' in staged_xml
    assert 'optional="false"' in staged_xml
    assert len(plan["activation_gates"]) == 9
    assert plan["current_verdict"] == "MONETIZATION_GATE_BLOCKED"
    for phrase in ("licensed", "active-trial", "expired-trial", "unlicensed", "offline", "uninitialized-facade"):
        assert phrase in runbook


def test_jetbrains_publication_workflow_blocks_a_pending_listing_update():
    workflow = (ROOT / ".github" / "workflows" / "jetbrains-marketplace.yml").read_text(encoding="utf-8")

    assert "Require the previous Marketplace update to be clear" in workflow
    assert "scripts/jetbrains_marketplace_status.py" in workflow
    assert "--plugin-id 33009 --require-clear --json" in workflow


def test_ci_builds_checks_and_smokes_the_installable_package():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "permissions:\n  contents: read" in workflow
    assert "package-contract:" in workflow
    assert "python -m build" in workflow
    assert "python -m twine check dist/*" in workflow
    assert "python -m pip install dist/*.whl" in workflow
    assert "actions/setup-node@v7.0.0" in workflow
    assert "actions/upload-artifact@v7.0.1" in workflow


def test_zenodo_metadata_and_visual_evidence_are_publicly_archivable():
    metadata = json.loads((ROOT / ".zenodo.json").read_text(encoding="utf-8"))

    assert metadata["upload_type"] == "software"
    assert metadata["access_right"] == "open"
    assert metadata["creators"] == [{"name": "Katz, Richard"}]
    assert metadata["related_identifiers"][0]["identifier"] == "https://github.com/zrk222/code-factory"
    assert "Mermaid diagrams" in metadata["description"]
    assert metadata["version"] == "0.23.2"
    assert metadata["publication_date"] == "2026-08-01"
    assert "conceptual visual walkthrough" in metadata["description"]

    assets = ROOT / "docs" / "assets"
    for name in (
        "verify-policy.gif",
        "code-factory-proof-first.png",
        "factory-editor-control-room.svg",
        "prd-to-app-factory.svg",
        "product-missions.svg",
        "signal-loop.svg",
        "code-factory-quickstart-cover-v0171.png",
        "code-factory-quickstart-v0171.mp4",
    ):
        assert (assets / name).is_file(), name
    visual_assets = assets / "how-it-works"
    assert len(list(visual_assets.glob("*.png"))) == 9
    assert (visual_assets / "manifest.json").is_file()
    assert (ROOT / "docs" / "HOW_IT_WORKS_VISUAL.md").is_file()

    source_manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    assert "recursive-include docs *.md *.gif *.png *.svg *.mp4 *.json" in source_manifest

    for path in (
        ROOT / "README.md",
        ROOT / "PUBLICATION_GUIDE.md",
        ROOT / "docs" / "ARCHITECTURE.md",
        ROOT / "docs" / "JETBRAINS_CONTROL_ROOM.md",
    ):
        assert "```mermaid" in path.read_text(encoding="utf-8"), path.name

    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    for entry in (
        "include .zenodo.json",
        "include CITATION.cff",
        "recursive-include docs *.md *.gif *.png *.svg",
        "*.mp4",
    ):
        assert entry in manifest

    for generated_tree in (
        "editors/vscode/node_modules",
        "editors/vscode/dist",
        "editors/intellij/.gradle",
        "editors/intellij/.intellijPlatform",
        "editors/intellij/.kotlin",
        "editors/intellij/build",
    ):
        assert f"prune {generated_tree}" in manifest


def test_codex_usage_sample_is_privacy_safe_and_does_not_invent_savings():
    sample = json.loads((ROOT / "docs" / "CODEX_USAGE_SAMPLE.json").read_text(encoding="utf-8"))

    assert sample["scope"]["assembly_invocations"] == 19
    assert sum(sample["assembly_invocations"][key] for key in ("real", "help", "dry_run")) == 19
    assert sample["token_counters"]["attribution"] == "not_attributable_to_code_factory"
    assert sample["productivity_claims"]["quality"] == "unknown"
    assert sample["productivity_claims"]["time_saved_seconds"] is None
    assert sample["productivity_claims"]["tokens_saved"] is None
    assert all(value is False for value in sample["privacy"].values())
