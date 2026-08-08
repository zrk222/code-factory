from __future__ import annotations

import json
import re
import struct
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
    assert _match(ROOT / "CITATION.cff", r"^date-released: (\d{4}-\d{2}-\d{2})$") == "2026-08-06"


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
    assert project["description"] == (
        "Create a reviewable MVP starting state in minutes with local receipts, proof paths, and room to extend."
    )
    assert {"mvp", "mcp", "graph-ops", "prd-grill"}.issubset(project["keywords"])


def test_public_ctas_are_outcome_led_and_preserve_proof_boundaries():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    vscode_package = json.loads((ROOT / "editors" / "vscode" / "package.json").read_text(encoding="utf-8"))
    vscode_readme = (ROOT / "editors" / "vscode" / "README.md").read_text(encoding="utf-8")
    intellij_plugin = (ROOT / "editors" / "intellij" / "src" / "main" / "resources" / "META-INF" / "plugin.xml").read_text(encoding="utf-8")
    intellij_readme = (ROOT / "editors" / "intellij" / "README.md").read_text(encoding="utf-8")

    value = "Why pay for opaque app generators?"
    assert value in readme
    assert readme.index(value) < readme.index("## What Code Factory is")
    assert "factory mvp \"Build an approval tracker\" --root ." in readme
    assert "Watch the exact shipped UI in 60 seconds" in readme
    assert "star Code Factory" in readme
    assert "production-ready before the relevant proof exists" in readme
    assert "reviewable MVP starting state in minutes" in vscode_package["description"]
    assert {"mvp", "mcp", "graph-ops"}.issubset(vscode_package["keywords"])
    for content in (vscode_readme, intellij_plugin, intellij_readme):
        assert value in content
        assert "Graph Ops" in content
    assert "Star Code Factory" in vscode_readme
    assert "Star Code Factory" in intellij_readme
    for content in (readme, vscode_readme, intellij_plugin, intellij_readme):
        assert "PRD Grill" in content
        assert "factory prd grill" in content


def test_github_discovery_assets_and_community_drafts_are_reviewable_only():
    guide = (ROOT / "docs" / "GITHUB_DISCOVERY.md").read_text(encoding="utf-8")
    preview = ROOT / "docs" / "assets" / "github-social-preview-1280x640.png"

    with preview.open("rb") as handle:
        assert handle.read(8) == b"\x89PNG\r\n\x1a\n"
        assert struct.unpack(">I", handle.read(4)) == (13,)
        assert handle.read(4) == b"IHDR"
        width, height = struct.unpack(">II", handle.read(8))
    assert (width, height) == (1280, 640)
    assert "Settings → General → Social preview" in guide
    assert "not proof that a live Open Graph image is configured" in guide
    assert "Show HN" in guide
    assert "Indie Hackers" in guide
    assert "r/devops" in guide
    assert "r/platformengineering" in guide
    assert "r/sre" in guide
    assert "r/kubernetes" in guide
    assert "Code Factory does not submit, vote on, or coordinate votes" in guide


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
        "js-yaml": "^4.3.1",
    }
    assert lock["packages"]["node_modules/brace-expansion"]["version"] == "5.0.9"
    assert lock["packages"]["node_modules/fast-uri"]["version"] == "3.1.5"
    assert lock["packages"]["node_modules/js-yaml"]["version"] == "4.3.1"
    assert "dependencies" not in package

    for relative in ("vscode-extension.yml", "publish.yml"):
        workflow = (ROOT / ".github" / "workflows" / relative).read_text(encoding="utf-8")
        install = workflow.index("npm ci")
        audit = workflow.index("npm run audit", install)
        tests = workflow.index("npm test", audit)
        assert install < audit < tests


def test_openvsx_workflow_seals_a_tested_immutable_candidate_before_manual_publish():
    workflow = (ROOT / ".github" / "workflows" / "openvsx.yml").read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "release_ref:" in workflow
    assert "publish:" in workflow
    assert "Require an immutable release tag" in workflow
    assert "git tag --points-at HEAD" in workflow
    assert "npm ci" in workflow
    assert "npm run audit" in workflow
    assert "npm test" in workflow
    assert workflow.index("npm ci") < workflow.index("npm run audit") < workflow.index("npm test")
    assert "sha256sum factoryline-vscode.vsix" in workflow
    assert "environment: openvsx" in workflow
    assert "if: inputs.publish == true" in workflow
    assert "secrets.OPENVSX_TOKEN" in workflow
    assert "ovsx@1.1.0 publish" in workflow
    assert "OPENVSX_TOKEN is required" in workflow


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
    assert "for attempt in 1 2 3" in workflow
    assert "sleep 20" in workflow


def test_intellij_compatibility_reuses_verified_package_with_cached_dependencies():
    workflow = (ROOT / ".github" / "workflows" / "intellij-plugin.yml").read_text(encoding="utf-8")
    gradle = (ROOT / "editors" / "intellij" / "build.gradle.kts").read_text(encoding="utf-8")
    package_job = workflow.split("  compatibility:", maxsplit=1)[0]

    assert workflow.count("gradle/actions/setup-gradle@v6.2.0") == 2
    assert "Build, verify, and preflight plugin package" in package_job
    assert "Package verification attempt $attempt failed" in package_job
    assert package_job.count("for attempt in 1 2 3") == 1
    assert "actions/download-artifact@v8.0.1" in workflow
    assert "name: factoryline-intellij-plugin" in workflow
    assert "Resolve verified plugin archive" in workflow
    assert 'test "${#archives[@]}" -eq 1' in workflow
    assert "factorylineVerificationArchive" in workflow
    assert "./gradlew buildPlugin verifyPlugin -PfactorylineVerificationProduct" not in workflow
    assert "tasks.named<VerifyPluginTask>(\"verifyPlugin\")" in gradle
    assert "archiveFile.set(file(archive))" in gradle


def test_python_ci_matrix_caches_package_downloads():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "python-version: ${{ matrix.python }}\n          cache: pip" in workflow


def test_hosted_release_and_editor_versions_are_declared():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    vscode = json.loads((ROOT / "editors" / "vscode" / "package.json").read_text(encoding="utf-8"))
    gradle = (ROOT / "editors" / "intellij" / "build.gradle.kts").read_text(encoding="utf-8")
    hosted_workflow = (ROOT / ".github" / "workflows" / "hosted-adapter.yml").read_text(encoding="utf-8")

    assert project["version"] == "0.26.0"
    assert "hosted" in project["optional-dependencies"]
    assert vscode["version"] == "0.8.1"
    assert 'version = "0.8.2"' in gradle
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
    assert 'id="app.factoryline.intellij.openGraphOps"' in plugin_xml
    assert "Unified Graph Ops" in plugin_xml
    assert "Use FactoryLine when you want to" in plugin_xml
    assert "Turn an outcome into a buildable starting point" in plugin_xml
    assert "Review AI or teammate changes with evidence" in plugin_xml
    assert "Use real plugin UI, not concept art." in screenshot_brief
    assert "1280x800" in screenshot_brief


def test_marketplace_acquisition_kit_uses_real_product_assets_and_observed_metrics_only():
    kit = (ROOT / "docs" / "JETBRAINS_MARKETPLACE_ACQUISITION_KIT.md").read_text(encoding="utf-8")
    baseline = json.loads((ROOT / "docs" / "JETBRAINS_MARKETPLACE_MEASUREMENT.json").read_text(encoding="utf-8"))

    assert "Verify AI code before you ship." in kit
    assert "Run First Proof" in kit
    assert "factory mvp" in kit
    assert "Graph Ops" in kit
    assert "conversion rate" in kit
    assert "causal uplift" in kit
    assert "deliberately leaves" in kit
    assert baseline == {
        "schema": "factory.jetbrains-marketplace-baseline.v1",
        "recorded_at": "2026-08-04T05:00:00Z",
        "source": "https://plugins.jetbrains.com/api/plugins/33009",
        "plugin_id": 33009,
        "downloads": 46,
        "listed_version": "0.7.1",
        "listing_status": "MARKETPLACE_UPDATE_PENDING",
        "measurement_boundary": {
            "download_delta": "publicly observable",
            "conversion_rate": "unavailable_without_Marketplace_impressions_or_page_views",
            "causal_uplift": "unavailable_without_attribution_or_a_controlled_experiment",
            "productivity_or_savings": "not a_Marketplace_download_metric",
        },
    }
    assets = ROOT / "docs" / "assets" / "marketplace"
    for name in ("factory-studio-mvp-1280x800.png", "graph-ops-studio-1280x800.png"):
        assert (assets / name).is_file(), name


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
    assert plan["plugin"]["current_free_version"] == "0.8.1"
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
    assert metadata["version"] == "0.26.0"
    assert metadata["publication_date"] == "2026-08-06"
    assert "Unified Graph Ops" in metadata["description"]
    assert "conceptual visual walkthrough" in metadata["description"]
    assert "prd-grill" in metadata["keywords"]

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
    assert "graph_ops.html" in (ROOT / "pyproject.toml").read_text(encoding="utf-8")

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


def test_historical_release_headings_are_not_renamed_by_version_bumps() -> None:
    """A blanket version-string replace once renamed a past section heading.

    README section headings record which release introduced a feature. Rewriting
    them makes the document claim a feature shipped in a version it did not.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "## New in 0.25.0: the contradiction gate" in readme
    assert "## New in 0.24.0: Unified Graph Ops" in readme
    assert readme.count("## New in 0.26.0:") == 1, "exactly one section may claim 0.26.0"
