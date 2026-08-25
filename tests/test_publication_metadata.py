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
    assert _match(ROOT / "CITATION.cff", r"^date-released: (\d{4}-\d{2}-\d{2})$") == "2026-08-25"


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
    assert project["description"] == "Catch AI-generated tests that could never fail and review AI code with local proof."
    assert {
        "mvp",
        "mcp",
        "model-context-protocol",
        "cursor",
        "opencode",
        "graph-ops",
        "prd-grill",
        "verifier-plane",
        "proof-debt",
        "ai-governance",
        "design-review",
        "ui-quality",
        "gauntlet",
        "e2e-testing",
        "survival-card",
    }.issubset(project["keywords"])


def test_python_wheel_data_is_explicit_and_does_not_depend_on_package_discovery():
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert "include-package-data = false" in project
    assert 'factoryline = ["builtin_packs/**/*", "data/*.json", "hosted_console.html", "graph_ops.html"]' in project


def test_public_ctas_are_outcome_led_and_preserve_proof_boundaries():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    vscode_package = json.loads((ROOT / "editors" / "vscode" / "package.json").read_text(encoding="utf-8"))
    vscode_readme = (ROOT / "editors" / "vscode" / "README.md").read_text(encoding="utf-8")
    intellij_plugin = (ROOT / "editors" / "intellij" / "src" / "main" / "resources" / "META-INF" / "plugin.xml").read_text(encoding="utf-8")
    intellij_readme = (ROOT / "editors" / "intellij" / "README.md").read_text(encoding="utf-8")

    value = "Catch AI-generated tests that could never fail — before review."
    assert value in readme
    assert "challenges whether a test can actually reject" in readme
    assert readme.index(value) < readme.index("## What it does")
    assert "factory mvp \"Build an approval tracker\" --root ." in readme
    assert "See actual Factory Studio" in readme
    assert "factory-studio-mvp-1280x800.png" in readme
    assert readme.index("factory mvp \"Build an approval tracker\" --root .") < readme.index("## Install")
    assert "live Hugging Face Space" in readme
    assert "Cursor or OpenCode MCP" in readme
    assert "deterministic proof" in readme
    assert "star Code Factory" in readme
    assert "This optional link only opens the repository." in readme
    assert "starter is never called production-ready" in readme
    assert "offline-verifiable Survival Card" in readme
    assert "factory gauntlet" in readme
    assert vscode_package["description"] == "Catch AI-generated tests that could never fail. Review code with local proof."
    assert {"mvp", "mcp", "graph-ops", "proof-debt", "ai-governance", "design-review", "ui-quality"}.issubset(vscode_package["keywords"])
    for content in (vscode_readme, intellij_readme):
        assert value in content
        assert "Graph Ops" in content
    assert "Your IDE feels slow. Your AI code looks fine." in intellij_plugin
    assert "FactoryLine AI Proof is free, local IDE Guardian + AI proof for JetBrains." in intellij_plugin
    assert 'width="40"' in (ROOT / "editors" / "intellij" / "src" / "main" / "resources" / "META-INF" / "pluginIcon.svg").read_text(encoding="utf-8")
    assert 'height="40"' in (ROOT / "editors" / "intellij" / "src" / "main" / "resources" / "META-INF" / "pluginIcon_dark.svg").read_text(encoding="utf-8")
    assert "Star Code Factory" in vscode_readme
    assert "Star Code Factory" in intellij_readme
    for content in (readme, vscode_readme, intellij_plugin, intellij_readme):
        assert "PRD Grill" in content
        assert "factory prd grill" in content
        assert "Proof Debt" in content
    operations = (ROOT / "docs" / "ENTERPRISE_TEAMS_OPERATIONS.md").read_text(encoding="utf-8")
    assert "Vibe coding / solo work" in operations
    assert "Professional teams" in operations
    assert "Design is a first-class review lane" in operations
    assert "Prestige Design Review" in operations
    assert "does not silently call a model" in operations


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
    assert "Catch AI-generated tests that could never fail and review AI code with local" in guide
    assert "proof." in guide
    assert "code-generation" in guide
    assert "r/devops" in guide
    assert "r/platformengineering" in guide
    assert "r/sre" in guide
    assert "r/kubernetes" in guide
    assert "Code Factory does not submit, vote on, or coordinate votes" in guide


def test_publish_workflow_uses_trusted_publishing_without_stored_credentials():
    workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")

    assert "permissions:\n  contents: read" in workflow
    assert "  validate_python:" in workflow
    assert "  validate_vscode:" in workflow
    assert "  validate_intellij:" in workflow
    assert "  publish:" in workflow
    assert "needs: [validate_python, validate_vscode, validate_intellij]" in workflow
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
    assert "name: release-python-${{ github.event.release.tag_name }}" in workflow
    assert "name: release-vscode-${{ github.event.release.tag_name }}" in workflow
    assert "name: release-intellij-${{ github.event.release.tag_name }}" in workflow
    assert "path: release-bundle/python" in workflow
    assert "path: release-bundle/editors" in workflow
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
    assert "  authorize:" in workflow
    assert "Require the scoped Open VSX publisher token before candidate work" in workflow
    assert "needs: authorize" in workflow
    assert "inputs.publish == false || needs.authorize.result == 'success'" in workflow
    assert "needs: [authorize, validate]" in workflow
    assert "secrets.OPENVSX_TOKEN" in workflow
    assert "ovsx@1.1.0 publish" in workflow
    assert "OPENVSX_TOKEN is required" in workflow
    assert workflow.index("Require the scoped Open VSX publisher token before candidate work") < workflow.index("Install, audit, test, and package")


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
    assert workflow.count("chmod +x gradlew") == 3


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


def test_vscode_marketplace_workflow_seals_the_candidate_and_requires_a_scoped_secret():
    workflow = (ROOT / ".github" / "workflows" / "vscode-marketplace.yml").read_text(encoding="utf-8")

    assert "environment: vscode-marketplace" in workflow
    assert "secrets.VSCE_PAT" in workflow
    assert "VSCE_PAT is required in the vscode-marketplace environment." in workflow
    assert "sha256sum --check SHA256SUMS.txt" in workflow
    assert "--packagePath vscode-marketplace-candidate/factoryline-vscode.vsix" in workflow
    assert "--oidc" not in workflow


def test_hosted_release_and_editor_versions_are_declared():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    vscode = json.loads((ROOT / "editors" / "vscode" / "package.json").read_text(encoding="utf-8"))
    gradle = (ROOT / "editors" / "intellij" / "build.gradle.kts").read_text(encoding="utf-8")
    hosted_workflow = (ROOT / ".github" / "workflows" / "hosted-adapter.yml").read_text(encoding="utf-8")

    assert project["version"] == "0.44.3"
    assert "hosted" in project["optional-dependencies"]
    assert vscode["version"] == "0.8.11"
    assert 'version = "0.8.16"' in gradle
    assert "postgres:17" in hosted_workflow
    assert "FACTORY_TEST_POSTGRES_DSN" in hosted_workflow


def test_jetbrains_listing_is_outcome_led_and_first_proof_is_discoverable():
    plugin_xml = (ROOT / "editors" / "intellij" / "src" / "main" / "resources" / "META-INF" / "plugin.xml").read_text(encoding="utf-8")
    screenshot_brief = (ROOT / "docs" / "JETBRAINS_MARKETPLACE_SCREENSHOTS.md").read_text(encoding="utf-8")

    assert "<id>app.factoryline</id>" in plugin_xml
    assert "<name>FactoryLine AI Proof</name>" in plugin_xml
    assert "Your IDE feels slow. Your AI code looks fine." in plugin_xml
    assert "FactoryLine AI Proof is free, local IDE Guardian + AI proof for JetBrains." in plugin_xml
    assert "New in 0.8.16 — Senior Attention, not another vague warning" in plugin_xml
    assert "Tools | FactoryLine | Run First Proof" in plugin_xml
    assert 'id="app.factoryline.intellij.firstProof"' in plugin_xml
    assert "Run First Proof" in plugin_xml
    assert 'id="app.factoryline.intellij.openGraphOps"' in plugin_xml
    assert "Unified Graph Ops" in plugin_xml
    assert 'id="app.factoryline.intellij.openGuardian"' in plugin_xml
    assert "Open Guardian Core" in plugin_xml
    assert "Use FactoryLine when you want to" in plugin_xml
    assert "Turn an outcome into a buildable starting point" in plugin_xml
    assert "Review AI or teammate changes with evidence" in plugin_xml
    assert "Use real plugin UI, not concept art." in screenshot_brief
    assert "1280x800" in screenshot_brief


def test_intellij_source_uses_supported_choice_dialog_api_with_safe_defaults():
    actions = (ROOT / "editors" / "intellij" / "src" / "main" / "kotlin" / "app" / "factoryline" / "intellij" / "FactoryLineActions.kt").read_text(encoding="utf-8")

    assert "Messages.showChooseDialog" not in actions
    assert actions.count("Messages.showDialog(") >= 4
    assert 'risks, 1, Messages.getQuestionIcon()' in actions
    assert 'FactoryLineExecutionConfirmation.confirm(project, "Prepare Repair Scope")' in actions


def test_intellij_build_uses_the_gradle_9_5_compatible_kotlin_plugin_line():
    settings = (ROOT / "editors" / "intellij" / "settings.gradle.kts").read_text(encoding="utf-8")
    build = (ROOT / "editors" / "intellij" / "build.gradle.kts").read_text(encoding="utf-8")

    assert 'id("org.jetbrains.kotlin.jvm") version "2.4.10"' in settings
    assert 'id("org.jetbrains.kotlin.jvm") version "2.1.20"' not in settings
    assert "jvmDefault.set(JvmDefaultMode.NO_COMPATIBILITY)" in build


def test_marketplace_acquisition_kit_uses_real_product_assets_and_observed_metrics_only():
    kit = (ROOT / "docs" / "JETBRAINS_MARKETPLACE_ACQUISITION_KIT.md").read_text(encoding="utf-8")
    baseline = json.loads((ROOT / "docs" / "JETBRAINS_MARKETPLACE_MEASUREMENT.json").read_text(encoding="utf-8"))

    assert "Catch AI-generated tests that could never fail — before review." in kit
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
    assert sample["owner_approved_monthly_price"] == 5.95
    assert sample["owner_approved_annual_price"] == 60.0
    assert round((average - 5.95) / average, 10) == sample["discount_from_sample_average"]
    assert sample["status"] == "owner_approved_future_price_not_active_on_marketplace"
    assert sample["free_through"] == "2026-12-31"


def test_jetbrains_paid_launch_is_complete_but_cannot_activate_early():
    plan = json.loads((ROOT / "docs" / "JETBRAINS_MONETIZATION_2027.json").read_text(encoding="utf-8"))
    runbook = (ROOT / "docs" / "JETBRAINS_MONETIZATION_2027.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    active_xml = (ROOT / "editors" / "intellij" / "src" / "main" / "resources" / "META-INF" / "plugin.xml").read_text(encoding="utf-8")
    staged_xml = (ROOT / "editors" / "intellij" / "monetization" / "plugin-product-descriptor-2027.xml").read_text(encoding="utf-8")

    assert plan["offer"]["monthly_price_usd"] == 5.95
    assert plan["offer"]["annual_price_usd"] == 60.0
    assert plan["offer"]["monthly_price_status"] == "owner_approved"
    assert plan["offer"]["paid_from"] == "2027-01-01"
    assert plan["plugin"]["current_free_version"] == "0.8.16"
    assert plan["paid_descriptor"] == {
        "product_code": "PFACTORYLINE",
        "product_code_status": "proposed_not_registered",
        "release_date": "20270101",
        "release_version": "20271",
        "optional": True,
        "active_descriptor_contains_product_descriptor": False,
        "staging_template": "editors/intellij/monetization/plugin-product-descriptor-2027.xml",
    }
    assert "<product-descriptor" not in active_xml
    assert "$5.95 USD per named seat/month or $60 USD per named seat/year" not in active_xml
    assert "Optional paid features are not active in this Marketplace build" in active_xml
    assert "star Code Factory" not in active_xml
    assert not (ROOT / "editors" / "intellij" / "src" / "main" / "kotlin" / "app" / "factoryline" / "intellij" / "FactoryLineGitHubStarPrompt.kt").exists()
    assert "$5.95 USD per named seat/month" in readme
    assert 'code="PFACTORYLINE"' in staged_xml
    assert 'release-date="20270101"' in staged_xml
    assert 'release-version="20271"' in staged_xml
    assert 'optional="true"' in staged_xml
    assert len(plan["activation_gates"]) == 9
    assert plan["current_verdict"] == "MONETIZATION_GATE_BLOCKED"
    for phrase in ("licensed", "active-trial", "expired-trial", "unlicensed", "offline", "uninitialized-facade"):
        assert phrase in runbook


def test_jetbrains_publication_workflow_blocks_an_occupied_binary_update_slot():
    workflow = (ROOT / ".github" / "workflows" / "jetbrains-marketplace.yml").read_text(encoding="utf-8")

    assert "Require an open Marketplace binary-update slot" in workflow
    assert "scripts/jetbrains_marketplace_status.py" in workflow
    assert "--plugin-id 33009 --require-upload-slot --json" in workflow
    assert "guardianReleaseGate" in workflow
    assert "verify sealed candidate" in workflow
    assert "Restore Gradle wrapper execute permission" in workflow
    assert "needs: [validate, compatibility]" in workflow


def test_jetbrains_reviewer_and_growth_docs_keep_external_approval_and_reviews_honest():
    reviewer = (ROOT / "docs" / "JETBRAINS_REVIEWER_SUMMARY.md").read_text(encoding="utf-8")
    compliance = (ROOT / "docs" / "JETBRAINS_MARKETPLACE_COMPLIANCE_0_8_16.md").read_text(encoding="utf-8")
    growth = (ROOT / "docs" / "JETBRAINS_POST_RELEASE_GROWTH.md").read_text(encoding="utf-8")

    assert "Guardian Core" in reviewer
    assert "manual review" in reviewer
    assert "external" in compliance
    assert "guardianReleaseGate" in compliance
    assert "prepared, not executed" in growth
    assert "honest Marketplace review" in growth
    assert "no Marketplace-review prompt" in growth
    assert "fabricated" in growth


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
    assert metadata["version"] == "0.44.3"
    assert metadata["publication_date"] == "2026-08-25"
    assert "Unified Graph Ops" in metadata["description"]
    assert "Journey Reality" in metadata["description"]
    assert "audits the agent" in metadata["description"]
    assert "60-day personal-use case" in metadata["description"]
    assert "not a benchmark, guaranteed ROI, or verified cash saving" in metadata["description"]
    assert "conceptual visual walkthrough" not in metadata["description"]
    assert "prd-grill" in metadata["keywords"]
    assert "verifier-plane" in metadata["keywords"]
    assert "github-pull-request" in metadata["keywords"]
    assert "proof-review" in metadata["keywords"]
    assert "plan-to-proof-review" in metadata["keywords"]
    assert "design-review" in metadata["keywords"]
    assert "langgraph-assurance" in metadata["keywords"]
    assert "resume parity" in metadata["description"]
    assert "Survival Card" in metadata["description"]
    assert "gauntlet" in metadata["keywords"]
    assert "survival-card" in metadata["keywords"]

    assets = ROOT / "docs" / "assets"
    for name in (
        "verify-policy.gif",
        "factoryline-logo-480.png",
        "factory-editor-control-room.svg",
        "operational-proof-loop-1600x900.png",
        "operational-proof-loop.svg",
        "prd-to-app-factory.svg",
        "product-missions.svg",
        "signal-loop.svg",
    ):
        assert (assets / name).is_file(), name
    for retired in (
        "code-factory-proof-first.png",
        "code-factory-quickstart-cover-v0171.png",
        "code-factory-quickstart-v0171.mp4",
        "factory-studio-control-room.png",
        "factory-studio-control-room-1080.png",
    ):
        assert not (assets / retired).exists(), retired
    assert not (assets / "how-it-works").exists()
    assert (ROOT / "docs" / "PRODUCT_VISUALS.md").is_file()
    assert not (ROOT / "docs" / "HOW_IT_WORKS_VISUAL.md").exists()

    operational_loop = assets / "operational-proof-loop-1600x900.png"
    with operational_loop.open("rb") as handle:
        assert handle.read(8) == b"\x89PNG\r\n\x1a\n"
        assert struct.unpack(">I", handle.read(4)) == (13,)
        assert handle.read(4) == b"IHDR"
        assert struct.unpack(">II", handle.read(8)) == (1600, 900)

    visual_guide = (ROOT / "docs" / "PRODUCT_VISUALS.md").read_text(encoding="utf-8")
    assert "Operational proof loop" in visual_guide
    assert "editorial workflow diagram" in visual_guide

    source_manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    assert "recursive-include docs *.md *.gif *.png *.svg *.json" in source_manifest
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
        "*.json",
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


def test_release_history_lives_in_the_changelog_not_the_landing_page() -> None:
    """Keep version provenance without making the README a release archive."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    assert "[CHANGELOG.md](CHANGELOG.md)" in readme
    assert "## New in 0.25.0:" not in readme
    assert "## New in 0.24.0:" not in readme
    for version in ("0.24.0", "0.25.0", "0.26.0", "0.27.0", "0.28.0", "0.28.2", "0.29.0", "0.30.0", "0.31.0"):
        assert version in changelog


def test_habituation_essay_is_explicit_about_its_evidence_boundary() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    essay = (ROOT / "docs" / "HABITUATION_ESSAY.md").read_text(encoding="utf-8")

    assert "docs/HABITUATION_ESSAY.md" in readme
    assert "Treat it as a hypothesis, not a verdict" in essay
    assert "blocking policy is even eligible" in essay
    assert "does not rank people, compare teams, transmit observations" in essay
