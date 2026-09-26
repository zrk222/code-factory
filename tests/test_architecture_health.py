from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import factoryline.architecture_health as architecture_health
from factoryline.architecture_health import (
    _cadence_projection,
    collect_architecture_health,
    evaluate_architecture_health,
    release_cadence_status,
)
from factoryline.cli import main


def _policy(path: Path, **budgets: int | float) -> Path:
    payload = {
        "schema": "factory.architecture-policy.v1",
        "baseline": {},
        "budgets": {
            "max_markdown_files": budgets.get("markdown", 2),
            "max_python_files": budgets.get("python", 2),
            "max_markdown_python_ratio": budgets.get("ratio", 2.0),
            "max_cli_lines": budgets.get("cli", 5),
            "max_core_modules": budgets.get("core", 2),
        },
        "review_thresholds": {
            "markdown_python_ratio": 1.5,
            "cli_lines": 5000,
            "core_modules": 150,
        },
        "release": {
            "max_releases_30d": 4,
            "minimum_days_between_releases": 7,
            "effective_at": "2026-09-01T00:00:00Z",
            "exception_requires": "human-release-authority",
            "requires_changelog_entry": False,
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_health_collects_files_and_excludes_package_init(tmp_path: Path) -> None:
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "factoryline" / "__init__.py").write_text(
        "__version__ = '1.0.0'\n", encoding="utf-8"
    )
    (tmp_path / "factoryline" / "one.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# readme\n", encoding="utf-8")
    metrics = collect_architecture_health(tmp_path)["metrics"]
    assert metrics["markdown_files"] == 1
    assert metrics["python_files"] == 2
    assert metrics["core_modules"] == 1
    assert metrics["version"] == "1.0.0"
    assert metrics["module_domains"] == {"manifest_missing": 1}


def test_health_blocks_budget_regression_but_keeps_debt_separate(
    tmp_path: Path,
) -> None:
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "factoryline" / "cli.py").write_text(
        "\n".join(["pass"] * 6), encoding="utf-8"
    )
    (tmp_path / "factoryline" / "one.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# readme\n", encoding="utf-8")
    result = evaluate_architecture_health(
        tmp_path, _policy(tmp_path / "policy.json", cli=5)
    )
    assert result["decision"] == "BLOCKED"
    assert any(
        item["code"] == "E_ARCH_CLI_LINES_GROWTH" for item in result["regressions"]
    )
    assert not any(item["blocking"] for item in result["baseline_debt"])


def test_health_exposes_core_and_specialist_module_domains(tmp_path: Path) -> None:
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "factoryline" / "appforge_demo.py").write_text(
        "pass\n", encoding="utf-8"
    )
    (tmp_path / "factoryline" / "contract.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "architecture-boundaries.json").write_text(
        json.dumps(
            {
                "schema": "factory.module-boundaries.v1",
                "defaultDomain": "core",
                "domains": {"appforge": ["factoryline/appforge_*.py"]},
            }
        ),
        encoding="utf-8",
    )
    domains = collect_architecture_health(tmp_path)["metrics"]["module_domains"]
    assert domains == {"appforge": 1, "core": 1}


def test_specialist_modules_do_not_count_against_core_surface_budget(
    tmp_path: Path,
) -> None:
    (tmp_path / "factoryline").mkdir()
    for name in ("cli_demo.py", "appforge_demo.py", "contract.py"):
        (tmp_path / "factoryline" / name).write_text("pass\n", encoding="utf-8")
    (tmp_path / "architecture-boundaries.json").write_text(
        json.dumps(
            {
                "schema": "factory.module-boundaries.v1",
                "defaultDomain": "core",
                "domains": {
                    "appforge": ["factoryline/appforge_*.py"],
                    "cli_surfaces": ["factoryline/cli_*.py"],
                },
            }
        ),
        encoding="utf-8",
    )
    metrics = collect_architecture_health(tmp_path)["metrics"]
    assert metrics["total_factoryline_modules"] == 3
    assert metrics["core_modules"] == 1
    assert metrics["module_domains"] == {
        "appforge": 1,
        "cli_surfaces": 1,
        "core": 1,
    }


def test_malformed_boundary_manifest_is_blocking(tmp_path: Path) -> None:
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "factoryline" / "cli.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "architecture-boundaries.json").write_text(
        "{not-json", encoding="utf-8"
    )
    result = evaluate_architecture_health(
        tmp_path, _policy(tmp_path / "policy.json", cli=2)
    )
    assert result["decision"] == "BLOCKED"
    assert any(
        item["code"] == "E_ARCH_BOUNDARY_MANIFEST_INVALID"
        for item in result["regressions"]
    )


def test_boundary_manifest_with_owners_validates_specialist_contract(
    tmp_path: Path,
) -> None:
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "factoryline" / "appforge_demo.py").write_text(
        "pass\n", encoding="utf-8"
    )
    (tmp_path / "architecture-boundaries.json").write_text(
        json.dumps(
            {
                "schema": "factory.module-boundaries.v1",
                "defaultDomain": "core",
                "domains": {"appforge": ["factoryline/appforge_*.py"]},
                "owners": {"appforge": "appforge-maintainers"},
                "experimental": ["factoryline/appforge_demo.py"],
            }
        ),
        encoding="utf-8",
    )
    domains = collect_architecture_health(tmp_path)["metrics"]["module_domains"]
    assert domains == {"appforge": 1, "core": 0}


def test_boundary_manifest_missing_declared_owner_is_blocking(tmp_path: Path) -> None:
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "factoryline" / "appforge_demo.py").write_text(
        "pass\n", encoding="utf-8"
    )
    (tmp_path / "architecture-boundaries.json").write_text(
        json.dumps(
            {
                "schema": "factory.module-boundaries.v1",
                "defaultDomain": "core",
                "domains": {"appforge": ["factoryline/appforge_*.py"]},
                "owners": {},
            }
        ),
        encoding="utf-8",
    )
    result = evaluate_architecture_health(
        tmp_path, _policy(tmp_path / "policy.json", cli=2)
    )
    assert result["decision"] == "BLOCKED"
    assert any(
        item["code"] == "E_ARCH_BOUNDARY_MANIFEST_INVALID"
        for item in result["regressions"]
    )


def test_release_policy_requires_exact_changelog_heading(tmp_path: Path) -> None:
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "factoryline" / "__init__.py").write_text(
        '__version__ = "1.2.3"\n', encoding="utf-8"
    )
    (tmp_path / "factoryline" / "cli.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "architecture-boundaries.json").write_text(
        json.dumps(
            {
                "schema": "factory.module-boundaries.v1",
                "defaultDomain": "core",
                "domains": {},
            }
        ),
        encoding="utf-8",
    )
    policy = _policy(tmp_path / "policy.json", cli=2)
    value = json.loads(policy.read_text(encoding="utf-8"))
    value["release"]["requires_changelog_entry"] = True
    policy.write_text(json.dumps(value), encoding="utf-8")
    result = evaluate_architecture_health(tmp_path, policy)
    assert result["decision"] == "BLOCKED"
    assert any(
        item["code"] == "E_ARCH_RELEASE_CHANGELOG_MISSING"
        for item in result["regressions"]
    )
    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\n## 1.2.3\n", encoding="utf-8"
    )
    assert evaluate_architecture_health(tmp_path, policy)["decision"] == "HEALTHY"


def test_architecture_health_cli_emits_machine_readable_receipt(
    capsys, tmp_path: Path
) -> None:
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "factoryline" / "cli.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "architecture-boundaries.json").write_text(
        json.dumps(
            {
                "schema": "factory.module-boundaries.v1",
                "defaultDomain": "core",
                "domains": {},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "architecture-policy.json").write_text(
        json.dumps(
            {
                "schema": "factory.architecture-policy.v1",
                "baseline": {},
                "budgets": {
                    "max_markdown_files": 1,
                    "max_python_files": 2,
                    "max_markdown_python_ratio": 2.0,
                    "max_cli_lines": 2,
                    "max_core_modules": 2,
                },
                "review_thresholds": {
                    "markdown_python_ratio": 1.5,
                    "cli_lines": 5000,
                    "core_modules": 150,
                },
                "release": {"max_releases_30d": 4},
            }
        ),
        encoding="utf-8",
    )
    assert main(["architecture", "health", "--root", str(tmp_path), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["schema"] == "factory.architecture-health.v1"
    assert output["decision"] == "HEALTHY"


def test_expiring_exact_acceptance_can_clear_intentional_measured_growth(
    tmp_path: Path,
) -> None:
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "factoryline" / "cli.py").write_text(
        "\n".join(["pass"] * 6), encoding="utf-8"
    )
    (tmp_path / "factoryline" / "one.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# readme\n", encoding="utf-8")
    (tmp_path / "architecture-boundaries.json").write_text(
        json.dumps(
            {
                "schema": "factory.module-boundaries.v1",
                "defaultDomain": "core",
                "domains": {},
            }
        ),
        encoding="utf-8",
    )
    policy = _policy(tmp_path / "policy.json", cli=5, core=0)
    value = json.loads(policy.read_text(encoding="utf-8"))
    value["review_thresholds"]["cli_lines"] = 5
    value["accepted_debt"] = {
        "decision_id": "ARCH-TEST-1",
        "owner": "reviewer",
        "expires_at": "2099-01-01T00:00:00+00:00",
        "reason": "Temporary acceptance while the bounded extraction slice lands.",
        "codes": [
            "E_ARCH_CLI_LINES_GROWTH",
            "E_ARCH_CORE_MODULES_GROWTH",
            "ARCH_CLI_MONOLITH",
        ],
        "metrics": {"cli_lines": 6, "core_modules": 2},
    }
    policy.write_text(json.dumps(value), encoding="utf-8")
    result = evaluate_architecture_health(tmp_path, policy)
    assert result["decision"] == "HEALTHY"
    assert not result["regressions"]
    assert {item["code"] for item in result["accepted_regressions"]} == {
        "E_ARCH_CLI_LINES_GROWTH",
        "E_ARCH_CORE_MODULES_GROWTH",
    }
    assert {item["code"] for item in result["accepted_baseline_debt"]} == {
        "ARCH_CLI_MONOLITH"
    }


def test_stale_acceptance_is_retired_when_its_finding_no_longer_exists(
    tmp_path: Path,
) -> None:
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "factoryline" / "cli.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# readme\n", encoding="utf-8")
    (tmp_path / "architecture-boundaries.json").write_text(
        json.dumps(
            {
                "schema": "factory.module-boundaries.v1",
                "defaultDomain": "core",
                "domains": {},
            }
        ),
        encoding="utf-8",
    )
    policy = _policy(tmp_path / "policy.json", cli=10, core=2)
    value = json.loads(policy.read_text(encoding="utf-8"))
    value["accepted_debt"] = {
        "decision_id": "ARCH-RETIRED-1",
        "owner": "reviewer",
        "expires_at": "2099-01-01T00:00:00+00:00",
        "reason": "A previous command-surface regression was accepted while it was active.",
        "codes": ["E_ARCH_CLI_LINES_GROWTH"],
        "metrics": {"cli_lines": 99},
    }
    policy.write_text(json.dumps(value), encoding="utf-8")

    result = evaluate_architecture_health(tmp_path, policy)

    assert result["decision"] == "HEALTHY"
    assert not result["regressions"]
    assert result["accepted_debt"] is None


def test_active_acceptance_with_stale_measurement_still_blocks(
    tmp_path: Path,
) -> None:
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "factoryline" / "cli.py").write_text(
        "\n".join(["pass"] * 6), encoding="utf-8"
    )
    (tmp_path / "README.md").write_text("# readme\n", encoding="utf-8")
    (tmp_path / "architecture-boundaries.json").write_text(
        json.dumps(
            {
                "schema": "factory.module-boundaries.v1",
                "defaultDomain": "core",
                "domains": {},
            }
        ),
        encoding="utf-8",
    )
    policy = _policy(tmp_path / "policy.json", cli=5, core=2)
    value = json.loads(policy.read_text(encoding="utf-8"))
    value["accepted_debt"] = {
        "decision_id": "ARCH-STALE-MEASURE-1",
        "owner": "reviewer",
        "expires_at": "2099-01-01T00:00:00+00:00",
        "reason": "The current CLI growth was reviewed against its measured value.",
        "codes": ["E_ARCH_CLI_LINES_GROWTH"],
        "metrics": {"cli_lines": 5},
    }
    policy.write_text(json.dumps(value), encoding="utf-8")

    result = evaluate_architecture_health(tmp_path, policy)

    assert result["decision"] == "BLOCKED"
    assert "E_ARCH_ACCEPTANCE_INVALID" in {
        item["code"] for item in result["regressions"]
    }


def test_protocol_modules_are_classified_under_their_owned_boundary(
    tmp_path: Path,
) -> None:
    package = tmp_path / "factoryline"
    package.mkdir()
    for name in ("mcp_setup.py", "mcp_mrt.py", "webmcp.py", "ordinary.py"):
        (package / name).write_text("pass\n", encoding="utf-8")
    (tmp_path / "architecture-boundaries.json").write_text(
        json.dumps(
            {
                "schema": "factory.module-boundaries.v1",
                "defaultDomain": "core",
                "domains": {
                    "agent_protocols": ["factoryline/mcp*.py", "factoryline/webmcp.py"]
                },
                "owners": {"agent_protocols": "agent-protocols-maintainers"},
            }
        ),
        encoding="utf-8",
    )

    snapshot = collect_architecture_health(tmp_path)

    assert snapshot["metrics"]["module_domains"] == {"agent_protocols": 3, "core": 1}
    assert snapshot["metrics"]["core_modules"] == 1


def test_repository_classifies_mcp_transport_helpers_as_agent_protocols() -> None:
    root = Path(__file__).resolve().parents[1]
    paths = [
        "factoryline/mcp.py",
        "factoryline/mcp_setup.py",
        "factoryline/mcp_mrt.py",
        "factoryline/mcp_replay.py",
        "factoryline/webmcp.py",
    ]

    _counts, assignments = architecture_health._module_classification(root, paths)

    assert set(assignments.values()) == {"agent_protocols"}


def test_required_documentation_index_blocks_unclassified_markdown(
    tmp_path: Path,
) -> None:
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "factoryline" / "cli.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# readme\n", encoding="utf-8")
    (tmp_path / "docs" / "guide.md").write_text("# guide\n", encoding="utf-8")
    policy = _policy(tmp_path / "policy.json")
    value = json.loads(policy.read_text(encoding="utf-8"))
    value["documentation"] = {"require_index": True}
    policy.write_text(json.dumps(value), encoding="utf-8")
    (tmp_path / "docs" / "DOCUMENTATION_INDEX.json").write_text(
        json.dumps(
            {
                "schema": "factory.documentation-index.v1",
                "canonical": [
                    {
                        "path": "docs/guide.md",
                        "executable": "factoryline/cli.py",
                    }
                ],
                "coverage": [{"glob": "README.md", "status": "canonical"}],
                "rules": {
                    "canonical_paths_must_exist": True,
                    "canonical_entries_require_executable_or_decision": True,
                },
            }
        ),
        encoding="utf-8",
    )
    result = evaluate_architecture_health(tmp_path, policy)
    assert result["decision"] == "BLOCKED"
    assert any(
        item["code"] == "E_ARCH_DOCUMENTATION_INDEX_INVALID"
        for item in result["regressions"]
    )


def test_required_release_train_validates_channels_and_states(tmp_path: Path) -> None:
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "factoryline" / "__init__.py").write_text(
        '__version__ = "1.0.0"\n', encoding="utf-8"
    )
    (tmp_path / "factoryline" / "cli.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\n## 1.0.0\n", encoding="utf-8"
    )
    (tmp_path / "architecture-boundaries.json").write_text(
        json.dumps(
            {
                "schema": "factory.module-boundaries.v1",
                "defaultDomain": "core",
                "domains": {},
            }
        ),
        encoding="utf-8",
    )
    policy = _policy(tmp_path / "policy.json")
    value = json.loads(policy.read_text(encoding="utf-8"))
    value["release"]["requires_changelog_entry"] = True
    value["release"]["require_train"] = True
    policy.write_text(json.dumps(value), encoding="utf-8")
    (tmp_path / "release-train.json").write_text(
        json.dumps(
            {
                "schema": "factory.release-train.v1",
                "train_id": "test",
                "owner": "reviewer",
                "channels": [
                    {
                        "id": "core",
                        "version_source": "factoryline/__init__.py",
                        "changelog": "CHANGELOG.md",
                        "artifact": "dist/*.whl",
                    }
                ],
                "cadence": {
                    "max_releases_30d": 4,
                    "minimum_days_between_releases": 7,
                    "effective_at": "2026-09-01T00:00:00Z",
                    "exception_requires": "human-release-authority",
                    "requires_changelog_entry": True,
                },
                "publication_states": [
                    "prepared",
                    "verified",
                    "uploaded",
                    "processing",
                    "published",
                    "pending_review",
                    "blocked",
                    "not_configured",
                ],
            }
        ),
        encoding="utf-8",
    )
    result = evaluate_architecture_health(tmp_path, policy)
    assert result["decision"] == "HEALTHY"
    assert result["metrics"]["release_train"] == {
        "status": "valid",
        "channels": 1,
        "cadence": {
            "max_releases_30d": 4,
            "minimum_days_between_releases": 7,
            "effective_at": "2026-09-01T00:00:00Z",
            "exception_requires": "human-release-authority",
            "requires_changelog_entry": True,
        },
    }


def test_release_cadence_projects_a_forward_freeze_without_rewriting_history() -> None:
    now = datetime(2026, 9, 21, tzinfo=timezone.utc)
    releases = [
        ("v0.46.7", datetime(2026, 9, 19, tzinfo=timezone.utc)),
        ("v0.46.6", datetime(2026, 9, 18, tzinfo=timezone.utc)),
        ("v0.46.5", datetime(2026, 9, 14, tzinfo=timezone.utc)),
        ("v0.46.4", datetime(2026, 9, 9, tzinfo=timezone.utc)),
        ("v0.46.3", datetime(2026, 9, 6, tzinfo=timezone.utc)),
    ]
    result = _cadence_projection(releases, now=now)
    assert result["state"] == "rate_limited"
    assert result["admission"] is False
    assert result["latest_tag"] == "v0.46.7"
    assert result["next_eligible_at"] == "2026-10-09T00:00:00.000001Z"

    boundary = _cadence_projection(
        releases,
        now=datetime(2026, 10, 9, tzinfo=timezone.utc),
    )
    assert boundary["admission"] is False
    after_boundary = _cadence_projection(
        releases,
        now=datetime(2026, 10, 9, 0, 0, 0, 1, tzinfo=timezone.utc),
    )
    assert after_boundary["admission"] is True


def test_release_cadence_starts_from_policy_adoption_without_erasing_history() -> None:
    effective = datetime(2026, 9, 21, 15, 1, 54, tzinfo=timezone.utc)
    releases = [
        (f"v0.46.{index}", datetime(2026, 9, index + 1, tzinfo=timezone.utc))
        for index in range(5)
    ]

    result = _cadence_projection(
        releases,
        now=datetime(2026, 9, 24, tzinfo=timezone.utc),
        effective_at=effective,
    )

    assert result["state"] == "no_tags"
    assert result["admission"] is True
    assert result["recent_count"] == 0
    assert result["pre_policy_release_count"] == 5
    assert result["effective_at"] == "2026-09-21T15:01:54Z"

    before_effective = _cadence_projection(
        releases,
        now=datetime(2026, 9, 21, 15, 1, 53, tzinfo=timezone.utc),
        effective_at=effective,
    )
    assert before_effective["state"] == "not_yet_effective"
    assert before_effective["admission"] is False
    assert before_effective["next_eligible_at"] == "2026-09-21T15:01:54Z"


def test_release_cadence_fails_closed_when_policy_and_train_diverge(
    monkeypatch, tmp_path: Path
) -> None:
    (tmp_path / "architecture-policy.json").write_text(
        json.dumps(
            {
                "release": {
                    "max_releases_30d": 5,
                    "minimum_days_between_releases": 7,
                    "exception_requires": "human-release-authority",
                    "requires_changelog_entry": True,
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "release-train.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        architecture_health,
        "_tracked_files",
        lambda root: [root / "architecture-policy.json", root / "release-train.json"],
    )
    monkeypatch.setattr(
        architecture_health,
        "_release_train",
        lambda *_args: {
            "status": "valid",
            "cadence": {
                "max_releases_30d": 4,
                "minimum_days_between_releases": 7,
                "exception_requires": "human-release-authority",
                "requires_changelog_entry": True,
            },
        },
    )

    result = release_cadence_status(tmp_path)

    assert result["available"] is False
    assert result["admission"] is False
    assert result["state"] == "release_policy_mismatch"


def test_release_cadence_excludes_only_bound_candidate(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    from types import SimpleNamespace

    cadence = {
        "max_releases_30d": 4,
        "minimum_days_between_releases": 7,
        "effective_at": "2026-09-01T00:00:00Z",
        "exception_requires": "human-release-authority",
        "requires_changelog_entry": True,
    }
    (tmp_path / "architecture-policy.json").write_text(json.dumps({"release": cadence}))
    monkeypatch.setattr(architecture_health, "_tracked_files", lambda root: [])
    monkeypatch.setattr(
        architecture_health,
        "_release_train",
        lambda *args: {"status": "valid", "cadence": cadence},
    )

    def git(argv, **kwargs):
        if "rev-parse" in argv:
            return SimpleNamespace(
                stdout="a" * 40
                if argv[-1] in {"HEAD", "refs/tags/v0.46.9^{commit}"}
                else "b" * 40
            )
        return SimpleNamespace(
            stdout="v0.46.8\t2026-09-10T00:00:00+00:00\nv0.46.9\t2026-09-25T00:00:00+00:00\n"
        )

    monkeypatch.setattr(architecture_health.subprocess, "run", git)
    now = datetime(2026, 9, 25, 12, tzinfo=timezone.utc)
    assert not release_cadence_status(tmp_path, now)["admission"]
    result = release_cadence_status(tmp_path, now, candidate_tag="v0.46.9")
    assert result["admission"]
    assert result["recent_count"] == 1
    assert result["excluded_candidate_tag"] == "v0.46.9"
    import pytest

    with pytest.raises(ValueError, match="checked-out commit"):
        release_cadence_status(tmp_path, now, candidate_tag="v0.46.8")
    with pytest.raises(ValueError, match="vMAJOR"):
        release_cadence_status(tmp_path, now, candidate_tag="--all")
