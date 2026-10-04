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
        "file_size_guard": {
            "required": True,
            "required_paths": [path.name],
            "files": {
                path.name: {
                    "max_lines": 10000,
                    "max_bytes": 10_000_000,
                    "rationale": "Keep the temporary test policy bounded.",
                }
            },
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


def test_file_size_guard_reports_measurements_and_blocks_file_growth(
    tmp_path: Path,
) -> None:
    source_dir = tmp_path / "factoryline"
    source_dir.mkdir()
    target = source_dir / "large_module.py"
    target.write_text("pass\npass\npass\n", encoding="utf-8")
    policy = _policy(tmp_path / "policy.json", cli=10)
    payload = json.loads(policy.read_text(encoding="utf-8"))
    payload["file_size_guard"] = {
        "required": True,
        "required_paths": ["factoryline/large_module.py"],
        "files": {
            "factoryline/large_module.py": {
                "max_lines": 2,
                "max_bytes": 100,
                "rationale": "Freeze this module until responsibilities are split.",
            }
        },
    }
    policy.write_text(json.dumps(payload), encoding="utf-8")

    blocked = evaluate_architecture_health(tmp_path, policy)

    measured = blocked["metrics"]["file_size_guard"]["files"][
        "factoryline/large_module.py"
    ]
    assert blocked["metrics"]["file_size_guard"]["enforced"] is True
    assert measured == {
        "lines": 3,
        "bytes": len(b"pass\npass\npass\n"),
        "max_lines": 2,
        "max_bytes": 100,
    }
    assert any(
        finding["code"] == "E_ARCH_FILE_LINES_GROWTH"
        for finding in blocked["regressions"]
    )

    target.write_text("pass\npass\n", encoding="utf-8")
    within_budget = evaluate_architecture_health(tmp_path, policy)
    assert not any(
        finding["code"] == "E_ARCH_FILE_LINES_GROWTH"
        for finding in within_budget["regressions"]
    )

    target.write_text("p" * 120 + "\npass\n", encoding="utf-8")
    byte_growth = evaluate_architecture_health(tmp_path, policy)
    assert not any(
        finding["code"] == "E_ARCH_FILE_LINES_GROWTH"
        for finding in byte_growth["regressions"]
    )
    assert any(
        finding["code"] == "E_ARCH_FILE_BYTES_GROWTH"
        for finding in byte_growth["regressions"]
    )


def test_file_size_guard_rejects_escaping_policy_paths(tmp_path: Path) -> None:
    (tmp_path / "factoryline").mkdir()
    policy = _policy(tmp_path / "policy.json", cli=10)
    payload = json.loads(policy.read_text(encoding="utf-8"))
    payload["file_size_guard"] = {
        "required": True,
        "required_paths": ["../outside.py"],
        "files": {
            "../outside.py": {
                "max_lines": 10,
                "max_bytes": 100,
                "rationale": "This path must be rejected.",
            }
        },
    }
    policy.write_text(json.dumps(payload), encoding="utf-8")

    result = evaluate_architecture_health(tmp_path, policy)

    assert any(
        finding["code"] == "E_ARCH_FILE_SIZE_POLICY_INVALID"
        for finding in result["regressions"]
    )


def test_file_size_guard_cannot_be_removed_from_policy(tmp_path: Path) -> None:
    (tmp_path / "factoryline").mkdir()
    policy = _policy(tmp_path / "policy.json", cli=10)
    payload = json.loads(policy.read_text(encoding="utf-8"))
    payload.pop("file_size_guard")
    policy.write_text(json.dumps(payload), encoding="utf-8")

    result = evaluate_architecture_health(tmp_path, policy)

    assert result["decision"] == "BLOCKED"
    assert "E_ARCH_FILE_SIZE_POLICY_INVALID" in {
        finding["code"] for finding in result["regressions"]
    }


def test_file_size_guard_blocks_when_required_path_budget_is_removed(
    tmp_path: Path,
) -> None:
    policy = _policy(tmp_path / "policy.json", cli=10)
    payload = json.loads(policy.read_text(encoding="utf-8"))
    payload["file_size_guard"] = {
        "required": True,
        "required_paths": ["factoryline/one.py", "factoryline/two.py"],
        "files": {
            "factoryline/one.py": {
                "max_lines": 1,
                "max_bytes": 5,
                "rationale": "Keep this temporary module bounded.",
            }
        },
    }
    policy.write_text(json.dumps(payload), encoding="utf-8")

    result = evaluate_architecture_health(tmp_path, policy)

    assert result["decision"] == "BLOCKED"
    assert "E_ARCH_FILE_SIZE_POLICY_INVALID" in {
        finding["code"] for finding in result["regressions"]
    }


def test_self_guard_blocks_when_path_and_budget_are_both_removed(
    tmp_path: Path,
) -> None:
    root = Path(architecture_health.__file__).resolve().parents[1]
    payload = json.loads(
        (root / "architecture-policy.json").read_text(encoding="utf-8")
    )
    missing = "factoryline/graph_ops.py"
    payload["file_size_guard"]["required_paths"].remove(missing)
    payload["file_size_guard"]["files"].pop(missing)
    altered_policy = tmp_path / "architecture-policy.json"
    altered_policy.write_text(json.dumps(payload), encoding="utf-8")

    result = evaluate_architecture_health(root, altered_policy)

    assert result["decision"] == "BLOCKED"
    assert "E_ARCH_FILE_SIZE_POLICY_INVALID" in {
        finding["code"] for finding in result["regressions"]
    }


def test_self_guard_blocks_when_file_size_ceiling_is_raised(tmp_path: Path) -> None:
    root = Path(architecture_health.__file__).resolve().parents[1]
    payload = json.loads(
        (root / "architecture-policy.json").read_text(encoding="utf-8")
    )
    payload["file_size_guard"]["files"]["factoryline/cli.py"]["max_lines"] += 1
    altered_policy = tmp_path / "architecture-policy.json"
    altered_policy.write_text(json.dumps(payload), encoding="utf-8")

    result = evaluate_architecture_health(root, altered_policy)

    assert result["decision"] == "BLOCKED"
    assert "E_ARCH_FILE_SIZE_POLICY_INVALID" in {
        finding["code"] for finding in result["regressions"]
    }


def test_self_guard_applies_to_installed_cli_targeting_checkout(
    tmp_path: Path, monkeypatch
) -> None:
    root = Path(architecture_health.__file__).resolve().parents[1]
    monkeypatch.setattr(
        architecture_health,
        "__file__",
        str(tmp_path / "site-packages" / "factoryline" / "architecture_health.py"),
    )
    payload = json.loads(
        (root / "architecture-policy.json").read_text(encoding="utf-8")
    )
    payload["file_size_guard"]["files"]["factoryline/graph_ops.py"]["max_bytes"] += 1
    altered_policy = tmp_path / "architecture-policy.json"
    altered_policy.write_text(json.dumps(payload), encoding="utf-8")

    result = evaluate_architecture_health(root, altered_policy)

    assert result["decision"] == "BLOCKED"
    assert "E_ARCH_FILE_SIZE_POLICY_INVALID" in {
        finding["code"] for finding in result["regressions"]
    }


def test_self_guard_detects_checkout_with_single_quoted_toml_identity(
    tmp_path: Path,
) -> None:
    source_root = Path(architecture_health.__file__).resolve().parents[1]
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        "[project]\nname = 'factoryline-code-factory'\n", encoding="utf-8"
    )
    payload = json.loads(
        (source_root / "architecture-policy.json").read_text(encoding="utf-8")
    )
    (root / "architecture-policy.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    payload["file_size_guard"] = {
        "required": True,
        "required_paths": ["factoryline/cli.py"],
        "files": {
            "factoryline/cli.py": {
                "max_lines": 999999,
                "max_bytes": 999999999,
            }
        },
    }
    altered = tmp_path / "alternate-policy.json"
    altered.write_text(json.dumps(payload), encoding="utf-8")

    result = evaluate_architecture_health(root, altered)

    assert result["decision"] == "BLOCKED"
    assert "E_ARCH_FILE_SIZE_POLICY_INVALID" in {
        finding["code"] for finding in result["regressions"]
    }


def test_self_guard_requires_pinned_default_policy_when_override_is_used(
    tmp_path: Path,
) -> None:
    source_root = Path(architecture_health.__file__).resolve().parents[1]
    root = tmp_path / "checkout"
    (root / "factoryline").mkdir(parents=True)
    (root / "factoryline/architecture_health.py").write_text("", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "factoryline-code-factory"\n', encoding="utf-8"
    )
    alternate = tmp_path / "alternate-policy.json"
    alternate.write_bytes((source_root / "architecture-policy.json").read_bytes())

    result = evaluate_architecture_health(root, alternate)

    assert result["decision"] == "BLOCKED"
    assert "E_ARCH_FILE_SIZE_POLICY_INVALID" in {
        finding["code"] for finding in result["regressions"]
    }


def test_self_guard_detects_pinned_default_policy_after_identity_files_change(
    tmp_path: Path,
) -> None:
    source_root = Path(architecture_health.__file__).resolve().parents[1]
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname = "renamed-project"\n', encoding="utf-8"
    )
    (root / "architecture-policy.json").write_bytes(
        (source_root / "architecture-policy.json").read_bytes()
    )
    alternate = tmp_path / "alternate-policy.json"
    payload = json.loads(
        (source_root / "architecture-policy.json").read_text(encoding="utf-8")
    )
    payload["file_size_guard"]["files"]["factoryline/cli.py"]["max_lines"] += 1
    alternate.write_text(json.dumps(payload), encoding="utf-8")

    result = evaluate_architecture_health(root, alternate)

    assert result["decision"] == "BLOCKED"
    assert "E_ARCH_FILE_SIZE_POLICY_INVALID" in {
        finding["code"] for finding in result["regressions"]
    }


def test_file_size_guard_normalizes_crlf_before_counting_bytes(
    tmp_path: Path,
) -> None:
    source_dir = tmp_path / "factoryline"
    source_dir.mkdir()
    target = source_dir / "large_module.py"
    target.write_bytes(b"pass\r\npass\r\n")
    policy = _policy(tmp_path / "policy.json", cli=10)
    payload = json.loads(policy.read_text(encoding="utf-8"))
    payload["file_size_guard"] = {
        "required": True,
        "required_paths": ["factoryline/large_module.py"],
        "files": {
            "factoryline/large_module.py": {
                "max_lines": 2,
                "max_bytes": len(b"pass\npass\n"),
                "rationale": "Line-ending conversion must not count as source growth.",
            }
        },
    }
    policy.write_text(json.dumps(payload), encoding="utf-8")

    result = evaluate_architecture_health(tmp_path, policy)

    measured = result["metrics"]["file_size_guard"]["files"][
        "factoryline/large_module.py"
    ]
    assert measured["lines"] == 2
    assert measured["bytes"] == len(b"pass\npass\n")
    assert "E_ARCH_FILE_BYTES_GROWTH" not in {
        finding["code"] for finding in result["regressions"]
    }


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
                "file_size_guard": {
                    "required": True,
                    "required_paths": ["architecture-policy.json"],
                    "files": {
                        "architecture-policy.json": {
                            "max_lines": 10000,
                            "max_bytes": 10_000_000,
                            "rationale": "Keep the temporary test policy bounded.",
                        }
                    },
                },
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
            "scope": "per_channel",
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
                "scope": "per_channel",
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


def test_editor_cadence_is_measured_from_its_own_tags(tmp_path, monkeypatch):
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
        if "refs/tags/vscode-v*" in argv:
            return SimpleNamespace(stdout="")
        if "refs/tags/jetbrains-v*" in argv:
            return SimpleNamespace(
                stdout="jetbrains-v0.9.6\t2026-09-10T00:00:00+00:00\n"
            )
        return SimpleNamespace(stdout="v0.46.9\t2026-09-26T00:00:00+00:00\n")

    monkeypatch.setattr(architecture_health.subprocess, "run", git)
    now = datetime(2026, 9, 28, tzinfo=timezone.utc)
    assert not release_cadence_status(tmp_path, now)["admission"]
    assert release_cadence_status(tmp_path, now, channel="vscode")["admission"]
    assert release_cadence_status(tmp_path, now, channel="jetbrains")["admission"]


def test_cadence_selects_exact_channel_tags_and_keeps_version_suffixes(
    tmp_path, monkeypatch
):
    from types import SimpleNamespace

    cadence = {
        "scope": "per_channel",
        "max_releases_30d": 4,
        "minimum_days_between_releases": 7,
        "effective_at": "2026-09-21T15:01:54Z",
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

    core_tags = (
        "v0.46.4+openvsxfix\t2026-09-15T00:00:00+00:00\n"
        "v0.46.9\t2026-09-26T05:53:51+00:00\n"
        "vscode-v1.0.2\t2026-09-30T17:42:41+00:00\n"
    )
    vscode_tags = "vscode-v1.0.2\t2026-09-30T17:42:41+00:00\n"
    jetbrains_tags = "jetbrains-v1.0.2\t2026-09-30T17:42:41+00:00\n"

    def git(argv, **kwargs):
        if "refs/tags/vscode-v*" in argv:
            return SimpleNamespace(stdout=vscode_tags)
        if "refs/tags/jetbrains-v*" in argv:
            return SimpleNamespace(stdout=jetbrains_tags)
        return SimpleNamespace(stdout=core_tags)

    monkeypatch.setattr(architecture_health.subprocess, "run", git)
    now = datetime(2026, 9, 30, 18, tzinfo=timezone.utc)

    core = release_cadence_status(tmp_path, now)
    vscode = release_cadence_status(tmp_path, now, channel="vscode")
    jetbrains = release_cadence_status(tmp_path, now, channel="jetbrains")

    assert core["latest_tag"] == "v0.46.9"
    assert core["pre_policy_release_count"] == 1
    assert core["recent_count"] == 1
    assert core["next_eligible_at"] == "2026-10-03T05:53:51Z"
    assert vscode["latest_tag"] == "vscode-v1.0.2"
    assert jetbrains["latest_tag"] == "jetbrains-v1.0.2"
