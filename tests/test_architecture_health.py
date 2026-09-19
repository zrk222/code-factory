from __future__ import annotations

import json
from pathlib import Path

from factoryline.architecture_health import (
    collect_architecture_health,
    evaluate_architecture_health,
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
        "release": {"max_releases_30d": 4},
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
