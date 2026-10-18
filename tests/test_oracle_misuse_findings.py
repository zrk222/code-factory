from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from factoryline.review_audits import security_scan


@pytest.mark.parametrize(
    ("assertion", "reason"),
    [
        (
            "assert (compute(), expected)",
            "nonempty container assertion is always truthy",
        ),
        (
            "assert {'actual': compute()}",
            "nonempty mapping assertion is always truthy",
        ),
        (
            "assert True",
            "literal assertion is statically truthy",
        ),
        (
            "assert 2 == 1 + 1",
            "literal assertion is statically truthy",
        ),
    ],
)
def test_security_scan_reports_statically_truthy_assertions(
    tmp_path, assertion, reason
):
    (tmp_path / "test_vacuous.py").write_text(
        f"def compute(): return 1\ndef test_behavior():\n    {assertion}\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    findings = [
        item
        for item in report["findings"]
        if item["code"] == "QUALITY_WEAK_TEST_ORACLE"
    ]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "MEDIUM"
    assert reason in finding["message"]
    assert finding["facts"]["whole_test_oracle"] == "UNASSESSED"
    assert finding["facts"]["execution_state"] == "NOT_ESTABLISHED"


def test_specific_local_defect_survives_an_independent_strong_assertion(tmp_path):
    (tmp_path / "test_mixed.py").write_text(
        "def compute(): return 1\n"
        "def test_mixed():\n"
        "    assert compute() == 1\n"
        "    assert (compute(), 1)\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    findings = [
        item
        for item in report["findings"]
        if item["code"] == "QUALITY_WEAK_TEST_ORACLE"
    ]
    assert len(findings) == 1
    assert "nonempty container assertion" in findings[0]["message"]


def test_security_scan_reports_discarded_comparison_as_local_oracle_defect(tmp_path):
    (tmp_path / "test_style.py").write_text(
        "def get_style(): return 'plain'\n"
        "def test_style():\n    get_style() == 'minimal'\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    findings = [
        item
        for item in report["findings"]
        if item["code"] == "QUALITY_WEAK_TEST_ORACLE"
    ]
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert "comparison result is discarded" in findings[0]["message"]
    assert findings[0]["facts"]["whole_test_oracle"] == "UNASSESSED"


def test_comparison_result_consumed_with_side_effect_is_not_discarded(tmp_path):
    (tmp_path / "test_effect.py").write_text(
        "seen = []\n"
        "def inspect():\n    seen.append('called')\n    return 1\n"
        "def test_effect():\n"
        "    seen.append(inspect() == 1)\n"
        "    assert seen == ['called', True]\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert "QUALITY_WEAK_TEST_ORACLE" not in report["finding_counts"]


def test_real_stacked_click_callback_remains_actionable(tmp_path):
    cases = json.loads(
        (Path(__file__).parent / "fixtures/external_oracle_cases.json").read_text()
    )
    source = next(
        item["source"]
        for item in cases
        if item["id"] == "click-test_open_file_pathlib_dash"
    )
    (tmp_path / "test_cli.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    findings = [
        item
        for item in report["findings"]
        if item["code"] == "QUALITY_WEAK_TEST_ORACLE"
    ]
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert "never invoked or referenced" in findings[0]["message"]
    assert findings[0]["facts"]["whole_test_oracle"] == "UNASSESSED"


def test_global_callback_binding_is_not_proven_uninvoked(tmp_path):
    (tmp_path / "test_cli.py").write_text(
        "import click\ncli = None\n"
        "def test_cli():\n    global cli\n"
        "    @click.command()\n    def cli():\n        assert compute() == 7\n"
        "    globals().get('cli')\n"
        "def teardown_function():\n    cli.main([], standalone_mode=False)\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert "QUALITY_WEAK_TEST_ORACLE" not in report["finding_counts"]


def test_ordinary_compute_smoke_remains_unknown_info(tmp_path):
    (tmp_path / "test_smoke.py").write_text(
        "def compute(): return 4\ndef test_smoke(): compute()\n", encoding="utf-8"
    )
    report = security_scan(tmp_path, cache_enabled=False)
    unknown = [
        item
        for item in report["findings"]
        if item["code"] == "QUALITY_UNKNOWN_TEST_ORACLE"
    ]
    assert len(unknown) == 1
    assert unknown[0]["severity"] == "INFO"
    assert "QUALITY_WEAK_TEST_ORACLE" not in report["finding_counts"]


def test_meaningful_click_callback_is_not_downgraded(tmp_path):
    (tmp_path / "test_cli.py").write_text(
        textwrap.dedent(
            """\
            import click
            from click.testing import CliRunner

            def test_cli_callback():
                @click.command()
                def cli():
                    value = int("7")
                    assert value == 7

                runner = CliRunner()
                runner.invoke(cli, [], catch_exceptions=False)
            """
        ),
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert "QUALITY_WEAK_TEST_ORACLE" not in report["finding_counts"]
    assert "QUALITY_UNKNOWN_TEST_ORACLE" not in report["finding_counts"]


def test_shadowed_type_providers_are_not_treated_as_universal_builtin(tmp_path):
    (tmp_path / "test_provider.py").write_text(
        "def isinstance(value, expected): return value == expected\n"
        "def object(): return 'ok'\n"
        "def test_provider(): assert isinstance(object(), str)\n",
        encoding="utf-8",
    )
    report = security_scan(tmp_path, cache_enabled=False)
    assert "QUALITY_WEAK_TEST_ORACLE" not in report["finding_counts"]
