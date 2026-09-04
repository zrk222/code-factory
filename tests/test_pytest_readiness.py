from pathlib import Path

from factoryline.pytest_readiness import collect_pytest_readiness


def test_setup_phase_skip_cannot_satisfy_readiness(tmp_path: Path) -> None:
    suite = tmp_path / "test_sabotage.py"
    suite.write_text(
        "import pytest\n"
        "def test_pass(): assert True\n"
        "@pytest.mark.skip(reason='sabotage')\n"
        "def test_setup_skip(): assert True\n",
        encoding="utf-8",
    )
    result = collect_pytest_readiness([str(suite)])
    assert result == {"exit_code": 0, "passed": 1, "skipped": 1, "xfailed": 0}
    assert (result["passed"], result["skipped"], result["xfailed"]) != (1, 0, 0)
