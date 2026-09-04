from pathlib import Path


def test_ci_runs_native_python_matrix_on_all_supported_host_families() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "os: [ubuntu-latest, windows-latest, macos-latest]" in workflow
    assert "matrix.os" in workflow
