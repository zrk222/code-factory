from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def isolated_ty_host_configuration(request, monkeypatch, tmp_path_factory):
    """Type-intent fixtures declare their own checker and Git configuration."""
    if request.path.name != "test_review_audits.py" or not (
        request.node.originalname or ""
    ).startswith("test_ty_"):
        return
    host = tmp_path_factory.mktemp("ty-host")
    for name in ("HOME", "USERPROFILE", "APPDATA", "XDG_CONFIG_HOME", "ProgramFiles"):
        directory = host / name.lower()
        directory.mkdir()
        monkeypatch.setenv(name, str(directory))
    for name in (
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
        "TY_CONFIG_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
