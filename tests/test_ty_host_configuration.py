"""Host overrides must remain visible to the real type-intent policy."""

import pytest

from factoryline import intent_quality


@pytest.fixture
def isolated_host(tmp_path, monkeypatch):
    for name in ("HOME", "USERPROFILE", "APPDATA", "XDG_CONFIG_HOME", "ProgramFiles"):
        directory = tmp_path / name.lower()
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
    return tmp_path


@pytest.mark.parametrize(
    "name",
    [
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
    ],
)
def test_git_environment_override_still_vetoes_type_credit(
    isolated_host, monkeypatch, name
):
    monkeypatch.setenv(name, "1")
    state, safe = intent_quality._ty_global_git_configuration(65536)
    assert safe is False
    assert state["state"] == "environment_override"


@pytest.mark.parametrize(
    "relative", ["userprofile/.gitconfig", "xdg_config_home/git/config"]
)
@pytest.mark.parametrize(
    "content", ["[include]\npath = external\n", "[core]\nexcludesFile = external\n"]
)
def test_host_git_file_still_vetoes_type_credit(isolated_host, relative, content):
    # Path.home uses USERPROFILE on Windows and HOME on POSIX.
    from pathlib import Path

    target = isolated_host / relative
    if relative == "userprofile/.gitconfig":
        target = Path.home() / ".gitconfig"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    state, safe = intent_quality._ty_global_git_configuration(65536)
    assert safe is False
    assert state["state"] in {"include", "global_ignore_configured"}


def test_host_ty_configuration_still_vetoes_type_credit(isolated_host):
    config = isolated_host / "appdata/ty/ty.toml"
    config.parent.mkdir()
    config.write_text("[src]\nexclude = ['tests']\n", encoding="utf-8")
    assert intent_quality._ty_external_config_state(isolated_host) == {
        "state": "unknown",
        "config_override": True,
    }
