"""Reject invented default adapter transfers in the finite source model."""

import ast

import pytest

from factoryline.credential_role_adapter_selection import _property_default
from factoryline.credential_role_setting_boundary import _setting_getter_shape


@pytest.mark.parametrize(
    "fallback",
    [
        "lambda name, dflt: supplied",
        "lambda name, dflt: getattr(settings, name, 'other')",
        "lambda name, dflt: getattr(settings, 'OTHER', dflt)",
    ],
)
def test_setting_fallback_must_preserve_default(tmp_path, fallback):
    tree = ast.parse(
        "def get_setting(name, dflt):\n"
        f"    getter = getattr(settings, 'ALLAUTH_SETTING_GETTER', {fallback})\n"
        "    getter = import_callable(getter)\n"
        "    return getter(name, dflt)\n"
    )
    assert _setting_getter_shape({tmp_path / "utils.py": tree}) is None


def test_decorated_getter_cannot_prove_default(tmp_path):
    tree = ast.parse(
        "@replacement\n"
        "def get_setting(name, dflt):\n"
        "    getter = getattr(settings, 'ALLAUTH_SETTING_GETTER', "
        "lambda name, dflt: getattr(settings, name, dflt))\n"
        "    getter = import_callable(getter)\n"
        "    return getter(name, dflt)\n"
    )
    assert _setting_getter_shape({tmp_path / "utils.py": tree}) is None


@pytest.mark.parametrize(
    "prefix",
    [
        "self = supplied",
        "self._setting = supplied",
        "mutate(self)",
    ],
)
def test_property_cannot_mutate_its_receiver_before_default(prefix):
    owner = ast.parse(
        "class Settings:\n"
        "    @property\n"
        "    def ADAPTER(self):\n"
        f"        {prefix}\n"
        "        return self._setting('ADAPTER', 'module.Adapter')\n"
    ).body[0]
    assert _property_default(owner) is None
