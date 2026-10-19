"""Omitted source defaults never masquerade as explicit call-expression tokens."""

import ast
import hashlib
from pathlib import Path

import pytest

from factoryline.credential_role_identity_effects import (
    ResolvedIdentityCall,
    summarize_identity_effect,
)
from factoryline.credential_role_sources import SourceSnapshotIndex


def _run(signature, body, actual="backend"):
    raw = (
        f"def inspect(backend):\n    def helper({signature}):\n"
        + "".join("        " + row + "\n" for row in body.splitlines())
        + f"    helper({actual})\n"
    ).encode()
    tree, path = ast.parse(raw), Path("fixture.py")
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(Path("."), {path: tree}, {path: raw}, {path: digest})
    outer, helper = tree.body[0], tree.body[0].body[0]
    before = ast.dump(tree, include_attributes=True)

    def resolve(call, path):
        names = [arg.arg for arg in [*helper.args.posonlyargs, *helper.args.args]]
        mapping = dict(zip(names, call.args))
        mapping.update((row.arg, row.value) for row in call.keywords)
        assert all(
            value is arg
            for value, arg in zip(list(mapping.values())[: len(call.args)], call.args)
        )
        return ResolvedIdentityCall(helper, path, mapping)

    result = summarize_identity_effect(
        outer,
        path,
        index,
        {"backend": "backend"},
        strict_calls=True,
        resolve_call=resolve,
    )
    assert ast.dump(tree, include_attributes=True) == before
    return result


@pytest.mark.parametrize(
    "signature",
    [
        "target, mode=None",
        "target, *, mode=None",
        "target, mode=False",
        "target, mode=(1, 'two', (None, True))",
        "target, /, mode=None",
    ],
)
def test_immutable_defaults_seed_separate_callee_values(signature):
    result = _run(signature, "if mode is None: target.data = None")
    assert result.status == "NO_CLASS_EFFECT"
    assert result.field_writes == ("backend.data",)


def test_explicit_root_actual_never_falls_back_to_literal_default():
    result = _run("target, mode=None", "mode.__class__ = Evil", "backend, mode=backend")
    assert result.class_writes == ("backend",)


def test_explicit_unknown_actual_never_falls_back_to_literal_default():
    assert (
        _run(
            "target, mode=None", "if mode: target.data = None", "backend, mode=opaque"
        ).status
        == "UNKNOWN"
    )


@pytest.mark.parametrize(
    "default", ["[]", "{}", "set()", "opaque", "('one', [])", "-1", "tuple()"]
)
def test_mutable_or_dynamic_default_is_unknown_even_when_unused(default):
    assert _run(f"target, mode={default}", "target.data = None").status == "UNKNOWN"


def test_required_keyword_only_parameter_is_not_a_none_default():
    assert _run("target, *, mode", "target.data = None").status == "UNKNOWN"
