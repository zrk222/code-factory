"""Caller-proved field identities propagate without erasing unsupported effects."""

import ast
import hashlib
from pathlib import Path

import pytest

from factoryline.credential_role_identity_effects import (
    ResolvedIdentityCall,
    summarize_identity_effect,
)
from factoryline.credential_role_sources import SourceSnapshotIndex


def _summary(source, fields, *, resolve=False):
    path, raw = Path("fixture.py"), source.encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(Path("."), {path: tree}, {path: raw}, {path: digest})
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef))

    def resolver(call, path):
        helper = next(
            node for node in function.body if isinstance(node, ast.FunctionDef)
        )
        return ResolvedIdentityCall(helper, path, {"value": call.args[0]})

    return summarize_identity_effect(
        function,
        path,
        index,
        {"fixture": "fixture"},
        field_roots=fields,
        resolve_call=resolver if resolve else None,
    )


FIELDS = {("fixture", "backend"): "backend"}


@pytest.mark.parametrize(
    "body,status,roots",
    [
        ("fixture.backend.__class__ = Candidate", "CLASS_WRITE", ("backend",)),
        ("fixture.backend.data = None", "NO_CLASS_EFFECT", ()),
        ("return fixture.backend", "ESCAPE", ("backend",)),
        ("opaque(fixture.backend)", "ESCAPE", ("backend",)),
        ("fixture.backend.opaque()", "UNKNOWN", ()),
        (
            "saved = fixture.backend\nsaved.__class__ = Candidate",
            "CLASS_WRITE",
            ("backend",),
        ),
        ("fixture.backend = Other()\nfixture.backend.data = None", "UNKNOWN", ()),
        ("del fixture.backend", "UNKNOWN", ()),
        ("if fixture.backend: pass", "UNKNOWN", ()),
        ("def later(): return fixture.backend\nreturn later", "ESCAPE", ("fixture",)),
    ],
)
def test_projected_identity_effects(body, status, roots):
    source = "def inspect(fixture):\n" + "".join(
        "    " + line + "\n" for line in body.splitlines()
    )
    result = _summary(source, FIELDS)
    assert result.status == status
    if status == "CLASS_WRITE":
        assert result.class_writes == roots
    elif status == "ESCAPE":
        assert result.escapes == roots


def test_recursive_field_identity_keeps_backend_and_strategy_distinct():
    fields = {**FIELDS, ("backend", "strategy"): "strategy"}
    result = _summary(
        "def inspect(fixture): fixture.backend.strategy.__class__ = Evil\n", fields
    )
    assert result.class_writes == ("strategy",)


def test_exact_helper_receives_projected_backend_root():
    source = "def inspect(fixture):\n    def helper(value): value.__class__ = Evil\n    helper(fixture.backend)\n"
    result = _summary(source, FIELDS, resolve=True)
    assert result.class_writes == ("backend",)


def test_missing_projection_stays_unknown():
    assert (
        _summary("def inspect(fixture): fixture.backend.data = None\n", {}).status
        == "UNKNOWN"
    )


@pytest.mark.parametrize(
    "fields",
    [
        [],
        {("a",): "b"},
        {("a", "__class__"): "b"},
        {("a", "field"): 3},
        {(str(n), "field"): "b" for n in range(65)},
    ],
)
def test_invalid_or_unbounded_graph_is_unknown(fields):
    result = _summary("def inspect(fixture): pass\n", fields)
    assert result.status == "UNKNOWN"


def test_field_graph_is_not_inferred_from_annotation():
    result = _summary(
        "def inspect(fixture):\n    fixture.backend: Backend\n    fixture.backend.data = None\n",
        {},
    )
    assert result.status == "UNKNOWN"
