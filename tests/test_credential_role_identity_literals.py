"""Strict call summaries retain literal data shapes and reject opaque behavior."""

import ast
import hashlib
from pathlib import Path

import pytest

from factoryline.credential_role_identity_effect_types import (
    ResolvedIdentityCall,
    SourceFieldLiteral,
)
from factoryline.credential_role_identity_effects import summarize_identity_effect
from factoryline.credential_role_sources import SourceSnapshotIndex


def _run(body, *, field=False, forged=False):
    source = "initial = {}\ndef inspect(backend, strategy, opaque):\n" + "".join(
        "    " + row + "\n" for row in body.splitlines()
    )
    raw, path = source.encode(), Path("fixture.py")
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(Path("."), {path: tree}, {path: raw}, {path: digest})
    function = tree.body[1]
    literal = ast.Dict(keys=[], values=[]) if forged else tree.body[0].value
    fields = (
        {("strategy", "data"): SourceFieldLiteral(path, literal)} if field else None
    )

    def resolve(call, path):
        if not isinstance(call.func, ast.Name) or call.func.id != "helper":
            return None
        helper = next(
            node for node in function.body if isinstance(node, ast.FunctionDef)
        )
        return ResolvedIdentityCall(
            helper, path, dict(zip((arg.arg for arg in helper.args.args), call.args))
        )

    return summarize_identity_effect(
        function,
        path,
        index,
        {"backend": "backend", "strategy": "strategy"},
        field_roots=fields,
        strict_calls=True,
        resolve_call=resolve,
    )


@pytest.mark.parametrize(
    "body,field",
    [
        ("data = {}\ndata.update({'code': 'known'})\nbackend.data = data", False),
        ("strategy.data.update({'code': 'known'})\nbackend.data = strategy.data", True),
        (
            "def helper(data, values, target):\n    data.update(values)\n    target.data = data\nhelper(strategy.data, {'code': 'known'}, backend)",
            True,
        ),
        (
            "data = {}\ndata.update({'items': [1, 'two', None]})\nbackend.data = data",
            False,
        ),
    ],
)
def test_exact_literal_dictionary_leaf_and_forwarded_values(body, field):
    result = _run(body, field=field)
    assert result.status == "NO_CLASS_EFFECT"
    assert result.field_writes == ("backend.data",)


@pytest.mark.parametrize(
    "body,field",
    [
        ("data = {}\ndata.update(opaque)\nbackend.data = data", False),
        ("strategy.data.update({'token': backend})", True),
        ("strategy.data.update({'code': opaque})", True),
        ("strategy.data.update(**opaque)", True),
        ("strategy.data = opaque\nstrategy.data.update({'code': 'known'})", True),
        ("data = {}\ndata[opaque] = 'value'\ndata.update({'code': 'known'})", False),
        ("data = {}\ndata.update({'code': 'known'})\nopaque(data)", False),
        ("data = {}\ndata.update({'code': opaque()})", False),
        (
            "def helper(data, values): data.update(values)\nhelper(strategy.data, opaque)",
            True,
        ),
        ("globals()['backend'] = backend", False),
        ("result = opaque.property", False),
        ("result = opaque + 1", False),
        ("if opaque: backend.data = None", False),
        ("data = {}\ndata |= backend\nbackend.data = data", False),
    ],
)
def test_opaque_mapping_escapes_and_implicit_behavior_remain_unproved(body, field):
    assert _run(body, field=field).status != "NO_CLASS_EFFECT"


def test_uncaptured_literal_cannot_prove_heap_shape():
    assert (
        _run("strategy.data.update({'code': 'known'})", field=True, forged=True).status
        == "UNKNOWN"
    )
