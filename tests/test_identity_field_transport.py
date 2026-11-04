"""The shared field channel preserves value evidence and uncertainty."""

from hashlib import sha256
from pathlib import Path

import pytest

from factoryline.credential_role_identity_effects import (
    _Value,
    summarize_identity_effect,
)
from factoryline.semantic_credential_sensor import signing_configuration_inventory


@pytest.mark.parametrize("expression", ["self.command", '"{}".format(self.command)'])
def test_typed_field_return_preserves_origin_kind_and_trace(expression):
    raw = {"module.py": f"def run(self):\n    return {expression}\n".encode()}
    context = signing_configuration_inventory(
        raw, {name: sha256(value).hexdigest() for name, value in raw.items()}
    )
    index, path = context["index"], Path("module.py")
    origin = ("ORIGIN", (1, 0, 1, 1), "a" * 64)
    value = _Value(
        roots=frozenset({"captured-input"}),
        inert_kind="scalar",
        scalar_kind="text",
        trace=(origin,),
    )
    summary = summarize_identity_effect(
        index.snapshots[path].body[0],
        path,
        index,
        {"self": "receiver"},
        field_roots={("receiver", "command"): value},
        ordinary_fields=("command",),
        role_view=True,
    )
    assert summary.return_status == "COMPLETE"
    projected = summary.return_values[0].value
    assert projected.roots == value.roots
    assert projected.inert_kind == "scalar" and projected.scalar_kind == "text"
    assert origin in projected.trace
    assert not projected.unknown and not projected.content_unknown
    # Transporting value evidence does not remove the independent effect gate.
    assert summary.status != "NO_CLASS_EFFECT"


@pytest.mark.parametrize("uncertainty", ["unknown", "content_unknown"])
def test_typed_field_transport_never_clears_uncertainty(uncertainty):
    raw = {"module.py": b"def run(self):\n    return self.command\n"}
    context = signing_configuration_inventory(
        raw, {name: sha256(value).hexdigest() for name, value in raw.items()}
    )
    index, path = context["index"], Path("module.py")
    value = _Value(roots=frozenset({"captured-input"}), **{uncertainty: True})
    summary = summarize_identity_effect(
        index.snapshots[path].body[0],
        path,
        index,
        {"self": "receiver"},
        field_roots={("receiver", "command"): value},
        ordinary_fields=("command",),
        role_view=True,
    )
    assert summary.status != "NO_CLASS_EFFECT"
    assert any(event.uncertain for event in summary.role_events)
    assert getattr(summary.return_values[0].value, uncertainty)


def test_typed_field_overwrite_removes_old_origin():
    raw = {
        "module.py": b"def run(self):\n    self.command = 'safe'\n    return self.command\n"
    }
    context = signing_configuration_inventory(
        raw, {name: sha256(value).hexdigest() for name, value in raw.items()}
    )
    index, path = context["index"], Path("module.py")
    value = _Value(
        roots=frozenset({"captured-input"}), inert_kind="scalar", scalar_kind="text"
    )
    summary = summarize_identity_effect(
        index.snapshots[path].body[0],
        path,
        index,
        {"self": "receiver"},
        field_roots={("receiver", "command"): value},
        ordinary_fields=("command",),
        role_view=True,
    )
    assert "captured-input" not in summary.return_values[0].value.roots
    assert summary.field_writes


@pytest.mark.parametrize("typed_scalar", [False, True])
def test_field_transport_does_not_exempt_opaque_consumer_effects(typed_scalar):
    raw = {"module.py": b"def run(self):\n    opaque(self.command)\n"}
    context = signing_configuration_inventory(
        raw, {name: sha256(value).hexdigest() for name, value in raw.items()}
    )
    index, path = context["index"], Path("module.py")
    value = _Value(
        roots=frozenset({"selected"}),
        inert_kind="scalar" if typed_scalar else None,
        scalar_kind="text" if typed_scalar else None,
    )
    summary = summarize_identity_effect(
        index.snapshots[path].body[0],
        path,
        index,
        {"self": "receiver"},
        field_roots={("receiver", "command"): value},
        ordinary_fields=("command",),
        role_view=True,
    )
    assert summary.status != "NO_CLASS_EFFECT"
    assert summary.escapes or summary.unknowns


@pytest.mark.parametrize(
    "changes",
    [
        {"unknown": True},
        {"content_unknown": True},
        {"inert_kind": None},
        {"class_roots": frozenset({"class-capability"})},
        {"items": (("nested", _Value(roots=frozenset({"nested-origin"}))),)},
    ],
)
def test_scalar_flow_bridge_rejects_uncertainty_and_nonscalar_capabilities(changes):
    import ast
    from dataclasses import replace

    from factoryline.finite_capture import security_structural_value

    origin = ("REQUEST_SOURCE", (1, 0, 1, 5), "a" * 64)
    value = _Value(
        roots=frozenset({"source-origin"}),
        inert_kind="scalar",
        scalar_kind="text",
        trace=(origin,),
    )
    result = security_structural_value(
        ast.parse('"prefix" + item', mode="eval").body,
        {"item": replace(value, **changes)},
    )
    assert result.unknown or result.content_unknown


def test_generator_capture_keeps_lazy_uses_and_eager_input_separate():
    import ast

    from factoryline.credential_role_identity_effects import own_function_nodes

    raw = {
        "module.py": b"def run(self):\n    pending = (consume(self) for item in source(self) if guard(self))\n"
    }
    context = signing_configuration_inventory(
        raw, {name: sha256(value).hexdigest() for name, value in raw.items()}
    )
    index, path = context["index"], Path("module.py")
    function = index.snapshots[path].body[0]
    calls = {
        node.func.id
        for node in own_function_nodes(function, path, index)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert calls == {"source"}
    summary = summarize_identity_effect(
        function, path, index, {"self": "receiver"}, strict_calls=True, role_view=True
    )
    assert summary.status == "UNKNOWN"
    assert any(event.kind == "nested_capture" for event in summary.role_events)


@pytest.mark.parametrize("iterable", ["None", "True", "1", "1.0", "1j", "..."])
def test_invalid_generator_construction_cannot_prove_receiver_effects(iterable):
    raw = {
        "module.py": (
            "def run(self):\n"
            f"    pending = (item for item in {iterable})\n"
            "    return self\n"
        ).encode()
    }
    context = signing_configuration_inventory(
        raw, {name: sha256(value).hexdigest() for name, value in raw.items()}
    )
    index, path = context["index"], Path("module.py")
    summary = summarize_identity_effect(
        index.snapshots[path].body[0],
        path,
        index,
        {"self": "receiver"},
        strict_calls=True,
        role_view=True,
    )
    assert summary.status == "UNKNOWN"
    assert "unmodeled nested definition-time effects" in summary.unknowns
    with pytest.raises(TypeError):
        eval(f"(item for item in {iterable})")


@pytest.mark.parametrize(
    ("expression", "unknown"),
    [
        ("(item for item in ())", False),
        ("(item for item in (1, (2,)))", False),
        ('(item for item in "text")', False),
        ('(item for item in b"text")', False),
        ('(item for item in b"x" * 2)', False),
        ("(item async for item in ())", True),
        ("(item for item in source())", True),
        ("(item for item in unknown)", True),
    ],
)
def test_generator_construction_requires_proven_builtin_iterable(expression, unknown):
    import ast
    from factoryline.credential_role_identity_effects import _definition_effects_unknown

    assert (
        _definition_effects_unknown(ast.parse(expression, mode="eval").body) is unknown
    )
