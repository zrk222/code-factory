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
