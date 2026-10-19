"""Focused tests for the bounded identity-effect source model."""

import ast
import hashlib
from pathlib import Path
import textwrap

from factoryline.credential_role_identity_effects import (
    ResolvedIdentityCall,
    summarize_identity_effect,
)
from factoryline.credential_role_sources import SourceSnapshotIndex


def _index(source):
    path = Path("fixture.py")
    raw = textwrap.dedent(source).encode()
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
    index = SourceSnapshotIndex(
        Path("."), {path: tree}, {path: raw}, {path: hashlib.sha256(raw).hexdigest()}
    )
    return path, tree, index


def _function(tree, name):
    return next(
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name
    )


def _summarize(source, name, roots):
    path, tree, index = _index(source)
    return summarize_identity_effect(_function(tree, name), path, index, roots)


def test_detects_backend_method_and_initializer_class_replacement():
    source = """
        class Candidate: pass
        def morph(self): self.__class__ = Candidate
        def __init__(self): self.__class__ = Candidate
    """
    for name in ("morph", "__init__"):
        result = _summarize(source, name, {"self": "backend"})
        assert result.status == "CLASS_WRITE"
        assert result.class_writes == ("backend",)


def test_opaque_backend_argument_is_an_escape():
    result = _summarize(
        "def mutate(backend): opaque(backend)", "mutate", {"backend": "b"}
    )
    assert result.status == "ESCAPE"
    assert result.escapes == ("b",)


def test_literal_container_constant_index_preserves_class_write_detection():
    source = "def mutate(backend): saved = [backend]; saved[0].__class__ = Candidate"
    result = _summarize(source, "mutate", {"backend": "b"})
    assert result.status == "CLASS_WRITE"
    assert result.class_writes == ("b",)
    assert result.escapes == ("b",)


def test_heap_alias_followed_by_class_write_is_unknown_and_unsafe():
    source = "def mutate(self): self.alias = self; self.alias.__class__ = Candidate"
    result = _summarize(source, "mutate", {"self": "b"})
    assert result.status == "UNKNOWN"
    assert result.escapes == ("b",)


def test_exact_test_strategy_field_write_has_no_class_effect():
    source = """
        def set_request_data(self, values, backend):
            if values:
                self._request_data.update(values)
                backend.data = self._request_data
    """
    result = _summarize(source, "set_request_data", {"backend": "b"})
    assert result.status == "NO_CLASS_EFFECT"
    assert result.field_writes == ("b.data",)


def test_returned_root_and_heap_field_capture_are_escapes():
    returned = _summarize("def f(backend): return backend", "f", {"backend": "b"})
    captured = _summarize("def f(self): self.saved = self", "f", {"self": "b"})
    unknown_read = _summarize("def f(self): return self.saved", "f", {"self": "b"})
    assert returned.status == captured.status == "ESCAPE"
    assert unknown_read.status == "UNKNOWN"


def test_exact_source_callback_recurses_with_explicit_parameter_mapping():
    path, tree, index = _index("""
        def caller(backend): helper(backend)
        def helper(target): target.__class__ = Candidate
    """)

    def resolve(call, call_path):
        if (
            call_path == path
            and isinstance(call.func, ast.Name)
            and call.func.id == "helper"
        ):
            return ResolvedIdentityCall(
                _function(tree, "helper"), path, {"target": call.args[0]}
            )
        return None

    result = summarize_identity_effect(
        _function(tree, "caller"), path, index, {"backend": "b"}, resolve_call=resolve
    )
    assert result.status == "CLASS_WRITE"
    assert result.class_writes == ("b",)


def test_recursive_call_cycle_fails_closed():
    path, tree, index = _index("def mutate(backend): recurse(backend)")
    function = _function(tree, "mutate")

    def resolve(call, _path):
        return ResolvedIdentityCall(function, path, {"backend": call.args[0]})

    result = summarize_identity_effect(
        function, path, index, {"backend": "b"}, resolve_call=resolve
    )
    assert result.status == "UNKNOWN"
    assert "call depth or cycle limit" in result.unknowns


def test_exact_callback_cannot_omit_a_tracked_argument():
    path, tree, index = _index(
        "def caller(backend): helper(backend)\ndef helper(target): pass"
    )

    def resolve(call, _path):
        return ResolvedIdentityCall(_function(tree, "helper"), path, {})

    result = summarize_identity_effect(
        _function(tree, "caller"), path, index, {"backend": "b"}, resolve_call=resolve
    )
    assert result.status == "UNKNOWN"
    assert "exact call mapping must cover each actual once" in result.unknowns


def test_exact_callback_cannot_drop_duplicate_root_actual():
    path, tree, index = _index(
        "def caller(backend): helper(backend, backend)\n"
        "def helper(first, second): first.__class__ = Candidate"
    )

    def resolve(call, _path):
        return ResolvedIdentityCall(
            _function(tree, "helper"), path, {"first": call.args[0]}
        )

    result = summarize_identity_effect(
        _function(tree, "caller"), path, index, {"backend": "b"}, resolve_call=resolve
    )
    assert result.status == "UNKNOWN"
    assert "exact call mapping must cover each actual once" in result.unknowns


def test_call_through_unresolved_field_value_is_unknown():
    result = _summarize(
        "def caller(backend): opaque(backend.data)", "caller", {"backend": "b"}
    )
    assert result.status == "UNKNOWN"
    assert "call receives an unresolved tracked value" in result.unknowns


def test_dict_dynamic_key_containing_root_is_an_escape():
    result = _summarize(
        "def f(backend, key): saved = {key: backend}",
        "f",
        {"backend": "b"},
    )
    assert result.status == "UNKNOWN"
    assert result.escapes == ("b",)
    assert "alias receives unresolved tracked expression" in result.unknowns


def test_dynamic_instance_class_constructor_is_unknown():
    result = _summarize(
        "def f(backend): return backend.__class__()", "f", {"backend": "b"}
    )
    assert result.status == "UNKNOWN"


def test_ast_state_budget_exhaustion_is_unknown():
    path, tree, index = _index("def f(backend):\n    value = backend\n    return value")
    result = summarize_identity_effect(
        _function(tree, "f"), path, index, {"backend": "b"}, state_budget=1
    )
    assert result.status == "UNKNOWN"
    assert "AST state budget exceeded" in result.unknowns


def test_unsupported_conditional_alias_is_unknown():
    result = _summarize(
        "def f(backend, other, choose): alias = backend if choose else other",
        "f",
        {"backend": "b"},
    )
    assert result.status == "UNKNOWN"
    assert "alias receives unresolved tracked expression" in result.unknowns


def test_tracked_root_stored_on_foreign_heap_object_escapes():
    result = _summarize(
        "def f(backend, holder): holder.saved = backend", "f", {"backend": "b"}
    )
    assert result.status == "ESCAPE"
    assert result.escapes == ("b",)


def test_multi_target_assignment_of_tracked_root_is_unknown():
    result = _summarize(
        "def f(backend): first = second = backend", "f", {"backend": "b"}
    )
    assert result.status == "UNKNOWN"
    assert "multi-target tracked assignment" in result.unknowns


def test_implicit_special_method_dispatch_on_root_is_unknown():
    sources = (
        "def f(backend):\n    for item in backend: pass",
        "def f(backend):\n    with backend: pass",
        "def f(backend):\n    if backend == None: pass",
    )
    for source in sources:
        result = _summarize(source, "f", {"backend": "b"})
        assert result.status == "UNKNOWN"
        assert "implicit special-method dispatch on tracked root" in result.unknowns


def test_bare_tracked_attribute_read_is_unknown_for_descriptor_effects():
    result = _summarize("def f(self): self.trigger", "f", {"self": "b"})
    assert result.status == "UNKNOWN"
    assert "bare tracked attribute read may invoke a descriptor" in result.unknowns


def test_super_calls_and_reflection_are_unknown_for_tracked_receiver():
    sources = (
        ("def __init__(self): super().__init__()", "__init__"),
        ("def f(self): alias = super", "f"),
    )
    for source, name in sources:
        result = _summarize(source, name, {"self": "b"})
        assert result.status == "UNKNOWN"
        assert "super uses implicit or reflective receiver" in result.unknowns
