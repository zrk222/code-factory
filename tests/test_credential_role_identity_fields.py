"""Caller-proved field identities propagate without erasing unsupported effects."""

import ast
import hashlib
from pathlib import Path
import pytest
from factoryline.credential_role_identity_effects import (
    ResolvedIdentityCall,
    summarize_identity_effect,
)
from factoryline.credential_role_constructor_provider import SourceSnapshotIndex
import textwrap


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


# --- Merged from test_credential_role_identity_defaults.py; test definitions and fixtures retained ---
"""Omitted source defaults never masquerade as explicit call-expression tokens."""


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


# --- Merged from test_credential_role_identity_effects.py; test definitions and fixtures retained ---
"""Focused tests for the bounded identity-effect source model."""


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
