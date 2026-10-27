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


def _summary(source, fields, *, resolve=False, role_view=False):
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
        role_view=role_view,
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


def test_role_events_follow_source_stores_aliases_and_literal_containers():
    path, tree, index = _index("""
        def inspect(self, key, logger):
            self.secret = key
            self.logger = logger
            self.carrier = {"owner": self, "key": self.secret}
            stored_logger = self.logger
            stored_key = self.carrier["key"]
            stored_owner = self.carrier["owner"]
            return stored_key
    """)
    result = summarize_identity_effect(
        _function(tree, "inspect"),
        path,
        index,
        {"self": "owner", "key": "candidate", "logger": "logger"},
        role_view=True,
    )
    stores = {
        (event.relevant, event.receiver_roots, event.roots)
        for event in result.role_events
        if event.kind == "field_store"
    }
    assert ("secret", ("owner",), ("candidate",)) in stores
    assert ("logger", ("owner",), ("logger",)) in stores
    assert ("carrier", ("owner",), ("candidate", "owner")) in stores
    reads = {
        (event.relevant, event.receiver_roots, event.roots)
        for event in result.role_events
        if event.kind == "field_read"
    }
    assert ("secret", ("owner",), ("candidate",)) in reads
    assert ("logger", ("owner",), ("logger",)) in reads
    assert ("carrier", ("owner",), ("candidate", "owner")) in reads
    assert any(
        event.kind == "return_escape" and event.roots == ("candidate",)
        for event in result.role_events
    )
    assert result.escapes == ("candidate", "logger", "owner")


def test_field_name_does_not_override_the_source_value_role():
    path, tree, index = _index("""
        def inspect(self, other):
            self.secret = other
            return self.secret
    """)
    result = summarize_identity_effect(
        _function(tree, "inspect"),
        path,
        index,
        {"self": "owner", "other": "ordinary"},
        role_view=True,
    )
    read = next(event for event in result.role_events if event.kind == "field_read")
    assert read.relevant == "secret"
    assert read.roots == ("ordinary",)
    assert read.receiver_roots == ("owner",)
    assert any(
        event.kind == "return_escape" and event.roots == ("ordinary",)
        for event in result.role_events
    )


def test_branch_and_overwrite_field_projections_keep_all_roots_unknown():
    branch = _summarize(
        """
        def inspect(self, key, choose):
            if choose:
                self.value = key
            else:
                self.value = self
            return self.value
    """,
        "inspect",
        {"self": "owner", "key": "candidate"},
        role_view=True,
    )
    assert branch.status == "UNKNOWN"
    branch_read = next(
        event
        for event in branch.role_events
        if event.kind == "field_read" and event.relevant == "value"
    )
    assert branch_read.roots == ("candidate", "owner")
    assert branch_read.uncertain
    assert set(branch.escapes) == {"candidate", "owner"}

    overwritten = _summarize(
        """
        def inspect(self, key):
            self.value = key
            self.value = "ordinary"
            return self.value
    """,
        "inspect",
        {"self": "owner", "key": "candidate"},
        role_view=True,
    )
    assert overwritten.status == "UNKNOWN"
    assert any(
        event.kind == "field_store" and event.roots == ("candidate",)
        for event in overwritten.role_events
    )
    assert any(
        event.kind == "field_read" and event.roots == ("candidate",) and event.uncertain
        for event in overwritten.role_events
    )
    assert "projected field identity overwritten" in overwritten.unknowns


def test_unknown_property_and_bound_method_keep_owner_attribution():
    path, tree, index = _index("""
        def inspect(self):
            callback = self.dispatch
            return self.plugin
    """)
    result = summarize_identity_effect(
        _function(tree, "inspect"),
        path,
        index,
        {"self": "owner"},
        role_view=True,
    )
    assert result.status == "UNKNOWN"
    assert any(
        event.kind == "bound_method_or_unknown_property"
        and event.roots == ("owner",)
        and event.relevant == "dispatch"
        for event in result.role_events
    )
    assert any(
        event.kind == "unknown_property_read"
        and event.roots == ("owner",)
        and event.relevant == "plugin"
        for event in result.role_events
    )
    assert any(
        event.kind == "return_escape" and event.roots == ("owner",)
        for event in result.role_events
    )


def test_legacy_summary_keeps_default_aggregate_and_role_view_is_opt_in():
    source = "def inspect(self, key): self.value = key; return self.value"
    legacy = _summarize(source, "inspect", {"self": "owner", "key": "candidate"})
    roles = _summarize(
        source, "inspect", {"self": "owner", "key": "candidate"}, role_view=True
    )
    assert legacy.role_events == ()
    assert legacy.status == "UNKNOWN"
    assert roles.role_events
    assert roles.status == "UNKNOWN"
    assert legacy.escapes == ("candidate",)
    assert roles.escapes == ("candidate",)


def test_property_and_dynamic_attribute_hooks_remain_unknown_in_role_view():
    path, tree, index = _index("""
        class Owner:
            @property
            def secret(self):
                return self

            def inspect(self, key):
                self.secret = key
                return self.secret
    """)
    result = summarize_identity_effect(
        _function(tree, "inspect"),
        path,
        index,
        {"self": "owner", "key": "candidate"},
        role_view=True,
    )
    assert result.status == "UNKNOWN"
    assert any(
        event.kind == "attribute_dispatch_unknown"
        and event.relevant == "secret"
        and event.uncertain
        for event in result.role_events
    )


def test_unresolved_calls_with_or_without_tracked_actuals_remain_unknown():
    path, tree, index = _index("""
        def inspect(self, logger):
            logger.info("message")
            unrelated()
    """)
    result = summarize_identity_effect(
        _function(tree, "inspect"),
        path,
        index,
        {"self": "owner", "logger": "logger"},
        role_view=True,
    )
    assert result.status == "UNKNOWN"
    assert any(
        event.kind == "unresolved_method_call" and event.roots == ("logger",)
        for event in result.role_events
    )
    assert any(
        event.kind == "unresolved_ambient_call"
        and event.uncertain
        and event.relevant == "ambient"
        for event in result.role_events
    )
    assert "unresolved ambient call may reach tracked identity" in result.unknowns


def test_local_container_is_a_carrier_until_export_and_mutation_stays_unknown():
    source = """
        def inspect(key):
            headers = {"signature": [key]}
            alias = headers["signature"]
            return 0
    """
    local = _summarize(source, "inspect", {"key": "candidate"}, role_view=True)
    assert local.status == "NO_CLASS_EFFECT"
    assert any(
        event.kind == "local_container" and event.roots == ("candidate",)
        for event in local.role_events
    )
    assert not any(
        event.kind in {"return_escape", "opaque_call_escape", "unresolved_method_call"}
        for event in local.role_events
    )

    returned = _summarize(
        "def inspect(key): headers = {'signature': [key]}; return headers",
        "inspect",
        {"key": "candidate"},
        role_view=True,
    )
    assert returned.status == "ESCAPE"
    assert "candidate" in returned.escapes

    mutated = _summarize(
        "def inspect(key): headers = {'signature': [key]}; "
        "headers['signature'].append('replacement')",
        "inspect",
        {"key": "candidate"},
        role_view=True,
    )
    assert mutated.status == "UNKNOWN"
    assert any(
        event.kind == "unresolved_method_call" and event.roots == ("candidate",)
        for event in mutated.role_events
    )


def test_exact_helper_mapping_merges_field_and_backreference_role_events():
    path, tree, index = _index("""
        def caller(owner, candidate):
            helper(owner, candidate)

        def helper(self, key):
            self.secret = key
            self.owner = self
    """)
    caller = _function(tree, "caller")
    helper = _function(tree, "helper")

    def resolve(call, call_path):
        if isinstance(call.func, ast.Name) and call.func.id == "helper":
            return ResolvedIdentityCall(
                helper, call_path, {"self": call.args[0], "key": call.args[1]}
            )
        return None

    result = summarize_identity_effect(
        caller,
        path,
        index,
        {"owner": "owner", "candidate": "candidate"},
        resolve_call=resolve,
        role_view=True,
    )
    assert any(
        event.kind == "field_store"
        and event.relevant == "secret"
        and event.receiver_roots == ("owner",)
        and event.roots == ("candidate",)
        for event in result.role_events
    )
    assert any(
        event.kind == "field_store"
        and event.relevant == "owner"
        and event.receiver_roots == ("owner",)
        and event.roots == ("owner",)
        for event in result.role_events
    )


def test_constructor_role_consumer_requires_exact_store_and_no_related_effects():
    source = """
        class Owner:
            def __init__(self, key):
                self.secret = key
    """
    path, tree, index = _index(source)
    owner = tree.body[0]
    constructor = owner.body[0]
    store = constructor.body[0]
    result = summarize_identity_effect(
        constructor,
        path,
        index,
        {"self": "owner", "key": "candidate"},
        strict_calls=True,
        role_view=True,
        ordinary_fields={"secret"},
    )
    from factoryline.credential_role_identity_effects import (
        _app_signing_constructor_role_transfer_closed,
    )

    assert result.status != "NO_CLASS_EFFECT"
    assert _app_signing_constructor_role_transfer_closed(result, path, "secret", store)

    back_path, back_tree, back_index = _index("""
        class Owner:
            def inspect(self, key):
                self.secret = key
                self.owner = self
    """)
    back_method = _function(back_tree, "inspect")
    back_store = back_method.body[0]
    backreference = summarize_identity_effect(
        back_method,
        back_path,
        back_index,
        {"self": "owner", "key": "candidate"},
        strict_calls=True,
        role_view=True,
        ordinary_fields={"secret"},
    )
    assert not _app_signing_constructor_role_transfer_closed(
        backreference,
        back_path,
        "secret",
        back_store,
    )


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


def _application_role_index(source):
    from factoryline.mock_fixture_provenance import application_test_index

    path = Path("fixture.py")
    raw = textwrap.dedent(source).encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = application_test_index(Path("."), {path: tree}, {path: raw}, {path: digest})
    assert index is not None
    return path, tree, index


def _function(tree, name):
    return next(
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name
    )


def _summarize(source, name, roots, *, role_view=False):
    path, tree, index = _index(source)
    return summarize_identity_effect(
        _function(tree, name), path, index, roots, role_view=role_view
    )


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


@pytest.mark.parametrize(
    "header",
    [
        "    def inner(value=(yield 1)): pass\n",
        "    async def inner(value=(yield 1)): pass\n",
        "    @(yield 1)\n    def inner(): pass\n",
        "    class Inner((yield 1)): pass\n",
        "    factory = lambda value=(yield 1): None\n",
    ],
)
def test_own_scope_includes_eager_nested_header_suspension(header):
    from types import CodeType
    from factoryline.credential_role_identity_effects import own_function_nodes

    raw = ("def outer():\n" + header + "    return {'key': 1}\n").encode()
    path, tree = Path("scope.py"), ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(Path("."), {path: tree}, {path: raw}, {path: digest})
    assert index.validate(path)
    code = next(
        item
        for item in compile(raw, str(path), "exec").co_consts
        if isinstance(item, CodeType)
    )
    assert code.co_flags & 0x20  # CPython independently identifies the outer generator.
    assert any(
        isinstance(node, ast.Yield)
        for node in own_function_nodes(tree.body[0], path, index)
    )


@pytest.mark.parametrize(
    "body,status",
    [("value.__class__ = Other", "CLASS_WRITE"), ("opaque(value)", "ESCAPE")],
)
def test_own_scope_effects_ignore_forged_parent_metadata(body, status):
    raw = ("def mutate(value):\n    " + body + "\n").encode()
    path, tree = Path("scope.py"), ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(Path("."), {path: tree}, {path: raw}, {path: digest})
    function = tree.body[0]
    assert index.validate(path)
    index.parents[path][id(function.body[0])] = ast.parse(
        "lambda: None", mode="eval"
    ).body
    result = summarize_identity_effect(function, path, index, {"value": "account"})
    assert result.status == status


def test_own_scope_excludes_nested_bodies_but_keeps_definition_headers():
    from factoryline.credential_role_identity_effects import own_function_nodes

    raw = b"def outer():\n    def inner(value=header_call()):\n        body_call()\n    return 1\n"
    path, tree = Path("scope.py"), ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(Path("."), {path: tree}, {path: raw}, {path: digest})
    assert index.validate(path)
    calls = [
        node.func.id
        for node in own_function_nodes(tree.body[0], path, index)
        if isinstance(node, ast.Call)
    ]
    assert calls == ["header_call"]


def test_application_role_facades_reject_plaintext_without_crypto_roundtrip():
    from factoryline import credential_identity_audit as identity_audit
    from factoryline import credential_role_identity_effects as role_effects

    path, tree, index = _application_role_index(
        "def view():\n    credential = 'ordinary text'\n    return credential\n"
    )
    assignment = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign))
    literal = assignment.value

    for module in (identity_audit, role_effects):
        assert (
            module.application_value_role_evidence(
                index, path, literal, assignment, "credential"
            )
            is None
        )
        assert (
            module.application_plaintext_effect_evidence(
                index, path, literal, assignment, "credential"
            )
            is None
        )


def test_application_identity_helper_epoch_invalidates_cached_role_evidence(
    monkeypatch,
):
    from factoryline import credential_identity_audit as identity_audit

    path, tree, index = _application_role_index(
        "def view():\n    credential = 'ordinary text'\n    return credential\n"
    )
    assignment = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign))
    epoch = identity_audit.application_identity_helper_epoch()
    assert identity_audit.application_identity_helper_epoch in epoch
    assert identity_audit.application_plaintext_effect_evidence in epoch
    assert identity_audit._app_local_crypto_roundtrip in epoch
    identity_audit.application_plaintext_effect_evidence(
        index, path, assignment.value, assignment, "credential"
    )
    assert len(index["profiles"]) == 1

    helper = identity_audit._app_local_crypto_roundtrip

    def replacement(*args, **kwargs):
        return None

    with monkeypatch.context() as patch:
        patch.setattr(helper, "__code__", replacement.__code__)
        identity_audit.application_plaintext_effect_evidence(
            index, path, assignment.value, assignment, "credential"
        )
        assert len(index["profiles"]) == 2

    identity_audit.application_plaintext_effect_evidence(
        index, path, assignment.value, assignment, "credential"
    )
    assert len(index["profiles"]) == 2
