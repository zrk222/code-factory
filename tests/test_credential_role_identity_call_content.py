"""Unknown call results stay separate from tracked receiver identity."""

import ast
import hashlib
from pathlib import Path
import pytest


from factoryline.credential_role_identity_effects import (
    ResolvedIdentityCall,
    _Value,
)
from factoryline.credential_role_identity_effects import summarize_identity_effect
from factoryline.credential_role_identity_effects import (
    identity_value,
    tracked_roots,
)
from factoryline.credential_role_constructor_provider import SourceSnapshotIndex
from factoryline.credential_role_identity_effects import SourceFieldLiteral
from factoryline import credential_role_identity_effects as identity


def _analyze(
    tmp_path, strategy_body, backend_body, *, wrong_mapping=False, nonlocal_store=False
):
    source = (
        "class Strategy:\n"
        "    def request_data(self):\n"
        + "".join("        " + line + "\n" for line in strategy_body.splitlines())
        + "class Backend:\n"
        "    def initialize(self):\n"
        + "".join("        " + line + "\n" for line in backend_body.splitlines())
    )
    if nonlocal_store:
        source = "def enclosing():\n    leaked = None\n" + "".join(
            "    " + line + "\n" for line in source.splitlines()
        )
        compile(source, "fixture.py", "exec")  # Compile only; target code never runs.
    path = Path(tmp_path) / "fixture.py"
    raw = source.encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(
        Path(tmp_path), {path: tree}, {path: raw}, {path: digest}
    )
    scope = tree.body[0] if nonlocal_store else tree
    strategy, backend = [node for node in scope.body if isinstance(node, ast.ClassDef)]
    method = next(node for node in backend.body if isinstance(node, ast.FunctionDef))
    request_data = next(
        node for node in strategy.body if isinstance(node, ast.FunctionDef)
    )

    def resolve(call, call_path):
        if (
            call_path == path
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "request_data"
            and call.func.value is not None
        ):
            receiver = (
                ast.Name(id="different", ctx=ast.Load())
                if wrong_mapping
                else call.func.value
            )
            return ResolvedIdentityCall(request_data, path, {"self": receiver})
        return None

    return summarize_identity_effect(
        method,
        path,
        index,
        {"self": "backend"},
        resolve_call=resolve,
        field_roots={("backend", "strategy"): "strategy"},
        strict_calls=True,
    )


def test_exact_call_result_content_does_not_alias_backend(tmp_path):
    result = _analyze(tmp_path, "return {}", "self.data = self.strategy.request_data()")

    assert result.status == "NO_CLASS_EFFECT"
    assert not result.escapes
    assert not result.unknowns


@pytest.mark.parametrize(
    "strategy_body",
    [
        "return self",
        "self.__class__ = Changed\nreturn {}",
        "import inspect\nframe = inspect.currentframe().f_back\n"
        "frame.f_locals['self'].__class__ = Changed\nreturn {}",
    ],
)
def test_exact_callee_root_escape_or_mutation_stays_unresolved(tmp_path, strategy_body):
    result = _analyze(
        tmp_path, strategy_body, "self.data = self.strategy.request_data()"
    )

    assert result.status != "NO_CLASS_EFFECT"


def test_unknown_call_result_cannot_flow_to_an_opaque_call(tmp_path):
    result = _analyze(
        tmp_path,
        "return {}",
        "self.data = self.strategy.request_data()\nopaque(self.data)",
    )

    assert result.status == "UNKNOWN"


def test_unknown_call_result_cannot_hide_in_literal_container_before_escape(tmp_path):
    result = _analyze(
        tmp_path,
        "return {}",
        "self.data = self.strategy.request_data()\nsaved = [self.data]\nopaque(saved)",
    )

    assert result.status == "UNKNOWN"


@pytest.mark.parametrize("projection", ["self.data.callback", "self.data['x']"])
def test_content_unknown_attribute_or_subscript_extraction_stays_unknown(
    tmp_path, projection
):
    result = _analyze(
        tmp_path,
        "return {}",
        f"self.data = self.strategy.request_data()\nopaque({projection})",
    )

    assert result.status == "UNKNOWN"


def test_content_unknown_return_and_foreign_store_stay_unknown(tmp_path):
    returned = _analyze(
        tmp_path,
        "return {}",
        "self.data = self.strategy.request_data()\nreturn self.data",
    )
    stored = _analyze(
        tmp_path,
        "return {}",
        "self.data = self.strategy.request_data()\nexternal.value = self.data",
    )

    assert returned.status == "UNKNOWN"
    assert stored.status == "UNKNOWN"


@pytest.mark.parametrize(
    "container",
    ["[self.data]", "{'nested': [{'value': self.data}] }"],
)
def test_nested_content_unknown_cannot_escape_in_returned_container(
    tmp_path, container
):
    result = _analyze(
        tmp_path,
        "return {}",
        f"self.data = self.strategy.request_data()\nreturn {container}",
    )

    assert result.status == "UNKNOWN"


def test_formatting_content_unknown_stays_unknown(tmp_path):
    result = _analyze(
        tmp_path,
        "return {}",
        "self.data = self.strategy.request_data()\nmessage = f'{self.data}'",
    )

    assert result.status == "UNKNOWN"


@pytest.mark.parametrize(
    "consumer",
    [
        "for item in self.data:\n    pass",
        "with self.data:\n    pass",
        "items = [None for item in self.data]",
        "items = self.data + 1",
        "items = [*self.data]",
        "items = {**self.data}",
        "if self.data == None:\n    pass",
    ],
)
def test_unmodeled_content_consumers_stay_unknown(tmp_path, consumer):
    result = _analyze(
        tmp_path,
        "return {}",
        f"self.data = self.strategy.request_data()\n{consumer}",
    )

    assert result.status == "UNKNOWN"


def test_passive_content_alias_and_literal_container_storage_are_allowed(tmp_path):
    result = _analyze(
        tmp_path,
        "return {}",
        "self.data = self.strategy.request_data()\n"
        "saved = self.data\n"
        "container = [{'value': saved}]",
    )

    assert result.status == "NO_CLASS_EFFECT"
    assert not result.escapes
    assert not result.unknowns


def test_identity_test_of_content_can_control_branch_without_protocol_dispatch(
    tmp_path,
):
    result = _analyze(
        tmp_path,
        "return {}",
        "self.data = self.strategy.request_data()\n"
        "if self.data is None:\n"
        "    return {}",
    )

    assert result.status == "NO_CLASS_EFFECT"


def test_source_call_mapping_must_use_the_actual_receiver(tmp_path):
    result = _analyze(
        tmp_path,
        "return {}",
        "self.data = self.strategy.request_data()",
        wrong_mapping=True,
    )

    assert result.status == "UNKNOWN"


def test_nonstrict_calls_preserve_tracked_roots_in_unknown_expressions():
    node = ast.parse("strategy.request_data()", mode="eval").body
    aliases = {"strategy": _Value(roots=frozenset({"strategy"}))}
    value = identity_value(node, aliases)
    strict_value = identity_value(node, aliases, strict_calls=True)

    assert tracked_roots(value) == {"strategy"}
    assert strict_value.content_unknown


@pytest.mark.parametrize("value", ["self.data", "[self.data]", "{'x': [self.data]}"])
def test_global_content_storage_is_an_escape(tmp_path, value):
    result = _analyze(
        tmp_path,
        "return {}",
        f"global leaked\nself.data = self.strategy.request_data()\nleaked = {value}",
    )
    assert result.status == "UNKNOWN"
    assert (
        "global/nonlocal assignment contains unresolved tracked value"
        in result.unknowns
    )


@pytest.mark.parametrize(
    "body",
    [
        "saved = self.data\ndef inner():\n    return saved",
        "saved = [self.data]\ndef inner():\n    return saved",
        "def inner(value=self.data):\n    pass",
        "@opaque\ndef inner():\n    pass",
    ],
)
def test_nested_content_capture_and_definition_effects_stay_unknown(tmp_path, body):
    result = _analyze(
        tmp_path, "return {}", "self.data = self.strategy.request_data()\n" + body
    )
    assert result.status == "UNKNOWN"


@pytest.mark.parametrize("value", ["self.data", "{'x': [self.data]}"])
def test_nonlocal_content_storage_is_an_escape(tmp_path, value):
    result = _analyze(
        tmp_path,
        "return {}",
        f"nonlocal leaked\nself.data = self.strategy.request_data()\nleaked = {value}",
        nonlocal_store=True,
    )
    assert result.status == "UNKNOWN"
    assert (
        "global/nonlocal assignment contains unresolved tracked value"
        in result.unknowns
    )


# --- Merged from test_credential_role_identity_literals.py; test definitions and fixtures retained ---
"""Strict call summaries retain literal data shapes and reject opaque behavior."""


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


def test_receiver_helper_code_epoch_invalidates_and_restores_cached_model():
    from types import SimpleNamespace

    from factoryline import credential_role_identity_effects as identity
    from factoryline.credential_role_constructor_provider import ClassChainMemo

    enrolled = {
        identity._identity_call_value,
        identity._capture_nested_scope,
        identity._strict_read_is_unknown,
        identity._identity_field_value,
        identity._identity_field_key_valid,
        identity._call_has_expansion,
        identity._resolved_parameter_names,
        identity._call_actual_expressions,
        identity._mapped_formal_value,
        identity._exact_receiver_class_for_function,
    }
    assert enrolled <= set(identity._receiver_helper_epoch())

    memo = SimpleNamespace(
        defers_validation=lambda *_: True,
        index=None,
        imports={},
        classes={},
        audit=None,
        _analysis_batch=SimpleNamespace(helper_epoch={}),
        source_models={},
    )
    helper = identity._capture_nested_scope
    original_code = helper.__code__
    calls = []

    def derive():
        calls.append(object())
        return calls[-1]

    first = ClassChainMemo.source_model(
        memo, "receiver", derive, helper_epoch=identity._receiver_helper_epoch
    )
    assert (
        ClassChainMemo.source_model(
            memo, "receiver", derive, helper_epoch=identity._receiver_helper_epoch
        )
        is first
    )
    assert len(calls) == 1

    def replacement(*_args, **_kwargs):
        return set()

    try:
        helper.__code__ = replacement.__code__
        changed = ClassChainMemo.source_model(
            memo, "receiver", derive, helper_epoch=identity._receiver_helper_epoch
        )
        assert changed is not first
        assert len(calls) == 2
    finally:
        helper.__code__ = original_code

    restored = ClassChainMemo.source_model(
        memo, "receiver", derive, helper_epoch=identity._receiver_helper_epoch
    )
    assert restored is first
    assert len(calls) == 2


def _captured_identity_source(tmp_path, source):
    path = Path(tmp_path) / "captured_identity.py"
    raw = source.encode("utf-8")
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(
        Path(tmp_path), {path: tree}, {path: raw}, {path: digest}
    )
    assert index.validate(path)
    return path, tree, index


def test_contains_tracked_and_class_identity_property_distinguish_effects():
    empty = identity._Value()
    tracked = identity._Value(roots=frozenset({"backend"}))
    assert not identity.contains_tracked(empty)
    assert identity.contains_tracked(tracked)
    assert identity.IdentityEffectSummary("NO_CLASS_EFFECT").preserves_class_identity
    assert not identity.IdentityEffectSummary("CLASS_WRITE").preserves_class_identity


def test_maps_each_actual_once_uses_expression_identity():
    actuals = ast.parse("helper(backend, value)", mode="eval").body.args
    assert identity.maps_each_actual_once(
        actuals, {"backend": actuals[0], "value": actuals[1]}
    )
    assert not identity.maps_each_actual_once(
        actuals, {"backend": actuals[0], "value": actuals[0]}
    )


def test_call_unknown_and_tracked_root_helpers_include_receiver_and_arguments():
    call = ast.parse("backend.send(opaque)", mode="eval").body
    aliases = {
        "backend": identity._Value(roots=frozenset({"backend"})),
        "opaque": identity._Value(roots=frozenset({"session"}), content_unknown=True),
    }
    assert identity.call_has_unknown_value(call, aliases)
    assert identity.call_argument_roots(call, aliases) == {"session"}
    assert identity.call_tracked_roots(call, aliases) == {"backend", "session"}
    assert not identity.call_has_unknown_value(
        ast.parse("backend.send('ok')", mode="eval").body,
        {"backend": aliases["backend"]},
    )


def test_assignment_target_accepts_one_target_and_rejects_ambiguous_targets():
    single, multiple, annotated = ast.parse(
        "value = source\nleft = right = source\nother: object = source"
    ).body
    assert identity.assignment_target(single).id == "value"
    assert identity.assignment_target(multiple) is None
    assert identity.assignment_target(annotated).id == "other"


def test_nested_capture_roots_uses_validated_lexical_capture(tmp_path):
    path, tree, index = _captured_identity_source(
        tmp_path,
        "def operation():\n    def callback():\n        return backend\n    return callback\n",
    )
    operation = tree.body[0]
    aliases = {"backend": identity._Value(roots=frozenset({"backend"}))}
    assert identity.nested_capture_roots(operation, path, aliases, index) == {"backend"}
    clean_path, clean_tree, clean_index = _captured_identity_source(
        tmp_path / "clean", "def operation():\n    return 1\n"
    )
    assert (
        identity.nested_capture_roots(
            clean_tree.body[0], clean_path, aliases, clean_index
        )
        == set()
    )


def test_record_escape_preserves_root_and_marks_strict_unknown_content():
    value = ast.parse("backend", mode="eval").body
    effects = identity._Effects()
    identity.record_escape(
        value,
        {
            "backend": identity._Value(
                roots=frozenset({"backend"}), content_unknown=True
            )
        },
        effects,
        "return",
        strict_calls=True,
    )
    summary = effects.freeze()
    assert summary.status == "UNKNOWN"
    assert summary.escapes == ("backend",)
    assert summary.unknowns == ("return contains unresolved tracked value",)


def test_record_opaque_call_marks_argument_escape_or_unresolved_dispatch():
    escaped = identity._Effects()
    identity.record_opaque_call(
        ast.parse("opaque(backend)", mode="eval").body,
        {"backend": identity._Value(roots=frozenset({"backend"}))},
        {"backend"},
        escaped,
    )
    assert escaped.freeze().status == "ESCAPE"
    unresolved = identity._Effects()
    identity.record_opaque_call(
        ast.parse("opaque()", mode="eval").body, {}, set(), unresolved
    )
    assert "unresolved method call on tracked object" in unresolved.freeze().unknowns


def test_strict_read_effects_distinguish_unknown_and_captured_values(tmp_path):
    path, tree, index = _captured_identity_source(
        tmp_path, "def operation():\n    return missing.value\n"
    )
    unknown = next(node for node in ast.walk(tree) if isinstance(node, ast.Attribute))
    effects = identity._Effects()
    identity.strict_read_effects(unknown, {}, index.parents[path], effects)
    assert "unresolved value in strict identity summary" in effects.freeze().unknowns
    captured = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and node.id == "missing"
    )
    known_effects = identity._Effects()
    identity.strict_read_effects(
        captured,
        {"missing": identity._Value(roots=frozenset({"backend"}))},
        index.parents[path],
        known_effects,
    )
    assert known_effects.freeze().status == "NO_CLASS_EFFECT"


def test_strict_protocol_effects_reject_opaque_operator_but_allow_literals(tmp_path):
    path, tree, index = _captured_identity_source(
        tmp_path, "def operation(backend):\n    return backend + 1\n"
    )
    operation = tree.body[0]
    expression = next(
        node for node in ast.walk(operation) if isinstance(node, ast.BinOp)
    )
    effects = identity._Effects()
    identity.strict_protocol_effects(
        expression,
        {"backend": identity._Value(roots=frozenset({"backend"}))},
        index.parents[path],
        effects,
    )
    assert "unresolved consumer of strict identity content" in effects.freeze().unknowns
    literal = ast.parse("1 + 2", mode="eval").body
    literal_effects = identity._Effects()
    identity.strict_protocol_effects(literal, {}, {}, literal_effects)
    assert literal_effects.freeze().status == "NO_CLASS_EFFECT"


def test_implicit_protocol_roots_tracks_for_iteration_receiver():
    loop = ast.parse("for item in backend:\n    pass\n").body[0]
    assert identity.implicit_protocol_roots(
        loop, {"backend": identity._Value(roots=frozenset({"backend"}))}
    ) == {"backend"}


def test_super_reference_requires_loaded_super_name():
    loaded = ast.parse("super()", mode="eval").body.func
    stored = ast.Name(id="super", ctx=ast.Store())
    assert identity.super_reference(loaded)
    assert not identity.super_reference(stored)


def test_tracks_receiver_requires_first_positional_parameter_in_aliases():
    method = ast.parse("def call(self, item):\n    return item\n").body[0]
    assert identity.tracks_receiver(
        method, {"self": identity._Value(roots=frozenset({"backend"}))}
    )
    assert not identity.tracks_receiver(method, {"item": identity._Value()})


def test_record_implicit_effects_marks_loaded_super_dispatch_unknown():
    method = ast.parse("def call(self):\n    super()\n").body[0]
    super_name = method.body[0].value.func
    effects = identity._Effects()
    identity.record_implicit_effects(
        super_name,
        method,
        {"self": identity._Value(roots=frozenset({"backend"}))},
        effects,
    )
    assert "super uses implicit or reflective receiver" in effects.freeze().unknowns


def test_identity_fields_accepts_owner_member_roots_and_rejects_invalid_keys():
    fields = identity.identity_fields({("Strategy", "data"): "strategy"}, None)
    assert identity.tracked_roots(fields[("Strategy", "data")]) == {"strategy"}
    assert (
        identity.identity_fields({("Strategy", "__class__"): "strategy"}, None) is None
    )


def test_literal_dict_update_only_accepts_exact_inert_dictionary_pair():
    accepted = ast.parse("data.update({'code': 'known'})", mode="eval").body
    rejected = ast.parse("data.update({'code': opaque})", mode="eval").body
    aliases = {"data": identity._Value(inert_kind="dict")}
    assert identity.literal_dict_update(accepted, aliases)
    assert not identity.literal_dict_update(rejected, aliases)


def test_mapped_call_values_requires_exact_actual_to_formal_identity():
    path, tree, _index = _captured_identity_source(
        Path.cwd(),
        "def helper(backend, payload):\n    return payload\n"
        "def caller(backend):\n    return helper(backend, {})\n",
    )
    helper, caller = tree.body
    call = caller.body[0].value
    resolved = ResolvedIdentityCall(
        helper, path, {"backend": call.args[0], "payload": call.args[1]}
    )
    out = identity._Effects()
    mapped = identity.mapped_call_values(
        call,
        {"backend": identity._Value(roots=frozenset({"backend"}))},
        {"backend"},
        resolved,
        out,
    )
    assert mapped is not None
    assert identity.tracked_roots(mapped["backend"]) == {"backend"}
    assert mapped["payload"].inert_kind == "dict"
    expanded = ast.parse("helper(*values)", mode="eval").body
    failure = identity._Effects()
    assert identity.mapped_call_values(expanded, {}, set(), resolved, failure) is None
    assert (
        "expanded call arguments are not an exact binding" in failure.freeze().unknowns
    )


def test_summarize_identity_call_reports_captured_opaque_argument_escape(tmp_path):
    path, tree, index = _captured_identity_source(
        tmp_path, "def operation(backend):\n    opaque(backend)\n"
    )
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    result = identity.summarize_identity_call(
        call, path, index, {"backend": "backend"}, resolve_call=lambda *_: None
    )
    assert result.status == "ESCAPE"
    assert result.escapes == ("backend",)


def test_captured_function_valid_rejects_ast_outside_captured_snapshot(tmp_path):
    path, tree, index = _captured_identity_source(
        tmp_path, "def operation():\n    return 1\n"
    )
    assert identity.captured_function_valid(tree.body[0], path, index)
    other = ast.parse("def operation():\n    return 1\n").body[0]
    assert not identity.captured_function_valid(other, path, index)


def test_exported_names_reports_global_and_nonlocal_bindings():
    tree = ast.parse(
        "def outer():\n    value = None\n    def inner():\n"
        "        global session\n        nonlocal value\n"
    )
    inner = tree.body[0].body[1]
    assert identity.exported_names(ast.walk(inner)) == {"session", "value"}


def test_exact_receiver_class_resolves_only_unique_local_constructor(tmp_path):
    path, tree, index = _captured_identity_source(
        tmp_path,
        "class Client:\n    pass\n"
        "def operation():\n    client = Client()\n    client.send()\n"
        "def unresolved(other):\n    other.send()\n",
    )
    client_class = tree.body[0]
    classes = {(path, "Client"): client_class}
    client_receiver = tree.body[1].body[1].value.func.value
    other_receiver = tree.body[2].body[0].value.func.value
    assert identity.exact_receiver_class(
        path, client_receiver, index, {}, classes, None
    ) == (path, "Client")
    assert (
        identity.exact_receiver_class(path, other_receiver, index, {}, classes, None)
        is None
    )


def test_module_fixture_evidence_requires_selected_settings_and_exact_module_owner(
    tmp_path,
):
    path, tree, source = _captured_identity_source(
        tmp_path,
        "PASSWORD = 'local-fixture'\ndef helper():\n    PASSWORD = 'nested-fixture'\n",
    )
    assert source.validate(path)
    index = {"source": source, "modules": {path: tree}, "configuration_bytes": {}}
    assert (
        identity.module_fixture_credential_evidence(
            index, path, tree.body[0], "PASSWORD"
        )
        is None
    )
    assert (
        identity.module_fixture_evidence_for_binding(
            index, path, tree.body[0], "PASSWORD"
        )
        is None
    )
    assert (
        identity.module_fixture_evidence_for_binding(
            index, path, tree.body[1].body[0], "PASSWORD"
        )
        is None
    )


def test_module_fixture_predicate_epoch_tracks_native_code_replacement(monkeypatch):
    from factoryline import credential_role_constructor_provider as provider

    epoch = identity.module_fixture_helper_epoch()
    assert identity.module_fixture_evidence_for_binding in epoch
    assert identity.module_fixture_credential_evidence in epoch
    before = provider._helper_snapshot(identity.module_fixture_helper_epoch)
    original = identity.module_fixture_evidence_for_binding

    def changed(*args):
        return None

    with monkeypatch.context() as patch:
        patch.setattr(original, "__code__", changed.__code__)
        assert provider._helper_snapshot(identity.module_fixture_helper_epoch) != before
    assert provider._helper_snapshot(identity.module_fixture_helper_epoch) == before
