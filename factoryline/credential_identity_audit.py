"""Captured application credential evidence and source-bound audit helpers."""

import ast

from . import credential_role_identity_effects as _legacy


def application_value_role_evidence(index, path, literal, assignment, secret):
    """Resolve shared test-authority effects before the reversible-value lane."""
    django_fixture = _legacy.django_testcase_helper_secret_evidence(
        index, path, literal, assignment, secret
    )
    if django_fixture is not None:
        return django_fixture
    signing = _app_signing_authority(index, path, assignment, secret)
    if signing is not None:
        return signing
    object_signing = _app_object_signing_authority(index, path, assignment, secret)
    if object_signing is not None:
        return object_signing
    factory = _app_factory_test_authority(index, path, assignment, secret)
    if factory is not None:
        return factory
    plaintext = _legacy.application_plaintext_effect_evidence(
        index, path, literal, assignment, secret
    )
    return plaintext or application_test_scope_role_evidence(
        index, path, assignment, secret
    )


def application_test_scope_role_evidence(index, path, assignment, secret):
    """Recompute test-invocation scope independently of crypto validity."""
    from .credential_role_method_use_getter_audit import _source_test_scope_evidence

    return _source_test_scope_evidence(index, path, assignment, secret)


class _TestScopeContractEpoch:
    """Retain actual immutable model bindings for role-cache generations."""

    __name__ = "test_scope_contract_epoch"

    @property
    def __code__(self):
        from . import credential_role_method_use_getter_audit as getter

        names = sorted(
            name
            for name in vars(getter)
            if name.startswith("_SCOPE_") or name == "SCOPE_API_CONTRACT_EPOCH"
        )
        values = tuple(getattr(getter, name) for name in names)
        key = tuple((name, id(value)) for name, value in zip(names, values))
        current = getattr(self, "current", None)
        if current is None or current[0] != key:
            current = (key, object(), values)
            self.current = current
        return current[1]


_TEST_SCOPE_CONTRACT_EPOCH = _TestScopeContractEpoch()


def _app_digest_provider_binding(index, path, owner, call):
    """Resolve both caller-visible and terminal providers before value projection."""
    from . import mock_fixture_provenance as fixture

    selected = fixture._app_source_symbol(index, path, call.func, owner)
    if selected is None or not isinstance(selected[1], ast.FunctionDef):
        return None
    target, helper = selected
    if helper.decorator_list or helper.args.vararg or helper.args.kwarg:
        return None
    canonical = fixture._app_expression_name(index, path, call.func, owner)
    if canonical is None or any(
        isinstance(node, ast.ImportFrom)
        and any(alias.name == "*" for alias in node.names)
        for selected_path in {path, target}
        for node in ast.walk(index["modules"][selected_path])
    ):
        return None
    return target, helper


def _app_digest_call(index, path, owner, call, actual, secret):
    from . import mock_fixture_provenance as fixture

    selected = _app_digest_provider_binding(index, path, owner, call)
    if selected is None:
        return None
    target, helper = selected
    values = _app_digest_bound_values(call, helper, actual, secret, owner, fixture)
    if values is None:
        return None
    result = _app_digest_wrapper_return(helper, values)
    if result is None:
        return None
    if not (
        isinstance(result, ast.Call)
        and not result.args
        and not result.keywords
        and isinstance(result.func, ast.Attribute)
        and result.func.attr in {"digest", "hexdigest"}
    ):
        return None
    constructor = result.func.value
    if (
        not isinstance(constructor, ast.Call)
        or constructor.keywords
        or len(constructor.args) != 3
    ):
        return None
    if (
        fixture._app_expression_name(index, target, constructor.func, helper)
        != "hmac.new"
    ):
        return None
    key, message, algorithm = constructor.args
    if fixture._app_expression_name(
        index, target, algorithm, helper
    ) != "hashlib.sha256" or not _app_digest_bytes(key, values, {secret}):
        return None
    if not _app_digest_bytes(message, values, set()):
        return None
    if not _app_digest_provider_closed(index, path, owner, call, target, helper):
        return None
    return _app_credential_source_row(
        index, target, helper, "captured_pure_digest_wrapper"
    )


def _app_digest_provider_closed(index, path, owner, call, target, helper):
    from . import mock_fixture_provenance as fixture, review_audits as audit

    canonical = fixture._app_expression_name(index, path, call.func, owner)
    key = (
        "digest-provider-closed",
        canonical,
        target,
        id(helper),
        _app_source_role_epoch(index),
    )
    cache = index.setdefault("profiles", {})
    if key in cache:
        return cache[key]
    provider = _legacy._class_binding._captured_terminal_provider_mutation
    if any(
        provider(index["source"], audit, name)
        for name in (
            canonical,
            fixture._django_name(index, target) + "." + helper.name,
            "hmac.new",
        )
    ):
        return False
    if provider(
        index["source"],
        audit,
        "hashlib.sha256",
        readonly_argument=_app_digest_algorithm_argument,
    ):
        return False
    if any(
        fixture._django_provider_root_shadowed(index["module_paths"], name)
        for name in ("hmac", "hashlib")
    ):
        return False
    cache[key] = True
    return True


def _app_digest_bytes(node, values, roots):
    value = _legacy.identity_value(
        node, values, strict_calls=True, material_values=True
    )
    return (
        not value.unknown
        and not value.content_unknown
        and value.scalar_kind == "bytes"
        and value.roots == roots
    )


def _app_digest_bound_values(call, helper, actual, secret, owner, fixture):
    from .review_integrity import bind_source_call

    try:
        bound = bind_source_call(call, helper, apply_defaults=True)
    except (TypeError, ValueError):
        return None
    values = {}
    for name, expression in bound.items():
        if expression is actual:
            values[name] = _legacy._Value(roots=frozenset({secret}), scalar_kind="text")
        else:
            if isinstance(expression, ast.Name):
                assignment = fixture._app_local_assignment(owner, expression.id)
                expression = (
                    assignment.value
                    if assignment is not None and assignment.lineno < call.lineno
                    else None
                )
            value = _legacy.identity_value(
                expression, {}, strict_calls=True, material_values=True
            )
            if value.unknown or value.content_unknown or not value.scalar_kind:
                return None
            values[name] = value
    return values


def _app_digest_wrapper_return(helper, values):
    statements = [
        n
        for n in helper.body
        if not (
            isinstance(n, ast.Expr)
            and isinstance(n.value, ast.Constant)
            and isinstance(n.value.value, str)
        )
    ]
    if (
        not statements
        or len(statements) > 8
        or not isinstance(statements[-1], ast.Return)
    ):
        return None
    for statement in statements[:-1]:
        if (
            not isinstance(statement, ast.Assign)
            or len(statement.targets) != 1
            or not isinstance(statement.targets[0], ast.Name)
        ):
            return None
        value = _legacy.identity_value(
            statement.value, values, strict_calls=True, material_values=True
        )
        if value.unknown or value.content_unknown or not value.scalar_kind:
            return None
        values[statement.targets[0].id] = value
    return statements[-1].value


def _app_digest_algorithm_argument(node, aliases, parents):
    """Only the stable HMAC digestmod slot borrows a digest constructor."""
    from . import review_audits as audit

    call = parents.get(id(node))
    if not _app_digest_lexical_read(call, node, parents):
        return False
    return (
        isinstance(call, ast.Call)
        and not call.keywords
        and len(call.args) == 3
        and call.args[2] is node
        and audit._resolved_ast_name(call.func, aliases) == "hmac.new"
        and audit._resolved_ast_name(node, aliases) == "hashlib.sha256"
    )


def _app_digest_lexical_read(call, node, parents):
    roots = []
    for expression in (getattr(call, "func", None), node):
        while isinstance(expression, ast.Attribute):
            expression = expression.value
        if isinstance(expression, ast.Name):
            roots.append(expression.id)
    scope = parents.get(id(node))
    while scope is not None and not isinstance(scope, ast.Module):
        if isinstance(
            scope,
            (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
        ):
            return False
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if any(_legacy.binding_occurrences(scope.body, root) for root in roots):
                return False
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                root in _legacy._argument_names(scope) for root in roots
            ):
                return False
        scope = parents.get(id(scope))
    return True


def _app_digest_test_owner(index, path, function, parents, fixture):
    cls = parents.get(id(function))
    if not isinstance(cls, ast.ClassDef):
        return None
    chain = fixture._django_class_chain(
        index, path, cls, "django.test.TestCase"
    ) or fixture._django_class_chain(index, path, cls, "unittest.TestCase")
    if not chain or not function.args.args:
        return None
    if not _app_digest_receiver_closed(index, chain):
        return None
    receiver = function.args.args[0].arg
    assertions = {
        "assertEqual",
        "assertNotEqual",
        "assertTrue",
        "assertFalse",
        "assertIsNone",
        "assertIsNotNone",
    }
    if any(
        _legacy.binding_occurrences(owner.body, name)
        for _, _, owner in chain
        for name in assertions | {"__getattribute__", "__getattr__"}
    ):
        return None
    from . import review_audits as audit

    if any(
        _legacy._class_binding._captured_terminal_provider_mutation(
            index["source"],
            audit,
            name,
            readonly_argument=lambda node,
            aliases,
            parents: _app_digest_unrelated_provider_argument(
                node, aliases, parents, name
            ),
        )
        for name in ("unittest.TestCase", "django.test.TestCase")
    ):
        return None
    if _legacy.binding_occurrences(function.body, receiver):
        return None
    if any(
        not _app_signing_class_stable(index, (path, cls), name) for name in assertions
    ):
        return None
    return receiver, assertions


def _app_digest_unrelated_provider_argument(node, aliases, parents, canonical):
    """An exact sibling API argument does not expose the protected namespace."""
    from . import review_audits as audit

    selected = node
    while (
        isinstance((parent := parents.get(id(selected))), ast.Attribute)
        and parent.value is selected
    ):
        if parent.attr.startswith("__"):
            return False
        selected = parent
    resolved = audit._resolved_ast_name(selected, aliases)
    return (
        isinstance(resolved, str)
        and resolved.partition(".")[0] == canonical.partition(".")[0]
        and not _legacy._class_binding._terminal_provider_related(resolved, canonical)
        and _app_digest_lexical_read(parents.get(id(node)), node, parents)
    )


def _app_digest_receiver_closed(index, chain):
    """An opaque receiver or reflective method can replace the inherited oracle."""
    for path, _, owner in chain:
        if owner.decorator_list or owner.keywords:
            return False
        parents = index["source"].parents[path]
        for method in owner.body:
            if not isinstance(method, ast.FunctionDef) or not method.args.args:
                continue
            receiver = method.args.args[0].arg
            if _legacy.binding_occurrences(method.body, receiver):
                return False
            aliases = _app_digest_receiver_aliases(method, receiver, parents)
            if aliases is None:
                return False
            if not _app_digest_receiver_reads_closed(method, aliases, parents):
                return False
    return True


def _app_digest_receiver_reads_closed(method, aliases, parents):
    for node in ast.walk(method):
        if (
            not isinstance(node, ast.Name)
            or node.id not in aliases
            or not isinstance(node.ctx, ast.Load)
        ):
            continue
        nested = _legacy._enclosing_function(node, parents)
        if nested is not method and node.id in _legacy._argument_names(nested):
            continue
        parent = parents.get(id(node))
        if isinstance(parent, ast.Assign) and parent.value is node:
            continue
        if not isinstance(parent, ast.Attribute) or parent.value is not node:
            return False
        if parent.attr.startswith("__"):
            return False
    return True


def _app_digest_receiver_aliases(method, receiver, parents):
    """Reuse exact local binding identity for receiver aliases captured by closures."""
    aliases = {receiver}
    for _ in range(8):
        previous = set(aliases)
        for node in ast.walk(method):
            if (
                not isinstance(node, ast.Assign)
                or not isinstance(node.value, ast.Name)
                or node.value.id not in aliases
            ):
                continue
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                return None
            target = node.targets[0]
            if _legacy._enclosing_function(
                node, parents
            ) is not method or _legacy.binding_occurrences(method.body, target.id) != [
                target
            ]:
                return None
            aliases.add(target.id)
        if aliases == previous:
            return aliases
    return None


def _app_digest_operation_witnesses(index, path, owner, operations, witnesses, parents):
    from . import mock_fixture_provenance as fixture

    contract = _app_digest_test_owner(index, path, owner, parents, fixture)
    if contract is None:
        return None
    receiver, assertions = contract
    rows = list(witnesses)
    for call, _, _ in operations.values():
        closure = _app_digest_result_closure(owner, call, parents, receiver, assertions)
        if closure is None:
            return None
        rows.extend(
            _app_credential_source_row(index, path, node, "test_digest_oracle")
            for node in closure["sinks"]
        )
    return rows


def _app_digest_result_closure(function, call, parents, receiver, assertions):
    from .finite_capture import captured_value_use_closure

    def oracle(scope, value):
        parent = parents.get(id(value))
        if (
            isinstance(parent, ast.Call)
            and value in parent.args
            and not parent.keywords
            and isinstance(parent.func, ast.Attribute)
            and parent.func.attr in assertions
            and isinstance(parent.func.value, ast.Name)
            and parent.func.value.id == receiver
        ):
            return parent
        return None

    return captured_value_use_closure(
        function,
        call,
        parents,
        lambda node: _legacy._enclosing_function(node, parents),
        lambda scope: (),
        oracle,
    )


def _app_object_signing_authority(index, path, assignment, secret):
    """Demand constructor key-flow facts separately from test-owner closure."""
    source = index["source"]
    if not source.validate(path):
        return None
    owner = source.parents[path].get(id(assignment))
    if not isinstance(owner, ast.ClassDef):
        return None
    uses = _app_object_signing_uses(index, path, owner, assignment, secret)
    if uses is None:
        return None
    operations, rows = [], []
    for function, node in uses:
        call = source.parents[path].get(id(node))
        if isinstance(call, ast.keyword):
            call = source.parents[path].get(id(call))
        flow = _app_signing_constructor_flow(index, path, function, call, node)
        if flow is None:
            return None
        operations.append((function, call, flow))
        rows.extend(flow)
    if not _app_object_signing_pair(index, path, owner, operations):
        return None
    return _app_object_signing_witness(
        index, path, owner, assignment, secret, uses, rows
    )


def _app_signing_constructor_flow(index, path, function, call, actual, seen=()):
    """Follow captured parameter/field transfers to a modeled key constructor.

    This describes a key consumer, not a benign credential: the caller must
    separately close ownership, paired generation and verification lifetimes.
    """
    from . import mock_fixture_provenance as fixture

    if (
        not isinstance(call, ast.Call)
        or _legacy._call_has_expansion(call)
        or len(seen) >= 6
    ):
        return None
    canonical = fixture._app_expression_name(index, path, call.func, function)
    if canonical == "slack_sdk.signature.SignatureVerifier":
        return _app_signature_terminal(index, path, function, call, actual)
    selected = fixture._app_source_symbol(index, path, call.func, function)
    if selected is None or not isinstance(selected[1], ast.ClassDef):
        return None
    target_path, owner = selected
    key = (target_path, id(owner))
    if key in seen:
        return None
    chain = _app_signing_transfer_chain(index, target_path, owner)
    if not chain or not _app_signing_captured_provider_stable(index, chain):
        return None
    transfer = _app_signing_constructor_transfer(
        index, chain, path, function, call, actual
    )
    if transfer is None:
        return None
    constructor_path, field, statement = transfer
    rows = []
    for class_path, cls in chain:
        edges = _app_signing_field_consumers(
            index, class_path, cls, field, statement, (*seen, key)
        )
        if edges is None:
            return None
        rows.extend(edges)
    if not rows:
        return None
    return [
        _app_credential_source_row(
            index, constructor_path, statement, "captured_key_field_transfer", field
        ),
        *rows,
    ]


def _app_signing_constructor_transfer(index, chain, caller_path, caller, call, actual):
    from .review_integrity import bind_source_call

    source = index["source"]
    if (
        not source.validate(caller_path)
        or id(caller) not in source.parents[caller_path]
        or not any(node is call for node in ast.walk(caller))
    ):
        return None
    constructors = [
        (p, n)
        for p, cls in chain
        for n in cls.body
        if isinstance(n, ast.FunctionDef) and n.name == "__init__"
    ]
    if len(constructors) != 1:
        return None
    constructor_path, constructor = constructors[0]
    try:
        bound = bind_source_call(
            call,
            constructor,
            ast.Name(id="_instance", ctx=ast.Load()),
            apply_defaults=False,
        )
        with_defaults = bind_source_call(
            call,
            constructor,
            ast.Name(id="_instance", ctx=ast.Load()),
            apply_defaults=True,
        )
    except (TypeError, ValueError):
        return None
    formals = [name for name, value in bound.items() if value is actual]
    if len(formals) != 1:
        return None
    constructor_args = [*constructor.args.posonlyargs, *constructor.args.args]
    if not constructor_args:
        return None
    receiver = constructor_args[0].arg
    roots = {receiver: "owner", formals[0]: "candidate"}
    roots.update(
        {
            name: _legacy.SourceFieldLiteral(
                caller_path if name in bound else constructor_path, value
            )
            for name, value in with_defaults.items()
            if name not in roots and isinstance(value, ast.Constant)
        }
    )
    parameters = _legacy._captured_parameter_values(roots, source)
    if parameters is None:
        return None
    transfer = _app_signing_parameter_field(
        index,
        constructor_path,
        constructor,
        formals[0],
        _legacy._initial_scalar_guards(constructor, parameters),
    )
    if transfer is None:
        return None
    inert_nodes, metadata_fields = _app_signing_metadata_assignments(
        index, constructor_path, constructor, receiver
    )
    ordinary_fields = _app_signing_ordinary_fields(
        chain, {transfer[0], *metadata_fields}
    )
    if ordinary_fields is None:
        return None
    resolver = _app_signing_constructor_resolver(chain, receiver)
    effects = _legacy.summarize_identity_effect(
        constructor,
        constructor_path,
        index["source"],
        roots,
        resolve_call=resolver,
        strict_calls=True,
        role_view=True,
        ordinary_fields=ordinary_fields,
        source_inert_nodes=inert_nodes,
    )
    if not _app_signing_constructor_role_transfer_closed(
        effects, constructor_path, transfer[0], transfer[1]
    ):
        return None
    return constructor_path, *transfer


def _app_signing_metadata_assignments(index, path, constructor, receiver):
    from . import mock_fixture_provenance as fixture

    ignored, fields = set(), set()
    parents = index["source"].parents[path]
    for statement in constructor.body:
        if (
            not isinstance(statement, ast.Assign)
            or len(statement.targets) != 1
            or not isinstance(statement.value, ast.Call)
        ):
            continue
        target, call = statement.targets[0], statement.value
        if not (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == receiver
            and not target.attr.startswith("__")
            and len(call.args) == 1
            and not call.keywords
        ):
            continue
        if _app_class_metadata_consumer(index, path, call.args[0]) is None:
            continue
        selected = fixture._app_source_symbol(
            index, path, call.func, _legacy._enclosing_function(call, parents)
        )
        if selected is None or not _app_metadata_logger_result(index, *selected):
            continue
        ignored.update((path, id(node)) for node in ast.walk(statement))
        fields.add(target.attr)
    return ignored, fields


def _app_metadata_logger_result(index, path, function):
    from . import mock_fixture_provenance as fixture

    parameters = [*function.args.posonlyargs, *function.args.args]
    if not parameters:
        return False
    metadata_receiver = parameters[0].arg
    body = [
        node
        for node in function.body
        if not (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
    ]
    if (
        len(body) != 1
        or not isinstance(body[0], ast.Return)
        or not isinstance(body[0].value, ast.Call)
    ):
        return False
    call = body[0].value
    if (
        fixture._app_expression_name(index, path, call.func, function)
        != "logging.getLogger"
        or len(call.args) != 1
        or call.keywords
        or not isinstance(call.args[0], ast.JoinedStr)
    ):
        return False
    return _app_metadata_logging_environment_closed(index) and all(
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        or isinstance(node, ast.FormattedValue)
        and node.conversion == -1
        and node.format_spec is None
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "__name__"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == metadata_receiver
        for node in call.args[0].values
    )


def _app_metadata_logging_environment_closed(index):
    """Reject captured logger factories, manager access and logging-provider exports."""
    from . import mock_fixture_provenance as fixture

    if not _app_signing_terminal_stable(index, "logging"):
        return False
    for path, tree in index["modules"].items():
        parents = index["source"].parents[path]
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Name, ast.Attribute)):
                continue
            canonical = fixture._app_expression_name(index, path, node)
            if canonical == "logging":
                if not isinstance(parents.get(id(node)), ast.Attribute):
                    return False
            elif (
                canonical
                and canonical.startswith("logging.")
                and canonical not in {"logging.Logger", "logging.getLogger"}
            ):
                return False
    return True


def _app_signing_ordinary_fields(chain, selected_fields):
    """Prove only selected instance fields avoid source-declared descriptors and slots."""
    if not selected_fields or any(
        not isinstance(name, str) or not name.isidentifier() for name in selected_fields
    ):
        return None
    for _, owner in chain:
        if _legacy.binding_occurrences(owner.body, "__slots__"):
            return None
        if any(
            _legacy.binding_occurrences(owner.body, name) for name in selected_fields
        ):
            return None
    return frozenset(selected_fields)


def _app_signing_constructor_resolver(chain, receiver):
    """Resolve exact direct receiver-method calls in the captured constructor chain."""
    from .review_integrity import bind_source_call

    methods = [(path, owner.name, owner) for path, owner in chain]

    def resolve(call, call_path):
        if not (
            isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == receiver
        ):
            return None
        selected = _legacy.effective_method(methods, call.func.attr)
        if selected is None:
            return None
        method_path, method = selected
        try:
            bound = bind_source_call(
                call, method, call.func.value, apply_defaults=False
            )
        except (TypeError, ValueError):
            return None
        return _legacy.ResolvedIdentityCall(method, method_path, bound)

    return resolve


def _app_signing_constructor_role_transfer_closed(summary, path, field, statement):
    """Require the exact key-field store and reject every unresolved or relevant side effect."""
    transfers = [
        row
        for row in summary.field_transfers
        if row.path == path
        and row.target_root == "owner"
        and row.target_field == field
        and row.source_roots == ("candidate",)
        and row.statement is statement
        and row.unconditional
    ]
    if not isinstance(statement, ast.Assign):
        return False
    expected_span = _legacy._event_span(path, statement.value)
    stores = [
        event
        for event in summary.role_events
        if event.kind == "field_store"
        and event.source_span == expected_span
        and event.relevant == field
        and event.receiver_roots == ("owner",)
        and event.roots == ("candidate",)
        and not event.uncertain
    ]
    if summary.unknowns or len(transfers) != 1 or len(stores) != 1:
        return False
    for event in summary.role_events:
        if event is stores[0]:
            continue
        if event.uncertain or {"owner", "candidate"}.intersection(event.roots):
            return False
    return True


def _app_signing_captured_provider_stable(index, chain):
    key = (
        "signing-captured-provider",
        tuple((path, id(owner)) for path, owner in chain),
        _app_source_role_epoch(index),
    )
    cache = index.setdefault("profiles", {})
    if key in cache:
        return cache[key]
    imports = _app_crypto_provider_imports(index)
    result = imports is not None and _app_signing_provider_model_closed(
        index, chain, imports
    )
    cache[key] = result
    return result


def _app_signing_provider_model_closed(index, chain, imports):
    """Reuse the provider model, excluding only source-proven metadata operands."""
    selected = {
        _legacy._class_binding._source_module(path) + "." + owner.name
        for path, owner in chain
    }
    model = _legacy._class_binding.constructor_provider_model(
        selected,
        index["source"],
        imports,
        _legacy._class_binding._source_aliases,
        _legacy._class_binding._has_opaque_owner_capture,
    )
    if model is None:
        return False
    roots, aliases, filtered, shared, fields, consumers = model
    metadata = _app_class_metadata_operands(index, selected, aliases)
    for path, node, callee in metadata:
        filtered.setdefault(path, set()).update(id(item) for item in ast.walk(node))
        consumers.add(callee)
    return _legacy._class_binding._captured_mutations_inert(
        index["source"], roots, aliases, filtered, shared, fields, consumers
    )


def _app_class_metadata_operands(index, selected, aliases):
    from . import review_audits as audit

    result = []
    for path, tree in index["modules"].items():
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Name, ast.Attribute)) or not isinstance(
                node.ctx, ast.Load
            ):
                continue
            if audit._resolved_ast_name(node, aliases[path]) not in selected:
                continue
            callee = _app_class_metadata_consumer(index, path, node)
            if callee is not None:
                result.append((path, node, callee))
    return result


def _app_class_metadata_consumer(index, path, actual):
    from . import mock_fixture_provenance as fixture
    from .review_integrity import bind_source_call

    parents = index["source"].parents[path]
    call = parents.get(id(actual))
    if isinstance(call, ast.keyword):
        call = parents.get(id(call))
    if not isinstance(call, ast.Call) or _legacy._call_has_expansion(call):
        return None
    selected = fixture._app_source_symbol(
        index, path, call.func, _legacy._enclosing_function(call, parents)
    )
    if selected is None or not isinstance(selected[1], ast.FunctionDef):
        return None
    target_path, function = selected
    if not _app_metadata_header_inert(index, target_path, function):
        return None
    try:
        bound = bind_source_call(call, function, apply_defaults=False)
    except (TypeError, ValueError):
        return None
    formals = [name for name, value in bound.items() if value is actual]
    if len(formals) != 1 or not _app_metadata_formal_closed(
        index, target_path, function, formals[0]
    ):
        return None
    return _legacy._class_binding._source_module(target_path) + "." + function.name


def _app_metadata_formal_closed(index, path, function, formal):
    parents = index["source"].parents[path]
    references = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name) and node.id == formal
    ]
    if not references:
        return False
    return all(
        isinstance(node.ctx, ast.Load)
        and _legacy._enclosing_function(node, parents) is function
        and isinstance(parents.get(id(node)), ast.Attribute)
        and isinstance(parents[id(node)].ctx, ast.Load)
        and parents[id(node)].attr in {"__name__", "__qualname__", "__module__"}
        for node in references
    )


def _app_metadata_header_inert(index, path, function):
    if function.decorator_list or getattr(function, "type_params", ()):
        return False
    args = function.args
    parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    parameters.extend(arg for arg in (args.vararg, args.kwarg) if arg)
    defaults = [
        *args.defaults,
        *(value for value in args.kw_defaults if value is not None),
    ]
    annotations = [arg.annotation for arg in parameters if arg.annotation is not None]
    if function.returns is not None:
        annotations.append(function.returns)
    return all(_legacy._immutable_default(value) for value in defaults) and all(
        _app_metadata_annotation_inert(index, path, node) for node in annotations
    )


def _app_metadata_annotation_inert(index, path, node):
    """Explicit unmodified stdlib annotation models, never arbitrary evaluation."""
    from . import mock_fixture_provenance as fixture

    if isinstance(node, ast.Constant):
        return node.value is None or isinstance(node.value, str)
    if isinstance(node, ast.Name) and node.id in {
        "str",
        "bytes",
        "int",
        "bool",
        "object",
    }:
        return _app_builtin_annotation_inert(index, path, node)
    canonical = fixture._app_expression_name(index, path, node)
    if canonical in {"typing.Any", "logging.Logger"}:
        root = canonical.partition(".")[0]
        return not fixture._django_provider_root_shadowed(
            index["module_paths"], root
        ) and _app_signing_terminal_stable(index, canonical)
    if isinstance(node, ast.Subscript):
        generic = fixture._app_expression_name(index, path, node.value)
        arguments = (
            node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
        )
        arity = {
            "typing.Optional": (1, 1),
            "typing.Union": (1, 16),
            "typing.Dict": (2, 2),
            "typing.List": (1, 1),
            "typing.Sequence": (1, 1),
            "typing.Mapping": (2, 2),
            "typing.Tuple": (1, 16),
        }.get(generic)
        return (
            arity is not None
            and arity[0] <= len(arguments) <= arity[1]
            and not fixture._django_provider_root_shadowed(
                index["module_paths"], "typing"
            )
            and _app_signing_terminal_stable(index, generic)
            and all(
                _app_metadata_annotation_inert(index, path, argument)
                for argument in arguments
            )
        )
    return False


def _app_builtin_annotation_inert(index, path, node):
    current = node
    parents = index["source"].parents[path]
    while current is not None:
        if isinstance(
            current, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ) and _legacy.binding_occurrences(current.body, node.id):
            return False
        if isinstance(
            current, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) and node.id in _legacy._argument_names(current):
            return False
        current = parents.get(id(current))
    return _app_signing_terminal_stable(index, "builtins." + node.id)


def _app_signing_transfer_chain(index, path, owner, seen=()):
    """Close source inheritance; ABCMeta is an explicit non-transforming model."""
    from . import mock_fixture_provenance as fixture

    key = (path, id(owner))
    if key in seen or len(seen) >= 8 or owner.decorator_list:
        return None
    if _legacy.binding_occurrences(index["modules"][path].body, owner.name) != [owner]:
        return None
    if any(_legacy.binding_occurrences(owner.body, name) for name in _legacy._HOOKS):
        return None
    for keyword in owner.keywords:
        if (
            keyword.arg != "metaclass"
            or fixture._app_expression_name(index, path, keyword.value) != "abc.ABCMeta"
            or not _app_signing_terminal_stable(index, "abc.ABCMeta")
        ):
            return None
    chain = [(path, owner)]
    for base in owner.bases:
        selected = fixture._app_source_symbol(index, path, base)
        if selected is None or not isinstance(selected[1], ast.ClassDef):
            return None
        inherited = _app_signing_transfer_chain(index, *selected, (*seen, key))
        if inherited is None:
            return None
        chain.extend(row for row in inherited if row not in chain)
    return chain


def _app_signature_terminal(index, path, function, call, actual):
    from . import mock_fixture_provenance as fixture
    from . import review_audits as audit

    args = [
        *call.args[:1],
        *(kw.value for kw in call.keywords if kw.arg == "signing_secret"),
    ]
    if (
        args != [actual]
        or len(call.args) > 1
        or any(kw.arg != "signing_secret" for kw in call.keywords)
    ):
        return None
    if fixture._django_provider_root_shadowed(index["module_paths"], "slack_sdk"):
        return None
    root = call.func
    while isinstance(root, ast.Attribute):
        root = root.value
    if not isinstance(
        root, ast.Name
    ) or _legacy._class_binding._presentation_provider_shadow(
        call.func, root.id, index["source"], path, audit
    ):
        return None
    if not _app_signing_terminal_stable(index, "slack_sdk.signature.SignatureVerifier"):
        return None
    return [
        _app_credential_source_row(
            index, path, call, "modeled_signature_key_constructor"
        )
    ]


def _app_signing_terminal_stable(index, canonical):
    from . import review_audits as audit

    key = ("signing-terminal-stable", canonical, _app_source_role_epoch(index))
    cache = index.setdefault("profiles", {})
    if key in cache:
        return cache[key]
    for path, tree in index["modules"].items():
        if not index["source"].validate(path):
            return False
        aliases, mutations, star = _legacy._class_binding._presentation_provider_facts(
            tree, list(ast.walk(tree)), index["source"].parents[path], audit
        )
        overlapping = [
            (provider, member)
            for provider, member in mutations
            if _legacy._class_binding._mutation_overlaps(provider, member, canonical)
        ]
        readonly_type = (
            canonical in {"typing.Sequence", "typing.Mapping"}
            and overlapping == [(canonical, "*")]
            and _app_stdlib_type_reads_closed(
                index, path, tree, aliases, canonical, audit
            )
        )
        if star or overlapping and not readonly_type:
            cache[key] = False
            return False
    cache[key] = True
    return True


def _app_stdlib_type_reads_closed(index, path, tree, aliases, canonical, audit):
    """Model unmodified typing ABC checks as reads, retaining exports and writes."""
    parents = index["source"].parents[path]
    found = False
    for node in ast.walk(tree):
        if (
            not isinstance(node, (ast.Name, ast.Attribute))
            or audit._resolved_ast_name(node, aliases) != canonical
        ):
            continue
        if not isinstance(node.ctx, ast.Load):
            return False
        parent = parents.get(id(node))
        if _app_annotation_reference_only(node, parents, aliases, audit):
            continue
        if not (
            isinstance(parent, ast.Call)
            and len(parent.args) == 2
            and parent.args[1] is node
            and not parent.keywords
            and isinstance(parent.func, ast.Name)
            and parent.func.id == "isinstance"
            and _app_builtin_annotation_inert(index, path, parent.func)
            and not _legacy._class_binding._presentation_provider_shadow(
                node,
                node.id if isinstance(node, ast.Name) else "typing",
                index["source"],
                path,
                audit,
            )
        ):
            return False
        found = True
    return found


def _app_annotation_reference_only(node, parents, aliases, audit):
    """Recognize type arguments only inside declaration annotations, not value calls."""
    current = node
    for _ in range(16):
        parent = parents.get(id(current))
        if isinstance(parent, ast.arg):
            return parent.annotation is current
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return parent.returns is current
        if isinstance(parent, ast.AnnAssign):
            return parent.annotation is current
        if not isinstance(parent, (ast.Subscript, ast.Tuple, ast.List, ast.Attribute)):
            return False
        if isinstance(parent, ast.Subscript) and audit._resolved_ast_name(
            parent.value, aliases
        ) not in {
            "typing.Optional",
            "typing.Union",
            "typing.Dict",
            "typing.List",
            "typing.Sequence",
            "typing.Mapping",
            "typing.Tuple",
            "typing.Callable",
        }:
            return False
        current = parent
    return False


def _app_signing_parameter_field(index, path, constructor, formal, known_scalars=None):
    """Require the non-null actual to enter one exact instance field."""
    parents = index["source"].parents[path]
    args = [*constructor.args.posonlyargs, *constructor.args.args]
    if not args or constructor.decorator_list:
        return None
    receiver = args[0].arg
    transfer = None
    nodes = _legacy.own_function_nodes(
        constructor, path, index["source"], known_scalars
    )
    # Retain the prior rejection of nested captures. Only outer lexical guards
    # use constructor parameter facts; nested scopes have their own bindings.
    nodes += [
        child
        for scope in nodes
        if scope is not constructor
        and isinstance(
            scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        )
        for child in ast.walk(scope)
    ]
    for node in nodes:
        if not isinstance(node, ast.Name) or node.id != formal:
            continue
        parent = parents.get(id(node))
        if _app_signing_null_fallback(node, parent, parents, formal):
            continue
        if (
            not isinstance(node.ctx, ast.Load)
            or _legacy._enclosing_function(node, parents) is not constructor
        ):
            return None
        target = _legacy.assignment_target(parent)
        if not (
            isinstance(parent, (ast.Assign, ast.AnnAssign))
            and parent.value is node
            and isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == receiver
            and parents.get(id(parent)) is constructor
            and transfer is None
        ):
            return None
        transfer = target.attr, parent
    return transfer


def _app_bound_field_transfer(index, path, call, caller, field):
    """Bind one captured constructor store to the exact caller argument root."""
    from . import mock_fixture_provenance as fixture
    from .review_integrity import bind_source_call

    selected = fixture._app_source_symbol(index, path, call.func, caller)
    if selected is None or not isinstance(selected[1], ast.ClassDef):
        return None
    target_path, owner = selected
    constructors = [
        node
        for node in owner.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "__init__"
    ]
    if len(constructors) != 1 or owner.decorator_list:
        return None
    constructor = constructors[0]
    params = [
        *constructor.args.posonlyargs,
        *constructor.args.args,
        *constructor.args.kwonlyargs,
    ]
    if not params or constructor.decorator_list:
        return None
    receiver = params[0].arg
    try:
        bound = bind_source_call(
            call, constructor, ast.Name(id="_target", ctx=ast.Load())
        )
    except (TypeError, ValueError):
        return None
    roots = {receiver: "target"}
    roots.update((param.arg, "input:" + param.arg) for param in params[1:])
    summary = _legacy.summarize_identity_effect(
        constructor, target_path, index["source"], roots, strict_calls=False
    )
    rows = [
        row
        for row in summary.field_transfers
        if row.target_root == "target" and row.target_field == field
    ]
    selected_transfer = _app_select_bound_field_transfer(
        index, target_path, path, caller, field, constructor, bound, rows
    )
    if selected_transfer is None:
        return None
    transfer, formals, branch_proof = selected_transfer
    if summary.field_writes.count("target." + field) != 1 and branch_proof is None:
        # Branch-pruned writes are intentionally checked by the separate
        # source-bound selector; the may-effect set collapses branch arms.
        return None
    if len(formals) != 1 or len(transfer.source_roots) != 1:
        return None
    return {
        "path": target_path,
        "class": owner,
        "constructor": constructor,
        "bound": bound,
        "formal": formals[0],
        "actual": bound[formals[0]],
        "transfer": transfer,
        "branch_proof": branch_proof,
    }


def _app_select_bound_field_transfer(
    index, constructor_path, caller_path, caller, field, constructor, bound, rows
):
    branch_proof = None
    if len(rows) == 1 and rows[0].unconditional and rows[0].statement is not None:
        transfer = rows[0]
        formals = [name for name in bound if "input:" + name in transfer.source_roots]
    else:
        branch_proof = _app_literal_branch_field_transfer(
            index, constructor_path, constructor, bound, caller_path, caller, field
        )
        if branch_proof is None:
            return None
        selected = [row for row in rows if row.statement is branch_proof["statement"]]
        if len(selected) != 1:
            return None
        transfer = selected[0]
        formals = [branch_proof["formal"]]
    return transfer, formals, branch_proof


def _app_header_list_transfer(index, constructor_transfer):
    """Prove a finite map projection keeps each caller-owned list unchanged."""
    from . import mock_fixture_provenance as fixture

    transfer = constructor_transfer["transfer"]
    call = transfer.value
    if not (
        isinstance(call, ast.Call)
        and not _legacy._call_has_expansion(call)
        and len(call.args) == 1
        and not call.keywords
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == constructor_transfer["formal"]
    ):
        return None
    selected = fixture._app_source_symbol(
        index, transfer.path, call.func, constructor_transfer["constructor"]
    )
    if selected is None or not isinstance(selected[1], ast.FunctionDef):
        return None
    path, function = selected
    parameters = [*function.args.posonlyargs, *function.args.args]
    if not (
        len(parameters) == 1
        and not function.args.kwonlyargs
        and not function.args.vararg
        and not function.args.kwarg
        and not function.decorator_list
        and len(function.body) == 3
        and _app_metadata_header_inert(index, path, function)
    ):
        return None
    initial, conditional, returned = function.body
    target = _legacy.assignment_target(initial)
    if not (
        isinstance(target, ast.Name)
        and isinstance(initial.value, ast.Dict)
        and not initial.value.keys
        and isinstance(returned, ast.Return)
        and isinstance(returned.value, ast.Name)
        and returned.value.id == target.id
        and isinstance(conditional, ast.If)
        and not conditional.orelse
        and len(conditional.body) == 1
        and isinstance(conditional.body[0], ast.For)
    ):
        return None
    parameter = parameters[0].arg
    guard = conditional.test
    loop = conditional.body[0]
    if not (
        isinstance(guard, ast.Compare)
        and isinstance(guard.left, ast.Name)
        and guard.left.id == parameter
        and len(guard.ops) == 1
        and isinstance(guard.ops[0], ast.IsNot)
        and len(guard.comparators) == 1
        and isinstance(guard.comparators[0], ast.Constant)
        and guard.comparators[0].value is None
        and not loop.orelse
        and len(loop.body) == 2
        and isinstance(loop.target, ast.Tuple)
        and len(loop.target.elts) == 2
        and all(isinstance(node, ast.Name) for node in loop.target.elts)
        and isinstance(loop.iter, ast.Call)
        and not loop.iter.args
        and not loop.iter.keywords
        and isinstance(loop.iter.func, ast.Attribute)
        and loop.iter.func.attr == "items"
        and isinstance(loop.iter.func.value, ast.Name)
        and loop.iter.func.value.id == parameter
    ):
        return None
    key, value = loop.target.elts
    normalization, branch = loop.body
    normalized = _legacy.assignment_target(normalization)
    if not (
        isinstance(normalized, ast.Name)
        and isinstance(normalization.value, ast.Call)
        and not normalization.value.args
        and not normalization.value.keywords
        and isinstance(normalization.value.func, ast.Attribute)
        and normalization.value.func.attr == "lower"
        and isinstance(normalization.value.func.value, ast.Name)
        and normalization.value.func.value.id == key.id
        and isinstance(branch, ast.If)
        and len(branch.body) == 1
        and isinstance(branch.test, ast.Call)
        and isinstance(branch.test.func, ast.Name)
        and branch.test.func.id == "isinstance"
        and not branch.test.keywords
        and len(branch.test.args) == 2
        and isinstance(branch.test.args[0], ast.Name)
        and branch.test.args[0].id == value.id
        and isinstance(branch.test.args[1], ast.Name)
        and branch.test.args[1].id == "list"
    ):
        return None
    store = branch.body[0]
    destination = _legacy.assignment_target(store)
    if not (
        isinstance(store, ast.Assign)
        and len(store.targets) == 1
        and isinstance(destination, ast.Subscript)
        and isinstance(destination.value, ast.Name)
        and destination.value.id == target.id
        and isinstance(destination.slice, ast.Name)
        and destination.slice.id == normalized.id
        and isinstance(store.value, ast.Name)
        and store.value.id == value.id
        and _app_builtin_annotation_inert(index, path, branch.test.func)
        and _app_builtin_annotation_inert(index, path, branch.test.args[1])
    ):
        return None
    return {
        "path": path,
        "function": function,
        "input": call.args[0],
        "list_guard": branch.test,
        "store": store,
        "output": returned.value,
    }


def _app_request_verification_projection(
    index, test_path, test_method, process_call, process_path, process_method, rows
):
    """Join captured request field transfers to a process verifier and observed success."""
    transfer_inputs = _app_request_transfer_inputs(
        index, test_path, test_method, process_call, process_method
    )
    if transfer_inputs is None:
        return None
    request_actual, request_formal, process_args, process_bound, raw, headers = (
        transfer_inputs
    )
    if raw["actual"] is not headers["actual"]:
        if not (
            isinstance(raw["actual"], ast.Name)
            and isinstance(headers["actual"], ast.Call)
            and headers["actual"].func is not None
        ):
            return None
    verifier_inputs = _app_request_signature_inputs(
        index, process_path, process_method, request_formal, rows
    )
    if verifier_inputs is None:
        return None
    body_row, signature_row, timestamp_row, signature_value, verify_call, condition = (
        verifier_inputs
    )
    if not _app_request_verification_prefix_closed(
        index,
        process_path,
        process_method,
        request_formal,
        condition,
        (body_row["statement"], timestamp_row["statement"], signature_row["statement"]),
    ):
        return None
    observed = _app_request_success_observation(
        index, test_path, test_method, process_call, process_args[3].arg, process_bound
    )
    if observed is None:
        return None
    carrier = _app_test_header_signature_carrier(
        index,
        test_path,
        test_method,
        headers["actual"],
        signature_row["key"],
        timestamp_row["key"],
        raw["actual"],
    )
    if carrier is None:
        return None
    return {
        "request_actual": request_actual,
        "request_transfer": raw,
        "header_transfer": headers,
        "body_read": body_row,
        "signature_read": signature_row,
        "timestamp_read": timestamp_row,
        "signature_value": signature_value,
        "verification": verify_call,
        "success_observation": observed,
        "header_carrier": carrier,
    }


def _app_request_transfer_inputs(
    index, test_path, test_method, process_call, process_method
):
    from . import mock_fixture_provenance as fixture
    from .review_integrity import bind_source_call
    from .finite_capture import captured_call_scalar

    process_args = [
        *process_method.args.posonlyargs,
        *process_method.args.args,
        *process_method.args.kwonlyargs,
    ]
    if len(process_args) < 4 or process_method.decorator_list:
        return None
    try:
        process_bound = bind_source_call(
            process_call,
            process_method,
            process_call.func.value,
            apply_defaults=False,
        )
    except (TypeError, ValueError):
        return None
    request_formal = process_args[1].arg
    request_actual = process_bound.get(request_formal)
    if not isinstance(request_actual, ast.Name):
        return None
    request_assignment = fixture._app_local_assignment(test_method, request_actual.id)
    if request_assignment is None or not isinstance(request_assignment.value, ast.Call):
        return None
    request_call = request_assignment.value
    raw = _app_bound_field_transfer(
        index, test_path, request_call, test_method, "raw_body"
    )
    headers = _app_bound_field_transfer(
        index, test_path, request_call, test_method, "headers"
    )
    if (
        raw is None
        or headers is None
        or _app_header_list_transfer(index, headers) is None
    ):
        return None
    if captured_call_scalar(
        index["source"], test_path, test_method, raw["bound"].get("mode"), raw["path"]
    ) != ("http",):
        return None
    return request_actual, request_formal, process_args, process_bound, raw, headers


def _app_request_signature_inputs(
    index, process_path, process_method, request_formal, rows
):
    body_row = _app_process_body_read(process_method, request_formal)
    if not body_row:
        return None
    verifier_calls = _app_property_verification_operations(
        index, process_path, process_method, rows
    )
    if len(verifier_calls) != 1:
        return None
    verify_call, signature_value = verifier_calls[0]
    arguments = _app_signature_verification_arguments(verify_call)
    if arguments is None or not all(
        isinstance(arguments[name], ast.Name)
        for name in ("body", "timestamp", "signature")
    ):
        return None
    signature_row = _app_process_header_read(
        process_method, request_formal, arguments["signature"].id
    )
    timestamp_row = _app_process_header_read(
        process_method, request_formal, arguments["timestamp"].id
    )
    if not signature_row or not timestamp_row:
        return None
    if (
        arguments["body"].id != body_row["local"]
        or arguments["timestamp"].id != timestamp_row["local"]
        or arguments["signature"].id != signature_row["local"]
    ):
        return None
    condition = index["source"].parents[process_path].get(id(verify_call))
    process_args = [
        *process_method.args.posonlyargs,
        *process_method.args.args,
        *process_method.args.kwonlyargs,
    ]
    if not _app_success_guard_calls_parameter(
        condition, verify_call, process_args[3].arg
    ):
        return None
    return (
        body_row,
        signature_row,
        timestamp_row,
        signature_value,
        verify_call,
        condition,
    )


def _app_success_guard_calls_parameter(condition, verify_call, next_parameter):
    return (
        isinstance(condition, ast.If)
        and condition.test is verify_call
        and len(condition.body) == 1
        and isinstance(condition.body[0], ast.Return)
        and isinstance(condition.body[0].value, ast.Call)
        and isinstance(condition.body[0].value.func, ast.Name)
        and condition.body[0].value.func.id == next_parameter
    )


def _app_process_header_read(method, request_name, label):
    rows = []
    for node in ast.walk(method):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        value = node.value
        if (
            not isinstance(target, ast.Name)
            or target.id != label
            or not isinstance(value, ast.Subscript)
        ):
            continue
        get_call = value.value
        if not (
            isinstance(get_call, ast.Call)
            and isinstance(get_call.func, ast.Attribute)
            and get_call.func.attr == "get"
            and isinstance(get_call.func.value, ast.Attribute)
            and get_call.func.value.attr == "headers"
            and isinstance(get_call.func.value.value, ast.Name)
            and get_call.func.value.value.id == request_name
            and isinstance(value.slice, ast.Constant)
            and value.slice.value == 0
            and get_call.args
            and isinstance(get_call.args[0], ast.Constant)
            and isinstance(get_call.args[0].value, str)
            and len(get_call.args) == 2
            and isinstance(get_call.args[1], (ast.List, ast.Tuple))
        ):
            continue
        rows.append(
            {"local": target.id, "key": get_call.args[0].value, "statement": node}
        )
    return rows[0] if len(rows) == 1 else None


def _app_process_body_read(method, request_name):
    rows = [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "raw_body"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == request_name
    ]
    return (
        {"local": rows[0].targets[0].id, "statement": rows[0]}
        if len(rows) == 1
        else None
    )


def _app_request_success_observation(
    index, path, test_method, process_call, next_name, bound, expected_status=200
):
    from . import mock_fixture_provenance as fixture

    parents = index["source"].parents[path]
    assignment = parents.get(id(process_call))
    if not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1:
        return None
    result = assignment.targets[0]
    if not isinstance(result, ast.Name):
        return None
    observed = _app_result_status_assertion(
        test_method, result, assignment, parents, expected_status
    )
    actual_next = bound.get(next_name)
    if observed is None or not isinstance(actual_next, ast.Name):
        return None
    selected = fixture._app_source_symbol(index, path, actual_next, test_method)
    if selected is None or not isinstance(selected[1], ast.FunctionDef):
        return None
    returns = [node for node in selected[1].body if isinstance(node, ast.Return)]
    if len(returns) != 1 or not isinstance(returns[0].value, ast.Call):
        return None
    status = [kw.value for kw in returns[0].value.keywords if kw.arg == "status"]
    if (
        len(status) != 1
        or not isinstance(status[0], ast.Constant)
        or status[0].value != 200
    ):
        return None
    return {"assertion": observed, "continuation": returns[0], "status": status[0]}


def _app_result_status_assertion(
    test_method, result, assignment, parents, expected_status
):
    stores = [
        node
        for node in ast.walk(test_method)
        if isinstance(node, ast.Name)
        and node.id == result.id
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    if len(stores) != 2 or any(node.lineno > assignment.lineno for node in stores):
        return None
    later_loads = [
        node
        for node in ast.walk(test_method)
        if isinstance(node, ast.Name)
        and node.id == result.id
        and isinstance(node.ctx, ast.Load)
        and node.lineno > assignment.end_lineno
    ]
    if not later_loads:
        return None
    for node in later_loads:
        attribute = parents.get(id(node))
        comparison = (
            parents.get(id(attribute)) if isinstance(attribute, ast.Attribute) else None
        )
        assertion = (
            parents.get(id(comparison)) if isinstance(comparison, ast.Compare) else None
        )
        if not (
            isinstance(attribute, ast.Attribute)
            and attribute.value is node
            and isinstance(comparison, ast.Compare)
            and comparison.left is attribute
            and isinstance(assertion, ast.Assert)
        ):
            return None
    observed = [
        node
        for node in ast.walk(test_method)
        if isinstance(node, ast.Assert)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Attribute)
        and isinstance(node.test.left.value, ast.Name)
        and node.test.left.value.id == result.id
        and isinstance(node.test.comparators[0], ast.Constant)
        and node.test.comparators[0].value == expected_status
        and len(node.test.ops) == len(node.test.comparators) == 1
        and isinstance(node.test.ops[0], ast.Eq)
        and node.test.left.attr == "status"
    ]
    return observed[0] if len(observed) == 1 else None


def _app_test_header_signature_carrier(
    index, path, test_method, headers_call, signature_key, timestamp_key, body_actual
):
    from .review_integrity import bind_source_call

    carrier = _app_header_carrier_method(index, path, test_method, headers_call)
    if carrier is None:
        return None
    owner, method, bound, returns, mapping = carrier
    signature_list, timestamp_list = _app_header_signature_lists(
        mapping, signature_key, timestamp_key
    )
    if signature_list is None:
        return None
    signature_info = _app_header_signature_definition(
        owner, path, signature_list, timestamp_list, index
    )
    if signature_info is None:
        return None
    generated, generated_method, signature_formals, producer = signature_info
    try:
        signature_bound = bind_source_call(
            generated, generated_method, generated.func.value, apply_defaults=False
        )
    except (TypeError, ValueError):
        return None
    body_value = signature_bound.get(signature_formals[1].arg)
    time_value = signature_bound.get(signature_formals[2].arg)
    body_formal = signature_formals[1].arg
    time_formal = signature_formals[2].arg
    if (
        not isinstance(body_value, ast.Name)
        or body_value.id != body_formal
        or not isinstance(bound.get(body_formal), ast.Name)
        or not isinstance(body_actual, ast.Name)
        or bound[body_formal].id != body_actual.id
        or not isinstance(time_value, ast.Name)
        or time_value.id != time_formal
        or not isinstance(bound.get(time_formal), ast.Name)
        or timestamp_list.elts[0].id != time_formal
    ):
        return None
    return {
        "method": method,
        "mapping": returns,
        "signature_call": generated,
        "modeled_producer": producer,
        "signature_key": signature_key,
        "timestamp_key": timestamp_key,
        "body_formal": body_formal,
        "timestamp_formal": time_formal,
    }


def _app_header_carrier_method(index, path, test_method, headers_call):
    from .review_integrity import bind_source_call

    if not isinstance(headers_call, ast.Call) or not isinstance(
        headers_call.func, ast.Attribute
    ):
        return None
    owner = _legacy._fixture_scope(index, path, test_method, ast.ClassDef)
    if owner is None or not isinstance(headers_call.func.value, ast.Name):
        return None
    name = headers_call.func.attr
    methods = [
        node
        for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(methods) != 1 or _legacy.binding_occurrences(owner.body, name) != methods:
        return None
    method = methods[0]
    try:
        bound = bind_source_call(
            headers_call, method, headers_call.func.value, apply_defaults=False
        )
    except (TypeError, ValueError):
        return None
    returns = [node.value for node in method.body if isinstance(node, ast.Return)]
    if len(returns) != 1 or not isinstance(returns[0], ast.Dict):
        return None
    mapping = {}
    for key, value in zip(returns[0].keys, returns[0].values):
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            return None
        if key.value.lower() in {name.lower() for name in mapping} or not isinstance(
            value, ast.List
        ):
            return None
        mapping[key.value] = value
    return owner, method, bound, returns[0], mapping


def _app_header_signature_lists(mapping, signature_key, timestamp_key):
    signature_list, timestamp_list = (
        mapping.get(signature_key),
        mapping.get(timestamp_key),
    )
    if not (
        isinstance(signature_list, ast.List)
        and len(signature_list.elts) == 1
        and isinstance(timestamp_list, ast.List)
        and len(timestamp_list.elts) == 1
        and isinstance(timestamp_list.elts[0], ast.Name)
    ):
        return None, None
    return signature_list, timestamp_list


def _app_header_signature_definition(
    owner, path, signature_list, timestamp_list, index
):
    generated = signature_list.elts[0]
    if not isinstance(generated, ast.Call) or not isinstance(
        generated.func, ast.Attribute
    ):
        return None
    if not isinstance(generated.func.value, ast.Name):
        return None
    name = generated.func.attr
    methods = [
        node
        for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(methods) != 1 or _legacy.binding_occurrences(owner.body, name) != methods:
        return None
    method = methods[0]
    formals = [*method.args.posonlyargs, *method.args.args]
    if len(formals) < 3:
        return None
    returns = [node for node in method.body if isinstance(node, ast.Return)]
    if len(returns) != 1 or not isinstance(returns[0].value, ast.Call):
        return None
    producer = returns[0].value
    arguments = _app_signature_producer_arguments(producer)
    if arguments is None or not _app_signature_producer_matches(
        index, path, method, producer, formals, arguments
    ):
        return None
    return generated, method, formals, producer


def _app_signature_producer_arguments(producer):
    if len(producer.args) > 2:
        return None
    arguments = dict(zip(("body", "timestamp"), producer.args))
    for keyword in producer.keywords:
        if keyword.arg not in {"body", "timestamp"} or keyword.arg in arguments:
            return None
        arguments[keyword.arg] = keyword.value
    return arguments


def _app_signature_producer_matches(index, path, method, producer, formals, arguments):
    values = list(arguments.values())
    receiver = producer.func.value if isinstance(producer.func, ast.Attribute) else None
    return (
        isinstance(producer.func, ast.Attribute)
        and producer.func.attr == "generate_signature"
        and isinstance(receiver, ast.Attribute)
        and isinstance(receiver.value, ast.Name)
        and receiver.value.id == formals[0].arg
        and _app_signing_slot_read(receiver, method, index["source"].parents[path])
        and not _legacy._call_has_expansion(producer)
        and len(values) == 2
        and all(isinstance(item, ast.Name) for item in values)
        and set(arguments) == {"body", "timestamp"}
        and arguments["body"].id == formals[1].arg
        and arguments["timestamp"].id == formals[2].arg
    )


def _app_request_verification_prefix_closed(
    index, path, method, request, condition, reads
):
    """Reject bypasses and intervening writes on the selected request path."""
    from .finite_capture import captured_scalar_guard

    parents = index["source"].parents[path]
    owner = parents.get(id(method))
    if not isinstance(owner, ast.ClassDef) or len(method.body) != 5:
        return False
    skip = method.body[0]
    if not (
        isinstance(skip, ast.If)
        and not skip.orelse
        and len(skip.body) == 1
        and isinstance(skip.body[0], ast.Return)
        and isinstance(skip.test, ast.Call)
        and not _legacy._call_has_expansion(skip.test)
        and isinstance(skip.test.func, ast.Attribute)
        and isinstance(skip.test.func.value, ast.Name)
        and skip.test.func.value.id == method.args.args[0].arg
        and len(skip.test.args) == 2
        and not skip.test.keywords
        and isinstance(skip.test.args[0], ast.Attribute)
        and isinstance(skip.test.args[0].value, ast.Name)
        and skip.test.args[0].value.id == request
        and skip.test.args[0].attr == "mode"
        and method.body[1:4] == list(reads)
        and method.body[4] is condition
    ):
        return False
    members = _legacy.binding_occurrences(owner.body, skip.test.func.attr)
    if len(members) != 1 or not isinstance(members[0], ast.FunctionDef):
        return False
    helper = members[0]
    parameters = [*helper.args.posonlyargs, *helper.args.args]
    if not (
        len(parameters) == 2
        and len(helper.body) == 1
        and isinstance(helper.body[0], ast.Return)
        and len(helper.decorator_list) == 1
        and isinstance(helper.decorator_list[0], ast.Name)
        and helper.decorator_list[0].id == "staticmethod"
        and _app_signing_terminal_stable(index, "builtins.staticmethod")
    ):
        return False
    return (
        captured_scalar_guard(
            helper.body[0].value,
            {parameters[0].arg: "http"},
            lambda node: _app_builtin_annotation_inert(index, path, node),
        )
        is False
    )


def _app_literal_branch_field_transfer(
    index, path, constructor, bound, caller_path, caller, field
):
    from .finite_capture import captured_literal_branch_field_transfer

    return captured_literal_branch_field_transfer(
        index["source"],
        path,
        constructor,
        bound,
        caller_path,
        caller,
        field,
        lambda node: _app_builtin_annotation_inert(index, path, node),
    )


def _app_signing_null_fallback(node, parent, parents, formal):
    if isinstance(parent, ast.Compare) and parent.left is node:
        return bool(
            len(parent.ops) == 1
            and isinstance(parent.ops[0], ast.Is)
            and len(parent.comparators) == 1
            and isinstance(parent.comparators[0], ast.Constant)
            and parent.comparators[0].value is None
        )
    if not isinstance(node.ctx, ast.Store):
        return False
    statement = parent
    branch = parents.get(id(statement))
    return bool(
        isinstance(statement, ast.Assign)
        and statement.targets == [node]
        and isinstance(branch, ast.If)
        and branch.body == [statement]
        and not branch.orelse
        and isinstance(branch.test, ast.Compare)
        and isinstance(branch.test.left, ast.Name)
        and branch.test.left.id == formal
        and _app_signing_null_fallback(branch.test.left, branch.test, parents, formal)
    )


def _app_signing_field_consumers(index, path, owner, field, declaration, seen):
    source = index["source"]
    parents = source.parents[path]
    rows = []
    for node in ast.walk(owner):
        if not isinstance(node, ast.Attribute) or node.attr != field:
            continue
        statement = parents.get(id(node))
        if statement is declaration and _legacy.assignment_target(statement) is node:
            continue
        function = _legacy._enclosing_function(node, parents)
        args = [*function.args.posonlyargs, *function.args.args] if function else []
        if not (
            args
            and isinstance(node.value, ast.Name)
            and node.value.id == args[0].arg
            and isinstance(node.ctx, ast.Load)
        ):
            return None
        call = (
            parents.get(id(statement))
            if isinstance(statement, ast.keyword)
            else statement
        )
        edge = _app_signing_constructor_flow(index, path, function, call, node, seen)
        if edge is None:
            return None
        if (
            len(edge) == 1
            and edge[0]["role"] == "modeled_signature_key_constructor"
            and not _app_terminal_verifier_operations(index, path, function, call)
        ):
            capability = _app_verifier_property_flow(index, path, owner, function, call)
            if capability is None:
                return None
            edge.extend(capability)
        rows.extend(edge)
    return rows


def _app_verifier_property_flow(index, path, owner, getter, constructor):
    """Follow a lazy field only through its exact property and verifier reads."""
    parents = index["source"].parents[path]
    args = [*getter.args.posonlyargs, *getter.args.args]
    statement = parents.get(id(constructor))
    target = _legacy.assignment_target(statement)
    if not (
        len(args) == 1
        and not getter.args.kwonlyargs
        and not getter.args.vararg
        and not getter.args.kwarg
        and len(getter.decorator_list) == 1
        and isinstance(getter.decorator_list[0], ast.Name)
        and getter.decorator_list[0].id == "property"
        and not _legacy.binding_occurrences(owner.body, "property")
        and not _legacy.binding_occurrences(index["modules"][path].body, "property")
        and _app_signing_terminal_stable(index, "builtins.property")
        and isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name)
        and target.value.id == args[0].arg
    ):
        return None
    if not _app_verifier_property_header(index, path, getter):
        return None
    if not _app_verifier_lazy_body(getter, statement, target.attr, args[0].arg):
        return None
    if not _app_verifier_field_uses(index, path, owner, getter, target.attr):
        return None
    uses = _app_verifier_property_uses(index, path, owner, getter)
    if not uses:
        return None
    return [
        _app_credential_source_row(
            index, path, getter, "captured_verifier_property", getter.name
        ),
        *(
            _app_credential_source_row(
                index, path, call, "captured_signature_verification"
            )
            for call in uses
        ),
    ]


def _app_verifier_property_header(index, path, getter):
    from . import mock_fixture_provenance as fixture

    if getter.args.defaults or any(
        value is not None for value in getter.args.kw_defaults
    ):
        return False
    annotations = [
        arg.annotation
        for arg in (*getter.args.posonlyargs, *getter.args.args)
        if arg.annotation is not None
    ]
    if getter.returns is not None:
        annotations.append(getter.returns)
    return all(
        _app_metadata_annotation_inert(index, path, annotation)
        or (
            fixture._app_expression_name(index, path, annotation)
            == "slack_sdk.signature.SignatureVerifier"
            and not fixture._django_provider_root_shadowed(
                index["module_paths"], "slack_sdk"
            )
            and _app_signing_terminal_stable(
                index, "slack_sdk.signature.SignatureVerifier"
            )
        )
        for annotation in annotations
    )


def _app_verifier_lazy_body(getter, statement, field, receiver):
    body = [
        node
        for node in getter.body
        if not isinstance(node, ast.Expr)
        or not isinstance(node.value, ast.Constant)
        or not isinstance(node.value.value, str)
    ]
    if (
        len(body) != 2
        or not isinstance(body[0], ast.If)
        or not isinstance(body[1], ast.Return)
    ):
        return False
    branch, returned = body
    test = branch.test
    return bool(
        branch.body == [statement]
        and not branch.orelse
        and isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Is)
        and len(test.comparators) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value is None
        and _app_receiver_field(test.left, receiver, field, ast.Load)
        and _app_receiver_field(returned.value, receiver, field, ast.Load)
        and not _legacy.binding_occurrences(getter.body, receiver)
    )


def _app_receiver_field(node, receiver, field, context):
    return bool(
        isinstance(node, ast.Attribute)
        and node.attr == field
        and isinstance(node.ctx, context)
        and isinstance(node.value, ast.Name)
        and node.value.id == receiver
    )


def _app_verifier_field_uses(index, path, owner, getter, field):
    parents = index["source"].parents[path]
    for node in ast.walk(owner):
        if not isinstance(node, ast.Attribute) or node.attr != field:
            continue
        function = _legacy._enclosing_function(node, parents)
        if function is getter:
            continue  # The full getter statement/return shape was already matched.
        args = [*function.args.posonlyargs, *function.args.args] if function else []
        statement = parents.get(id(node))
        if not (
            function
            and function.name == "__init__"
            and args
            and _app_receiver_field(node, args[0].arg, field, ast.Store)
            and isinstance(statement, (ast.Assign, ast.AnnAssign))
            and _legacy.assignment_target(statement) is node
            and isinstance(statement.value, ast.Constant)
            and statement.value.value is None
        ):
            return False
    return True


def _app_verifier_property_uses(index, path, owner, getter):
    parents = index["source"].parents[path]
    verified = []
    for node in ast.walk(owner):
        if not isinstance(node, ast.Attribute) or node.attr != getter.name:
            continue
        function = _legacy._enclosing_function(node, parents)
        args = [*function.args.posonlyargs, *function.args.args] if function else []
        operation = parents.get(id(node))
        call = parents.get(id(operation))
        if not (
            args
            and _app_receiver_field(node, args[0].arg, getter.name, ast.Load)
            and _app_signing_slot_read(node, function, parents)
            and isinstance(operation, ast.Attribute)
            and operation.attr == "is_valid"
            and isinstance(call, ast.Call)
            and call.func is operation
            and _app_signature_verification_arguments(call) is not None
        ):
            return None
        verified.append(call)
    return verified


def _app_signature_verification_arguments(call):
    if _legacy._call_has_expansion(call) or len(call.args) > 3:
        return None
    arguments = dict(zip(("body", "timestamp", "signature"), call.args))
    for keyword in call.keywords:
        if (
            keyword.arg not in {"body", "timestamp", "signature"}
            or keyword.arg in arguments
        ):
            return None
        arguments[keyword.arg] = keyword.value
    return arguments if set(arguments) == {"body", "timestamp", "signature"} else None


def _app_object_signing_uses(index, path, owner, assignment, secret):
    """Keep unsupported capability owners active until their lifetime closes."""
    from . import mock_fixture_provenance as fixture

    references = _app_object_origin_references(index, path, owner, assignment, secret)
    if references is None:
        return None
    parents = index["source"].parents[path]
    uses = _app_object_secret_uses(index, path, owner, secret, references)
    if not uses:
        return None
    for method in owner.body:
        if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if fixture._app_has_dynamic_scope(
            index, path, method, list(ast.walk(method))
        ) or not _app_object_owner_receiver_closed(method, parents):
            return None
    return uses


def _app_object_origin_references(index, path, owner, assignment, secret):
    if (
        not owner.name.startswith("Test")
        or owner.bases
        or owner.keywords
        or owner.decorator_list
    ):
        return None
    if any(
        _legacy.binding_occurrences(owner.body, name)
        for name in (*_legacy._HOOKS, "__init__")
    ):
        return None
    references = _app_signing_source_references(index)
    if references is None or not _app_signing_origin_namespace_private(
        index, path, references[2]
    ):
        return None
    if any(
        _app_signing_class_export(n, owner)
        for _, n in references[0].get(owner.name, ())
    ):
        return None
    if _legacy.binding_occurrences(owner.body, secret) != [
        assignment.targets[0]
        if isinstance(assignment, ast.Assign)
        else assignment.target
    ]:
        return None
    return references


def _app_object_secret_uses(index, path, owner, secret, references):
    parents = index["source"].parents[path]
    uses = []
    for other_path, node in [
        *references[0].get(secret, ()),
        *references[1].get(secret, ()),
    ]:
        if not isinstance(node.ctx, ast.Load):
            if isinstance(node, ast.Attribute):
                return None
            continue
        if other_path != path:
            continue  # Declaring namespace cannot be imported; unrelated slots are distinct.
        function = _legacy._enclosing_function(node, parents)
        if isinstance(node, ast.Name):
            if _legacy._fixture_scope(index, path, node, ast.ClassDef) is not owner:
                if function is None:
                    return None
                continue
        elif (
            not function
            or parents.get(id(function)) is not owner
            or not _app_signing_slot_read(node, function, parents)
        ):
            return None
        if function is not None and not function.name.startswith("test_"):
            return None
        uses.append((function, node))
    return uses if uses else None


def _app_object_owner_receiver_closed(method, parents):
    args = [*method.args.posonlyargs, *method.args.args]
    if not args:
        return False
    return all(
        isinstance(parents.get(id(n)), ast.Attribute)
        and parents[id(n)].value is n
        and not parents[id(n)].attr.startswith("__")
        for n in ast.walk(method)
        if isinstance(n, ast.Name)
        and n.id == args[0].arg
        and isinstance(n.ctx, ast.Load)
    )


def _app_object_signing_pair(index, path, owner, operations):
    source = index["source"]
    parents = source.parents[path]
    signers, verifiers = [], []
    for function, call, rows in operations:
        if (
            function is None
            and len(rows) == 1
            and rows[0]["role"] == "modeled_signature_key_constructor"
        ):
            statement = parents.get(id(call))
            target = _legacy.assignment_target(statement)
            if (
                not isinstance(target, ast.Name)
                or parents.get(id(statement)) is not owner
            ):
                return False
            signers.append(target.id)
        elif function is not None and function.name.startswith("test_"):
            verified = _app_object_verifier_receiver_closed(
                index, path, function, call, rows
            )
            if not verified:
                return False
            verifiers.extend(
                (function, operation, payload, rows, projection)
                for operation, payload, projection in verified
            )
        else:
            return False
    return _app_object_pair_results_closed(index, path, owner, signers, verifiers)


def _app_object_pair_results_closed(index, path, owner, signers, verifiers):
    from .finite_capture import captured_value_use_closure

    parents = index["source"].parents[path]
    if not signers or not verifiers:
        return False
    generated = []
    for field in signers:
        calls = _app_object_signer_receiver_closed(index, path, owner, field)
        if not calls:
            return False
        generated.extend(calls)
    required = [
        row for row in verifiers if not row[4] or not row[4].get("fixed_request")
    ]
    inputs = {id(payload): call for _, call, payload, _, _ in required}
    request_inputs = {
        id(projection["request_actual"]): call
        for _, call, _, _, projection in required
        if projection is not None
    }
    consumed = set()
    for call in generated:
        result = captured_value_use_closure(
            _legacy._enclosing_function(call, parents),
            call,
            parents,
            lambda node: _legacy._enclosing_function(node, parents),
            lambda function: _app_signing_helper_callers(
                index, path, owner, function, generated
            ),
            lambda function, value: inputs.get(id(value))
            or request_inputs.get(id(value)),
        )
        if result is None:
            return False
        consumed.update(id(node) for node in result["sinks"])
    return bool(required) and consumed == {id(call) for _, call, _, _, _ in required}


def _app_signing_helper_callers(index, path, owner, function, terminal_calls=()):
    """Only source-bound, unexported helper returns may cross test methods."""
    from .review_integrity import bind_source_call

    if function.name.startswith("test_") or not _app_metadata_header_inert(
        index, path, function
    ):
        return None
    if _legacy.binding_occurrences(owner.body, function.name) != [function]:
        return None
    parents = index["source"].parents[path]
    result = []
    for node in ast.walk(owner):
        if not isinstance(node, ast.Attribute) or node.attr != function.name:
            continue
        caller = _legacy._enclosing_function(node, parents)
        call = parents.get(id(node))
        if any(call is terminal for terminal in terminal_calls):
            continue
        if not (
            caller
            and parents.get(id(caller)) is owner
            and _app_signing_slot_read(node, caller, parents)
            and isinstance(call, ast.Call)
            and call.func is node
            and not _legacy._call_has_expansion(call)
        ):
            return None
        try:
            bind_source_call(call, function, node.value, apply_defaults=False)
        except (TypeError, ValueError):
            return None
        result.append((caller, call))
    return result or None


def _app_object_signer_receiver_closed(index, path, owner, field):
    parents = index["source"].parents[path]
    found = []
    for node in ast.walk(owner):
        if not isinstance(node, ast.Attribute) or node.attr != field:
            continue
        function = _legacy._enclosing_function(node, parents)
        operation = parents.get(id(node))
        call = parents.get(id(operation))
        if not (
            function
            and _app_signing_slot_read(node, function, parents)
            and isinstance(operation, ast.Attribute)
            and operation.attr == "generate_signature"
            and isinstance(call, ast.Call)
            and call.func is operation
        ):
            return None
        found.append(call)
    return found


def _app_object_verifier_receiver_closed(index, path, function, constructor, rows):
    from . import mock_fixture_provenance as fixture

    parents = index["source"].parents[path]
    statement = parents.get(id(constructor))
    target = _legacy.assignment_target(statement)
    if (
        not isinstance(target, ast.Name)
        or fixture._app_local_assignment(function, target.id) is not statement
    ):
        return None
    selected = fixture._app_source_symbol(index, path, constructor.func, function)
    if selected is None:
        return None
    verified = []
    for node in ast.walk(function):
        if (
            not isinstance(node, ast.Name)
            or node.id != target.id
            or not isinstance(node.ctx, ast.Load)
        ):
            continue
        use = _app_object_verifier_use(
            index, path, function, node, target.id, selected, rows, parents
        )
        if use is None:
            return None
        verified.append(use)
    return verified


def _app_object_verifier_use(
    index, path, function, node, receiver_name, selected, rows, parents
):
    operation = parents.get(id(node))
    call = parents.get(id(operation))
    if (
        _legacy._enclosing_function(node, parents) is not function
        or not isinstance(operation, ast.Attribute)
        or not isinstance(operation.ctx, ast.Load)
        or operation.attr.startswith("_")
        or not isinstance(call, ast.Call)
        or call.func is not operation
    ):
        return None
    method = next(
        (
            item
            for item in selected[1].body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == operation.attr
        ),
        None,
    )
    fields = {
        row["name"]
        for row in rows
        if row["role"] in {"captured_key_field_transfer", "captured_verifier_property"}
    }
    if method is None or _app_object_method_exports_receiver(method, fields):
        return None
    if not _app_called_receiver_uses_closed(selected[1], method):
        return None
    return _app_object_verifier_result(
        index, path, function, call, selected, method, rows, parents
    )


def _app_object_verifier_result(
    index, path, function, call, selected, method, rows, parents
):
    projection = _app_request_verification_projection(
        index, path, function, call, selected[0], method, rows
    )
    if projection is not None:
        return call, projection["signature_value"], projection
    fixed = _app_fixed_verification_request(
        index, path, function, call, selected[0], method, rows
    )
    if fixed is not None:
        return call, None, fixed
    payload = _app_object_verified_payload(index, call, selected[0], method, rows)
    if payload is None or not isinstance(parents.get(id(call)), ast.Assert):
        return None
    return call, payload, None


def _app_fixed_verification_request(
    index, path, function, call, method_path, method, rows
):
    """Close additional negative verifier cases with wholly literal request data."""
    request_input = _app_fixed_request_literal_input(
        index, path, function, call, method
    )
    if request_input is None:
        return None
    parameters, bound, request = request_input
    verification = _app_fixed_request_verifier(
        index, method_path, method, rows, parameters[1].arg
    )
    if verification is None:
        return None
    if (
        _app_request_success_observation(
            index, path, function, call, parameters[3].arg, bound, 401
        )
        is None
    ):
        return None
    return {
        "fixed_request": True,
        "request_actual": request,
        "verification": verification,
    }


def _app_fixed_request_literal_input(index, path, function, call, method):
    from . import mock_fixture_provenance as fixture
    from .review_integrity import bind_source_call

    parameters = [*method.args.posonlyargs, *method.args.args, *method.args.kwonlyargs]
    if len(parameters) != 4 or not isinstance(call.func, ast.Attribute):
        return None
    bound = bind_source_call(call, method, call.func.value, apply_defaults=False)
    request = bound.get(parameters[1].arg)
    if not isinstance(request, ast.Name):
        return None
    statement = fixture._app_local_assignment(function, request.id)
    if statement is None or not isinstance(statement.value, ast.Call):
        return None
    raw = _app_bound_field_transfer(index, path, statement.value, function, "raw_body")
    headers = _app_bound_field_transfer(
        index, path, statement.value, function, "headers"
    )
    if (
        raw is None
        or headers is None
        or _app_header_list_transfer(index, headers) is None
    ):
        return None
    if not isinstance(raw["actual"], ast.Constant) or not isinstance(
        raw["actual"].value, str
    ):
        return None
    mapping = headers["actual"]
    if not isinstance(mapping, ast.Dict) or len(list(ast.walk(mapping))) > 128:
        return None
    try:
        literal = ast.literal_eval(mapping)
    except (ValueError, TypeError, SyntaxError):
        return None
    if not all(
        isinstance(key, str)
        and isinstance(value, list)
        and all(isinstance(item, str) for item in value)
        for key, value in literal.items()
    ):
        return None
    if any(
        node is not request
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id == request.id
        and isinstance(node.ctx, ast.Load)
    ):
        return None
    return parameters, bound, request


def _app_fixed_request_verifier(index, method_path, method, rows, request_formal):
    verified = _app_property_verification_operations(index, method_path, method, rows)
    if len(verified) != 1:
        return None
    verify_call = verified[0][0]
    condition = index["source"].parents[method_path].get(id(verify_call))
    body = _app_process_body_read(method, request_formal)
    arguments = _app_signature_verification_arguments(verify_call)
    if (
        body is None
        or arguments is None
        or not all(
            isinstance(arguments[name], ast.Name)
            for name in ("body", "timestamp", "signature")
        )
    ):
        return None
    time_read = _app_process_header_read(
        method, request_formal, arguments["timestamp"].id
    )
    signature_read = _app_process_header_read(
        method, request_formal, arguments["signature"].id
    )
    if (
        time_read is None
        or signature_read is None
        or not _app_request_verification_prefix_closed(
            index,
            method_path,
            method,
            request_formal,
            condition,
            (body["statement"], time_read["statement"], signature_read["statement"]),
        )
    ):
        return None
    return verify_call


def _app_called_receiver_uses_closed(owner, method, active=()):
    """Close raw receiver exports in source-bound methods called by the selected method."""
    if id(method) in active or len(active) >= 8:
        return False
    args = [*method.args.posonlyargs, *method.args.args]
    if not args or _legacy.binding_occurrences(method.body, args[0].arg):
        return False
    parents = {
        id(child): node
        for node in ast.walk(method)
        for child in ast.iter_child_nodes(node)
    }
    for node in ast.walk(method):
        if (
            not isinstance(node, ast.Name)
            or node.id != args[0].arg
            or not isinstance(node.ctx, ast.Load)
        ):
            continue
        if not _app_receiver_attribute_use_closed(owner, method, node, parents, active):
            return False
    return True


def _app_receiver_attribute_use_closed(owner, method, node, parents, active):
    member = parents.get(id(node))
    if not isinstance(member, ast.Attribute) or member.attr.startswith("__"):
        return False
    definitions = _legacy.binding_occurrences(owner.body, member.attr)
    if len(definitions) != 1 or not isinstance(definitions[0], ast.FunctionDef):
        return True
    target = definitions[0]
    property_read = (
        len(target.decorator_list) == 1
        and isinstance(target.decorator_list[0], ast.Name)
        and target.decorator_list[0].id == "property"
    )
    called = parents.get(id(member))
    if not property_read and (
        not isinstance(called, ast.Call) or called.func is not member
    ):
        return False
    if not target.decorator_list or property_read:
        return _app_called_receiver_uses_closed(owner, target, (*active, id(method)))
    return (
        len(target.decorator_list) == 1
        and isinstance(target.decorator_list[0], ast.Name)
        and target.decorator_list[0].id == "staticmethod"
    )


def _app_object_verified_payload(index, call, path, method, rows):
    """Bind a captured boolean verification result to its exact signature input."""
    from .review_integrity import bind_source_call

    source = index["source"]
    parents = source.parents[path]
    terminals = {
        tuple(row["span"])
        for row in rows
        if row["role"] == "modeled_signature_key_constructor"
        and row["path"] == source.relative(path)
    }
    calls = [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and _legacy._enclosing_function(node, parents) is method
        and (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)
        in terminals
    ]
    if method.decorator_list or _legacy._call_has_expansion(call):
        return None
    verified = (
        _app_terminal_verifier_operations(index, path, method, calls[0])
        if len(calls) == 1
        else _app_property_verification_operations(index, path, method, rows)
    )
    returns = [node for node in ast.walk(method) if isinstance(node, ast.Return)]
    if (
        not verified
        or len(returns) != 1
        or returns[0].value not in [c for c, _ in verified]
    ):
        return None
    payloads = [payload for _, payload in verified]
    if not all(isinstance(payload, ast.Name) for payload in payloads):
        return None
    formal = payloads[0].id
    if any(payload.id != formal for payload in payloads):
        return None
    allowed = {id(payload) for payload in payloads}
    if any(
        id(node) not in allowed
        for node in ast.walk(method)
        if isinstance(node, ast.Name) and node.id == formal
    ):
        return None
    try:
        bound = bind_source_call(call, method, call.func.value, apply_defaults=False)
    except (TypeError, ValueError):
        return None
    return bound.get(formal)


def _app_property_verification_operations(index, path, method, rows):
    source = index["source"]
    spans = {
        tuple(row["span"])
        for row in rows
        if row["role"] == "captured_signature_verification"
        and row["path"] == source.relative(path)
    }
    calls = [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)
        in spans
    ]
    return [
        (call, _app_signature_verification_arguments(call)["signature"])
        for call in calls
    ]


def _app_terminal_verifier_operations(index, path, function, constructor):
    """A key-bearing terminal object may only perform boolean verification."""
    from . import mock_fixture_provenance as fixture

    parents = index["source"].parents[path]
    statement = parents.get(id(constructor))
    target = _legacy.assignment_target(statement)
    if (
        not isinstance(target, ast.Name)
        or fixture._app_local_assignment(function, target.id) is not statement
    ):
        return None
    verified = []
    for node in ast.walk(function):
        if (
            not isinstance(node, ast.Name)
            or node.id != target.id
            or not isinstance(node.ctx, ast.Load)
        ):
            continue
        operation = parents.get(id(node))
        call = parents.get(id(operation))
        if not (
            _legacy._enclosing_function(node, parents) is function
            and isinstance(operation, ast.Attribute)
            and operation.attr == "is_valid"
            and isinstance(call, ast.Call)
            and call.func is operation
            and not _legacy._call_has_expansion(call)
            and len(call.args) <= 3
        ):
            return None
        arguments = _app_signature_verification_arguments(call)
        if arguments is None:
            return None
        verified.append((call, arguments["signature"]))
    return verified or None


def _app_object_method_exports_receiver(method, fields):
    args = [*method.args.posonlyargs, *method.args.args]
    if not args:
        return True
    parents = {
        id(child): parent
        for parent in ast.walk(method)
        for child in ast.iter_child_nodes(parent)
    }
    return any(
        not _app_object_receiver_projection_closed(
            parents.get(id(node)), fields, parents
        )
        for node in ast.walk(method)
        if isinstance(node, ast.Name)
        and node.id == args[0].arg
        and isinstance(node.ctx, ast.Load)
    )


def _app_object_receiver_projection_closed(projection, fields, parents):
    """A bound method retains its key-bearing receiver even without raw self."""
    if not isinstance(projection, ast.Attribute):
        return False
    if isinstance(projection.ctx, ast.Store) or projection.attr in fields:
        return True
    call = parents.get(id(projection))
    return isinstance(call, ast.Call) and call.func is projection


def _app_object_signing_witness(index, path, owner, assignment, secret, uses, rows):
    from . import mock_fixture_provenance as fixture

    source = index["source"]
    return {
        "eligible": True,
        "classification": "APPLICATION_TEST_CREDENTIAL_ROLE",
        "source": source.relative(path),
        "source_sha256": source.inventory[path],
        "declaration_span": fixture._evidence_node_span(assignment),
        "profile": "LOCAL_SOURCE_SIGNING_AUTHORITY",
        "runtime_assurance": "INCOMPLETE",
        "transport_role": "UNASSESSED",
        "target_execution": "not_performed",
        "isolation_assurance": "UNASSESSED",
        "modeled_api_assumption": "Unmodified slack_sdk.signature.SignatureVerifier models signature generation and verification; ABCMeta is modeled as non-transforming. Captured constructor/field consumers and closed test-owned capabilities are checked statically; runtime, deployment and transport assurance remain incomplete.",
        "witness_sources": rows,
        "consumer_use_closure": {
            "schema": "factory.test-authority-consumer-closure.v1",
            "complete": True,
            "origin": _app_credential_source_row(
                index, path, assignment, "synthetic_signing_origin", secret
            ),
            "owner": _app_credential_source_row(
                index, path, owner, "test_owner", owner.name
            ),
            "consumers": [
                _app_credential_source_row(
                    index, path, node, "signing_key_consumer", secret
                )
                for _, node in uses
            ],
        },
    }


def _app_signing_authority(index, path, assignment, secret):
    """Prove one source-owned key crosses closed signing/verification edges."""
    from . import mock_fixture_provenance as fixture

    source = index["source"]
    if not source.validate(path):
        return None
    selected = _app_signing_origin_scopes(index, path, assignment, secret)
    if selected is None:
        return None
    owner, scopes = selected
    witnesses, loads = [], []
    for function, uses in scopes:
        rows = _app_signing_scope_edges(index, path, function, uses)
        if rows is None:
            return None
        witnesses.extend(rows)
        loads.extend(uses)
    if not loads:
        return None
    digest = any(row.get("role") == "captured_pure_digest_wrapper" for row in witnesses)
    if digest and fixture._app_known_credential_format(
        getattr(assignment.value, "value", "")
    ):
        return None
    origin = _app_credential_source_row(
        index, path, assignment, "synthetic_signing_origin", secret
    )
    return {
        "eligible": True,
        "classification": "APPLICATION_TEST_CREDENTIAL_ROLE",
        "source": source.relative(path),
        "source_sha256": source.inventory[path],
        "declaration_span": fixture._evidence_node_span(assignment),
        "profile": "SOURCE_BOUND_DIGEST_TEST_AUTHORITY"
        if digest
        else "LOCAL_SOURCE_SIGNING_AUTHORITY",
        "runtime_assurance": "INCOMPLETE",
        "transport_role": "UNASSESSED",
        "target_execution": "not_performed",
        "isolation_assurance": "UNASSESSED",
        "modeled_api_assumption": "Stable PyJWT signing/verification or HMAC digest boundaries, captured test-owned key flow and closed result consumers; no runtime or deployment guarantee.",
        "witness_sources": witnesses,
        "consumer_use_closure": {
            "schema": "factory.test-authority-consumer-closure.v1",
            "complete": True,
            "origin": origin,
            "owner": _app_credential_source_row(
                index, path, owner, "test_owner", owner.name
            ),
            "consumers": [
                _app_credential_source_row(
                    index, path, n, "signing_key_consumer", secret
                )
                for n in loads
            ],
        },
    }


def _app_signing_origin_scopes(index, path, assignment, secret):
    """Keep scalar origins separate from their exact lexical consumers."""
    from . import mock_fixture_provenance as fixture

    source = index["source"]
    parents = source.parents[path]
    owner = parents.get(id(assignment))
    if isinstance(owner, ast.ClassDef):
        return _app_class_signing_scopes(index, path, owner, assignment, secret)
    if not isinstance(
        owner, (ast.FunctionDef, ast.AsyncFunctionDef)
    ) or not owner.name.startswith("test_"):
        return None
    if fixture._app_local_assignment(
        owner, secret
    ) is not assignment or not _app_factory_test_decorators(index, path, owner):
        return None
    nodes = list(ast.walk(owner))
    if len(nodes) > 1024 or fixture._app_has_dynamic_scope(index, path, owner, nodes):
        return None
    loads = [
        n
        for n in nodes
        if isinstance(n, ast.Name) and n.id == secret and isinstance(n.ctx, ast.Load)
    ]
    if any(_legacy._enclosing_function(n, parents) is not owner for n in loads):
        return None
    return owner, [(owner, loads)]


def _app_class_signing_scopes(index, path, owner, assignment, secret):
    """Close a class slot before applying any consumer API model.

    A test-class name is not a benign-role proof. Explicit class exports,
    instance escapes, inheritance, hooks, writes and unbound consumers decline.
    """
    from . import mock_fixture_provenance as fixture

    if (
        not owner.name.startswith("Test")
        or owner.bases
        or owner.keywords
        or owner.decorator_list
        or _legacy.binding_occurrences(index["modules"][path].body, owner.name)
        != [owner]
        or _legacy.binding_occurrences(owner.body, secret)
        != [
            assignment.targets[0]
            if isinstance(assignment, ast.Assign)
            else assignment.target
        ]
        or any(
            _legacy.binding_occurrences(owner.body, name)
            for name in (*_legacy._HOOKS, "__init__")
        )
        or _legacy._fixture_reflective_uses(
            index, path, assignment, secret, all_sources=True
        )
    ):
        return None
    source = index["source"]
    parents = source.parents[path]
    methods = {
        node: []
        for node in owner.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    if not _app_signing_class_uses(index, path, owner, secret, methods):
        return None
    selected = []
    for function, uses in methods.items():
        if _legacy._definition_effects_unknown(
            function
        ) or not _app_signing_owner_closed(function, parents, secret):
            return None
        if not uses:
            continue
        if (
            not function.name.startswith("test_")
            or not _app_factory_test_decorators(index, path, function)
            or len(list(ast.walk(function))) > 1024
            or fixture._app_has_dynamic_scope(
                index, path, function, list(ast.walk(function))
            )
        ):
            return None
        selected.append((function, uses))
    return (owner, selected) if selected else None


def _app_signing_source_references(index):
    """Build one generation-bound reference view, shared by class-slot demands."""
    from . import review_audits as audit

    key = ("signing-source-references", _app_source_role_epoch(index))
    cache = index.setdefault("profiles", {})
    if key in cache:
        return cache[key]
    names, members, imports = {}, {}, []
    for path, tree in index["modules"].items():
        if not index["source"].validate(path):
            return None
        nodes = list(ast.walk(tree))
        if not _app_signing_namespace_providers_closed(index, path, tree, nodes, audit):
            return None
        for node in nodes:
            if isinstance(node, ast.Name):
                names.setdefault(node.id, []).append((path, node))
            elif isinstance(node, ast.Attribute):
                members.setdefault(node.attr, []).append((path, node))
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                imports.append((path, node))
    cache[key] = names, members, imports
    return cache[key]


def _app_signing_namespace_providers_closed(index, path, tree, nodes, audit):
    """Reuse importer/capability facts; unclosed module-table access declines."""
    from .finite_capture import (
        _shell_dynamic_provider_access,
        _shell_namespace_queries_closed,
    )

    parents = index["source"].parents[path]
    aliases, mutations, star = _legacy._class_binding._presentation_provider_facts(
        tree, _app_namespace_projected_nodes(nodes, parents), parents, audit
    )
    return not (
        star
        or _shell_dynamic_provider_access(nodes, aliases, audit, parents, "")
        or not _shell_namespace_queries_closed(nodes, aliases, audit, parents, "")
        or _app_signing_namespace_projection(nodes)
        or any(
            provider in {"sys", "builtins", "importlib"} and member == "*"
            for provider, member in mutations
        )
        or any(
            isinstance(node, (ast.Name, ast.Attribute))
            and audit._resolved_ast_name(node, aliases) == "sys.modules"
            for node in nodes
        )
    )


def _app_namespace_projected_nodes(nodes, parents):
    """A passed field is a capability to that field, not its namespace prefix.

    Assignment and reflective-write records retain their full AST operands;
    only duplicate prefix occurrences in expression walks are omitted here.
    """
    return [
        node
        for node in nodes
        if not (
            isinstance(node, (ast.Name, ast.Attribute))
            and isinstance(parents.get(id(node)), ast.Attribute)
            and parents[id(node)].value is node
        )
    ]


def _app_signing_namespace_projection(nodes):
    """Unresolved frame or object namespaces can recover the declaring class."""
    return any(
        isinstance(node, ast.Name)
        and node.id == "__builtins__"
        or isinstance(node, ast.Attribute)
        and (
            node.attr
            in {
                "__subclasses__",
                "__mro__",
                "__bases__",
                "__base__",
                "__getattribute__",
                "__getattr__",
                "__dict__",
                "__globals__",
            }
            or node.attr
            in {
                "f_locals",
                "f_globals",
                "f_builtins",
                "gi_frame",
                "cr_frame",
                "ag_frame",
                "tb_frame",
            }
        )
        for node in nodes
    )


def _app_signing_origin_namespace_private(index, path, imports):
    """A declaring module import exposes its class namespace until closed."""
    from . import mock_fixture_provenance as fixture

    origin = fixture._django_name(index, path)
    if not origin:
        return False
    for other_path, statement in imports:
        module = fixture._django_name(index, other_path)
        if not module:
            return False
        package = (
            module
            if index["source"].relative(other_path).endswith("/__init__.py")
            else module.rpartition(".")[0]
        )
        rows = fixture._django_import_rows(statement, package)
        if rows is None or any(
            origin == target
            or origin.startswith(target + ".")
            or target.startswith(origin + ".")
            for _, target in rows
        ):
            return False
    return True


def _app_signing_class_uses(index, path, owner, secret, methods):
    references = _app_signing_source_references(index)
    if references is None:
        return False
    names, members, imports = references
    if not _app_signing_origin_namespace_private(index, path, imports) or any(
        _app_signing_class_export(node, owner)
        for node in [
            *(node for _, node in names.get(owner.name, ())),
            *(node for _, node in imports),
        ]
    ):
        return False
    parents = index["source"].parents[path]
    for other_path, node in members.get(secret, ()):
        function = _legacy._enclosing_function(
            node, index["source"].parents[other_path]
        )
        if (
            other_path != path
            or function not in methods
            or not _app_signing_slot_read(node, function, parents)
        ):
            return False
        methods[function].append(node)
    return not any(
        other_path == path
        and isinstance(node.ctx, ast.Load)
        and _legacy._enclosing_function(node, parents) is None
        for other_path, node in names.get(secret, ())
    )


def _app_signing_class_export(node, owner):
    if isinstance(node, ast.Name):
        return node.id == owner.name and isinstance(node.ctx, ast.Load)
    return isinstance(node, (ast.Import, ast.ImportFrom)) and any(
        alias.name in {owner.name, "*"} for alias in node.names
    )


def _app_signing_slot_read(node, function, parents):
    args = [*function.args.posonlyargs, *function.args.args]
    return bool(
        args
        and not function.decorator_list
        and isinstance(node.ctx, ast.Load)
        and isinstance(node.value, ast.Name)
        and node.value.id == args[0].arg
        and not _legacy.binding_occurrences(function.body, args[0].arg)
        and _legacy._enclosing_function(node, parents) is function
    )


def _app_signing_owner_closed(function, parents, secret):
    args = [*function.args.posonlyargs, *function.args.args]
    if not args:
        return False
    receiver = args[0].arg
    return all(
        isinstance(parents.get(id(node)), ast.Attribute)
        and parents[id(node)].value is node
        and parents[id(node)].attr == secret
        and _legacy._enclosing_function(node, parents) is function
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id == receiver
        and isinstance(node.ctx, ast.Load)
    )


def _app_signing_scope_edges(index, path, owner, loads):
    parents = index["source"].parents[path]
    operations, witnesses = {}, []
    for load in loads:
        if _legacy._enclosing_function(load, parents) is not owner:
            return None
        call = parents.get(id(load))
        if isinstance(call, ast.keyword):
            call = parents.get(id(call))
        if not isinstance(call, ast.Call):
            return None
        resolved = _app_signing_key_edge(index, path, owner, call, load)
        if resolved is None:
            return None
        kind, rows, payload = resolved
        operations[id(call)] = (call, kind, payload)
        witnesses.extend(rows)
    if loads and {kind for _, kind, _ in operations.values()} == {"digest"}:
        return _app_digest_operation_witnesses(
            index, path, owner, operations, witnesses, parents
        )
    if not loads or not {kind for _, kind, _ in operations.values()} == {
        "encode",
        "decode",
    }:
        return None
    if not _app_signing_results_closed(owner, operations, parents) or not (
        _app_signing_receivers_closed(index, path, owner, operations)
    ):
        return None
    return witnesses


def _app_signing_key_edge(index, path, owner, call, actual):
    from . import mock_fixture_provenance as fixture

    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(
        kw.arg is None for kw in call.keywords
    ):
        return None
    canonical = fixture._app_expression_name(index, path, call.func, owner)
    if canonical in {"jwt.encode", "jwt.decode"}:
        return _app_direct_jwt_key_edge(index, path, call, actual, canonical, fixture)
    if isinstance(actual, ast.Name):
        digest = _app_digest_call(index, path, owner, call, actual, actual.id)
        if digest is not None:
            return "digest", [digest], None
    return _app_captured_signing_key_edge(index, path, owner, call, actual)


def _app_direct_jwt_key_edge(index, path, call, actual, canonical, fixture):
    if fixture._jwt_bound_argument(call, 1, {"key"}) is not actual:
        return None
    if not _app_signing_provider_closed(index):
        return None
    if any(
        kw.arg == "json_encoder"
        and not (isinstance(kw.value, ast.Constant) and kw.value.value is None)
        for kw in call.keywords
    ):
        return None
    kind = canonical.rsplit(".", 1)[1]
    payload = fixture._jwt_bound_argument(
        call, 0, {"payload"} if kind == "encode" else {"jwt", "msg"}
    )
    return (
        kind,
        [_app_credential_source_row(index, path, call, "modeled_crypto_boundary")],
        payload,
    )


def _app_captured_signing_key_edge(index, path, owner, call, actual):
    from .review_integrity import bind_source_call

    selected = _app_signing_callee(index, path, owner, call)
    if selected is None:
        return None
    selected_path, method, receiver = selected
    try:
        bound = bind_source_call(call, method, receiver, apply_defaults=False)
    except (TypeError, ValueError):
        return None
    formal = next((name for name, value in bound.items() if value is actual), None)
    if formal is None or _legacy.binding_occurrences(method.body, formal):
        return None
    uses = [
        n
        for n in ast.walk(method)
        if isinstance(n, ast.Name) and n.id == formal and isinstance(n.ctx, ast.Load)
    ]
    operations = _app_wrapper_key_operations(index, selected_path, method, uses, bound)
    if operations is None:
        return None
    kinds, witnesses, payloads = operations
    if (
        len(kinds) != 1
        or payloads
        and any(value is not payloads[0] for value in payloads)
    ):
        return None
    return (
        kinds.pop(),
        [
            *witnesses,
            _app_credential_source_row(
                index, selected_path, method, "captured_crypto_wrapper"
            ),
        ],
        payloads[0] if payloads else None,
    )


def _app_wrapper_key_operations(index, selected_path, method, uses, bound):
    parents = index["source"].parents[selected_path]
    kinds, witnesses, payloads = set(), [], []
    for use in uses:
        edge = _app_wrapper_key_operation(index, selected_path, method, use, parents)
        if edge is None:
            return None
        kinds.add(edge[0])
        witnesses.extend(edge[1])
        if edge[0] == "decode":
            payload = edge[2]
            if not isinstance(payload, ast.Name) or payload.id not in bound:
                return None
            if any(
                isinstance(n, ast.Name)
                and n.id == payload.id
                and isinstance(n.ctx, ast.Load)
                and n is not payload
                for n in ast.walk(method)
            ):
                return None
            payloads.append(bound[payload.id])
    return kinds, witnesses, payloads


def _app_wrapper_key_operation(index, selected_path, method, use, parents):
    from . import mock_fixture_provenance as fixture

    operation = parents.get(id(use))
    if isinstance(operation, ast.keyword):
        operation = parents.get(id(operation))
    if (
        not isinstance(operation, ast.Call)
        or _legacy._enclosing_function(use, parents) is not method
    ):
        return None
    backend = fixture._app_expression_name(index, selected_path, operation.func, method)
    if backend not in {"jwt.encode", "jwt.decode"}:
        return None
    return _app_signing_key_edge(index, selected_path, method, operation, use)


def _app_signing_callee(index, path, owner, call):
    from . import mock_fixture_provenance as fixture

    if not isinstance(call.func, ast.Attribute):
        return None
    target = _app_signing_callee_target(index, path, owner, call, fixture)
    if target is None:
        return None
    selected_path, cls, expression, instance = target
    method = _app_signing_callee_method(
        index, selected_path, cls, call.func.attr, instance, fixture
    )
    if method is None:
        return None
    if not _app_signing_class_stable(index, (selected_path, cls), call.func.attr):
        return None
    if instance and any(
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == expression.id
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in ast.walk(owner)
    ):
        return None
    if fixture._app_has_dynamic_scope(
        index, selected_path, method, list(ast.walk(method))
    ):
        return None
    return selected_path, method, expression


def _app_signing_callee_target(index, path, owner, call, fixture):
    expression = call.func.value
    selected = fixture._app_source_symbol(index, path, expression, owner)
    instance = False
    if selected is None and isinstance(expression, ast.Name):
        assignment = fixture._app_local_assignment(owner, expression.id)
        if assignment is None or not isinstance(assignment.value, ast.Call):
            return None
        if assignment.lineno >= call.lineno:
            return None
        selected = fixture._app_source_symbol(index, path, assignment.value.func, owner)
        instance = True
    if selected is None or not isinstance(selected[1], ast.ClassDef):
        return None
    return selected[0], selected[1], expression, instance


def _app_signing_callee_method(
    index, selected_path, cls, method_name, instance, fixture
):
    if (
        cls.bases
        or cls.keywords
        or any(
            _legacy.binding_occurrences(cls.body, name)
            for name in ("__new__", "__getattr__", "__getattribute__")
        )
    ):
        return None
    for decorator in cls.decorator_list:
        if fixture._app_expression_name(index, selected_path, decorator) not in {
            "dataclasses.dataclass",
            "typing.final",
        }:
            return None
    methods = [
        n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == method_name
    ]
    if (
        len(methods) != 1
        or len(_legacy.binding_occurrences(cls.body, method_name)) != 1
    ):
        return None
    method = methods[0]
    if method.decorator_list and not (
        len(method.decorator_list) == 1
        and isinstance(method.decorator_list[0], ast.Name)
        and method.decorator_list[0].id == "classmethod"
        and not _legacy.binding_occurrences(
            index["modules"][selected_path].body, "classmethod"
        )
    ):
        return None
    if _legacy._definition_effects_unknown(
        method, allowed_decorators=method.decorator_list
    ):
        return None
    if not instance and not method.decorator_list:
        return None
    return method


def _app_signing_receivers_closed(index, path, owner, operations):
    """Only verified calls may consume a constructed wrapper capability."""
    from . import mock_fixture_provenance as fixture

    source = index["source"]
    parents = source.parents[path]
    for call, _, _ in operations.values():
        selected = _app_signing_callee(index, path, owner, call)
        if selected is None:
            continue  # Direct modeled PyJWT calls have no captured receiver.
        _, _, receiver = selected
        if not isinstance(receiver, ast.Name):
            continue  # Class-level calls are checked by class binding closure.
        assignment = fixture._app_local_assignment(owner, receiver.id)
        if assignment is None or not isinstance(assignment.value, ast.Call):
            continue
        resolved = fixture._app_source_symbol(index, path, assignment.value.func, owner)
        if resolved is None or not isinstance(resolved[1], ast.ClassDef):
            return False
        class_path, cls = resolved
        chain = [(class_path, cls.name, cls)]
        if any(
            _legacy.binding_occurrences(cls.body, hook) for hook in _legacy._HOOKS
        ) or any(
            not _legacy._method_stable(chain, name, source, absent=True)
            for name in ("__init__", "__post_init__")
        ):
            return False
        for node in ast.walk(owner):
            if not (
                isinstance(node, ast.Name)
                and node.id == receiver.id
                and isinstance(node.ctx, ast.Load)
            ):
                continue
            member = parents.get(id(node))
            invocation = parents.get(id(member))
            if not (
                _legacy._enclosing_function(node, parents) is owner
                and isinstance(member, ast.Attribute)
                and member.value is node
                and isinstance(member.ctx, ast.Load)
                and isinstance(invocation, ast.Call)
                and invocation.func is member
                and id(invocation) in operations
            ):
                return False
    return True


def _app_signing_class_stable(index, selected, member, permitted_references=()):
    cache = index.setdefault("profiles", {})
    key = (
        "signing-class-stable",
        selected[0],
        id(selected[1]),
        member,
        tuple(sorted(id(node) for node in permitted_references)),
        _app_source_role_epoch(index),
    )
    if key in cache:
        return cache[key]
    spellings = _app_signing_class_spellings(index, selected[1].name)
    if spellings is None:
        return False
    for path, tree in index["modules"].items():
        if not index["source"].validate(path) or not _app_signing_class_source_closed(
            index, path, tree, selected, member, permitted_references, spellings
        ):
            cache[key] = False
            return False
    cache[key] = True
    return True


def _app_signing_class_spellings(index, class_name):
    spellings = {class_name}
    imports = [
        node
        for tree in index["modules"].values()
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    ]
    for _ in range(16):
        expanded = spellings | {
            alias.asname or alias.name
            for node in imports
            for alias in node.names
            if alias.name in spellings
        }
        if expanded == spellings:
            return spellings
        spellings = expanded
    return None


def _app_signing_class_source_closed(
    index, path, tree, selected, member, permitted_references, spellings
):
    parents = index["source"].parents[path]
    return all(
        _app_signing_class_node_closed(
            index,
            path,
            node,
            parents,
            selected,
            member,
            permitted_references,
            spellings,
        )
        for node in ast.walk(tree)
    )


def _app_signing_class_node_closed(
    index, path, node, parents, selected, member, permitted_references, spellings
):
    from . import mock_fixture_provenance as fixture

    if (
        isinstance(node, ast.Attribute)
        and node.attr == member
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ):
        return False
    if not isinstance(node, (ast.Name, ast.Attribute)) or not isinstance(
        node.ctx, ast.Load
    ):
        return True
    if (node.id if isinstance(node, ast.Name) else node.attr) not in spellings:
        return True
    function = _legacy._enclosing_function(node, parents)
    resolved = fixture._app_source_symbol(index, path, node, function)
    if resolved is None:
        return False
    if resolved != selected or any(
        node is reference for reference in permitted_references
    ):
        return True
    parent = parents.get(id(node))
    if isinstance(parent, ast.Call) and parent.func is node:
        return True
    return _app_signing_class_method_receiver_use(parent, parents, selected[1])


def _app_signing_class_method_receiver_use(parent, parents, selected_class):
    return (
        isinstance(parent, ast.Attribute)
        and isinstance(parent.ctx, ast.Load)
        and isinstance(parents.get(id(parent)), ast.Call)
        and parents[id(parent)].func is parent
        and any(
            isinstance(node, ast.FunctionDef) and node.name == parent.attr
            for node in selected_class.body
        )
    )


def _app_signing_provider_closed(index):
    key = ("signing-provider-closure", _app_source_role_epoch(index))
    cache = index.setdefault("profiles", {})
    if key in cache:
        return cache[key]
    for path, tree in index["modules"].items():
        if not index["source"].validate(
            path
        ) or not _app_signing_provider_module_closed(index, path, tree):
            cache[key] = False
            return False
    cache[key] = True
    return True


def _app_signing_provider_module_closed(index, path, tree):
    from . import mock_fixture_provenance as fixture
    from .finite_capture import finite_provider_mutation_index
    from . import review_audits as audit

    if fixture._django_provider_root_shadowed(index["module_paths"], "jwt"):
        return False
    aliases = _app_signing_provider_aliases(index, path, tree, fixture)
    if aliases is None:
        return False
    if not aliases:
        return True
    parents = index["source"].parents[path]
    nodes = []
    for node in ast.walk(tree):
        if _app_signing_provider_private_access(index, path, node, parents, fixture):
            return False
        if not _app_signing_exception_projection(index, path, node, parents):
            nodes.append(node)
    mutations = finite_provider_mutation_index(nodes, aliases, audit, parents)
    return not any(
        provider == "jwt" or provider.startswith("jwt.") for provider, _ in mutations
    )


def _app_signing_provider_aliases(index, path, tree, fixture):
    aliases = {}
    for statement in ast.walk(tree):
        for name, target in fixture._django_import_rows(statement, "") or ():
            if target != "jwt" and not target.startswith("jwt."):
                continue
            scope = _legacy._enclosing_function(
                statement, index["source"].parents[path]
            )
            if (
                scope is not None
                or len(_legacy.binding_occurrences(tree.body, name)) != 1
            ):
                # A scoped provider import needs scoped binding effects;
                # never omit it from a module-wide closure.
                return None
            aliases[name] = target
    return aliases


def _app_signing_provider_private_access(index, path, node, parents, fixture):
    if not isinstance(node, ast.Attribute) or not node.attr.startswith("__"):
        return False
    name = fixture._app_expression_name(
        index, path, node.value, _legacy._enclosing_function(node, parents)
    )
    return bool(name and (name == "jwt" or name.startswith("jwt.")))


def _app_source_role_epoch(index):
    """Scope reusable role facts to current immutable inputs and actual callees."""
    source = index["source"]
    dependencies = tuple(
        (
            h,
            getattr(h, "__code__", h),
            getattr(h, "__defaults__", None),
            getattr(h, "__kwdefaults__", None),
        )
        for h in _legacy.module_fixture_helper_epoch()
    )
    identity = (
        tuple(
            sorted(
                (
                    str(p),
                    digest,
                    id(source.source_bytes.get(p)),
                    id(source.snapshots.get(p)),
                )
                for p, digest in source.inventory.items()
            )
        ),
        tuple(tuple(id(value) for value in row) for row in dependencies),
    )
    cached = index.get("_source_role_generation")
    if cached is None or cached[0] != identity:
        cached = (identity, object(), dependencies)
        index["_source_role_generation"] = cached
    return cached[1]


def _app_signing_exception_projection(index, path, node, parents):
    """A modeled raises context consumes an exception value, not its namespace."""
    from . import mock_fixture_provenance as fixture

    if not isinstance(node, (ast.Name, ast.Attribute)) or not isinstance(
        node.ctx, ast.Load
    ):
        return False
    outer = node
    while (
        isinstance(parents.get(id(outer)), ast.Attribute)
        and parents[id(outer)].value is outer
    ):
        outer = parents[id(outer)]
    call = parents.get(id(outer))
    if not isinstance(call, ast.Call) or call.args != [outer] or call.keywords:
        return False
    item = parents.get(id(call))
    if not isinstance(item, ast.withitem) or item.context_expr is not call:
        return False
    owner = _legacy._enclosing_function(call, parents)
    return fixture._app_expression_name(
        index, path, call.func, owner
    ) == "pytest.raises" and _app_factory_provider_closed(index, path, "pytest.raises")


def _app_signing_results_closed(owner, operations, parents):
    """Verification must consume this test's signed token; keys never enter payloads.

    Decoded claims are not the signing capability. Their later use is outside
    this literal's key-role proof and does not establish payload privacy.
    """
    from . import mock_fixture_provenance as fixture

    tokens = _app_signing_encoded_tokens(owner, operations, parents, fixture)
    if not tokens or not _app_signing_decoded_tokens_closed(operations, tokens):
        return False
    return _app_signing_token_loads_closed(owner, operations, parents, tokens)


def _app_signing_encoded_tokens(owner, operations, parents, fixture):
    tokens = {}
    for call, kind, _ in operations.values():
        if kind != "encode":
            continue
        statement = parents.get(id(call))
        if (
            not isinstance(statement, ast.Assign)
            or len(statement.targets) != 1
            or not isinstance(statement.targets[0], ast.Name)
        ):
            return False
        name = statement.targets[0].id
        if fixture._app_local_assignment(owner, name) is not statement:
            return None
        tokens[name] = statement
    return tokens


def _app_signing_decoded_tokens_closed(operations, tokens):
    for call, kind, payload in operations.values():
        if kind == "decode" and (
            not isinstance(payload, ast.Name)
            or payload.id not in tokens
            or tokens[payload.id].lineno >= call.lineno
        ):
            return False
    return True


def _app_signing_token_loads_closed(owner, operations, parents, tokens):
    for node in ast.walk(owner):
        if (
            not isinstance(node, ast.Name)
            or node.id not in tokens
            or not isinstance(node.ctx, ast.Load)
        ):
            continue
        current = parents.get(id(node))
        if isinstance(current, ast.keyword):
            current = parents.get(id(current))
        edge = operations.get(id(current))
        if edge is None or edge[1] != "decode" or edge[2] is not node:
            return False
    return True


def _app_factory_test_authority(index, path, assignment, secret):
    """Bound a newly created factory authority to its local APIClient exercise."""
    from . import mock_fixture_provenance as fixture

    context = _app_factory_test_context(index, path, assignment, secret, fixture)
    if context is None:
        return None
    source, function, parents, nodes = context
    creates = _app_factory_creation_calls(index, path, function, secret, nodes, fixture)
    requests = _app_factory_client_requests(index, path, function)
    if not creates or not requests:
        return None
    exercised, request_permitted = _app_factory_exercised_requests(
        function, secret, requests, parents
    )
    if not _app_factory_exercise_order_closed(creates, exercised):
        return None
    if not all(
        _app_factory_authority_uses_closed(index, path, function, call, exercised)
        for call, _ in creates
    ):
        return None
    permitted = _app_factory_permitted_uses(creates, request_permitted, nodes, secret)
    loads = _app_factory_secret_loads(nodes, secret)
    if not _app_factory_consumers_closed(
        index, path, function, loads, permitted, exercised, parents, secret
    ):
        return None
    return _app_factory_authority_witness(
        index, path, assignment, function, secret, creates, loads, source, fixture
    )


def _app_factory_test_context(index, path, assignment, secret, fixture):
    source = index["source"]
    if not source.validate(path):
        return None
    function = source.parents[path].get(id(assignment))
    if not isinstance(function, ast.FunctionDef) or not function.name.startswith(
        "test_"
    ):
        return None
    if (
        assignment not in function.body
        or fixture._app_local_assignment(function, secret) is not assignment
    ):
        return None
    if not _app_factory_test_decorators(index, path, function):
        return None
    nodes = list(ast.walk(function))
    if len(nodes) > 1024 or any(
        isinstance(node, (ast.Global, ast.Nonlocal)) for node in nodes
    ):
        return None
    if any(_app_factory_nested_secret_use(node, function, secret) for node in nodes):
        return None
    return source, function, source.parents[path], nodes


def _app_factory_nested_secret_use(node, function, secret):
    return (
        node is not function
        and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        )
        and any(
            isinstance(child, ast.Name) and child.id == secret
            for child in ast.walk(node)
        )
    )


def _app_factory_creation_calls(index, path, function, secret, nodes, fixture):
    creates = []
    for node in nodes:
        if not isinstance(node, ast.Call) or not any(
            isinstance(kw.value, ast.Name) and kw.value.id == secret
            for kw in node.keywords
        ):
            continue
        provider = _app_factory_provider(index, path, function, node)
        if provider is not None and fixture._app_active_call(
            index, path, function, node
        ):
            creates.append((node, provider))
    return creates


def _app_factory_exercised_requests(function, secret, requests, parents):
    exercised = []
    permitted = set()
    for call in requests:
        arguments = [*call.args[1:], *(kw.value for kw in call.keywords)]
        uses = [
            n
            for argument in arguments
            for n in ast.walk(argument)
            if isinstance(n, ast.Name)
            and n.id == secret
            and _app_factory_material_use(n, call, parents)
        ]
        if any(isinstance(n, ast.Name) and n.id == secret for n in uses):
            exercised.append(call)
            permitted.update(id(n) for n in uses)
    return exercised, permitted


def _app_factory_exercise_order_closed(creates, exercised):
    return bool(exercised) and min(call.lineno for call in exercised) > min(
        call.lineno for call, _ in creates
    )


def _app_factory_permitted_uses(creates, request_permitted, nodes, secret):
    permitted = {
        id(keyword.value)
        for call, _ in creates
        for keyword in call.keywords
        if isinstance(keyword.value, ast.Name) and keyword.value.id == secret
    }
    permitted.update(request_permitted)
    assertions = [node for node in nodes if isinstance(node, ast.Assert)]
    for assertion in assertions:
        # Literal comparisons are harmless reads; arbitrary calls under assert
        # are not a safe credential consumer merely because they are assertions.
        if _app_factory_literal_assertion(assertion, secret):
            permitted.update(id(node) for node in ast.walk(assertion))
    return permitted


def _app_factory_secret_loads(nodes, secret):
    return [
        node
        for node in nodes
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id == secret
    ]


def _app_factory_consumers_closed(
    index, path, function, loads, permitted, exercised, parents, secret
):
    if not loads or any(id(node) not in permitted for node in loads):
        return False
    return any(
        _app_factory_response_asserted(function, call, parents) for call in exercised
    )


def _app_factory_authority_witness(
    index, path, assignment, function, secret, creates, loads, source, fixture
):
    # This is a modeled test-client/factory contract, never a claim that the
    # project ran or that deployment, transport or isolation was verified.
    origin = _app_credential_source_row(
        index, path, assignment, "test_credential_origin", secret
    )
    owner = _app_credential_source_row(
        index, path, function, "test_owner", function.name
    )
    consumers = [
        _app_credential_source_row(index, path, n, "test_credential_consumer", secret)
        for n in loads
    ]
    witnesses = [
        _app_credential_source_row(index, p, n, "test_factory_provider")
        for _, (p, n) in creates
    ]
    return {
        "eligible": True,
        "classification": "APPLICATION_TEST_CREDENTIAL_ROLE",
        "source": source.relative(path),
        "source_sha256": source.inventory[path],
        "declaration_span": fixture._evidence_node_span(assignment),
        "profile": "SOURCE_BOUND_FACTORY_TEST_AUTHORITY",
        "modeled_api_assumption": "Captured factory.django.DjangoModelFactory creates test authority; an unchanged rest_framework.test.APIClient exercises a relative in-process route. Runtime execution and isolation are unassessed.",
        "runtime_assurance": "INCOMPLETE",
        "transport_role": "UNASSESSED",
        "isolation_assurance": "UNASSESSED",
        "target_execution": "not_performed",
        "witness_sources": witnesses,
        "consumer_use_closure": {
            "schema": "factory.test-authority-consumer-closure.v1",
            "complete": True,
            "origin": origin,
            "owner": owner,
            "consumers": consumers,
        },
    }


def _app_factory_material_use(node, call, parents):
    """Only immutable string/container interpolation may carry a fixture input."""
    current = node
    while (parent := parents.get(id(current))) is not call:
        if not isinstance(
            parent,
            (
                ast.Dict,
                ast.List,
                ast.Tuple,
                ast.keyword,
                ast.JoinedStr,
                ast.FormattedValue,
            ),
        ):
            return False
        current = parent
    return True


def _app_factory_authority_uses_closed(index, path, function, creation, requests):
    from . import mock_fixture_provenance as fixture

    parents = index["source"].parents[path]
    statement = parents.get(id(creation))
    if isinstance(statement, ast.Expr) and statement in function.body:
        return True
    if (
        not isinstance(statement, ast.Assign)
        or len(statement.targets) != 1
        or not isinstance(statement.targets[0], ast.Name)
    ):
        return False
    name = statement.targets[0].id
    if fixture._app_local_assignment(function, name) is not statement:
        return False
    for node in ast.walk(function):
        if (
            isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, ast.Load)
        ):
            parent = parents.get(id(node))
            if not isinstance(parent, ast.Attribute) or not isinstance(
                parent.ctx, ast.Load
            ):
                return False
            if not any(
                _app_factory_material_use(parent, call, parents) for call in requests
            ):
                return False
            if any(
                isinstance(n, ast.Call) and parent is n.func for n in ast.walk(function)
            ):
                return False
    return True


def _app_factory_literal_assertion(assertion, secret):
    """Only exact literal scalars and the captured string have inert equality."""
    test = assertion.test
    return bool(
        assertion.msg is None
        and isinstance(test, ast.Compare)
        and all(
            isinstance(op, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)) for op in test.ops
        )
        and all(
            isinstance(n, ast.Constant)
            and type(n.value) in (type(None), bool, int, float, str, bytes)
            or isinstance(n, ast.Name)
            and n.id == secret
            for n in (test.left, *test.comparators)
        )
    )


def _app_factory_test_decorators(index, path, function):
    from . import mock_fixture_provenance as fixture

    for decorator in function.decorator_list:
        expression = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = fixture._app_expression_name(index, path, expression)
        if name not in {"pytest.mark.django_db", "pytest.mark.parametrize"}:
            return False
        if isinstance(decorator, ast.Call) and (
            any(not _legacy._immutable_default(arg) for arg in decorator.args)
            or any(
                kw.arg is None or not _legacy._immutable_default(kw.value)
                for kw in decorator.keywords
            )
        ):
            return False
    return True


def _app_factory_provider(index, path, function, call):
    from . import mock_fixture_provenance as fixture

    if call.args or any(kw.arg is None for kw in call.keywords):
        return None
    selection = _app_factory_provider_selection(index, path, function, call, fixture)
    if selection is None:
        return None
    selected, chain, model_assignment = selection
    imports = _app_crypto_provider_imports(index)
    if imports is None or not _app_factory_classes_closed(
        index, selected, chain, imports, model_assignment
    ):
        return None
    if not all(
        fixture._django_model_signal_registration_clear(index, module_path)
        for module_path in index["modules"]
    ):
        return None
    for provider_path in (path, selected[0]):
        if not _app_factory_provider_closed(
            index, provider_path, "factory.django.DjangoModelFactory"
        ):
            return None
    return selected


def _app_factory_provider_selection(index, path, function, call, fixture):
    selected = fixture._app_source_symbol(index, path, call.func, function)
    if selected is None:
        return None
    owner_path, owner = selected
    if (
        not isinstance(owner, ast.ClassDef)
        or owner.decorator_list
        or owner.keywords
        or len(owner.bases) != 1
    ):
        return None
    if (
        fixture._app_expression_name(index, owner_path, owner.bases[0])
        != "factory.django.DjangoModelFactory"
    ):
        return None
    if not _app_factory_declaration_closed(index, owner_path, owner, factory=True):
        return None
    meta = [n for n in owner.body if isinstance(n, ast.ClassDef) and n.name == "Meta"]
    if len(meta) != 1 or meta[0].bases or meta[0].decorator_list:
        return None
    model = [
        n
        for n in meta[0].body
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id == "model"
    ]
    if len(model) != 1:
        return None
    model_ref = fixture._app_source_symbol(index, owner_path, model[0].value)
    if model_ref is None or not isinstance(model_ref[1], ast.ClassDef):
        return None
    chain = fixture._django_class_chain(
        index, model_ref[0], model_ref[1], "django.db.models.Model"
    )
    if chain is None or any(
        not _app_factory_declaration_closed(index, p, cls, factory=False)
        for p, _, cls in chain
    ):
        return None
    return selected, chain, model[0]


def _app_factory_classes_closed(index, selected, chain, imports, model_assignment):
    """Reuse provider effects with one exact validated Meta.model declaration edge."""
    source = index["source"]
    selected_chain = [(selected[0], selected[1].name, selected[1]), *chain]
    references = [
        model_assignment.value,
        *(base for _, _, cls in selected_chain for base in cls.bases),
    ]
    if any(
        not _app_signing_class_stable(index, (path, cls), None, references)
        for path, _, cls in selected_chain
    ):
        return False
    roots = {
        _legacy._class_binding._source_module(path) + "." + name
        for path, name, _ in selected_chain
    }

    def capture_guard(snapshot, aliases, owners, filtered, fields, consumers):
        filtered.setdefault(selected[0], set()).add(id(model_assignment))
        return _legacy._class_binding._has_opaque_owner_capture(
            snapshot, aliases, owners, filtered, fields, consumers
        )

    model = _legacy._class_binding.constructor_provider_model(
        roots, source, imports, _legacy._class_binding._source_aliases, capture_guard
    )
    return model is not None and _legacy._class_binding._captured_mutations_inert(
        source, *model
    )


def _app_factory_declaration_closed(index, path, owner, *, factory):
    """Decline executable/custom descriptors and hooks until their effects resolve."""
    from . import mock_fixture_provenance as fixture

    if owner.decorator_list or owner.keywords:
        return False
    for statement in owner.body:
        if isinstance(statement, ast.Pass) or (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue
        if isinstance(statement, ast.ClassDef) and statement.name == "Meta":
            if not _app_factory_meta_declaration_closed(
                index, path, statement, factory, fixture
            ):
                return False
            continue
        if not _app_factory_field_declaration_closed(
            index, path, statement, factory, fixture
        ):
            return False
    return True


def _app_factory_meta_declaration_closed(index, path, meta, factory, fixture):
    if meta.bases or meta.decorator_list or meta.keywords:
        return False
    for item in meta.body:
        if isinstance(item, ast.Pass):
            continue
        if (
            not isinstance(item, ast.Assign)
            or len(item.targets) != 1
            or not isinstance(item.targets[0], ast.Name)
        ):
            return False
        if factory and item.targets[0].id == "model":
            if fixture._app_source_symbol(index, path, item.value) is None:
                return False
        elif not _legacy._immutable_default(item.value):
            return False
    return True


def _app_factory_field_declaration_closed(index, path, statement, factory, fixture):
    if (
        not isinstance(statement, ast.Assign)
        or len(statement.targets) != 1
        or not isinstance(statement.targets[0], ast.Name)
        or statement.targets[0].id.startswith("_")
    ):
        return False
    if _legacy._immutable_default(statement.value):
        return True
    value = statement.value
    if (
        not isinstance(value, ast.Call)
        or not all(_legacy._immutable_default(arg) for arg in value.args)
        or not all(
            kw.arg is not None and _legacy._immutable_default(kw.value)
            for kw in value.keywords
        )
    ):
        return False
    canonical = fixture._app_expression_name(index, path, value.func)
    providers = (
        {"factory.Faker"}
        if factory
        else {
            "django.db.models.CharField",
            "django.db.models.TextField",
            "django.db.models.IntegerField",
            "django.db.models.BooleanField",
            "django.db.models.EmailField",
            "django.db.models.UUIDField",
        }
    )
    return canonical in providers


def _app_factory_provider_closed(index, path, canonical):
    # Provider state is process-wide. A captured import can replace it before
    # the test executes, even when this test's own module has no write.
    if not all(index["source"].validate(p) for p in index["modules"]):
        return False
    cache = index.setdefault("profiles", {})
    key = ("factory-provider-closure", canonical, _app_source_role_epoch(index))
    if key not in cache:
        cache[key] = all(
            _app_factory_module_provider_closed(index, p, tree, canonical)
            for p, tree in index["modules"].items()
        )
    return cache[key]


def _app_factory_module_provider_closed(index, path, tree, canonical):
    from . import mock_fixture_provenance as fixture

    parents = index["source"].parents[path]
    if not fixture._app_provider_unchanged(index, path, tree, canonical):
        return False
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Name, ast.Attribute)) or not isinstance(
            node.ctx, ast.Load
        ):
            continue
        function = _legacy._enclosing_function(node, parents)
        if fixture._app_expression_name(index, path, node, function) != canonical:
            continue
        parent = parents.get(id(node))
        if isinstance(parent, ast.Call) and parent.func is node:
            continue
        if isinstance(parent, ast.ClassDef) and node in parent.bases:
            continue
        return False
    return True


def _app_factory_client_requests(index, path, function):
    from . import mock_fixture_provenance as fixture

    clients = []
    for statement in function.body:
        requests = _app_factory_assigned_client_requests(
            index, path, function, statement, fixture
        )
        if requests:
            clients.extend(requests)
    if _app_factory_provider_closed(index, path, "rest_framework.test.APIClient"):
        clients.extend(
            _app_factory_inline_client_requests(index, path, function, fixture)
        )
    return clients


def _app_factory_assigned_client_requests(index, path, function, statement, fixture):
    if (
        not isinstance(statement, ast.Assign)
        or len(statement.targets) != 1
        or not isinstance(statement.targets[0], ast.Name)
    ):
        return None
    call = statement.value
    if not isinstance(call, ast.Call) or call.args or call.keywords:
        return None
    if (
        fixture._app_expression_name(index, path, call.func, function)
        != "rest_framework.test.APIClient"
    ):
        return None
    name = statement.targets[0].id
    if fixture._app_local_assignment(function, name) is not statement:
        return None
    if not _app_factory_provider_closed(index, path, "rest_framework.test.APIClient"):
        return None
    requests = fixture._app_client_requests(function, [name])
    if not requests or any(
        not _app_factory_relative_request(call) for call in requests
    ):
        return None
    parents = index["source"].parents[path]
    if any(
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == name
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in ast.walk(function)
    ):
        return None
    loads = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id == name
    ]
    if any(
        not isinstance(parents.get(id(node)), ast.Attribute)
        or not any(parents[id(node)] is request.func for request in requests)
        for node in loads
    ):
        return None
    return requests


def _app_factory_relative_request(call):
    return (
        bool(call.args)
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
        and call.args[0].value.startswith("/")
        and not call.args[0].value.startswith("//")
    )


def _app_factory_inline_client_requests(index, path, function, fixture):
    return [
        call
        for call in ast.walk(function)
        if _app_factory_inline_client_request(index, path, function, call, fixture)
    ]


def _app_factory_inline_client_request(index, path, function, call, fixture):
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
        return False
    if call.func.attr not in {"post", "put", "patch"}:
        return False
    receiver = call.func.value
    if not isinstance(receiver, ast.Call) or receiver.args or receiver.keywords:
        return False
    if (
        fixture._app_expression_name(index, path, receiver.func, function)
        != "rest_framework.test.APIClient"
    ):
        return False
    return _app_factory_relative_request(call)


def _app_factory_response_asserted(function, call, parents):
    statement = parents.get(id(call))
    if (
        not isinstance(statement, ast.Assign)
        or len(statement.targets) != 1
        or not isinstance(statement.targets[0], ast.Name)
    ):
        return False
    name = statement.targets[0].id
    from . import mock_fixture_provenance as fixture

    if fixture._app_local_assignment(function, name) is not statement:
        return False
    for node in ast.walk(function):
        if isinstance(node, ast.Assert) and node.lineno > statement.lineno:
            if any(
                isinstance(n, ast.Attribute)
                and isinstance(n.value, ast.Name)
                and n.value.id == name
                and n.attr == "status_code"
                for n in ast.walk(node.test)
            ):
                return True
    return False


def application_plaintext_effect_evidence(index, path, literal, assignment, secret):
    """Cache source-bound role evidence by the existing snapshot/helper identity."""
    source = index.get("source")
    if source is None or not source.validate(path):
        return None
    cache = index.setdefault("profiles", {})
    key = _application_effect_cache_key(index, path, assignment)
    if key not in cache:
        cache[key] = _application_plaintext_effect_evidence_uncached(
            index, path, literal, assignment, secret
        )
    return cache[key]


def _application_effect_cache_key(index, path, assignment):
    from . import mock_fixture_provenance as fixture

    source = index["source"]
    inventory = tuple(
        sorted((source.relative(p), digest) for p, digest in source.inventory.items())
    )
    configs = tuple(
        sorted(
            (name, raw)
            for name, raw in index.get("configuration_bytes", {}).items()
            if isinstance(raw, bytes)
        )
    )
    helpers = _legacy.module_fixture_helper_epoch()
    span = fixture._evidence_node_span(assignment)
    return (
        "application-credential-role",
        inventory,
        configs,
        tuple((id(h), id(getattr(h, "__code__", h))) for h in helpers),
        source.relative(path),
        tuple(span) if span else None,
    )


def _application_plaintext_effect_evidence_uncached(
    index, path, literal, assignment, secret
):
    from . import mock_fixture_provenance as fixture

    function = index["source"].parents[path].get(id(assignment))
    if (
        not isinstance(function, ast.FunctionDef)
        or function.decorator_list
        or fixture._app_local_assignment(function, secret) is not assignment
    ):
        return None
    roundtrip = _app_local_crypto_roundtrip(index, path, function, secret)
    if roundtrip is None:
        return None
    providers = _app_crypto_roundtrip_provider(index, roundtrip)
    if providers is None:
        return fixture._django_unknown(
            "source-resolved transform provider or payload-only role is unresolved"
        )
    consumers = _app_plaintext_test_uses(index, path, function, secret, roundtrip)
    if consumers is None:
        return _app_incomplete_plaintext_evidence(
            index,
            path,
            assignment,
            function,
            secret,
            "plaintext consumer-use closure is incomplete",
        )
    source = index["source"]
    origin = _app_credential_source_row(
        index, path, assignment, "plaintext_credential_origin", secret
    )
    owner = _app_credential_source_row(
        index, path, function, "test_owner", function.name
    )
    provider_rows = {
        role: _app_credential_source_row(index, owner_path, node, role)
        for owner_path, node, role in providers
    }
    value_effect = {
        "schema": "factory.credential-role-effect-summary.v1",
        "status": "SOURCE_CLOSED_TEST_BODY",
        "material_role": "PLAINTEXT_CREDENTIAL_VALUE",
        "origin": origin,
        "owner": owner,
        "consumers": consumers,
        "providers": list(provider_rows.values()),
        "persistence_role": "NOT_OBSERVED_IN_CLOSED_TEST_BODY",
        "transport_role": "NOT_OBSERVED_IN_CLOSED_TEST_BODY",
        "unknown_reasons": [],
    }
    return {
        "eligible": True,
        "classification": "APPLICATION_TEST_CREDENTIAL_ROLE",
        "source": source.relative(path),
        "source_sha256": source.inventory[path],
        "declaration_span": fixture._evidence_node_span(assignment),
        "profile": "LOCAL_REVERSIBLE_CREDENTIAL_ROUNDTRIP",
        "modeled_api_assumption": (
            "The exact captured cryptography AESGCM import is modeled as a reversible "
            "transform API; provider execution and cryptographic correctness were not assessed."
        ),
        "runtime_assurance": "INCOMPLETE",
        "transport_role": "UNASSESSED",
        "target_execution": "not_performed",
        "isolation_assurance": "UNASSESSED",
        "value_effect": value_effect,
        "witness_sources": provider_rows,
        "consumer_use_closure": {
            "schema": "factory.credential-role-consumer-closure.v1",
            "complete": True,
            "origin": origin,
            "owner": owner,
            "consumers": consumers,
        },
    }


def _app_local_crypto_roundtrip(index, path, function, secret):
    """Capture one same-instance encrypt/decrypt equality use and its imported owner."""
    token_assignment = _app_roundtrip_token_assignment(function.body, secret)
    if token_assignment is None:
        return None
    token, encrypt = token_assignment.targets[0].id, token_assignment.value
    instance = encrypt.func.value.id
    from . import mock_fixture_provenance as fixture

    instance_assignment = fixture._app_local_assignment(function, instance)
    if not instance_assignment or not isinstance(instance_assignment.value, ast.Call):
        return None
    assertion = _app_roundtrip_assertion(function.body, secret, token, instance)
    if (
        assertion is None
        or fixture._app_local_assignment(function, token) is not token_assignment
    ):
        return None
    decrypt = assertion.test.left
    parents = index["source"].parents[path]
    loads = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id == instance
        and isinstance(node.ctx, ast.Load)
    ]
    if len(loads) != 2 or any(
        not isinstance(parents.get(id(node)), ast.Attribute)
        or parents[id(node)].value is not node
        for node in loads
    ):
        return None
    canonical = fixture._app_expression_name(
        index, path, instance_assignment.value.func, function
    )
    if not isinstance(canonical, str) or "." not in canonical:
        return None
    module, _, name = canonical.rpartition(".")
    provider_path, tree = fixture._django_mod(index, module)
    if tree is None:
        return None
    owners = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == name
    ]
    if len(owners) != 1 or _legacy.binding_occurrences(tree.body, name) != owners:
        return None
    return {
        "instance": instance,
        "encrypt": encrypt,
        "decrypt": decrypt,
        "assertion": assertion,
        "token_assignment": token_assignment,
        "test_path": path,
        "test_function": function,
        "instance_assignment": instance_assignment,
        "provider_canonical": canonical,
        "provider_path": provider_path,
        "provider_class": owners[0],
    }


def _app_roundtrip_token_assignment(statements, secret):
    rows = [
        row
        for row in statements
        if isinstance(row, ast.Assign)
        and len(row.targets) == 1
        and isinstance(row.targets[0], ast.Name)
        and isinstance(row.value, ast.Call)
        and isinstance(row.value.func, ast.Attribute)
        and row.value.func.attr == "encrypt"
        and isinstance(row.value.func.value, ast.Name)
        and len(row.value.args) == 1
        and isinstance(row.value.args[0], ast.Name)
        and row.value.args[0].id == secret
        and not row.value.keywords
    ]
    return rows[0] if len(rows) == 1 else None


def _app_roundtrip_assertion(statements, secret, token, instance):
    rows = [
        row
        for row in statements
        if isinstance(row, ast.Assert)
        and isinstance(row.test, ast.Compare)
        and len(row.test.ops) == 1
        and isinstance(row.test.ops[0], ast.Eq)
        and len(row.test.comparators) == 1
        and isinstance(row.test.comparators[0], ast.Name)
        and row.test.comparators[0].id == secret
        and isinstance(row.test.left, ast.Call)
        and isinstance(row.test.left.func, ast.Attribute)
        and row.test.left.func.attr == "decrypt"
        and isinstance(row.test.left.func.value, ast.Name)
        and row.test.left.func.value.id == instance
        and len(row.test.left.args) == 1
        and isinstance(row.test.left.args[0], ast.Name)
        and row.test.left.args[0].id == token
        and not row.test.left.keywords
    ]
    return rows[0] if len(rows) == 1 else None


def _app_crypto_roundtrip_provider(index, pair):
    """Bind a small closed local-transform provider to exact imported AESGCM calls."""
    path, owner, source = pair["provider_path"], pair["provider_class"], index["source"]
    methods = _app_crypto_methods(path, owner, source)
    if methods is None:
        return None
    from .credential_role_method_use_getter_audit import _member_mutated
    from . import review_audits

    if (
        any(_member_mutated(owner, name) for name in methods if name != "__init__")
        or any(
            _legacy._definition_effects_unknown(method) for method in methods.values()
        )
        or not _app_crypto_fixture_constructor_inert(index, pair)
    ):
        return None
    imports = _app_crypto_provider_imports(index)
    if (
        imports is None
        or not _legacy._class_binding.constructor_provider_bindings_inert(
            [(path, owner.name, owner)], source, imports
        )
    ):
        return None
    if _legacy._class_binding._captured_terminal_provider_mutation(
        source,
        review_audits,
        "cryptography.hazmat.primitives.ciphers.aead.AESGCM",
    ):
        return None
    init, encrypt, decrypt, derive = (
        methods[name] for name in ("__init__", "encrypt", "decrypt", "_derive_aesgcm")
    )
    field = _app_crypto_initialization(index, path, owner, init)
    if field is None or not _app_crypto_encrypt(index, path, owner, encrypt, field):
        return None
    if not _app_crypto_derive(index, path, derive) or not _app_crypto_decrypt(
        index, path, owner, decrypt
    ):
        return None
    return [
        (path, owner, "source_resolved_transform_owner"),
        (path, init, "transform_provider_initialization"),
        (path, encrypt, "payload_transform_method"),
        (path, decrypt, "token_consumer_method"),
        (path, derive, "transform_provider_derivation"),
    ]


def _app_crypto_provider_imports(index):
    """Resolve captured source imports for the shared constructor-provider closure."""
    from . import mock_fixture_provenance as fixture

    imports = {}
    for path, tree in index["modules"].items():
        scoped = _app_crypto_module_imports(index, path, tree, fixture)
        if scoped is None:
            return None
        imports[path] = scoped
    return imports


def _app_crypto_module_imports(index, path, tree, fixture):
    module = fixture._django_name(index, path)
    if not isinstance(module, str):
        return None
    package = (
        module
        if index["source"].relative(path).endswith("/__init__.py")
        else module.rpartition(".")[0]
    )
    scoped = {}
    for statement in tree.body:
        rows = fixture._django_import_rows(statement, package)
        if rows is None:
            return None
        if isinstance(statement, ast.ImportFrom):
            _app_crypto_from_imports(index, statement, rows, fixture, scoped)
        elif isinstance(statement, ast.Import):
            _app_crypto_module_imports_for_statement(index, rows, fixture, scoped)
    return scoped


def _app_crypto_from_imports(index, statement, rows, fixture, scoped):
    aliases = {alias.asname or alias.name: alias for alias in statement.names}
    for bound, target in rows:
        alias = aliases.get(bound)
        module_path, _ = fixture._django_mod(index, target.rpartition(".")[0])
        if alias is not None and module_path is not None:
            scoped[bound] = (module_path, alias.name)


def _app_crypto_module_imports_for_statement(index, rows, fixture, scoped):
    for bound, target in rows:
        module_path, _ = fixture._django_mod(index, target)
        if module_path is not None:
            scoped[bound] = (module_path, None)


def _app_crypto_fixture_constructor_inert(index, pair):
    from . import mock_fixture_provenance as fixture

    assignment = pair["instance_assignment"]
    call = assignment.value if isinstance(assignment, ast.Assign) else None
    return bool(
        isinstance(call, ast.Call)
        and fixture._app_expression_name(
            index, pair["test_path"], call.func, pair["test_function"]
        )
        == pair["provider_canonical"]
        and len(call.args) == 1
        and not call.keywords
        and _legacy._immutable_default(call.args[0])
    )


def _app_crypto_methods(path, owner, source):
    names = ("__init__", "encrypt", "decrypt", "_derive_aesgcm")
    if (
        not source.validate(path)
        or source.parents[path].get(id(owner)) is not source.snapshots[path]
        or owner.decorator_list
        or owner.bases
        or owner.keywords
    ):
        return None
    for statement in owner.body:
        if isinstance(statement, ast.Expr) and isinstance(
            statement.value, ast.Constant
        ):
            if isinstance(statement.value.value, str):
                continue
        if not isinstance(statement, ast.FunctionDef):
            return None
        if _legacy._definition_effects_unknown(statement) or (
            statement.name.startswith("__") and statement.name != "__init__"
        ):
            return None
    methods = {}
    for name in names:
        selected = _legacy.effective_method([(path, owner.name, owner)], name)
        if (
            selected is None
            or selected[0] != path
            or _legacy.binding_occurrences(owner.body, name) != [selected[1]]
        ):
            return None
        methods[name] = selected[1]
    return methods


def _app_crypto_method_arguments(method, names):
    arguments = [*method.args.posonlyargs, *method.args.args]
    return bool(
        [row.arg for row in arguments] == list(names)
        and not method.args.vararg
        and not method.args.kwarg
        and not method.args.kwonlyargs
        and not method.args.defaults
        and not method.args.kw_defaults
        and not _legacy._definition_effects_unknown(method)
    )


def _app_crypto_aesgcm_call(index, path, function, call):
    from . import mock_fixture_provenance as fixture

    return bool(
        isinstance(call, ast.Call)
        and fixture._app_expression_name(index, path, call.func, function)
        == "cryptography.hazmat.primitives.ciphers.aead.AESGCM"
    )


def _app_crypto_initialization(index, path, owner, init):
    if not _app_crypto_method_arguments(init, ("self", "key")) or len(init.body) != 1:
        return None
    assignment = init.body[0]
    if not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1:
        return None
    target, call = assignment.targets[0], assignment.value
    if (
        not isinstance(target, ast.Attribute)
        or target.attr.startswith("__")
        or not _legacy._class_binding.instance_receiver(
            target, init, owner, index["source"], path
        )
        or not _app_crypto_aesgcm_call(index, path, init, call)
        or len(call.args) != 1
        or call.keywords
        or not isinstance(call.args[0], ast.Name)
        or call.args[0].id != "key"
        or [
            node
            for node in ast.walk(init)
            if isinstance(node, ast.Name)
            and node.id == "key"
            and isinstance(node.ctx, ast.Load)
        ]
        != [call.args[0]]
    ):
        return None
    return target.attr


def _app_exact_none_guard(node, name):
    return bool(
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.Is)
        and len(node.comparators) == 1
        and isinstance(node.left, ast.Name)
        and node.left.id == name
        and isinstance(node.comparators[0], ast.Constant)
        and node.comparators[0].value is None
    )


def _app_crypto_encrypt(index, path, owner, method, field):
    if (
        not _app_crypto_method_arguments(method, ("self", "data"))
        or len(method.body) != 2
    ):
        return False
    guard, statement = method.body
    if (
        not isinstance(guard, ast.If)
        or not _app_exact_none_guard(guard.test, "data")
        or guard.orelse
        or len(guard.body) != 1
    ):
        return False
    missing = guard.body[0]
    call = statement.value if isinstance(statement, ast.Return) else None
    if (
        not isinstance(missing, ast.Return)
        or not isinstance(missing.value, ast.Constant)
        or missing.value.value is not None
        or not isinstance(call, ast.Call)
        or not isinstance(call.func, ast.Attribute)
        or call.func.attr != "encrypt"
        or len(call.args) != 3
        or call.keywords
        or not isinstance(call.func.value, ast.Attribute)
        or call.func.value.attr != field
        or not _legacy._class_binding.instance_receiver(
            call.func.value, method, owner, index["source"], path
        )
    ):
        return False
    nonce, payload, aad = call.args
    if not isinstance(nonce, ast.Constant) or not isinstance(nonce.value, bytes):
        return False
    if not isinstance(aad, ast.Constant) or aad.value is not None:
        return False
    if not isinstance(payload, ast.Call) or payload.args or payload.keywords:
        return False
    if not isinstance(payload.func, ast.Attribute) or payload.func.attr != "encode":
        return False
    data = payload.func.value
    reads = [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Name)
        and node.id == "data"
        and isinstance(node.ctx, ast.Load)
    ]
    return (
        isinstance(data, ast.Name)
        and data.id == "data"
        and reads == [guard.test.left, data]
    )


def _app_crypto_derive(index, path, method):
    if (
        not _app_crypto_method_arguments(method, ("self", "salt"))
        or len(method.body) != 1
    ):
        return False
    statement = method.body[0]
    call = statement.value if isinstance(statement, ast.Return) else None
    if not _app_crypto_aesgcm_call(index, path, method, call):
        return False
    return bool(
        len(call.args) == 1
        and not call.keywords
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == "salt"
        and [
            node
            for node in ast.walk(method)
            if isinstance(node, ast.Name)
            and node.id == "salt"
            and isinstance(node.ctx, ast.Load)
        ]
        == [call.args[0]]
    )


def _app_crypto_decrypt(index, path, owner, method):
    if (
        not _app_crypto_method_arguments(method, ("self", "token"))
        or len(method.body) != 2
    ):
        return False
    assignment, statement = method.body
    if (
        not isinstance(assignment, ast.Assign)
        or len(assignment.targets) != 1
        or not isinstance(assignment.targets[0], ast.Name)
    ):
        return False
    derive = assignment.value
    if (
        not isinstance(derive, ast.Call)
        or not isinstance(derive.func, ast.Attribute)
        or derive.func.attr != "_derive_aesgcm"
        or len(derive.args) != 1
        or derive.keywords
        or not _legacy._class_binding.instance_receiver(
            derive.func.value, method, owner, index["source"], path
        )
        or not _legacy._immutable_default(derive.args[0])
    ):
        return False
    decoded = statement.value if isinstance(statement, ast.Return) else None
    if not isinstance(decoded, ast.Call) or decoded.args or decoded.keywords:
        return False
    crypt = (
        decoded.func.value
        if isinstance(decoded.func, ast.Attribute) and decoded.func.attr == "decode"
        else None
    )
    if (
        not isinstance(crypt, ast.Call)
        or not isinstance(crypt.func, ast.Attribute)
        or crypt.func.attr != "decrypt"
        or len(crypt.args) != 3
        or crypt.keywords
    ):
        return False
    token = crypt.args[1]
    return bool(
        isinstance(token, ast.Name)
        and token.id == "token"
        and isinstance(crypt.func.value, ast.Name)
        and crypt.func.value.id == assignment.targets[0].id
        and isinstance(crypt.args[0], ast.Constant)
        and isinstance(crypt.args[0].value, bytes)
        and isinstance(crypt.args[2], ast.Constant)
        and crypt.args[2].value is None
        and [
            node
            for node in ast.walk(method)
            if isinstance(node, ast.Name)
            and node.id == "token"
            and isinstance(node.ctx, ast.Load)
        ]
        == [token]
    )


def _app_plaintext_test_uses(index, path, function, secret, pair):
    from . import mock_fixture_provenance as fixture

    if not _app_roundtrip_token_closed(index, path, function, pair):
        return None
    roots = [
        ("transform_payload_input", pair["encrypt"].args[0]),
        ("local_roundtrip_comparison", pair["assertion"].test.comparators[0]),
    ]
    closure = _legacy._structural_closed_consumer_uses(
        function,
        secret,
        roots,
        index["source"].parents[path],
        lambda node: _legacy._enclosing_function(node, index["source"].parents[path]),
        lambda expression: fixture._app_credential_lineage(
            index, path, function, expression, secret
        ),
    )
    if closure is None:
        return None
    _, loads, roles = closure
    return [
        _app_credential_source_row(index, path, node, roles[id(node)], node.id)
        for node in sorted(loads, key=lambda item: (item.lineno, item.col_offset))
    ]


def _app_roundtrip_token_closed(index, path, function, pair):
    from . import mock_fixture_provenance as fixture

    token = pair["decrypt"].args[0]
    assignment = (
        fixture._app_local_assignment(function, token.id)
        if isinstance(token, ast.Name)
        else None
    )
    if assignment is None or assignment is not pair["token_assignment"]:
        return False
    loads = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id == token.id
        and isinstance(node.ctx, ast.Load)
    ]
    stores = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id == token.id
        and isinstance(node.ctx, ast.Store)
    ]
    return loads == [pair["decrypt"].args[0]] and stores == [assignment.targets[0]]


def _app_credential_source_row(index, path, node, role, name=""):
    from . import mock_fixture_provenance as fixture

    source = index["source"]
    return {
        "path": source.relative(path),
        "sha256": source.inventory[path],
        "span": fixture._evidence_node_span(node),
        "name": name,
        "role": role,
    }


def _app_incomplete_plaintext_evidence(
    index, path, assignment, function, secret, reason
):
    from . import mock_fixture_provenance as fixture

    origin = _app_credential_source_row(
        index, path, assignment, "plaintext_credential_origin", secret
    )
    return {
        "eligible": False,
        "source": index["source"].relative(path),
        "source_sha256": index["source"].inventory[path],
        "declaration_span": fixture._evidence_node_span(assignment),
        "value_effect": {
            "schema": "factory.credential-role-effect-summary.v1",
            "status": "INCOMPLETE",
            "material_role": "PLAINTEXT_CREDENTIAL_VALUE",
            "origin": origin,
            "owner": _app_credential_source_row(
                index, path, function, "test_owner", function.name
            ),
            "consumers": [],
            "providers": [],
            "persistence_role": "UNASSESSED",
            "transport_role": "UNASSESSED",
            "unknown_reasons": [reason],
        },
    }


def application_identity_helper_epoch():
    """Bind every moved application audit predicate and its core callees."""
    return (
        _legacy._APP_RECEIVER_HOOKS_CACHE_TOKEN,
        _TEST_SCOPE_CONTRACT_EPOCH,
        application_test_scope_role_evidence,
        application_value_role_evidence,
        _app_digest_call,
        _app_digest_bytes,
        _app_digest_algorithm_argument,
        _app_digest_bound_values,
        _app_digest_wrapper_return,
        _app_digest_test_owner,
        _app_digest_provider_binding,
        _app_digest_provider_closed,
        _app_digest_result_closure,
        _app_digest_operation_witnesses,
        _app_digest_receiver_closed,
        _app_digest_unrelated_provider_argument,
        _app_digest_receiver_aliases,
        _app_digest_receiver_reads_closed,
        _app_digest_lexical_read,
        _app_object_signing_authority,
        _app_signing_constructor_flow,
        _app_signing_constructor_transfer,
        _app_signing_metadata_assignments,
        _app_metadata_logger_result,
        _app_metadata_logging_environment_closed,
        _app_signing_ordinary_fields,
        _app_signing_constructor_resolver,
        _app_signing_constructor_role_transfer_closed,
        _app_signing_captured_provider_stable,
        _app_signing_provider_model_closed,
        _app_class_metadata_operands,
        _app_class_metadata_consumer,
        _app_metadata_formal_closed,
        _app_metadata_header_inert,
        _app_metadata_annotation_inert,
        _app_builtin_annotation_inert,
        _app_signing_transfer_chain,
        _app_signature_terminal,
        _app_signing_terminal_stable,
        _app_stdlib_type_reads_closed,
        _app_annotation_reference_only,
        _app_signing_parameter_field,
        _app_bound_field_transfer,
        _app_select_bound_field_transfer,
        _app_header_list_transfer,
        _app_request_verification_projection,
        _app_request_transfer_inputs,
        _app_request_signature_inputs,
        _app_success_guard_calls_parameter,
        _app_process_header_read,
        _app_process_body_read,
        _app_request_success_observation,
        _app_result_status_assertion,
        _app_test_header_signature_carrier,
        _app_header_carrier_method,
        _app_header_signature_lists,
        _app_header_signature_definition,
        _app_signature_producer_arguments,
        _app_signature_producer_matches,
        _app_request_verification_prefix_closed,
        _app_literal_branch_field_transfer,
        _app_signing_null_fallback,
        _app_signing_field_consumers,
        _app_verifier_property_flow,
        _app_verifier_property_header,
        _app_verifier_lazy_body,
        _app_receiver_field,
        _app_verifier_field_uses,
        _app_verifier_property_uses,
        _app_signature_verification_arguments,
        _app_object_signing_uses,
        _app_object_origin_references,
        _app_object_secret_uses,
        _app_object_owner_receiver_closed,
        _app_object_signing_pair,
        _app_object_pair_results_closed,
        _app_signing_helper_callers,
        _app_object_signer_receiver_closed,
        _app_object_verifier_receiver_closed,
        _app_object_verifier_use,
        _app_object_verifier_result,
        _app_fixed_verification_request,
        _app_fixed_request_literal_input,
        _app_fixed_request_verifier,
        _app_called_receiver_uses_closed,
        _app_receiver_attribute_use_closed,
        _app_object_verified_payload,
        _app_property_verification_operations,
        _app_terminal_verifier_operations,
        _app_object_method_exports_receiver,
        _app_object_receiver_projection_closed,
        _app_object_signing_witness,
        _app_signing_authority,
        _app_signing_origin_scopes,
        _app_class_signing_scopes,
        _app_signing_source_references,
        _app_signing_namespace_providers_closed,
        _app_namespace_projected_nodes,
        _app_signing_namespace_projection,
        _app_signing_origin_namespace_private,
        _app_signing_class_uses,
        _app_signing_class_export,
        _app_signing_slot_read,
        _app_signing_owner_closed,
        _app_signing_scope_edges,
        _app_signing_key_edge,
        _app_direct_jwt_key_edge,
        _app_captured_signing_key_edge,
        _app_wrapper_key_operations,
        _app_wrapper_key_operation,
        _app_signing_callee,
        _app_signing_callee_target,
        _app_signing_callee_method,
        _app_signing_receivers_closed,
        _app_signing_class_stable,
        _app_signing_class_spellings,
        _app_signing_class_source_closed,
        _app_signing_class_node_closed,
        _app_signing_class_method_receiver_use,
        _app_signing_provider_closed,
        _app_signing_provider_module_closed,
        _app_signing_provider_aliases,
        _app_signing_provider_private_access,
        _app_source_role_epoch,
        _app_signing_exception_projection,
        _app_signing_results_closed,
        _app_signing_encoded_tokens,
        _app_signing_decoded_tokens_closed,
        _app_signing_token_loads_closed,
        _app_factory_test_authority,
        _app_factory_test_context,
        _app_factory_nested_secret_use,
        _app_factory_creation_calls,
        _app_factory_exercised_requests,
        _app_factory_exercise_order_closed,
        _app_factory_permitted_uses,
        _app_factory_secret_loads,
        _app_factory_consumers_closed,
        _app_factory_authority_witness,
        _app_factory_material_use,
        _app_factory_authority_uses_closed,
        _app_factory_literal_assertion,
        _app_factory_test_decorators,
        _app_factory_provider,
        _app_factory_provider_selection,
        _app_factory_classes_closed,
        _app_factory_declaration_closed,
        _app_factory_meta_declaration_closed,
        _app_factory_field_declaration_closed,
        _app_factory_provider_closed,
        _app_factory_module_provider_closed,
        _app_factory_client_requests,
        _app_factory_assigned_client_requests,
        _app_factory_relative_request,
        _app_factory_inline_client_requests,
        _app_factory_inline_client_request,
        _app_factory_response_asserted,
        application_plaintext_effect_evidence,
        _application_effect_cache_key,
        _application_plaintext_effect_evidence_uncached,
        _app_local_crypto_roundtrip,
        _app_roundtrip_token_assignment,
        _app_roundtrip_assertion,
        _app_crypto_roundtrip_provider,
        _app_crypto_provider_imports,
        _app_crypto_module_imports,
        _app_crypto_from_imports,
        _app_crypto_module_imports_for_statement,
        _app_crypto_fixture_constructor_inert,
        _app_crypto_methods,
        _app_crypto_method_arguments,
        _app_crypto_aesgcm_call,
        _app_crypto_initialization,
        _app_exact_none_guard,
        _app_crypto_encrypt,
        _app_crypto_derive,
        _app_crypto_decrypt,
        _app_plaintext_test_uses,
        _app_roundtrip_token_closed,
        _app_credential_source_row,
        _app_incomplete_plaintext_evidence,
        _legacy.ResolvedIdentityCall,
        _legacy._argument_names,
        _legacy._call_has_expansion,
        _legacy._class_binding,
        _legacy._definition_effects_unknown,
        _legacy._enclosing_function,
        _legacy._event_span,
        _legacy._fixture_reflective_uses,
        _legacy._fixture_scope,
        _legacy._immutable_default,
        _legacy._method_stable,
        _legacy.assignment_target,
        _legacy.binding_occurrences,
        _legacy.effective_method,
        _legacy.module_fixture_helper_epoch,
        _legacy.summarize_identity_effect,
        application_identity_helper_epoch,
    )
