"""Bounded source-only identity-effect summaries for selected object roots."""

import ast
import hashlib
from collections import deque
from collections.abc import Callable, Mapping

from dataclasses import dataclass, field as _dataclass_field
from .credential_role_constructor_provider import resolve_class

from .credential_role_constructor_provider import binding_occurrences

from . import credential_role_constructor_provider as _class_binding

from . import credential_role_identity_effects as _identity_effects

from . import credential_role_constructor_provider as _scope_bindings

from .credential_role_constructor_provider import effective_method

from .credential_role_constructor_provider import SourceSnapshotIndex


@dataclass(frozen=True)
class ResolvedIdentityCall:
    """Captured callee with an exact formal-to-call-expression mapping."""

    function: ast.FunctionDef | ast.AsyncFunctionDef
    path: object
    arguments: Mapping[str, ast.expr]
    negative_binding_closed: bool = False
    negative_binding_check: Callable[[], bool] | None = None


@dataclass(frozen=True)
class SourceFieldLiteral:
    """Captured literal; caller proves current contents, ownership and no escape."""

    path: object
    value: ast.expr


@dataclass(frozen=True)
class IdentityEffectSummary:
    """May-effects; field writes do not change class identity."""

    status: str
    class_writes: tuple[str, ...] = ()
    escapes: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()
    field_writes: tuple[str, ...] = ()
    field_transfers: tuple["IdentityFieldTransfer", ...] = ()
    role_events: tuple["IdentityEffectEvent", ...] = ()
    return_values: tuple["IdentityReturnProjection", ...] = ()
    return_status: str = "UNKNOWN"

    @property
    def preserves_class_identity(self):
        """Report preserved class identity only for the no-class-effect summary status."""
        return self.status == "NO_CLASS_EFFECT"


@dataclass(frozen=True)
class _Value:
    roots: frozenset[str] = frozenset()
    items: tuple[tuple[object, "_Value"], ...] = ()
    class_roots: frozenset[str] = frozenset()
    unknown: bool = False
    content_unknown: bool = False
    inert_kind: str | None = None
    scalar_kind: str | None = None
    trace: tuple[tuple[object, ...], ...] = ()
    container_id: str | None = None


@dataclass(frozen=True)
class IdentityReturnProjection:
    """One source-bound possible return value; it does not replace return effects."""

    path: object
    source_span: tuple[object, ...]
    value: _Value


@dataclass(frozen=True)
class IdentityFieldTransfer:
    """Captured assignment from tracked source roots into one receiver field."""

    path: object
    target_root: str
    target_field: str
    source_roots: tuple[str, ...]
    statement: ast.AST
    value: ast.expr
    unconditional: bool


@dataclass(frozen=True)
class IdentityEffectEvent:
    """Root-attributed source event; descriptive evidence, not benign-use proof."""

    kind: str
    roots: tuple[str, ...]
    source_span: tuple[object, ...]
    relevant: str | None = None
    receiver_roots: tuple[str, ...] = ()
    uncertain: bool = False


@dataclass
class _Effects:
    class_writes: set[str] = _dataclass_field(default_factory=set)
    escapes: set[str] = _dataclass_field(default_factory=set)
    unknowns: set[str] = _dataclass_field(default_factory=set)
    field_writes: set[str] = _dataclass_field(default_factory=set)
    field_transfers: list[IdentityFieldTransfer] = _dataclass_field(
        default_factory=list
    )
    role_events: list[IdentityEffectEvent] = _dataclass_field(default_factory=list)
    record_role_events: bool = False
    return_values: list[IdentityReturnProjection] = _dataclass_field(
        default_factory=list
    )
    return_status: str = "UNKNOWN"

    def merge(self, other, *, include_returns=False):
        """Merge class writes, escapes, unknowns, and field writes from another effect accumulator."""
        for name in ("class_writes", "escapes", "unknowns", "field_writes"):
            getattr(self, name).update(getattr(other, name))
        self.field_transfers.extend(other.field_transfers)
        if include_returns:
            self.return_values.extend(other.return_values)
            self.return_status = other.return_status
        if self.record_role_events:
            self.role_events.extend(other.role_events)

    def freeze(self):
        """Freeze effect sets into a deterministically sorted summary, prioritizing unknowns, then writes, then escapes."""
        status = (
            "UNKNOWN"
            if self.unknowns
            else "CLASS_WRITE"
            if self.class_writes
            else "ESCAPE"
            if self.escapes
            else "NO_CLASS_EFFECT"
        )
        fields = ("class_writes", "escapes", "unknowns", "field_writes")
        return IdentityEffectSummary(
            status,
            *(tuple(sorted(getattr(self, name))) for name in fields),
            tuple(self.field_transfers),
            tuple(
                sorted(
                    set(self.role_events),
                    key=lambda event: (
                        repr(event.source_span),
                        event.kind,
                        event.relevant or "",
                        event.roots,
                        event.receiver_roots,
                        event.uncertain,
                    ),
                )
            )
            if self.record_role_events
            else (),
            tuple(self.return_values),
            self.return_status,
        )


def _event_span(path, node):
    return (
        str(path) if path is not None else None,
        getattr(node, "lineno", None),
        getattr(node, "col_offset", None),
        getattr(node, "end_lineno", None),
        getattr(node, "end_col_offset", None),
    )


def _role_expression_roots(node, aliases, *, strict_calls=False):
    """Retain receiver attribution for unknown property and bound-method values."""
    if node is None or not isinstance(node, ast.expr):
        return set()
    value = identity_value(node, aliases, strict_calls=strict_calls)
    roots = tracked_roots(value)
    if isinstance(node, ast.Attribute):
        receiver = tracked_roots(
            identity_value(node.value, aliases, strict_calls=strict_calls)
        )
        projected = [aliases.get((root, node.attr)) for root in receiver]
        known_projection = [item for item in projected if item is not None]
        if known_projection:
            roots.update(
                set().union(*(tracked_roots(item) for item in known_projection))
            )
        elif receiver:
            roots.update(receiver)
    elif isinstance(node, ast.Subscript) and not roots:
        roots.update(
            _role_expression_roots(node.value, aliases, strict_calls=strict_calls)
        )
    elif isinstance(node, (ast.List, ast.Tuple, ast.Dict)) and not roots:
        for child in ast.iter_child_nodes(node):
            roots.update(
                _role_expression_roots(child, aliases, strict_calls=strict_calls)
            )
    return roots


def _add_role_event(
    effects,
    kind,
    roots,
    path,
    node,
    relevant=None,
    *,
    receiver_roots=(),
    uncertain=False,
):
    if effects is None or not effects.record_role_events:
        return
    roots = tuple(sorted(set(roots)))
    receivers = tuple(sorted(set(receiver_roots)))
    if roots or receivers or uncertain:
        effects.role_events.append(
            IdentityEffectEvent(
                kind, roots, _event_span(path, node), relevant, receivers, uncertain
            )
        )


CallResolver = Callable[[ast.Call, object], ResolvedIdentityCall | None]


def contains_tracked(value):
    """Report whether an identity value contains any tracked roots, uncertainty, or nested items."""
    return bool(
        value.roots
        or value.class_roots
        or value.unknown
        or value.content_unknown
        or value.items
    )


def tracked_roots(value):
    """Collect direct and recursively nested tracked roots from an identity value."""
    roots = set(value.roots | value.class_roots)
    for _, item in value.items:
        roots.update(tracked_roots(item))
    return roots


def _has_unknown_content(value):
    return bool(
        value.unknown
        or value.content_unknown
        or any(_has_unknown_content(item) for _, item in value.items)
    )


def maps_each_actual_once(actuals, arguments):
    """Confirm each resolved formal maps to one distinct actual expression by AST identity."""
    expressions = tuple(arguments.values())
    return all(isinstance(expr, ast.expr) for expr in expressions) and sorted(
        map(id, expressions)
    ) == sorted(map(id, actuals))


def source_symbol_index(index):
    """Reuse the captured symbol/import wrapper across source-owned consumers."""
    wrapper = getattr(index, "_identity_symbol_index", None)
    if wrapper is None:
        module_paths = index.module_paths()
        if module_paths is None:
            return None
        wrapper = {
            "source": index,
            "modules": index.snapshots,
            "module_paths": module_paths,
            "imports": {},
            "profiles": {},
        }
        index._identity_symbol_index = wrapper
    return wrapper


def resolve_source_identity_call(
    call, path, index, *, lexical_scope=None, defer_negative_binding=False
):
    """Resolve one exact captured import/re-export and bind its source signature."""
    wrapper = _source_identity_call_context(call, path, index)
    if wrapper is None:
        return None
    from .mock_fixture_provenance import _app_source_symbol
    from .credential_role_constructor_provider import (
        _scope_scope_bindings,
    )
    from . import review_audits as audit

    lexical_scope = lexical_scope or _scope_scope_bindings(
        call, index.parents[path], None
    )
    if isinstance(lexical_scope, ast.Lambda) or _source_call_head_shadowed(
        call, index, path, audit
    ):
        return None
    provider_chain = []
    selected = _app_source_symbol(
        wrapper, path, call.func, lexical_scope, provider_chain=provider_chain
    )
    if selected is None:
        return None
    callee_path, function = selected
    if not _source_identity_function_supported(function):
        return None
    arguments = _bind_source_identity_call(call, index, callee_path, function)
    if arguments is None:
        return None
    from .mock_fixture_provenance import _app_expression_name, _django_name

    providers = _source_identity_provider_bindings(
        wrapper,
        path,
        call.func,
        lexical_scope,
        callee_path,
        function,
        provider_chain,
        _app_expression_name,
        _django_name,
    )
    check_binding = _source_identity_binding_check(
        index,
        call,
        path,
        callee_path,
        function,
        providers,
        audit,
        defer_negative_binding,
    )

    if defer_negative_binding:
        return ResolvedIdentityCall(
            function, callee_path, arguments, negative_binding_check=check_binding
        )
    return ResolvedIdentityCall(
        function, callee_path, arguments, negative_binding_closed=check_binding()
    )


def _source_identity_binding_check(
    index, call, path, callee_path, function, providers, audit, deferred
):
    from . import credential_role_constructor_provider as provider

    terminal_provider_mutation = provider._captured_terminal_provider_mutation

    def generation():
        return (
            index.root,
            frozenset(index.source_bytes),
            frozenset(index.inventory),
            tuple(
                (
                    p,
                    tree,
                    index.source_bytes.get(p),
                    index.inventory.get(p),
                    getattr(tree, "_oracle_source_sha256", None),
                )
                for p, tree in index.snapshots.items()
            ),
        )

    captured_generation = generation() if deferred else None
    captured_trees = {
        p: audit._oracle_tree_fingerprint(index.snapshots[p])
        for p in {path, callee_path}
    }

    def check_binding():
        if captured_generation is not None and _source_identity_generation_changed(
            index,
            path,
            callee_path,
            call,
            function,
            audit,
            generation,
            captured_generation,
            captured_trees,
        ):
            return False
        if not all(provider is not None for provider, _, _ in providers):
            return False
        if (
            provider._captured_terminal_provider_mutation
            is not terminal_provider_mutation
        ):
            return False
        bindings = tuple(
            (provider, (owner_path, name))
            for provider, owner_path, name in sorted(providers)
        )
        return not terminal_provider_mutation(
            index,
            audit,
            bindings[0][0],
            local_binding=bindings[0][1],
            additional_bindings=bindings[1:],
        )

    return check_binding


def _source_identity_generation_changed(
    index,
    path,
    callee_path,
    call,
    function,
    audit,
    generation,
    captured_generation,
    captured_trees,
):
    return (
        generation() != captured_generation
        or any(
            audit._oracle_tree_fingerprint(index.snapshots[p]) != digest
            for p, digest in captured_trees.items()
        )
        or not index.validate(path)
        or not index.validate(callee_path)
        or id(function) not in index.parents[callee_path]
        or id(call) not in index.parents[path]
    )


def _source_identity_call_context(call, path, index):
    if not isinstance(call, ast.Call) or not index.validate(path):
        return None
    return source_symbol_index(index)


def _bind_source_identity_call(call, index, callee_path, function):
    if (
        not index.validate(callee_path)
        or id(function) not in index.parents[callee_path]
    ):
        return None
    from .review_integrity import bind_source_call

    try:
        return bind_source_call(call, function, apply_defaults=True)
    except (TypeError, ValueError):
        return None


def _source_call_head_shadowed(call, index, path, audit):
    from .credential_role_constructor_provider import _presentation_provider_shadow

    head = call.func
    while isinstance(head, ast.Attribute):
        head = head.value
    return isinstance(head, ast.Name) and _presentation_provider_shadow(
        call, head.id, index, path, audit
    )


def _source_identity_function_supported(function):
    return (
        isinstance(function, ast.FunctionDef)
        and not function.decorator_list
        and function.args.vararg is None
        and function.args.kwarg is None
    )


def _source_identity_provider_bindings(
    wrapper,
    path,
    func,
    scope,
    callee_path,
    function,
    chain,
    expression_name,
    django_name,
):
    return {
        (expression_name(wrapper, path, func, scope), callee_path, function.name),
        *chain,
        *(
            (django_name(wrapper, owner_path) + "." + name, owner_path, name)
            for _, owner_path, name in chain
        ),
    }


_UNKNOWN_KEY = object()


def identity_value(node, aliases, *, strict_calls=False, material_values=False):
    """Share value algebra while separating possible data origins from exact identity."""
    projected = (
        aliases.get(("expression", id(node))) if isinstance(node, ast.expr) else None
    )
    if isinstance(projected, _Value):
        return _value_with_trace(projected, node, "BOUND_EXPRESSION")
    if isinstance(node, ast.BinOp):
        scalar_add = _known_scalar_add(node, aliases)
        if scalar_add is not None:
            return scalar_add
    return _dispatch_identity_value(node, aliases, strict_calls, material_values)


def _known_scalar_add(node, aliases):
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Add):
        return None
    values = (
        identity_value(node.left, aliases, strict_calls=True),
        identity_value(node.right, aliases, strict_calls=True),
    )
    if (
        any(
            value.unknown
            or value.content_unknown
            or value.class_roots
            or value.items
            or value.inert_kind != "scalar"
            or value.scalar_kind not in {"text", "bytes"}
            for value in values
        )
        or values[0].scalar_kind != values[1].scalar_kind
    ):
        return None
    return _Value(
        roots=frozenset().union(*(value.roots for value in values)),
        inert_kind="scalar",
        scalar_kind=values[0].scalar_kind,
        trace=(
            *values[0].trace,
            *values[1].trace,
            _value_trace(node, "BUILTIN_SCALAR_ADD"),
        )[:64],
    )


def _dispatch_identity_value(node, aliases, strict_calls, material_values):
    handlers = (
        (ast.Constant, _constant_identity_value),
        (ast.Name, _name_identity_value),
        (ast.Attribute, _attribute_value),
        ((ast.List, ast.Tuple, ast.Dict), _container_value),
        (ast.Subscript, _subscript_value),
        (ast.Call, _identity_call_value),
    )
    handler = next((item for kind, item in handlers if isinstance(node, kind)), None)
    if handler is None:
        return _unknown_expression(
            node, aliases, strict_calls=strict_calls, material_values=material_values
        )
    if handler is _constant_identity_value:
        return handler(node)
    if handler is _name_identity_value:
        return handler(node, aliases, material_values)
    return handler(
        node, aliases, strict_calls=strict_calls, material_values=material_values
    )


def _constant_identity_value(node):
    scalar = {str: "text", bytes: "bytes", bool: "boolean", int: "integer"}.get(
        type(node.value), "none" if node.value is None else "scalar"
    )
    return _Value(
        inert_kind="scalar", scalar_kind=scalar, trace=(_value_trace(node, "CONSTANT"),)
    )


def _name_identity_value(node, aliases, material_values):
    value = aliases.get(node.id, _Value(unknown=material_values))
    return _value_with_trace(value, node, "ALIAS_USE")


def _identity_call_value(node, aliases, *, strict_calls=False, material_values=False):
    if material_values:
        formatted = _structural_scalar_format(node, aliases)
        if formatted is not None:
            return formatted
    if (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in {"encode", "decode"}
        and not node.args
        and not node.keywords
    ):
        receiver = identity_value(
            node.func.value,
            aliases,
            strict_calls=strict_calls,
            material_values=material_values,
        )
        incoming, outgoing = (
            ("text", "bytes") if node.func.attr == "encode" else ("bytes", "text")
        )
        if (
            not receiver.unknown
            and not receiver.content_unknown
            and receiver.scalar_kind == incoming
        ):
            return _Value(
                roots=receiver.roots,
                items=receiver.items,
                class_roots=receiver.class_roots,
                unknown=False,
                content_unknown=False,
                inert_kind=receiver.inert_kind,
                scalar_kind=outgoing,
                trace=(
                    *receiver.trace,
                    _value_trace(node, "BUILTIN_" + node.func.attr.upper()),
                ),
            )
    if isinstance(node.func, ast.Attribute) and node.func.attr == "__class__":
        receiver = identity_value(
            node.func.value,
            aliases,
            strict_calls=strict_calls,
            material_values=material_values,
        )
        if contains_tracked(receiver):
            return _Value(
                roots=frozenset(tracked_roots(receiver))
                if material_values
                else frozenset(),
                unknown=True,
                content_unknown=material_values,
                trace=(*receiver.trace, _value_trace(node, "UNKNOWN_CLASS_CALL")),
            )
    value = _unknown_expression(
        node, aliases, strict_calls=strict_calls, material_values=material_values
    )
    if not material_values:
        return _Value(content_unknown=True) if strict_calls else value
    return _Value(
        roots=value.roots,
        items=value.items,
        class_roots=value.class_roots,
        unknown=True,
        content_unknown=True,
        trace=(*value.trace, _value_trace(node, "OPAQUE_CALL")),
    )


def _subscript_value(node, aliases, *, strict_calls=False, material_values=False):
    base = identity_value(
        node.value, aliases, strict_calls=strict_calls, material_values=material_values
    )
    key = node.slice.value if isinstance(node.slice, ast.Constant) else None
    if strict_calls and base.content_unknown:
        if not material_values:
            return _Value(
                roots=tracked_roots(base),
                class_roots=base.class_roots,
                unknown=True,
                content_unknown=True,
                trace=(
                    *base.trace,
                    _value_trace(node, "UNKNOWN_CONTAINER_SELECT"),
                ),
            )
        selected = dict(base.items).get(key, _Value())
        return _Value(
            roots=frozenset(tracked_roots(base) | tracked_roots(selected)),
            items=selected.items,
            class_roots=selected.class_roots | base.class_roots,
            unknown=True,
            content_unknown=True,
            scalar_kind=selected.scalar_kind,
            trace=(
                *dict.fromkeys((*base.trace, *selected.trace)),
                _value_trace(node, "UNKNOWN_CONTAINER_SELECT"),
            ),
        )
    selected = dict(base.items).get(key, _Value(unknown=contains_tracked(base)))
    return _value_with_trace(selected, node, "CONTAINER_SELECT")


def _structural_scalar_format(node, aliases):
    """Track material origins through literal formats with primitive operands only."""
    if not (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(node.func.value, ast.Constant)
        and type(node.func.value.value) is str
        and len(node.func.value.value) <= 4096
        and len(node.args) <= 32
        and not node.keywords
    ):
        return None
    from string import Formatter

    try:
        fields = list(Formatter().parse(node.func.value.value))
    except ValueError:
        return None
    if any(
        field is not None and (field and not field.isdecimal() or spec or conversion)
        for _, field, spec, conversion in fields
    ):
        return None
    selected = [field for _, field, _, _ in fields if field is not None]
    if (
        selected.count("") > len(node.args)
        or "" in selected
        and any(selected)
        or any(field and int(field) >= len(node.args) for field in selected)
    ):
        return None
    values = [
        identity_value(arg, aliases, strict_calls=True, material_values=True)
        for arg in node.args
    ]
    if any(
        value.unknown
        or value.content_unknown
        or value.items
        or value.class_roots
        or value.scalar_kind not in {"text", "bytes", "integer", "boolean"}
        for value in values
    ):
        return None
    trace = tuple(dict.fromkeys(step for value in values for step in value.trace))
    if len(trace) >= 64:
        return None
    return _Value(
        roots=frozenset().union(*(value.roots for value in values)),
        scalar_kind="text",
        trace=(*trace, _value_trace(node, "TEXT_INTERPOLATION")),
    )


def _unknown_expression(node, aliases, *, strict_calls=False, material_values=False):
    roots = set()
    if isinstance(node, ast.expr):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and not node.args
            and not node.keywords
        ):
            roots.update(tracked_roots(aliases.get(node.func.id, _Value())))
        else:
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                    roots.update(tracked_roots(aliases.get(child.id, _Value())))
    return _Value(
        roots=frozenset(roots),
        unknown=material_values or bool(roots),
        trace=(_value_trace(node, "UNKNOWN_EXPRESSION"),),
    )


def _value_trace(node, operation):
    try:
        digest = hashlib.sha256(
            ast.dump(node, include_attributes=False).encode("utf-8")
        ).hexdigest()
    except (TypeError, ValueError):
        digest = ""
    return (
        operation,
        (
            getattr(node, "lineno", None),
            getattr(node, "col_offset", None),
            getattr(node, "end_lineno", None),
            getattr(node, "end_col_offset", None),
        ),
        digest,
    )


def _value_with_trace(value, node, operation):
    trace = (*value.trace, _value_trace(node, operation))
    exhausted = len(trace) > 64
    return _Value(
        roots=value.roots,
        items=value.items,
        class_roots=value.class_roots,
        unknown=value.unknown or exhausted,
        content_unknown=value.content_unknown or exhausted,
        inert_kind=value.inert_kind,
        scalar_kind=value.scalar_kind,
        trace=trace[:64],
        container_id=value.container_id,
    )


def _unproved_return_binding(value, call):
    from dataclasses import replace

    return replace(
        _value_with_trace(value, call, "UNPROVED_HELPER_PROVIDER"),
        items=tuple(
            (key, _unproved_return_binding(child, call)) for key, child in value.items
        ),
    )


def _container_value(node, aliases, *, strict_calls=False, material_values=False):
    if isinstance(node, (ast.List, ast.Tuple, ast.Dict)):
        pairs = (
            zip(node.keys, node.values)
            if isinstance(node, ast.Dict)
            else enumerate(node.elts)
        )
        items, unknown = [], False
        for key, item in pairs:
            value = identity_value(
                item,
                aliases,
                strict_calls=strict_calls,
                material_values=material_values,
            )
            if isinstance(node, ast.Dict) and not isinstance(key, ast.Constant):
                key_value = (
                    identity_value(
                        key,
                        aliases,
                        strict_calls=strict_calls,
                        material_values=material_values,
                    )
                    if isinstance(key, ast.expr)
                    else _Value()
                )
                if contains_tracked(value) or contains_tracked(key_value):
                    unknown = True
                    items.append(
                        (
                            _UNKNOWN_KEY,
                            _Value(items=(("key", key_value), ("value", value))),
                        )
                    )
            else:
                items.append(
                    (key.value if isinstance(key, ast.Constant) else key, value)
                )
        return _Value(
            items=tuple(items),
            unknown=unknown,
            inert_kind=_inert_container(node, items),
            scalar_kind=type(node).__name__.lower(),
            trace=(_value_trace(node, "CONTAINER"),),
            container_id=_container_identity(node),
        )
    return _Value()


def _container_identity(node):
    trace = _value_trace(node, "CONTAINER")
    return hashlib.sha256(repr((trace[1], trace[2])).encode("utf-8")).hexdigest()


def _unknown_value(value, reason):
    items = tuple((key, _unknown_value(item, reason)) for key, item in value.items)
    trace = (*value.trace, (reason, (), ""))
    return _Value(
        roots=value.roots,
        items=items,
        class_roots=value.class_roots,
        unknown=True,
        content_unknown=True,
        inert_kind=value.inert_kind,
        scalar_kind=value.scalar_kind,
        trace=trace[-64:],
        container_id=value.container_id,
    )


def _value_container_ids(value):
    result = {value.container_id} if value.container_id else set()
    for _, item in value.items:
        result.update(_value_container_ids(item))
    return result


def _container_value_shape(value):
    return (
        value.container_id,
        tuple((key, _container_value_shape(item)) for key, item in value.items),
    )


def join_identity_values(values, *, max_states=512, max_depth=32):
    """Join bounded may-values recursively without dropping nested origins."""
    values = tuple(values)
    if not values:
        return _Value(unknown=True, content_unknown=True)
    if len(values) > max_states or any(
        not isinstance(value, _Value) for value in values
    ):
        possible = [value for value in values if isinstance(value, _Value)]
        return _Value(
            roots=frozenset().union(*(tracked_roots(value) for value in possible)),
            class_roots=frozenset().union(*(value.class_roots for value in possible)),
            unknown=True,
            content_unknown=True,
        )
    return _join_identity_values(values, [0], max_states, max_depth, 0)


def _join_identity_values(selected, states, max_states, max_depth, depth):
    states[0] += 1
    roots = frozenset().union(*(value.roots for value in selected))
    classes = frozenset().union(*(value.class_roots for value in selected))
    if states[0] > max_states or depth > max_depth:
        return _Value(
            roots=frozenset(set().union(*(tracked_roots(value) for value in selected))),
            class_roots=classes,
            unknown=True,
            content_unknown=True,
        )
    if all(value == selected[0] for value in selected[1:]):
        value = selected[0]
        return (
            _unknown_value(value, "VALUE_TRACE_BUDGET")
            if len(value.trace) > 64
            else value
        )
    maps = [dict(value.items) for value in selected]
    keys = list(dict.fromkeys(key for mapping in maps for key in mapping))
    if len(keys) > 128:
        roots = frozenset(
            set(roots).union(*(tracked_roots(value) for value in selected))
        )
    items = [
        (
            key,
            _join_identity_values(
                [mapping[key] for mapping in maps if key in mapping],
                states,
                max_states,
                max_depth,
                depth + 1,
            ),
        )
        for key in keys[:128]
    ]
    return _joined_identity_value(selected, roots, classes, items)


def _joined_identity_value(selected, roots, classes, items):
    traces = tuple(dict.fromkeys(step for value in selected for step in value.trace))
    container_ids = {value.container_id for value in selected}
    return _Value(
        roots=roots,
        items=tuple(items),
        class_roots=classes,
        unknown=True,
        content_unknown=True,
        inert_kind=selected[0].inert_kind
        if all(value.inert_kind == selected[0].inert_kind for value in selected)
        else None,
        scalar_kind=selected[0].scalar_kind
        if all(value.scalar_kind == selected[0].scalar_kind for value in selected)
        else None,
        trace=traces[:64],
        container_id=next(iter(container_ids)) if len(container_ids) == 1 else None,
    )


def invalidate_structural_statement(statement, environment):
    """Invalidate every source-visible mutable alias touched or escaped by a statement."""
    if not isinstance(environment, dict):
        return False

    nodes = tuple(ast.walk(statement))
    parents = {
        id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)
    }
    changed_values = _structural_mutation_facts(statement, environment, parents, nodes)
    if not any(changed_values):
        return False
    mutated_ids, mutated_shapes, receiver_roots = changed_values
    changed = False
    for name, value in tuple(environment.items()):
        if not isinstance(value, _Value):
            continue
        if _structural_value_affected(
            name, value, mutated_ids, mutated_shapes, receiver_roots
        ):
            environment[name] = _unknown_value(value, "MUTABLE_ALIAS_OR_ESCAPE")
            changed = True
    return changed


def _structural_mutation_facts(statement, environment, parents, nodes):
    mutated_ids, mutated_shapes, receiver_roots = set(), set(), set()
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            parent = parents.get(id(node))
            if (
                isinstance(parent, (ast.Subscript, ast.Attribute))
                and parent.ctx is node.ctx
            ):
                _register_structural_mutation(
                    parent.value,
                    environment,
                    mutated_ids,
                    mutated_shapes,
                    receiver_roots,
                )
            elif isinstance(parent, ast.AugAssign) and parent.target is node:
                _register_structural_mutation(
                    node, environment, mutated_ids, mutated_shapes, receiver_roots
                )
        elif isinstance(node, ast.Call):
            _register_structural_mutation(
                node.func.value if isinstance(node.func, ast.Attribute) else None,
                environment,
                mutated_ids,
                mutated_shapes,
                receiver_roots,
            )
            for argument in [*node.args, *(keyword.value for keyword in node.keywords)]:
                _register_structural_mutation(
                    argument, environment, mutated_ids, mutated_shapes, receiver_roots
                )
    targets = (
        [*statement.targets]
        if isinstance(statement, (ast.Assign, ast.Delete))
        else [statement.target]
        if isinstance(statement, (ast.AnnAssign, ast.AugAssign))
        else []
    )
    for target in targets:
        if isinstance(target, (ast.Attribute, ast.Subscript)):
            _register_structural_mutation(
                target.value, environment, mutated_ids, mutated_shapes, receiver_roots
            )
        elif isinstance(statement, ast.AugAssign) and isinstance(target, ast.Name):
            _register_structural_mutation(
                target, environment, mutated_ids, mutated_shapes, receiver_roots
            )
    return mutated_ids, mutated_shapes, receiver_roots


def _register_structural_mutation(
    expression, environment, mutated_ids, mutated_shapes, receiver_roots
):
    if not isinstance(expression, ast.expr):
        return
    value = identity_value(
        expression, environment, strict_calls=True, material_values=True
    )
    ids = _value_container_ids(value)
    if ids:
        mutated_ids.update(ids)
    elif value.items:
        mutated_shapes.add(_container_value_shape(value))
    receiver_roots.update(value.roots)


def _structural_value_affected(
    name, value, mutated_ids, mutated_shapes, receiver_roots
):
    if _value_container_ids(value) & mutated_ids:
        return True
    if (
        mutated_shapes
        and value.items
        and _container_value_shape(value) in mutated_shapes
    ):
        return True
    return isinstance(name, tuple) and len(name) == 2 and name[0] in receiver_roots


def call_has_unknown_value(call, aliases, *, strict_calls=False):
    """Detect unknown content among a call's arguments and method receiver."""
    args = [*call.args, *(item.value for item in call.keywords)]
    if isinstance(call.func, ast.Attribute):
        args.append(call.func.value)
    return any(
        _has_unknown_content(identity_value(arg, aliases, strict_calls=strict_calls))
        for arg in args
    )


def call_argument_roots(call, aliases, *, strict_calls=False):
    """Collect tracked roots from positional and keyword call arguments."""
    args = [*call.args, *(item.value for item in call.keywords)]
    return set().union(
        *(
            tracked_roots(identity_value(arg, aliases, strict_calls=strict_calls))
            for arg in args
        )
    )


def call_tracked_roots(call, aliases, *, strict_calls=False):
    """Collect tracked roots from call arguments and, for method or constructor expressions, the receiver identity."""
    roots = call_argument_roots(call, aliases, strict_calls=strict_calls)
    if isinstance(call.func, ast.Attribute):
        roots.update(
            tracked_roots(
                identity_value(call.func.value, aliases, strict_calls=strict_calls)
            )
        )
    elif isinstance(call.func, ast.Call):
        roots.update(
            identity_value(call.func, aliases, strict_calls=strict_calls).class_roots
        )
    return roots


def assignment_target(node):
    """Return the sole assignment target for a simple assignment or annotated assignment; reject multi-target assignments."""
    if isinstance(node, ast.Assign):
        return node.targets[0] if len(node.targets) == 1 else None
    return getattr(node, "target", None)


def nested_capture_roots(
    function, path, aliases, index, *, strict_calls=False, effects=None
):
    """Collect tracked roots captured by nested scopes and mark unresolved captures as unknown in strict mode."""
    pass

    captured, tracked = set(), set(aliases)
    for node in ast.walk(function):
        _capture_nested_scope(
            node,
            function,
            path,
            tracked,
            aliases,
            index,
            strict_calls,
            effects,
            captured,
        )
    return captured


def _capture_nested_scope(
    node, function, path, tracked, aliases, index, strict_calls, effects, captured
):
    scopes = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
    if node is function or not isinstance(node, scopes):
        return
    parent = index.parents[path].get(id(node))
    while parent is not None and parent is not function:
        parent = index.parents[path].get(id(parent))
    if parent is not function:
        return
    if strict_calls and _definition_effects_unknown(node):
        effects.unknowns.add("unmodeled nested definition-time effects")
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in tracked:
            roots = tracked_roots(aliases[child.id])
            captured.update(roots)
            _add_role_event(
                effects,
                "nested_capture",
                roots,
                path,
                child,
                child.id,
                uncertain=_has_unknown_content(aliases[child.id]),
            )
            if strict_calls and _has_unknown_content(aliases[child.id]):
                effects.unknowns.add("nested scope captures unresolved tracked value")


def record_write(
    target,
    value,
    aliases,
    effects,
    *,
    strict_calls=False,
    source_node=None,
    path=None,
    function=None,
    parents=None,
    initial_fields=None,
    ordinary_fields=(),
):
    """Record attribute or container writes, including escaped roots and unresolved stored values where strict analysis requires it."""
    if isinstance(target, ast.Attribute):
        return _record_attribute_write(
            target,
            value,
            aliases,
            effects,
            strict_calls=strict_calls,
            source_node=source_node,
            path=path,
            function=function,
            parents=parents,
            initial_fields=initial_fields,
            ordinary_fields=ordinary_fields,
        )
    elif isinstance(target, ast.Subscript):
        base = identity_value(target.value, aliases, strict_calls=strict_calls)
        if base.roots or contains_tracked(base) or base.inert_kind in {"dict", "list"}:
            effects.unknowns.add("write through tracked container")
        if strict_calls and _has_unknown_content(value):
            effects.unknowns.add("field stores unresolved tracked value")
        effects.escapes.update(tracked_roots(value))
        _add_role_event(
            effects,
            "container_write",
            tracked_roots(value),
            path,
            source_node or target,
            "subscript",
            receiver_roots=tracked_roots(base),
            uncertain=contains_tracked(base) or _has_unknown_content(value),
        )


def record_escape(
    node,
    aliases,
    effects,
    reason,
    *,
    strict_calls=False,
    path=None,
    event_kind="escape",
    relevant=None,
):
    """Record escaped roots and mark the supplied effect unknown when the escaping value has unresolved content."""
    value = identity_value(node, aliases, strict_calls=strict_calls)
    effects.escapes.update(tracked_roots(value))
    if value.unknown or (strict_calls and _has_unknown_content(value)):
        effects.unknowns.add(reason + " contains unresolved tracked value")
    _add_role_event(
        effects,
        event_kind,
        _role_expression_roots(node, aliases, strict_calls=strict_calls),
        path,
        node,
        relevant or reason,
        uncertain=value.unknown or (strict_calls and _has_unknown_content(value)),
    )


def _inert_container(node, items):
    if isinstance(node, ast.Dict) and not all(
        isinstance(key, ast.Constant) for key in node.keys
    ):
        return None
    return (
        type(node).__name__.lower()
        if all(value.inert_kind is not None for _, value in items)
        else None
    )


def _attribute_value(node, aliases, *, strict_calls=False, material_values=False):
    base = identity_value(
        node.value, aliases, strict_calls=strict_calls, material_values=material_values
    )
    if node.attr == "__class__" and base.roots:
        return _Value(class_roots=base.roots)
    if len(base.roots) == 1 and not base.unknown and not base.class_roots:
        projected = aliases.get((next(iter(base.roots)), node.attr))
        if projected is not None:
            return _value_with_trace(projected, node, "FIELD_SELECT")
    if strict_calls and base.roots and not base.class_roots and not base.unknown:
        if not material_values:
            return _Value(content_unknown=True)
        return _Value(
            roots=base.roots,
            unknown=True,
            content_unknown=True,
            trace=(*base.trace, _value_trace(node, "UNKNOWN_FIELD")),
        )
    if strict_calls and base.content_unknown:
        if not material_values:
            return _Value(unknown=True)
        return _Value(
            roots=base.roots,
            class_roots=base.class_roots,
            unknown=True,
            content_unknown=True,
            trace=(*base.trace, _value_trace(node, "UNKNOWN_FIELD")),
        )
    return _Value(
        roots=base.roots if material_values else frozenset(),
        class_roots=base.class_roots if material_values else frozenset(),
        unknown=bool(base.roots or base.class_roots or base.unknown),
        content_unknown=base.content_unknown,
        trace=(*base.trace, _value_trace(node, "UNKNOWN_FIELD")),
    )


def _record_attribute_write(
    target,
    value,
    aliases,
    effects,
    *,
    strict_calls=False,
    source_node=None,
    path=None,
    function=None,
    parents=None,
    initial_fields=None,
    ordinary_fields=(),
):
    base = identity_value(target.value, aliases, strict_calls=strict_calls)
    if base.roots:
        _record_tracked_attribute_write(
            target,
            value,
            base,
            aliases,
            effects,
            strict_calls=strict_calls,
            source_node=source_node,
            path=path,
            function=function,
            parents=parents,
            initial_fields=initial_fields,
            ordinary_fields=ordinary_fields,
        )
    else:
        _record_external_attribute_write(
            target,
            value,
            aliases,
            effects,
            strict_calls=strict_calls,
            source_node=source_node,
            path=path,
        )


def _record_tracked_attribute_write(
    target,
    value,
    base,
    aliases,
    effects,
    *,
    strict_calls,
    source_node,
    path,
    function,
    parents,
    initial_fields,
    ordinary_fields,
):
    field_ids = {f"{root}.{target.attr}" for root in base.roots}
    if any((root, target.attr) in (initial_fields or {}) for root in base.roots) or (
        effects.record_role_events and field_ids.intersection(effects.field_writes)
    ):
        effects.unknowns.add("projected field identity overwritten")
    if target.attr == "__class__":
        effects.class_writes.update(base.roots)
        if effects.record_role_events and (base.unknown or base.content_unknown):
            effects.unknowns.add("class write receiver identity is unresolved")
        _add_role_event(
            effects, "class_write", base.roots, path, source_node or target, target.attr
        )
    else:
        _record_tracked_field_store(
            target,
            value,
            base,
            aliases,
            effects,
            strict_calls=strict_calls,
            source_node=source_node,
            path=path,
            function=function,
            parents=parents,
            ordinary_fields=ordinary_fields,
        )
    effects.escapes.update(tracked_roots(value))
    if value.unknown:
        effects.unknowns.add("field stores unresolved tracked value")


def _record_tracked_field_store(
    target,
    value,
    base,
    aliases,
    effects,
    *,
    strict_calls,
    source_node,
    path,
    function,
    parents,
    ordinary_fields,
):
    effects.field_writes.update(f"{root}.{target.attr}" for root in base.roots)
    if source_node is not None and path is not None and function is not None:
        effects.field_transfers.extend(
            IdentityFieldTransfer(
                path,
                root,
                target.attr,
                tuple(sorted(tracked_roots(value))),
                parents.get(id(source_node)) if parents else None,
                source_node,
                _field_transfer_unconditional(source_node, function, parents),
            )
            for root in sorted(base.roots)
        )
    source_roots = (
        _role_expression_roots(source_node, aliases, strict_calls=strict_calls)
        if source_node is not None
        else tracked_roots(value)
    )
    _add_role_event(
        effects,
        "field_store",
        source_roots,
        path,
        source_node or target,
        target.attr,
        receiver_roots=base.roots,
        uncertain=(
            value.unknown
            or _has_unknown_content(value)
            or not (source_roots or value.inert_kind or value.items)
        ),
    )
    if (
        effects.record_role_events
        and target.attr not in ordinary_fields
        and not _ordinary_field_dispatch(function, target.attr, parents)
    ):
        effects.unknowns.add("attribute store dispatch is not source-closed")
        _add_role_event(
            effects,
            "attribute_dispatch_unknown",
            source_roots,
            path,
            source_node or target,
            target.attr,
            receiver_roots=base.roots,
            uncertain=True,
        )
    backreferences = set(source_roots).intersection(base.roots)
    if backreferences:
        _add_role_event(
            effects,
            "backreference_field_store",
            backreferences,
            path,
            source_node or target,
            target.attr,
            receiver_roots=base.roots,
        )


def _record_external_attribute_write(
    target, value, aliases, effects, *, strict_calls, source_node, path
):
    effects.escapes.update(tracked_roots(value))
    _add_role_event(
        effects,
        "external_field_store",
        _role_expression_roots(source_node, aliases, strict_calls=strict_calls)
        if source_node is not None
        else tracked_roots(value),
        path,
        source_node or target,
        target.attr if isinstance(target, ast.Attribute) else None,
        uncertain=value.unknown or _has_unknown_content(value),
    )
    if strict_calls and _has_unknown_content(value):
        effects.unknowns.add("field stores unresolved tracked value")
    if contains_tracked(identity_value(target, aliases, strict_calls=strict_calls)):
        effects.unknowns.add("write through tracked value")


def _field_transfer_unconditional(source_node, function, parents):
    if parents is None:
        return False
    control = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.With,
        ast.AsyncWith,
        ast.Match,
        ast.ExceptHandler,
    )
    node = source_node
    while node is not function:
        node = parents.get(id(node))
        if node is None or isinstance(node, control):
            return False
    return True


def _ordinary_field_dispatch(function, field_name, parents):
    owner = parents.get(id(function)) if parents else None
    if not isinstance(owner, ast.ClassDef) or owner.bases:
        return False
    if any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name
        in {"__getattribute__", "__getattr__", "__setattr__", "__delattr__"}
        for node in owner.body
    ):
        return False
    for node in owner.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == field_name and node.decorator_list:
                return False
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            target = assignment_target(node)
            if isinstance(target, ast.Name) and target.id in {field_name, "__slots__"}:
                return False
    return True


def _join_field_values(values, *, uncertain=False):
    values = tuple(values)
    if not values:
        return _Value(unknown=True)
    if not uncertain and all(value == values[0] for value in values[1:]):
        return values[0]
    roots = set().union(*(tracked_roots(value) for value in values))
    classes = set().union(*(value.class_roots for value in values))
    return _Value(
        roots=frozenset(roots),
        class_roots=frozenset(classes),
        unknown=True,
        content_unknown=any(_has_unknown_content(value) for value in values),
    )


def _field_projection_value(receiver_root, value):
    """Keep self-backreferences attributable and unresolved when read back."""
    if receiver_root not in tracked_roots(value):
        return value
    return _Value(
        roots=value.roots,
        items=value.items,
        class_roots=value.class_roots,
        unknown=True,
        content_unknown=value.content_unknown,
        inert_kind=value.inert_kind,
        scalar_kind=value.scalar_kind,
        trace=value.trace,
    )


def record_opaque_call(call, aliases, involved, out, *, strict_calls=False, path=None):
    """Record tracked roots as escaping when an opaque call receives them; otherwise mark the call as unresolved."""
    if call_argument_roots(call, aliases, strict_calls=strict_calls):
        out.escapes.update(involved)
        _add_role_event(
            out,
            "opaque_call_escape",
            _role_expression_roots(call, aliases, strict_calls=strict_calls),
            path,
            call,
            _call_role_actuals(call, aliases, strict_calls=strict_calls),
            receiver_roots=(
                _role_expression_roots(
                    call.func.value, aliases, strict_calls=strict_calls
                )
                if isinstance(call.func, ast.Attribute)
                else ()
            ),
            uncertain=call_has_unknown_value(call, aliases, strict_calls=strict_calls),
        )
    else:
        out.unknowns.add("unresolved method call on tracked object")
        _add_role_event(
            out,
            "unresolved_method_call",
            involved,
            path,
            call,
            _call_role_actuals(call, aliases, strict_calls=strict_calls),
            receiver_roots=(
                _role_expression_roots(
                    call.func.value, aliases, strict_calls=strict_calls
                )
                if isinstance(call.func, ast.Attribute)
                else ()
            ),
            uncertain=True,
        )


def _call_role_actuals(call, aliases, *, strict_calls=False):
    actuals = [
        f"arg[{i}]"
        for i, value in enumerate(call.args)
        if _role_expression_roots(value, aliases, strict_calls=strict_calls)
    ]
    actuals.extend(
        f"keyword:{item.arg}"
        for item in call.keywords
        if item.arg
        and _role_expression_roots(item.value, aliases, strict_calls=strict_calls)
    )
    if isinstance(call.func, ast.Attribute) and _role_expression_roots(
        call.func.value, aliases, strict_calls=strict_calls
    ):
        actuals.append("receiver")
    return ",".join(actuals) or "ambient"


def strict_read_effects(node, aliases, parents, out):
    """Unknown names and properties may hide behavior without a Call node."""
    if not isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) or not isinstance(
        node.ctx, ast.Load
    ):
        return
    parent = parents.get(id(node))
    if isinstance(parent, ast.Call) and parent.func is node:
        return
    if _strict_read_is_unknown(node, aliases):
        out.unknowns.add("unresolved value in strict identity summary")


def _strict_read_is_unknown(node, aliases):
    value = identity_value(node, aliases, strict_calls=True)
    return value.unknown or not (
        value.roots
        or value.class_roots
        or value.inert_kind
        or value.items
        or value.content_unknown
    )


def strict_protocol_effects(node, aliases, parents, out):
    """Reject opaque content at consumers unless the operation is inert."""
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) and not isinstance(
        node.ctx, ast.Load
    ):
        return
    if (
        isinstance(node, ast.expr)
        and _has_unknown_content(identity_value(node, aliases, strict_calls=True))
        and not _passive_content_use(node, parents)
    ):
        out.unknowns.add("unresolved consumer of strict identity content")
    operands = _protocol_operands(node)
    if (
        operands
        and _known_scalar_add(node, aliases) is None
        and not all(
            identity_value(value, aliases, strict_calls=True).inert_kind
            for value in operands
        )
    ):
        out.unknowns.add("unresolved protocol operand in strict identity summary")


def _passive_content_use(node, parents):
    parent = parents.get(id(node))
    if isinstance(parent, ast.Call) and parent.func is node:
        return True
    if isinstance(parent, (ast.List, ast.Tuple)) and node in parent.elts:
        return True
    if isinstance(parent, ast.Dict) and node in parent.values:
        return all(isinstance(key, ast.Constant) for key in parent.keys)
    if isinstance(parent, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
        return getattr(parent, "value", None) is node
    if isinstance(parent, ast.Expr) and parent.value is node:
        return True
    compare = node if isinstance(node, ast.Compare) else parent
    return isinstance(compare, ast.Compare) and all(
        isinstance(op, (ast.Is, ast.IsNot)) for op in compare.ops
    )


def _protocol_operands(node):
    if isinstance(node, ast.AugAssign):
        return [node.target, node.value]
    if isinstance(node, ast.BinOp):
        return [node.left, node.right]
    if isinstance(node, ast.UnaryOp):
        return [node.operand]
    if isinstance(node, ast.Compare):
        if all(isinstance(op, (ast.Is, ast.IsNot)) for op in node.ops):
            return []
        return [node.left, *node.comparators]
    if isinstance(node, ast.BoolOp):
        return node.values
    if isinstance(node, (ast.If, ast.While, ast.IfExp, ast.Assert)):
        if isinstance(node.test, ast.Compare) and all(
            isinstance(op, (ast.Is, ast.IsNot)) for op in node.test.ops
        ):
            return []
        return [node.test]
    if isinstance(node, ast.FormattedValue):
        return [node.value]
    return []


def implicit_protocol_roots(node, aliases, *, strict_calls=False):
    """Collect tracked roots used by iteration, context management, comparisons, operators, awaits, and comprehension iteration."""
    if _known_scalar_add(node, aliases) is not None:
        return set()
    expressions = []
    if isinstance(node, (ast.For, ast.AsyncFor)):
        expressions.append(node.iter)
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        expressions.extend(item.context_expr for item in node.items)
    elif isinstance(
        node,
        (
            ast.Compare,
            ast.IfExp,
            ast.If,
            ast.While,
            ast.Assert,
            ast.BinOp,
            ast.UnaryOp,
            ast.BoolOp,
        ),
    ):
        expressions.extend(_protocol_operands(node))
    elif isinstance(node, ast.Await):
        expressions.append(node.value)
    elif isinstance(node, ast.comprehension):
        expressions.append(node.iter)
    return set().union(
        *(
            tracked_roots(identity_value(expr, aliases, strict_calls=strict_calls))
            for expr in expressions
        )
    )


def super_reference(node):
    """Recognize a loaded AST name spelled super, without inferring its runtime binding."""
    return (
        isinstance(node, ast.Name)
        and node.id == "super"
        and isinstance(node.ctx, ast.Load)
    )


def tracks_receiver(function, aliases):
    """Check whether the function's first positional receiver is present in the tracked alias map."""
    params = [*function.args.posonlyargs, *function.args.args]
    return bool(params and params[0].arg in aliases)


def record_implicit_effects(node, function, aliases, effects, *, strict_calls=False):
    """Mark unknown effects for implicit super dispatch, tracked special-method operations, or unresolved descriptor reads."""
    if tracks_receiver(function, aliases) and super_reference(node):
        effects.unknowns.add("super uses implicit or reflective receiver")
    if implicit_protocol_roots(node, aliases, strict_calls=strict_calls):
        effects.unknowns.add("implicit special-method dispatch on tracked root")
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Attribute):
        if identity_value(node.value, aliases, strict_calls=strict_calls).unknown:
            effects.unknowns.add("bare tracked attribute read may invoke a descriptor")


def identity_fields(fields, index):
    """Normalize field identities only for bounded mappings with valid owner/member keys and source-backed or literal roots."""
    if fields is None:
        return {}
    if not isinstance(fields, Mapping) or len(fields) > 64:
        return None
    result = {}
    for key, root in fields.items():
        value = _identity_field_value(key, root, index)
        if value is None:
            return None
        result[key] = value
    return result


def _identity_field_value(key, root, index):
    literal = (
        _source_literal(root, index) if isinstance(root, SourceFieldLiteral) else None
    )
    if not _identity_field_key_valid(key, root, literal):
        return None
    return literal if literal is not None else _Value(roots=frozenset({root}))


def _identity_field_key_valid(key, root, literal):
    return (
        isinstance(key, tuple)
        and len(key) == 2
        and all(isinstance(item, str) and item for item in key)
        and (literal is not None or isinstance(root, str) and root)
        and key[1].isidentifier()
        and not key[1].startswith("__")
    )


def _source_literal(root, index):
    if not index.validate(root.path) or id(root.value) not in index.parents[root.path]:
        return None
    value = identity_value(root.value, {})
    return value if value.inert_kind is not None else None


def literal_dict_update(call, aliases, *, strict_calls=False):
    """Recognize a one-argument dict update only when both receiver and input are inert dictionaries."""
    if not (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "update"
        and len(call.args) == 1
        and not call.keywords
    ):
        return False
    receiver, values = (
        identity_value(call.func.value, aliases, strict_calls=strict_calls),
        identity_value(call.args[0], aliases, strict_calls=strict_calls),
    )
    return receiver.inert_kind == values.inert_kind == "dict"


def mapped_call_values(call, aliases, involved, resolved, out, *, strict_calls=False):
    """Bind each call actual to exactly one resolved formal parameter; record uncertainty and return no mapping on ambiguity."""
    if _call_has_expansion(call):
        out.unknowns.add("expanded call arguments are not an exact binding")
        return None
    if not isinstance(resolved, ResolvedIdentityCall):
        out.unknowns.add("invalid exact call binding")
        return None
    actuals = [*call.args, *(keyword.value for keyword in call.keywords)]
    binding = _authoritative_call_mapping(call, resolved, out, actuals)
    if binding is None:
        return None
    authoritative, actuals = binding
    params = _resolved_parameter_names(resolved.function)
    provided = _exact_provided_mapping(
        resolved.arguments, resolved.function, actuals, authoritative, out
    )
    if provided is None or not maps_each_actual_once(actuals, provided):
        out.unknowns.add("exact call mapping must cover each actual once")
        return None
    return _mapped_call_formals(
        provided, params, actuals, aliases, involved, resolved, out, strict_calls
    )


def _authoritative_call_mapping(call, resolved, out, actuals):
    from .review_integrity import bind_source_call

    receiver = (
        call.func.value
        if isinstance(call.func, ast.Attribute)
        and any(
            expression is call.func.value for expression in resolved.arguments.values()
        )
        else None
    )
    try:
        authoritative = bind_source_call(
            call, resolved.function, receiver=receiver, apply_defaults=False
        )
    except (TypeError, ValueError):
        out.unknowns.add("call does not match the captured source signature")
        return None
    if receiver is not None:
        actuals.append(receiver)
    return authoritative, actuals


def _exact_provided_mapping(arguments, function, actuals, authoritative, out):
    defaults = _declared_call_defaults(function)
    provided = {}
    for formal, expression in arguments.items():
        if any(expression is actual for actual in actuals):
            provided[formal] = expression
        elif (
            not isinstance(expression, ast.expr)
            or formal not in defaults
            or defaults[formal] is not expression
        ):
            out.unknowns.add("call mapping includes an unbound non-default expression")
            return None
    if set(provided) != set(authoritative) or any(
        provided[name] is not expression for name, expression in authoritative.items()
    ):
        return None
    return provided


def _mapped_call_formals(
    provided, params, actuals, aliases, involved, resolved, out, strict_calls
):
    mapped = {}
    for formal, expr in provided.items():
        value = _mapped_formal_value(
            formal, expr, params, actuals, aliases, out, strict_calls
        )
        if value is None:
            return None
        mapped[formal] = value
    if set().union(*(tracked_roots(value) for value in mapped.values())) != involved:
        out.unknowns.add("exact call mapping omits a tracked root")
        return None
    return _with_inert_defaults(
        resolved.function, mapped, out, strict_calls=strict_calls
    )


def _call_has_expansion(call):
    return any(isinstance(arg, ast.Starred) for arg in call.args) or any(
        keyword.arg is None for keyword in call.keywords
    )


def _resolved_parameter_names(function):
    return {
        arg.arg
        for arg in [
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        ]
    }


def _call_actual_expressions(call):
    actuals = [*call.args, *(kw.value for kw in call.keywords)]
    if isinstance(call.func, ast.Attribute):
        actuals.append(call.func.value)
    return actuals


def _mapped_formal_value(formal, expr, params, actuals, aliases, out, strict_calls):
    if formal not in params or not any(expr is actual for actual in actuals):
        out.unknowns.add("call mapping is not an exact parameter binding")
        return None
    value = identity_value(expr, aliases, strict_calls=strict_calls)
    roots = tracked_roots(value)
    if not isinstance(expr, ast.expr) or len(roots) > 1 or (value.items and roots):
        out.unknowns.add("ambiguous exact call root mapping")
        return None
    if value.unknown or (strict_calls and value.content_unknown):
        out.unknowns.add("exact formal is bound to an unknown actual value")
    return value


def _declared_call_defaults(function):
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    defaults = dict(
        zip((arg.arg for arg in positional[-len(args.defaults) :]), args.defaults)
    )
    defaults.update(
        (arg.arg, value) for arg, value in zip(args.kwonlyargs, args.kw_defaults)
    )
    return defaults


def _with_inert_defaults(function, mapped, out, *, strict_calls=False):
    defaults = _declared_call_defaults(function)
    for parameter in [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]:
        if parameter.arg in mapped:
            continue
        default = defaults.get(parameter.arg)
        if not _immutable_default(default):
            out.unknowns.add(
                "missing formal or omitted default is not an immutable literal"
            )
            return None
        mapped[parameter.arg] = identity_value(default, {}, strict_calls=strict_calls)
    return mapped


def _immutable_default(node, depth=0):
    if depth >= 8:
        return False
    if isinstance(node, ast.Constant):
        return type(node.value) in (
            type(None),
            bool,
            int,
            float,
            complex,
            str,
            bytes,
            type(Ellipsis),
        )
    if (
        isinstance(node, ast.BinOp)
        and isinstance(node.op, ast.Mult)
        and isinstance(node.left, ast.Constant)
        and type(node.left.value) is bytes
        and isinstance(node.right, ast.Constant)
        and type(node.right.value) is int
        and 0 <= node.right.value <= 4096
        and len(node.left.value) * node.right.value <= 65536
    ):
        return True
    return (
        isinstance(node, ast.Tuple)
        and len(node.elts) <= 64
        and all(_immutable_default(item, depth + 1) for item in node.elts)
    )


def summarize_identity_call(
    call, path, index, roots, *, resolve_call, field_roots=None, role_view=False
):
    """Summarize one captured call under caller-proved current heap/dispatch facts.

    Allocation, ownership, descriptors, prior mutations, and binding stability
    are separate caller obligations. This is not fixture admission or execution.
    """
    out = _Effects(record_role_events=role_view)
    if not _captured_identity_call_valid(call, path, index):
        out.unknowns.add("call is not a validated captured expression")
        return out.freeze()
    analyzer = _Analyzer(index, resolve_call, 4, 512, field_roots, True, role_view)
    if analyzer.fields is None:
        out.unknowns.add("invalid initial field identity graph")
        return out.freeze()
    aliases = {
        name: root if isinstance(root, _Value) else _Value(roots=frozenset({root}))
        for name, root in roots.items()
    }
    aliases.update(analyzer.fields)
    expression_nodes = _captured_argument_calls(call, path, index, out)
    if expression_nodes is None:
        return out.freeze()
    if len(expression_nodes) > 512:
        out.unknowns.add("argument effect state budget exceeded")
        return out.freeze()
    for nested in reversed(expression_nodes):
        if nested is not call:
            analyzer._call(nested, path, aliases, 0, frozenset(), out)
    analyzer._call(call, path, aliases, 0, frozenset(), out, capture_returns=True)
    _complete_identity_call_result(out, call, path, aliases)
    return out.freeze()


def _captured_identity_call_valid(call, path, index):
    return (
        isinstance(call, ast.Call)
        and index.validate(path)
        and id(call) in index.parents[path]
    )


def _captured_argument_calls(call, path, index, out):
    selected = []
    for argument in _call_actual_expressions(call):
        if id(argument) not in index.parents[path]:
            out.unknowns.add("call actual is outside the validated source tree")
            continue
        selected.extend(
            node for node in ast.walk(argument) if isinstance(node, ast.Call)
        )
    return selected


def _complete_identity_call_result(out, call, path, aliases):
    if out.return_values:
        return
    candidate = _unknown_expression(
        call, aliases, strict_calls=True, material_values=True
    )
    out.return_values.append(
        IdentityReturnProjection(
            path,
            _event_span(path, call),
            _value_with_trace(candidate, call, "UNRESOLVED_CALL_RESULT"),
        )
    )
    out.return_status = "UNKNOWN"


def captured_source_call_result(call, path, index, roots):
    """Return one exact captured helper result while retaining its may-effects.

    Only a complete single-result projection is returned. Opaque argument
    effects, provider writes, unknown escapes and unresolved callers remain
    visible and decline the value projection.
    """
    if not isinstance(call, ast.Call) or not index.validate(path):
        return None

    def resolve(candidate, candidate_path):
        parents = index.parents.get(candidate_path)
        if parents is None:
            return None
        lexical_scope = _enclosing_function(candidate, parents)
        return resolve_source_identity_call(
            candidate, candidate_path, index, lexical_scope=lexical_scope
        )

    summary = summarize_identity_call(
        call, path, index, roots, resolve_call=resolve, role_view=True
    )
    if not _source_call_summary_complete(summary) or not _source_call_effects_clear(
        summary, roots
    ):
        return None
    projection = summary.return_values[0].value
    if projection.unknown or projection.content_unknown:
        return None
    return {"value": projection, "effects": summary, "source": summary.return_values[0]}


def _source_call_summary_complete(summary):
    return not (summary.unknowns or summary.class_writes or summary.field_writes) and (
        summary.return_status == "COMPLETE" and len(summary.return_values) == 1
    )


def _source_call_effects_clear(summary, roots):
    allowed = {"return_escape", "local_alias", "local_container"}
    root_names = set().union(*(tracked_roots(value) for value in roots.values()))
    return not any(
        event.uncertain
        or (root_names.intersection(event.roots) and event.kind not in allowed)
        for event in summary.role_events
    )


def captured_function_valid(function, path, index):
    """Confirm a function node belongs to a validated captured source snapshot."""
    return bool(
        isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        and index.validate(path)
        and any(node is function for node in ast.walk(index.snapshots[path]))
    )


def own_function_nodes(function, path, index):
    """Walk lexical bodies and eager nested headers without trusting parent metadata."""
    scopes = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
    pending, result = deque([function]), []
    while pending:
        node = pending.popleft()
        result.append(node)
        if node is function or not isinstance(node, scopes):
            pending.extend(ast.iter_child_nodes(node))
            continue
        # A nested body has its own scope. Defaults, decorators, annotations,
        # bases and keywords are evaluated while defining it in the outer scope.
        for field, value in ast.iter_fields(node):
            if field == "body":
                continue
            if isinstance(value, ast.AST):
                pending.append(value)
            elif isinstance(value, list):
                pending.extend(child for child in value if isinstance(child, ast.AST))
    return result


def exported_names(nodes):
    """Names stored outside the owning function's already-separated scope."""
    return {
        name
        for node in nodes
        if isinstance(node, (ast.Global, ast.Nonlocal))
        for name in node.names
    }


def _definition_effects_unknown(node, *, allowed_decorators=()):
    if isinstance(node, ast.ClassDef):
        return True
    args = node.args
    params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    params.extend(arg for arg in (args.vararg, args.kwarg) if arg)
    return bool(
        any(
            item not in allowed_decorators
            for item in getattr(node, "decorator_list", [])
        )
        or any(not _immutable_default(value) for value in args.defaults)
        or any(
            value is not None and not _immutable_default(value)
            for value in args.kw_defaults
        )
        or getattr(node, "returns", None)
        or getattr(node, "type_params", ())
        or any(arg.annotation for arg in params)
    )


def exact_receiver_class(path, receiver, index, imports, classes, audit):
    """Resolve a receiver Name from one direct local `name = Class(...)` binding."""
    if (
        not isinstance(receiver, ast.Name)
        or not index.validate(path)
        or path not in index.snapshots
    ):
        return None
    return _exact_receiver_class_for_function(
        path, receiver, index, imports, classes, audit, index.parents[path]
    )


def _exact_receiver_class_for_function(
    path, receiver, index, imports, classes, audit, parents
):
    function = _enclosing_function(receiver, parents)
    constructor = _local_constructor(receiver, function, parents) if function else None
    if constructor is None or _root_name(constructor.func) is None:
        return None
    class_ref = resolve_class(path, constructor.func, imports, classes)
    if class_ref is None or not _class_binding_is_exact(
        class_ref, constructor.func, path, index, imports, classes, function, parents
    ):
        return None
    chain = _class_chain(index, class_ref, imports, classes, audit)
    if not chain or any(_custom_new(owner) for _, _, owner in chain):
        return None
    return class_ref


def _local_constructor(receiver, function, parents):
    if _has_nested_scope(receiver, function, parents):
        return None
    if receiver.id in _argument_names(function):
        return None
    bindings = binding_occurrences(function.body, receiver.id)
    if len(bindings) != 1 or not isinstance(bindings[0], ast.Name):
        return None
    target = bindings[0]
    statement = parents.get(id(target))
    if (
        not isinstance(statement, ast.Assign)
        or parents.get(id(statement)) is not function
    ):
        return None
    if len(statement.targets) != 1 or statement.targets[0] is not target:
        return None
    constructor = statement.value
    if not isinstance(constructor, ast.Call):
        return None
    class_name = _root_name(constructor.func)
    if class_name is None or class_name in _argument_names(function):
        return None
    if binding_occurrences(function.body, class_name):
        return None
    return constructor


def _class_binding_is_exact(
    class_ref, expression, path, index, imports, classes, function, parents
):
    return bool(
        not _outer_scope_shadows(function, expression, parents)
        and _module_binding_is_exact(
            class_ref, expression, path, index, imports, classes
        )
    )


def _module_binding_is_exact(class_ref, expression, path, index, imports, classes):
    root_name = _root_name(expression)
    if root_name is None:
        return False
    tree = index.snapshots[path]
    rows = binding_occurrences(tree.body, root_name)
    if len(rows) != 1:
        return False
    binding = rows[0]
    resolved = imports.get(path, {}).get(root_name)
    if resolved:
        expected = (
            (resolved[0], expression.attr)
            if isinstance(expression, ast.Attribute)
            else resolved
        )
        return (
            isinstance(binding, (ast.Import, ast.ImportFrom)) and expected == class_ref
        )
    return class_ref == (path, root_name) and classes.get(class_ref) is binding


def _class_chain(index, class_ref, imports, classes, audit):
    from .credential_role_constructor_provider import class_chain

    return class_chain(index, class_ref[0], class_ref[1], imports, classes, audit)


def _custom_new(owner):
    return bool(binding_occurrences(owner.body, "__new__"))


def _enclosing_function(node, parents):
    current = node
    while current is not None:
        current = parents.get(id(current))
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return current
        if isinstance(current, ast.ClassDef):
            return None
    return None


def _has_nested_scope(node, function, parents):
    current = node
    while current is not function:
        current = parents.get(id(current))
        if current is None or isinstance(
            current,
            (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
        ):
            return True
    return False


def _argument_names(function):
    args = function.args
    result = {arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    if args.vararg:
        result.add(args.vararg.arg)
    if args.kwarg:
        result.add(args.kwarg.arg)
    return result


def _outer_scope_shadows(function, expression, parents):
    root_name = _root_name(expression)
    current = parents.get(id(function))
    while current is not None:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if root_name in _argument_names(current):
                return True
            if binding_occurrences(current.body, root_name):
                return True
        current = parents.get(id(current))
    return False


def _root_name(expression):
    if isinstance(expression, ast.Name):
        return expression.id
    if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
        return expression.value.id
    return None


_HOOKS = (
    "__new__",
    "__getattr__",
    "__getattribute__",
    "__setattr__",
    "__delattr__",
    "__bool__",
    "__len__",
    "__class__",
)


class _AppReceiverHooksCacheToken:
    """Expose live constants and actual helper owners through a named token."""

    __name__ = "_APP_RECEIVER_HOOKS_CACHE_TOKEN"

    @property
    def __code__(self):
        dependencies = tuple(
            (
                helper,
                getattr(helper, "__code__", helper),
                getattr(helper, "__defaults__", None),
                getattr(helper, "__kwdefaults__", None),
            )
            for helper in module_fixture_helper_epoch()
            if helper is not self
        )
        current = (
            id(_HOOKS),
            id(module_fixture_helper_epoch),
            id(module_fixture_helper_epoch.__code__),
            *(tuple(id(value) for value in dependency) for dependency in dependencies),
        )
        if not hasattr(self, "_epochs"):
            self._epochs = {}
        if current not in self._epochs:
            # Retain identities and their referents for this process lifetime;
            # recycled Python object IDs must never resurrect a stale cache key.
            self._epochs[current] = (
                object(),
                dependencies,
                _HOOKS,
                module_fixture_helper_epoch,
                module_fixture_helper_epoch.__code__,
            )
        return self._epochs[current][0]

    def __call__(self):
        return self.__code__


_APP_RECEIVER_HOOKS_CACHE_TOKEN = _AppReceiverHooksCacheToken()


def _receiver_helper_epoch():
    return (
        *(
            globals()[name]
            for name in (
                "_HOOKS",
                "_local_receiver_stable",
                "_safe_use",
                "_method_stable",
                "_field_writes_safe",
                "_function",
                "_identity_call_value",
                "_capture_nested_scope",
                "_strict_read_is_unknown",
                "_identity_field_value",
                "_identity_field_key_valid",
                "_call_has_expansion",
                "_resolved_parameter_names",
                "_call_actual_expressions",
                "_mapped_formal_value",
                "_exact_receiver_class_for_function",
                "_event_span",
                "_role_expression_roots",
                "_add_role_event",
                "_join_field_values",
                "_field_projection_value",
                "_ordinary_field_dispatch",
                "_attribute_value",
                "_record_attribute_write",
                "record_write",
                "record_escape",
                "record_opaque_call",
                "nested_capture_roots",
                "_capture_nested_scope",
                "summarize_identity_call",
                "summarize_identity_effect",
                "effective_method",
                "binding_occurrences",
            )
        ),
        _Analyzer.__init__,
        _Analyzer.run,
        _Analyzer._aliases,
        _Analyzer._visit,
        _Analyzer._assignment,
        _Analyzer._attribute_role,
        _Analyzer._call,
        _Effects.merge,
        _Effects.freeze,
        _class_binding.effective_method,
        _identity_effects.summarize_identity_effect,
        _scope_bindings.binding_occurrences,
    )


def local_receiver_stable(path, receiver, getter, chain, index):
    """Reuse candidate-independent identity checks only in a validated batch."""

    def derive():
        return _local_receiver_stable(path, receiver, getter, chain, index)

    memo = getattr(index, "class_chain_memo", None)
    if memo is None:
        return derive()
    key = (
        "local-receiver-lifetime",
        path,
        id(receiver),
        getter,
        tuple((source, name, id(owner)) for source, name, owner in chain),
    )
    return memo.source_model(key, derive, helper_epoch=_receiver_helper_epoch)


def _local_receiver_stable(path, receiver, getter, chain, index):
    """Unknown calls/escapes or effectful initialization cannot prove exclusion."""
    if not isinstance(receiver, ast.Name) or not index.validate(path):
        return False
    if any(
        binding_occurrences(owner.body, hook)
        for _, _, owner in chain
        for hook in _HOOKS
    ):
        return False
    if not _method_stable(chain, "__init__", index, absent=True):
        return False
    parents = index.parents[path]
    function = _function(receiver, parents)
    if function is None:
        return False
    for node in ast.walk(function):
        if (
            isinstance(node, ast.Name)
            and node.id == receiver.id
            and isinstance(node.ctx, ast.Load)
        ):
            if not _safe_use(node, function, parents, getter, chain, index):
                return False
    return True


def _safe_use(node, function, parents, getter, chain, index):
    if _function(node, parents) is not function:
        return False
    parent = parents.get(id(node))
    if not isinstance(parent, ast.Attribute) or parent.value is not node:
        return False
    call = parents.get(id(parent))
    return (
        isinstance(call, ast.Call)
        and call.func is parent
        and (parent.attr == getter or _method_stable(chain, parent.attr, index))
    )


def _method_stable(chain, name, index, *, absent=False):
    bound = any(binding_occurrences(owner.body, name) for _, _, owner in chain)
    if not bound:
        return absent
    row = effective_method(chain, name)
    if row is None:
        return False
    path, method = row
    args = [*method.args.posonlyargs, *method.args.args]
    if not args or args[0].arg != "self" or isinstance(method, ast.AsyncFunctionDef):
        return False
    # No exact callee binder is enabled here: even a no-argument call can
    # inspect its caller's frame or mutate a class through global state.
    if any(isinstance(node, ast.Call) for node in ast.walk(method)):
        return False
    summary = summarize_identity_effect(method, path, index, {"self": "receiver"})
    return summary.preserves_class_identity and _field_writes_safe(summary, chain)


def _field_writes_safe(summary, chain):
    for field in summary.field_writes:
        member = field.removeprefix("receiver.")
        for _, _, owner in chain:
            bindings = binding_occurrences(owner.body, member)
            if not bindings:
                continue
            if len(bindings) != 1 or not any(
                isinstance(statement, (ast.Assign, ast.AnnAssign))
                and isinstance(statement.value, ast.Constant)
                and any(
                    target is bindings[0]
                    for target in (
                        statement.targets
                        if isinstance(statement, ast.Assign)
                        else [statement.target]
                    )
                )
                for statement in owner.body
            ):
                return False
            break
    return True


def _function(node, parents):
    while node is not None:
        node = parents.get(id(node))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return node
        if isinstance(node, ast.ClassDef):
            return None
    return None


def summarize_identity_effect(
    function,
    path,
    index: SourceSnapshotIndex,
    roots: Mapping[str, str | SourceFieldLiteral | _Value],
    *,
    resolve_call: CallResolver | None = None,
    field_roots: Mapping[tuple[str, str], str | SourceFieldLiteral] | None = None,
    strict_calls=False,
    max_depth=4,
    state_budget=512,
    role_view=False,
    ordinary_fields=(),
    source_inert_nodes=(),
):
    """Summarize captured ASTs without executing target code.

    Callers prove exact bindings, branches, descriptors, allocation and current
    field ownership; initial field projections are not admission evidence.
    Unknown protocols, heap escapes and overwritten projections fail closed.
    Strict mode also rejects unresolved calls without explicit root arguments.
    Source-backed parameter literals retain their value role rather than becoming
    identity roots. The caller still proves the exact actual/default binding.
    """
    parameters = {
        name: _source_literal(value, index)
        if isinstance(value, SourceFieldLiteral)
        else value
        for name, value in roots.items()
    }
    if any(value is None for value in parameters.values()):
        return IdentityEffectSummary(
            "UNKNOWN", unknowns=("invalid captured parameter literal",)
        )
    return (
        _Analyzer(
            index,
            resolve_call,
            max_depth,
            state_budget,
            field_roots,
            strict_calls,
            role_view,
            ordinary_fields,
            source_inert_nodes,
        )
        .run(function, path, parameters, 0, frozenset())
        .freeze()
    )


class _Analyzer:
    def __init__(
        self,
        index,
        resolver,
        depth_limit,
        budget,
        field_roots,
        strict_calls,
        role_view,
        ordinary_fields=(),
        source_inert_nodes=(),
    ):
        self.index, self.resolver = index, resolver
        self.depth_limit, self.budget, self.states = depth_limit, budget, 0
        self.fields = identity_fields(field_roots, index)
        self.strict_calls = strict_calls
        self.role_view = role_view
        self.ordinary_fields = frozenset(ordinary_fields)
        self.source_inert_nodes = frozenset(source_inert_nodes)

    def run(
        self,
        function,
        path,
        roots,
        depth,
        active,
    ):
        """Analyze a captured function within depth and state budgets; return explicit unknown effects when validation is incomplete."""
        out = _Effects(record_role_events=self.role_view)
        if self.fields is None:
            out.unknowns.add("invalid initial field identity graph")
            return out
        if depth > self.depth_limit or (path, id(function)) in active:
            out.unknowns.add("call depth or cycle limit")
            return out
        if not captured_function_valid(function, path, self.index):
            out.unknowns.add("callee is not a validated captured function")
            return out
        nodes = [
            node
            for node in own_function_nodes(function, path, self.index)
            if (path, id(node)) not in self.source_inert_nodes
        ]
        self.states += len(nodes)
        if self.states > self.budget:
            out.unknowns.add("AST state budget exceeded")
            return out
        aliases = self._aliases(
            function,
            path,
            roots,
            nodes,
            out,
        )
        active = active | {(path, id(function))}
        self._visit(nodes, function, path, aliases, depth, active, out)
        self._project_returns(function, path, roots, aliases, nodes, out)
        out.escapes.update(
            nested_capture_roots(
                function,
                path,
                aliases,
                self.index,
                strict_calls=self.strict_calls,
                effects=out,
            )
        )
        return out

    def _project_returns(self, function, path, roots, aliases, nodes, out):
        returns = [node for node in nodes if isinstance(node, ast.Return)]
        if not returns:
            out.return_status = (
                "UNKNOWN"
                if any(isinstance(node, (ast.Yield, ast.YieldFrom)) for node in nodes)
                else "NO_RETURN"
            )
            return
        from .finite_capture import evaluate_helper_flow

        initial = {
            name: value
            if isinstance(value, _Value)
            else _Value(roots=frozenset({value}))
            for name, value in roots.items()
        }
        initial.update(self.fields)
        result = evaluate_helper_flow(
            function,
            initial,
            lambda expression, environment: (
                True,
                identity_value(
                    expression,
                    environment,
                    strict_calls=self.strict_calls,
                    material_values=True,
                ),
            ),
            max_states=self.budget,
        )
        if result["status"] == "COMPLETE" and len(result["return_values"]) == 1:
            value = result["return_values"][0]
            if isinstance(value, _Value):
                out.return_values.append(
                    IdentityReturnProjection(
                        path,
                        _event_span(path, returns[0]),
                        _value_with_trace(value, returns[0], "HELPER_RETURN"),
                    )
                )
                out.return_status = "UNKNOWN" if value.unknown else "COMPLETE"
                return
        # Unsupported control flow retains possible origins as UNKNOWN. It may
        # inform a may-flow witness, but cannot prove one selected result.
        for node in returns:
            value = identity_value(
                node.value,
                aliases,
                strict_calls=self.strict_calls,
                material_values=True,
            )
            possible = _Value(
                roots=value.roots,
                items=value.items,
                class_roots=value.class_roots,
                unknown=True,
                content_unknown=value.content_unknown or value.unknown,
                inert_kind=value.inert_kind,
                scalar_kind=value.scalar_kind,
                trace=(*value.trace, _value_trace(node, "UNKNOWN_RETURN_PATH")),
            )
            out.return_values.append(
                IdentityReturnProjection(path, _event_span(path, node), possible)
            )
        out.return_status = "UNKNOWN"

    def _visit(self, nodes, function, path, aliases, depth, active, out):
        exported = exported_names(nodes)
        parents = self.index.parents[path]
        for node in nodes:
            if (
                self.role_view
                and isinstance(node, ast.Attribute)
                and isinstance(node.ctx, ast.Load)
            ):
                self._attribute_role(node, path, function, aliases, parents, out)
            if self.strict_calls:
                strict_read_effects(node, aliases, parents, out)
                strict_protocol_effects(node, aliases, parents, out)
            record_implicit_effects(
                node, function, aliases, out, strict_calls=self.strict_calls
            )
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                self._assignment(node, aliases, function, path, out, exported)
            elif isinstance(node, (ast.AugAssign, ast.Delete)):
                for target in (
                    node.targets if isinstance(node, ast.Delete) else [node.target]
                ):
                    record_write(
                        target,
                        _Value(),
                        aliases,
                        out,
                        strict_calls=self.strict_calls,
                        path=path,
                        source_node=node,
                        function=function,
                        parents=parents,
                        initial_fields=self.fields,
                    )
            elif isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)):
                record_escape(
                    getattr(node, "value", None),
                    aliases,
                    out,
                    "return/yield",
                    strict_calls=self.strict_calls,
                    path=path,
                    event_kind="return_escape",
                )
            elif isinstance(node, ast.Call):
                self._call(node, path, aliases, depth, active, out)

    def _aliases(self, function, path, roots, nodes, out):
        args = function.args
        params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
        params += [item for item in (args.vararg, args.kwarg) if item]
        env = {
            name: root if isinstance(root, _Value) else _Value(frozenset({root}))
            for name, root in roots.items()
        }
        env.update(self.fields)
        assigns = [
            n
            for n in nodes
            if isinstance(n, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
        ]
        self._record_root_parameter_rebindings(function, params, roots, env, out)
        self._resolve_alias_assignments(function, path, assigns, env, out)
        return env

    @staticmethod
    def _record_root_parameter_rebindings(function, params, roots, env, out):
        for param in params:
            if (
                param.arg in roots
                and tracked_roots(env[param.arg])
                and any(
                    isinstance(node, ast.Name)
                    and node.id == param.arg
                    and isinstance(node.ctx, ast.Store)
                    for node in ast.walk(function)
                )
            ):
                out.unknowns.add(f"root parameter rebound: {param.arg}")

    def _resolve_alias_assignments(self, function, path, assigns, env, out):
        for _ in range(min(len(assigns) + 1, 32)):
            changed = False
            field_writes = {}
            for node in assigns:
                changed |= self._alias_assignment_update(
                    node, function, path, env, field_writes
                )
            changed |= self._apply_alias_field_writes(field_writes, env)
            if not changed:
                break
        else:
            out.unknowns.add("alias fixed-point limit")

    def _alias_assignment_update(self, node, function, path, env, field_writes):
        target = assignment_target(node)
        value = identity_value(
            getattr(node, "value", None), env, strict_calls=self.strict_calls
        )
        if isinstance(target, ast.Name):
            if binding_occurrences(function.body, target.id) != [target]:
                return False
            if (contains_tracked(value) or value.inert_kind is not None) and env.get(
                target.id
            ) != value:
                env[target.id] = value
                return True
            return False
        if (
            not self.role_view
            or not isinstance(target, ast.Attribute)
            or target.attr == "__class__"
        ):
            return False
        base = identity_value(target.value, env, strict_calls=self.strict_calls)
        roots = tracked_roots(base)
        if not roots:
            return False
        unconditional = _field_transfer_unconditional(
            node, function, self.index.parents.get(path)
        )
        for root in roots:
            field_writes.setdefault((root, target.attr), []).append(
                (value, unconditional, len(roots) != 1 or base.unknown)
            )
        return False

    def _apply_alias_field_writes(self, field_writes, env):
        changed = False
        for key, writes in field_writes.items():
            candidates = [value for value, _, _ in writes]
            ambiguous = len(writes) != 1 or any(not row[1] or row[2] for row in writes)
            if len(writes) == 1 and writes[0][1] and not writes[0][2]:
                projected = candidates[0]
            else:
                if any(not row[1] for row in writes):
                    candidates.append(self.fields.get(key, _Value(unknown=True)))
                projected = _join_field_values(candidates, uncertain=ambiguous)
            if self.role_view:
                projected = _field_projection_value(key[0], projected)
            if env.get(key) != projected:
                env[key] = projected
                changed = True
        return changed

    def _attribute_role(self, node, path, function, aliases, parents, out):
        receiver = _role_expression_roots(
            node.value, aliases, strict_calls=self.strict_calls
        )
        if not receiver:
            return
        projected = [aliases.get((root, node.attr)) for root in receiver]
        known = [value for value in projected if value is not None]
        if known:
            roots = set().union(*(tracked_roots(value) for value in known))
            _add_role_event(
                out,
                "field_read",
                roots,
                path,
                node,
                node.attr,
                receiver_roots=receiver,
                uncertain=len(receiver) != 1
                or any(value.unknown or _has_unknown_content(value) for value in known),
            )
            if node.attr not in self.ordinary_fields and not _ordinary_field_dispatch(
                function, node.attr, parents
            ):
                out.unknowns.add("attribute read dispatch is not source-closed")
                _add_role_event(
                    out,
                    "attribute_dispatch_unknown",
                    roots,
                    path,
                    node,
                    node.attr,
                    receiver_roots=receiver,
                    uncertain=True,
                )
            return
        parent = parents.get(id(node))
        bound = (isinstance(parent, ast.Call) and parent.func is node) or (
            isinstance(parent, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
            and getattr(parent, "value", None) is node
        )
        _add_role_event(
            out,
            "bound_method_or_unknown_property" if bound else "unknown_property_read",
            receiver,
            path,
            node,
            node.attr,
            receiver_roots=receiver,
            uncertain=True,
        )

    def _assignment(self, node, aliases, function, path, out, exported):
        if isinstance(node, ast.Assign) and len(node.targets) != 1:
            value = identity_value(node.value, aliases, strict_calls=self.strict_calls)
            if contains_tracked(value):
                out.unknowns.add("multi-target tracked assignment")
            return
        value, target = (
            identity_value(
                getattr(node, "value", None),
                aliases,
                strict_calls=self.strict_calls,
            ),
            assignment_target(node),
        )
        if isinstance(target, (ast.Tuple, ast.List)):
            if contains_tracked(value):
                out.unknowns.add("destructuring tracked object")
        elif isinstance(target, ast.Name):
            self._assignment_name(
                node, target, value, aliases, function, path, out, exported
            )
        else:
            record_write(
                target,
                value,
                aliases,
                out,
                strict_calls=self.strict_calls,
                source_node=getattr(node, "value", None),
                path=path,
                function=function,
                parents=self.index.parents[path],
                initial_fields=self.fields,
                ordinary_fields=self.ordinary_fields,
            )

    def _assignment_name(
        self, node, target, value, aliases, function, path, out, exported
    ):
        if target.id in exported:
            record_escape(
                node.value,
                aliases,
                out,
                "global/nonlocal assignment",
                strict_calls=self.strict_calls,
                path=path,
                event_kind="global_escape",
                relevant=target.id,
            )
        ambiguous = contains_tracked(value) and binding_occurrences(
            function.body, target.id
        ) != [target]
        if ambiguous:
            out.unknowns.add(f"ambiguous alias binding: {target.id}")
            return
        if value.items:
            if not self.role_view:
                out.escapes.update(tracked_roots(value))
            _add_role_event(
                out,
                "local_container",
                _role_expression_roots(
                    node.value, aliases, strict_calls=self.strict_calls
                ),
                path,
                node,
                target.id,
                uncertain=_has_unknown_content(value),
            )
        if value.unknown:
            out.unknowns.add("alias receives unresolved tracked expression")
        elif contains_tracked(value):
            _add_role_event(
                out, "local_alias", tracked_roots(value), path, node, target.id
            )

    def _call(self, call, path, aliases, depth, active, out, *, capture_returns=False):
        if literal_dict_update(call, aliases, strict_calls=self.strict_calls):
            return
        if call_has_unknown_value(call, aliases, strict_calls=self.strict_calls):
            out.unknowns.add("call receives an unresolved tracked value")
            _add_role_event(
                out,
                "call_with_unresolved_value",
                _role_expression_roots(call, aliases, strict_calls=self.strict_calls),
                path,
                call,
                _call_role_actuals(call, aliases, strict_calls=self.strict_calls),
                receiver_roots=(
                    _role_expression_roots(
                        call.func.value, aliases, strict_calls=self.strict_calls
                    )
                    if isinstance(call.func, ast.Attribute)
                    else ()
                ),
                uncertain=True,
            )
            if not capture_returns:
                return
        involved = call_tracked_roots(call, aliases, strict_calls=self.strict_calls)
        if not involved and not self.strict_calls:
            if self.role_view:
                out.unknowns.add("unresolved ambient call may reach tracked identity")
            _add_role_event(
                out,
                "unresolved_ambient_call",
                (),
                path,
                call,
                _call_role_actuals(call, aliases, strict_calls=self.strict_calls),
                uncertain=True,
            )
            return
        resolved = self.resolver(call, path) if self.resolver else None
        if resolved is None:
            if self.role_view:
                out.unknowns.add(
                    "unresolved call may reach tracked identity indirectly"
                )
            record_opaque_call(
                call,
                aliases,
                involved,
                out,
                strict_calls=self.strict_calls,
                path=path,
            )
            return
        mapped = mapped_call_values(
            call,
            aliases,
            involved,
            resolved,
            out,
            strict_calls=self.strict_calls,
        )
        if mapped is None:
            return
        mapped.update(
            (key, value)
            for key, value in aliases.items()
            if isinstance(key, tuple) and key[:1] == ("expression",)
        )

        nested = self.run(resolved.function, resolved.path, mapped, depth + 1, active)
        if (
            capture_returns
            and nested.return_values
            and not (
                resolved.negative_binding_closed
                or resolved.negative_binding_check is not None
                and any(
                    not isinstance(projection.value, _Value)
                    or projection.value.unknown is not True
                    or projection.value.items != ()
                    for projection in nested.return_values
                )
                and resolved.negative_binding_check() is True
            )
        ):
            from dataclasses import replace

            nested.return_values = [
                replace(
                    projection, value=_unproved_return_binding(projection.value, call)
                )
                for projection in nested.return_values
            ]
        out.merge(nested, include_returns=capture_returns)


def _fixture_symbol(index, path, expression, function=None):
    from . import mock_fixture_provenance as fixture

    return fixture._app_source_symbol(index, path, expression, function)


def _fixture_constant(index, path, expression, function=None):
    selected = _fixture_symbol(index, path, expression, function)
    if selected is None:
        return None
    owner_path, statement = selected
    if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
        return None
    if not isinstance(statement.value, ast.Constant):
        return None
    return owner_path, statement


def _fixture_scope(index, path, node, kind):
    current = node
    parents = index["source"].parents[path]
    while current is not None and not isinstance(current, kind):
        current = parents.get(id(current))
    return current


def _fixture_class_maps(index):
    classes, imports = {}, {}
    for path, tree in index["modules"].items():
        if not index["source"].validate(path):
            return None
        imports[path] = {}
        for owner in tree.body:
            if not isinstance(owner, ast.ClassDef):
                continue
            classes[path, owner.name] = owner
            for base in owner.bases:
                if not isinstance(base, ast.Name):
                    continue
                selected = _fixture_symbol(index, path, base)
                if selected is not None and isinstance(selected[1], ast.ClassDef):
                    if selected[0] != path:
                        imports[path][base.id] = selected[0], selected[1].name
    return classes, imports


def _fixture_chain(index, path, owner, maps, terminal, contract):
    from . import review_audits as audit

    return _class_binding.resolve_class_chain_with_terminals(
        index["source"],
        path,
        owner.name,
        maps[1],
        maps[0],
        audit,
        {terminal: contract},
    )


def _fixture_literal_setting(tree, name):
    from . import mock_fixture_provenance as fixture

    rows = fixture._django_assignment(tree, name)
    if len(rows) != 1:
        return None
    try:
        return ast.literal_eval(rows[0][1])
    except (ValueError, TypeError, RecursionError):
        return None


def _fixture_pytest_options(index):
    from .review_audits import tomllib

    raw = index["configuration_bytes"].get("pyproject.toml")
    if not isinstance(raw, bytes):
        return None
    try:
        options = tomllib.loads(raw.decode("utf8"))["tool"]["pytest"]["ini_options"]
    except (UnicodeError, ValueError, KeyError, TypeError):
        return None
    return options if isinstance(options, dict) else None


def _fixture_settings(index):
    from . import mock_fixture_provenance as fixture

    options = _fixture_pytest_options(index)
    if options is None or options.get("django_find_project") is not False:
        return None
    selected = options.get("DJANGO_SETTINGS_MODULE")
    if (
        not isinstance(selected, str)
        or not selected
        or not all(part.isidentifier() for part in selected.split("."))
    ):
        return None
    path, tree = fixture._django_mod(index, selected)
    if tree is None or binding_occurrences(tree.body, "AUTHENTICATION_BACKENDS"):
        return None
    databases = _fixture_literal_setting(tree, "DATABASES")
    if not _fixture_database_is_local(databases):
        return None
    return path, tree


def _fixture_database_is_local(databases):
    if not isinstance(databases, dict) or set(databases) != {"default"}:
        return False
    default = databases["default"]
    if (
        not isinstance(default, dict)
        or default.get("ENGINE") != "django.db.backends.sqlite3"
    ):
        return False
    if (
        set(default) - {"ENGINE", "NAME"}
        or default.get("NAME", ":memory:") != ":memory:"
    ):
        return False
    return True


def _fixture_selected_user_model(index, settings, fixture):
    selected = _fixture_literal_setting(settings[1], "AUTH_USER_MODEL")
    apps = _fixture_literal_setting(settings[1], "INSTALLED_APPS")
    if (
        not isinstance(selected, str)
        or selected.count(".") != 1
        or not isinstance(apps, list)
    ):
        return None
    label, name = selected.split(".")
    modules = [
        app for app in apps if isinstance(app, str) and app.rsplit(".", 1)[-1] == label
    ]
    if len(modules) != 1:
        return None
    path, tree = fixture._django_mod(index, modules[0] + ".models")
    return (path, name, tree) if tree is not None else None


def _fixture_user_model(index, settings, maps):
    from . import mock_fixture_provenance as fixture

    selected = _fixture_selected_user_model(index, settings, fixture)
    if selected is None:
        return None
    path, name, _ = selected
    owner = maps[0].get((path, name))
    if owner is None:
        return None
    chain = _fixture_chain(
        index,
        path,
        owner,
        maps,
        "django.contrib.auth.models.AbstractUser",
        "django.AbstractUser.default-manager-password.v1",
    )
    if chain is None or not chain["terminal_assumptions"]:
        return None
    protected = {
        "objects",
        "USERNAME_FIELD",
        "EMAIL_FIELD",
        "REQUIRED_FIELDS",
        "password",
        "set_password",
        "check_password",
        "save",
        "__getattr__",
        "__getattribute__",
        "__setattr__",
        "__new__",
        "__init__",
    }
    if any(
        _fixture_class_binding(node, key)
        for _, _, node in chain["chain"]
        for key in protected
    ):
        return None
    return chain


def _fixture_class_binding(owner, name):
    return bool(binding_occurrences(owner.body, name))


def _fixture_testcase_owner_closed(index, path, owner):
    from . import mock_fixture_provenance as fixture

    origin = fixture._django_name(index, path)
    if not origin:
        return False
    class_origin = f"{origin}.{owner.name}"
    for other_path, tree in index["modules"].items():
        if not index["source"].validate(other_path):
            return False
        if other_path == path and any(
            isinstance(node, ast.Name)
            and node.id == owner.name
            and isinstance(node.ctx, ast.Load)
            for node in ast.walk(tree)
        ):
            return False
        package = fixture._django_name(index, other_path).rpartition(".")[0]
        for statement in ast.walk(tree):
            if not isinstance(statement, (ast.Import, ast.ImportFrom)):
                continue
            rows = fixture._django_import_rows(statement, package)
            if rows is None or any(
                target in {origin, class_origin, f"{origin}.*"} for _, target in rows
            ):
                return False
    return True


def _fixture_test_chain(index, path, function, maps):
    owner = index["source"].parents[path].get(id(function))
    if not isinstance(owner, ast.ClassDef) or function.decorator_list:
        return None
    chain = _fixture_chain(
        index,
        path,
        owner,
        maps,
        "django.test.TestCase",
        "django.TestCase.transactional-local-client.v1",
    )
    if chain is None or not chain["terminal_assumptions"]:
        return None
    protected = {
        "client",
        "client_class",
        "__getattr__",
        "__getattribute__",
        "__setattr__",
        "__delattr__",
        "__new__",
        "__init__",
        "setUpClass",
        "_pre_setup",
        "_fixture_setup",
        "run",
        "__call__",
    }
    if any(
        _fixture_class_binding(node, key)
        for _, _, node in chain["chain"]
        for key in protected
    ):
        return None
    return chain


def _fixture_create_user_provider(call):
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "create_user":
        return None
    manager = call.func.value
    if not isinstance(manager, ast.Attribute) or manager.attr != "objects":
        return None
    return manager.value


def _fixture_resolve_user_model_provider(index, path, function, provider, fixture):
    if isinstance(provider, ast.Name):
        rows = binding_occurrences(function.body, provider.id)
        if len(rows) != 1 or not isinstance(rows[0], ast.Name):
            return None
        assignment = index["source"].parents[path].get(id(rows[0]))
        if not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1:
            return None
        if not _fixture_model_alias_closed(index, path, function, provider, assignment):
            return None
        provider = assignment.value
    if not isinstance(provider, ast.Call) or provider.args or provider.keywords:
        return None
    if (
        fixture._app_expression_name(index, path, provider.func, function)
        != "django.contrib.auth.get_user_model"
    ):
        return None
    if not _fixture_user_model_getter_use_closed(
        index, path, function, provider, fixture
    ):
        return None
    return True


def _fixture_user_model_getter_use_closed(index, path, function, selected, fixture):
    canonical = "django.contrib.auth.get_user_model"
    if (
        not isinstance(selected, ast.Call)
        or selected.args
        or selected.keywords
        or fixture._app_expression_name(index, path, selected.func, function)
        != canonical
    ):
        return False
    parents = index["source"].parents[path]
    references = []
    for node in ast.walk(function):
        if not isinstance(node, (ast.Name, ast.Attribute)):
            continue
        if not isinstance(node.ctx, ast.Load):
            continue
        if fixture._app_expression_name(index, path, node, function) != canonical:
            continue
        if (
            _fixture_scope(index, path, node, (ast.FunctionDef, ast.AsyncFunctionDef))
            is not function
        ):
            return False
        call = parents.get(id(node))
        if (
            not isinstance(call, ast.Call)
            or call.func is not node
            or call is not selected
        ):
            return False
        references.append(node)
    return len(references) == 1 and references[0] is selected.func


def _fixture_model_alias_closed(index, path, function, selected, assignment):
    """Keep a fresh model provider alias within its exact local manager-call role."""
    if (assignment.end_lineno, assignment.end_col_offset) >= (
        selected.lineno,
        selected.col_offset,
    ):
        return False
    for node in ast.walk(function):
        if (
            not isinstance(node, ast.Name)
            or node.id != selected.id
            or node is assignment.targets[0]
        ):
            continue
        if not _fixture_model_alias_use(index, path, function, node):
            return False
    return True


def _fixture_model_alias_use(index, path, function, node):
    """Reject provider writes, escapes and aliases before granting enrollment identity."""
    if (
        not isinstance(node.ctx, ast.Load)
        or _fixture_scope(index, path, node, (ast.FunctionDef, ast.AsyncFunctionDef))
        is not function
    ):
        return False
    parents = index["source"].parents[path]
    manager = parents.get(id(node))
    if not isinstance(manager, ast.Attribute) or manager.attr != "objects":
        return False
    method = parents.get(id(manager))
    if not isinstance(manager.ctx, ast.Load) or not isinstance(method, ast.Attribute):
        return False
    call = parents.get(id(method))
    return bool(
        method.attr == "create_user"
        and isinstance(method.ctx, ast.Load)
        and isinstance(call, ast.Call)
        and call.func is method
    )


def _fixture_create_user_username(call):
    args = {item.arg: item.value for item in call.keywords}
    if None in args or len(args) != len(call.keywords):
        return None
    return args.get("username") if not call.args else call.args[0]


def _fixture_creation_username(index, path, function, call):
    from . import mock_fixture_provenance as fixture

    provider = _fixture_create_user_provider(call)
    if provider is None or not _fixture_resolve_user_model_provider(
        index, path, function, provider, fixture
    ):
        return None
    return _fixture_create_user_username(call)


def _fixture_creator(index, path, function, call, use):
    from . import mock_fixture_provenance as fixture

    if function.name != "setUp" or function.decorator_list:
        return None
    username = _fixture_creation_username(index, path, function, call)
    password = (
        {item.arg: item.value for item in call.keywords}.get("password")
        if not call.args
        else call.args[2]
        if len(call.args) == 3
        else None
    )
    if password is not use or not fixture._app_active_call(index, path, function, call):
        return None
    identity = _fixture_constant(index, path, username, function)
    return identity if identity is not None else None


def _fixture_login(index, path, function, call, use, maps):
    from . import mock_fixture_provenance as fixture

    if not function.name.startswith("test_") or function.decorator_list:
        return None
    if fixture._app_member_chain(call.func) != ["self", "client", "login"] or call.args:
        return None
    receiver = call.func.value.value
    owner = index["source"].parents[path].get(id(function))
    if not _class_binding.instance_receiver(
        receiver, function, owner, index["source"], path
    ):
        return None
    args = {item.arg: item.value for item in call.keywords}
    if (
        set(args) != {"username", "password"}
        or len(call.keywords) != 2
        or args["password"] is not use
    ):
        return None
    chain = _fixture_test_chain(index, path, function, maps)
    identity = _fixture_constant(index, path, args["username"], function)
    if chain is None or identity is None:
        return None
    if not fixture._app_active_call(index, path, function, call):
        return None
    if not fixture._app_capability_interval(index, path, function, call.lineno):
        return None
    if not _fixture_receiver_interval_clear(index, path, function, call):
        return None
    return identity, chain


def _fixture_imports_secret(index, path, tree, origin_path, statement, secret):
    from . import mock_fixture_provenance as fixture

    origin_module = fixture._django_name(index, origin_path)
    for node in tree.body:
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(node, ast.ImportFrom) and any(
            alias.name == "*" for alias in node.names
        ):
            return True
        rows = fixture._django_import_rows(
            node, fixture._django_name(index, path).rpartition(".")[0]
        )
        for name, target in rows or ():
            if _fixture_symbol(index, path, ast.Name(id=name, ctx=ast.Load())) == (
                origin_path,
                statement,
            ) or target in {origin_module, f"{origin_module}.{secret}"}:
                return True
    return False


def _fixture_reflective_uses(
    index, origin_path, statement, secret, *, all_sources=False
):
    from . import mock_fixture_provenance as fixture

    dynamic = {
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "delattr",
        "eval",
        "exec",
        "compile",
        "__import__",
        "_getframe",
        "currentframe",
        "stack",
        "walk_stack",
        "__getattribute__",
        "__getattr__",
        "__dict__",
        "__globals__",
        "attrgetter",
    }
    for path, tree in index["modules"].items():
        if not index["source"].validate(path):
            return True
        if (
            not all_sources
            and path != origin_path
            and not _fixture_imports_secret(
                index, path, tree, origin_path, statement, secret
            )
        ):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                scope = (
                    _fixture_scope(
                        index, path, node, (ast.FunctionDef, ast.AsyncFunctionDef)
                    )
                    or tree
                )
                if fixture._app_dynamic_callable(
                    index, path, scope, node.func, dynamic
                ):
                    return True
    return False


def _fixture_secret_aliases(index, path, statement):
    from . import mock_fixture_provenance as fixture

    aliases = {}
    for source_path in index["modules"]:
        selected = fixture._django_imports(index, source_path)
        aliases[source_path] = {
            name
            for name in (selected or {})
            if _fixture_symbol(index, source_path, ast.Name(id=name, ctx=ast.Load()))
            == (path, statement)
        }
    return aliases


def _fixture_module_aliases(index, origin_path):
    from . import mock_fixture_provenance as fixture

    origin = fixture._django_name(index, origin_path)
    aliases = {}
    for path, tree in index["modules"].items():
        package = fixture._django_name(index, path).rpartition(".")[0]
        selected = {
            name
            for node in tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for name, target in (fixture._django_import_rows(node, package) or ())
            if target == origin
        }
        if any(
            isinstance(node, ast.ImportFrom)
            and any(alias.name == "*" for alias in node.names)
            for node in tree.body
        ):
            selected.add("*")
        aliases[path] = selected
    return aliases


def _fixture_module_alias_use_supported(index, path, node, aliases, secret):
    if (
        isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id == secret
        and "*" in aliases[path]
    ):
        return False
    if not (
        isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id in aliases[path]
    ):
        return True
    parent = index["source"].parents[path].get(id(node))
    return bool(
        isinstance(parent, ast.Attribute)
        and parent.value is node
        and parent.attr == secret
        and isinstance(parent.ctx, ast.Load)
    )


def _fixture_declaration_target(path, use_path, statement, node):
    if use_path != path:
        return False
    targets = (
        statement.targets if isinstance(statement, ast.Assign) else [statement.target]
    )
    return any(node is item for target in targets for item in ast.walk(target))


def _fixture_consumer_row(index, path, statement, maps, use_path, use):
    function = _fixture_scope(
        index, use_path, use, (ast.FunctionDef, ast.AsyncFunctionDef)
    )
    if _fixture_symbol(index, use_path, use, function) != (path, statement):
        return ()
    if not isinstance(use.ctx, ast.Load):
        return None
    parents = index["source"].parents[use_path]
    parent = parents.get(id(use))
    call = parents.get(id(parent)) if isinstance(parent, ast.keyword) else parent
    if not isinstance(function, ast.FunctionDef) or not isinstance(call, ast.Call):
        return None
    creator = _fixture_creator(index, use_path, function, call, use)
    login = (
        None if creator else _fixture_login(index, use_path, function, call, use, maps)
    )
    if creator is None and login is None:
        return None
    return use_path, use, function, call, creator, login


def _fixture_consumers(index, path, statement, maps):
    secret = (
        statement.targets[0].id
        if isinstance(statement, ast.Assign)
        else statement.target.id
    )
    aliases = _fixture_secret_aliases(index, path, statement)
    module_aliases = _fixture_module_aliases(index, path)
    rows = []
    for use_path, tree in index["modules"].items():
        found = _fixture_consumers_in_tree(
            index,
            path,
            statement,
            maps,
            secret,
            aliases,
            module_aliases,
            use_path,
            tree,
        )
        if found is None:
            return None
        rows.extend(found)
    return None if _fixture_reflective_uses(index, path, statement, secret) else rows


def _fixture_consumers_in_tree(
    index, path, statement, maps, secret, aliases, module_aliases, use_path, tree
):
    rows = []
    for use in ast.walk(tree):
        if not _fixture_module_alias_use_supported(
            index, use_path, use, module_aliases, secret
        ):
            return None
        if not isinstance(use, (ast.Name, ast.Attribute)):
            continue
        if not _fixture_candidate_use(use, aliases[use_path], secret):
            continue
        if _fixture_declaration_target(path, use_path, statement, use):
            continue
        row = _fixture_consumer_row(index, path, statement, maps, use_path, use)
        if row is None:
            return None
        if row:
            rows.append(row)
    return rows


def _fixture_candidate_use(use, imported_aliases, secret):
    return (
        isinstance(use, ast.Name)
        and use.id in imported_aliases | {secret}
        or isinstance(use, ast.Attribute)
        and use.attr == secret
    )


def _fixture_setup_reaches(index, login, creation):
    chain = login[5][1]["chain"]
    creator_path, _, creator_function = creation[:3]
    owners = [node for _, _, node in chain]
    creator_owner = index["source"].parents[creator_path].get(id(creator_function))
    if creator_owner not in owners:
        return False
    for path, _, owner in chain:
        if not _fixture_setup_owner_is_supported(index, path, owner):
            return False
    return True


def django_testcase_helper_secret_evidence(index, path, literal, assignment, secret):
    """Bind a helper-local password to one source-resolved TestCase account/client lifecycle."""
    from . import mock_fixture_provenance as fixture

    source = index["source"]
    if not source.validate(path) or not isinstance(literal, ast.Constant):
        return None
    helper = source.parents[path].get(id(assignment))
    owner = source.parents[path].get(id(helper))
    if not _fixture_helper_owner_valid(helper, owner, assignment, literal, secret):
        return None
    context = _fixture_helper_test_context(index, path, helper, owner, fixture)
    if context is None:
        return None
    chain, lifecycle = context
    credential = _fixture_helper_credential_witness(
        index, path, helper, literal, secret, fixture
    )
    if credential is None:
        return None
    creation, client, login, password = credential
    from .credential_role_constructor_provider import django_user_identifier_contract

    identifier_contract = django_user_identifier_contract(index)
    if identifier_contract is None:
        return None
    account_field = _fixture_owned_field_closure(
        index,
        path,
        owner,
        creation,
        lifecycle["methods"],
        _fixture_account_field_consumer(
            index, path, creation, fixture, identifier_contract
        ),
    )
    client_field = _fixture_owned_field_closure(
        index,
        path,
        owner,
        client,
        lifecycle["methods"],
        _fixture_client_field_consumer(
            index, path, owner, helper, client, login, fixture
        ),
    )
    if account_field is None or client_field is None:
        return None
    account_field["identifier_contract"] = identifier_contract
    return _fixture_helper_evidence_record(
        index,
        path,
        assignment,
        secret,
        owner,
        helper,
        lifecycle,
        creation,
        client,
        login,
        identifier_contract,
        account_field,
        client_field,
        password,
        fixture,
    )


def _fixture_helper_credential_witness(index, path, helper, literal, secret, fixture):
    creation = _fixture_helper_account_creation(index, path, helper, secret, fixture)
    client = _fixture_helper_client_creation(index, path, helper, fixture)
    if creation is None or client is None:
        return None
    login = _fixture_helper_client_login(
        index, path, helper, creation, client, secret, fixture
    )
    if login is None:
        return None
    password = fixture._app_closed_consumer_uses(
        index,
        path,
        helper,
        secret,
        literal.value,
        {"credential_creation": creation, "local_client_login": login},
    )
    return (creation, client, login, password) if password is not None else None


def _fixture_helper_test_context(index, path, helper, owner, fixture):
    maps = _fixture_class_maps(index)
    chain = _fixture_test_chain(index, path, helper, maps) if maps is not None else None
    if chain is None or not _fixture_testcase_owner_closed(index, path, owner):
        return None
    lifecycle = _fixture_helper_lifecycle(index, path, owner, helper, chain, fixture)
    if lifecycle is None or not _fixture_helper_providers_clear(
        index, path, lifecycle["methods"], fixture
    ):
        return None
    return chain, lifecycle


def _fixture_helper_owner_valid(helper, owner, assignment, literal, secret):
    return (
        isinstance(helper, ast.FunctionDef)
        and isinstance(owner, ast.ClassDef)
        and not helper.decorator_list
        and _fixture_literal_binding(helper, assignment, literal, secret)
    )


def _fixture_helper_evidence_record(
    index,
    path,
    assignment,
    secret,
    owner,
    helper,
    lifecycle,
    creation,
    client,
    login,
    identifier_contract,
    account_field,
    client_field,
    password,
    fixture,
):
    source = index["source"]
    relative, digest = source.relative(path), source.inventory.get(path)
    if not isinstance(relative, str) or not isinstance(digest, str):
        return None
    return {
        "eligible": True,
        "classification": "APPLICATION_TEST_CREDENTIAL_ROLE",
        "source": relative,
        "source_sha256": digest,
        "declaration_span": fixture._evidence_node_span(assignment),
        "profile": "SOURCE_BOUND_FACTORY_TEST_AUTHORITY",
        "witness_spans": {
            "testcase": fixture._evidence_node_span(owner),
            "setup": fixture._evidence_node_span(lifecycle["setup"]),
            "helper": fixture._evidence_node_span(helper),
            "creation": fixture._evidence_node_span(creation),
            "client": fixture._evidence_node_span(client),
            "login": fixture._evidence_node_span(login),
        },
        "runtime_assurance": "INCOMPLETE",
        "transport_role": "UNASSESSED",
        "target_execution": "not_performed",
        "isolation_assurance": "UNASSESSED",
        "witness_sources": {
            "source": {
                "path": relative,
                "sha256": digest,
                "span": fixture._evidence_node_span(owner),
            },
        },
        "consumer_use_closure": {
            "schema": "factory.test-authority-consumer-closure.v1",
            "complete": True,
            "source": relative,
            "source_sha256": digest,
            "registration": lifecycle["registration"],
            "credential": password,
            "account_field": account_field,
            "client_field": client_field,
        },
    }


def _fixture_literal_binding(function, assignment, literal, secret):
    return bool(
        isinstance(assignment, ast.Assign)
        and len(assignment.targets) == 1
        and isinstance(assignment.targets[0], ast.Name)
        and assignment.targets[0].id == secret
        and assignment.value is literal
        and isinstance(literal.value, str)
        and binding_occurrences(function.body, secret) == [assignment.targets[0]]
    )


def _fixture_helper_lifecycle(index, path, owner, helper, chain, fixture):
    setup_rows = binding_occurrences(owner.body, "setUp")
    if len(setup_rows) != 1 or not isinstance(setup_rows[0], ast.FunctionDef):
        return None
    setup = setup_rows[0]
    methods = {
        node.name: node
        for node in owner.body
        if isinstance(node, ast.FunctionDef) and not node.decorator_list
    }
    selected, assertions = _fixture_setup_registrations(
        index, path, setup, methods, fixture
    )
    if selected is None:
        return None
    if not selected or sum(method is helper for method, _ in selected) != 1:
        return None
    if any(
        sum(candidate is method for candidate, _ in selected) != 1
        for method, _ in selected
    ):
        return None
    test_methods = [
        node
        for node in owner.body
        if isinstance(node, ast.FunctionDef)
        and node.name.startswith("test_")
        and not node.decorator_list
    ]
    if not test_methods:
        return None
    if not _fixture_helper_receivers_closed(index, path, owner, methods):
        return None
    if not _fixture_helper_calls_unique(owner, selected):
        return None
    registration = {
        "chain": [fixture._evidence_node_span(node) for _, _, node in chain["chain"]],
        "setup": fixture._evidence_node_span(setup),
        "helper_calls": [fixture._evidence_node_span(call) for _, call in selected],
        "assertions": [fixture._evidence_node_span(call) for call in assertions],
    }
    return {
        "setup": setup,
        "methods": tuple([setup, *(method for method, _ in selected), *test_methods]),
        "calls": tuple(call for _, call in selected),
        "registration": registration,
    }


def _fixture_setup_registrations(index, path, setup, methods, fixture):
    selected, assertions = [], []
    for call in (node for node in ast.walk(setup) if isinstance(node, ast.Call)):
        member = fixture._app_member_chain(call.func)
        if member and member[0] == "self" and len(member) == 2 and member[1] in methods:
            method = methods[member[1]]
            if method is setup or call.args or call.keywords:
                return None, None
            selected.append((method, call))
        elif (
            member == ["self", "assertTrue"]
            and len(call.args) == 1
            and not call.keywords
        ):
            if not fixture._app_provider_unchanged(
                index, path, setup, "django.test.TestCase"
            ):
                return None, None
            assertions.append(call)
        else:
            return None, None
    return selected, assertions


def _fixture_helper_receivers_closed(index, path, owner, methods):
    from . import credential_identity_audit as identity_audit

    parents = index["source"].parents[path]
    for method in methods.values():
        if not identity_audit._app_object_owner_receiver_closed(method, parents):
            return False
        receivers = [
            node.value
            for node in ast.walk(method)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "self"
        ]
        if any(
            not _class_binding.instance_receiver(
                receiver, method, owner, index["source"], path
            )
            for receiver in receivers
        ):
            return False
    return True


def _fixture_helper_calls_unique(owner, selected):
    for method, call in selected:
        refs = [
            node
            for node in ast.walk(owner)
            if isinstance(node, ast.Attribute) and node.attr == method.name
        ]
        if refs != [call.func]:
            return False
    return True


def _fixture_helper_providers_clear(index, path, methods, fixture):
    providers = (
        "django.test.TestCase",
        "django.test.Client",
        "django.contrib.auth.models.User",
    )
    return all(
        fixture._app_provider_unchanged(index, path, index["modules"][path], provider)
        and all(
            fixture._app_provider_unchanged(index, path, method, provider)
            for method in methods
        )
        for provider in providers
    )


def _fixture_helper_account_creation(index, path, helper, secret, fixture):
    calls = [
        node
        for node in ast.walk(helper)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "create_superuser"
    ]
    if len(calls) != 1:
        return None
    call = calls[0]
    provider = (
        call.func.value.value if isinstance(call.func.value, ast.Attribute) else None
    )
    if (
        not isinstance(call.func.value, ast.Attribute)
        or call.func.value.attr != "objects"
        or fixture._app_expression_name(index, path, provider, helper)
        != "django.contrib.auth.models.User"
        or not fixture._app_provider_unchanged(
            index, path, helper, "django.contrib.auth.models.User"
        )
        or not fixture._app_active_call(index, path, helper, call)
    ):
        return None
    args = _fixture_user_manager_arguments(call)
    if (
        args is None
        or not _fixture_expression_is_local_literal(helper, args["password"], secret)
        or not _fixture_string_literal(index, path, helper, args["username"])
        or not _fixture_string_literal(index, path, helper, args["email"])
    ):
        return None
    assignment = index["source"].parents[path].get(id(call))
    target = (
        assignment.targets[0]
        if isinstance(assignment, ast.Assign) and len(assignment.targets) == 1
        else None
    )
    return (
        call
        if isinstance(target, ast.Attribute)
        and fixture._app_member_chain(target)[:1] == ["self"]
        else None
    )


def _fixture_user_manager_arguments(call):
    names = ("username", "email", "password")
    if _call_has_expansion(call) or len(call.args) > len(names):
        return None
    values = dict(zip(names, call.args))
    for item in call.keywords:
        if item.arg not in names or item.arg in values:
            return None
        values[item.arg] = item.value
    return values if set(values) == set(names) else None


def _fixture_expression_is_local_literal(function, expression, secret):
    if isinstance(expression, ast.Name):
        rows = binding_occurrences(function.body, expression.id)
        return (
            expression.id == secret and len(rows) == 1 and isinstance(rows[0], ast.Name)
        )
    return False


def _fixture_helper_client_creation(index, path, helper, fixture):
    calls = [
        node
        for node in ast.walk(helper)
        if isinstance(node, ast.Call)
        and fixture._app_expression_name(index, path, node.func, helper)
        == "django.test.Client"
    ]
    if len(calls) != 1 or calls[0].args or calls[0].keywords:
        return None
    assignment = index["source"].parents[path].get(id(calls[0]))
    target = (
        assignment.targets[0]
        if isinstance(assignment, ast.Assign) and len(assignment.targets) == 1
        else None
    )
    return (
        calls[0]
        if isinstance(target, ast.Attribute)
        and fixture._app_member_chain(target)[:1] == ["self"]
        else None
    )


def _fixture_helper_client_login(
    index, path, helper, creation, client, secret, fixture
):
    client_field = _fixture_assignment_field(index, path, client, fixture)
    if client_field is None:
        return None
    calls = [
        node
        for node in ast.walk(helper)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "login"
        and fixture._app_member_chain(node.func.value) == ["self", client_field]
    ]
    if len(calls) != 1:
        return None
    call, values = calls[0], _fixture_keywords(calls[0])
    created = _fixture_user_manager_arguments(creation)
    if (
        call.args
        or values is None
        or set(values) != {"username", "password"}
        or created is None
        or not _fixture_expression_is_local_literal(helper, values["password"], secret)
        or _fixture_string_literal(index, path, helper, values["username"])
        != _fixture_string_literal(index, path, helper, created["username"])
        or not fixture._app_active_call(index, path, helper, call)
    ):
        return None
    return call


def _fixture_assignment_field(index, path, call, fixture):
    assignment = index["source"].parents[path].get(id(call))
    target = (
        assignment.targets[0]
        if isinstance(assignment, ast.Assign) and len(assignment.targets) == 1
        else None
    )
    chain = fixture._app_member_chain(target) if target is not None else None
    return chain[1] if chain and chain[0] == "self" and len(chain) == 2 else None


def _fixture_same_origin(function, left, right):
    return (
        isinstance(left, ast.Name)
        and isinstance(right, ast.Name)
        and left.id == right.id
        and len(binding_occurrences(function.body, left.id)) == 1
    )


def _fixture_string_literal(index, path, function, expression):
    if isinstance(expression, ast.Name):
        rows = binding_occurrences(function.body, expression.id)
        if len(rows) != 1:
            return None
        statement = index["source"].parents[path].get(id(rows[0]))
        if (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and statement.targets[0] is rows[0]
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            return statement.value.value
        return None
    selected = _fixture_constant(index, path, expression, function)
    if selected is None or not isinstance(selected[1].value, ast.Constant):
        return None
    value = selected[1].value.value
    return value if isinstance(value, str) else None


def _fixture_keywords(call):
    if _call_has_expansion(call):
        return None
    values = {}
    for item in call.keywords:
        if item.arg is None or item.arg in values:
            return None
        values[item.arg] = item.value
    return values


def _fixture_owned_field_closure(index, path, owner, creation, methods, consumer):
    from . import mock_fixture_provenance as fixture
    from .finite_capture import captured_value_use_closure

    assignment = index["source"].parents[path].get(id(creation))
    target = (
        assignment.targets[0]
        if isinstance(assignment, ast.Assign) and len(assignment.targets) == 1
        else None
    )
    chain = fixture._app_member_chain(target) if target is not None else None
    if not chain or chain[0] != "self" or len(chain) != 2:
        return None
    field = chain[1]
    reads = _fixture_owned_field_reads(
        index, path, owner, field, target, methods, fixture
    )
    if reads is None:
        return None

    def scope_of(node):
        return _fixture_scope(index, path, node, ast.FunctionDef)

    def successors(function, value, parents):
        return _fixture_owned_field_successors(
            creation,
            assignment,
            field,
            reads,
            function,
            value,
            parents,
            fixture,
            scope_of,
        )

    result = captured_value_use_closure(
        _fixture_scope(index, path, creation, ast.FunctionDef),
        creation,
        index["source"].parents[path],
        scope_of,
        lambda _function: None,
        consumer,
        field_successors=successors,
    )
    if result is None:
        return None
    return {
        "schema": "factory.captured-owned-field-use-closure.v1",
        "complete": True,
        "source": index["source"].relative(path),
        "source_sha256": index["source"].inventory.get(path),
        "field": field,
        "assignment_span": fixture._evidence_node_span(assignment),
        "uses": [fixture._evidence_node_span(node) for node in result["nodes"]],
        "sinks": [fixture._evidence_node_span(node) for node in result["sinks"]],
    }


def _fixture_owned_field_reads(index, path, owner, field, target, methods, fixture):
    reads = [
        node
        for node in ast.walk(owner)
        if isinstance(node, ast.Attribute)
        and fixture._app_member_chain(node) == ["self", field]
        and isinstance(node.ctx, ast.Load)
    ]
    writes = [
        node
        for node in ast.walk(owner)
        if isinstance(node, ast.Attribute)
        and fixture._app_member_chain(node) == ["self", field]
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    if not reads or writes != [target]:
        return None
    if any(
        _fixture_scope(index, path, node, ast.FunctionDef) not in methods
        for node in (*reads, *writes)
    ):
        return None
    return reads


def _fixture_owned_field_successors(
    creation, assignment, field, reads, function, value, parents, fixture, scope_of
):
    parent = parents.get(id(value))
    if parent is assignment and value is creation:
        return tuple((scope_of(node), node) for node in reads)
    if isinstance(value, ast.Attribute) and fixture._app_member_chain(value) == [
        "self",
        field,
    ]:
        if isinstance(parent, ast.Attribute) and parent.value is value:
            return [(function, parent)]
        if isinstance(parent, ast.Call) and (
            value in parent.args or any(item.value is value for item in parent.keywords)
        ):
            return [(function, parent)]
    if isinstance(value, ast.Attribute) and fixture._app_member_chain(value)[:2] == [
        "self",
        field,
    ]:
        if isinstance(parent, ast.Call) and parent.func is value:
            return [(function, parent)]
    if (
        isinstance(value, ast.Name)
        and isinstance(parent, ast.Call)
        and (
            value in parent.args or any(item.value is value for item in parent.keywords)
        )
    ):
        return [(function, parent)]
    return None


def _fixture_account_field_consumer(index, path, creation, fixture, contract):
    field = _fixture_assignment_field(index, path, creation, fixture)
    if field is None or contract is None:
        return lambda _function, _value: None

    def consume(function, value):
        if not isinstance(value, ast.Attribute):
            return None
        chain = fixture._app_member_chain(value)
        projection = chain[-1] if chain else None
        if projection in contract["projections"] and _fixture_field_origin(
            index, path, function, value, field, fixture, projection=projection
        ):
            return value
        return None

    return consume


def _fixture_client_field_consumer(index, path, owner, helper, client, login, fixture):
    field = _fixture_assignment_field(index, path, client, fixture)

    def consume(function, value):
        if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute):
            return None
        method = value.func.attr
        if method not in {"login", "get", "post"}:
            return None
        receiver = value.func.value
        if (
            _fixture_field_origin(index, path, function, receiver, field, fixture)
            is False
        ):
            return None
        if method == "login":
            return value if function is helper and value is login else None
        return (
            value
            if function.name.startswith("test_")
            and fixture._app_active_call(index, path, function, value)
            else None
        )

    return consume


def _fixture_field_origin(
    index, path, function, expression, field, fixture, projection=None
):
    chain = (
        fixture._app_member_chain(expression)
        if isinstance(expression, ast.Attribute)
        else None
    )
    if chain == ["self", field] and projection is None:
        return True
    if chain == ["self", field, projection] and projection is not None:
        return True
    if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
        rows = binding_occurrences(function.body, expression.value.id)
        statement = (
            index["source"].parents[path].get(id(rows[0])) if len(rows) == 1 else None
        )
        if isinstance(statement, ast.Assign):
            selected = statement.value
            if projection is not None and isinstance(selected, ast.Attribute):
                selected_chain = fixture._app_member_chain(selected)
                if selected_chain in (["self", field], ["self", field, projection]):
                    return True
            if projection is None and fixture._app_member_chain(selected) == [
                "self",
                field,
            ]:
                return True
    if isinstance(expression, ast.Name):
        rows = binding_occurrences(function.body, expression.id)
        if len(rows) != 1:
            return False
        statement = index["source"].parents[path].get(id(rows[0]))
        return isinstance(statement, ast.Assign) and _fixture_field_origin(
            index,
            path,
            function,
            statement.value,
            field,
            fixture,
            projection=projection,
        )
    return False


def _fixture_setup_owner_is_supported(index, path, owner):
    methods = binding_occurrences(owner.body, "setUp")
    if not methods:
        return True
    if len(methods) != 1 or not isinstance(methods[0], ast.FunctionDef):
        return False
    method = methods[0]
    if method.decorator_list or not method.body:
        return False
    first = method.body[0]
    if not isinstance(first, ast.Expr) or not isinstance(first.value, ast.Call):
        return False
    return _fixture_setup_call_is_supported(index, path, method, first.value)


def _fixture_setup_call_is_supported(index, path, method, call):
    from . import mock_fixture_provenance as fixture

    expected = ast.parse("super().setUp()", mode="eval").body
    if ast.dump(call, include_attributes=False) != ast.dump(
        expected, include_attributes=False
    ):
        return False
    if not fixture._django_builtins_unshadowed(index, path, {"super"}):
        return False
    if not _fixture_setup_super_unique(index, path, method, call):
        return False
    return _fixture_setup_client_lifetime(index, path, method)


def _fixture_demanded_providers_clear(index, rows):
    from . import mock_fixture_provenance as fixture

    providers = {
        "django.contrib.auth.get_user_model",
        "django.contrib.auth.models.AbstractUser",
        "django.test.TestCase",
        "django.test.Client",
    }
    for path, _, function, _, _, _ in rows:
        if not all(
            fixture._app_provider_unchanged(index, path, function, key)
            for key in providers
        ):
            return False
        if not all(
            fixture._app_provider_unchanged(index, path, index["modules"][path], key)
            for key in providers
        ):
            return False
    return True


def _fixture_role_rows(index, path, statement, secret):
    if index["source"].parents[path].get(id(statement)) is not index["modules"][path]:
        return None
    target = _fixture_declaration_target_node(statement)
    if target is None or binding_occurrences(index["modules"][path].body, secret) != [
        target
    ]:
        return None
    settings = _fixture_settings(index)
    if settings is None:
        return None
    maps = _fixture_class_maps(index)
    if maps is None:
        return None
    model = _fixture_user_model(index, settings, maps)
    if model is None:
        return None
    rows = _fixture_consumers(index, path, statement, maps)
    return (rows, model, settings) if rows is not None else None


def _fixture_declaration_target_node(statement):
    if isinstance(statement, ast.Assign) and statement.targets:
        return statement.targets[0]
    if isinstance(statement, ast.AnnAssign):
        return statement.target
    return None


def _fixture_role_pair(rows, index):
    if not rows or not _fixture_demanded_providers_clear(index, rows):
        return None
    creators = [row for row in rows if row[4] is not None]
    logins = [row for row in rows if row[5] is not None]
    if len(creators) != 1 or not logins:
        return None
    creator = creators[0]
    if any(
        row[5][0] != creator[4] or not _fixture_setup_reaches(index, row, creator)
        for row in logins
    ):
        return None
    return creators[0], logins


def _fixture_order_consumer_rows(index, rows):
    """Keep complete consumer rows deterministic across captured inventory order."""
    return sorted(
        rows,
        key=lambda row: (
            index["source"].relative(row[0]),
            row[1].lineno,
            row[1].col_offset,
            row[1].end_lineno,
            row[1].end_col_offset,
            row[3].lineno,
            row[3].col_offset,
            row[3].end_lineno,
            row[3].end_col_offset,
        ),
    )


def module_fixture_credential_evidence(index, path, statement, secret):
    """Demand a module binding's finite enrollment/login roles under explicit Django contracts."""
    role_rows = _fixture_role_rows(index, path, statement, secret)
    if role_rows is None:
        return None
    rows, model, settings = role_rows
    rows = _fixture_order_consumer_rows(index, rows)
    pair = _fixture_role_pair(rows, index)
    if pair is None:
        return None
    creator, logins = pair
    source = index["source"]

    def source_row(selected_path, node, role):
        return {
            "path": source.relative(selected_path),
            "sha256": source.inventory[selected_path],
            "span": [
                node.lineno,
                node.col_offset,
                node.end_lineno,
                node.end_col_offset,
            ],
            "role": role,
        }

    span = [
        statement.lineno,
        statement.col_offset,
        statement.end_lineno,
        statement.end_col_offset,
    ]
    return {
        "eligible": True,
        "classification": "APPLICATION_TEST_CREDENTIAL_ROLE",
        "source": source.relative(path),
        "source_sha256": source.inventory[path],
        "declaration_span": span,
        "profile": "DJANGO_CLASS_LOCAL_ACCOUNT_ENROLLMENT",
        "runtime_assurance": "INCOMPLETE",
        "transport_role": "UNASSESSED",
        "target_execution": "not_performed",
        "isolation_assurance": "UNASSESSED",
        "external_api_assumptions": model["terminal_assumptions"]
        + logins[0][5][1]["terminal_assumptions"],
        "settings": source_row(
            settings[0], settings[1].body[0], "selected_configuration_module"
        ),
        "consumer_use_closure": {
            "schema": "factory.application-consumer-use-closure.v2",
            "complete": True,
            "assignments": [source_row(path, statement, "credential_declaration")],
            "uses": [
                source_row(
                    row[0],
                    row[1],
                    "fresh_enrollment" if row[4] else "local_client_login",
                )
                for row in rows
            ],
            "operations": [
                source_row(
                    row[0],
                    row[3],
                    "fresh_enrollment" if row[4] else "local_client_login",
                )
                for row in rows
            ],
        },
    }


def module_fixture_helper_epoch():
    """Bind every captured module-role predicate and its reused source resolver."""
    from . import mock_fixture_provenance as fixture
    from . import credential_role_constructor_provider as provider
    from . import credential_role_method_use_getter_audit as getter
    from . import review_integrity
    from . import finite_capture
    from . import review_audits
    from . import credential_identity_audit as application_audit

    return (
        *security_value_helper_epoch(),
        module_fixture_evidence_for_binding,
        module_fixture_credential_evidence,
        _fixture_symbol,
        _fixture_constant,
        _fixture_scope,
        _fixture_class_maps,
        _fixture_chain,
        _fixture_literal_setting,
        _fixture_settings,
        _fixture_user_model,
        _fixture_test_chain,
        _fixture_class_binding,
        _fixture_creator,
        _fixture_creation_username,
        _fixture_login,
        _fixture_imports_secret,
        _fixture_reflective_uses,
        _fixture_secret_aliases,
        _fixture_module_aliases,
        _fixture_module_alias_use_supported,
        _fixture_declaration_target,
        _fixture_consumer_row,
        _fixture_consumers,
        _fixture_setup_reaches,
        _fixture_setup_owner_is_supported,
        _fixture_setup_call_is_supported,
        _fixture_demanded_providers_clear,
        _fixture_pytest_options,
        _fixture_selected_user_model,
        _fixture_create_user_provider,
        _fixture_resolve_user_model_provider,
        _fixture_create_user_username,
        _fixture_database_is_local,
        _fixture_consumers_in_tree,
        _fixture_candidate_use,
        _fixture_role_rows,
        _fixture_declaration_target_node,
        _fixture_role_pair,
        _fixture_order_consumer_rows,
        django_testcase_helper_secret_evidence,
        _fixture_literal_binding,
        _fixture_helper_lifecycle,
        _fixture_testcase_owner_closed,
        _fixture_helper_providers_clear,
        _fixture_helper_account_creation,
        _fixture_user_manager_arguments,
        _fixture_expression_is_local_literal,
        _fixture_helper_client_creation,
        _fixture_helper_client_login,
        _fixture_assignment_field,
        _fixture_same_origin,
        _fixture_string_literal,
        _fixture_keywords,
        _fixture_owned_field_closure,
        _fixture_account_field_consumer,
        _fixture_client_field_consumer,
        _fixture_field_origin,
        provider.resolve_class_chain_with_terminals,
        provider.SourceSnapshotIndex.validate,
        provider.SourceSnapshotIndex.module_paths,
        review_integrity.bind_source_call,
        _receiver_helper_epoch,
        _APP_RECEIVER_HOOKS_CACHE_TOKEN,
        *(helper for helper in _receiver_helper_epoch() if callable(helper)),
        provider.binding_occurrences,
        provider._presentation_provider_facts,
        finite_capture._shell_dynamic_provider_access,
        finite_capture._shell_namespace_queries_closed,
        finite_capture.captured_value_use_closure,
        finite_capture._captured_value_use_successors,
        finite_capture._captured_value_alias_loads,
        finite_capture.captured_literal_branch_field_transfer,
        finite_capture._captured_projection_receiver,
        finite_capture._captured_projection_receiver_closed,
        finite_capture.captured_call_scalar,
        finite_capture.captured_scalar_guard,
        finite_capture.captured_selected_field_assignments,
        review_audits._constant_truth_value,
        review_audits._constant_value,
        review_audits._comparison_value,
        fixture._app_local_assignment,
        fixture._app_closed_consumer_uses,
        fixture._app_credential_lineage,
        fixture._app_source_symbol,
        fixture._app_provider_unchanged,
        fixture._app_dynamic_callable,
        fixture._django_imports,
        fixture._django_import_rows,
        fixture._django_mod,
        _fixture_setup_super_unique,
        _fixture_setup_client_use,
        _fixture_setup_client_surface,
        _fixture_setup_client_lifetime,
        _class_binding.instance_receiver,
        _fixture_receiver_interval_clear,
        _fixture_prefix_receiver_use,
        _fixture_prefix_client_call,
        _fixture_user_model_getter_use_closed,
        _fixture_model_alias_closed,
        _fixture_model_alias_use,
        application_plaintext_effect_evidence,
        application_value_role_evidence,
        _immutable_default,
        _definition_effects_unknown,
        provider.constructor_provider_helper_epoch,
        *provider.constructor_provider_helper_epoch(),
        *(
            helper
            for name, helper in globals().items()
            if name.startswith("_app_") and callable(helper)
        ),
        *application_audit.application_identity_helper_epoch(),
        *(
            helper
            for name, helper in vars(fixture).items()
            if name.startswith("_app_consumer_")
        ),
        provider.effective_method,
        getter._member_mutated,
    )


def application_value_role_evidence(index, path, literal, assignment, secret):
    """Preserve the legacy facade for captured application credential evidence."""
    from .credential_identity_audit import application_value_role_evidence as evaluate

    return evaluate(index, path, literal, assignment, secret)


def _app_bound_field_transfer(index, path, call, caller, field):
    """Preserve the legacy helper seam for captured field transfer."""
    from .credential_identity_audit import _app_bound_field_transfer as evaluate

    return evaluate(index, path, call, caller, field)


def _app_signing_constructor_role_transfer_closed(summary, path, field, statement):
    """Preserve the legacy verifier seam for constructor-store admission."""
    from .credential_identity_audit import (
        _app_signing_constructor_role_transfer_closed as evaluate,
    )

    return evaluate(summary, path, field, statement)


def _app_literal_branch_field_transfer(
    index, path, constructor, bound, caller_path, caller, field
):
    """Preserve the legacy seam for branch-selected field transfer."""
    from .credential_identity_audit import (
        _app_literal_branch_field_transfer as evaluate,
    )

    return evaluate(index, path, constructor, bound, caller_path, caller, field)


def application_plaintext_effect_evidence(index, path, literal, assignment, secret):
    """Preserve the legacy facade for cached plaintext role evidence."""
    from .credential_identity_audit import (
        application_plaintext_effect_evidence as evaluate,
    )

    return evaluate(index, path, literal, assignment, secret)


def _app_crypto_methods(path, owner, source):
    """Preserve the legacy helper seam for captured crypto methods."""
    from .credential_identity_audit import _app_crypto_methods as evaluate

    return evaluate(path, owner, source)


def module_fixture_evidence_for_binding(index, path, assignment, secret):
    """Resolve module-level credential evidence only for its captured module binding."""
    if index["source"].parents[path].get(id(assignment)) is not index["modules"][path]:
        return None
    return module_fixture_credential_evidence(index, path, assignment, secret)


def _fixture_setup_super_unique(index, path, method, call):
    from . import mock_fixture_provenance as fixture

    nodes = own_function_nodes(method, path, index["source"])
    names = [
        node
        for node in nodes
        if isinstance(node, ast.Name)
        and node.id == "super"
        and isinstance(node.ctx, ast.Load)
    ]
    return (
        len(names) == 1
        and isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Call)
        and names[0] is call.func.value.func
        and fixture._django_builtins_unshadowed(index, path, {"super"})
    )


def _fixture_setup_client_use(index, path, method, node):
    from . import mock_fixture_provenance as fixture

    parents = index["source"].parents[path]
    chain = fixture._app_member_chain(node)
    if chain == ["self", "client"]:
        login = parents.get(id(node))
        if not isinstance(login, ast.Attribute) or login.value is not node:
            return False
    elif chain == ["self", "client", "login"]:
        login = node
    else:
        return False
    if isinstance(node.ctx, (ast.Store, ast.Del)):
        return False
    call = parents.get(id(login))
    if not isinstance(login, ast.Attribute) or login.attr != "login":
        return False
    if not isinstance(call, ast.Call) or call.func is not login or call.args:
        return False
    args = {item.arg: item.value for item in call.keywords}
    if None in args or len(call.keywords) != 2 or set(args) != {"username", "password"}:
        return False
    receiver = node.value if chain == ["self", "client"] else node.value.value
    owner = parents.get(id(method))
    return _class_binding.instance_receiver(
        receiver, method, owner, index["source"], path
    )


def _fixture_setup_client_surface(index, path, method):
    from . import mock_fixture_provenance as fixture

    nodes = own_function_nodes(method, path, index["source"])
    parents = index["source"].parents[path]
    for node in nodes:
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "self"
        ):
            return False
        if (
            isinstance(node, ast.Name)
            and node.id == "self"
            and isinstance(node.ctx, ast.Load)
        ):
            parent = parents.get(id(node))
            if not isinstance(parent, ast.Attribute) or parent.value is not node:
                return False
            if parent.attr.startswith("__"):
                return False
        if not isinstance(node, ast.Attribute):
            continue
        if (fixture._app_member_chain(node) or [])[:2] != ["self", "client"]:
            continue
        if not _fixture_setup_client_use(index, path, method, node):
            return False
    return True


def _fixture_setup_client_lifetime(index, path, method):
    """Close explicit selected-client writes and receiver escapes in captured setup."""
    from . import mock_fixture_provenance as fixture

    if _class_binding._receiver(method) != "self" or binding_occurrences(
        method.body, "self"
    ):
        return False
    if not _fixture_setup_client_surface(index, path, method):
        return False
    nodes = own_function_nodes(method, path, index["source"])
    end = max((getattr(node, "end_lineno", 0) for node in nodes), default=0) + 1
    return fixture._app_capability_interval(index, path, method, end)


def _fixture_receiver_interval_clear(index, path, function, invocation):
    """Keep the selected instance unescaped before a modeled local-client call."""
    parents = index["source"].parents[path]
    before = (invocation.lineno, invocation.col_offset)
    for node in own_function_nodes(function, path, index["source"]):
        if not isinstance(node, ast.Name) or node.id != "self":
            continue
        if (node.lineno, node.col_offset) >= before:
            continue
        if not _fixture_prefix_receiver_use(parents, node):
            return False
    return True


def _fixture_prefix_receiver_use(parents, node):
    """Reject prefix receiver escapes, reflective access and client capability changes."""
    member = parents.get(id(node))
    if not isinstance(member, ast.Attribute) or member.value is not node:
        return False
    if member.attr.startswith("__") or not isinstance(member.ctx, ast.Load):
        return False
    selected = member
    while isinstance(parents.get(id(selected)), (ast.Attribute, ast.Subscript)):
        selected = parents[id(selected)]
        if not isinstance(selected.ctx, ast.Load):
            return False
    call = parents.get(id(selected))
    if member.attr == "client":
        return _fixture_prefix_client_call(member, selected, call)
    return not isinstance(call, ast.Call) or call.func is not selected


def _fixture_prefix_client_call(member, selected, call):
    """Recognize the modeled local Client API, without admitting stored method aliases."""
    methods = {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "login",
        "logout",
    }
    return bool(
        isinstance(selected, ast.Attribute)
        and selected.value is member
        and selected.attr in methods
        and isinstance(call, ast.Call)
        and call.func is selected
    )


def structural_value_join(values):
    """Join bounded may-values, preserving known origins/items under UNKNOWN."""
    return join_identity_values(values)


def _structural_closed_consumer_uses(
    function, name, roots, parents, scope_of, transform
):
    """Share one complete use graph; family contracts supply permitted terminals."""
    from .finite_capture import captured_value_use_closure

    origin = binding_occurrences(function.body, name)
    if len(origin) != 1 or not isinstance(origin[0], ast.Name):
        return None
    permitted = {
        id(node): role for role, expression in roots for node in ast.walk(expression)
    }
    loads = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, ast.Load)
    ]
    if not loads or any(scope_of(node) is not function for node in loads):
        return None
    visited = {}

    def consumer(scope, node):
        return node if id(node) in permitted else None

    for load in loads:
        closure = captured_value_use_closure(
            function,
            load,
            parents,
            scope_of,
            lambda scope: (),
            consumer,
            field_successors=lambda scope, node, pp: _structural_consumer_transfer(
                scope, node, pp, transform
            ),
        )
        if closure is None:
            return None
        visited.update((id(node), node) for node in closure["nodes"])
    reached = [
        node
        for node in visited.values()
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    ]
    assignments = _structural_consumer_assignments(function, name, reached, parents)
    if assignments is None:
        return None
    roles = {id(node): permitted.get(id(node), "derived_value") for node in reached}
    if not _structural_consumer_writes_closed(function, name, origin[0], assignments):
        return None
    return assignments, reached, roles


def _structural_consumer_assignments(function, name, reached, parents):
    assignments = {}
    for node in reached:
        if node.id == name:
            continue
        bindings = binding_occurrences(function.body, node.id)
        if len(bindings) != 1 or not isinstance(bindings[0], ast.Name):
            return None
        assignment = parents.get(id(bindings[0]))
        if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
            return None
        assignments[node.id] = assignment
    return assignments


def _structural_consumer_transfer(scope, node, current_parents, transform):
    parent = current_parents.get(id(node))
    if isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is node:
        return None
    if isinstance(parent, ast.Attribute):
        call = current_parents.get(id(parent))
        if isinstance(call, ast.Call) and call.func is parent and transform(call):
            return [(scope, call)]
    if isinstance(parent, ast.expr) and transform(parent):
        return [(scope, parent)]
    return ()


def _structural_consumer_writes_closed(function, name, origin, assignments):
    """Nested write-only captures and namespace exports cannot disappear from a use graph."""
    targets = {name: origin}
    for key, statement in assignments.items():
        target = (
            statement.target
            if isinstance(statement, ast.AnnAssign)
            else statement.targets[0]
        )
        targets[key] = target
    for node in ast.walk(function):
        if (
            isinstance(node, (ast.Global, ast.Nonlocal))
            and set(node.names) & targets.keys()
        ):
            return False
        if (
            isinstance(node, ast.Name)
            and node.id in targets
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node is not targets[node.id]
        ):
            return False
    return True


def _module_function_binding_epoch(module):
    """Capture module bindings and code for functions and owned class methods."""
    from types import FunctionType

    namespace = vars(module)
    bindings = []
    for name in sorted(namespace):
        value = namespace[name]
        if isinstance(value, FunctionType):
            bindings.append(value)
        if not isinstance(value, type) or value.__module__ != module.__name__:
            continue
        for method_name in sorted(vars(value)):
            descriptor = vars(value)[method_name]
            if isinstance(descriptor, (classmethod, staticmethod)):
                function = descriptor.__func__
            elif isinstance(descriptor, FunctionType):
                function = descriptor
            else:
                continue
            bindings.append(function)
    return tuple(bindings)


def _security_structural_request_value(expression, leaf, value_type):
    from .semantic_credential_sensor import _SecurityFlowValue, _security_flow_step

    if isinstance(leaf, _SecurityFlowValue):
        steps = tuple(leaf.steps)
        digest = next(
            (step[2] for step in steps if isinstance(step, tuple) and len(step) == 3),
            "unknown-source",
        )
        return value_type(
            roots=frozenset({"source:" + digest}) if leaf.tainted else frozenset(),
            inert_kind="scalar" if leaf.kind in {"text", "bytes"} else None,
            unknown=False,
            scalar_kind=leaf.kind,
            trace=steps,
        )
    return value_type(
        roots=frozenset({"source:unknown-request-kind"}),
        unknown=True,
        content_unknown=True,
        trace=(_security_flow_step(expression, "REQUEST_SOURCE_UNKNOWN_KIND"),),
    )


def _security_structural_summary_context(
    call, function, roots, path, index, source_resolved, callee_path
):
    from . import finite_capture

    if (
        not isinstance(call, ast.Call)
        or not isinstance(function, ast.FunctionDef)
        or function.decorator_list
    ) or not isinstance(roots, dict):
        return None
    binding = finite_capture._structural_helper_binding(call, function, source_resolved)
    if binding is None:
        return None
    module, actuals = binding
    callee_path = path if callee_path is None else callee_path
    source_index = getattr(module, "_security_source_model", None)
    invalid = finite_capture._structural_helper_invalid_reason(
        source_index, index, path, callee_path, function
    )
    return invalid or (module, actuals, callee_path, source_index)


def _security_structural_exact_resolver(
    call,
    function,
    callee_path,
    actuals,
    source_resolved,
    negative_binding_closed,
    negative_binding_check,
    resolve_call,
):
    def exact_resolver(candidate, candidate_path):
        if candidate is call:
            return ResolvedIdentityCall(
                function,
                callee_path,
                actuals,
                negative_binding_closed=not source_resolved or negative_binding_closed,
                negative_binding_check=negative_binding_check,
            )
        return (
            resolve_call(candidate, candidate_path) if callable(resolve_call) else None
        )

    return exact_resolver


def _source_index_request_leaf_values(function, path, index):
    """Project request leaves only from the validated source node and its lexical bindings."""
    if not index.validate(path) or id(function) not in index.parents[path]:
        return {}
    from . import review_audits as audit
    from . import review_integrity as flow
    from . import semantic_credential_sensor as sensor

    tree = index.snapshots[path]
    aliases = audit._security_aliases(tree.body)
    parents = index.parents[path]
    values = {}
    for expression in own_function_nodes(function, path, index):
        if not isinstance(expression, (ast.Call, ast.Subscript, ast.Attribute)):
            continue
        statement = _source_request_parent_statement(expression, function, parents)
        if statement is None or not sensor.http_request_payload(
            expression,
            aliases,
            function,
            statement,
            flow._security_scope_request_aliases,
        ):
            continue
        kind = sensor._request_payload_source_kind(
            expression,
            aliases,
            flow._security_scope_request_aliases,
            function,
            statement,
        )
        if kind not in {"text", "bytes"}:
            continue
        leaf = sensor._SecurityFlowValue(
            True, kind, (sensor._security_flow_step(expression, "REQUEST_SOURCE"),)
        )
        values[("expression", id(expression))] = _security_structural_request_value(
            expression, leaf, _Value
        )
    return values


def _source_request_parent_statement(expression, function, parents):
    current = expression
    while current is not function:
        parent = parents.get(id(current))
        if (
            parent is None
            or isinstance(
                parent,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
            )
            and parent is not function
        ):
            return None
        if isinstance(parent, ast.stmt):
            return parent
        current = parent
    return None


def security_value_helper_epoch():
    """Bind cached proofs to the shared value, effect, binding and transfer kernel."""
    from . import finite_capture
    from . import semantic_credential_sensor
    from . import credential_role_identity_effects as effects
    from . import review_audits as audit
    from .import_context import import_resolution_helpers
    from .credential_role_constructor_provider import (
        _presentation_provider_shadow,
        constructor_provider_helper_epoch,
    )
    from .mock_fixture_provenance import (
        _app_source_symbol,
        _app_expression_name,
        _django_name,
        _django_mod,
    )

    return (
        security_value_helper_epoch,
        _Value,
        _Value.__init__,
        IdentityEffectSummary,
        *import_resolution_helpers(),
        _presentation_provider_shadow,
        *constructor_provider_helper_epoch(),
        _app_source_symbol,
        _app_expression_name,
        _django_name,
        _django_mod,
        IdentityReturnProjection,
        ResolvedIdentityCall,
        ResolvedIdentityCall.__init__,
        SourceSnapshotIndex.validate,
        audit._oracle_tree_fingerprint,
        audit.integrity._security_local_helper_definition,
        *_module_function_binding_epoch(effects),
        *_module_function_binding_epoch(finite_capture),
        *_module_function_binding_epoch(semantic_credential_sensor),
        identity_value,
        _identity_call_value,
        _subscript_value,
        _container_value,
        _attribute_value,
        _unknown_expression,
        _value_trace,
        _value_with_trace,
        _unproved_return_binding,
        tracked_roots,
        _unknown_value,
        _container_identity,
        _value_container_ids,
        _container_value_shape,
        structural_value_join,
        join_identity_values,
        invalidate_structural_statement,
        resolve_source_identity_call,
        source_symbol_index,
        summarize_identity_call,
        mapped_call_values,
        _declared_call_defaults,
        _with_inert_defaults,
        _immutable_default,
        _Analyzer._call,
        _Analyzer._visit,
        _Analyzer._project_returns,
        _Effects.merge,
        _Effects.freeze,
        *(
            value
            for name, value in globals().items()
            if name.startswith("_structural_") and callable(value)
        ),
        *(
            value
            for name, value in vars(finite_capture).items()
            if (
                name.startswith(("security_structural_", "_security_structural_"))
                or name
                in {
                    "_SecurityFlowState",
                    "_security_store_structural_targets",
                    "_security_merge_structural_states",
                    "_security_source_path",
                    "_structural_compat_value",
                    "_legacy_security_value",
                    "security_input_value_flow",
                    "security_helper_return_value",
                }
            )
            and callable(value)
        ),
    )
