"""Bounded source-only identity-effect summaries for selected object roots."""

import ast
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

    def merge(self, other):
        """Merge class writes, escapes, unknowns, and field writes from another effect accumulator."""
        for name in ("class_writes", "escapes", "unknowns", "field_writes"):
            getattr(self, name).update(getattr(other, name))
        self.field_transfers.extend(other.field_transfers)
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


_UNKNOWN_KEY = object()


def identity_value(node, aliases, *, strict_calls=False):
    """Project names, attributes, and literal containers without evaluation."""
    if isinstance(node, ast.Constant):
        return _Value(inert_kind="scalar")
    if isinstance(node, ast.Name):
        return aliases.get(node.id, _Value())
    if isinstance(node, ast.Attribute):
        return _attribute_value(node, aliases, strict_calls=strict_calls)
    if isinstance(node, (ast.List, ast.Tuple, ast.Dict)):
        return _container_value(node, aliases, strict_calls=strict_calls)
    if isinstance(node, ast.Subscript):
        return _subscript_value(node, aliases, strict_calls=strict_calls)
    if isinstance(node, ast.Call):
        return _identity_call_value(node, aliases, strict_calls=strict_calls)
    return _unknown_expression(node, aliases, strict_calls=strict_calls)


def _identity_call_value(node, aliases, *, strict_calls=False):
    if isinstance(node.func, ast.Attribute) and node.func.attr == "__class__":
        receiver = identity_value(node.func.value, aliases, strict_calls=strict_calls)
        if contains_tracked(receiver):
            return _Value(unknown=True)
    return (
        _Value(content_unknown=True)
        if strict_calls
        else _unknown_expression(node, aliases, strict_calls=strict_calls)
    )


def _subscript_value(node, aliases, *, strict_calls=False):
    base = identity_value(node.value, aliases, strict_calls=strict_calls)
    key = node.slice.value if isinstance(node.slice, ast.Constant) else None
    if strict_calls and base.content_unknown:
        return _Value(unknown=True)
    return dict(base.items).get(key, _Value(unknown=contains_tracked(base)))


def _unknown_expression(node, aliases, *, strict_calls=False):
    roots = set()
    if isinstance(node, ast.expr):
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                roots.update(tracked_roots(aliases.get(child.id, _Value())))
    return _Value(roots=frozenset(roots), unknown=bool(roots))


def _container_value(node, aliases, *, strict_calls=False):
    if isinstance(node, (ast.List, ast.Tuple, ast.Dict)):
        pairs = (
            zip(node.keys, node.values)
            if isinstance(node, ast.Dict)
            else enumerate(node.elts)
        )
        items, unknown = [], False
        for key, item in pairs:
            value = identity_value(item, aliases, strict_calls=strict_calls)
            if isinstance(node, ast.Dict) and not isinstance(key, ast.Constant):
                key_value = (
                    identity_value(key, aliases, strict_calls=strict_calls)
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
        )
    return _Value()


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


def _attribute_value(node, aliases, *, strict_calls=False):
    base = identity_value(node.value, aliases, strict_calls=strict_calls)
    if node.attr == "__class__" and base.roots:
        return _Value(class_roots=base.roots)
    if len(base.roots) == 1 and not base.unknown and not base.class_roots:
        projected = aliases.get((next(iter(base.roots)), node.attr))
        if projected is not None:
            return projected
    if strict_calls and base.roots and not base.class_roots and not base.unknown:
        return _Value(content_unknown=True)
    if strict_calls and base.content_unknown:
        return _Value(unknown=True)
    return _Value(unknown=bool(base.roots or base.class_roots or base.unknown))


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
    if operands and not all(
        identity_value(value, aliases, strict_calls=True).inert_kind
        for value in operands
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
    params = _resolved_parameter_names(resolved.function)
    actuals = _call_actual_expressions(call)
    if not maps_each_actual_once(actuals, resolved.arguments):
        out.unknowns.add("exact call mapping must cover each actual once")
        return None
    mapped = {}
    for formal, expr in resolved.arguments.items():
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
    if (
        not isinstance(expr, ast.expr)
        or value.unknown
        or (strict_calls and value.content_unknown)
        or len(roots) > 1
        or (value.items and roots)
    ):
        out.unknowns.add("ambiguous exact call root mapping")
        return None
    return value


def _with_inert_defaults(function, mapped, out, *, strict_calls=False):
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    defaults = dict(
        zip((arg.arg for arg in positional[-len(args.defaults) :]), args.defaults)
    )
    defaults.update(
        (arg.arg, value) for arg, value in zip(args.kwonlyargs, args.kw_defaults)
    )
    for parameter in [*positional, *args.kwonlyargs]:
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
    pass
    pass

    out = _Effects(record_role_events=role_view)
    if (
        not index.validate(path)
        or id(call) not in index.parents[path]
        or not isinstance(call, ast.Call)
    ):
        out.unknowns.add("call is not a validated captured expression")
        return out.freeze()
    analyzer = _Analyzer(index, resolve_call, 4, 512, field_roots, True, role_view)
    if analyzer.fields is None:
        out.unknowns.add("invalid initial field identity graph")
        return out.freeze()
    aliases = {name: _Value(roots=frozenset({root})) for name, root in roots.items()}
    aliases.update(analyzer.fields)
    analyzer._call(call, path, aliases, 0, frozenset(), out)
    return out.freeze()


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
    roots: Mapping[str, str],
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
    """
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
        .run(function, path, dict(roots), 0, frozenset())
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

    def _call(self, call, path, aliases, depth, active, out):
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

        out.merge(self.run(resolved.function, resolved.path, mapped, depth + 1, active))


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
                target in {origin, class_origin, f"{origin}.*"}
                for _, target in rows
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
    if (
        not isinstance(helper, ast.FunctionDef)
        or not isinstance(owner, ast.ClassDef)
        or helper.decorator_list
        or not _fixture_literal_binding(helper, assignment, literal, secret)
    ):
        return None
    maps = _fixture_class_maps(index)
    chain = _fixture_test_chain(index, path, helper, maps) if maps is not None else None
    if chain is None or not _fixture_testcase_owner_closed(index, path, owner):
        return None
    lifecycle = _fixture_helper_lifecycle(index, path, owner, helper, chain, fixture)
    if lifecycle is None:
        return None
    if not _fixture_helper_providers_clear(index, path, lifecycle["methods"], fixture):
        return None
    creation = _fixture_helper_account_creation(index, path, helper, secret, fixture)
    client = _fixture_helper_client_creation(index, path, helper, fixture)
    if creation is None or client is None:
        return None
    login = _fixture_helper_client_login(index, path, helper, creation, client, secret, fixture)
    if login is None:
        return None
    password = fixture._app_closed_consumer_uses(
        index, path, helper, secret, literal.value,
        {"credential_creation": creation, "local_client_login": login},
    )
    if password is None:
        return None
    from .credential_role_constructor_provider import django_user_identifier_contract

    identifier_contract = django_user_identifier_contract(index)
    if identifier_contract is None:
        return None
    account_field = _fixture_owned_field_closure(
        index, path, owner, creation, lifecycle["methods"],
        _fixture_account_field_consumer(index, path, creation, fixture, identifier_contract),
    )
    client_field = _fixture_owned_field_closure(
        index, path, owner, client, lifecycle["methods"],
        _fixture_client_field_consumer(index, path, owner, helper, client, login, fixture),
    )
    if account_field is None or client_field is None:
        return None
    account_field["identifier_contract"] = identifier_contract
    relative = source.relative(path)
    digest = source.inventory.get(path)
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
            "source": {"path": relative, "sha256": digest, "span": fixture._evidence_node_span(owner)},
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
        node.name: node for node in owner.body
        if isinstance(node, ast.FunctionDef) and not node.decorator_list
    }
    selected, assertions = [], []
    for call in (node for node in ast.walk(setup) if isinstance(node, ast.Call)):
        member = fixture._app_member_chain(call.func)
        if member and member[0] == "self" and len(member) == 2 and member[1] in methods:
            method = methods[member[1]]
            if method is setup or call.args or call.keywords:
                return None
            selected.append((method, call))
        elif (
            member == ["self", "assertTrue"]
            and len(call.args) == 1 and not call.keywords
            and fixture._app_provider_unchanged(index, path, setup, "django.test.TestCase")
        ):
            assertions.append(call)
        else:
            return None
    if not selected or sum(method is helper for method, _ in selected) != 1:
        return None
    if any(sum(candidate is method for candidate, _ in selected) != 1 for method, _ in selected):
        return None
    test_methods = [
        node for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
        and not node.decorator_list
    ]
    if not test_methods:
        return None
    parents = index["source"].parents[path]
    from . import credential_identity_audit as identity_audit

    for method in methods.values():
        if not identity_audit._app_object_owner_receiver_closed(method, parents):
            return None
        receivers = [
            node.value for node in ast.walk(method)
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
            return None
    for method, call in selected:
        refs = [node for node in ast.walk(owner) if isinstance(node, ast.Attribute) and node.attr == method.name]
        if refs != [call.func]:
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


def _fixture_helper_providers_clear(index, path, methods, fixture):
    providers = (
        "django.test.TestCase",
        "django.test.Client",
        "django.contrib.auth.models.User",
    )
    return all(
        fixture._app_provider_unchanged(index, path, index["modules"][path], provider)
        and all(fixture._app_provider_unchanged(index, path, method, provider) for method in methods)
        for provider in providers
    )


def _fixture_helper_account_creation(index, path, helper, secret, fixture):
    calls = [node for node in ast.walk(helper) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == "create_superuser"]
    if len(calls) != 1:
        return None
    call = calls[0]
    provider = call.func.value.value if isinstance(call.func.value, ast.Attribute) else None
    if (
        not isinstance(call.func.value, ast.Attribute) or call.func.value.attr != "objects"
        or fixture._app_expression_name(index, path, provider, helper) != "django.contrib.auth.models.User"
        or not fixture._app_provider_unchanged(index, path, helper, "django.contrib.auth.models.User")
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
    target = assignment.targets[0] if isinstance(assignment, ast.Assign) and len(assignment.targets) == 1 else None
    return call if isinstance(target, ast.Attribute) and fixture._app_member_chain(target)[:1] == ["self"] else None


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
        return expression.id == secret and len(rows) == 1 and isinstance(rows[0], ast.Name)
    return False


def _fixture_helper_client_creation(index, path, helper, fixture):
    calls = [node for node in ast.walk(helper) if isinstance(node, ast.Call)
             and fixture._app_expression_name(index, path, node.func, helper) == "django.test.Client"]
    if len(calls) != 1 or calls[0].args or calls[0].keywords:
        return None
    assignment = index["source"].parents[path].get(id(calls[0]))
    target = assignment.targets[0] if isinstance(assignment, ast.Assign) and len(assignment.targets) == 1 else None
    return calls[0] if isinstance(target, ast.Attribute) and fixture._app_member_chain(target)[:1] == ["self"] else None


def _fixture_helper_client_login(index, path, helper, creation, client, secret, fixture):
    client_field = _fixture_assignment_field(index, path, client, fixture)
    if client_field is None:
        return None
    calls = [node for node in ast.walk(helper) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == "login"
             and fixture._app_member_chain(node.func.value) == ["self", client_field]]
    if len(calls) != 1:
        return None
    call, values = calls[0], _fixture_keywords(calls[0])
    created = _fixture_user_manager_arguments(creation)
    if (
        call.args or values is None or set(values) != {"username", "password"}
        or created is None or not _fixture_expression_is_local_literal(helper, values["password"], secret)
        or _fixture_string_literal(index, path, helper, values["username"])
        != _fixture_string_literal(index, path, helper, created["username"])
        or not fixture._app_active_call(index, path, helper, call)
    ):
        return None
    return call


def _fixture_assignment_field(index, path, call, fixture):
    assignment = index["source"].parents[path].get(id(call))
    target = assignment.targets[0] if isinstance(assignment, ast.Assign) and len(assignment.targets) == 1 else None
    chain = fixture._app_member_chain(target) if target is not None else None
    return chain[1] if chain and chain[0] == "self" and len(chain) == 2 else None


def _fixture_same_origin(function, left, right):
    return isinstance(left, ast.Name) and isinstance(right, ast.Name) and left.id == right.id and len(
        binding_occurrences(function.body, left.id)
    ) == 1


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
    target = assignment.targets[0] if isinstance(assignment, ast.Assign) and len(assignment.targets) == 1 else None
    chain = fixture._app_member_chain(target) if target is not None else None
    if not chain or chain[0] != "self" or len(chain) != 2:
        return None
    field = chain[1]
    reads = [node for node in ast.walk(owner) if isinstance(node, ast.Attribute)
             and fixture._app_member_chain(node) == ["self", field] and isinstance(node.ctx, ast.Load)]
    writes = [node for node in ast.walk(owner) if isinstance(node, ast.Attribute)
              and fixture._app_member_chain(node) == ["self", field]
              and isinstance(node.ctx, (ast.Store, ast.Del))]
    if not reads or writes != [target] or any(
        _fixture_scope(index, path, node, ast.FunctionDef) not in methods for node in (*reads, *writes)
    ):
        return None
    def scope_of(node):
        return _fixture_scope(index, path, node, ast.FunctionDef)
    def successors(function, value, parents):
        parent = parents.get(id(value))
        if parent is assignment and value is creation:
            return tuple((scope_of(node), node) for node in reads)
        if isinstance(value, ast.Attribute) and fixture._app_member_chain(value) == ["self", field]:
            if isinstance(parent, ast.Attribute) and parent.value is value:
                return [(function, parent)]
            if isinstance(parent, ast.Call) and (value in parent.args or any(item.value is value for item in parent.keywords)):
                return [(function, parent)]
        if isinstance(value, ast.Attribute) and fixture._app_member_chain(value)[:2] == ["self", field]:
            if isinstance(parent, ast.Call) and parent.func is value:
                return [(function, parent)]
        if isinstance(value, ast.Name) and isinstance(parent, ast.Call) and (
            value in parent.args or any(item.value is value for item in parent.keywords)
        ):
            return [(function, parent)]
        return None
    result = captured_value_use_closure(
        _fixture_scope(index, path, creation, ast.FunctionDef), creation,
        index["source"].parents[path], scope_of, lambda _function: None, consumer,
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


def _fixture_account_field_consumer(index, path, creation, fixture, contract):
    field = _fixture_assignment_field(index, path, creation, fixture)
    if field is None or contract is None:
        return lambda _function, _value: None
    def consume(function, value):
        if not isinstance(value, ast.Attribute):
            return None
        chain = fixture._app_member_chain(value)
        projection = chain[-1] if chain else None
        if (
            projection in contract["projections"]
            and _fixture_field_origin(
                index, path, function, value, field, fixture, projection=projection
            )
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
        if _fixture_field_origin(index, path, function, receiver, field, fixture) is False:
            return None
        if method == "login":
            return value if function is helper and value is login else None
        return value if function.name.startswith("test_") and fixture._app_active_call(index, path, function, value) else None
    return consume


def _fixture_field_origin(index, path, function, expression, field, fixture, projection=None):
    chain = fixture._app_member_chain(expression) if isinstance(expression, ast.Attribute) else None
    if chain == ["self", field] and projection is None:
        return True
    if chain == ["self", field, projection] and projection is not None:
        return True
    if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
        rows = binding_occurrences(function.body, expression.value.id)
        statement = index["source"].parents[path].get(id(rows[0])) if len(rows) == 1 else None
        if isinstance(statement, ast.Assign):
            selected = statement.value
            if projection is not None and isinstance(selected, ast.Attribute):
                selected_chain = fixture._app_member_chain(selected)
                if selected_chain in (["self", field], ["self", field, projection]):
                    return True
            if projection is None and fixture._app_member_chain(selected) == ["self", field]:
                return True
    if isinstance(expression, ast.Name):
        rows = binding_occurrences(function.body, expression.id)
        if len(rows) != 1:
            return False
        statement = index["source"].parents[path].get(id(rows[0]))
        return isinstance(statement, ast.Assign) and _fixture_field_origin(
            index, path, function, statement.value, field, fixture, projection=projection
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
