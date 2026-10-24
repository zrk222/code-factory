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
            roots.update(set().union(*(tracked_roots(item) for item in known_projection)))
        elif receiver:
            roots.update(receiver)
    elif isinstance(node, ast.Subscript) and not roots:
        roots.update(_role_expression_roots(node.value, aliases, strict_calls=strict_calls))
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
        field_ids = {f"{root}.{target.attr}" for root in base.roots}
        if any(
            (root, target.attr) in (initial_fields or {}) for root in base.roots
        ) or (
            effects.record_role_events
            and field_ids.intersection(effects.field_writes)
        ):
            effects.unknowns.add("projected field identity overwritten")
        if target.attr == "__class__":
            effects.class_writes.update(base.roots)
            if effects.record_role_events and (base.unknown or base.content_unknown):
                effects.unknowns.add("class write receiver identity is unresolved")
            _add_role_event(
                effects,
                "class_write",
                base.roots,
                path,
                source_node or target,
                target.attr,
            )
        else:
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
            if effects.record_role_events and target.attr not in ordinary_fields and not _ordinary_field_dispatch(
                function, target.attr, parents
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
        effects.escapes.update(tracked_roots(value))
        if value.unknown:
            effects.unknowns.add("field stores unresolved tracked value")
    else:
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
            uncertain=(value.unknown or _has_unknown_content(value)),
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
        and node.name in {"__getattribute__", "__getattr__", "__setattr__", "__delattr__"}
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
                _role_expression_roots(call.func.value, aliases, strict_calls=strict_calls)
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
                _role_expression_roots(call.func.value, aliases, strict_calls=strict_calls)
                if isinstance(call.func, ast.Attribute)
                else ()
            ),
            uncertain=True,
        )


def _call_role_actuals(call, aliases, *, strict_calls=False):
    actuals = [f"arg[{i}]" for i, value in enumerate(call.args) if _role_expression_roots(value, aliases, strict_calls=strict_calls)]
    actuals.extend(
        f"keyword:{item.arg}"
        for item in call.keywords
        if item.arg and _role_expression_roots(item.value, aliases, strict_calls=strict_calls)
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
        )
        .run(function, path, dict(roots), 0, frozenset())
        .freeze()
    )


class _Analyzer:
    def __init__(
        self, index, resolver, depth_limit, budget, field_roots, strict_calls, role_view,
        ordinary_fields=(),
    ):
        self.index, self.resolver = index, resolver
        self.depth_limit, self.budget, self.states = depth_limit, budget, 0
        self.fields = identity_fields(field_roots, index)
        self.strict_calls = strict_calls
        self.role_view = role_view
        self.ordinary_fields = frozenset(ordinary_fields)

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
        nodes = own_function_nodes(function, path, self.index)
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
        for param in params:
            if param.arg not in roots or not tracked_roots(env[param.arg]):
                continue
            rebindings = [
                node
                for node in ast.walk(function)
                if isinstance(node, ast.Name)
                and node.id == param.arg
                and isinstance(node.ctx, ast.Store)
            ]
            if rebindings:
                out.unknowns.add(f"root parameter rebound: {param.arg}")
        assigns = [
            n
            for n in nodes
            if isinstance(n, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
        ]
        for _ in range(min(len(assigns) + 1, 32)):
            changed = False
            field_writes = {}
            for node in assigns:
                target = assignment_target(node)
                value = identity_value(
                    getattr(node, "value", None),
                    env,
                    strict_calls=self.strict_calls,
                )
                if isinstance(target, ast.Name):
                    if binding_occurrences(function.body, target.id) != [target]:
                        continue
                    if (
                        contains_tracked(value) or value.inert_kind is not None
                    ) and env.get(target.id) != value:
                        env[target.id], changed = value, True
                elif (
                    self.role_view
                    and isinstance(target, ast.Attribute)
                    and target.attr != "__class__"
                ):
                    base = identity_value(target.value, env, strict_calls=self.strict_calls)
                    roots = tracked_roots(base)
                    if not roots:
                        continue
                    unconditional = _field_transfer_unconditional(
                        node, function, self.index.parents.get(path)
                    )
                    for root in roots:
                        field_writes.setdefault((root, target.attr), []).append(
                            (value, unconditional, len(roots) != 1 or base.unknown)
                        )
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
                    env[key], changed = projected, True
            if not changed:
                break
        else:
            out.unknowns.add("alias fixed-point limit")
        return env

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
                uncertain=len(receiver) != 1 or any(
                    value.unknown or _has_unknown_content(value) for value in known
                ),
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
        bound = (
            isinstance(parent, ast.Call) and parent.func is node
        ) or (
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
            if contains_tracked(value) and binding_occurrences(
                function.body, target.id
            ) != [target]:
                out.unknowns.add(f"ambiguous alias binding: {target.id}")
            else:
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
                        out,
                        "local_alias",
                        tracked_roots(value),
                        path,
                        node,
                        target.id,
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
                out.unknowns.add("unresolved call may reach tracked identity indirectly")
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
        binding_occurrences(node.body, key)
        for _, _, node in chain["chain"]
        for key in protected
    ):
        return None
    return chain


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
        binding_occurrences(node.body, key)
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
        _application_effect_cache_key,
        _application_plaintext_effect_evidence_uncached,
        _immutable_default,
        _definition_effects_unknown,
        provider.constructor_provider_helper_epoch,
        *provider.constructor_provider_helper_epoch(),
        *(
            helper
            for name, helper in globals().items()
            if name.startswith("_app_") and callable(helper)
        ),
        *(
            helper
            for name, helper in vars(fixture).items()
            if name.startswith("_app_consumer_")
        ),
        provider.effective_method,
        getter._member_mutated,
    )


def application_value_role_evidence(index, path, literal, assignment, secret):
    """Resolve shared test-authority effects before the reversible-value lane."""
    signing = _app_signing_authority(index, path, assignment, secret)
    if signing is not None:
        return signing
    object_signing = _app_object_signing_authority(index, path, assignment, secret)
    if object_signing is not None:
        return object_signing
    factory = _app_factory_test_authority(index, path, assignment, secret)
    return (
        factory
        if factory is not None
        else application_plaintext_effect_evidence(
            index, path, literal, assignment, secret
        )
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

    if not isinstance(call, ast.Call) or _call_has_expansion(call) or len(seen) >= 6:
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
    transfer = _app_signing_constructor_transfer(index, chain, call, actual)
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


def _app_signing_constructor_transfer(index, chain, call, actual):
    from .review_integrity import bind_source_call

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
    except (TypeError, ValueError):
        return None
    formals = [name for name, value in bound.items() if value is actual]
    if len(formals) != 1:
        return None
    transfer = _app_signing_parameter_field(
        index, constructor_path, constructor, formals[0]
    )
    if transfer is None:
        return None
    constructor_args = [*constructor.args.posonlyargs, *constructor.args.args]
    if not constructor_args:
        return None
    receiver = constructor_args[0].arg
    ordinary_fields = _app_signing_ordinary_fields(chain, {transfer[0]})
    if ordinary_fields is None:
        return None
    resolver = _app_signing_constructor_resolver(chain, receiver)
    effects = summarize_identity_effect(
        constructor,
        constructor_path,
        index["source"],
        {receiver: "owner", formals[0]: "candidate"},
        resolve_call=resolver,
        strict_calls=True,
        role_view=True,
        ordinary_fields=ordinary_fields,
    )
    if not _app_signing_constructor_role_transfer_closed(
        effects, constructor_path, transfer[0], transfer[1]
    ):
        return None
    return constructor_path, *transfer


def _app_signing_ordinary_fields(chain, selected_fields):
    """Prove only selected instance fields avoid source-declared descriptors and slots."""
    if not selected_fields or any(
        not isinstance(name, str) or not name.isidentifier() for name in selected_fields
    ):
        return None
    for _, owner in chain:
        if binding_occurrences(owner.body, "__slots__"):
            return None
        if any(binding_occurrences(owner.body, name) for name in selected_fields):
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
        selected = effective_method(methods, call.func.attr)
        if selected is None:
            return None
        method_path, method = selected
        try:
            bound = bind_source_call(
                call, method, call.func.value, apply_defaults=False
            )
        except (TypeError, ValueError):
            return None
        return ResolvedIdentityCall(method, method_path, bound)

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
    expected_span = _event_span(path, statement.value)
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
        _class_binding._source_module(path) + "." + owner.name for path, owner in chain
    }
    model = _class_binding.constructor_provider_model(
        selected,
        index["source"],
        imports,
        _class_binding._source_aliases,
        _class_binding._has_opaque_owner_capture,
    )
    if model is None:
        return False
    roots, aliases, filtered, shared, fields, consumers = model
    metadata = _app_class_metadata_operands(index, selected, aliases)
    for path, node, callee in metadata:
        filtered.setdefault(path, set()).update(id(item) for item in ast.walk(node))
        consumers.add(callee)
    return _class_binding._captured_mutations_inert(
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
    if not isinstance(call, ast.Call) or _call_has_expansion(call):
        return None
    selected = fixture._app_source_symbol(
        index, path, call.func, _enclosing_function(call, parents)
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
    return _class_binding._source_module(target_path) + "." + function.name


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
        and _enclosing_function(node, parents) is function
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
    return all(_immutable_default(value) for value in defaults) and all(
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
        ) and binding_occurrences(current.body, node.id):
            return False
        if isinstance(
            current, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) and node.id in _argument_names(current):
            return False
        current = parents.get(id(current))
    return _app_signing_terminal_stable(index, "builtins." + node.id)


def _app_signing_transfer_chain(index, path, owner, seen=()):
    """Close source inheritance; ABCMeta is an explicit non-transforming model."""
    from . import mock_fixture_provenance as fixture

    key = (path, id(owner))
    if key in seen or len(seen) >= 8 or owner.decorator_list:
        return None
    if binding_occurrences(index["modules"][path].body, owner.name) != [owner]:
        return None
    if any(binding_occurrences(owner.body, name) for name in _HOOKS):
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
    if not isinstance(root, ast.Name) or _class_binding._presentation_provider_shadow(
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
        aliases, mutations, star = _class_binding._presentation_provider_facts(
            tree, list(ast.walk(tree)), index["source"].parents[path], audit
        )
        overlapping = [
            (provider, member)
            for provider, member in mutations
            if _class_binding._mutation_overlaps(provider, member, canonical)
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
            and not _class_binding._presentation_provider_shadow(
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


def _app_signing_parameter_field(index, path, constructor, formal):
    """Require the non-null actual to enter one exact instance field."""
    parents = index["source"].parents[path]
    args = [*constructor.args.posonlyargs, *constructor.args.args]
    if not args or constructor.decorator_list:
        return None
    receiver = args[0].arg
    transfer = None
    for node in ast.walk(constructor):
        if not isinstance(node, ast.Name) or node.id != formal:
            continue
        parent = parents.get(id(node))
        if _app_signing_null_fallback(node, parent, parents, formal):
            continue
        if (
            not isinstance(node.ctx, ast.Load)
            or _enclosing_function(node, parents) is not constructor
        ):
            return None
        target = assignment_target(parent)
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
    summary = summarize_identity_effect(
        constructor, target_path, index["source"], roots, strict_calls=False
    )
    rows = [
        row
        for row in summary.field_transfers
        if row.target_root == "target" and row.target_field == field
    ]
    branch_proof = None
    if len(rows) == 1 and rows[0].unconditional and rows[0].statement is not None:
        transfer = rows[0]
        formals = [name for name in bound if "input:" + name in transfer.source_roots]
    else:
        branch_proof = _app_literal_branch_field_transfer(
            index, target_path, constructor, bound, path, caller, field
        )
        if branch_proof is None:
            return None
        selected = [row for row in rows if row.statement is branch_proof["statement"]]
        if len(selected) != 1:
            return None
        transfer = selected[0]
        formals = [branch_proof["formal"]]
    if summary.field_writes.count("target." + field) != 1:
        # Branch-pruned writes are intentionally checked by the separate
        # source-bound selector; the may-effect set collapses branch arms.
        if branch_proof is None:
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


def _app_header_list_transfer(index, constructor_transfer):
    """Prove a finite map projection keeps each caller-owned list unchanged."""
    from . import mock_fixture_provenance as fixture

    transfer = constructor_transfer["transfer"]
    call = transfer.value
    if not (
        isinstance(call, ast.Call)
        and not _call_has_expansion(call)
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
    target = assignment_target(initial)
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
    normalized = assignment_target(normalization)
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
    destination = assignment_target(store)
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
    from . import mock_fixture_provenance as fixture
    from .review_integrity import bind_source_call

    source = index["source"]
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
    constructor_mode = raw["bound"].get("mode")
    from .finite_capture import captured_call_scalar

    if captured_call_scalar(
        source, test_path, test_method, constructor_mode, raw["path"]
    ) != ("http",):
        return None
    if raw["actual"] is not headers["actual"]:
        if not (
            isinstance(raw["actual"], ast.Name)
            and isinstance(headers["actual"], ast.Call)
            and headers["actual"].func is not None
        ):
            return None
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
    condition = source.parents[process_path].get(id(verify_call))
    if not (
        isinstance(condition, ast.If)
        and condition.test is verify_call
        and len(condition.body) == 1
        and isinstance(condition.body[0], ast.Return)
        and isinstance(condition.body[0].value, ast.Call)
        and isinstance(condition.body[0].value.func, ast.Name)
        and condition.body[0].value.func.id == process_args[3].arg
    ):
        return None
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
    actual_next = bound.get(next_name)
    if len(observed) != 1 or not isinstance(actual_next, ast.Name):
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
    return {"assertion": observed[0], "continuation": returns[0], "status": status[0]}


def _app_test_header_signature_carrier(
    index, path, test_method, headers_call, signature_key, timestamp_key, body_actual
):
    from .review_integrity import bind_source_call

    if not isinstance(headers_call, ast.Call) or not isinstance(
        headers_call.func, ast.Attribute
    ):
        return None
    owner = _fixture_scope(index, path, test_method, ast.ClassDef)
    if owner is None or not isinstance(headers_call.func.value, ast.Name):
        return None
    name = headers_call.func.attr
    methods = [
        node
        for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(methods) != 1 or binding_occurrences(owner.body, name) != methods:
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
        if (
            not isinstance(key, ast.Constant)
            or not isinstance(key.value, str)
            or key.value.lower() in {name.lower() for name in mapping}
            or not isinstance(value, ast.List)
        ):
            return None
        mapping[key.value] = value
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
        return None
    generated = signature_list.elts[0]
    if not isinstance(generated, ast.Call) or not isinstance(
        generated.func, ast.Attribute
    ):
        return None
    generated_method = generated.func.attr
    if not isinstance(generated.func.value, ast.Name):
        return None
    methods = [
        node
        for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name == generated_method
    ]
    if (
        len(methods) != 1
        or binding_occurrences(owner.body, generated_method) != methods
    ):
        return None
    signature_formals = [*methods[0].args.posonlyargs, *methods[0].args.args]
    if len(signature_formals) < 3:
        return None
    producer_returns = [
        node for node in methods[0].body if isinstance(node, ast.Return)
    ]
    if len(producer_returns) != 1 or not isinstance(
        producer_returns[0].value, ast.Call
    ):
        return None
    producer = producer_returns[0].value
    producer_arguments = dict(zip(("body", "timestamp"), producer.args))
    if len(producer.args) > 2:
        return None
    for keyword in producer.keywords:
        if (
            keyword.arg not in {"body", "timestamp"}
            or keyword.arg in producer_arguments
        ):
            return None
        producer_arguments[keyword.arg] = keyword.value
    producer_args = list(producer_arguments.values())
    if not (
        isinstance(producer.func, ast.Attribute)
        and producer.func.attr == "generate_signature"
        and isinstance(producer.func.value, ast.Attribute)
        and isinstance(producer.func.value.value, ast.Name)
        and producer.func.value.value.id == signature_formals[0].arg
        and _app_signing_slot_read(
            producer.func.value,
            methods[0],
            index["source"].parents[path],
        )
        and not _call_has_expansion(producer)
        and len(producer_args) == 2
        and all(isinstance(item, ast.Name) for item in producer_args)
        and set(producer_arguments) == {"body", "timestamp"}
        and producer_arguments["body"].id == signature_formals[1].arg
        and producer_arguments["timestamp"].id == signature_formals[2].arg
    ):
        return None
    signature_bound = bind_source_call(
        generated, methods[0], generated.func.value, apply_defaults=False
    )
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
        "mapping": returns[0],
        "signature_call": generated,
        "modeled_producer": producer,
        "signature_key": signature_key,
        "timestamp_key": timestamp_key,
        "body_formal": body_formal,
        "timestamp_formal": time_formal,
    }


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
        and not _call_has_expansion(skip.test)
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
    members = binding_occurrences(owner.body, skip.test.func.attr)
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
        if statement is declaration and assignment_target(statement) is node:
            continue
        function = _enclosing_function(node, parents)
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
    target = assignment_target(statement)
    if not (
        len(args) == 1
        and not getter.args.kwonlyargs
        and not getter.args.vararg
        and not getter.args.kwarg
        and len(getter.decorator_list) == 1
        and isinstance(getter.decorator_list[0], ast.Name)
        and getter.decorator_list[0].id == "property"
        and not binding_occurrences(owner.body, "property")
        and not binding_occurrences(index["modules"][path].body, "property")
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
        and not binding_occurrences(getter.body, receiver)
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
        function = _enclosing_function(node, parents)
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
            and assignment_target(statement) is node
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
        function = _enclosing_function(node, parents)
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
    if _call_has_expansion(call) or len(call.args) > 3:
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
    if any(binding_occurrences(owner.body, name) for name in (*_HOOKS, "__init__")):
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
    if binding_occurrences(owner.body, secret) != [
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
        function = _enclosing_function(node, parents)
        if isinstance(node, ast.Name):
            if _fixture_scope(index, path, node, ast.ClassDef) is not owner:
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
            target = assignment_target(statement)
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
            _enclosing_function(call, parents),
            call,
            parents,
            lambda node: _enclosing_function(node, parents),
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
    if binding_occurrences(owner.body, function.name) != [function]:
        return None
    parents = index["source"].parents[path]
    result = []
    for node in ast.walk(owner):
        if not isinstance(node, ast.Attribute) or node.attr != function.name:
            continue
        caller = _enclosing_function(node, parents)
        call = parents.get(id(node))
        if any(call is terminal for terminal in terminal_calls):
            continue
        if not (
            caller
            and parents.get(id(caller)) is owner
            and _app_signing_slot_read(node, caller, parents)
            and isinstance(call, ast.Call)
            and call.func is node
            and not _call_has_expansion(call)
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
        function = _enclosing_function(node, parents)
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
    target = assignment_target(statement)
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
        operation = parents.get(id(node))
        call = parents.get(id(operation))
        if (
            _enclosing_function(node, parents) is not function
            or not isinstance(operation, ast.Attribute)
            or not isinstance(operation.ctx, ast.Load)
            or operation.attr.startswith("_")
            or not isinstance(call, ast.Call)
            or call.func is not operation
        ):
            return None
        method = next(
            (
                n
                for n in selected[1].body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == operation.attr
            ),
            None,
        )
        fields = {
            row["name"]
            for row in rows
            if row["role"]
            in {"captured_key_field_transfer", "captured_verifier_property"}
        }
        if method is None or _app_object_method_exports_receiver(method, fields):
            return None
        if not _app_called_receiver_uses_closed(selected[1], method):
            return None
        projection = _app_request_verification_projection(
            index, path, function, call, selected[0], method, rows
        )
        if projection is not None:
            verified.append((call, projection["signature_value"], projection))
            continue
        fixed = _app_fixed_verification_request(
            index, path, function, call, selected[0], method, rows
        )
        if fixed is not None:
            verified.append((call, None, fixed))
            continue
        payload = _app_object_verified_payload(index, call, selected[0], method, rows)
        if payload is None or not isinstance(parents.get(id(call)), ast.Assert):
            return None
        verified.append((call, payload, None))
    return verified


def _app_fixed_verification_request(
    index, path, function, call, method_path, method, rows
):
    """Close additional negative verifier cases with wholly literal request data."""
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
    verified = _app_property_verification_operations(index, method_path, method, rows)
    if len(verified) != 1:
        return None
    condition = index["source"].parents[method_path].get(id(verified[0][0]))
    body = _app_process_body_read(method, parameters[1].arg)
    arguments = _app_signature_verification_arguments(verified[0][0])
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
        method, parameters[1].arg, arguments["timestamp"].id
    )
    signature_read = _app_process_header_read(
        method, parameters[1].arg, arguments["signature"].id
    )
    if (
        time_read is None
        or signature_read is None
        or not _app_request_verification_prefix_closed(
            index,
            method_path,
            method,
            parameters[1].arg,
            condition,
            (body["statement"], time_read["statement"], signature_read["statement"]),
        )
    ):
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
        "verification": verified[0][0],
    }


def _app_called_receiver_uses_closed(owner, method, active=()):
    """Close raw receiver exports in source-bound methods called by the selected method."""
    if id(method) in active or len(active) >= 8:
        return False
    args = [*method.args.posonlyargs, *method.args.args]
    if not args or binding_occurrences(method.body, args[0].arg):
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
        member = parents.get(id(node))
        if not isinstance(member, ast.Attribute) or member.attr.startswith("__"):
            return False
        definitions = binding_occurrences(owner.body, member.attr)
        if len(definitions) == 1 and isinstance(definitions[0], ast.FunctionDef):
            called = parents.get(id(member))
            target = definitions[0]
            property_read = (
                len(target.decorator_list) == 1
                and isinstance(target.decorator_list[0], ast.Name)
                and target.decorator_list[0].id == "property"
            )
            if not property_read and (
                not isinstance(called, ast.Call) or called.func is not member
            ):
                return False
            if target.decorator_list:
                if property_read:
                    if not _app_called_receiver_uses_closed(
                        owner, target, (*active, id(method))
                    ):
                        return False
                    continue
                if not (
                    len(target.decorator_list) == 1
                    and isinstance(target.decorator_list[0], ast.Name)
                    and target.decorator_list[0].id == "staticmethod"
                ):
                    return False
            elif not _app_called_receiver_uses_closed(
                owner, target, (*active, id(method))
            ):
                return False
    return True


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
        and _enclosing_function(node, parents) is method
        and (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)
        in terminals
    ]
    if method.decorator_list or _call_has_expansion(call):
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
    target = assignment_target(statement)
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
            _enclosing_function(node, parents) is function
            and isinstance(operation, ast.Attribute)
            and operation.attr == "is_valid"
            and isinstance(call, ast.Call)
            and call.func is operation
            and not _call_has_expansion(call)
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
    origin = _app_credential_source_row(
        index, path, assignment, "synthetic_signing_origin", secret
    )
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
        "modeled_api_assumption": "Unmodified PyJWT encode/decode are modeled signing/verification boundaries. Only captured test-owned key flow and closed signed-token consumers are established; no runtime or deployment guarantee.",
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
    if any(_enclosing_function(n, parents) is not owner for n in loads):
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
        or binding_occurrences(index["modules"][path].body, owner.name) != [owner]
        or binding_occurrences(owner.body, secret)
        != [
            assignment.targets[0]
            if isinstance(assignment, ast.Assign)
            else assignment.target
        ]
        or any(binding_occurrences(owner.body, name) for name in (*_HOOKS, "__init__"))
        or _fixture_reflective_uses(index, path, assignment, secret, all_sources=True)
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
        if _definition_effects_unknown(function) or not _app_signing_owner_closed(
            function, parents, secret
        ):
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
    aliases, mutations, star = _class_binding._presentation_provider_facts(
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
        function = _enclosing_function(node, index["source"].parents[other_path])
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
        and _enclosing_function(node, parents) is None
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
        and not binding_occurrences(function.body, args[0].arg)
        and _enclosing_function(node, parents) is function
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
        and _enclosing_function(node, parents) is function
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id == receiver
        and isinstance(node.ctx, ast.Load)
    )


def _app_signing_scope_edges(index, path, owner, loads):
    parents = index["source"].parents[path]
    operations, witnesses = {}, []
    for load in loads:
        if _enclosing_function(load, parents) is not owner:
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
    from .review_integrity import bind_source_call

    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(
        kw.arg is None for kw in call.keywords
    ):
        return None
    canonical = fixture._app_expression_name(index, path, call.func, owner)
    if canonical in {"jwt.encode", "jwt.decode"}:
        if fixture._jwt_bound_argument(
            call, 1, {"key"}
        ) is not actual or not _app_signing_provider_closed(index):
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
    selected = _app_signing_callee(index, path, owner, call)
    if selected is None:
        return None
    selected_path, method, receiver = selected
    try:
        bound = bind_source_call(call, method, receiver, apply_defaults=False)
    except (TypeError, ValueError):
        return None
    formal = next((name for name, value in bound.items() if value is actual), None)
    if formal is None or binding_occurrences(method.body, formal):
        return None
    parents = index["source"].parents[selected_path]
    uses = [
        n
        for n in ast.walk(method)
        if isinstance(n, ast.Name) and n.id == formal and isinstance(n.ctx, ast.Load)
    ]
    kinds, witnesses, payloads = set(), [], []
    for use in uses:
        operation = parents.get(id(use))
        if isinstance(operation, ast.keyword):
            operation = parents.get(id(operation))
        if (
            not isinstance(operation, ast.Call)
            or _enclosing_function(use, parents) is not method
        ):
            return None
        backend = fixture._app_expression_name(
            index, selected_path, operation.func, method
        )
        if backend not in {"jwt.encode", "jwt.decode"}:
            return None
        edge = _app_signing_key_edge(index, selected_path, method, operation, use)
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
    if len(kinds) != 1:
        return None
    if payloads and any(value is not payloads[0] for value in payloads):
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


def _app_signing_callee(index, path, owner, call):
    from . import mock_fixture_provenance as fixture

    if not isinstance(call.func, ast.Attribute):
        return None
    expression = call.func.value
    selected = fixture._app_source_symbol(index, path, expression, owner)
    instance = False
    if selected is None and isinstance(expression, ast.Name):
        assignment = fixture._app_local_assignment(owner, expression.id)
        if (
            assignment is None
            or not isinstance(assignment.value, ast.Call)
            or assignment.lineno >= call.lineno
        ):
            return None
        selected = fixture._app_source_symbol(index, path, assignment.value.func, owner)
        instance = True
    if selected is None or not isinstance(selected[1], ast.ClassDef):
        return None
    selected_path, cls = selected
    if (
        cls.bases
        or cls.keywords
        or any(
            binding_occurrences(cls.body, name)
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
        n
        for n in cls.body
        if isinstance(n, ast.FunctionDef) and n.name == call.func.attr
    ]
    if len(methods) != 1 or len(binding_occurrences(cls.body, call.func.attr)) != 1:
        return None
    method = methods[0]
    if method.decorator_list and not (
        len(method.decorator_list) == 1
        and isinstance(method.decorator_list[0], ast.Name)
        and method.decorator_list[0].id == "classmethod"
        and not binding_occurrences(index["modules"][selected_path].body, "classmethod")
    ):
        return None
    if _definition_effects_unknown(method, allowed_decorators=method.decorator_list):
        return None
    if not instance and not method.decorator_list:
        return None
    if not _app_signing_class_stable(index, selected, call.func.attr):
        return None
    if instance and any(
        isinstance(n, ast.Attribute)
        and isinstance(n.value, ast.Name)
        and n.value.id == expression.id
        and isinstance(n.ctx, (ast.Store, ast.Del))
        for n in ast.walk(owner)
    ):
        return None
    if fixture._app_has_dynamic_scope(
        index, selected_path, method, list(ast.walk(method))
    ):
        return None
    return selected_path, method, expression


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
        if any(binding_occurrences(cls.body, hook) for hook in _HOOKS) or any(
            not _method_stable(chain, name, source, absent=True)
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
                _enclosing_function(node, parents) is owner
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
    from . import mock_fixture_provenance as fixture

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
    spellings = {selected[1].name}
    imports = [
        n
        for tree in index["modules"].values()
        for n in ast.walk(tree)
        if isinstance(n, ast.ImportFrom)
    ]
    for _ in range(16):
        expanded = spellings | {
            alias.asname or alias.name
            for node in imports
            for alias in node.names
            if alias.name in spellings
        }
        if expanded == spellings:
            break
        spellings = expanded
    else:
        return False
    for path, tree in index["modules"].items():
        if not index["source"].validate(path):
            return False
        parents = index["source"].parents[path]
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and node.attr == member
                and isinstance(node.ctx, (ast.Store, ast.Del))
            ):
                cache[key] = False
                return False
            if not isinstance(node, (ast.Name, ast.Attribute)) or not isinstance(
                node.ctx, ast.Load
            ):
                continue
            if (node.id if isinstance(node, ast.Name) else node.attr) not in spellings:
                continue
            function = _enclosing_function(node, parents)
            resolved = fixture._app_source_symbol(index, path, node, function)
            if resolved is None:
                cache[key] = False
                return False
            if resolved != selected:
                continue
            if any(node is reference for reference in permitted_references):
                continue
            parent = parents.get(id(node))
            if isinstance(parent, ast.Call) and parent.func is node:
                continue
            if (
                isinstance(parent, ast.Attribute)
                and isinstance(parent.ctx, ast.Load)
                and isinstance(parents.get(id(parent)), ast.Call)
                and parents[id(parent)].func is parent
                and any(
                    isinstance(n, ast.FunctionDef) and n.name == parent.attr
                    for n in selected[1].body
                )
            ):
                continue
            cache[key] = False
            return False
    cache[key] = True
    return True


def _app_signing_provider_closed(index):
    from . import mock_fixture_provenance as fixture
    from .finite_capture import finite_provider_mutation_index
    from . import review_audits as audit

    key = ("signing-provider-closure", _app_source_role_epoch(index))
    cache = index.setdefault("profiles", {})
    if key in cache:
        return cache[key]
    if fixture._django_provider_root_shadowed(index["module_paths"], "jwt"):
        return False
    for path, tree in index["modules"].items():
        if not index["source"].validate(path):
            return False
        aliases = {}
        for statement in ast.walk(tree):
            for name, target in fixture._django_import_rows(statement, "") or ():
                if target == "jwt" or target.startswith("jwt."):
                    scope = _enclosing_function(
                        statement, index["source"].parents[path]
                    )
                    if (
                        scope is not None
                        or len(binding_occurrences(tree.body, name)) != 1
                    ):
                        # A scoped provider import needs scoped binding effects;
                        # never omit it from a module-wide closure.
                        cache[key] = False
                        return False
                    aliases[name] = target
        if not aliases:
            continue
        parents = index["source"].parents[path]
        nodes = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
                name = fixture._app_expression_name(
                    index, path, node.value, _enclosing_function(node, parents)
                )
                if name and (name == "jwt" or name.startswith("jwt.")):
                    cache[key] = False
                    return False
            if not _app_signing_exception_projection(index, path, node, parents):
                nodes.append(node)
        mutations = finite_provider_mutation_index(nodes, aliases, audit, parents)
        if any(
            provider == "jwt" or provider.startswith("jwt.")
            for provider, _ in mutations
        ):
            cache[key] = False
            return False
    cache[key] = True
    return True


def _app_source_role_epoch(index):
    """Scope reusable role facts to current immutable inputs and actual callees."""
    source = index["source"]
    return (
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
        tuple(
            (
                id(h),
                id(getattr(h, "__code__", h)),
                id(getattr(h, "__defaults__", None)),
                id(getattr(h, "__kwdefaults__", None)),
            )
            for h in module_fixture_helper_epoch()
        ),
    )


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
    owner = _enclosing_function(call, parents)
    return fixture._app_expression_name(
        index, path, call.func, owner
    ) == "pytest.raises" and _app_factory_provider_closed(index, path, "pytest.raises")


def _app_signing_results_closed(owner, operations, parents):
    """Verification must consume this test's signed token; keys never enter payloads.

    Decoded claims are not the signing capability. Their later use is outside
    this literal's key-role proof and does not establish payload privacy.
    """
    from . import mock_fixture_provenance as fixture

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
            return False
        tokens[name] = statement
    if not tokens:
        return False
    for call, kind, payload in operations.values():
        if kind == "decode" and (
            not isinstance(payload, ast.Name)
            or payload.id not in tokens
            or tokens[payload.id].lineno >= call.lineno
        ):
            return False
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

    source = index["source"]
    if not source.validate(path):
        return None
    parents = source.parents[path]
    function = parents.get(id(assignment))
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
        isinstance(n, (ast.Global, ast.Nonlocal)) for n in nodes
    ):
        return None
    if any(
        n is not function
        and isinstance(
            n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        )
        and any(
            isinstance(child, ast.Name) and child.id == secret for child in ast.walk(n)
        )
        for n in nodes
    ):
        return None
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
    if not creates:
        return None
    requests = _app_factory_client_requests(index, path, function)
    if not requests:
        return None
    permitted = {
        id(kw.value)
        for call, _ in creates
        for kw in call.keywords
        if isinstance(kw.value, ast.Name) and kw.value.id == secret
    }
    exercised = []
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
            permitted.update(id(n) for n in uses)
            exercised.append(call)
    if not exercised or min(call.lineno for call in exercised) <= min(
        call.lineno for call, _ in creates
    ):
        return None
    if not all(
        _app_factory_authority_uses_closed(index, path, function, call, exercised)
        for call, _ in creates
    ):
        return None
    assertions = [n for n in nodes if isinstance(n, ast.Assert)]
    for assertion in assertions:
        # Literal comparisons are harmless reads; arbitrary calls under assert
        # are not a safe credential consumer merely because they are assertions.
        if _app_factory_literal_assertion(assertion, secret):
            permitted.update(id(n) for n in ast.walk(assertion))
    loads = [
        n
        for n in nodes
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id == secret
    ]
    if not loads or any(id(n) not in permitted for n in loads):
        return None
    if not any(
        _app_factory_response_asserted(function, call, parents) for call in exercised
    ):
        return None
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
            any(not _immutable_default(arg) for arg in decorator.args)
            or any(
                kw.arg is None or not _immutable_default(kw.value)
                for kw in decorator.keywords
            )
        ):
            return False
    return True


def _app_factory_provider(index, path, function, call):
    from . import mock_fixture_provenance as fixture

    if call.args or any(kw.arg is None for kw in call.keywords):
        return None
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
    imports = _app_crypto_provider_imports(index)
    if imports is None or not _app_factory_classes_closed(
        index, selected, chain, imports, model[0]
    ):
        return None
    if not all(
        fixture._django_model_signal_registration_clear(index, p)
        for p in index["modules"]
    ):
        return None
    for provider_path in (path, owner_path):
        if not _app_factory_provider_closed(
            index, provider_path, "factory.django.DjangoModelFactory"
        ):
            return None
    return selected


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
        _class_binding._source_module(path) + "." + name
        for path, name, _ in selected_chain
    }

    def capture_guard(snapshot, aliases, owners, filtered, fields, consumers):
        filtered.setdefault(selected[0], set()).add(id(model_assignment))
        return _class_binding._has_opaque_owner_capture(
            snapshot, aliases, owners, filtered, fields, consumers
        )

    model = _class_binding.constructor_provider_model(
        roots, source, imports, _class_binding._source_aliases, capture_guard
    )
    return model is not None and _class_binding._captured_mutations_inert(
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
            if statement.bases or statement.decorator_list or statement.keywords:
                return False
            for item in statement.body:
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
                elif not _immutable_default(item.value):
                    return False
            continue
        if (
            not isinstance(statement, ast.Assign)
            or len(statement.targets) != 1
            or not isinstance(statement.targets[0], ast.Name)
        ):
            return False
        if statement.targets[0].id.startswith("_"):
            return False
        if _immutable_default(statement.value):
            continue
        value = statement.value
        if (
            not isinstance(value, ast.Call)
            or not all(_immutable_default(arg) for arg in value.args)
            or not all(
                kw.arg is not None and _immutable_default(kw.value)
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
        if canonical not in providers:
            return False
    return True


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
        function = _enclosing_function(node, parents)
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
        if (
            not isinstance(statement, ast.Assign)
            or len(statement.targets) != 1
            or not isinstance(statement.targets[0], ast.Name)
        ):
            continue
        call = statement.value
        if not isinstance(call, ast.Call) or call.args or call.keywords:
            continue
        if (
            fixture._app_expression_name(index, path, call.func, function)
            != "rest_framework.test.APIClient"
        ):
            continue
        name = statement.targets[0].id
        if fixture._app_local_assignment(function, name) is not statement:
            continue
        if not _app_factory_provider_closed(
            index, path, "rest_framework.test.APIClient"
        ):
            continue
        requests = fixture._app_client_requests(function, [name])
        if not requests or any(
            not call.args
            or not isinstance(call.args[0], ast.Constant)
            or not isinstance(call.args[0].value, str)
            or not call.args[0].value.startswith("/")
            or call.args[0].value.startswith("//")
            for call in requests
        ):
            continue
        parents = index["source"].parents[path]
        if any(
            isinstance(n, ast.Attribute)
            and isinstance(n.value, ast.Name)
            and n.value.id == name
            and isinstance(n.ctx, (ast.Store, ast.Del))
            for n in ast.walk(function)
        ):
            continue
        loads = [
            n
            for n in ast.walk(function)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id == name
        ]
        if any(
            not isinstance(parents.get(id(n)), ast.Attribute)
            or not any(parents[id(n)] is call.func for call in requests)
            for n in loads
        ):
            continue
        clients.extend(requests)
    if _app_factory_provider_closed(index, path, "rest_framework.test.APIClient"):
        for call in ast.walk(function):
            if (
                not isinstance(call, ast.Call)
                or not isinstance(call.func, ast.Attribute)
                or call.func.attr not in {"post", "put", "patch"}
            ):
                continue
            receiver = call.func.value
            if not isinstance(receiver, ast.Call) or receiver.args or receiver.keywords:
                continue
            if (
                fixture._app_expression_name(index, path, receiver.func, function)
                != "rest_framework.test.APIClient"
            ):
                continue
            if (
                call.args
                and isinstance(call.args[0], ast.Constant)
                and isinstance(call.args[0].value, str)
                and call.args[0].value.startswith("/")
                and not call.args[0].value.startswith("//")
            ):
                clients.append(call)
    return clients


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
    helpers = module_fixture_helper_epoch()
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
    if len(owners) != 1 or binding_occurrences(tree.body, name) != owners:
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
        or any(_definition_effects_unknown(method) for method in methods.values())
        or not _app_crypto_fixture_constructor_inert(index, pair)
    ):
        return None
    imports = _app_crypto_provider_imports(index)
    if imports is None or not _class_binding.constructor_provider_bindings_inert(
        [(path, owner.name, owner)], source, imports
    ):
        return None
    if _class_binding._captured_terminal_provider_mutation(
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
                aliases = {
                    alias.asname or alias.name: alias for alias in statement.names
                }
                for bound, target in rows:
                    alias = aliases.get(bound)
                    module_path, _ = fixture._django_mod(
                        index, target.rpartition(".")[0]
                    )
                    if alias is not None and module_path is not None:
                        scoped[bound] = (module_path, alias.name)
            elif isinstance(statement, ast.Import):
                for bound, target in rows:
                    module_path, _ = fixture._django_mod(index, target)
                    if module_path is not None:
                        scoped[bound] = (module_path, None)
        imports[path] = scoped
    return imports


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
        and _immutable_default(call.args[0])
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
        if _definition_effects_unknown(statement) or (
            statement.name.startswith("__") and statement.name != "__init__"
        ):
            return None
    methods = {}
    for name in names:
        selected = effective_method([(path, owner.name, owner)], name)
        if (
            selected is None
            or selected[0] != path
            or binding_occurrences(owner.body, name) != [selected[1]]
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
        and not _definition_effects_unknown(method)
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
        or not _class_binding.instance_receiver(
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
        or not _class_binding.instance_receiver(
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
        or not _class_binding.instance_receiver(
            derive.func.value, method, owner, index["source"], path
        )
        or not _immutable_default(derive.args[0])
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
    aliases = fixture._app_consumer_aliases(index, path, function, secret)
    if aliases is None:
        return None
    candidates, assignments = aliases
    roots = [
        ("transform_payload_input", pair["encrypt"].args[0]),
        ("local_roundtrip_comparison", pair["assertion"].test.comparators[0]),
    ]
    used = fixture._app_consumer_reached_assignments(
        candidates, assignments, secret, roots
    )
    if used is None:
        return None
    closure = fixture._app_consumer_allowed_loads(
        list(ast.walk(function)), function, secret, candidates, used, roots
    )
    if closure is None:
        return None
    loads, roles = closure
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
