"""Bounded source-only identity-effect summaries for selected object roots."""

import ast

from collections.abc import Callable, Mapping

from dataclasses import dataclass, field as _dataclass_field
from .credential_role_scope_bindings import resolve_class

from .credential_role_scope_bindings import binding_occurrences

from . import credential_role_scope_bindings as _class_binding

from . import credential_role_identity_effects as _identity_effects

from . import credential_role_scope_bindings as _scope_bindings

from .credential_role_scope_bindings import effective_method

from .credential_role_sources import SourceSnapshotIndex


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


@dataclass
class _Effects:
    class_writes: set[str] = _dataclass_field(default_factory=set)
    escapes: set[str] = _dataclass_field(default_factory=set)
    unknowns: set[str] = _dataclass_field(default_factory=set)
    field_writes: set[str] = _dataclass_field(default_factory=set)

    def merge(self, other):
        """Merge class writes, escapes, unknowns, and field writes from another effect accumulator."""
        for name in ("class_writes", "escapes", "unknowns", "field_writes"):
            getattr(self, name).update(getattr(other, name))

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
            status, *(tuple(sorted(getattr(self, name))) for name in fields)
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
        if isinstance(node.func, ast.Attribute) and node.func.attr == "__class__":
            if contains_tracked(
                identity_value(node.func.value, aliases, strict_calls=strict_calls)
            ):
                return _Value(unknown=True)
        if strict_calls:
            return _Value(content_unknown=True)
    return _unknown_expression(node, aliases, strict_calls=strict_calls)


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
    scopes = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
    for node in ast.walk(function):
        if node is function or not isinstance(node, scopes):
            continue
        parent = index.parents[path].get(id(node))
        while parent is not None and parent is not function:
            parent = index.parents[path].get(id(parent))
        if parent is not function:
            continue
        if strict_calls and _definition_effects_unknown(node):
            effects.unknowns.add("unmodeled nested definition-time effects")
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in tracked:
                captured.update(tracked_roots(aliases[child.id]))
                if strict_calls and _has_unknown_content(aliases[child.id]):
                    effects.unknowns.add(
                        "nested scope captures unresolved tracked value"
                    )
    return captured


def record_write(target, value, aliases, effects, *, strict_calls=False):
    """Record attribute or container writes, including escaped roots and unresolved stored values where strict analysis requires it."""
    if isinstance(target, ast.Attribute):
        return _record_attribute_write(
            target, value, aliases, effects, strict_calls=strict_calls
        )
    elif isinstance(target, ast.Subscript):
        base = identity_value(target.value, aliases, strict_calls=strict_calls)
        if base.roots or contains_tracked(base) or base.inert_kind in {"dict", "list"}:
            effects.unknowns.add("write through tracked container")
        if strict_calls and _has_unknown_content(value):
            effects.unknowns.add("field stores unresolved tracked value")
        effects.escapes.update(tracked_roots(value))


def record_escape(node, aliases, effects, reason, *, strict_calls=False):
    """Record escaped roots and mark the supplied effect unknown when the escaping value has unresolved content."""
    value = identity_value(node, aliases, strict_calls=strict_calls)
    effects.escapes.update(tracked_roots(value))
    if value.unknown or (strict_calls and _has_unknown_content(value)):
        effects.unknowns.add(reason + " contains unresolved tracked value")


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


def _record_attribute_write(target, value, aliases, effects, *, strict_calls=False):
    base = identity_value(target.value, aliases, strict_calls=strict_calls)
    if base.roots:
        if any((root, target.attr) in aliases for root in base.roots):
            effects.unknowns.add("projected field identity overwritten")
        if target.attr == "__class__":
            effects.class_writes.update(base.roots)
        else:
            effects.field_writes.update(f"{root}.{target.attr}" for root in base.roots)
        effects.escapes.update(tracked_roots(value))
        if value.unknown:
            effects.unknowns.add("field stores unresolved tracked value")
    else:
        effects.escapes.update(tracked_roots(value))
        if strict_calls and _has_unknown_content(value):
            effects.unknowns.add("field stores unresolved tracked value")
        if contains_tracked(identity_value(target, aliases, strict_calls=strict_calls)):
            effects.unknowns.add("write through tracked value")


def record_opaque_call(call, aliases, involved, out, *, strict_calls=False):
    """Record tracked roots as escaping when an opaque call receives them; otherwise mark the call as unresolved."""
    if call_argument_roots(call, aliases, strict_calls=strict_calls):
        out.escapes.update(involved)
    else:
        out.unknowns.add("unresolved method call on tracked object")


def strict_read_effects(node, aliases, parents, out):
    """Unknown names and properties may hide behavior without a Call node."""
    if not isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)) or not isinstance(
        node.ctx, ast.Load
    ):
        return
    parent = parents.get(id(node))
    if isinstance(parent, ast.Call) and parent.func is node:
        return
    value = identity_value(node, aliases, strict_calls=True)
    if value.unknown or not (
        value.roots
        or value.class_roots
        or value.inert_kind
        or value.items
        or value.content_unknown
    ):
        out.unknowns.add("unresolved value in strict identity summary")


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
        literal = (
            _source_literal(root, index)
            if isinstance(root, SourceFieldLiteral)
            else None
        )
        if not (
            isinstance(key, tuple)
            and len(key) == 2
            and all(isinstance(item, str) and item for item in key)
            and (literal is not None or isinstance(root, str) and root)
            and key[1].isidentifier()
            and not key[1].startswith("__")
        ):
            return None
        result[key] = (
            literal if literal is not None else _Value(roots=frozenset({root}))
        )
    return result


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
    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(
        keyword.arg is None for keyword in call.keywords
    ):
        out.unknowns.add("expanded call arguments are not an exact binding")
        return None
    if not isinstance(resolved, ResolvedIdentityCall):
        out.unknowns.add("invalid exact call binding")
        return None
    params = {
        arg.arg
        for arg in [
            *resolved.function.args.posonlyargs,
            *resolved.function.args.args,
            *resolved.function.args.kwonlyargs,
        ]
    }
    actuals = [*call.args, *(kw.value for kw in call.keywords)]
    if isinstance(call.func, ast.Attribute):
        actuals.append(call.func.value)
    if not maps_each_actual_once(actuals, resolved.arguments):
        out.unknowns.add("exact call mapping must cover each actual once")
        return None
    mapped = {}
    for formal, expr in resolved.arguments.items():
        if formal not in params or not any(expr is actual for actual in actuals):
            out.unknowns.add("call mapping is not an exact parameter binding")
            return
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
        else:
            mapped[formal] = value
    if set().union(*(tracked_roots(value) for value in mapped.values())) != involved:
        out.unknowns.add("exact call mapping omits a tracked root")
        return None
    return _with_inert_defaults(
        resolved.function, mapped, out, strict_calls=strict_calls
    )


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
    return (
        isinstance(node, ast.Tuple)
        and len(node.elts) <= 64
        and all(_immutable_default(item, depth + 1) for item in node.elts)
    )


def summarize_identity_call(
    call, path, index, roots, *, resolve_call, field_roots=None
):
    """Summarize one captured call under caller-proved current heap/dispatch facts.

    Allocation, ownership, descriptors, prior mutations, and binding stability
    are separate caller obligations. This is not fixture admission or execution.
    """
    pass
    pass

    out = _Effects()
    if (
        not index.validate(path)
        or id(call) not in index.parents[path]
        or not isinstance(call, ast.Call)
    ):
        out.unknowns.add("call is not a validated captured expression")
        return out.freeze()
    analyzer = _Analyzer(index, resolve_call, 4, 512, field_roots, True)
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
    """Return nodes owned by the function itself while excluding nested function, lambda, and class scopes."""
    parents, scopes, result = (
        index.parents[path],
        (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef),
        [],
    )
    for node in ast.walk(function):
        parent, nested = parents.get(id(node)), False
        while parent is not None and parent is not function:
            if isinstance(parent, scopes):
                nested = True
                break
            parent = parents.get(id(parent))
        if not nested:
            result.append(node)
    return result


def exported_names(nodes):
    """Names stored outside the owning function's already-separated scope."""
    return {
        name
        for node in nodes
        if isinstance(node, (ast.Global, ast.Nonlocal))
        for name in node.names
    }


def _definition_effects_unknown(node):
    if isinstance(node, ast.ClassDef):
        return True
    args = node.args
    params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    params.extend(arg for arg in (args.vararg, args.kwarg) if arg)
    return bool(
        getattr(node, "decorator_list", [])
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
    parents = index.parents[path]
    function = _enclosing_function(receiver, parents)
    if function is None:
        return None
    constructor = _local_constructor(receiver, function, parents)
    if constructor is None:
        return None
    class_name = _root_name(constructor.func)
    if class_name is None:
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
    from .credential_role_bindings import class_chain

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
                "summarize_identity_effect",
                "effective_method",
                "binding_occurrences",
            )
        ),
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
):
    """Summarize captured ASTs without executing target code.

    Callers prove exact bindings, branches, descriptors, allocation and current
    field ownership; initial field projections are not admission evidence.
    Unknown protocols, heap escapes and overwritten projections fail closed.
    Strict mode also rejects unresolved calls without explicit root arguments.
    """
    return (
        _Analyzer(
            index, resolve_call, max_depth, state_budget, field_roots, strict_calls
        )
        .run(function, path, dict(roots), 0, frozenset())
        .freeze()
    )


class _Analyzer:
    def __init__(self, index, resolver, depth_limit, budget, field_roots, strict_calls):
        self.index, self.resolver = index, resolver
        self.depth_limit, self.budget, self.states = depth_limit, budget, 0
        self.fields = identity_fields(field_roots, index)
        self.strict_calls = strict_calls

    def run(self, function, path, roots, depth, active):
        """Analyze a captured function within depth and state budgets; return explicit unknown effects when validation is incomplete."""
        out = _Effects()
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
        aliases = self._aliases(function, roots, nodes, out)
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
        for node in nodes:
            if self.strict_calls:
                strict_read_effects(node, aliases, self.index.parents[path], out)
                strict_protocol_effects(node, aliases, self.index.parents[path], out)
            record_implicit_effects(
                node, function, aliases, out, strict_calls=self.strict_calls
            )
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                self._assignment(node, aliases, function, out, exported)
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
                    )
            elif isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)):
                record_escape(
                    getattr(node, "value", None),
                    aliases,
                    out,
                    "return/yield",
                    strict_calls=self.strict_calls,
                )
            elif isinstance(node, ast.Call):
                self._call(node, path, aliases, depth, active, out)

    def _aliases(self, function, roots, nodes, out):
        args = function.args
        params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
        params += [item for item in (args.vararg, args.kwarg) if item]
        env = {
            name: root if isinstance(root, _Value) else _Value(frozenset({root}))
            for name, root in roots.items()
        }
        env.update(self.fields)
        for param in params:
            if param.arg in roots and binding_occurrences(function.body, param.arg):
                out.unknowns.add(f"root parameter rebound: {param.arg}")
        assigns = [
            n
            for n in nodes
            if isinstance(n, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
        ]
        for _ in range(min(len(assigns) + 1, 32)):
            changed = False
            for node in assigns:
                target = assignment_target(node)
                if not isinstance(target, ast.Name) or binding_occurrences(
                    function.body, target.id
                ) != [target]:
                    continue
                value = identity_value(
                    getattr(node, "value", None),
                    env,
                    strict_calls=self.strict_calls,
                )
                if (
                    contains_tracked(value) or value.inert_kind is not None
                ) and env.get(target.id) != value:
                    env[target.id], changed = value, True
            if not changed:
                break
        else:
            out.unknowns.add("alias fixed-point limit")
        return env

    def _assignment(self, node, aliases, function, out, exported):
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
                )
            if contains_tracked(value) and binding_occurrences(
                function.body, target.id
            ) != [target]:
                out.unknowns.add(f"ambiguous alias binding: {target.id}")
            else:
                if value.items:
                    out.escapes.update(tracked_roots(value))
                if value.unknown:
                    out.unknowns.add("alias receives unresolved tracked expression")
        else:
            record_write(target, value, aliases, out, strict_calls=self.strict_calls)

    def _call(self, call, path, aliases, depth, active, out):
        if literal_dict_update(call, aliases, strict_calls=self.strict_calls):
            return
        if call_has_unknown_value(call, aliases, strict_calls=self.strict_calls):
            out.unknowns.add("call receives an unresolved tracked value")
            return
        involved = call_tracked_roots(call, aliases, strict_calls=self.strict_calls)
        if not involved and not self.strict_calls:
            return
        resolved = self.resolver(call, path) if self.resolver else None
        if resolved is None:
            record_opaque_call(
                call, aliases, involved, out, strict_calls=self.strict_calls
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
