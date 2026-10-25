"""Source-bound pickle provider models and reconstruction analysis."""

import ast
import hashlib
from dataclasses import dataclass

_PROVIDER_ASSUMPTIONS = (
    "CANONICAL_CPYTHON_PICKLE",
    "IMMUTABLE_PROVIDER_ARTIFACTS",
    "NO_RUNTIME_MONKEY_PATCHING",
    "TRUSTED_IMPORT_INITIALIZATION",
)
_PROVIDER_MODEL = {
    "id": "builtin-exception-record-v1",
    "version": 1,
    "constructor": "single-inheritance Exception record; closed builtin arguments and state",
    "reconstruction": "canonical BaseException reduction; no custom reducer or state hooks",
    "scope": "conditional trusted initialization; source-visible violations reject",
    "annotations": "canonical typing.TYPE_CHECKING is False; kind-checked builtin types, None aliases, generic aliases and unions; inert strings only outside union operands",
}
_PROVIDER_MODEL_V2 = {
    "id": "builtin-exception-record-v2",
    "version": 2,
    "constructor": "single-inheritance Exception reconstruction; bounded delegated constructors and closed values",
    "reconstruction": "canonical BaseException args plus separately validated instance-state BUILD",
    "scope": "conditional trusted initialized provider; source-visible lookup mutations reject",
    "annotations": "historical definition annotations are not re-evaluated after validated cached initialization",
    "values": "UTF-8 rendered scalars <=16384 bytes; integers <=4096 bits; tuple/state nodes <=512",
}
_PROVIDER_MODEL_V3 = {
    "id": "typed-pickle-reconstruction-v3",
    "version": 3,
    "constructor": "source-bound single-inheritance Exception constructor with exact IntEnum member leaves",
    "reconstruction": "BaseException args followed by default instance-dict BUILD; no custom reducer or state hooks",
    "scope": "conditional initialized immutable provider; exact dump/load frame and modeled methods; captured writes checked globally; only potential escapes in unexecuted function bodies deferred",
    "values": "None, bool, bounded int, finite float, str, bytes, tuple, list, dict, exact source-bound IntEnum members",
    "limits": "depth <=8; nodes <=512; scalar UTF-8/bytes and field names <=16384; int <=4096 bits; dict keys exact immutable builtins",
    "display": "optional exact typing.cast identity recipe for direct self.args[1] return",
}
_PROVIDER_MODEL_V4 = {
    "id": "typed-pickle-reconstruction-v4",
    "version": 4,
    "constructor": "source-regenerated typed object graph with exact builtin and source-instance nodes",
    "reconstruction": "protocol 0/1 copyreg reconstruction and protocol 2-5 NEWOBJ/container insertion/state recipes",
    "scope": "bounded source-bound instances, list/dict subclasses, OrderedDict and paired closed state hooks",
    "graph": "identity-preserving node/ref table; mutable-shell memoization; immutable tuple cycles abstain",
    "limits": "depth <=8; nodes <=512; classes <=16; artifacts <=64; scalar UTF-8/bytes <=16384; int <=4096 bits",
}
_PROVIDER_MODELS = {
    (_PROVIDER_MODEL["id"], 1): _PROVIDER_MODEL,
    (_PROVIDER_MODEL_V2["id"], 2): _PROVIDER_MODEL_V2,
    (_PROVIDER_MODEL_V3["id"], 3): _PROVIDER_MODEL_V3,
    (_PROVIDER_MODEL_V4["id"], 4): _PROVIDER_MODEL_V4,
}


def _cache_member_callables(member):
    if isinstance(member, (classmethod, staticmethod)):
        return (member.__func__,)
    if isinstance(member, property):
        return tuple(
            accessor
            for accessor in (member.fget, member.fset, member.fdel)
            if accessor is not None
        )
    return (member,)


def cache_helpers():
    """Return model-owned callables and the executable members of its classes."""
    owned = tuple(globals().get(name) for name in _CACHE_HELPER_NAMES)
    return owned + tuple(
        method
        for owner in owned
        if isinstance(owner, type)
        for member in vars(owner).values()
        for method in _cache_member_callables(member)
        if callable(method)
    )


@dataclass(frozen=True)
class _ProviderV3EnumMember:
    path: str
    name: str
    class_ast_sha256: str
    member: str
    value: int


@dataclass
class _ProviderV4SourceObject:
    path: str
    name: str
    class_ast_sha256: str
    base_kind: str
    base_items: object
    state: dict
    slots: tuple
    state_hook_uses: tuple
    slot_state: dict
    serialized_state: object = None
    state_recipe: str = "DEFAULT_INSTANCE_STATE"
    reduce_recipe: str = "CANONICAL_OBJECT_REDUCE"
    mro: tuple = ()


@dataclass(frozen=True)
class _ProviderV4Iterator:
    values: tuple


@dataclass(frozen=True)
class _ProviderV4OrderedDict:
    items: tuple


@dataclass(frozen=True)
class _ProviderV4AbstractScalar:
    kind: str
    source_path: str
    span: tuple
    ast_sha256: str


class _ProviderV4Return(Exception):
    def __init__(self, value):
        self.value = value


class _ProviderV4Graph:
    """Encode exact scanner-owned values while preserving mutable identity.

    Input objects are created only by the source interpreter below. Public API
    consumers cannot submit object/state graphs as evidence authority.
    """

    def __init__(self, interpreter=None):
        self.nodes = []
        self.memo = {}
        self.tuple_stack = set()
        self.open_nodes = set()
        self.remaining = 512
        self.interpreter = interpreter

    def edge(self, value, depth=0):
        """Encode a bounded object-graph edge while preserving repeated references and rejecting unsupported values."""
        self.remaining -= 1
        if self.remaining < 0 or depth > 8:
            raise ValueError("typed graph budget exceeded")
        scalar = _provider_v4_scalar(value)
        if scalar is not None:
            return scalar
        identity = id(value)
        if identity in self.tuple_stack:
            raise ValueError("cycle through immutable tuple is unsupported")
        if identity in self.memo:
            if identity in self.open_nodes and self.tuple_stack:
                raise ValueError("cycle through immutable tuple is unsupported")
            return {"tag": "ref", "id": self.memo[identity]}
        index = len(self.nodes)
        self.memo[identity] = index
        node = {"id": index}
        self.nodes.append(node)
        self.open_nodes.add(identity)
        try:
            self._contents(node, value, depth)
        finally:
            self.open_nodes.remove(identity)
        return {"tag": "ref", "id": index}

    def _contents(self, node, value, depth):
        kind = type(value)
        if kind in {tuple, list}:
            self._sequence(node, value, depth)
        elif kind is dict:
            node.update(tag="dict", items=self._mapping(value.items(), depth))
        elif kind is _ProviderV4OrderedDict:
            node.update(tag="ordered_dict", items=self._mapping(value.items, depth))
        elif kind is _ProviderV4SourceObject:
            self._instance(node, value, depth)
        else:
            raise ValueError("unmodeled graph value")

    def _sequence(self, node, value, depth):
        immutable = type(value) is tuple
        if immutable:
            self.tuple_stack.add(id(value))
        try:
            node.update(
                tag="tuple" if immutable else "list",
                items=[self.edge(item, depth + 1) for item in value],
            )
        finally:
            self.tuple_stack.discard(id(value))

    def _mapping(self, items, depth):
        output = []
        for key, value in items:
            if type(key) not in {str, bytes, int, float, bool, type(None)}:
                raise ValueError("non-builtin mapping key")
            output.append([self.edge(key, depth + 1), self.edge(value, depth + 1)])
        return output

    def _instance(self, node, value, depth):
        if self.interpreter is None:
            raise ValueError("source instances require a source interpreter")
        self.interpreter._complete_object_state(
            value, self.interpreter.classes[value.path, value.name]
        )
        node.update(
            tag="source_instance",
            type={
                "path": value.path,
                "name": value.name,
                "class_ast_sha256": value.class_ast_sha256,
            },
            base_kind=value.base_kind,
            base_items=self.edge(value.base_items, depth + 1),
            state=self.edge(
                value.serialized_state
                if value.serialized_state is not None
                else value.state,
                depth + 1,
            ),
            slots=list(value.slots),
            state_hook_uses=list(value.state_hook_uses),
            state_recipe=value.state_recipe,
            reduce_recipe=value.reduce_recipe,
            mro=[
                {"path": path, "name": name, "class_ast_sha256": digest}
                for path, name, digest in value.mro
            ],
            protocol_recipes=_provider_v4_protocol_recipes(
                value.base_kind, value.state_recipe, value.reduce_recipe
            ),
        )


def _provider_v4_scalar(value):
    import math

    kind = type(value)
    if kind not in {str, bytes, int, float, bool, type(None)}:
        return None
    if kind is str and _provider_v2_text_size(value) is None:
        raise ValueError("string exceeds graph bound")
    if (
        kind is bytes
        and len(value) > 16_384
        or kind is int
        and value.bit_length() > 4_096
    ):
        raise ValueError("scalar exceeds graph bound")
    if kind is float and not math.isfinite(value):
        raise ValueError("nonfinite float is not a canonical graph scalar")
    return {
        "tag": "scalar",
        "kind": kind.__name__,
        "value": value.hex() if kind is bytes else value,
    }


def _provider_v4_protocol_recipes(
    base_kind,
    state_recipe="DEFAULT_DICT_BUILD",
    reduce_recipe="CANONICAL_OBJECT_REDUCE",
):
    if base_kind not in {"object", "list", "dict", "ordered_dict"}:
        raise ValueError("unsupported allocation base")
    old = (
        "COPYREG_RECONSTRUCTOR" if base_kind != "ordered_dict" else "ORDEREDDICT_REDUCE"
    )
    new = "OBJECT_NEWOBJ" if base_kind != "ordered_dict" else "ORDEREDDICT_REDUCE"
    insertion = {
        "object": "NONE",
        "list": "APPEND_OR_EXTEND",
        "dict": "SETITEM",
        "ordered_dict": "ORDERED_SETITEM",
    }[base_kind]
    return [
        {
            "protocol": protocol,
            "allocation": old if protocol < 2 else new,
            "insertion": "BASE_VALUE_IN_RECONSTRUCTOR"
            if protocol < 2 and base_kind in {"list", "dict"}
            else insertion,
            "reduce": reduce_recipe,
            "state": state_recipe,
        }
        for protocol in range(6)
    ]


class _ProviderV4SourceInterpreter:
    """Evaluate a closed source-operation grammar, never Python target code."""

    def __init__(self, contract, sources):
        self.contract = contract
        self.sources = sources
        self.trees = _provider_source_trees(contract, sources)
        if self.trees is None:
            raise ValueError("provider source closure is incomplete")
        self.classes = _provider_v4_source_classes(contract, self.trees)
        self.remaining = 512
        self.stack = []
        self.method_uses = []
        self.parents = {
            path: {
                child: node
                for node in ast.walk(tree)
                for child in ast.iter_child_nodes(node)
            }
            for path, tree in self.trees.items()
        }
        self.yield_frames = []

    def value(self, node, env, path):
        """Interpret one captured expression using the closed source environment and explicit modeled operations."""
        self.remaining -= 1
        if self.remaining < 0 or len(self.stack) > 8:
            raise ValueError("source interpreter budget exhausted")
        if isinstance(node, ast.Name) and node.id in env:
            return env[node.id]
        if isinstance(node, ast.Constant):
            _provider_v4_scalar(node.value)
            return node.value
        if isinstance(node, (ast.List, ast.Tuple, ast.Dict)):
            return self.collection(node, env, path)
        if isinstance(node, ast.Attribute):
            return self.attribute(node, env, path)
        if isinstance(node, ast.Call):
            return self.call(node, env, path)
        if isinstance(node, ast.Subscript):
            return self.subscript(node, env, path)
        raise ValueError("unsupported source expression")

    def attribute(self, node, env, path):
        """Resolve a captured field or method while rejecting unknown descriptor and provider behavior."""
        receiver = self.value(node.value, env, path)
        if type(receiver) is _ProviderV4SourceObject:
            if node.attr in receiver.state:
                return receiver.state[node.attr]
            if node.attr in receiver.slots and node.attr in receiver.slot_state:
                return receiver.slot_state[node.attr]
            model = self.classes[receiver.path, receiver.name]
            if node.attr in model.get("class_values", {}):
                return model["class_values"][node.attr]
        raise ValueError("unresolved source attribute")

    def collection(self, node, env, path):
        """Build an exact bounded builtin collection from source expressions without executing target code."""
        if isinstance(node, ast.Dict):
            result = {}
            for key, value in zip(node.keys, node.values):
                if key is None:
                    raise ValueError("mapping unpacking is unresolved")
                actual = self.value(key, env, path)
                _provider_v4_mapping_key(actual)
                result[actual] = self.value(value, env, path)
            return result
        values = [self.value(item, env, path) for item in node.elts]
        return tuple(values) if isinstance(node, ast.Tuple) else values

    def subscript(self, node, env, path):
        """Read a modeled collection element only when both the receiver and index are closed."""
        receiver = self.value(node.value, env, path)
        if type(receiver) not in {list, tuple, dict, str, bytes}:
            raise ValueError("unknown item-access protocol")
        if isinstance(node.slice, ast.Slice):
            if any(
                value is not None
                for value in (node.slice.lower, node.slice.upper, node.slice.step)
            ):
                raise ValueError("only full builtin slices are modeled")
            return receiver[:]
        key = self.value(node.slice, env, path)
        _provider_v4_mapping_key(key)
        return receiver[key]

    def call(self, call, env, path):
        """Dispatch a source call to an explicitly supported builtin or captured class operation."""
        if any(item.arg is None for item in call.keywords) or any(
            isinstance(item, ast.Starred) for item in call.args
        ):
            raise ValueError("expanded source calls are unresolved")
        args = [self.value(node, env, path) for node in call.args]
        kwargs = {item.arg: self.value(item.value, env, path) for item in call.keywords}
        if _provider_v4_super_call_shape(call):
            return self.super_method(call.func.attr, args, kwargs, env, path)
        if isinstance(call.func, ast.Name):
            if call.func.id in env:
                raise ValueError("local callable shadows a source provider or builtin")
            symbol = _provider_v4_resolve_symbol(path, call.func.id, self.trees)
            if symbol in self.classes:
                return self.construct(symbol, call, args, kwargs)
            return _provider_v4_builtin_call(symbol, args, kwargs)
        if isinstance(call.func, ast.Attribute):
            receiver = self.value(call.func.value, env, path)
            return self.method(receiver, call.func.attr, call, args, kwargs)
        raise ValueError("indirect source call")

    def super_method(self, name, args, kwargs, env, path):
        """Resolve a modeled super call using the captured class hierarchy and lexical owner."""
        from .credential_role_constructor_provider import binding_occurrences

        if not self.stack or binding_occurrences(self.trees[path].body, "super"):
            raise ValueError("super provider is unresolved")
        model = self.classes[self.stack[-1][:2]]
        method = model["methods"][self.stack[-1][2]]
        if any(
            item.arg == "super" for item in [*method.args.args, *method.args.kwonlyargs]
        ) or binding_occurrences(method.body, "super"):
            raise ValueError("super provider is shadowed")
        receiver = env[method.args.args[0].arg]
        if kwargs:
            raise ValueError("unmodeled base method keywords")
        target, base_kind = self.source_super_target(receiver, model, name)
        if target is not None:
            return self.run_method(
                receiver, target, target["own_methods"][name], None, args, kwargs
            )
        model = {**model, "base": base_kind}
        if model["base"] == "dict":
            return self.dict_base_method(receiver, name, args)
        if name != "__init__":
            raise ValueError("unmodeled base method effect")
        if model["base"] == "object":
            if args:
                raise ValueError("object initializer rejects arguments")
            return None
        values = self.closed_base_values(args, "list")
        receiver.base_items[:] = values
        return None

    def source_super_target(self, receiver, owner, name):
        """Find the next captured implementation in the source-bound method resolution order."""
        dynamic = self.classes[receiver.path, receiver.name]
        order = dynamic["mro_order"]
        identity = owner["path"], owner["class"].name
        offset = order.index(identity) + 1
        for item in order[offset:]:
            if isinstance(item, tuple):
                candidate = self.classes[item]
                if name in candidate["own_methods"]:
                    return candidate, None
            elif (
                name == "__init__"
                or item == "dict"
                and name in {"items", "clear", "update", "setdefault", "__setitem__"}
            ):
                return None, item
        raise ValueError("unmodeled super lookup target")

    def closed_base_values(self, args, kind):
        """Validate builtin container constructor inputs before adding them to the object graph."""
        if len(args) > 1 or args and type(args[0]) not in {tuple, list, dict}:
            raise ValueError("unknown base container input")
        values = {"list": list, "dict": dict}[kind](*args)
        if kind == "dict":
            for key in values:
                _provider_v4_mapping_key(key)
        return values

    def dict_base_method(self, receiver, name, args):
        """Apply a supported dictionary base operation to the modeled instance state."""
        base = receiver.base_items
        if name == "__init__":
            values = self.closed_base_values(args, "dict")
            base.clear()
            base.update(values)
            return None
        if name == "items" and not args:
            return _ProviderV4Iterator(tuple(base.items()))
        if name == "clear" and not args:
            base.clear()
            return None
        if name == "update" and len(args) == 1 and type(args[0]) is dict:
            for key in args[0]:
                _provider_v4_mapping_key(key)
            base.update(args[0])
            return None
        if name == "setdefault" and 1 <= len(args) <= 2:
            _provider_v4_mapping_key(args[0])
            return base.setdefault(*args)
        if name == "__setitem__" and len(args) == 2:
            _provider_v4_mapping_key(args[0])
            base[args[0]] = args[1]
            return None
        raise ValueError("unmodeled dict-base method effect")

    def construct(self, symbol, call, args, kwargs):
        """Construct source-modeled instance state without importing or executing the target class."""
        model = self.classes[symbol]
        obj = _ProviderV4SourceObject(
            path=model["path"],
            name=model["class"].name,
            class_ast_sha256=model["digest"],
            base_kind=model["base"],
            base_items=[] if model["base"] == "list" else {},
            state={},
            slots=model["slots"],
            state_hook_uses=(),
            slot_state={},
            reduce_recipe=model["reduce_recipe"],
        )
        method = model["methods"].get("__init__")
        if method is None:
            if args or kwargs:
                raise ValueError("default object construction with arguments")
        else:
            if self.run_method(obj, model, method, call, args, kwargs) is not None:
                raise ValueError("constructor returns a non-None value")
        return obj

    def _complete_object_state(self, obj, model):
        if model["state_hooks"]:
            self._apply_source_state_hooks(obj, model)
            return
        obj.state_recipe = (
            "DEFAULT_DICT_AND_SLOT_BUILD" if obj.slots else "DEFAULT_DICT_BUILD"
        )
        obj.serialized_state = (
            (obj.state.copy(), obj.slot_state.copy()) if obj.slots else obj.state.copy()
        )
        obj.mro = tuple(
            (entry["path"], entry["class"].name, entry["digest"])
            for entry in model["mro_models"]
        )

    def _apply_source_state_hooks(self, original, model):
        getstate, setstate = (
            model["methods"]["__getstate__"],
            model["methods"]["__setstate__"],
        )
        state = self.run_method(original, model, getstate, None, [], {})
        shell = _ProviderV4SourceObject(
            path=original.path,
            name=original.name,
            class_ast_sha256=original.class_ast_sha256,
            base_kind=original.base_kind,
            base_items=[] if original.base_kind == "list" else {},
            state={},
            slots=original.slots,
            state_hook_uses=(),
            slot_state={},
            reduce_recipe=original.reduce_recipe,
        )
        self.run_method(shell, model, setstate, None, [state], {})
        if not _provider_v4_replayed_state_matches(original, shell):
            raise ValueError("paired state hook does not reconstruct source object")
        original.serialized_state = state
        original.state_recipe = "SOURCE_GETSTATE_SETSTATE_BUILD"
        original.state_hook_uses = tuple(
            _provider_v4_method_use(
                model["method_owners"].get(id(method), model), method
            )
            for method in (getstate, setstate)
        )
        original.mro = tuple(
            (entry["path"], entry["class"].name, entry["digest"])
            for entry in model["mro_models"]
        )

    def method(self, receiver, name, call, args, kwargs):
        """Resolve a method against the captured class model and reject instance-level shadowing."""
        if type(receiver) is _ProviderV4SourceObject:
            if name in receiver.state:
                raise ValueError("instance state shadows the source method")
            model = self.classes[receiver.path, receiver.name]
            method = model["methods"].get(name)
            if method is None:
                raise ValueError("unknown source instance method")
            return self.run_method(receiver, model, method, call, args, kwargs)
        return _provider_v4_builtin_method(receiver, name, args, kwargs)

    def run_method(self, receiver, model, method, call, args, kwargs):
        """Interpret a bounded captured method with exact argument binding and lexical-owner tracking."""
        model = model.get("method_owners", {}).get(id(method), model)
        identity = (model["path"], model["class"].name, method.name)
        if identity in self.stack:
            raise ValueError("recursive source method")
        env = _provider_v4_bind_values(method, args, kwargs)
        env[method.args.args[0].arg] = receiver
        self.stack.append(identity)
        self.method_uses.append(
            {
                "path": model["path"],
                "class": model["class"].name,
                "method": method.name,
                "span": _fixed_program_span(method),
                "ast_sha256": _provider_v4_ast_digest(method),
            }
        )
        try:
            try:
                is_generator = any(
                    isinstance(node, (ast.Yield, ast.YieldFrom))
                    for node in ast.walk(method)
                )
                if is_generator:
                    if call is None or not self._direct_builtin_consumer(
                        call, model["path"]
                    ):
                        raise ValueError(
                            "source generator escapes its closed builtin consumer"
                        )
                    frame = []
                    self.yield_frames.append(frame)
                self.block(method.body, env, model["path"])
            except _ProviderV4Return as returned:
                return returned.value
            if "frame" in locals():
                return _ProviderV4Iterator(tuple(frame))
            return None
        finally:
            if (
                "frame" in locals()
                and self.yield_frames
                and self.yield_frames[-1] is frame
            ):
                self.yield_frames.pop()
            self.stack.pop()

    def _direct_builtin_consumer(self, call, path):
        parent = self.parents.get(path, {}).get(call)
        return (
            isinstance(parent, ast.Call)
            and call in parent.args
            and isinstance(parent.func, ast.Name)
            and parent.func.id in {"dict", "list", "tuple"}
        )

    def block(self, statements, env, path):
        """Interpret a bounded statement block and propagate its explicit modeled return state."""
        for node in statements:
            self.remaining -= 1
            if self.remaining < 0:
                raise ValueError("source statement budget exhausted")
            if isinstance(node, ast.Return):
                raise _ProviderV4Return(
                    None if node.value is None else self.value(node.value, env, path)
                )
            if isinstance(node, ast.If):
                self.block(
                    node.body if self.condition(node.test, env, path) else node.orelse,
                    env,
                    path,
                )
            elif isinstance(node, ast.For):
                self.bounded_loop(node, env, path)
            elif isinstance(node, ast.Expr) and isinstance(
                node.value, (ast.Yield, ast.YieldFrom)
            ):
                self.bounded_yield(node.value, env, path)
            else:
                self.statement(node, env, path)
        return None

    def bounded_loop(self, node, env, path):
        """Expand a source loop only over a closed iterable within the interpreter budget."""
        if (
            node.orelse
            or node.type_comment
            or not isinstance(node.target, (ast.Name, ast.Tuple, ast.List))
        ):
            raise ValueError("unmodeled bounded loop")
        values = self.iterable(self.value(node.iter, env, path))
        if len(values) > 512:
            raise ValueError("source loop exceeds graph budget")
        for item in values:
            self.assign(node.target, item, env, path)
            self.block(node.body, env, path)

    def bounded_yield(self, node, env, path):
        """Collect bounded yielded values from supported source generator statements."""
        if not self.yield_frames or node.value is None:
            raise ValueError("yield outside closed source generator")
        value = self.value(node.value, env, path)
        if isinstance(node, ast.YieldFrom):
            self.yield_frames[-1].extend(self.iterable(value))
        else:
            self.yield_frames[-1].append(value)

    def iterable(self, value):
        """Extract bounded iteration values only from supported modeled containers."""
        if type(value) is _ProviderV4Iterator:
            return value.values
        if type(value) in {tuple, list}:
            return tuple(value)
        if type(value) is dict:
            for key in value:
                _provider_v4_mapping_key(key)
            return tuple(value)
        raise ValueError("unknown source iteration protocol")

    def statement(self, node, env, path):
        """Interpret one supported source statement, rejecting unknown effects and protocols."""
        if (
            isinstance(node, (ast.Pass,))
            or isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and type(node.value.value) is str
        ):
            return
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            self.value(node.value, env, path)
            return
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            self.assign(node.targets[0], self.value(node.value, env, path), env, path)
            return
        if isinstance(node, ast.AnnAssign) and node.value is not None:
            self.assign(node.target, self.value(node.value, env, path), env, path)
            return
        raise ValueError("unmodeled source statement effect")

    def assign(self, target, value, env, path):
        """Store a modeled value into a supported local, field or container target."""
        if isinstance(target, ast.Name):
            env[target.id] = value
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            values = self.iterable(value)
            if len(target.elts) != len(values):
                raise ValueError("unmatched source destructuring")
            for child, item in zip(target.elts, values):
                self.assign(child, item, env, path)
            return
        if isinstance(target, ast.Attribute):
            self.assign_field(target, value, env, path)
            return
        if isinstance(target, ast.Subscript):
            receiver, key = (
                self.value(target.value, env, path),
                self.value(target.slice, env, path),
            )
            if type(receiver) not in {list, dict}:
                raise ValueError("unmodeled item assignment")
            _provider_v4_mapping_key(key)
            receiver[key] = value
            return
        raise ValueError("unknown assignment target")

    def assign_field(self, target, value, env, path):
        """Update source-modeled instance fields while respecting its declared dictionary and slot layout."""
        receiver = self.value(target.value, env, path)
        if type(receiver) is not _ProviderV4SourceObject or target.attr.startswith(
            "__"
        ):
            raise ValueError("unsupported instance state store")
        if _provider_v2_text_size(target.attr) is None:
            raise ValueError("field name exceeds bound")
        if target.attr in receiver.slots:
            receiver.slot_state[target.attr] = value
            return
        model = self.classes[receiver.path, receiver.name]
        if any(
            target.attr in candidate["slots"] for candidate in model["mro_models"][1:]
        ):
            raise ValueError("base-slot assignment requires inherited descriptor model")
        receiver.state[target.attr] = value

    def condition(self, node, env, path):
        """Evaluate an exact supported condition or reject an unknown truth-value protocol."""
        if (
            not isinstance(node, ast.Compare)
            or len(node.ops) != 1
            or len(node.comparators) != 1
        ):
            raise ValueError("unknown source condition")
        left, right = (
            self.value(node.left, env, path),
            self.value(node.comparators[0], env, path),
        )
        if isinstance(node.ops[0], ast.Is):
            return left is right
        if isinstance(node.ops[0], ast.IsNot):
            return left is not right
        if type(left) in {str, bytes, int, float, bool, type(None)} and type(right) in {
            str,
            bytes,
            int,
            float,
            bool,
            type(None),
        }:
            if isinstance(node.ops[0], ast.Eq):
                return left == right
            if isinstance(node.ops[0], ast.NotEq):
                return left != right
        raise ValueError("unknown comparison protocol")


def _provider_v4_mapping_key(value):
    if (
        type(value) not in {str, bytes, int, float, bool, type(None)}
        or _provider_v4_scalar(value) is None
    ):
        raise ValueError("mapping key must have an exact builtin scalar type")


def _provider_v4_super_call_shape(node):
    return (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Call)
        and isinstance(node.func.value.func, ast.Name)
        and node.func.value.func.id == "super"
        and not node.func.value.args
        and not node.func.value.keywords
    )


def _provider_v4_ast_digest(node):
    return hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()


def _provider_v4_method_use(model, method):
    return {
        "path": model["path"],
        "class": model["class"].name,
        "class_ast_sha256": model["digest"],
        "method": method.name,
        "span": _fixed_program_span(method),
        "ast_sha256": _provider_v4_ast_digest(method),
    }


def _provider_v4_replayed_state_matches(original, restored):
    pairs = set()

    def same(left, right):
        if type(left) is not type(right):
            return False
        if type(left) in {str, bytes, int, float, bool, type(None)}:
            return left == right
        pair = (id(left), id(right))
        if pair in pairs:
            return True
        pairs.add(pair)
        if type(left) is dict:
            return left.keys() == right.keys() and all(
                same(key, key2) and same(left[key], right[key])
                for key, key2 in zip(left, right)
            )
        if type(left) in {tuple, list}:
            return len(left) == len(right) and all(
                same(a, b) for a, b in zip(left, right)
            )
        if type(left) is _ProviderV4OrderedDict:
            return same(left.items, right.items)
        if type(left) is _ProviderV4SourceObject:
            return (
                left.path == right.path
                and left.name == right.name
                and same(left.base_items, right.base_items)
                and same(left.state, right.state)
                and same(left.slot_state, right.slot_state)
            )
        return False

    return (
        same(original.base_items, restored.base_items)
        and same(original.state, restored.state)
        and same(original.slot_state, restored.slot_state)
    )


def _provider_v4_source_classes(contract, trees):
    from .credential_role_constructor_provider import binding_occurrences

    models = {}
    for row in contract["classes"]:
        tree = trees[row["path"]]
        matches = binding_occurrences(tree.body, row["name"])
        if (
            len(matches) != 1
            or not isinstance(matches[0], ast.ClassDef)
            or matches[0] not in tree.body
        ):
            raise ValueError("source class identity is ambiguous")
        cls = matches[0]
        if _provider_v4_ast_digest(cls) != row["class_ast_sha256"]:
            raise ValueError("source class hash differs")
        model = _provider_v4_class_model(cls, tree, row, trees)
        models[row["path"], row["name"]] = model
    return _provider_v4_resolve_mro(models)


def _provider_v4_class_model(cls, tree, row, trees):
    if cls.decorator_list or cls.keywords:
        raise ValueError("unmodeled class construction")
    bases = [
        _provider_v4_base_symbol(node, row["path"], trees) for node in cls.bases
    ] or ["object"]
    base = next(
        (value for value in bases if value in {"object", "list", "dict"}), "object"
    )
    methods = {}
    forbidden = _provider_v4_forbidden_methods(base)
    slots = _provider_v4_class_slots(cls)
    for node in cls.body:
        if isinstance(node, ast.FunctionDef):
            if node.name in forbidden or node.name in methods or node.decorator_list:
                raise ValueError("unmodeled reconstruction override")
            methods[node.name] = node
        elif not _provider_v4_inert_class_member(
            node, forbidden, slots
        ) and not _provider_v4_class_constant(node):
            raise ValueError("unmodeled class member")
    if ("__getstate__" in methods) != ("__setstate__" in methods):
        raise ValueError("source state hooks are not paired")
    reduce_method = methods.get("__reduce__")
    if reduce_method is not None and not _provider_v4_reduce_delegation(reduce_method):
        raise ValueError("source reducer has an unmodeled effect")
    init = methods.get("__init__")
    digest = _provider_v4_ast_digest(init) if init is not None else None
    if digest != row["constructor_ast_sha256"]:
        raise ValueError("source constructor identity differs")
    model = {
        "class": cls,
        "path": row["path"],
        "digest": row["class_ast_sha256"],
        "base": base,
        "bases": bases,
        "methods": methods,
        "slots": slots,
        "class_values": {
            node.targets[0].id: ast.literal_eval(node.value)
            for node in cls.body
            if _provider_v4_class_constant(node)
        },
        "state_hooks": ("__getstate__", "__setstate__")
        if "__getstate__" in methods
        else (),
        "reduce_recipe": "CANONICAL_BASE_REDUCE"
        if reduce_method is not None
        else "CANONICAL_OBJECT_REDUCE",
    }
    model["mro_models"] = [model]
    return model


def _provider_v4_class_constant(node):
    return (
        isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and not node.targets[0].id.startswith("__")
        and _provider_v2_class_value(node.value)
    )


def _provider_v4_base_symbol(node, path, trees):
    if isinstance(node, ast.Subscript):
        candidate = _provider_v4_resolve_symbol(path, ast.unparse(node.value), trees)
        if candidate not in {"list", "dict"}:
            raise ValueError("unknown generic base allocation")
        return candidate
    if not isinstance(node, ast.Name):
        raise ValueError("dynamic or starred base")
    candidate = _provider_v4_resolve_symbol(path, node.id, trees)
    if not isinstance(candidate, tuple) and candidate not in {"object", "list", "dict"}:
        raise ValueError("unknown native class allocator")
    return candidate


def _provider_v4_resolve_mro(models):
    linearized = {}
    for _ in range(16):
        for identity, model in models.items():
            if identity in linearized or any(
                isinstance(base, tuple) and base not in linearized
                for base in model["bases"]
            ):
                continue
            sequences = [
                list(linearized[base])
                if isinstance(base, tuple)
                else ([base, "object"] if base != "object" else ["object"])
                for base in model["bases"]
            ]
            mro = [identity, *_provider_v4_c3_merge([*sequences, list(model["bases"])])]
            linearized[identity] = mro
        if len(linearized) == len(models):
            return _provider_v4_apply_mro(models, linearized)
    raise ValueError("source inheritance is cyclic or unclosed")


def _provider_v4_c3_merge(sequences):
    result = []
    pending = [list(values) for values in sequences if values]
    while pending:
        head = next(
            (
                values[0]
                for values in pending
                if not any(values[0] in other[1:] for other in pending)
            ),
            None,
        )
        if head is None or len(result) > 16:
            raise ValueError("inconsistent or oversized source MRO")
        result.append(head)
        pending = [values[1:] if values[0] == head else values for values in pending]
        pending = [values for values in pending if values]
    return result


def _provider_v4_apply_mro(models, linearized):
    own = {key: dict(model["methods"]) for key, model in models.items()}
    values = {key: dict(model["class_values"]) for key, model in models.items()}
    for key, order in linearized.items():
        model = models[key]
        bases = {value for value in order if isinstance(value, str)}
        if len(bases - {"object"}) > 1:
            raise ValueError("conflicting native container layouts")
        model["base"] = next(iter(bases - {"object"}), "object")
        model["mro_order"] = order
        model["own_methods"] = own[key]
        model["mro_models"] = [
            models[item] for item in order if isinstance(item, tuple)
        ]
        model["methods"], model["class_values"], model["method_owners"] = {}, {}, {}
        for item in reversed(order):
            if not isinstance(item, tuple):
                continue
            model["methods"].update(own[item])
            model["class_values"].update(values[item])
            model["method_owners"].update(
                {id(method): models[item] for method in own[item].values()}
            )
        forbidden = _provider_v4_forbidden_methods(model["base"])
        if forbidden.intersection(model["methods"]):
            raise ValueError("inherited reconstruction override")
        if any(parent["slots"] for parent in model["mro_models"][1:]):
            raise ValueError("inherited slot layouts require separate descriptor model")
        model["state_hooks"] = (
            ("__getstate__", "__setstate__")
            if "__getstate__" in model["methods"]
            else ()
        )
        if ("__getstate__" in model["methods"]) != ("__setstate__" in model["methods"]):
            raise ValueError("inherited source state hooks are not paired")
    return models


def _provider_v4_forbidden_methods(base):
    forbidden = {
        "__new__",
        "__reduce_ex__",
        "__getnewargs__",
        "__getnewargs_ex__",
        "__getattribute__",
        "__getattr__",
        "__setattr__",
        "__delattr__",
        "__init_subclass__",
        "__class_getitem__",
        "__setitem__",
        "append",
        "extend",
    }
    if base in {"list", "dict"}:
        forbidden.update({"__iter__", "__len__", "__getitem__"})
    if base == "dict":
        forbidden.add("items")
    return forbidden


def _provider_v4_inert_class_member(node, forbidden, slots):
    if (
        isinstance(node, ast.Pass)
        or isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and type(node.value.value) is str
    ):
        return True
    if isinstance(node, ast.AnnAssign) and node.value is None:
        return (
            isinstance(node.target, ast.Name)
            and node.target.id not in forbidden
            and not _provider_v2_header_effect(node.annotation)
        )
    if (
        isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "__slots__"
    ):
        return _provider_v4_class_slots_value(node.value) == slots
    return False


def _provider_v4_class_slots(cls):
    rows = [
        node
        for node in cls.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "__slots__"
    ]
    if not rows:
        return ()
    if len(rows) != 1:
        raise ValueError("duplicate source slot declarations")
    slots = _provider_v4_class_slots_value(rows[0].value)
    if slots is None:
        raise ValueError("dynamic source slots are unsupported")
    return slots


def _provider_v4_class_slots_value(node):
    try:
        value = ast.literal_eval(node)
    except (TypeError, ValueError, SyntaxError, MemoryError, RecursionError):
        return None
    if isinstance(value, str):
        value = (value,)
    if type(value) not in {tuple, list} or len(value) > 32:
        return None
    if any(
        not isinstance(item, str)
        or not item.isidentifier()
        or item.startswith("__")
        or _provider_v2_text_size(item) is None
        for item in value
    ):
        return None
    return tuple(value) if len(set(value)) == len(value) else None


def _provider_v4_reduce_delegation(method):
    if (
        method.decorator_list
        or len(method.args.args) != 1
        or method.args.args[0].arg != "self"
        or len(method.body) != 1
        or not isinstance(method.body[0], ast.Return)
    ):
        return False
    call = method.body[0].value
    return (
        isinstance(call, ast.Call)
        and _provider_v4_super_call_shape(call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "__reduce__"
        and not call.args
        and not call.keywords
    )


def _provider_v4_resolve_symbol(path, name, trees, visited=()):
    from pathlib import PurePosixPath
    from .credential_role_constructor_provider import binding_occurrences

    tree = trees[path]
    identity = path, name
    if identity in visited or len(visited) >= 8:
        raise ValueError("source import cycle or chain limit")
    visited = (*visited, identity)
    bindings = binding_occurrences(tree.body, name)
    if not bindings:
        return name
    if len(bindings) != 1:
        raise ValueError("ambiguous source symbol")
    node = bindings[0]
    if isinstance(node, ast.ClassDef):
        return path, name
    if isinstance(node, ast.ImportFrom) and not any(
        alias.name == "*" for alias in node.names
    ):
        (alias,) = [item for item in node.names if (item.asname or item.name) == name]
        if node.level:
            package = PurePosixPath(path).parent.parts
            if node.level > len(package):
                raise ValueError("import outside captured package")
            module = ".".join(
                [
                    *package[: len(package) - node.level + 1],
                    *(node.module or "").split("."),
                ]
            )
        else:
            module = node.module or ""
        targets = [
            candidate
            for candidate in (
                module.replace(".", "/") + ".py",
                module.replace(".", "/") + "/__init__.py",
            )
            if candidate in trees
        ]
        if len(targets) == 1:
            return _provider_v4_resolve_symbol(targets[0], alias.name, trees, visited)
        if len(targets) > 1:
            raise ValueError("competing module identities")
        return module + "." + alias.name
    raise ValueError("source symbol is not a class or explicit import")


def _provider_v4_bind_values(method, args, kwargs):
    parameters = method.args
    if (
        not parameters.args
        or parameters.posonlyargs
        or parameters.vararg
        or parameters.kwarg
    ):
        raise ValueError("unsupported method signature")
    positional = [node.arg for node in parameters.args[1:]]
    if len(args) > len(positional):
        raise ValueError("too many method arguments")
    values = dict(zip(positional, args))
    for name, value in kwargs.items():
        if name in values or name not in {
            *positional,
            *(node.arg for node in parameters.kwonlyargs),
        }:
            raise ValueError("invalid keyword binding")
        values[name] = value
    defaults = (
        dict(zip(positional[-len(parameters.defaults) :], parameters.defaults))
        if parameters.defaults
        else {}
    )
    defaults.update(
        {
            node.arg: value
            for node, value in zip(parameters.kwonlyargs, parameters.kw_defaults)
            if value is not None
        }
    )
    for name in [*positional, *(node.arg for node in parameters.kwonlyargs)]:
        if name not in values:
            if name not in defaults or not _fixed_literal_value(defaults[name]):
                raise ValueError("unresolved method default")
            value = ast.literal_eval(defaults[name])
            if not _provider_v2_immutable_value(value):
                raise ValueError("mutable defaults have unknown prior state")
            values[name] = value
    return values


def _provider_v4_builtin_call(name, args, kwargs):
    if kwargs:
        raise ValueError("unmodeled builtin keywords")
    if name in {"dict", "list", "tuple"} and len(args) <= 1:
        if args and type(args[0]) not in {dict, list, tuple, _ProviderV4Iterator}:
            raise ValueError("unknown iteration protocol")
        values = (
            args[0].values
            if args and type(args[0]) is _ProviderV4Iterator
            else args[0]
            if args
            else ()
        )
        if name == "dict" and type(values) is not dict:
            pairs = []
            for item in values:
                if type(item) not in {tuple, list} or len(item) != 2:
                    raise ValueError("dictionary constructor requires exact pairs")
                _provider_v4_mapping_key(item[0])
                pairs.append((item[0], item[1]))
            return dict(pairs)
        return {"dict": dict, "list": list, "tuple": tuple}[name](values)
    if name == "collections.OrderedDict" and not args:
        return _ProviderV4OrderedDict(())
    raise ValueError("unmodeled source callable")


def _provider_v4_builtin_method(receiver, name, args, kwargs):
    if kwargs:
        raise ValueError("unmodeled builtin method keywords")
    if type(receiver) in {dict, list} and name == "copy" and not args:
        return receiver.copy()
    if type(receiver) is list and name == "append" and len(args) == 1:
        receiver.append(args[0])
        return None
    if type(receiver) is bytes and name == "split" and not args:
        return receiver.split()
    if (
        type(receiver) is dict
        and name == "update"
        and len(args) == 1
        and type(args[0]) is dict
    ):
        for key in args[0]:
            _provider_v4_mapping_key(key)
        receiver.update(args[0])
        return None
    if type(receiver) is dict and name == "clear" and not args:
        receiver.clear()
        return None
    if type(receiver) is dict and name == "setdefault" and 1 <= len(args) <= 2:
        _provider_v4_mapping_key(args[0])
        default = args[1] if len(args) == 2 else None
        if type(default) not in {
            type(None),
            str,
            bytes,
            int,
            float,
            bool,
            tuple,
            list,
            dict,
        }:
            raise ValueError("unknown dict default protocol")
        return receiver.setdefault(*args)
    raise ValueError("unmodeled builtin method effects")


def provider_pickle_graph_record(
    profile,
    source_bytes,
    object_expression,
    *,
    selected_contract_view,
    source_path,
    state_evidence=None,
):
    """Rebuild a generic reconstruction graph from a selected source expression.

    A graph is provisional until the runtime layer independently proves byte
    origin, cached identities and absence of source-visible provider mutation.
    """
    try:
        current = provider_analysis_profile(
            profile["analysis_profile"], tuple(profile["contracts"])
        )
        if current != profile or state_evidence is not None:
            return None
        contract = _provider_v2_selected_contract(current, selected_contract_view)
        if contract is None or contract["model"] != {
            "id": _PROVIDER_MODEL_V4["id"],
            "version": 4,
        }:
            return None
        interpreter = _ProviderV4SourceInterpreter(contract, source_bytes)
        tree, expression, scope = _provider_v4_caller_expression(
            source_bytes, source_path, object_expression
        )
        interpreter.trees[source_path] = tree
        if not _provider_v4_builtins_source_closed(interpreter.trees):
            return None
        value = _provider_v4_source_root(interpreter, scope, expression, source_path)
        graph = _ProviderV4Graph(interpreter)
        root = graph.edge(value)
        return _provider_v4_graph_record(
            current,
            contract,
            selected_contract_view,
            interpreter,
            graph,
            root,
            source_path,
        )
    except (
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
        SyntaxError,
        RecursionError,
        MemoryError,
        IndexError,
        ZeroDivisionError,
    ):
        return None


def _provider_v4_caller_expression(sources, path, original):
    raw = sources.get(path)
    if not isinstance(raw, bytes) or len(raw) > 1_000_000:
        raise ValueError("caller source is missing")
    tree = ast.parse(raw)
    matches = [
        node
        for node in ast.walk(tree)
        if type(node) is type(original)
        and _fixed_program_span(node) == _fixed_program_span(original)
        and _provider_v4_ast_digest(node) == _provider_v4_ast_digest(original)
    ]
    if len(matches) != 1:
        raise ValueError("root expression is not captured source")
    expression = matches[0]
    parents = {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }
    scope = expression
    while scope in parents and not isinstance(
        scope, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        scope = parents[scope]
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        raise ValueError("root expression is outside a callable frame")
    if any(
        isinstance(
            node, (ast.Global, ast.Nonlocal, ast.Yield, ast.YieldFrom, ast.Await)
        )
        for node in ast.walk(scope)
    ):
        raise ValueError("nonlocal callable effect")
    owner = parents.get(scope)
    if owner is not tree and not (
        isinstance(owner, ast.ClassDef) and parents.get(owner) is tree
    ):
        raise ValueError("nested caller closure")
    return tree, expression, scope


def _provider_v4_builtins_source_closed(trees):
    from . import review_audits as audit
    from .runtime_audit_integrity import (
        _conditional_enum_base_mutated,
        _conditional_file_aliases,
        _conditional_module_name,
    )

    modules = {path: _conditional_module_name(path) for path in trees}
    for path, tree in trees.items():
        aliases = _conditional_file_aliases(path, tree, modules)
        if aliases is None or _conditional_enum_base_mutated(
            list(ast.walk(tree)),
            aliases,
            audit,
            additional_roots={
                "object",
                "list",
                "dict",
                "tuple",
                "builtins.object",
                "builtins.list",
                "builtins.dict",
                "builtins.tuple",
            },
        ):
            return False
    return True


def _provider_v4_source_root(interpreter, scope, expression, path):
    parents = {
        child: node for node in ast.walk(scope) for child in ast.iter_child_nodes(node)
    }
    statement = expression
    while parents.get(statement) is not scope:
        statement = parents.get(statement)
        if statement is None:
            raise ValueError("root expression has no direct frame statement")
    if not isinstance(statement, (ast.Assign, ast.AnnAssign, ast.Return, ast.Expr)):
        raise ValueError("uncertain control flow around root")
    parameters = {
        item.arg
        for item in [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
    }
    if any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in parameters
        for node in ast.walk(scope)
    ):
        raise ValueError("callable parameter shadows source provider")
    env = {}
    for prior in scope.body[: scope.body.index(statement)]:
        interpreter.statement(prior, env, path)
    return interpreter.value(expression, env, path)


def _provider_v4_graph_record(
    profile, contract, view, interpreter, graph, root, source_path
):
    from .runtime_audit_common import canonical_bytes

    hashes = {
        path: hashlib.sha256(interpreter.sources[path]).hexdigest()
        for path in sorted({*contract["artifacts"], source_path})
    }
    payload = {
        "schema": "factory.typed-pickle-graph.v4",
        "root": root,
        "nodes": graph.nodes,
        "source_hashes": hashes,
        "method_uses": interpreter.method_uses,
        "selected_contract_sha256": view["selected_contract_sha256"],
        "selected_model_sha256": view["selected_model_sha256"],
        "runtime": contract["runtime"],
    }
    return {
        "assurance": "PROVISIONAL_PROVIDER_RECONSTRUCTION",
        "analysis_profile": profile["analysis_profile"],
        "typed_graph": payload,
        "typed_graph_sha256": hashlib.sha256(canonical_bytes(payload)).hexdigest(),
        "requires_initialized_provider_witness": True,
        "requires_protocol_conformance": True,
        "model_states_evaluated": 512 - interpreter.remaining,
        "target_execution": "not_performed",
    }


def _provider_profile_error(message):
    from .runtime_audit_common import RuntimeAuditError

    raise RuntimeAuditError("E_ANALYSIS_PROFILE", message)


def _provider_runtime_identity():
    """Fingerprint only local interpreter artifacts, never import target code."""
    import importlib.util
    import platform
    import sys
    import sysconfig
    from pathlib import Path

    if platform.python_implementation() != "CPython" or sys.version_info[:3] != (
        3,
        11,
        9,
    ):
        _provider_profile_error("builtin-exception-record-v1 requires CPython 3.11.9")
    spec = importlib.util.find_spec("_pickle")
    if spec is None:
        _provider_profile_error("stdlib pickle implementation is unavailable")
    binary = (
        Path(spec.origin)
        if spec.origin != "built-in"
        else (
            Path(sys.base_prefix) / "python311.dll"
            if sys.platform == "win32"
            else Path(sysconfig.get_config_var("LIBDIR") or sys.base_prefix)
            / (sysconfig.get_config_var("LDLIBRARY") or "")
        )
    )
    files = {
        "executable_sha256": Path(sys.executable),
        "pickle_source_sha256": Path(sysconfig.get_path("stdlib")) / "pickle.py",
        "pickle_implementation_sha256": binary,
    }
    try:
        identities = {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in files.items()
        }
    except (OSError, ValueError) as exc:
        _provider_profile_error(
            f"runtime artifact identity unavailable: {type(exc).__name__}"
        )
    return {"implementation": "cpython", "version": "3.11.9", **identities}


def provider_runtime_identity_v3():
    """Return the v3 pickle plus canonical enum, typing, and runtime artifact identities."""
    import platform
    import sys
    import sysconfig
    from pathlib import Path
    from .finite_capture import _provider_runtime_identity

    base = _provider_runtime_identity()
    if platform.python_implementation() != "CPython" or sys.version_info[:3] != (
        3,
        11,
        9,
    ):
        _provider_profile_error(
            "typed-pickle-reconstruction-v3 requires CPython 3.11.9"
        )
    enum_source = Path(sysconfig.get_path("stdlib")) / "enum.py"
    typing_source = Path(sysconfig.get_path("stdlib")) / "typing.py"
    if sys.platform == "win32":
        runtime_candidates = [
            Path(sys.base_prefix)
            / f"python{sys.version_info.major}{sys.version_info.minor}.dll"
        ]
    else:
        library = sysconfig.get_config_var("LDLIBRARY")
        libdir = sysconfig.get_config_var("LIBDIR") or sys.base_prefix
        runtime_candidates = (
            [Path(libdir) / library] if isinstance(library, str) else []
        )
        runtime_candidates.append(Path(sys.executable))
    runtime_binary = next((path for path in runtime_candidates if path.is_file()), None)
    if (
        runtime_binary is None
        or not enum_source.is_file()
        or not typing_source.is_file()
    ):
        _provider_profile_error(
            "v3 enum, typing, or interpreter runtime artifact identity unavailable"
        )
    try:
        return {
            **base,
            "enum_source_sha256": hashlib.sha256(enum_source.read_bytes()).hexdigest(),
            "typing_source_sha256": hashlib.sha256(
                typing_source.read_bytes()
            ).hexdigest(),
            "python_runtime_sha256": hashlib.sha256(
                runtime_binary.read_bytes()
            ).hexdigest(),
        }
    except (OSError, ValueError) as exc:
        _provider_profile_error(
            f"v3 runtime artifact identity unavailable: {type(exc).__name__}"
        )


def provider_runtime_identity_v4():
    """Bind protocol, container, enum, typing and optional hook runtime sources."""
    import sysconfig
    from pathlib import Path
    from .finite_capture import provider_runtime_identity_v3

    base = provider_runtime_identity_v3()
    stdlib = Path(sysconfig.get_path("stdlib"))
    files = {
        "copyreg_source_sha256": stdlib / "copyreg.py",
        "collections_source_sha256": stdlib / "collections" / "__init__.py",
        "http_cookiejar_source_sha256": stdlib / "http" / "cookiejar.py",
        "threading_source_sha256": stdlib / "threading.py",
    }
    if any(not path.is_file() for path in files.values()):
        _provider_profile_error(
            "v4 protocol/container/hook runtime artifact identity unavailable"
        )
    try:
        return {
            **base,
            **{
                name: hashlib.sha256(path.read_bytes()).hexdigest()
                for name, path in files.items()
            },
        }
    except (OSError, ValueError) as exc:
        _provider_profile_error(
            f"v4 runtime artifact identity unavailable: {type(exc).__name__}"
        )


def _provider_runtime_for_model(model, base_runtime=None):
    from .finite_capture import (
        _provider_runtime_identity,
        provider_runtime_identity_v3,
        provider_runtime_identity_v4,
    )

    if isinstance(model, dict) and (model.get("id"), model.get("version")) == (
        _PROVIDER_MODEL_V4["id"],
        _PROVIDER_MODEL_V4["version"],
    ):
        return provider_runtime_identity_v4()
    if isinstance(model, dict) and (model.get("id"), model.get("version")) == (
        _PROVIDER_MODEL_V3["id"],
        _PROVIDER_MODEL_V3["version"],
    ):
        return provider_runtime_identity_v3()
    return _provider_runtime_identity() if base_runtime is None else base_runtime


def _provider_digest(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _provider_artifact_module_identity(path):
    from pathlib import PurePosixPath

    parts = list(PurePosixPath(path).parts)
    if not parts or PurePosixPath(path).suffix != ".py":
        return None
    stem = PurePosixPath(path).stem
    if stem == "__init__":
        parts.pop()
        if not parts:
            parts = ["__init__"]
    else:
        parts[-1] = stem
    return ".".join(parts).casefold()


def _provider_artifacts_valid(artifacts, *, module_identity_required=False):
    from pathlib import PurePosixPath

    if not isinstance(artifacts, dict) or not 1 <= len(artifacts) <= 64:
        return False
    for path, digest in artifacts.items():
        if not isinstance(path, str) or not path or "\\" in path or ":" in path:
            return False
        normalized = PurePosixPath(path)
        if (
            normalized.is_absolute()
            or ".." in normalized.parts
            or str(normalized) != path
            or not _provider_digest(digest)
        ):
            return False
    if len({path.casefold() for path in artifacts}) != len(artifacts):
        return False
    if not module_identity_required:
        return True
    module_ids = [_provider_artifact_module_identity(path) for path in artifacts]
    return None not in module_ids and len(set(module_ids)) == len(module_ids)


def _provider_class_rows_valid(rows, artifacts, *, maximum=8):
    keys = {"path", "name", "class_ast_sha256", "constructor_ast_sha256"}
    if not isinstance(rows, list) or not 1 <= len(rows) <= maximum:
        return False
    seen = set()
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) != keys
            or not isinstance(row.get("path"), str)
            or row["path"] not in artifacts
        ):
            return False
        name = row["name"]
        if (
            not isinstance(name, str)
            or not name.isidentifier()
            or (row["path"], name) in seen
        ):
            return False
        if (
            not _provider_digest(row["class_ast_sha256"])
            or row["constructor_ast_sha256"] is not None
            and not _provider_digest(row["constructor_ast_sha256"])
        ):
            return False
        seen.add((row["path"], name))
    return True


def _provider_contract_valid(contract, runtime, *, allow_v2=False):
    keys = {
        "schema",
        "model",
        "runtime",
        "artifacts",
        "export",
        "classes",
        "assumptions",
    }
    if not isinstance(contract, dict) or set(contract) != keys:
        return False
    model, export = contract["model"], contract["export"]
    if (
        not isinstance(model, dict)
        or set(model) != {"id", "version"}
        or type(model.get("version")) is not int
    ):
        return False
    if not isinstance(model.get("id"), str):
        return False
    descriptor = _PROVIDER_MODELS.get((model["id"], model["version"]))
    if descriptor is None or not allow_v2 and descriptor is not _PROVIDER_MODEL:
        return False
    if (
        contract["schema"] != "factory.provider-contract.v1"
        or contract["runtime"] != runtime
        or contract["assumptions"] != list(_PROVIDER_ASSUMPTIONS)
    ):
        return False
    artifacts = contract["artifacts"]
    if (
        not _provider_artifacts_valid(artifacts, module_identity_required=allow_v2)
        or not isinstance(export, dict)
        or set(export) != {"path", "symbol"}
    ):
        return False
    maximum = 16 if descriptor is _PROVIDER_MODEL_V4 else 8
    return (
        isinstance(export["path"], str)
        and export["path"] in artifacts
        and isinstance(export["symbol"], str)
        and export["symbol"].isidentifier()
        and _provider_class_rows_valid(contract["classes"], artifacts, maximum=maximum)
    )


def provider_analysis_profile(
    analysis_profile="source-closed-v1", provider_contracts=()
):
    """Declare conditional assumptions; this alone never proves a negative."""
    from .runtime_audit_common import canonical_bytes
    from .finite_capture import _provider_runtime_identity
    import json

    if (
        not isinstance(analysis_profile, str)
        or analysis_profile
        not in {
            "source-closed-v1",
            "trusted-dependencies-v1",
            "trusted-dependencies-v2",
        }
        or not isinstance(provider_contracts, tuple)
    ):
        _provider_profile_error("unknown profile or non-tuple contracts")
    if analysis_profile != "trusted-dependencies-v2" and len(provider_contracts) != (
        analysis_profile == "trusted-dependencies-v1"
    ):
        _provider_profile_error(
            "default requires no contracts; conditional profile requires exactly one"
        )
    if analysis_profile == "trusted-dependencies-v2":
        return _provider_analysis_profile_v2(provider_contracts)
    core = {
        "analysis_profile": analysis_profile,
        "conditional": bool(provider_contracts),
        "contracts": [],
    }
    if provider_contracts:
        contract = provider_contracts[0]
        if not _provider_contract_valid(contract, _provider_runtime_identity()):
            _provider_profile_error("invalid conditional provider contract")
        try:
            encoded = canonical_bytes(contract)
            core["contracts"] = [json.loads(encoded)]
        except (TypeError, ValueError):
            _provider_profile_error("contract must contain JSON data only")
        core.update(
            {
                "state": "CONTRACT_DECLARED_NOT_SOURCE_VALIDATED",
                "model_sha256": hashlib.sha256(
                    canonical_bytes(_PROVIDER_MODEL)
                ).hexdigest(),
                "contract_sha256": hashlib.sha256(encoded).hexdigest(),
            }
        )
    core["profile_sha256"] = hashlib.sha256(canonical_bytes(core)).hexdigest()
    return core


def _provider_analysis_profile_v2(provider_contracts):
    from .runtime_audit_common import canonical_bytes
    from .finite_capture import _provider_runtime_identity
    import json

    if (
        not isinstance(provider_contracts, tuple)
        or not 1 <= len(provider_contracts) <= 32
    ):
        _provider_profile_error("trusted-dependencies-v2 requires 1 to 32 contracts")
    runtime = _provider_runtime_identity()
    if any(
        not _provider_contract_valid(
            contract,
            _provider_runtime_for_model(contract.get("model"), runtime)
            if isinstance(contract, dict)
            else runtime,
            allow_v2=True,
        )
        for contract in provider_contracts
    ):
        _provider_profile_error("invalid v2 provider contract")
    try:
        contracts = [
            json.loads(canonical_bytes(contract)) for contract in provider_contracts
        ]
        contracts.sort(key=_provider_contract_sort_key)
        if not _provider_contract_set_unambiguous(contracts):
            _provider_profile_error(
                "duplicate provider identity or conflicting artifact hash"
            )
        encoded = [canonical_bytes(contract) for contract in contracts]
        contract_digests = [hashlib.sha256(raw).hexdigest() for raw in encoded]
        if len(set(contract_digests)) != len(contract_digests):
            _provider_profile_error("duplicate provider contracts")
        model_rows = sorted(
            (_provider_model_descriptor(contract["model"]) for contract in contracts),
            key=lambda row: (row["id"], row["version"]),
        )
        model_set_sha256 = hashlib.sha256(canonical_bytes(model_rows)).hexdigest()
        contract_set_sha256 = hashlib.sha256(canonical_bytes(contracts)).hexdigest()
        core = {
            "analysis_profile": "trusted-dependencies-v2",
            "conditional": True,
            "contracts": contracts,
            "state": "CONTRACT_SET_DECLARED_NOT_SOURCE_VALIDATED",
            "model_sha256": model_set_sha256,
            "contract_sha256": contract_set_sha256,
            "contract_set_sha256": contract_set_sha256,
        }
        core["profile_sha256"] = hashlib.sha256(canonical_bytes(core)).hexdigest()
        return core
    except (TypeError, ValueError):
        _provider_profile_error("v2 contracts must contain canonical JSON data")


def _provider_contract_sort_key(contract):
    export = contract["export"]
    head = contract["classes"][0]
    return export["path"], export["symbol"], head["path"], head["name"]


def _provider_contract_set_unambiguous(contracts):
    exports, heads, artifacts, folded_artifacts = set(), set(), {}, {}
    for contract in contracts:
        export = contract["export"]
        head = contract["classes"][0]
        export_id = (export["path"], export["symbol"])
        head_id = (head["path"], head["name"])
        if export_id in exports or head_id in heads:
            return False
        exports.add(export_id)
        heads.add(head_id)
        for path, digest in contract["artifacts"].items():
            previous = artifacts.setdefault(path, digest)
            if previous != digest:
                return False
            folded = folded_artifacts.setdefault(path.casefold(), (path, digest))
            if folded != (path, digest):
                return False
    return True


def _provider_model_descriptor(model):
    return dict(_PROVIDER_MODELS[(model["id"], model["version"])])


def provider_contract_view(profile, contract_sha256):
    """Return one canonical v2 contract view; never choose by model success."""
    from .runtime_audit_common import canonical_bytes
    import json

    if (
        not isinstance(profile, dict)
        or profile.get("analysis_profile") != "trusted-dependencies-v2"
    ):
        return None
    try:
        current = provider_analysis_profile(
            "trusted-dependencies-v2", tuple(profile["contracts"])
        )
        if current != profile:
            return None
        matches = []
        for contract in current["contracts"]:
            digest = hashlib.sha256(canonical_bytes(contract)).hexdigest()
            if digest == contract_sha256:
                matches.append((contract, digest))
        if len(matches) != 1:
            return None
        contract, selected_digest = matches[0]
        model = _provider_model_descriptor(contract["model"])
        return {
            "profile_sha256": current["profile_sha256"],
            "contract_set_sha256": current["contract_set_sha256"],
            "selected_contract_sha256": selected_digest,
            "selected_model_sha256": hashlib.sha256(canonical_bytes(model)).hexdigest(),
            "contract": json.loads(canonical_bytes(contract)),
        }
    except (KeyError, TypeError, ValueError, RuntimeError, MemoryError, RecursionError):
        return None


def _provider_v2_selected_contract(profile, selected_contract_view):
    from .runtime_audit_common import canonical_bytes

    if not isinstance(selected_contract_view, dict) or set(selected_contract_view) != {
        "profile_sha256",
        "contract_set_sha256",
        "selected_contract_sha256",
        "selected_model_sha256",
        "contract",
    }:
        return None
    try:
        view = provider_contract_view(
            profile, selected_contract_view["selected_contract_sha256"]
        )
        if view != selected_contract_view:
            return None
        contract = view["contract"]
        if (
            hashlib.sha256(canonical_bytes(contract)).hexdigest()
            != view["selected_contract_sha256"]
        ):
            return None
        return contract
    except (KeyError, TypeError, ValueError, MemoryError, RecursionError):
        return None


def _provider_record_classes(contract, trees):
    from .credential_role_constructor_provider import binding_occurrences

    constructor = None
    rows = contract["classes"]
    for index, row in enumerate(rows):
        tree = trees[row["path"]]
        bindings = binding_occurrences(tree.body, row["name"])
        if (
            len(bindings) != 1
            or not isinstance(bindings[0], ast.ClassDef)
            or bindings[0] not in tree.body
        ):
            return None
        cls = bindings[0]
        if index and cls.lineno >= next(
            item.lineno
            for item in tree.body
            if isinstance(item, ast.ClassDef) and item.name == rows[index - 1]["name"]
        ):
            return None
        parent = rows[index + 1]["name"] if index + 1 < len(rows) else "Exception"
        if (
            cls.decorator_list
            or cls.keywords
            or len(cls.bases) != 1
            or not isinstance(cls.bases[0], ast.Name)
            or cls.bases[0].id != parent
        ):
            return None
        if index + 1 < len(rows) and rows[index + 1]["path"] != row["path"]:
            return None
        if (
            hashlib.sha256(ast.dump(cls, include_attributes=False).encode()).hexdigest()
            != row["class_ast_sha256"]
        ):
            return None
        method = _provider_record_constructor(
            cls, index == 0, _provider_annotation_names(tree, cls)
        )
        digest = (
            hashlib.sha256(
                ast.dump(method, include_attributes=False).encode()
            ).hexdigest()
            if method
            else None
        )
        if digest != row["constructor_ast_sha256"] or index == 0 and method is None:
            return None
        constructor = method if index == 0 else constructor
    if binding_occurrences(trees[rows[-1]["path"]].body, "Exception"):
        return None
    return constructor


def _provider_annotation_names(tree, cls):
    from .credential_role_constructor_provider import binding_occurrences

    body = tree.body[: tree.body.index(cls)]
    guards = binding_occurrences(body, "TYPE_CHECKING")
    typed = (
        len(guards) == 1
        and isinstance(guards[0], ast.ImportFrom)
        and guards[0].module == "typing"
        and guards[0].level == 0
        and any(
            alias.name == "TYPE_CHECKING" and alias.asname is None
            for alias in guards[0].names
        )
    )
    runtime = []
    for statement in body:
        if (
            typed
            and isinstance(statement, ast.If)
            and isinstance(statement.test, ast.Name)
            and statement.test.id == "TYPE_CHECKING"
            and guards[0].lineno < statement.lineno
        ):
            runtime.extend(statement.orelse)
        else:
            runtime.append(statement)
    names = {
        "str",
        "int",
        "float",
        "bool",
        "bytes",
        "object",
        "type",
        "tuple",
        "list",
        "dict",
        "set",
        "frozenset",
    }
    names = {
        name: "builtin_type"
        for name in names
        if not binding_occurrences(runtime, name)
        and not binding_occurrences(cls.body, name)
    }
    parents = {
        child: node
        for statement in runtime
        for node in ast.walk(statement)
        for child in ast.iter_child_nodes(node)
    }
    for statement in runtime:
        if (
            isinstance(statement, ast.Assign)
            and isinstance(statement.value, ast.Constant)
            and statement.value.value is None
        ):
            for target in statement.targets:
                if (
                    isinstance(target, ast.Name)
                    and binding_occurrences(runtime, target.id) == [target]
                    and not binding_occurrences(cls.body, target.id)
                    and parents.get(target) is statement
                ):
                    names[target.id] = "none"
    return names


def _provider_annotation_kind(node, names):
    if isinstance(node, ast.Constant):
        return (
            "none"
            if node.value is None
            else "literal_string"
            if type(node.value) is str
            else None
        )
    if isinstance(node, ast.Name):
        return names.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        kinds = {
            _provider_annotation_kind(node.left, names),
            _provider_annotation_kind(node.right, names),
        }
        return (
            "union"
            if kinds <= {"builtin_type", "generic_alias", "union", "none"}
            and kinds != {"none"}
            else None
        )
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and names.get(node.value.id) == "builtin_type"
        and node.value.id in {"tuple", "list", "dict", "set", "type"}
    ):
        arguments = (
            node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
        )
        return (
            "generic_alias"
            if all(
                _provider_annotation_kind(argument, names) is not None
                for argument in arguments
            )
            else None
        )
    return None


def _provider_annotation_supported(node, names):
    return node is None or _provider_annotation_kind(node, names) is not None


def _provider_record_constructor(cls, derived, annotation_names):
    from .review_integrity import _function_annotations

    methods = []
    for statement in cls.body:
        if (
            isinstance(statement, ast.FunctionDef)
            and derived
            and statement.name == "__init__"
        ):
            methods.append(statement)
        elif (
            isinstance(statement, ast.Pass)
            or isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and type(statement.value.value) is str
        ):
            continue
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.value is None
            and _provider_annotation_supported(statement.annotation, annotation_names)
        ):
            continue
        else:
            raise ValueError("unsupported exception class behavior")
    if not derived:
        return None
    if (
        len(methods) != 1
        or methods[0].decorator_list
        or not all(
            _provider_annotation_supported(annotation, annotation_names)
            for annotation in _function_annotations(methods[0])
        )
    ):
        return None
    return methods[0]


def _provider_record_export(contract, trees):
    from pathlib import PurePosixPath
    from .credential_role_constructor_provider import binding_occurrences

    if contract["model"]["id"] in {_PROVIDER_MODEL_V3["id"], _PROVIDER_MODEL_V4["id"]}:
        return _provider_v3_record_export(contract, trees, binding_occurrences)
    export, target = contract["export"], contract["classes"][0]
    bindings = binding_occurrences(trees[export["path"]].body, export["symbol"])
    if export["path"] == target["path"]:
        return (
            export["symbol"] == target["name"]
            and len(bindings) == 1
            and isinstance(bindings[0], ast.ClassDef)
        )
    if len(bindings) != 1 or not isinstance(bindings[0], ast.ImportFrom):
        return False
    binding = bindings[0]
    if binding.level != 1 or not binding.module:
        return False
    selected = (
        PurePosixPath(export["path"])
        .parent.joinpath(*binding.module.split("."))
        .with_suffix(".py")
        .as_posix()
    )
    return selected == target["path"] and any(
        alias.name == target["name"]
        and (alias.asname or alias.name) == export["symbol"]
        for alias in binding.names
    )


def _provider_v3_record_export(contract, trees, binding_occurrences):
    return (
        _provider_v3_export_chain(
            contract, trees, contract["classes"][0], binding_occurrences
        )
        is not None
    )


def _provider_v3_export_rows(contract, source_bytes):
    if (
        not isinstance(contract, dict)
        or contract.get("model", {}).get("id")
        not in {_PROVIDER_MODEL_V3["id"], _PROVIDER_MODEL_V4["id"]}
        or not isinstance(source_bytes, dict)
    ):
        return None
    rows = contract.get("classes")
    if not isinstance(rows, list) or not rows:
        return None
    return rows


def _provider_v3_export_target(rows, class_row):
    target = (
        rows[0] if class_row is None and isinstance(rows, list) and rows else class_row
    )
    if not isinstance(target, dict) or target not in rows:
        return None
    return target


def provider_export_chain_v3(contract, source_bytes, *, class_row=None):
    """Return source-bound module.symbol identities for one selected v3 export."""
    rows = _provider_v3_export_rows(contract, source_bytes)
    if rows is None:
        return None
    target = _provider_v3_export_target(rows, class_row)
    if target is None:
        return None
    trees = _provider_source_trees(contract, source_bytes)
    if trees is None:
        return None
    try:
        from .credential_role_constructor_provider import binding_occurrences

        return _provider_v3_export_chain(contract, trees, target, binding_occurrences)
    except (
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
        SyntaxError,
        MemoryError,
        RecursionError,
    ):
        return None


def _closed_literal_pickle_input(
    node, aliases, fixed_literal_value, security_proven_callee
):
    if len(node.args) != 1 or node.keywords:
        return None
    dump = node.args[0]
    if not isinstance(dump, ast.Call) or len(dump.args) != 1 or dump.keywords:
        return None
    literal = dump.args[0]
    if sum(1 for _ in ast.walk(literal)) > 512 or not fixed_literal_value(literal):
        return None
    if not all(
        security_proven_callee(call, aliases, name)
        for call, name in ((node, "pickle.loads"), (dump, "pickle.dumps"))
    ):
        return None
    return literal


def _closed_literal_pickle_source_evidence(
    relative, node, audit, closed_pickle_inventory, security_module_scope
):
    module = security_module_scope(getattr(node, "_security_lexical_scope", None))
    context = getattr(module, "_security_source_context", None)
    if not isinstance(context, tuple) or len(context) != 2:
        return None
    root, sources = context
    raw = sources.get(root / relative)
    if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != getattr(
        module, "_oracle_source_sha256", None
    ):
        return None
    inventory = closed_pickle_inventory(root, sources, audit)
    if inventory is None:
        return None
    return raw, inventory


def closed_literal_pickle_witness(
    relative, node, aliases, *, fixed_literal_value, closed_pickle_inventory
):
    """Prove only modeled stdlib bytes from an inline, closed builtin literal.

    This excludes arbitrary objects/reducers and does not certify runtime or
    deployment safety. The partition independently rebuilds this source witness.
    """
    from . import review_audits as audit
    from .review_integrity import _security_module_scope, _security_proven_callee

    literal = _closed_literal_pickle_input(
        node, aliases, fixed_literal_value, _security_proven_callee
    )
    if literal is None:
        return {}
    source = _closed_literal_pickle_source_evidence(
        relative, node, audit, closed_pickle_inventory, _security_module_scope
    )
    if source is None:
        return {}
    raw, inventory = source
    return {
        "schema": "factory.closed-literal-pickle.v1",
        "disposition": "PROVEN_CLOSED_LITERAL_PICKLE_BYTES",
        "source_path": relative,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "workspace_sources_sha256": inventory,
        "call_span": [
            node.lineno,
            node.col_offset,
            node.end_lineno,
            node.end_col_offset,
        ],
        "literal_sha256": hashlib.sha256(
            ast.dump(literal, include_attributes=False).encode()
        ).hexdigest(),
        "hypothesis": "EXTERNAL_PICKLE_BYTE_INJECTION",
        "provider_model": "stdlib_pickle_builtin_literal_values",
        "runtime_assurance": "INCOMPLETE",
        "target_execution": "not_performed",
    }


def _closed_local_pickle_scope(
    node, loaded_name, audit, load_call_shape, direct_scope_index, scope_module
):
    if loaded_name not in {
        "pickle.loads",
        "_pickle.loads",
    } or not load_call_shape(node, loaded_name, allow_nested=True):
        return None
    scope = getattr(node, "_oracle_scope", None) or getattr(
        node, "_security_lexical_scope", None
    )
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    load_index = direct_scope_index(node, scope, audit)
    if load_index is None:
        return None
    module = scope_module(scope)
    if not isinstance(module, ast.Module):
        return None
    return scope, load_index, module


def _closed_local_pickle_dump(
    node,
    scope,
    load_index,
    module,
    loaded_name,
    aliases,
    audit,
    direct_dump_origin,
    direct_scope_index,
    direct_protocol,
    serializer_imports_closed,
):
    selected = direct_dump_origin(node, scope, load_index, loaded_name, aliases, audit)
    if selected is None:
        return None
    dump_index, dump_statement, dump_call, payload_name = selected
    if direct_scope_index(dump_call, scope, audit) != dump_index:
        return None
    object_expression = dump_call.args[0]
    protocol = direct_protocol(dump_call)
    if protocol is None or sum(1 for _ in ast.walk(object_expression)) > 512:
        return None
    if not serializer_imports_closed(
        module, scope, dump_index, load_index, dump_call, node, aliases, audit
    ):
        return None
    return dump_statement, dump_call, payload_name, object_expression, protocol


def closed_local_pickle_origin(
    node,
    loaded_name,
    aliases,
    audit,
    *,
    load_call_shape,
    direct_scope_index,
    scope_module,
    direct_dump_origin,
    direct_protocol,
    serializer_imports_closed,
):
    """Prove a direct native dumps-to-loads source origin, without effect credit."""
    scope_state = _closed_local_pickle_scope(
        node,
        loaded_name,
        audit,
        load_call_shape,
        direct_scope_index,
        scope_module,
    )
    if scope_state is None:
        return None
    scope, load_index, module = scope_state
    dump_state = _closed_local_pickle_dump(
        node,
        scope,
        load_index,
        module,
        loaded_name,
        aliases,
        audit,
        direct_dump_origin,
        direct_scope_index,
        direct_protocol,
        serializer_imports_closed,
    )
    if dump_state is None:
        return None
    dump_statement, dump_call, payload_name, object_expression, protocol = dump_state
    return {
        "status": "LOCAL_DIRECT_DUMPS_LOADS_ORIGIN",
        "origin_kind": "nested" if payload_name is None else "named_payload",
        "load_call": node,
        "dump_call": dump_call,
        "dump_statement": dump_statement,
        "object_expression": object_expression,
        "payload_name": payload_name,
        "scope": scope,
        "protocol": protocol,
    }


def pickle_serializer_imports_closed(
    module,
    scope,
    dump_index,
    load_index,
    dump_call,
    load_call,
    aliases,
    audit,
    call_imported,
    alias_closure,
    serializer_namespace_only=False,
):
    """Validate selected serializer aliases and the existing provider mutation model."""
    nodes = list(ast.walk(module))
    identity = _pickle_serializer_identity_aliases(aliases)
    stable = _pickle_serializer_identity_aliases(
        audit._unmodified_serialization_aliases(nodes, aliases)
    )
    if not _pickle_serializer_provider_unmodified(module, aliases, audit, alias_closure):
        return False
    if serializer_namespace_only and stable != identity:
        return False
    if not serializer_namespace_only and audit._unmodified_serialization_aliases(
        nodes, aliases
    ) != aliases:
        return False
    return call_imported(module, scope, dump_call, dump_index, aliases, audit) and call_imported(
        module, scope, load_call, load_index, aliases, audit
    )


def _pickle_serializer_identity_aliases(aliases):
    origins = {"pickle", "_pickle", "pickle.loads", "pickle.dumps", "_pickle.loads", "_pickle.dumps"}
    return {name: origin for name, origin in aliases.items() if origin in origins}


def _pickle_serializer_provider_unmodified(module, aliases, audit, alias_closure):
    from .finite_capture import finite_provider_mutation_index

    nodes = list(ast.walk(module))
    roots = {"pickle", "_pickle", "sys", "importlib", "builtins"}
    resolved = alias_closure(nodes, aliases, roots, audit)
    for target in nodes:
        if not isinstance(target, (ast.Attribute, ast.Subscript)) or not isinstance(
            target.ctx, (ast.Store, ast.Del)
        ):
            continue
        if any(
            isinstance(part, ast.Name)
            and audit._resolved_ast_name(part, resolved).split(".", 1)[0] in roots
            for part in ast.walk(target)
        ):
            return False
    parents = {id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)}
    facts = finite_provider_mutation_index(nodes, resolved, audit, parents)
    if not _pickle_serializer_module_uses_closed(nodes, resolved, parents, audit):
        return False
    return not any(
        (owner == root or owner.startswith(root + "."))
        and not (
            attribute == "*"
            and owner in {"pickle", "_pickle", "pickle.HIGHEST_PROTOCOL", "_pickle.HIGHEST_PROTOCOL"}
        )
        for owner, attribute in facts
        for root in {"pickle", "_pickle"}
    )


def _pickle_serializer_module_uses_closed(nodes, resolved, parents, audit):
    for node in nodes:
        if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
            continue
        origin = audit._resolved_ast_name(node, resolved)
        root = origin.split(".", 1)[0]
        if root not in {"pickle", "_pickle", "sys", "importlib", "builtins"}:
            continue
        if origin != root:
            if _pickle_serializer_imported_value_use(origin, parents.get(id(node)), node):
                continue
            return False
        attribute = parents.get(id(node))
        if not isinstance(attribute, ast.Attribute) or attribute.value is not node:
            return False
        owner = parents.get(id(attribute))
        if origin not in {"pickle", "_pickle"}:
            if _pickle_serializer_namespace_data_read(origin, attribute, owner):
                continue
            return False
        if attribute.attr in {"loads", "dumps"} and isinstance(owner, ast.Call) and owner.func is attribute:
            continue
        if attribute.attr == "HIGHEST_PROTOCOL":
            # This integer is data, not a reference to the module or serializer.
            continue
        return False
    return True


def _pickle_serializer_namespace_data_read(origin, attribute, owner):
    """Separate immutable sys metadata from mutable import/serializer capabilities."""
    if origin != "sys":
        return False
    if attribute.attr in {"version_info", "maxsize", "executable"}:
        return True
    if attribute.attr == "getrefcount":
        return isinstance(owner, ast.Call) and owner.func is attribute
    return attribute.attr == "path" and isinstance(owner, ast.Compare)


def _pickle_serializer_imported_value_use(origin, owner, node):
    """From-import aliases retain the capability/data distinction of their origin."""
    if origin in {"pickle.HIGHEST_PROTOCOL", "_pickle.HIGHEST_PROTOCOL",
                  "sys.version_info", "sys.maxsize", "sys.executable"}:
        return True
    if origin == "sys.path":
        return isinstance(owner, ast.Compare)
    return origin in {"pickle.loads", "pickle.dumps", "_pickle.loads", "_pickle.dumps", "sys.getrefcount"} and isinstance(owner, ast.Call) and owner.func is node


def _provider_v3_export_chain(contract, trees, target, binding_occurrences):
    """Resolve a bounded, source-bound from-import chain to the selected class."""
    export = contract["export"]
    path = export["path"]
    symbol = export["symbol"] if target == contract["classes"][0] else target["name"]
    visited = set()
    if not _provider_v3_export_packages_closed(path, target["path"], trees):
        return None
    chain = []
    for _ in range(8):
        key = (path, symbol)
        if key in visited or path not in trees:
            return None
        visited.add(key)
        tree = trees[path]
        if not _provider_v3_reexport_module_closed(tree):
            return None
        chain.append(
            {
                "path": path,
                "symbol": symbol,
                "module": _provider_artifact_module_identity(path),
            }
        )
        step = _provider_v3_export_chain_step(
            path, symbol, target, tree, trees, binding_occurrences
        )
        if step is None:
            return None
        if step[0] == "done":
            return chain
        path, symbol = step[1], step[2]
    return None


def _provider_v3_export_chain_step(
    path, symbol, target, tree, trees, binding_occurrences
):
    matches = binding_occurrences(tree.body, symbol)
    if len(matches) != 1 or matches[0] not in tree.body:
        return None
    binding = matches[0]
    if isinstance(binding, ast.ClassDef):
        return (
            ("done",)
            if _provider_v3_final_export_class(path, symbol, binding, target)
            else None
        )
    if not isinstance(binding, ast.ImportFrom) or any(
        alias.name == "*" for alias in binding.names
    ):
        return None
    aliases = [
        alias for alias in binding.names if (alias.asname or alias.name) == symbol
    ]
    if len(aliases) != 1:
        return None
    next_path = _provider_v3_import_from_path(path, binding, trees)
    return None if next_path is None else ("next", next_path, aliases[0].name)


def _provider_v3_final_export_class(path, symbol, binding, target):
    if path != target["path"] or symbol != target["name"]:
        return False
    digest = hashlib.sha256(
        ast.dump(binding, include_attributes=False).encode()
    ).hexdigest()
    return digest == target["class_ast_sha256"]


def _provider_v3_export_packages_closed(export_path, target_path, trees):
    return _provider_v3_package_initializers_present(
        export_path, trees
    ) and _provider_v3_package_initializers_present(target_path, trees)


def _provider_v3_package_initializers_present(path, trees):
    from pathlib import PurePosixPath

    parts = PurePosixPath(path).parts
    for end in range(1, len(parts)):
        init = PurePosixPath(*parts[:end], "__init__.py").as_posix()
        if init not in trees or not _provider_v3_package_initializer_closed(
            trees[init]
        ):
            return False
    return True


def _provider_v3_package_initializer_closed(tree):
    """Check package search-path and import effects without treating lazy exports as the selected export."""
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(statement, ast.ImportFrom) and any(
            alias.name == "*" for alias in statement.names
        ):
            return False
        for node in ast.walk(statement):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in {
                    "eval",
                    "exec",
                    "globals",
                    "locals",
                    "vars",
                    "setattr",
                    "delattr",
                    "__import__",
                }:
                    return False
                if isinstance(func, ast.Attribute) and func.attr in {
                    "exec_module",
                    "import_module",
                    "reload",
                }:
                    return False
            if (
                isinstance(node, ast.Attribute)
                and node.attr == "__path__"
                and isinstance(node.ctx, (ast.Store, ast.Del))
            ):
                return False
    return True


def _provider_v3_reexport_module_closed(tree):
    """Reject dynamic module namespace mechanisms on a selected import path."""
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and statement.name in {"__getattr__", "__dir__"}:
                return False
            continue
        if isinstance(statement, ast.ImportFrom) and any(
            alias.name == "*" for alias in statement.names
        ):
            return False
        for node in ast.walk(statement):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in {
                    "eval",
                    "exec",
                    "globals",
                    "locals",
                    "vars",
                    "setattr",
                    "delattr",
                    "__import__",
                }:
                    return False
                if isinstance(func, ast.Attribute) and func.attr in {
                    "exec_module",
                    "import_module",
                    "reload",
                }:
                    return False
            if (
                isinstance(node, ast.Attribute)
                and node.attr in {"__dict__", "__path__"}
                and isinstance(node.ctx, (ast.Store, ast.Del))
            ):
                return False
    return True


def _provider_v3_import_from_path(source_path, statement, trees):
    from pathlib import PurePosixPath

    source = PurePosixPath(source_path)
    package = source.parent.parts
    if statement.level:
        if statement.level > len(package) + 1:
            return None
        base = package[: len(package) - statement.level + 1]
    else:
        base = ()
    module_parts = statement.module.split(".") if statement.module else []
    parts = (*base, *module_parts)
    if not parts:
        parts = package
    candidates = [
        PurePosixPath(*parts).with_suffix(".py").as_posix(),
        PurePosixPath(*parts, "__init__.py").as_posix(),
    ]
    matches = [candidate for candidate in candidates if candidate in trees]
    return matches[0] if len(matches) == 1 else None


def _provider_import_target(statement, name, suffix, contract, trees):
    from pathlib import PurePosixPath
    from .credential_role_constructor_provider import binding_occurrences

    export = contract["export"]
    path = PurePosixPath(export["path"])
    module = ".".join(
        path.parent.parts
        if path.name == "__init__.py"
        else (*path.parent.parts, path.stem)
    )
    for alias in statement.names:
        bound = alias.asname or (
            alias.name.split(".")[0]
            if isinstance(statement, ast.Import)
            else alias.name
        )
        if bound != name:
            continue
        if isinstance(statement, ast.Import):
            imported = alias.name if alias.asname else alias.name.split(".")[0]
            return ".".join([imported, *suffix]) == module + "." + export["symbol"]
        if statement.level or not statement.module:
            return False
        imported = ".".join([statement.module, alias.name, *suffix])
        if imported != module + "." + export["symbol"]:
            return False
        if suffix:
            package = statement.module.replace(".", "/") + "/__init__.py"
            tree = trees.get(package)
            preloaded = tree is not None and any(
                isinstance(item, ast.ImportFrom)
                and item.level == 1
                and item.module == alias.name
                and not any(row.name == "*" for row in item.names)
                for item in tree.body
            )
            return (
                tree is not None
                and not binding_occurrences(tree.body, alias.name)
                and (preloaded or not binding_occurrences(tree.body, "__getattr__"))
                and not any(
                    isinstance(item, ast.ImportFrom)
                    and any(row.name == "*" for row in item.names)
                    for item in tree.body
                )
            )
        return True
    return False


def _provider_source_trees(contract, source_bytes):
    trees = {}
    for path, digest in contract["artifacts"].items():
        raw = source_bytes.get(path)
        if (
            not isinstance(raw, bytes)
            or len(raw) > 1_000_000
            or hashlib.sha256(raw).hexdigest() != digest
        ):
            return None
        trees[path] = ast.parse(raw)
    return trees


def _provider_global_callable(scope, tree, parents, selected):
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    child = selected
    while parents.get(child) is not scope and child in parents:
        child = parents[child]
    if child not in scope.body:
        return False
    owner = parents.get(scope)
    return (
        owner is tree or isinstance(owner, ast.ClassDef) and parents.get(owner) is tree
    )


def provider_constructor_binding(
    profile, source_bytes, caller_bytes, call, *, selected_contract_view=None
):
    """Bind a constructor's lexical import only; this is not mutation assurance."""
    try:
        current = provider_analysis_profile(
            profile["analysis_profile"], tuple(profile["contracts"])
        )
        if (
            current != profile
            or not current["conditional"]
            or not isinstance(caller_bytes, bytes)
            or len(caller_bytes) > 1_000_000
        ):
            return None
        contract = _provider_binding_contract(current, selected_contract_view)
        if contract is None:
            return None
        return _provider_constructor_binding_source(
            current, contract, source_bytes, caller_bytes, call
        )
    except (
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
        SyntaxError,
        MemoryError,
        RecursionError,
    ):
        return None


def _provider_binding_contract(profile, selected_contract_view):
    if profile["analysis_profile"] == "trusted-dependencies-v2":
        return _provider_v2_selected_contract(profile, selected_contract_view)
    if selected_contract_view is not None:
        return None
    return profile["contracts"][0]


def _provider_constructor_binding_source(
    profile, contract, source_bytes, caller_bytes, call
):
    from .credential_role_constructor_provider import binding_occurrences

    tree = ast.parse(caller_bytes)
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _fixed_program_span(node) == _fixed_program_span(call)
        and ast.dump(node, include_attributes=False)
        == ast.dump(call, include_attributes=False)
    ]
    if len(matches) != 1:
        return None
    selected = matches[0]
    node, names = selected.func, []
    while isinstance(node, ast.Attribute):
        names.insert(0, node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    scope, parents = _provider_constructor_scope(tree, selected)
    if not _provider_constructor_import_is_closed(
        tree, scope, node.id, parents, selected, binding_occurrences
    ):
        return None
    bindings = binding_occurrences(tree.body, node.id)
    if (
        len(bindings) != 1
        or bindings[0] not in tree.body
        or not isinstance(bindings[0], (ast.Import, ast.ImportFrom))
        or bindings[0].lineno >= scope.lineno
        or any(
            isinstance(item, ast.ImportFrom)
            and any(alias.name == "*" for alias in item.names)
            for item in tree.body
        )
    ):
        return None
    trees = _provider_source_trees(contract, source_bytes)
    target_check = (
        _provider_import_target_v2
        if profile["analysis_profile"] == "trusted-dependencies-v2"
        else _provider_import_target
    )
    if (
        trees is None
        or not _provider_record_export(contract, trees)
        or not target_check(bindings[0], node.id, names, contract, trees)
    ):
        return None
    return {
        "status": "LEXICAL_PROVIDER_BINDING",
        "profile_sha256": profile["profile_sha256"],
        "caller_sha256": hashlib.sha256(caller_bytes).hexdigest(),
        "call_span": _fixed_program_span(selected),
        "export": dict(contract["export"]),
        "mutation_assurance": "NOT_YET_QUALIFIED",
    }


def _provider_constructor_scope(tree, selected):
    parents = {
        child: item for item in ast.walk(tree) for child in ast.iter_child_nodes(item)
    }
    scope = selected
    while scope in parents and not isinstance(
        scope, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        scope = parents[scope]
    return scope, parents


def _provider_constructor_import_is_closed(
    tree, scope, name, parents, selected, binding_occurrences
):
    if (
        not _provider_global_callable(scope, tree, parents, selected)
        or name in _captured_sink_parameter_names(scope)
        or binding_occurrences(scope.body, name)
    ):
        return False
    return True


def _provider_import_target_v2(statement, name, suffix, contract, trees):
    from pathlib import PurePosixPath

    export = contract["export"]
    path = PurePosixPath(export["path"])
    target_module = ".".join(
        path.parent.parts
        if path.name == "__init__.py"
        else (*path.parent.parts, path.stem)
    )
    if not _provider_import_name_matches(
        statement, name, suffix, target_module, export["symbol"]
    ):
        return False
    if not suffix:
        return True
    if (
        not isinstance(statement, ast.ImportFrom)
        or statement.level
        or not statement.module
    ):
        return False
    package_path = statement.module.replace(".", "/") + "/__init__.py"
    target_path = export["path"]
    if package_path not in trees or target_path not in trees:
        return False
    return _provider_v2_preload_path(
        package_path, target_path, trees
    ) and _provider_v2_target_binding_stable(package_path, target_path, trees)


def _provider_import_name_matches(statement, name, suffix, target_module, symbol):
    for alias in statement.names:
        bound = alias.asname or (
            alias.name.split(".")[0]
            if isinstance(statement, ast.Import)
            else alias.name
        )
        if bound != name:
            continue
        if isinstance(statement, ast.Import):
            imported = alias.name if alias.asname else alias.name.split(".")[0]
            return ".".join([imported, *suffix]) == target_module + "." + symbol
        if statement.level or not statement.module:
            return False
        return (
            ".".join([statement.module, alias.name, *suffix])
            == target_module + "." + symbol
        )
    return False


def _provider_v2_preload_path(package_path, target_path, trees):
    from pathlib import PurePosixPath

    pending, visited = [package_path], set()
    while pending:
        parent_path = pending.pop(0)
        if parent_path in visited:
            continue
        visited.add(parent_path)
        tree = trees.get(parent_path)
        if tree is None:
            continue
        for statement in tree.body:
            imported = _provider_v2_top_level_imports(statement, parent_path)
            for child_path in imported:
                if child_path not in trees or not _provider_v2_child_binding_stable(
                    tree, statement, PurePosixPath(child_path).stem
                ):
                    continue
                if child_path == target_path:
                    return True
                pending.append(child_path)
    return False


def _provider_v2_top_level_imports(statement, source_path):
    from pathlib import PurePosixPath

    path = PurePosixPath(source_path)
    package = path.parent if path.name == "__init__.py" else path.parent
    if (
        not isinstance(statement, ast.ImportFrom)
        or statement.level != 1
        or not statement.module
        or any(alias.name == "*" for alias in statement.names)
    ):
        return []
    module = ".".join((*package.parts, *statement.module.split(".")))
    child_name = statement.module.split(".")[-1]
    paths = []
    candidate = module.replace(".", "/") + ".py"
    init_candidate = module.replace(".", "/") + "/__init__.py"
    if child_name.isidentifier():
        paths.extend((candidate, init_candidate))
    return paths


def _provider_v2_child_binding_stable(tree, import_statement, child_name):
    return import_statement in tree.body and _provider_v2_child_name_stable(
        tree, child_name
    )


def _provider_v2_child_name_stable(tree, child_name):
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id == child_name
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            return False
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == child_name
        ):
            return False
        if isinstance(node, ast.Import):
            if any(
                (alias.asname or alias.name.split(".")[0]) == child_name
                for alias in node.names
            ):
                return False
        if isinstance(node, ast.ImportFrom) and any(
            alias.name == "*" or (alias.asname or alias.name) == child_name
            for alias in node.names
        ):
            return False
    return True


def _provider_v2_target_binding_stable(package_path, target_path, trees):
    from pathlib import PurePosixPath

    package_parts = PurePosixPath(package_path).parent.parts
    target_parts = PurePosixPath(target_path)
    target_parent = target_parts.parent.parts
    if target_parent[: len(package_parts)] != package_parts:
        return False
    current = list(package_parts)
    for part in target_parent[len(package_parts) :]:
        parent_init = "/".join((*current, "__init__.py"))
        parent_tree = trees.get(parent_init)
        if parent_tree is not None and not _provider_v2_child_name_stable(
            parent_tree, part
        ):
            return False
        current.append(part)
    parent_init = "/".join((*target_parent, "__init__.py"))
    parent_tree = trees.get(parent_init)
    return parent_tree is not None and _provider_v2_child_name_stable(
        parent_tree, target_parts.stem
    )


def _provider_record_value(node, environment):
    if isinstance(node, ast.Name) and node.id in environment:
        return environment[node.id]
    if isinstance(node, ast.Tuple):
        return tuple(_provider_record_value(item, environment) for item in node.elts)
    if _fixed_literal_value(node):
        return ast.literal_eval(node)
    raise ValueError("unclosed exception record value")


def _provider_record_block(body, environment, fields, receiver, remaining):
    for statement in body:
        remaining[0] -= 1
        if remaining[0] < 0:
            raise ValueError("exception record state budget exhausted")
        if isinstance(statement, ast.If):
            condition = statement.test
            if (
                not isinstance(condition, ast.Compare)
                or len(condition.ops) != 1
                or not isinstance(condition.ops[0], (ast.Is, ast.IsNot))
                or len(condition.comparators) != 1
                or not isinstance(condition.comparators[0], ast.Constant)
                or condition.comparators[0].value is not None
            ):
                raise ValueError("unsupported exception constructor branch")
            selected = _provider_record_value(condition.left, environment) is None
            if isinstance(condition.ops[0], ast.IsNot):
                selected = not selected
            _provider_record_block(
                statement.body if selected else statement.orelse,
                environment,
                fields,
                receiver,
                remaining,
            )
        elif isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target, value = (
                statement.targets[0],
                _provider_record_value(statement.value, environment),
            )
            if isinstance(target, ast.Name) and target.id != receiver:
                environment[target.id] = value
            elif (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == receiver
                and not target.attr.startswith("__")
            ):
                fields[target.attr] = value
            else:
                raise ValueError("unsupported exception constructor store")
        elif not (
            isinstance(statement, ast.Pass)
            or isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and type(statement.value.value) is str
        ):
            raise ValueError("unsupported exception constructor effect")


def _provider_record_state(constructor, call):
    from . import _bind_source_call
    from .review_integrity import _function_annotations, _lexical_nodes

    if (
        constructor.args.posonlyargs
        or constructor.args.vararg
        or constructor.args.kwarg
        or not constructor.args.args
    ):
        raise ValueError("unsupported exception constructor signature")
    if any(
        isinstance(
            node, (ast.Yield, ast.YieldFrom, ast.Await, ast.Global, ast.Nonlocal)
        )
        for node in _lexical_nodes(constructor)
    ):
        raise ValueError("unsupported lexical exception constructor semantics")
    if any(
        value is not None and not _fixed_literal_value(value)
        for value in [*constructor.args.defaults, *constructor.args.kw_defaults]
    ):
        raise ValueError("unsupported exception constructor default")
    if any(
        isinstance(node, (ast.Call, ast.NamedExpr))
        for annotation in _function_annotations(constructor)
        for node in ast.walk(annotation)
    ):
        raise ValueError("unsupported definition-time annotation effect")
    bound = _bind_source_call(call, constructor, receiver=ast.Constant(value=None))
    receiver = constructor.args.args[0].arg
    environment = {
        name: _provider_record_value(value, {})
        for name, value in bound.items()
        if name != receiver
    }
    fields = {}
    _provider_record_block(constructor.body, environment, fields, receiver, [512])
    if not isinstance(fields.get("args"), tuple):
        raise ValueError("exception reconstruction arguments are unresolved")
    return fields


def _provider_v2_class_chain(contract, trees):
    from .credential_role_constructor_provider import binding_occurrences

    rows = contract["classes"]
    if not 1 <= len(rows) <= 8:
        return None
    chain = []
    for index, row in enumerate(rows):
        tree = trees[row["path"]]
        item = _provider_v2_class_row(
            row, index, rows, chain, tree, binding_occurrences
        )
        if item is None:
            return None
        chain.append(item)
    if binding_occurrences(trees[rows[-1]["path"]].body, "Exception"):
        return None
    return chain


def _provider_v2_class_row(row, index, rows, chain, tree, binding_occurrences):
    matches = binding_occurrences(tree.body, row["name"])
    if (
        len(matches) != 1
        or not isinstance(matches[0], ast.ClassDef)
        or matches[0] not in tree.body
    ):
        return None
    cls = matches[0]
    if index and (
        row["path"] != rows[0]["path"] or cls.lineno >= chain[index - 1]["class"].lineno
    ):
        return None
    parent_name = rows[index + 1]["name"] if index + 1 < len(rows) else "Exception"
    if (
        cls.decorator_list
        or cls.keywords
        or len(cls.bases) != 1
        or not isinstance(cls.bases[0], ast.Name)
        or cls.bases[0].id != parent_name
    ):
        return None
    if (
        hashlib.sha256(ast.dump(cls, include_attributes=False).encode()).hexdigest()
        != row["class_ast_sha256"]
    ):
        return None
    valid_members, constructor = _provider_v2_class_members(cls)
    if not valid_members:
        return None
    digest = (
        hashlib.sha256(
            ast.dump(constructor, include_attributes=False).encode()
        ).hexdigest()
        if constructor is not None
        else None
    )
    if digest != row["constructor_ast_sha256"] or index == 0 and constructor is None:
        return None
    return {
        "class": cls,
        "path": row["path"],
        "name": row["name"],
        "init": constructor,
        "tree": tree,
    }


def _provider_v2_class_members(cls):
    from .review_integrity import _function_annotations

    methods = {}
    for statement in cls.body:
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and type(statement.value.value) is str
            or isinstance(statement, ast.Pass)
        ):
            continue
        if isinstance(statement, ast.Assign):
            if (
                len(statement.targets) != 1
                or not isinstance(statement.targets[0], ast.Name)
                or statement.targets[0].id == "args"
                or statement.targets[0].id.startswith("__")
                or not _provider_v2_class_value(statement.value)
            ):
                return False, None
            continue
        if isinstance(statement, ast.AnnAssign):
            if (
                not isinstance(statement.target, ast.Name)
                or statement.target.id.startswith("__")
                or statement.value is not None
                or _provider_v2_header_effect(statement.annotation)
            ):
                return False, None
            continue
        if not isinstance(statement, ast.FunctionDef) or statement.name not in {
            "__init__",
            "__str__",
            "__repr__",
        }:
            return False, None
        if (
            not _provider_v2_method_header_supported(
                statement, _function_annotations(statement)
            )
            or statement.name in methods
        ):
            return False, None
        methods[statement.name] = statement
    return True, methods.get("__init__")


def _provider_v2_method_header_supported(method, annotations):
    if (
        method.decorator_list
        or method.args.posonlyargs
        or method.args.vararg
        or method.args.kwarg
    ):
        return False
    if method.name == "__init__":
        if not method.args.args:
            return False
    elif (
        len(method.args.args) != 1
        or method.args.args[0].arg != "self"
        or method.args.kwonlyargs
    ):
        return False
    defaults = [*method.args.defaults, *method.args.kw_defaults]
    return not any(
        default is not None and not _fixed_literal_value(default)
        for default in defaults
    ) and not any(_provider_v2_header_effect(annotation) for annotation in annotations)


def _provider_v2_class_value(node):
    if sum(1 for _ in ast.walk(node)) > 512 or not _fixed_literal_value(node):
        return False
    return _provider_v2_immutable_value(ast.literal_eval(node))


def _provider_v2_immutable_value(value):
    if type(value) is str:
        return _provider_v2_text_size(value) is not None
    if type(value) is bytes:
        return len(value) <= 16_384
    if type(value) is int:
        return value.bit_length() <= 4_096
    if type(value) in {float, bool, type(None)}:
        return True
    return (
        type(value) is tuple
        and len(value) <= 64
        and all(_provider_v2_immutable_value(item) for item in value)
    )


def _provider_v2_header_effect(node):
    return node is not None and any(
        isinstance(
            item,
            (ast.Call, ast.NamedExpr, ast.Lambda, ast.Await, ast.Yield, ast.YieldFrom),
        )
        for item in ast.walk(node)
    )


def _provider_v2_value(node, environment, fields, receiver, remaining):
    remaining[0] -= 1
    if remaining[0] < 0:
        raise ValueError("provider reconstruction state budget exhausted")
    if isinstance(node, ast.Name) and node.id in environment:
        return environment[node.id]
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == receiver
        and node.attr in fields
    ):
        return fields[node.attr]
    if isinstance(node, ast.Tuple):
        return tuple(
            _provider_v2_value(item, environment, fields, receiver, remaining)
            for item in node.elts
        )
    if isinstance(node, ast.JoinedStr):
        return _provider_v2_fstring(node, environment, fields, receiver, remaining)
    if isinstance(node, (ast.List, ast.Dict, ast.Set)):
        raise ValueError("mutable provider literals are unsupported")
    if _fixed_literal_value(node):
        value = ast.literal_eval(node)
        if not _provider_v2_immutable_value(value):
            raise ValueError("provider scalar exceeds the bounded value model")
        return value
    raise ValueError("unclosed provider reconstruction value")


def _provider_v2_text_size(value):
    if len(value) > 16_384:
        return None
    size = 0
    for char in value:
        codepoint = ord(char)
        size += (
            1
            if codepoint <= 0x7F
            else 2
            if codepoint <= 0x7FF
            else 3
            if codepoint <= 0xFFFF
            else 4
        )
        if size > 16_384:
            return None
    return size


def _provider_v2_fstring(node, environment, fields, receiver, remaining):
    rendered = []
    total_size = 0
    for item in node.values:
        if isinstance(item, ast.Constant) and type(item.value) is str:
            piece = item.value
        elif isinstance(item, ast.FormattedValue) and item.format_spec is None:
            value = _provider_v2_value(
                item.value, environment, fields, receiver, remaining
            )
            if type(value) not in {
                str,
                bytes,
                int,
                float,
                bool,
                type(None),
            } or item.conversion not in {-1, 114, 115}:
                raise ValueError("unsupported provider f-string value")
            piece = repr(value) if item.conversion == 114 else str(value)
        else:
            raise ValueError("unsupported provider f-string expression")
        piece_size = _provider_v2_text_size(piece)
        if piece_size is None or total_size + piece_size > 16_384:
            raise ValueError("provider f-string output exceeds the bounded value model")
        total_size += piece_size
        rendered.append(piece)
    return "".join(rendered)


def _provider_v2_ast_value(value):
    if value is None or type(value) in {str, bytes, int, float, bool}:
        return ast.Constant(value=value)
    if type(value) is tuple:
        return ast.Tuple(
            elts=[_provider_v2_ast_value(item) for item in value], ctx=ast.Load()
        )
    raise ValueError("provider replay value is not a closed literal")


def _provider_v2_initializer_call(initializer, args, keywords):
    call = ast.Call(
        func=ast.Name(id="_provider_constructor", ctx=ast.Load()),
        args=[_provider_v2_ast_value(value) for value in args],
        keywords=[
            ast.keyword(arg=name, value=_provider_v2_ast_value(value))
            for name, value in keywords.items()
        ],
    )
    return call


def _provider_v2_super_call(statement, initializer, module_tree):
    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return None
    call = statement.value
    func = call.func
    if (
        not isinstance(func, ast.Attribute)
        or func.attr != "__init__"
        or not isinstance(func.value, ast.Call)
        or not isinstance(func.value.func, ast.Name)
        or func.value.func.id != "super"
        or func.value.args
        or func.value.keywords
    ):
        return None
    from .credential_role_constructor_provider import binding_occurrences

    if (
        binding_occurrences(module_tree.body, "super")
        or binding_occurrences(initializer.body, "super")
        or any(
            argument.arg == "super"
            for argument in (
                *initializer.args.posonlyargs,
                *initializer.args.args,
                *initializer.args.kwonlyargs,
            )
        )
    ):
        return None
    return call


def _provider_v2_call_values(call, environment, fields, receiver, remaining):
    args = [
        _provider_v2_value(node, environment, fields, receiver, remaining)
        for node in call.args
    ]
    keywords = {}
    for keyword in call.keywords:
        if keyword.arg is None or keyword.arg in keywords:
            raise ValueError("unsupported delegated constructor keywords")
        keywords[keyword.arg] = _provider_v2_value(
            keyword.value, environment, fields, receiver, remaining
        )
    return args, keywords


def _provider_v2_run_block(
    body, chain, index, environment, fields, receiver, module_tree, remaining
):
    for statement in body:
        remaining[0] -= 1
        if remaining[0] < 0:
            raise ValueError("provider reconstruction state budget exhausted")
        _provider_v2_run_statement(
            statement,
            chain,
            index,
            environment,
            fields,
            receiver,
            module_tree,
            remaining,
        )


def _provider_v2_run_statement(
    statement, chain, index, environment, fields, receiver, module_tree, remaining
):
    if isinstance(statement, ast.If):
        branch = _provider_v2_selected_branch(
            statement, environment, fields, receiver, remaining
        )
        _provider_v2_run_block(
            branch, chain, index, environment, fields, receiver, module_tree, remaining
        )
        return
    if isinstance(statement, ast.Assign):
        _provider_v2_assignment(statement, environment, fields, receiver, remaining)
        return
    if (
        isinstance(statement, ast.Pass)
        or isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and type(statement.value.value) is str
    ):
        return
    delegated = (
        _provider_v2_super_call(statement, chain[index]["init"], module_tree)
        if chain[index]["init"]
        else None
    )
    if delegated is None:
        raise ValueError("unsupported provider constructor effect")
    args, keywords = _provider_v2_call_values(
        delegated, environment, fields, receiver, remaining
    )
    _provider_v2_run_parent(
        chain, index + 1, args, keywords, fields, module_tree, remaining
    )


def _provider_v2_selected_branch(statement, environment, fields, receiver, remaining):
    test = statement.test
    if (
        not isinstance(test, ast.Compare)
        or len(test.ops) != 1
        or not isinstance(test.ops[0], (ast.Is, ast.IsNot))
        or len(test.comparators) != 1
        or not isinstance(test.comparators[0], ast.Constant)
        or test.comparators[0].value is not None
    ):
        raise ValueError("unsupported provider constructor condition")
    selected = (
        _provider_v2_value(test.left, environment, fields, receiver, remaining) is None
    )
    if isinstance(test.ops[0], ast.IsNot):
        selected = not selected
    return statement.body if selected else statement.orelse


def _provider_v2_assignment(statement, environment, fields, receiver, remaining):
    if len(statement.targets) != 1:
        raise ValueError("unsupported provider constructor assignment")
    target = statement.targets[0]
    value = _provider_v2_value(
        statement.value, environment, fields, receiver, remaining
    )
    if isinstance(target, ast.Name) and target.id != receiver:
        environment[target.id] = value
        return
    if (
        isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name)
        and target.value.id == receiver
        and not target.attr.startswith("__")
    ):
        fields[target.attr] = value
        return
    raise ValueError("unsupported provider constructor assignment")


def _provider_v2_run_parent(
    chain, start, args, keywords, fields, module_tree, remaining
):
    from . import _bind_source_call

    parent_index = next(
        (i for i in range(start, len(chain)) if chain[i]["init"] is not None), None
    )
    if parent_index is None:
        if keywords:
            raise ValueError("BaseException delegation with keywords is unsupported")
        fields["args"] = tuple(args)
        return
    initializer = chain[parent_index]["init"]
    call = _provider_v2_initializer_call(initializer, args, keywords)
    bound = _bind_source_call(call, initializer, receiver=ast.Constant(value=None))
    receiver = initializer.args.args[0].arg
    environment = {
        name: _provider_v2_value(value, {}, fields, receiver, remaining)
        for name, value in bound.items()
        if name != receiver
    }
    _provider_v2_run_block(
        initializer.body,
        chain,
        parent_index,
        environment,
        fields,
        receiver,
        module_tree,
        remaining,
    )


def _provider_v2_construct(chain, call, initial_args, remaining):
    from . import _bind_source_call

    initializer = chain[0]["init"]
    bound = _bind_source_call(call, initializer, receiver=ast.Constant(value=None))
    receiver = initializer.args.args[0].arg
    fields = {"args": tuple(initial_args)}
    environment = {
        name: _provider_v2_value(value, {}, fields, receiver, remaining)
        for name, value in bound.items()
        if name != receiver
    }
    _provider_v2_run_block(
        initializer.body,
        chain,
        0,
        environment,
        fields,
        receiver,
        chain[0]["tree"],
        remaining,
    )
    return fields


def _provider_v2_instance_state_walk(value, remaining, depth):
    remaining[0] -= 1
    if remaining[0] < 0 or depth > 8:
        return False
    if type(value) is str:
        return _provider_v2_text_size(value) is not None
    if type(value) is bytes:
        return len(value) <= 16_384
    if type(value) is int:
        return value.bit_length() <= 4_096
    if type(value) in {float, bool, type(None)}:
        return True
    return (
        type(value) is tuple
        and len(value) <= 64
        and all(
            _provider_v2_instance_state_walk(item, remaining, depth + 1)
            for item in value
        )
    )


def _provider_record_state_v2(chain, contract, call, instance_state):
    if not isinstance(call, ast.Call) or any(
        keyword.arg is None for keyword in call.keywords
    ):
        raise ValueError("v2 leaf reconstruction requires a closed constructor call")
    instance_cost = _provider_v2_instance_state_cost(instance_state)
    if instance_cost is None:
        raise ValueError("v2 instance BUILD state is not a bounded mapping")
    remaining = [512 - instance_cost]
    args = tuple(
        _provider_v2_value(item, {}, {}, "self", remaining) for item in call.args
    )
    constructor_fields = _provider_v2_construct(chain, call, args, remaining)
    reduced_args = constructor_fields.get("args")
    if not isinstance(reduced_args, tuple):
        raise ValueError("v2 BaseException args are unresolved")
    state = {key: value for key, value in constructor_fields.items() if key != "args"}
    state.update(instance_state)
    build_state = dict(state)
    reconstructed_call = ast.Call(
        func=ast.Name(id=contract["classes"][0]["name"], ctx=ast.Load()),
        args=[_provider_v2_ast_value(value) for value in reduced_args],
        keywords=[],
    )
    replay = _provider_v2_construct(chain, reconstructed_call, reduced_args, remaining)
    replay_state = {key: value for key, value in replay.items() if key != "args"}
    replay_state.update(build_state)
    if replay.get("args") != reduced_args or replay_state != build_state:
        raise ValueError("provider reconstruction replay mismatch")
    return {
        "args": reduced_args,
        "state": state,
        "build_state": build_state,
        "reconstruction": {
            "kind": "BaseException_ARGS_THEN_BUILD",
            "args": reduced_args,
        },
    }


def provider_exception_record(
    profile,
    source_bytes,
    call,
    *,
    selected_contract_view=None,
    instance_state=None,
    source_path=None,
):
    """Model one conditional constructor/reconstruction; not byte-flow admission."""
    if (
        not isinstance(profile, dict)
        or profile.get("analysis_profile")
        not in {"trusted-dependencies-v1", "trusted-dependencies-v2"}
        or not isinstance(source_bytes, dict)
    ):
        return None
    try:
        current = provider_analysis_profile(
            profile["analysis_profile"], tuple(profile["contracts"])
        )
        if current != profile:
            return None
        if current["analysis_profile"] == "trusted-dependencies-v2":
            return _provider_exception_record_v2(
                current,
                source_bytes,
                call,
                selected_contract_view,
                instance_state,
                source_path,
            )
        return _provider_exception_record_v1(
            current, source_bytes, call, selected_contract_view
        )
    except (
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
        SyntaxError,
        MemoryError,
        RecursionError,
    ):
        return None


def _provider_exception_record_v1(profile, source_bytes, call, selected_contract_view):
    if selected_contract_view is not None:
        return None
    contract = profile["contracts"][0]
    trees = _provider_source_trees(contract, source_bytes)
    if trees is None:
        return None
    constructor = _provider_record_classes(contract, trees)
    if constructor is None or not _provider_record_export(contract, trees):
        return None
    fields = _provider_record_state(constructor, call)
    reconstructed = ast.Call(
        func=ast.Name(id=contract["classes"][0]["name"], ctx=ast.Load()),
        args=[ast.parse(repr(value), mode="eval").body for value in fields["args"]],
        keywords=[],
    )
    _provider_record_state(constructor, reconstructed)
    return {
        "analysis_profile": profile["analysis_profile"],
        "profile_sha256": profile["profile_sha256"],
        "contract_sha256": profile["contract_sha256"],
        "model_sha256": profile["model_sha256"],
        "assurance": "CONDITIONAL_PROVIDER_CONTRACT",
        "args": fields["args"],
        "state": fields,
    }


def _provider_exception_record_v2(
    profile,
    source_bytes,
    call,
    selected_contract_view,
    instance_state,
    source_path=None,
):
    contract = _provider_v2_selected_contract(profile, selected_contract_view)
    if contract is None:
        return None
    trees = _provider_source_trees(contract, source_bytes)
    if trees is None or not _provider_record_export(contract, trees):
        return None
    instance_state = {} if instance_state is None else instance_state
    fields = _provider_v2_model_record(
        contract,
        trees,
        call,
        instance_state,
        profile=profile,
        source_bytes=source_bytes,
        source_path=source_path,
        selected_contract_view=selected_contract_view,
    )
    if fields is None:
        return None
    return {
        "analysis_profile": profile["analysis_profile"],
        "profile_sha256": profile["profile_sha256"],
        "contract_set_sha256": profile["contract_set_sha256"],
        "selected_contract_sha256": selected_contract_view["selected_contract_sha256"],
        "selected_model_sha256": selected_contract_view["selected_model_sha256"],
        "model_sha256": profile["model_sha256"],
        "assurance": "PROVISIONAL_PROVIDER_RECONSTRUCTION",
        "requires_initialized_provider_witness": True,
        **fields,
    }


def _provider_v2_model_record(
    contract,
    trees,
    call,
    instance_state,
    *,
    profile=None,
    source_bytes=None,
    source_path=None,
    selected_contract_view=None,
):
    if contract["model"] == {
        "id": _PROVIDER_MODEL_V3["id"],
        "version": _PROVIDER_MODEL_V3["version"],
    }:
        return _provider_v3_model_record(
            contract,
            trees,
            call,
            instance_state,
            profile=profile,
            source_bytes=source_bytes,
            source_path=source_path,
            selected_contract_view=selected_contract_view,
        )
    if not _provider_v2_instance_state_map(instance_state):
        return None
    if contract["model"]["id"] == _PROVIDER_MODEL_V2["id"]:
        chain = _provider_v2_class_chain(contract, trees)
        return (
            None
            if chain is None
            else _provider_record_state_v2(chain, contract, call, instance_state)
        )
    constructor = _provider_record_classes(contract, trees)
    if constructor is None:
        return None
    legacy_fields = _provider_record_state(constructor, call)
    reduced_call = ast.Call(
        func=ast.Name(id=contract["classes"][0]["name"], ctx=ast.Load()),
        args=[
            ast.parse(repr(value), mode="eval").body for value in legacy_fields["args"]
        ],
        keywords=[],
    )
    replay_fields = _provider_record_state(constructor, reduced_call)
    if replay_fields is None:
        raise ValueError("legacy provider reconstruction replay failed")
    state = {key: value for key, value in legacy_fields.items() if key != "args"}
    state.update(instance_state)
    return {
        "args": legacy_fields["args"],
        "state": state,
        "build_state": dict(state),
        "reconstruction": {
            "kind": "BaseException_ARGS_THEN_BUILD",
            "args": legacy_fields["args"],
        },
    }


def _provider_v3_model_record(
    contract,
    trees,
    call,
    instance_state,
    *,
    profile,
    source_bytes,
    source_path,
    selected_contract_view,
):
    context = _provider_v3_model_context(
        contract,
        trees,
        call,
        profile,
        source_bytes,
        source_path,
        selected_contract_view,
    )
    if context is None:
        return None
    state = _provider_v3_constructed_state(
        context,
        instance_state,
        source_path,
    )
    if state is None:
        return None
    return _provider_v3_graph_record(
        contract, context, state, source_bytes, source_path, selected_contract_view
    )


def _provider_v3_model_context(
    contract, trees, call, profile, source_bytes, source_path, selected_contract_view
):
    if not isinstance(source_path, str) or not isinstance(source_bytes, dict):
        return None
    caller_bytes = source_bytes.get(source_path)
    if not isinstance(caller_bytes, bytes) or len(caller_bytes) > 1_000_000:
        return None
    caller_tree = ast.parse(caller_bytes)
    root_call = _provider_v3_source_call(call, caller_tree)
    if root_call is None or not isinstance(root_call.func, ast.Name):
        return None
    binding = provider_constructor_binding(
        profile,
        source_bytes,
        caller_bytes,
        root_call,
        selected_contract_view=selected_contract_view,
    )
    if binding is None or binding["export"] != contract["export"]:
        return None
    classes = _provider_v3_class_models(contract, trees)
    if classes is None:
        return None
    root_row, root_model = classes[0]
    if root_call.func.id != root_row["name"] or root_model["kind"] != "exception":
        return None
    scope, _ = _provider_constructor_scope(caller_tree, root_call)
    enum_aliases = _provider_v3_caller_enum_aliases(
        contract, trees, caller_tree, scope, classes
    )
    if enum_aliases is None:
        return None
    return {
        "caller_tree": caller_tree,
        "root_call": root_call,
        "binding": binding,
        "classes": classes,
        "root_row": root_row,
        "root_model": root_model,
        "enum_aliases": enum_aliases,
        "source_path": source_path,
        "selected_contract_view": selected_contract_view,
    }


def _provider_v3_constructed_state(context, instance_state, source_path):
    root_model = context["root_model"]
    root_call = context["root_call"]
    enum_aliases = context["enum_aliases"]
    remaining = [512]
    enum_leaf_uses = []
    init = root_model["init"]
    from .review_integrity import _function_annotations

    if init is None or not _provider_v3_method_header_supported(
        init, _function_annotations(init)
    ):
        return None
    from . import _bind_source_call

    bound = _bind_source_call(root_call, init, receiver=ast.Constant(value=None))
    environment = {}
    for name, value_node in bound.items():
        if name == init.args.args[0].arg:
            continue
        environment[name] = _provider_v3_value(
            value_node,
            environment,
            enum_aliases,
            remaining,
            0,
            source_path,
            enum_leaf_uses,
        )
    constructed = _provider_v3_run_initializer(
        init,
        environment,
        enum_aliases,
        remaining,
        source_path,
        enum_leaf_uses,
        root_model["tree"],
    )
    if constructed is None:
        return None
    args, constructor_state = constructed
    if (
        len(args) != len(init.args.args) - 1
        or init.args.kwonlyargs
        or init.args.vararg
        or init.args.kwarg
    ):
        return None
    state = dict(constructor_state)
    if not _provider_v3_external_instance_state(
        instance_state, state, enum_aliases, remaining, source_path, enum_leaf_uses
    ):
        return None
    replay_environment = {
        argument.arg: value for argument, value in zip(init.args.args[1:], args)
    }
    replay = _provider_v3_run_initializer(
        init,
        replay_environment,
        enum_aliases,
        remaining,
        source_path,
        enum_leaf_uses,
        root_model["tree"],
    )
    if replay is None or replay[0] != args or replay[1] != constructor_state:
        return None
    if _provider_v3_instance_aliases(args, state):
        return None
    return {
        "args": args,
        "state": state,
        "enum_leaf_uses": enum_leaf_uses,
        "remaining": remaining,
        "initializer_use": {
            "source_path": context["root_row"]["path"],
            "class_name": context["root_row"]["name"],
            "class_ast_sha256": context["root_row"]["class_ast_sha256"],
            "method_name": "__init__",
            "span": _provider_v3_span(init),
            "ast_sha256": hashlib.sha256(
                ast.dump(init, include_attributes=False).encode()
            ).hexdigest(),
        },
    }


def _provider_v3_graph_record(
    contract, context, state_data, source_bytes, source_path, selected_contract_view
):
    root_row = context["root_row"]
    args = state_data["args"]
    state = state_data["state"]
    enum_leaf_uses = state_data["enum_leaf_uses"]
    source_hashes = {
        path: hashlib.sha256(source_bytes[path]).hexdigest()
        for path in sorted(set(contract["artifacts"]) | {source_path})
        if isinstance(source_bytes.get(path), bytes)
    }
    if len(source_hashes) != len(set(contract["artifacts"]) | {source_path}):
        return None
    export_chains = []
    for row, _ in context["classes"]:
        chain = provider_export_chain_v3(contract, source_bytes, class_row=row)
        if chain is None:
            return None
        export_chains.append(
            {"class_path": row["path"], "class_name": row["name"], "chain": chain}
        )
    graph_budget, graph_seen = [512], set()
    graph_budget[0] -= 1  # source-bound instance root
    args_nodes = [
        _provider_v3_graph_node(value, graph_budget, 0, graph_seen) for value in args
    ]
    state_nodes = {
        name: _provider_v3_graph_node(value, graph_budget, 0, graph_seen)
        for name, value in sorted(state.items())
    }
    enum_leaf_uses = _provider_v3_deduplicate_enum_uses(enum_leaf_uses)
    initializer_uses = [state_data["initializer_use"]]
    display_method_uses = []
    display_method = context["root_model"].get("display_method")
    if display_method is not None:
        display_method_uses.append(display_method)
    from .runtime_audit_common import canonical_bytes

    graph = {
        "schema": "factory.typed-pickle-graph.v3",
        "model": dict(_PROVIDER_MODEL_V3),
        "model_sha256": hashlib.sha256(canonical_bytes(_PROVIDER_MODEL_V3)).hexdigest(),
        "selected_contract_sha256": selected_contract_view["selected_contract_sha256"],
        "selected_model_sha256": selected_contract_view["selected_model_sha256"],
        "source_hashes": source_hashes,
        "export_chains": export_chains,
        "enum_leaf_uses": enum_leaf_uses,
        "initializer_uses": initializer_uses,
        "display_method_uses": display_method_uses,
        "root": {
            "tag": "instance",
            "type": {
                "module": _provider_artifact_module_identity(root_row["path"]),
                "qualname": root_row["name"],
                "class_ast_sha256": root_row["class_ast_sha256"],
            },
            "args": args_nodes,
            "state": state_nodes,
            "reconstruction": {
                "kind": "BaseException_ARGS_THEN_BUILD",
                "constructor_module": _provider_artifact_module_identity(
                    root_row["path"]
                ),
                "constructor_qualname": root_row["name"],
                "args_ref": "root.args",
                "build_state_ref": "root.state",
            },
        },
    }
    graph_sha256 = hashlib.sha256(canonical_bytes(graph)).hexdigest()
    return {
        "args": tuple(args_nodes),
        "state": state_nodes,
        "build_state": dict(state_nodes),
        "reconstruction": {
            "kind": "BaseException_ARGS_THEN_BUILD",
            "args": tuple(args_nodes),
        },
        "typed_graph": graph,
        "typed_graph_sha256": graph_sha256,
        "enum_leaf_uses": enum_leaf_uses,
        "initializer_uses": initializer_uses,
        "display_method_uses": display_method_uses,
        "export_chains": export_chains,
        "export_chain": export_chains[0]["chain"],
    }


def _provider_v3_source_call(call, caller_tree):
    if not isinstance(call, ast.AST):
        return None
    span = _provider_v3_span(call)
    matches = [
        node
        for node in ast.walk(caller_tree)
        if _provider_v3_source_call_matches(node, call, span)
    ]
    if len(matches) == 1 and isinstance(matches[0], ast.Call):
        return matches[0]
    return _provider_v3_source_name_call(call, matches, caller_tree)


def _provider_v3_source_name_call(call, matches, caller_tree):
    if isinstance(call, ast.Name) and len(matches) == 1:
        scope, _ = _provider_constructor_scope(caller_tree, matches[0])
        if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        candidates = []
        nodes = list(_provider_v3_scope_nodes(scope))
        stores = [
            node
            for node in nodes
            if isinstance(node, ast.Name)
            and node.id == call.id
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ]
        if len(stores) != 1:
            return None
        for node in nodes:
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == call.id
                and node.lineno < matches[0].lineno
            ):
                candidates.append(node.value)
            elif isinstance(
                node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr, ast.Delete)
            ):
                targets = (
                    node.targets
                    if isinstance(node, ast.Delete)
                    else [getattr(node, "target", None)]
                )
                if any(
                    isinstance(target, ast.Name) and target.id == call.id
                    for target in targets
                ):
                    return None
        if len(candidates) == 1 and isinstance(candidates[0], ast.Call):
            return candidates[0]
    return None


def _provider_v3_source_call_matches(node, call, span):
    return (
        isinstance(node, type(call))
        and _provider_v3_span(node) == span
        and ast.dump(node, include_attributes=False)
        == ast.dump(call, include_attributes=False)
    )


def _provider_v3_scope_nodes(scope):
    pending = list(scope.body)
    while pending:
        node = pending.pop()
        yield node
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        pending.extend(ast.iter_child_nodes(node))


def _provider_v3_span(node):
    return [
        getattr(node, "lineno", None),
        getattr(node, "col_offset", None),
        getattr(node, "end_lineno", None),
        getattr(node, "end_col_offset", None),
    ]


def _provider_v3_class_models(contract, trees):
    rows = contract.get("classes")
    if not isinstance(rows, list) or not 2 <= len(rows) <= 8:
        return None
    models = []
    enum_count = 0
    for index, row in enumerate(rows):
        model = _provider_v3_class_model(row, trees.get(row["path"]), index)
        if model is None:
            return None
        enum_count += model["kind"] == "int_enum"
        models.append((row, model))
    return models if enum_count else None


def _provider_v3_class_model(row, tree, index):
    from .credential_role_constructor_provider import binding_occurrences

    if tree is None:
        return None
    matches = binding_occurrences(tree.body, row["name"])
    if (
        len(matches) != 1
        or not isinstance(matches[0], ast.ClassDef)
        or matches[0] not in tree.body
    ):
        return None
    cls = matches[0]
    digest = hashlib.sha256(
        ast.dump(cls, include_attributes=False).encode()
    ).hexdigest()
    if cls.decorator_list or cls.keywords or digest != row["class_ast_sha256"]:
        return None
    methods = [item for item in cls.body if isinstance(item, ast.FunctionDef)]
    constructors = [item for item in methods if item.name == "__init__"]
    constructor = constructors[0] if len(constructors) == 1 else None
    constructor_digest = (
        hashlib.sha256(
            ast.dump(constructor, include_attributes=False).encode()
        ).hexdigest()
        if constructor is not None
        else None
    )
    if constructor_digest != row["constructor_ast_sha256"]:
        return None
    if index != 0:
        enum_model = _provider_v3_int_enum_class(cls, tree, methods)
        return (
            None
            if enum_model is None
            else {"kind": "int_enum", "class": cls, "tree": tree, **enum_model}
        )
    if not _provider_v3_exception_class(cls, tree, methods, constructor):
        return None
    display_method = _provider_v3_display_method(row, cls, tree, methods)
    if display_method is False:
        return None
    return {
        "kind": "exception",
        "class": cls,
        "tree": tree,
        "init": constructor,
        "display_method": display_method,
    }


def _provider_v3_exception_class(cls, tree, methods, constructor):
    from .credential_role_constructor_provider import binding_occurrences

    if (
        len(cls.bases) != 1
        or not isinstance(cls.bases[0], ast.Name)
        or cls.bases[0].id != "Exception"
        or binding_occurrences(tree.body, "Exception")
    ):
        return False
    allowed_methods = {"__init__", "__str__", "__repr__"}
    if constructor is None or any(
        item.name not in allowed_methods or item.decorator_list for item in methods
    ):
        return False
    forbidden = {
        "__new__",
        "__reduce__",
        "__reduce_ex__",
        "__getstate__",
        "__setstate__",
        "__getattribute__",
        "__setattr__",
        "__delattr__",
        "__init_subclass__",
    }
    if any(item.name in forbidden for item in methods):
        return False
    return all(
        isinstance(item, ast.Pass)
        or isinstance(item, ast.Expr)
        and isinstance(item.value, ast.Constant)
        and type(item.value.value) is str
        or isinstance(item, ast.FunctionDef)
        and item.name in allowed_methods
        for item in cls.body
    )


def _provider_v3_display_method(row, cls, tree, methods):
    candidates = [method for method in methods if method.name == "__str__"]
    if not candidates:
        return None
    if len(candidates) != 1 or not _provider_v3_typing_cast_source_closed():
        return False
    method = candidates[0]
    from .credential_role_constructor_provider import binding_occurrences

    if binding_occurrences(tree.body, "str"):
        return False
    imports = [
        (statement, alias)
        for statement in tree.body
        if isinstance(statement, ast.ImportFrom)
        and statement.level == 0
        and statement.module == "typing"
        for alias in statement.names
        if alias.name == "cast"
    ]
    if len(imports) != 1:
        return False
    statement, alias = imports[0]
    local_name = alias.asname or alias.name
    if binding_occurrences(tree.body, local_name) != [
        statement
    ] or not _provider_v3_cast_return_shape(method, local_name):
        return False
    return {
        "source_path": row["path"],
        "class_name": cls.name,
        "class_ast_sha256": row["class_ast_sha256"],
        "method_name": method.name,
        "span": _provider_v3_span(method),
        "ast_sha256": hashlib.sha256(
            ast.dump(method, include_attributes=False).encode()
        ).hexdigest(),
        "recipe": "TYPING_CAST_IDENTITY_ARGS_INDEX_1",
        "cast_import_span": _provider_v3_span(statement),
        "cast_import_ast_sha256": hashlib.sha256(
            ast.dump(statement, include_attributes=False).encode()
        ).hexdigest(),
    }


def _provider_v3_cast_return_shape(method, cast_name):
    if (
        method.decorator_list
        or len(method.args.args) != 1
        or method.args.args[0].arg != "self"
    ):
        return False
    if (
        method.args.defaults
        or method.args.kwonlyargs
        or method.args.kw_defaults
        or method.args.vararg
        or method.args.kwarg
    ):
        return False
    if len(method.body) != 1 or not isinstance(method.body[0], ast.Return):
        return False
    call = method.body[0].value
    if (
        not isinstance(call, ast.Call)
        or not isinstance(call.func, ast.Name)
        or call.func.id != cast_name
        or len(call.args) != 2
        or call.keywords
    ):
        return False
    if not isinstance(call.args[0], ast.Name) or call.args[0].id != "str":
        return False
    access = call.args[1]
    return (
        isinstance(access, ast.Subscript)
        and isinstance(access.value, ast.Attribute)
        and isinstance(access.value.value, ast.Name)
        and access.value.value.id == "self"
        and access.value.attr == "args"
        and isinstance(access.slice, ast.Constant)
        and access.slice.value == 1
    )


def _provider_v3_typing_cast_source_closed():
    import sysconfig
    from pathlib import Path

    try:
        path = Path(sysconfig.get_path("stdlib")) / "typing.py"
        source = path.read_bytes()
        tree = ast.parse(source)
    except (OSError, SyntaxError, ValueError, MemoryError, RecursionError):
        return False
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "cast"
    ]
    if len(functions) != 1:
        return False
    function = functions[0]
    body = function.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and type(body[0].value.value) is str
    ):
        body = body[1:]
    return (
        len(function.args.args) == 2
        and function.args.args[0].arg == "typ"
        and function.args.args[1].arg == "val"
        and not function.args.defaults
        and not function.args.kwonlyargs
        and not function.args.vararg
        and not function.args.kwarg
        and len(body) == 1
        and isinstance(body[0], ast.Return)
        and isinstance(body[0].value, ast.Name)
        and body[0].value.id == "val"
    )


def _provider_v3_method_header_supported(method, annotations):
    if not _provider_v2_method_header_supported(method, annotations):
        return False
    for default in [*method.args.defaults, *method.args.kw_defaults]:
        if default is None:
            continue
        if not _fixed_literal_value(default):
            return False
        try:
            value = ast.literal_eval(default)
        except (TypeError, ValueError, SyntaxError, MemoryError, RecursionError):
            return False
        if not _provider_v2_immutable_value(value):
            return False
    return True


def _provider_v3_int_enum_class(cls, tree, methods):
    from .credential_role_constructor_provider import binding_occurrences

    enum_aliases = [
        (statement, alias.asname or alias.name)
        for statement in tree.body
        if isinstance(statement, ast.ImportFrom)
        and statement.level == 0
        and statement.module == "enum"
        for alias in statement.names
        if alias.name == "IntEnum"
    ]
    if len(enum_aliases) != 1:
        return None
    import_statement, enum_name = enum_aliases[0]
    if (
        import_statement.lineno >= cls.lineno
        or len(binding_occurrences(tree.body, enum_name)) != 1
        or len(cls.bases) != 1
        or not isinstance(cls.bases[0], ast.Name)
        or cls.bases[0].id != enum_name
        or methods
    ):
        return None
    members, values = {}, set()
    for statement in cls.body:
        if (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and type(statement.value.value) is str
            or isinstance(statement, ast.Pass)
        ):
            continue
        if (
            not isinstance(statement, ast.Assign)
            or len(statement.targets) != 1
            or not isinstance(statement.targets[0], ast.Name)
        ):
            return None
        name = statement.targets[0].id
        if (
            not name.isidentifier()
            or not name.isupper()
            or not _fixed_literal_value(statement.value)
        ):
            return None
        value = ast.literal_eval(statement.value)
        if (
            type(value) is not int
            or value.bit_length() > 4096
            or name in members
            or value in values
        ):
            return None
        members[name] = value
        values.add(value)
    if not members:
        return None
    return {
        "members": members,
        "int_enum_name": enum_name,
        "enum_import": import_statement,
    }


def _provider_v3_caller_enum_aliases(contract, trees, caller_tree, scope, classes):
    from .credential_role_constructor_provider import binding_occurrences

    from_path = contract["export"]["path"]
    module = _provider_artifact_module_identity(from_path)
    result = {}
    for row, model in classes[1:]:
        if (
            model["kind"] != "int_enum"
            or _provider_v3_export_chain(contract, trees, row, binding_occurrences)
            is None
        ):
            return None
        bindings = []
        for statement in caller_tree.body:
            if (
                not isinstance(statement, ast.ImportFrom)
                or statement.level != 0
                or statement.module != module
            ):
                continue
            bindings.extend(
                (statement, alias)
                for alias in statement.names
                if alias.name == row["name"]
            )
        if len(bindings) != 1:
            return None
        statement, alias = bindings[0]
        local_name = alias.asname or alias.name
        occurrences = binding_occurrences(caller_tree.body, local_name)
        if (
            len(occurrences) != 1
            or occurrences[0] is not statement
            or binding_occurrences(scope.body, local_name)
        ):
            return None
        result[local_name] = (row, model)
    return result


def _provider_v3_value(
    node, environment, enum_aliases, remaining, depth, source_path, enum_leaf_uses
):
    remaining[0] -= 1
    if remaining[0] < 0 or depth > 8:
        raise ValueError("typed pickle graph budget exhausted")
    if isinstance(node, ast.Name) and node.id in environment:
        return environment[node.id]
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in enum_aliases
    ):
        row, model = enum_aliases[node.value.id]
        if node.attr not in model["members"]:
            raise ValueError("unknown IntEnum member")
        value = model["members"][node.attr]
        enum_leaf_uses.append(
            {
                "source_path": source_path,
                "span": _provider_v3_span(node),
                "ast_sha256": hashlib.sha256(
                    ast.dump(node, include_attributes=False).encode()
                ).hexdigest(),
                "enum_class_path": row["path"],
                "enum_class_name": row["name"],
                "class_ast_sha256": row["class_ast_sha256"],
                "member": node.attr,
                "literal_value": value,
            }
        )
        return _ProviderV3EnumMember(
            row["path"], row["name"], row["class_ast_sha256"], node.attr, value
        )
    if isinstance(node, ast.Constant):
        value = node.value
    elif isinstance(node, (ast.Tuple, ast.List, ast.Dict)):
        value = _provider_v3_container_value(
            node,
            environment,
            enum_aliases,
            remaining,
            depth,
            source_path,
            enum_leaf_uses,
        )
    else:
        raise ValueError("unsupported typed pickle expression")
    return _provider_v3_validate_scalar(value)


def _provider_v3_container_value(
    node, environment, enum_aliases, remaining, depth, source_path, enum_leaf_uses
):
    if isinstance(node, ast.Tuple):
        return tuple(
            _provider_v3_value(
                item,
                environment,
                enum_aliases,
                remaining,
                depth + 1,
                source_path,
                enum_leaf_uses,
            )
            for item in node.elts
        )
    if isinstance(node, ast.List):
        return [
            _provider_v3_value(
                item,
                environment,
                enum_aliases,
                remaining,
                depth + 1,
                source_path,
                enum_leaf_uses,
            )
            for item in node.elts
        ]
    value = {}
    for key_node, item_node in zip(node.keys, node.values):
        if key_node is None:
            raise ValueError("dictionary expansion is unsupported")
        key = _provider_v3_value(
            key_node,
            environment,
            enum_aliases,
            remaining,
            depth + 1,
            source_path,
            enum_leaf_uses,
        )
        if type(key) not in {type(None), bool, int, str, bytes} or key in value:
            raise ValueError("dictionary key is not a unique exact builtin")
        value[key] = _provider_v3_value(
            item_node,
            environment,
            enum_aliases,
            remaining,
            depth + 1,
            source_path,
            enum_leaf_uses,
        )
    return value


def _provider_v3_validate_scalar(value):
    if type(value) is str and _provider_v2_text_size(value) is None:
        raise ValueError("typed pickle string exceeds scalar limit")
    if type(value) is bytes and len(value) > 16_384:
        raise ValueError("typed pickle bytes exceed scalar limit")
    if type(value) is int and value.bit_length() > 4096:
        raise ValueError("typed pickle integer exceeds scalar limit")
    if type(value) is float:
        import math

        if not math.isfinite(value):
            raise ValueError("non-finite float is unsupported")
    if (
        value is None
        or type(value) in {bool, int, float, str, bytes, tuple, list, dict}
        or isinstance(value, _ProviderV3EnumMember)
    ):
        return value
    raise ValueError("unsupported typed pickle scalar")


def _provider_v3_run_initializer(
    initializer,
    environment,
    enum_aliases,
    remaining,
    source_path,
    enum_leaf_uses,
    module_tree,
):
    fields, base_args = {}, None
    for statement in initializer.body:
        remaining[0] -= 1
        if remaining[0] < 0:
            raise ValueError("typed pickle graph budget exhausted")
        if (
            isinstance(statement, ast.Pass)
            or isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and type(statement.value.value) is str
        ):
            continue
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            if (
                not isinstance(target, ast.Attribute)
                or not isinstance(target.value, ast.Name)
                or target.value.id != initializer.args.args[0].arg
                or target.attr.startswith("__")
                or target.attr == "args"
                or _provider_v2_text_size(target.attr) is None
            ):
                raise ValueError("unsupported source-instance field write")
            fields[target.attr] = _provider_v3_value(
                statement.value,
                environment,
                enum_aliases,
                remaining,
                0,
                source_path,
                enum_leaf_uses,
            )
            continue
        delegated = _provider_v2_super_call(statement, initializer, module_tree)
        if delegated is None or base_args is not None or delegated.keywords:
            raise ValueError("unsupported source-instance constructor effect")
        base_args = tuple(
            _provider_v3_value(
                item,
                environment,
                enum_aliases,
                remaining,
                0,
                source_path,
                enum_leaf_uses,
            )
            for item in delegated.args
        )
    if not isinstance(base_args, tuple):
        return None
    return base_args, fields


def _provider_v3_external_instance_state(
    instance_state, fields, enum_aliases, remaining, source_path, enum_leaf_uses
):
    if instance_state is None:
        return True
    if (
        type(instance_state) is not dict
        or len(instance_state) > 64
        or _provider_v3_instance_aliases((), instance_state)
    ):
        return False
    for name, value in instance_state.items():
        if (
            not isinstance(name, str)
            or not name.isidentifier()
            or name == "args"
            or name.startswith("__")
            or _provider_v2_text_size(name) is None
        ):
            return False
        if type(value) in {type(None), bool, int, float, str, bytes}:
            node = ast.Constant(value=value)
        elif type(value) is tuple:
            node = _provider_v3_python_literal(value)
        elif type(value) in {list, dict}:
            node = _provider_v3_python_literal(value)
        else:
            return False
        fields[name] = _provider_v3_value(
            node, {}, enum_aliases, remaining, 0, source_path, enum_leaf_uses
        )
    return True


def _provider_v3_python_literal(value):
    if value is None or type(value) in {bool, int, float, str, bytes}:
        return ast.Constant(value=value)
    if type(value) is tuple:
        return ast.Tuple(
            elts=[_provider_v3_python_literal(item) for item in value], ctx=ast.Load()
        )
    if type(value) is list:
        return ast.List(
            elts=[_provider_v3_python_literal(item) for item in value], ctx=ast.Load()
        )
    if type(value) is dict:
        return ast.Dict(
            keys=[_provider_v3_python_literal(key) for key in value],
            values=[_provider_v3_python_literal(item) for item in value.values()],
        )
    raise ValueError("state contains a non-literal value")


def _provider_v3_instance_aliases(args, state):
    seen = set()

    def visit(value):
        if type(value) in {tuple, list, dict}:
            identity = id(value)
            if identity in seen:
                return True
            seen.add(identity)
            children = value.values() if type(value) is dict else value
            if any(visit(item) for item in children):
                return True
            if type(value) is dict and any(visit(key) for key in value):
                return True
        return False

    return any(visit(value) for value in args) or any(
        visit(value) for value in state.values()
    )


def _provider_v3_graph_node(value, remaining, depth, seen):
    remaining[0] -= 1
    if remaining[0] < 0 or depth > 8:
        raise ValueError("typed pickle graph budget exhausted")
    if value is None or type(value) in {bool, int, float, str, bytes}:
        return _provider_v3_graph_scalar(value)
    if isinstance(value, _ProviderV3EnumMember):
        return _provider_v3_graph_enum_member(value, remaining)
    if type(value) in {tuple, list, dict}:
        return _provider_v3_graph_container(value, remaining, depth, seen)
    raise ValueError("typed pickle graph contains an unsupported value")


def _provider_v3_graph_scalar(value):
    if value is None:
        return {"tag": "none"}
    if type(value) is bool:
        return {"tag": "bool", "value": value}
    if type(value) is int:
        return {"tag": "int", "decimal": str(value)}
    if type(value) is float:
        return {"tag": "float", "hex": value.hex()}
    if type(value) is str:
        return {"tag": "str", "value": value}
    return {"tag": "bytes", "hex": value.hex()}


def _provider_v3_graph_enum_member(value, remaining):
    remaining[0] -= 2  # encoded enum value and canonical value-constructor argument
    if remaining[0] < 0:
        raise ValueError("typed pickle graph budget exhausted")
    numeric = {"tag": "int", "decimal": str(value.value)}
    return {
        "tag": "enum_member",
        "type": {
            "module": _provider_artifact_module_identity(value.path),
            "qualname": value.name,
            "class_ast_sha256": value.class_ast_sha256,
        },
        "member": value.member,
        "value": numeric,
        "reconstruction": {
            "kind": "IntEnum_VALUE_CONSTRUCT",
            "arguments": [numeric],
            "expected_member": value.member,
        },
    }


def _provider_v3_graph_container(value, remaining, depth, seen):
    identity = id(value)
    if identity in seen:
        raise ValueError("typed pickle graph contains aliased or cyclic containers")
    seen.add(identity)
    if type(value) is tuple:
        return {
            "tag": "tuple",
            "items": [
                _provider_v3_graph_node(item, remaining, depth + 1, seen)
                for item in value
            ],
        }
    if type(value) is list:
        return {
            "tag": "list",
            "items": [
                _provider_v3_graph_node(item, remaining, depth + 1, seen)
                for item in value
            ],
        }
    if len(value) > 64 or any(
        type(key) not in {type(None), bool, int, str, bytes} for key in value
    ):
        raise ValueError("typed pickle mapping has unsupported keys or size")
    pairs = [
        [
            _provider_v3_graph_node(key, remaining, depth + 1, seen),
            _provider_v3_graph_node(item, remaining, depth + 1, seen),
        ]
        for key, item in value.items()
    ]
    return {"tag": "dict", "items": pairs}


def _provider_v3_deduplicate_enum_uses(rows):
    indexed = {}
    for row in rows:
        key = (row["source_path"], tuple(row["span"]), row["ast_sha256"])
        existing = indexed.setdefault(key, row)
        if existing != row:
            raise ValueError("conflicting typed enum leaf evidence")
    return [indexed[key] for key in sorted(indexed)]


def _provider_v2_instance_state_map(value):
    return _provider_v2_instance_state_cost(value) is not None


def _provider_v2_instance_state_cost(value):
    if not isinstance(value, dict) or len(value) > 64:
        return None
    remaining = [512]
    for key, item in value.items():
        remaining[0] -= 1
        if (
            remaining[0] < 0
            or not isinstance(key, str)
            or not key.isidentifier()
            or key == "args"
            or key.startswith("__")
            or not _provider_v2_instance_state_walk(item, remaining, 0)
        ):
            return None
    return 512 - remaining[0]


def _fixed_literal_value(node):
    from .finite_capture import _fixed_literal_value as implementation

    return implementation(node)


def _fixed_program_span(node):
    from .finite_capture import _fixed_program_span as implementation

    return implementation(node)


def _captured_sink_parameter_names(scope):
    from .finite_capture import _captured_sink_parameter_names as implementation

    return implementation(scope)


_CACHE_HELPER_NAMES = tuple(
    name
    for name, value in globals().items()
    if callable(value) and getattr(value, "__module__", None) == __name__
)
