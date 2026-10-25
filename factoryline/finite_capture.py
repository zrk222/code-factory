"""Bounded source-origin capture for finite templates."""

import ast
import hashlib
from collections import defaultdict
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


def provider_export_chain_v3(contract, source_bytes, *, class_row=None):
    """Return source-bound module.symbol identities for one selected v3 export."""
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
    target = (
        rows[0] if class_row is None and isinstance(rows, list) and rows else class_row
    )
    if not isinstance(target, dict) or target not in rows:
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


def _security_helper_definition_supported(function):
    from . import review_integrity as flow

    defaults = [*function.args.defaults, *function.args.kw_defaults]
    if any(value is not None and not _fixed_literal_value(value) for value in defaults):
        return False
    annotations = [
        argument.annotation
        for argument in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
    ]
    annotations.append(function.returns)
    annotations.extend(
        node.annotation
        for node in flow._lexical_nodes(function)
        if isinstance(node, ast.AnnAssign)
    )
    if any(not _security_helper_annotation_supported(value) for value in annotations):
        return False
    return not any(
        isinstance(
            node, (ast.Yield, ast.YieldFrom, ast.Await, ast.Global, ast.Nonlocal)
        )
        for node in flow._lexical_nodes(function)
    )


def _security_helper_annotation_supported(value):
    return value is None or isinstance(value, (ast.Name, ast.Constant))


def _security_helper_binding(call, function):
    """Bind a source-owned helper; decline mutation, expansion and recursion."""
    from . import review_integrity as flow

    if (
        not isinstance(function, ast.FunctionDef)
        or function.decorator_list
        or function.args.vararg
        or function.args.kwarg
        or getattr(function, "_security_helper_active", False)
    ):
        return None
    module = flow._security_module_scope(function)
    if module is None or getattr(module, "_security_helper_flow_depth", 0) >= 8:
        return None
    if sum(1 for _ in ast.walk(function)) > 512:
        return None
    if not _security_helper_definition_supported(function):
        return None
    try:
        actuals = flow.bind_source_call(call, function, apply_defaults=True)
    except ValueError:
        return None
    if not _security_helper_provider_stable(module, call, function):
        return None
    return module, actuals


def _security_helper_provider_stable(module, call, function):
    from . import intent_quality, review_audits as audit

    # The existing binder resets this cache for every captured-source scan.
    # Cache provider facts only: flow states and return values remain per call.
    cache = getattr(module, "_security_sanitizer_provider_cache", {})
    key = ("native-helper-provider", id(function), call.func.id)
    if key not in cache:
        aliases = {function.name: function.name, call.func.id: function.name}
        cache[key] = intent_quality._sanitizer_provider_mutated(
            module, call, aliases, function.name, call.func.id, audit
        )
        module._security_sanitizer_provider_cache = cache
    return not cache[key]


def _security_flow_value(expression, environment, aliases):
    from . import review_integrity as flow

    if sum(1 for _ in ast.walk(expression)) > 512:
        return False, None
    if isinstance(expression, ast.Name):
        value = environment.get(expression.id)
        return value is not None, value
    if _fixed_literal_value(expression):
        return True, False
    if not isinstance(expression, (ast.Call, ast.Attribute, ast.Subscript)):
        # A may-taint arithmetic expression is not a proved evaluable value.
        return False, None
    if isinstance(expression, ast.Call) and flow.security_call_name(
        expression, aliases
    ) in {
        "os.path.join",
        "pathlib.Path",
        "pathlib.PurePath",
        "werkzeug.utils.secure_filename",
    }:
        return False, None
    tainted = {name for name, value in environment.items() if value is True}
    if flow._security_expr_tainted(expression, tainted, set(), aliases):
        return True, True
    return False, None


def _security_helper_initial(call, actuals, requests, parameters, aliases):
    supplied = {id(value) for value in call.args}
    supplied.update(id(keyword.value) for keyword in call.keywords)
    caller = {name: True for name in requests | parameters if isinstance(name, str)}
    initial = {}
    for name, value in actuals.items():
        # Omitted defaults belong to the definition, never to the caller's scope.
        if _fixed_literal_value(value):
            initial[name] = False
        elif id(value) in supplied:
            known, tainted = _security_flow_value(value, caller, aliases)
            initial[name] = tainted if known else None
        else:
            initial[name] = None
    return initial


def security_helper_return_tainted(call, function, requests, parameters, aliases):
    """Trace an exact source helper return from the supplied request roots without executing it."""
    binding = _security_helper_binding(call, function)
    if binding is None:
        return False
    module, actuals = binding
    initial = _security_helper_initial(call, actuals, requests, parameters, aliases)
    if any(value is None for value in initial.values()):
        return False
    function._security_helper_active = True
    module._security_helper_flow_depth = (
        getattr(module, "_security_helper_flow_depth", 0) + 1
    )
    try:
        result = evaluate_helper_flow(
            function,
            initial,
            lambda expression, environment: _security_flow_value(
                expression, environment, aliases
            ),
        )
        return result["status"] == "COMPLETE" and result["return_values"] == (True,)
    finally:
        function._security_helper_active = False
        module._security_helper_flow_depth -= 1


def security_forward_helper_sources(relative, call, aliases, requests, helpers):
    """Feed proven actual-argument sources into the existing callee sink pass."""
    from . import review_integrity as flow
    from .semantic_credential_sensor import (
        security_precondition_path_possible,
        request_payload_value_kind,
    )

    if not security_precondition_path_possible(call):
        return
    actual_values = [*call.args, *(keyword.value for keyword in call.keywords)]
    if not any(
        flow._security_expr_tainted(value, requests, set(), aliases)
        for value in actual_values
    ):
        return
    function = flow._security_local_helper_definition(call)
    binding = _security_helper_binding(call, function)
    if binding is None:
        return
    module, actuals = binding
    initial = _security_helper_initial(call, actuals, requests, set(), aliases)
    if any(value is None for value in initial.values()):
        return
    sources = {name for name, value in initial.items() if value is True}
    if not sources:
        return
    # This extension models straight-line local helpers only. Branches and
    # opaque side effects must not acquire a support verdict from this pass.
    if (
        any(
            not isinstance(
                statement, (ast.Assign, ast.AnnAssign, ast.Expr, ast.Return, ast.Pass)
            )
            for statement in function.body
        )
        or not _security_helper_sink_calls_supported(function, aliases, relative)
        or not _security_helper_prefix_supported(function, initial, aliases)
    ):
        return
    for name in tuple(sources):
        kind = request_payload_value_kind(
            actuals[name], requests, aliases, flow._security_scope_request_aliases
        )
        if kind:
            sources.add(("request-type:" + kind, name))
    function._security_helper_active = True
    module._security_helper_flow_depth = (
        getattr(module, "_security_helper_flow_depth", 0) + 1
    )
    try:
        # The normal raw scan owns emission. This pass supplies only native
        # source-bound preconditions on those same sink AST nodes.
        flow._security_analyze_source_sink_block(
            relative,
            function.body,
            function,
            aliases,
            sources,
            set(),
            set(),
            set(),
            set(),
            helpers,
        )
    finally:
        function._security_helper_active = False
        module._security_helper_flow_depth -= 1


def _security_helper_sink_calls_supported(function, aliases, relative):
    from . import review_audits as audit, review_integrity as flow

    for node in flow._lexical_nodes(function):
        if isinstance(node, ast.Call):
            finding = audit._security_call_finding(
                flow.security_call_name(node, aliases), relative, node
            )
            if finding is None or finding["code"] not in {
                "SECURITY_DYNAMIC_EXECUTION",
                "SECURITY_OS_COMMAND",
                "SECURITY_SHELL_COMMAND",
                "SECURITY_UNSAFE_DESERIALIZATION",
                "SECURITY_UNSAFE_YAML",
            }:
                return False
    return True


def _security_helper_prefix_supported(function, initial, aliases):
    environment = dict(initial)

    def callback(expression, state):
        """Resolve a helper expression using the captured provider aliases."""
        return _security_flow_value(expression, state, aliases)

    for statement in function.body:
        if isinstance(
            statement, ast.AnnAssign
        ) and not _security_helper_annotation_supported(statement.annotation):
            return False
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            known, name, value = _helper_flow_assignment(
                statement, environment, callback
            )
            if not known:
                return False
            environment[name] = value
        elif isinstance(statement, (ast.Expr, ast.Return)):
            value = statement.value
            if (
                value is not None
                and not isinstance(value, ast.Call)
                and not callback(value, environment)[0]
            ):
                return False
            if isinstance(statement, ast.Return):
                break
    return True


def _helper_flow_result(status, environment, states, reason, values=()):
    return {
        "status": status,
        "environment": environment,
        "return_values": tuple(values),
        "states_used": states,
        "reason": reason,
    }


def _helper_flow_assignment(statement, environment, evaluate_expression):
    if isinstance(statement, ast.Assign):
        if len(statement.targets) != 1 or not isinstance(
            statement.targets[0], ast.Name
        ):
            return False, "", None
        name = statement.targets[0].id
    elif isinstance(statement, ast.AnnAssign):
        if not isinstance(statement.target, ast.Name) or statement.value is None:
            return False, "", None
        name = statement.target.id
    else:
        return False, "", None
    try:
        known, value = evaluate_expression(statement.value, dict(environment))
    except Exception:
        known, value = False, None
    environment.pop(name, None)
    return (known is True, name, value)


def _helper_flow_step(statement, index, environment, evaluate_expression):
    if isinstance(statement, ast.Return):
        if statement.value is None:
            return "COMPLETE", "return", (None,)
        try:
            known, value = evaluate_expression(statement.value, dict(environment))
        except Exception:
            known, value = False, None
        return (
            ("COMPLETE", "return", (value,))
            if known is True
            else ("UNKNOWN", "unsupported return expression", ())
        )
    if isinstance(statement, ast.Pass):
        return "CONTINUE", "pass", ()
    if (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
        and index == 0
    ):
        return "CONTINUE", "docstring", ()
    if isinstance(statement, (ast.Assign, ast.AnnAssign)):
        known, name, value = _helper_flow_assignment(
            statement, environment, evaluate_expression
        )
        if not known:
            return "UNKNOWN", "unsupported assignment", ()
        environment[name] = value
        return "CONTINUE", "assignment", ()
    return "UNKNOWN", "unsupported statement", ()


def evaluate_helper_flow(function, initial, evaluate_expression, *, max_states=512):
    """Evaluate a bounded straight-line helper with caller-defined value semantics.

    This local transfer function applies reaching-definition kills for exact
    names and projects the resulting environment to a return value. It never
    imports or executes the target. Expression callbacks return ``(known,
    value)``; unsupported values and statements decline explicitly.

    The transfer follows the strong-update/reaching-definition concepts in
    CodeAnalyzer's Apache-2.0 ``dataflow/defuse.py`` (commit
    54acde45556869271c16d5fead1134a821012811), and the caller-owned actual to
    formal and return projection boundary in PyFlow's Apache-2.0 ``taint.py``
    (commit e057856a3d409ddc756bca9d3e90409f084bbbdc). This is a bounded local
    evaluator, not a CFG or IFDS solver.
    """
    if (
        not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        or type(max_states) is not int
        or max_states < 1
        or not isinstance(initial, dict)
        or not callable(evaluate_expression)
    ):
        return _helper_flow_result("UNKNOWN", {}, 0, "invalid evaluator input")
    if len(function.body) > max_states:
        return _helper_flow_result("BUDGET_EXHAUSTED", {}, 0, "state budget exhausted")
    if sum(isinstance(node, ast.Return) for node in function.body) > 1:
        return _helper_flow_result("UNKNOWN", {}, 0, "multiple returns")

    env = dict(initial)
    states = 0
    for index, statement in enumerate(function.body):
        if states >= max_states:
            return _helper_flow_result(
                "BUDGET_EXHAUSTED", env, states, "state budget exhausted"
            )
        states += 1
        status, reason, values = _helper_flow_step(
            statement, index, env, evaluate_expression
        )
        if status == "COMPLETE":
            return _helper_flow_result(status, env, states, reason, values)
        if status == "UNKNOWN":
            return _helper_flow_result(status, env, states, reason)
    return _helper_flow_result("UNKNOWN", env, states, "no supported return")


def captured_value_use_closure(
    function, node, parents, scope_of, return_callers, consumer, *, max_states=512
):
    """Account for every use through captured local aliases and helper returns.

    The caller binds exact functions and terminal consumers; this traversal
    never establishes their semantics from a spelling or executes source.
    Unknowns, empty paths, cycles and exhausted budgets decline closure.
    """
    pending = [(function, node, frozenset())]
    seen, sinks, nodes = set(), {}, []
    while pending:
        current, value, ancestors = pending.pop()
        key = (id(current), id(value))
        if key in ancestors or len(seen) >= max_states:
            return None
        if key in seen:
            continue
        seen.add(key)
        nodes.append(value)
        edge = consumer(current, value)
        if edge is not None:
            sinks[id(edge)] = edge
            continue
        successors = _captured_value_use_successors(
            current, value, parents, scope_of, return_callers
        )
        if not successors:
            return None
        pending.extend((scope, child, ancestors | {key}) for scope, child in successors)
    return {"sinks": tuple(sinks.values()), "nodes": tuple(nodes)} if sinks else None


def _captured_value_use_successors(function, value, parents, scope_of, return_callers):
    parent = parents.get(id(value))
    if isinstance(parent, ast.keyword) and parent.value is value and parent.arg:
        call = parents.get(id(parent))
        if (
            isinstance(call, ast.Call)
            and any(keyword is parent for keyword in call.keywords)
            and not any(keyword.arg is None for keyword in call.keywords)
            and not any(isinstance(argument, ast.Starred) for argument in call.args)
            and scope_of(call) is function
        ):
            return [(function, call)]
        return None
    if isinstance(parent, (ast.List, ast.Tuple)) and value in parent.elts:
        return [(function, parent)]
    if (
        isinstance(parent, ast.Dict)
        and value in parent.values
        and all(isinstance(key, ast.Constant) for key in parent.keys)
    ):
        return [(function, parent)]
    if isinstance(parent, (ast.Assign, ast.AnnAssign)) and parent.value is value:
        return _captured_value_alias_loads(function, parent, scope_of)
    if (
        isinstance(parent, ast.Return)
        and parent.value is value
        and scope_of(parent) is function
    ):
        return return_callers(function)
    return None


def _captured_value_alias_loads(function, assignment, scope_of):
    from .credential_role_constructor_provider import binding_occurrences

    targets = (
        assignment.targets
        if isinstance(assignment, ast.Assign)
        else [assignment.target]
    )
    if len(targets) != 1 or not isinstance(targets[0], ast.Name):
        return None
    name = targets[0].id
    if binding_occurrences(function.body, name) != targets:
        return None
    loads = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, ast.Load)
    ]
    if not loads or any(scope_of(node) is not function for node in loads):
        return None
    if any(node.lineno <= assignment.lineno for node in loads):
        return None
    return [(function, node) for node in loads]


def captured_literal_branch_field_transfer(
    source, path, constructor, bound, caller_path, caller, field, builtin_stable
):
    """Project a selected constructor field under source-bound scalar arguments.

    This is a value-lineage fact, not an admission or an effect-safety proof.
    Callers still close selected receiver mutations and all downstream uses.
    """
    receiver = _captured_projection_receiver(source, path, constructor, bound)
    if receiver is None:
        return None
    known = {}
    for name, actual in bound.items():
        value = captured_call_scalar(source, caller_path, caller, actual, path)
        if value is not None:
            known[name] = value[0]
    statements = captured_selected_field_assignments(
        constructor.body,
        receiver,
        field,
        known,
        lambda expression, state: captured_scalar_guard(
            expression, state, builtin_stable
        ),
        [512],
    )
    if statements is None or len(statements) != 1:
        return None
    statement = statements[0]
    value = statement.value
    while isinstance(value, ast.IfExp):
        truth = captured_scalar_guard(value.test, known, builtin_stable)
        if truth is None:
            return None
        value = value.body if truth else value.orelse
    if not isinstance(value, ast.Name) or value.id not in bound:
        return None
    return {
        "path": path,
        "constructor": constructor,
        "statement": statement,
        "formal": value.id,
        "actual": bound[value.id],
        "field": field,
        "source_sha256": source.inventory[path],
        "profile": "SOURCE_LITERAL_SELECTED_BRANCH",
    }


def _captured_projection_receiver(source, path, constructor, bound):
    from .credential_role_constructor_provider import binding_occurrences, DYNAMIC_HOOKS
    from .credential_role_identity_effects import captured_function_valid

    if not captured_function_valid(constructor, path, source):
        return None
    owner = source.parents[path].get(id(constructor))
    if (
        not isinstance(owner, ast.ClassDef)
        or owner.bases
        or owner.decorator_list
        or owner.keywords
    ):
        return None
    if any(binding_occurrences(owner.body, name) for name in DYNAMIC_HOOKS):
        return None
    formals = [*constructor.args.posonlyargs, *constructor.args.args]
    if not formals or any(
        binding_occurrences(constructor.body, name) for name in bound
    ):
        return None
    receiver = formals[0].arg
    return (
        receiver
        if _captured_projection_receiver_closed(source, path, constructor, receiver)
        else None
    )


def _captured_projection_receiver_closed(source, path, constructor, receiver):
    parents = source.parents[path]
    for node in ast.walk(constructor):
        if isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)):
            return False
        if (
            not isinstance(node, ast.Name)
            or node.id != receiver
            or not isinstance(node.ctx, ast.Load)
        ):
            continue
        parent = parents.get(id(node))
        if (
            not isinstance(parent, ast.Attribute)
            or parent.value is not node
            or parent.attr.startswith("__")
        ):
            return False
        operation = parents.get(id(parent))
        if isinstance(operation, ast.Call) and operation.func is parent:
            return False
    return True


def captured_call_scalar(source, path, caller, expression, default_path=None):
    """Resolve a bounded immutable scalar argument from current captured source bindings."""
    if (
        not source.validate(path)
        or not isinstance(caller, (ast.FunctionDef, ast.AsyncFunctionDef))
        or id(caller) not in source.parents[path]
    ):
        return None
    if id(expression) not in source.parents[path]:
        if default_path is None or not source.validate(default_path):
            return None
        if id(expression) not in source.parents[default_path]:
            return None
    if isinstance(expression, ast.Name):
        from .credential_role_constructor_provider import binding_occurrences

        if not source.validate(path):
            return None
        rows = [
            row
            for row in caller.body
            if isinstance(row, ast.Assign)
            and len(row.targets) == 1
            and isinstance(row.targets[0], ast.Name)
            and row.targets[0].id == expression.id
        ]
        assignment = (
            rows[0]
            if len(rows) == 1
            and len(binding_occurrences(caller.body, expression.id)) == 1
            else None
        )
        if (
            assignment is None
            or assignment not in caller.body
            or assignment.lineno >= expression.lineno
        ):
            return None
        expression = assignment.value
    if isinstance(expression, ast.Constant) and type(expression.value) in {
        str,
        bytes,
        int,
        float,
        bool,
        type(None),
    }:
        if isinstance(expression.value, (str, bytes)) and len(expression.value) > 4096:
            return None
        return (expression.value,)
    return None


def captured_scalar_guard(expression, known, builtin_stable):
    """Evaluate a modeled scalar guard, retaining unknown outcomes when identity is not closed."""
    from . import review_audits as audit

    if isinstance(expression, ast.Call):
        if (
            not isinstance(expression.func, ast.Name)
            or expression.func.id != "isinstance"
            or len(expression.args) != 2
            or expression.keywords
            or not isinstance(expression.args[0], ast.Name)
            or expression.args[0].id not in known
            or not isinstance(expression.args[1], ast.Name)
            or expression.args[1].id not in {"str", "bytes", "int", "bool"}
            or not all(
                builtin_stable(node) for node in (expression.func, expression.args[1])
            )
        ):
            return None
        types = {"str": str, "bytes": bytes, "int": int, "bool": bool}
        return isinstance(known[expression.args[0].id], types[expression.args[1].id])
    if isinstance(expression, ast.BoolOp):
        values = [
            captured_scalar_guard(child, known, builtin_stable)
            for child in expression.values
        ]
        if any(value is None for value in values):
            return None
        return all(values) if isinstance(expression.op, ast.And) else any(values)
    if isinstance(expression, ast.UnaryOp) and isinstance(expression.op, ast.Not):
        truth = captured_scalar_guard(expression.operand, known, builtin_stable)
        return None if truth is None else not truth
    allowed = (
        ast.Name,
        ast.Constant,
        ast.Compare,
        ast.Load,
        ast.Eq,
        ast.NotEq,
        ast.Is,
        ast.IsNot,
    )
    if any(not isinstance(node, allowed) for node in ast.walk(expression)):
        return None
    if isinstance(expression, ast.Compare) and any(
        isinstance(operator, (ast.Is, ast.IsNot)) for operator in expression.ops
    ):
        values = [expression.left, *expression.comparators]
        if not any(
            isinstance(value, ast.Constant) and value.value is None for value in values
        ):
            return None
    return audit._constant_truth_value(expression, known)


def captured_selected_field_assignments(body, receiver, field, known, guard, budget):
    """Collect bounded field assignments along modeled scalar branches without executing source."""
    rows = []
    for statement in body:
        budget[0] -= 1
        if budget[0] < 0:
            return None
        writes = [
            node
            for node in ast.walk(statement)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == receiver
            and node.attr == field
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ]
        if isinstance(statement, ast.If):
            truth = guard(statement.test, known)
            if truth is None:
                if writes:
                    return None
                continue
            branch = statement.body if truth else statement.orelse
            selected = captured_selected_field_assignments(
                branch, receiver, field, known, guard, budget
            )
            if selected is None:
                return None
            rows.extend(selected)
        elif writes:
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
                if isinstance(statement, ast.AnnAssign)
                else []
            )
            target = targets[0] if len(targets) == 1 else None
            if not isinstance(statement, (ast.Assign, ast.AnnAssign)) or writes != [
                target
            ]:
                return None
            rows.append(statement)
    return rows


def shell_execution_calls():
    """Return the shared canonical process primitives modeled by this scanner."""
    return (
        "os.system subprocess.run subprocess.Popen subprocess.call "
        "subprocess.check_call subprocess.check_output"
    ).split()


def _closed_shell_operation(command):
    """Recognize simple non-interpreter operations, never arbitrary shell safety."""
    import re

    if not isinstance(command, str) or not re.fullmatch(
        r"[A-Za-z0-9_.@+* -]{1,512}", command
    ):
        return None
    words = command.split()
    if len(words) == 3 and words[:2] == ["brew", "--prefix"]:
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@+-]*", words[2]):
            return "package_prefix_query"
    if len(words) >= 3 and words[:2] == ["upx", "--best"]:
        targets = words[3:] if words[2] == "--force-macos" else words[2:]
        if targets and all(
            re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]*(?:\*[A-Za-z0-9_.+-]+)?", word)
            for word in targets
        ):
            return "executable_packing"
    return None


def _closed_shell_call_role(call, call_name):
    """Accept one literal argument and explicit supported shell call options."""
    if len(call.args) != 1 or not isinstance(call.args[0], ast.Constant):
        return None
    if any(kw.arg is None for kw in call.keywords):
        return None
    if call_name == "os.system":
        if call.keywords:
            return None
    elif not any(
        kw.arg == "shell"
        and isinstance(kw.value, ast.Constant)
        and kw.value.value is True
        for kw in call.keywords
    ):
        return None
    # An overridden executable could use the same arguments for different effects.
    if any(
        kw.arg
        not in {
            "shell",
            "text",
            "encoding",
            "errors",
            "capture_output",
            "check",
            "timeout",
        }
        or not isinstance(kw.value, ast.Constant)
        for kw in call.keywords
    ):
        return None
    return _closed_shell_operation(call.args[0].value)


def _closed_shell_provider_mutated(node, head, supported):
    """Reject source-visible provider writes, reflection and monkey patches."""
    if isinstance(node, ast.ImportFrom) and any(
        alias.name == "*" for alias in node.names
    ):
        return True
    if (
        isinstance(node, ast.Name)
        and node.id == head
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ):
        return True
    if isinstance(node, ast.arg) and node.arg == head:
        return True
    if (
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.name == head
    ):
        return True
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
        base = node.value
        while isinstance(base, ast.Attribute):
            base = base.value
        if (isinstance(base, ast.Name) and base.id == head) or node.attr in {
            name.rsplit(".", 1)[-1] for name in supported
        }:
            return True
    if isinstance(node, ast.Call) and (
        node.func.id
        if isinstance(node.func, ast.Name)
        else getattr(node.func, "attr", "")
    ) in {
        "eval",
        "exec",
        "globals",
        "locals",
        "vars",
        "setattr",
        "delattr",
        "getattr",
        "__import__",
        "patch",
    }:
        return True
    return False


def _closed_shell_provider(tree, call, call_name, supported):
    """Bind a simple process call to one stable module-level provider import."""
    func = call.func
    name = (
        func.id
        if isinstance(func, ast.Name)
        else (
            f"{func.value.id}.{func.attr}"
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
            else ""
        )
    )
    head = name.partition(".")[0]
    imports = []
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            imports.extend(
                (alias.asname or alias.name.split(".")[0], alias.name)
                for alias in statement.names
            )
        elif isinstance(statement, ast.ImportFrom) and not statement.level:
            imports.extend(
                (alias.asname or alias.name, f"{statement.module}.{alias.name}")
                for alias in statement.names
            )
    origins = [origin for alias, origin in imports if alias == head]
    if len(origins) != 1 or origins[0] + name[len(head) :] != call_name:
        return False
    if not _closed_shell_namespace(tree, head):
        return False
    return not any(
        _closed_shell_provider_mutated(node, head, supported) for node in ast.walk(tree)
    )


def _closed_shell_namespace(tree, head):
    """Reject capability escapes, namespace access and aliased reflection."""
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    reflective = {
        "eval",
        "exec",
        "globals",
        "locals",
        "vars",
        "setattr",
        "delattr",
        "getattr",
        "__import__",
    }
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id == head
            and isinstance(node.ctx, ast.Load)
        ):
            if not isinstance(parents.get(node), ast.Attribute):
                return False
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            base = node.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name) and base.id == head:
                return False
        if isinstance(node, ast.ImportFrom) and node.module in {
            "builtins",
            "__builtin__",
        }:
            if any(alias.name in reflective for alias in node.names):
                return False
    return True


def _shell_source_provider_clear(raw, provider):
    """Reuse provider mutation/escape indexing across captured helper modules."""
    from . import review_audits as audit

    try:
        tree = ast.parse(raw)
    except (SyntaxError, ValueError, RecursionError):
        return False
    nodes = list(ast.walk(tree))
    aliases = _shell_import_aliases(nodes, audit, provider)
    if aliases is None:
        return False
    parents = {
        id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)
    }
    # Index maximal provider expressions: passing os.environ does not expose os.
    maximal = [
        node
        for node in nodes
        if not (
            isinstance(node, (ast.Name, ast.Attribute))
            and isinstance(parents.get(id(node)), ast.Attribute)
            and parents[id(node)].value is node
        )
    ]
    mutations = finite_provider_mutation_index(maximal, aliases, audit, parents)
    if _shell_dynamic_provider_access(
        nodes, aliases, audit, parents, provider
    ) or not _shell_namespace_queries_closed(nodes, aliases, audit, parents, provider):
        return False
    leaves = (
        {"system"}
        if provider == "os"
        else {"run", "Popen", "call", "check_call", "check_output"}
    )
    if any(
        (path == provider and attribute in leaves | {"*"})
        or path.startswith(provider + ".")
        and path.split(".")[1] in leaves
        for path, attribute in mutations
    ):
        return False
    for node in nodes:
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            origin = audit._resolved_ast_name(node, aliases)
            if origin.startswith(provider + "."):
                return False
        if isinstance(node, ast.Attribute) and node.attr == "modules":
            if any(isinstance(n, ast.Constant) and n.value == provider for n in nodes):
                return False
    return True


def _shell_import_aliases(nodes, audit, provider):
    """Preserve imported capability origins instead of flat last-binding wins."""
    origins = defaultdict(set)
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                origins[alias.asname or alias.name.split(".")[0]].add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                origins[alias.asname or alias.name].add(
                    "." * node.level + (node.module or "") + "." + alias.name
                )
    protected = {provider, "builtins", "importlib"}
    if any(
        len(values) > 1 and any(value.split(".")[0] in protected for value in values)
        for values in origins.values()
    ):
        return None
    return audit._security_aliases(nodes)


def _shell_dynamic_provider_access(nodes, aliases, audit, parents, provider):
    """Reject dynamic provider lookup and importer capability escapes."""
    importers = {"__import__", "builtins.__import__", "importlib.import_module"}
    for node in nodes:
        if not isinstance(node, (ast.Name, ast.Attribute)):
            continue
        if audit._resolved_ast_name(node, aliases) not in importers:
            continue
        parent = parents.get(id(node))
        if not isinstance(parent, ast.Call) or parent.func is not node:
            return True
        if not parent.args or not isinstance(parent.args[0], ast.Constant):
            return True
        module = parent.args[0].value
        if not isinstance(module, str) or module.split(".")[0] == provider:
            return True
        result_use = parents.get(id(parent))
        if not (
            isinstance(result_use, ast.Attribute)
            and result_use.attr == "__file__"
            and isinstance(result_use.ctx, ast.Load)
        ):
            return True
    return False


def _shell_namespace_queries_closed(nodes, aliases, audit, parents, provider):
    """Allow namespace presence queries without exposing mutable namespace maps."""
    for node in nodes:
        if not isinstance(node, (ast.Name, ast.Attribute)):
            continue
        canonical = audit._resolved_ast_name(node, aliases).removeprefix("builtins.")
        if canonical not in {"globals", "locals", "vars"}:
            continue
        call = parents.get(id(node))
        comparison = parents.get(id(call))
        if not (
            isinstance(call, ast.Call)
            and call.func is node
            and not call.args
            and not call.keywords
            and isinstance(comparison, ast.Compare)
            and len(comparison.ops) == 1
            and isinstance(comparison.ops[0], (ast.In, ast.NotIn))
            and comparison.comparators == [call]
            and isinstance(comparison.left, ast.Constant)
            and isinstance(comparison.left.value, str)
            and comparison.left.value != provider
        ):
            return False
    return True


def closed_shell_workspace(sources, provider):
    """Hash the complete consulted source inventory after provider checks."""
    import json

    if not sources or any(
        path.rsplit("/", 1)[-1] in {provider + ".py", "__init__.py"}
        and provider in path.replace(".py", "").split("/")
        for path in sources
    ):
        return None
    if not all(
        isinstance(raw, bytes) and _shell_source_provider_clear(raw, provider)
        for raw in sources.values()
    ):
        return None
    return hashlib.sha256(
        json.dumps(
            sorted(
                (path, hashlib.sha256(raw).hexdigest()) for path, raw in sources.items()
            ),
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def closed_shell_operation_witness(raw, relative, span, call_name):
    """Reconstruct a literal shell-injection classification from captured bytes."""
    if not isinstance(raw, bytes) or len(raw) > 1_000_000:
        return {}
    supported = shell_execution_calls()
    if call_name not in supported:
        return {}
    try:
        tree = ast.parse(raw)
    except (SyntaxError, ValueError, RecursionError):
        return {}
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and [
            getattr(node, key, None)
            for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
        ]
        == span
    ]
    if len(calls) != 1:
        return {}
    call = calls[0]
    role = _closed_shell_call_role(call, call_name)
    if role is None or not _closed_shell_provider(tree, call, call_name, supported):
        return {}
    command = call.args[0].value
    return {
        "schema": "factory.closed-shell-operation.v1",
        "disposition": "PROVEN_CLOSED_OPERATION_COMMAND_SYNTAX",
        "source_path": relative,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "call_span": span,
        "call": call_name,
        "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
        "operation_role": role,
        "hypothesis": "SOURCE_COMMAND_INJECTION",
        "input_effect": "CLOSED_LITERAL_COMMAND_SYNTAX",
        "operational_effects": "LOCAL_ARTIFACT_MUTATION"
        if role == "executable_packing"
        else "METADATA_QUERY",
        "runtime_assurance": "INCOMPLETE",
        "filesystem_assurance": "UNASSESSED",
        "executable_provenance": "UNASSESSED",
        "target_execution": "not_performed",
    }


def closed_shell_finding(call_name, relative, node):
    """Keep supported fixed-operation primitives separate from injection defects."""
    from . import review_audits as audit

    if call_name not in shell_execution_calls():
        return None
    module = audit.integrity._security_module_scope(
        getattr(node, "_security_lexical_scope", None)
    )
    context = getattr(module, "_security_source_context", None)
    if not isinstance(context, tuple) or len(context) != 2:
        return None
    root, sources = context
    raw = sources.get(root / relative)
    provider = call_name.split(".")[0]
    if any(
        path.relative_to(root).parts[0] in {provider, provider + ".py"}
        for path in sources
    ):
        return None
    span = [
        getattr(node, key, None)
        for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
    ]
    proof = closed_shell_operation_witness(raw, relative, span, call_name)
    if not proof or proof["source_sha256"] != getattr(
        module, "_oracle_source_sha256", None
    ):
        return None
    captured = {
        path.relative_to(root).as_posix(): data
        for path, data in sources.items()
        if path.suffix == ".py"
    }
    inventory = closed_shell_workspace(captured, provider)
    if inventory is None:
        return None
    proof["workspace_sources_sha256"] = inventory
    return audit._security_finding(
        "SECURITY_OS_COMMAND" if call_name == "os.system" else "SECURITY_SHELL_COMMAND",
        relative,
        node,
        "Fixed supported command syntax has no source injection input; executable, filesystem and runtime safety remain unassessed.",
        "INFO",
        **proof,
    )


def _finite_membership_reference(use, parent):
    if not isinstance(parent, ast.Compare) or use not in parent.comparators:
        return False
    index = parent.comparators.index(use)
    return isinstance(parent.ops[index], (ast.In, ast.NotIn))


def _finite_container_reference(use, parent, parents):
    if not isinstance(parent, ast.Starred):
        return False
    container = parents.get(id(parent))
    return isinstance(container, ast.Set) and parent.value is use


def _finite_call_reference(use, parent):
    if not isinstance(parent, ast.Call) or use not in parent.args or parent.keywords:
        return False
    target = parent.func
    if not isinstance(target, ast.Attribute):
        return False
    if target.attr == "intersection" and isinstance(
        target.value, (ast.Set, ast.SetComp)
    ):
        return True
    return (
        target.attr == "join"
        and isinstance(target.value, ast.Constant)
        and type(target.value.value) is str
    )


def finite_domain_reference_allowed(
    path, use, tail, capture_path, capture_name, capture, parents
):
    """Allow only modeled finite-domain capture and read shapes."""
    parent = parents.get(id(use))
    if not tail and path == capture_path and use is capture_name:
        return parent is capture and capture.args[0] is use
    if tail:
        return False
    return (
        _finite_membership_reference(use, parent)
        or _finite_container_reference(use, parent, parents)
        or _finite_call_reference(use, parent)
    )


def finite_provider_attribute_write_index(nodes, aliases, audit, parents=None):
    """Build the finite provider-attribute mutation set using the shared provider mutation analysis."""
    return finite_provider_mutation_index(nodes, aliases, audit, parents or {})


def finite_blocked_provider_prefixes(blocked, aliases):
    """Expand blocked provider aliases into every dotted prefix used to reject descendants."""
    prefixes = set()
    for path, name in blocked:
        origin = aliases.get(path, {}).get(name)
        if isinstance(origin, str):
            parts = origin.split(".")
            prefixes.update(".".join(parts[:i]) for i in range(1, len(parts) + 1))
    return prefixes


def finite_scope_binding_candidate(node, origins):
    """Recognize parameter, store/delete name, global, or nonlocal bindings that intersect the finite origin set."""
    if isinstance(node, ast.arg):
        return node.arg in origins
    if isinstance(node, ast.Name):
        return node.id in origins and isinstance(node.ctx, (ast.Store, ast.Del))
    return isinstance(node, (ast.Global, ast.Nonlocal)) and bool(
        origins.intersection(node.names)
    )


def _finite_capture_decorator(function, aliases, audit):
    if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    if len(function.decorator_list) != 1 or len(function.args.args) != 1:
        return None
    decorator = function.decorator_list[0]
    if not isinstance(decorator, ast.Call) or len(decorator.args) != 2:
        return None
    if (
        decorator.keywords
        or audit._resolved_ast_name(decorator.func, aliases)
        != "pytest.mark.parametrize"
    ):
        return None
    return decorator


def _finite_capture_parameter(function, decorator):
    if len(function.args.args) != 1 or len(decorator.args) != 2:
        return None
    if (
        not isinstance(decorator.args[0], ast.Constant)
        or type(decorator.args[0].value) is not str
        or function.args.args[0].arg != decorator.args[0].value
    ):
        return None
    return decorator.args[0].value


def _finite_sorted_capture(capture, integrity):
    if not isinstance(capture, ast.Call) or not isinstance(capture.func, ast.Name):
        return None
    if capture.func.id != "sorted" or len(capture.args) != 1 or capture.keywords:
        return None
    if integrity._builtin_repr_names_shadowed(capture, {"sorted"}):
        return None
    return capture


def finite_template_capture_shape(function, aliases, audit, integrity):
    """Recognize one pytest parameter capturing a sorted finite domain."""
    decorator = _finite_capture_decorator(function, aliases, audit)
    if decorator is None:
        return None
    parameter = _finite_capture_parameter(function, decorator)
    if parameter is None:
        return None
    capture = decorator.args[1]
    capture = _finite_sorted_capture(capture, integrity)
    return (parameter, capture) if capture is not None else None


class _FiniteInputCapture:
    def finite_template_inputs(self):
        """Build source-hashed finite-template witnesses only when snapshots, parameter domains, call sites, and template hashes are complete."""
        if not self.snapshot_complete:
            return {}
        rows = {}
        for path, tree in self.trees.items():
            for function in tree.body:
                profile = self._finite_template_profile(path, function)
                if profile is None:
                    continue
                parameter, capture, domain_path, domain_name, domain, values = profile
                calls = self._finite_template_exec_calls(function)
                if not calls:
                    continue
                for call in calls:
                    template_node = call.args[0]
                    program_proof = finite_template_program_hashes(
                        template_node, parameter, values
                    )
                    if program_proof is None:
                        continue
                    _, program_hashes = program_proof
                    rows[path, call.lineno, call.col_offset] = {
                        "schema": "factory.finite-template-input.v1",
                        "disposition": "PROVEN_FINITE_TEMPLATE_INPUT",
                        "hypothesis": "ARGUMENT_CODE_INJECTION",
                        "input_effect": "FINITE_SOURCE_TEMPLATE_INPUT",
                        "runtime_assurance": "INCOMPLETE",
                        "execution_effects": "UNASSESSED",
                        "target_execution": "not_performed",
                        "source_path": path.relative_to(self.root).as_posix(),
                        "source_sha256": self.inventory[path],
                        "capture_path": path.relative_to(self.root).as_posix(),
                        "capture_sha256": self.inventory[path],
                        "capture_span": self._finite_span(capture),
                        "domain_path": domain_path.relative_to(self.root).as_posix(),
                        "domain_sha256": self.inventory[domain_path],
                        "domain_span": self._finite_span(domain),
                        "call_span": self._finite_span(call),
                        "template_span": self._finite_span(template_node),
                        "template_sha256": hashlib.sha256(
                            ast.dump(template_node, include_attributes=False).encode()
                        ).hexdigest(),
                        "domain_size": len(values),
                        "program_hashes": program_hashes,
                        "scope_profile": "pytest-collection-finite-parameter",
                    }
        return rows if self.snapshot_complete else {}

    def _finite_template_profile(self, path, function):
        candidate = finite_template_capture_shape(
            function, self.aliases[path], self.audit, self.integrity
        )
        if candidate is None:
            return None
        parameter_name, capture = candidate
        if (
            not self._finite_pytest_provider_closed(path)
            or not self._provider_is_unmodified("builtins", {"sorted", "exec"})
            or not self._finite_module_initializer_safe(self.trees[path])
        ):
            return None
        if not isinstance(capture.args[0], ast.Name):
            return None
        name = capture.args[0].id
        origin = self.resolve(path, (name,))
        if (
            not origin
            or origin[0] != "value"
            or origin[3]
            or (path, name) in self.blocked
        ):
            return None
        domain_path, domain_name = origin[1:3]
        if not self._finite_module_initializer_safe(self.trees[domain_path]):
            return None
        domain = self.objects.get((domain_path, domain_name))
        declaration = self._finite_domain_declaration(domain_path, domain_name, domain)
        values = self._finite_domain_values(domain)
        if (
            not declaration
            or values is None
            or not self._finite_domain_uses(
                domain_path, domain_name, path, capture.args[0], capture
            )
        ):
            return None
        if not self._finite_function_closed(path, function, parameter_name):
            return None
        return (
            parameter_name,
            capture,
            domain_path,
            domain_name,
            declaration,
            values,
        )

    def _finite_domain_declaration(self, path, name, value):
        binding = self._unique_name_assignment(self.trees[path], name)
        target = (
            binding.targets[0]
            if isinstance(binding, ast.Assign) and len(binding.targets) == 1
            else binding.target
            if isinstance(binding, ast.AnnAssign)
            else None
        )
        return (
            value
            if isinstance(value, ast.Set)
            and (path, name) not in self.blocked
            and isinstance(binding, (ast.Assign, ast.AnnAssign))
            and binding.value is value
            and isinstance(target, ast.Name)
            and target.id == name
            else None
        )

    def _finite_domain_values(self, domain):
        if not isinstance(domain, ast.Set) or not 1 <= len(domain.elts) <= 64:
            return None
        if any(
            not isinstance(node, ast.Constant) or type(node.value) is not str
            for node in domain.elts
        ):
            return None
        values = [node.value for node in domain.elts]
        return sorted(values) if len(set(values)) == len(values) else None

    def _finite_domain_uses(
        self, domain_path, domain_name, capture_path, capture_name, capture
    ):
        refs = self.refs.get(("value", domain_path, domain_name), [])
        if not refs or any(
            source == domain_path and symbol in {None, domain_name}
            for source, symbol in self.unmodeled_imports
        ):
            return False
        return all(
            finite_domain_reference_allowed(
                path, use, tail, capture_path, capture_name, capture, self.parents
            )
            for path, use, tail in refs
        )

    def _finite_function_closed(self, path, function, parameter_name):
        return not (
            self.refs.get(("function", path, function.name))
            or any(
                source == path and symbol in {None, function.name}
                for source, symbol in self.unmodeled_imports
            )
            or any(
                item == (path, function.name) or item == (path, None)
                for view in self.imports.values()
                for item in view.values()
            )
            or any(
                argument.arg == parameter_name
                for statement in function.body
                for argument in ast.walk(statement)
                if isinstance(argument, ast.arg)
            )
            or any(
                parameter_name in self.audit._bound_names(statement)
                for statement in function.body
            )
        )

    def _finite_template_exec_calls(self, function):
        calls = [
            node
            for node in self._walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "exec"
        ]
        if not 1 <= len(calls) <= 64:
            return None
        for call in calls:
            if (
                not call.args
                or not isinstance(call.args[0], ast.JoinedStr)
                or self.integrity._builtin_repr_names_shadowed(call, {"exec"})
            ):
                return None
        return calls

    @staticmethod
    def _finite_span(node):
        return [
            getattr(node, name, None)
            for name in ("lineno", "col_offset", "end_lineno", "end_col_offset")
        ]


def _fixed_literal_value(node):
    literal_types = (str, bytes, int, float, complex, bool, type(None), type(Ellipsis))
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, ast.Constant):
            if type(current.value) not in literal_types:
                return False
        elif isinstance(current, ast.UnaryOp):
            if (
                not isinstance(current.op, (ast.UAdd, ast.USub))
                or not isinstance(current.operand, ast.Constant)
                or type(current.operand.value) not in {int, float, complex}
            ):
                return False
            stack.append(current.operand)
        elif isinstance(current, ast.Dict):
            if any(key is None for key in current.keys):
                return False
            stack.extend(ast.iter_child_nodes(current))
        elif isinstance(current, (ast.List, ast.Tuple, ast.Set, ast.Load)):
            stack.extend(ast.iter_child_nodes(current))
        else:
            return False
    try:
        ast.literal_eval(node)
    except (
        ValueError,
        TypeError,
        SyntaxError,
        MemoryError,
        RecursionError,
        OverflowError,
    ):
        return False
    return True


def _finite_eval_comprehension(tree, call):
    parents = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
    cursor = parents.get(call)
    while cursor is not None and not isinstance(cursor, ast.ListComp):
        if isinstance(
            cursor, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            return None
        cursor = parents.get(cursor)
    if cursor is None or len(cursor.generators) != 1:
        return None
    return cursor


def _finite_eval_domain(cursor, call):
    if cursor is None:
        return None
    generator = cursor.generators[0]
    if (
        generator.is_async
        or generator.ifs
        or not isinstance(generator.target, ast.Tuple)
        or not all(isinstance(n, ast.Name) for n in generator.target.elts)
        or not isinstance(generator.iter, (ast.List, ast.Tuple))
        or not 1 <= len(generator.iter.elts) <= 64
    ):
        return None
    names = [n.id for n in generator.target.elts]
    if len(set(names)) != len(names) or call.args[0].id not in names:
        return None
    target = generator.target.elts[names.index(call.args[0].id)]
    if any(
        n.id == target.id and n is not target and n is not call.args[0]
        for n in ast.walk(cursor)
        if isinstance(n, ast.Name)
    ):
        return None
    programs = []
    for row in generator.iter.elts:
        if (
            not isinstance(row, (ast.Tuple, ast.List))
            or len(row.elts) != len(names)
            or not _fixed_literal_value(row)
        ):
            return None
        value = row.elts[names.index(target.id)]
        if (
            not isinstance(value, ast.Constant)
            or type(value.value) is not str
            or len(value.value) > 4096
        ):
            return None
        try:
            expression = ast.parse(value.value, mode="eval")
        except (SyntaxError, ValueError, RecursionError):
            return None
        allowed = (
            ast.Expression,
            ast.Name,
            ast.Subscript,
            ast.Tuple,
            ast.List,
            ast.Load,
            ast.Constant,
            ast.BinOp,
            ast.BitOr,
        )
        if any(not isinstance(n, allowed) for n in ast.walk(expression)):
            return None
        programs.append(value.value)
    return generator.iter, programs


def _finite_eval_module_prefix(tree, comprehension):
    """Module initializer profile: later test bodies cannot run before this input."""
    prefix = []
    for statement in tree.body:
        if (
            isinstance(statement, (ast.Assign, ast.AnnAssign))
            and statement.value is comprehension
        ):
            return ast.Module(body=[*prefix, statement], type_ignores=[])
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            prefix.append(statement)
        elif isinstance(
            statement, (ast.Assign, ast.AnnAssign)
        ) and _fixed_literal_value(statement.value):
            prefix.append(statement)
        else:
            return None
    return None


def _finite_eval_source_shape(node, call_name, source_bytes, source_path):
    if (
        call_name != "eval"
        or not isinstance(node, ast.Call)
        or not isinstance(node.func, ast.Name)
        or node.func.id != "eval"
        or len(node.args) != 1
        or node.keywords
        or not isinstance(node.args[0], ast.Name)
        or not isinstance(source_bytes, bytes)
        or not isinstance(source_path, str)
    ):
        return False
    return True


def _finite_eval_source_call(node, call_name, source_bytes, source_path):
    if not _finite_eval_source_shape(node, call_name, source_bytes, source_path):
        return None
    try:
        tree = ast.parse(source_bytes)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return None

    matches = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and _finite_source_span(n) == _finite_source_span(node)
    ]
    if len(matches) != 1 or ast.dump(matches[0]) != ast.dump(node):
        return None
    return tree, matches[0]


def _finite_source_span(node):
    return [
        getattr(node, key, None)
        for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
    ]


def _finite_eval_closed_domain(tree, call):
    comprehension = _finite_eval_comprehension(tree, call)
    domain = _finite_eval_domain(comprehension, call)
    if domain is None:
        return None
    prefix = _finite_eval_module_prefix(tree, comprehension)
    if prefix is None:
        return None
    from .runtime_audit_integrity import _closed_declaration_binding

    if not _closed_declaration_binding(prefix, call):
        return None
    return comprehension, domain


def _finite_eval_witness_facts(source_bytes, source_path, call, comprehension, domain):
    domain_node, programs = domain
    import json

    return {
        "schema": "factory.finite-eval-input.v1",
        "disposition": "PROVEN_FINITE_LITERAL_EVAL_INPUT",
        "source_path": source_path,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "call_span": _finite_source_span(call),
        "domain_span": _finite_source_span(domain_node),
        "comprehension_span": _finite_source_span(comprehension),
        "program_sha256": hashlib.sha256(
            json.dumps(programs, separators=(",", ":")).encode()
        ).hexdigest(),
        "domain_size": len(programs),
        "hypothesis": "ARGUMENT_CODE_INJECTION",
        "scope_profile": "module-initializer-literal-table",
        "input_effect": "CLOSED_LITERAL_TYPE_EXPRESSIONS",
        "runtime_assurance": "INCOMPLETE",
        "target_execution": "not_performed",
    }


def finite_literal_eval_input_witness(node, call_name, *, source_bytes, source_path):
    """Prove finite source input only, not the effects of resolving type objects."""
    source_call = _finite_eval_source_call(node, call_name, source_bytes, source_path)
    if source_call is None:
        return {}
    tree, call = source_call
    closed_domain = _finite_eval_closed_domain(tree, call)
    if closed_domain is None:
        return {}
    comprehension, domain = closed_domain
    return _finite_eval_witness_facts(
        source_bytes, source_path, call, comprehension, domain
    )


def _finite_template_program_hash(program, value):
    import keyword

    if (
        not isinstance(value, str)
        or not value.isidentifier()
        or keyword.iskeyword(value)
    ):
        return None
    try:
        if len(program.encode("utf-8")) > 4096:
            return None
        tree = ast.parse(program, mode="exec")
    except (SyntaxError, ValueError, MemoryError, RecursionError, UnicodeError):
        return None
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.AsyncFunctionDef):
        return None
    function = tree.body[0]
    args = function.args
    if (
        function.decorator_list
        or args.posonlyargs
        or len(args.args) != 1
        or args.args[0].arg != value
        or args.vararg is not None
        or args.kwonlyargs
        or args.kwarg is not None
        or args.defaults
        or args.kw_defaults
        or not isinstance(function.returns, ast.Constant)
        or function.returns.value is not None
        or len(function.body) != 1
        or not isinstance(function.body[0], ast.Pass)
    ):
        return None
    args.args[0].arg = "FINITE_PARAMETER"
    return hashlib.sha256(program.encode("utf-8")).hexdigest(), ast.dump(
        tree, include_attributes=False
    )


def _finite_template_piece(item, parameter):
    if isinstance(item, ast.Constant) and type(item.value) is str:
        return True, item.value, False
    if (
        isinstance(item, ast.FormattedValue)
        and isinstance(item.value, ast.Name)
        and item.value.id == parameter
        and item.conversion == -1
        and item.format_spec is None
    ):
        return True, None, True
    return False, None, False


def _finite_template_skeleton(template, parameter, values):
    if not isinstance(template, ast.JoinedStr) or not isinstance(parameter, str):
        return None
    pieces, holes = [], 0
    for item in template.values:
        valid, piece, is_hole = _finite_template_piece(item, parameter)
        if not valid:
            return None
        pieces.append(piece)
        holes += is_hole
    if holes != 1 or not 1 <= len(values) <= 64:
        return None
    return pieces


def _finite_template_hash_rows(pieces, values):
    hashes, skeleton = [], None
    for value in values:
        program = "".join(value if part is None else part for part in pieces)
        result = _finite_template_program_hash(program, value)
        if result is None or (skeleton is not None and result[1] != skeleton):
            return None
        hashes.append(result[0])
        skeleton = result[1]
    return hashlib.sha256(skeleton.encode()).hexdigest(), hashes


def finite_template_program_hashes(template, parameter, values):
    """Hash every bounded rendering after checking one fixed async-function grammar."""
    pieces = _finite_template_skeleton(template, parameter, values)
    if pieces is None:
        return None
    return _finite_template_hash_rows(pieces, values)


def _provider_mutation_for_node(
    node, aliases, audit, parents, bindings, facts, capture_predicate
):
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
        _record_provider_paths(node.value, node.attr, aliases, audit, bindings, facts)
    elif isinstance(node, ast.Call):
        _reflective_provider_write(node, aliases, audit, bindings, facts)
    elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
        if capture_predicate is None or capture_predicate(node):
            _record_provider_capture(node, aliases, audit, bindings, facts)
    elif isinstance(node, (ast.Name, ast.Attribute)) and _provider_call_argument(
        node, parents
    ):
        _record_provider_paths(node, "*", aliases, audit, bindings, facts)
    elif isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)):
        _record_provider_paths(node.value, "*", aliases, audit, bindings, facts)


def finite_provider_mutation_index(
    nodes, aliases, audit, parents, *, capture_predicate=None
):
    """Collect provider mutation facts from writes, reflective calls, captured assignments, passed aliases, and returned aliases."""
    bindings = _provider_alias_bindings(nodes)
    facts = set()
    for node in nodes:
        _provider_mutation_for_node(
            node, aliases, audit, parents, bindings, facts, capture_predicate
        )
    return facts


def _record_provider_paths(node, attribute, aliases, audit, bindings, facts):
    paths, uncertain = _provider_paths(node, aliases, audit, bindings)
    facts.update((path, attribute) for path in paths)
    if uncertain:
        facts.update((path, "*") for path in paths)


def _record_provider_capture(node, aliases, audit, bindings, facts):
    value = node.value
    paths, _ = _provider_paths(value, aliases, audit, bindings)
    facts.update((path, "*") for path in paths)


def _provider_alias_bindings(nodes):
    bindings = defaultdict(list)
    for node in nodes:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bindings[target.id].append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                bindings[node.target.id].append(node.value)
    return bindings


def _provider_paths(node, aliases, audit, bindings, seen=frozenset(), depth=0):
    if depth > 16 or not isinstance(node, (ast.Name, ast.Attribute)):
        return set(), True
    if isinstance(node, ast.Attribute):
        paths, uncertain = _provider_paths(
            node.value, aliases, audit, bindings, seen, depth + 1
        )
        return {path + "." + node.attr for path in paths}, uncertain
    canonical = audit._resolved_ast_name(node, aliases)
    if "." in canonical:
        return {canonical}, False
    if aliases.get(node.id) == canonical and canonical:
        return {canonical}, False
    if node.id in seen:
        return set(), True
    values = bindings.get(node.id)
    if not values:
        return set(), True
    paths = set()
    uncertain = False
    for value in values:
        found, unknown = _provider_paths(
            value, aliases, audit, bindings, seen | {node.id}, depth + 1
        )
        paths.update(found)
        uncertain = uncertain or unknown or not found
    return paths, uncertain and bool(paths)


def _provider_call_argument(node, parents):
    child = node
    parent = parents.get(id(child))
    while parent is not None and not isinstance(parent, ast.Call):
        child = parent
        parent = parents.get(id(parent))
    return bool(
        isinstance(parent, ast.Call)
        and (
            any(argument is child for argument in parent.args)
            or any(
                keyword is child or keyword.value is child
                for keyword in parent.keywords
            )
        )
    )


def _reflective_provider_write(call, aliases, audit, bindings, facts):
    function = call.func
    canonical = audit._resolved_ast_name(function, aliases)
    receiver = None
    attribute = None
    if canonical in {"setattr", "builtins.setattr"} and len(call.args) >= 2:
        receiver, attribute = call.args[:2]
    elif (
        isinstance(function, ast.Attribute)
        and function.attr == "__setattr__"
        and call.args
    ):
        receiver, attribute = function.value, call.args[0]
    if receiver is None:
        return
    paths, uncertain = _provider_paths(receiver, aliases, audit, bindings)
    name = (
        attribute.value
        if isinstance(attribute, ast.Constant) and type(attribute.value) is str
        else "*"
    )
    facts.update((path, name) for path in paths)
    if uncertain:
        facts.update((path, "*") for path in paths)


def _fixed_program_span(node):
    span = [
        getattr(node, key, None)
        for key in ("lineno", "col_offset", "end_lineno", "end_col_offset")
    ]
    if (
        any(type(value) is not int for value in span)
        or span[0] < 1
        or min(span[1], span[3]) < 0
        or tuple(span[:2]) > tuple(span[2:])
    ):
        return None
    return span


def _fixed_eval_name_hazard(item, selected_func, sensitive_names):
    if isinstance(item, ast.Name) and item.id in sensitive_names:
        return item is not selected_func
    if isinstance(item, ast.arg) and item.arg in sensitive_names:
        return True
    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return item.name in sensitive_names
    return isinstance(item, ast.ExceptHandler) and item.name in sensitive_names


def _fixed_eval_import_hazard(item, sensitive_names):
    if isinstance(item, ast.alias):
        bound = item.asname or item.name.split(".", 1)[0]
        return item.name == "builtins" or bound in sensitive_names
    return isinstance(item, ast.ImportFrom) and (
        item.module == "builtins" or any(alias.name == "*" for alias in item.names)
    )


def _fixed_eval_attribute_hazard(item):
    sensitive = {
        "__dict__",
        "__globals__",
        "__builtins__",
        "__getattribute__",
        "__setattr__",
        "import_module",
    }
    return isinstance(item, ast.Attribute) and (
        item.attr in sensitive
        or (
            item.attr in {"exec", "eval"} and isinstance(item.ctx, (ast.Store, ast.Del))
        )
    )


def _fixed_eval_builtin_source_clear(tree, selected_call):
    names = {
        "__builtins__",
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "delattr",
        "__import__",
        "exec",
        "eval",
    }
    selected_func = selected_call.func
    return not any(
        _fixed_eval_name_hazard(item, selected_func, names)
        or _fixed_eval_import_hazard(item, names)
        or _fixed_eval_attribute_hazard(item)
        for item in ast.walk(tree)
    )


def _fixed_eval_builtin_aliases(tree):
    builtins_aliases, importlib_aliases, sys_aliases = set(), set(), set()
    importer_aliases = {"__import__"}
    for item in ast.walk(tree):
        if isinstance(item, ast.Import):
            destinations = {
                "builtins": builtins_aliases,
                "importlib": importlib_aliases,
                "sys": sys_aliases,
            }
            for alias in item.names:
                if alias.name in destinations:
                    destinations[alias.name].add(alias.asname or alias.name)
        if isinstance(item, ast.ImportFrom) and item.module == "builtins":
            importer_aliases.update(
                alias.asname or alias.name
                for alias in item.names
                if alias.name == "__import__"
            )
        if isinstance(item, ast.ImportFrom) and item.module in {
            "importlib",
            "importlib.util",
        }:
            importer_aliases.update(
                alias.asname or alias.name
                for alias in item.names
                if alias.name == "import_module"
            )
    return builtins_aliases, importlib_aliases, sys_aliases, importer_aliases


def _fixed_eval_provider_root(node, builtins_aliases, importer_aliases, sys_aliases):
    if isinstance(node, ast.Name) and node.id in builtins_aliases:
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return (
            node.func.id in importer_aliases
            and bool(node.args)
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "builtins"
        )
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute):
        key = node.slice.value if isinstance(node.slice, ast.Constant) else None
        return (
            node.value.attr == "modules"
            and key == "builtins"
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id in sys_aliases
        )
    return False


def _fixed_eval_provider_capability(
    node, builtins_aliases, importer_aliases, sys_aliases
):
    if _fixed_eval_provider_root(node, builtins_aliases, importer_aliases, sys_aliases):
        return True
    if isinstance(node, ast.Attribute) and node.attr == "modules":
        return isinstance(node.value, ast.Name) and node.value.id in sys_aliases
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return _fixed_eval_provider_root(
            node.value, builtins_aliases, importer_aliases, sys_aliases
        )
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "vars"
        and bool(node.args)
        and _fixed_eval_provider_root(
            node.args[0], builtins_aliases, importer_aliases, sys_aliases
        )
    )


def _fixed_eval_provider_alias_escape(
    tree, builtins_aliases, importer_aliases, sys_aliases
):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and any(
            _fixed_eval_provider_capability(
                child, builtins_aliases, importer_aliases, sys_aliases
            )
            for arg in [*node.args, *(keyword.value for keyword in node.keywords)]
            for child in ast.walk(arg)
        ):
            return True
        if isinstance(node, ast.ImportFrom):
            if node.module in {
                "builtins",
                "sys",
                "importlib",
                "importlib.util",
            } and any(
                alias.name
                in {"__dict__", "__getattribute__", "__setattr__", "__getattr__"}
                for alias in node.names
            ):
                return True
            if node.module == "sys" and any(
                alias.name == "modules" for alias in node.names
            ):
                return True
        value = None
        targets = []
        if isinstance(node, ast.Assign):
            value, targets = node.value, node.targets
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            value, targets = node.value, [node.target]
        if value is None:
            continue
        binds_name = any(
            isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
            for target in targets
            for child in ast.walk(target)
        )
        if binds_name and any(
            _fixed_eval_provider_capability(
                child, builtins_aliases, importer_aliases, sys_aliases
            )
            for child in ast.walk(value)
        ):
            return True
    return False


def _fixed_eval_builtin_write(node, builtins_aliases, importer_aliases, sys_aliases):
    if isinstance(node, ast.Name) and node.id == "__builtins__":
        return True
    if (
        isinstance(node, ast.Name)
        and node.id in {"eval", "exec"}
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ):
        return True
    if isinstance(node, ast.Attribute) and node.attr in {"eval", "exec"}:
        return isinstance(node.ctx, (ast.Store, ast.Del)) and _fixed_eval_provider_root(
            node.value, builtins_aliases, importer_aliases, sys_aliases
        )
    if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return _fixed_eval_builtin_subscript(
            node, builtins_aliases, importer_aliases, sys_aliases
        )
    return False


def _fixed_eval_builtin_subscript(
    node, builtins_aliases, importer_aliases, sys_aliases
):
    if not isinstance(node.value, ast.Attribute) or node.value.attr != "__dict__":
        return False
    if not _fixed_eval_provider_root(
        node.value.value, builtins_aliases, importer_aliases, sys_aliases
    ):
        return False
    key = node.slice.value if isinstance(node.slice, ast.Constant) else None
    return key in {None, "eval", "exec"}


def _fixed_eval_builtin_reflection(
    node, builtins_aliases, importlib_aliases, importer_aliases, sys_aliases
):
    if isinstance(node, ast.Attribute) and node.attr in {"__globals__", "__builtins__"}:
        return True
    if isinstance(node, ast.Attribute) and node.attr in {
        "__dict__",
        "__getattribute__",
        "__setattr__",
        "eval",
        "exec",
    }:
        if _fixed_eval_provider_root(
            node.value, builtins_aliases, importer_aliases, sys_aliases
        ):
            return node.attr in {
                "__dict__",
                "__getattribute__",
                "__setattr__",
            } or isinstance(node.ctx, (ast.Store, ast.Del))
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    reflective = isinstance(func, ast.Name) and func.id in {
        "setattr",
        "delattr",
        "getattr",
    }
    if isinstance(func, ast.Attribute):
        reflective |= func.attr in {"setattr", "delattr", "getattr"}
    return (
        reflective
        and bool(node.args)
        and _fixed_eval_provider_root(
            node.args[0], builtins_aliases, importer_aliases, sys_aliases
        )
    )


def _fixed_eval_dynamic_import_risk(node, importlib_aliases, importer_aliases):
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    direct = isinstance(func, ast.Name) and func.id in importer_aliases
    imported = (
        isinstance(func, ast.Attribute)
        and func.attr == "import_module"
        and isinstance(func.value, ast.Name)
        and func.value.id in importlib_aliases
    )
    if not (direct or imported):
        return False
    if not node.args:
        return True
    name = node.args[0]
    return (
        not isinstance(name, ast.Constant)
        or type(name.value) is not str
        or name.value.split(".", 1)[0] in {"builtins", "sys", "importlib"}
    )


def _fixed_eval_module_alias_escape(tree, aliases):
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Name)
            and node.id in aliases
            and isinstance(node.ctx, ast.Load)
        ):
            continue
        parent = parents.get(id(node))
        if (
            isinstance(parent, ast.Attribute)
            and parent.value is node
            and parent.attr
            not in {"__dict__", "__getattribute__", "__setattr__", "__getattr__"}
        ):
            continue
        return True
    return False


def _fixed_eval_module_scope(tree, target):
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    current = target
    while id(current) in parents:
        parent = parents[id(current)]
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if current in parent.body:
                return False
        elif isinstance(parent, ast.Lambda) and current is parent.body:
            return False
        current = parent
    return True


def _fixed_eval_interpreter_aliases(tree):
    aliases = {"eval", "exec"}
    aliases.update(
        alias.asname or alias.name
        for item in ast.walk(tree)
        if isinstance(item, ast.ImportFrom) and item.module == "builtins"
        for alias in item.names
        if alias.name in {"eval", "exec"}
    )
    assignments = [item for item in ast.walk(tree) if isinstance(item, ast.Assign)]
    for _ in range(len(assignments) + 1):
        before = set(aliases)
        for item in assignments:
            if isinstance(item.value, ast.Name) and item.value.id in aliases:
                aliases.update(
                    target.id for target in item.targets if isinstance(target, ast.Name)
                )
        if before == aliases:
            break
    return aliases


def _fixed_eval_interpreter_call(node, aliases):
    if not isinstance(node, ast.Call):
        return None
    function = node.func
    name = function.id if isinstance(function, ast.Name) else None
    if name is None and isinstance(function, ast.Attribute):
        name = function.attr
    return name if name in aliases else None


def _fixed_eval_callable_reaches_risk(node, aliases, risky, unresolved_classes):
    for item in ast.walk(node):
        if _fixed_eval_interpreter_call(item, aliases) is not None:
            return True
        if (
            isinstance(item, ast.Call)
            and isinstance(item.func, ast.Name)
            and item.func.id in risky | unresolved_classes
        ):
            return True
    return False


def _fixed_eval_class_init_hooks(node):
    hooks = [
        item
        for item in node.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name in {"__new__", "__init__"}
    ]
    unresolved = bool(node.bases or node.keywords or node.decorator_list)
    return hooks, unresolved


def _fixed_eval_local_class_aliases(tree, class_names):
    aliases = set()
    for _ in range(len(tree.body) + 1):
        added = False
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target, value = node.targets[0], node.value
            elif isinstance(node, ast.AnnAssign):
                target, value = node.target, node.value
            else:
                continue
            if (
                isinstance(target, ast.Name)
                and isinstance(value, ast.Name)
                and value.id in class_names | aliases
                and target.id not in class_names | aliases
            ):
                aliases.add(target.id)
                added = True
        if not added:
            break
    return aliases


def _fixed_eval_local_function_risks(functions, aliases, risky, constructors):
    added = False
    for name, function in functions.items():
        if name not in risky and _fixed_eval_callable_reaches_risk(
            function, aliases, risky, constructors
        ):
            risky.add(name)
            added = True
    return added


def _fixed_eval_local_class_risks(classes, aliases, risky, constructors):
    added = False
    for name, (hooks, _) in classes.items():
        if name in risky:
            continue
        if any(
            _fixed_eval_callable_reaches_risk(hook, aliases, risky, constructors)
            for hook in hooks
        ):
            risky.add(name)
            added = True
    return added


def _fixed_eval_module_init_constructor_call(tree, constructor_names):
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in constructor_names
        and _fixed_eval_module_scope(tree, node)
        for node in ast.walk(tree)
    )


def _fixed_eval_module_init_risky_reference(tree, risky):
    return any(
        isinstance(node, ast.Name)
        and node.id in risky
        and isinstance(node.ctx, ast.Load)
        and _fixed_eval_module_scope(tree, node)
        for node in ast.walk(tree)
    )


def _fixed_eval_interpreter_payload(node, name):
    if not node.args or not isinstance(node.args[0], ast.Constant):
        return None
    code = node.args[0].value
    if type(code) is not str:
        return None
    try:
        if len(code.encode("utf-8")) > 16 * 1024:
            return None
    except UnicodeEncodeError:
        return None
    try:
        return ast.parse(code, mode="eval" if name == "eval" else "exec")
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return None


def _fixed_eval_nested_interpreter_risk(tree, depth):
    aliases = _fixed_eval_interpreter_aliases(tree)
    for node in ast.walk(tree):
        name = _fixed_eval_interpreter_call(node, aliases)
        if name is None:
            continue
        nested = _fixed_eval_interpreter_payload(node, name)
        if nested is None:
            if _fixed_eval_module_scope(tree, node):
                return True
            continue
        if isinstance(nested, ast.Expression):
            expression = ast.copy_location(ast.Expr(value=nested.body), nested.body)
            nested = ast.Module(body=[expression], type_ignores=[])
        if _fixed_eval_builtin_provider_risk(nested, depth + 1):
            return True
    return False


def _fixed_eval_local_init_call_risk(tree):
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    classes = {
        node.name: _fixed_eval_class_init_hooks(node)
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    if not functions and not classes:
        return False
    aliases = _fixed_eval_interpreter_aliases(tree)
    unresolved_classes = {
        name for name, (_, unresolved) in classes.items() if unresolved
    }
    class_aliases = _fixed_eval_local_class_aliases(tree, unresolved_classes)
    constructor_names = unresolved_classes | class_aliases
    risky = set()
    for _ in range(len(functions) + len(classes) + 1):
        added = _fixed_eval_local_function_risks(
            functions, aliases, risky, constructor_names
        )
        added |= _fixed_eval_local_class_risks(
            classes, aliases, risky, constructor_names
        )
        if not added:
            break
    return _fixed_eval_module_init_constructor_call(
        tree, constructor_names
    ) or _fixed_eval_module_init_risky_reference(tree, risky)


def _fixed_eval_builtin_provider_risk(tree, depth=0):
    """Reject source-visible provider writes and opaque module-init eval/exec effects.

    Dynamic sinks inside function bodies remain separate alerts; this source
    profile does not establish runtime isolation or order across invocations.
    """
    if depth > 4:
        return True
    builtins_aliases, importlib_aliases, sys_aliases, importer_aliases = (
        _fixed_eval_builtin_aliases(tree)
    )
    if (
        _fixed_eval_module_alias_escape(tree, builtins_aliases)
        or _fixed_eval_module_alias_escape(tree, importlib_aliases)
        or _fixed_eval_module_alias_escape(tree, sys_aliases)
        or _fixed_eval_provider_alias_escape(
            tree, builtins_aliases, importer_aliases, sys_aliases
        )
    ):
        return True
    for node in ast.walk(tree):
        if _fixed_eval_builtin_write(
            node, builtins_aliases, importer_aliases, sys_aliases
        ):
            return True
        if _fixed_eval_builtin_reflection(
            node, builtins_aliases, importlib_aliases, importer_aliases, sys_aliases
        ):
            return True
        if _fixed_eval_dynamic_import_risk(node, importlib_aliases, importer_aliases):
            return True
    if _fixed_eval_local_init_call_risk(tree):
        return True
    return _fixed_eval_nested_interpreter_risk(tree, depth)


def fixed_eval_workspace_provider_clear(source_bytes, source_rows):
    """Recheck a complete hash-bound workspace for source-visible eval-provider mutation."""
    if not isinstance(source_bytes, dict) or not isinstance(source_rows, list):
        return False
    python_rows = [
        row
        for row in source_rows
        if isinstance(row, dict)
        and isinstance(row.get("path"), str)
        and row["path"].endswith(".py")
    ]
    if not python_rows:
        return False
    expected = {row["path"]: row.get("sha256") for row in python_rows}
    if len(expected) != len(python_rows):
        return False
    for relative, digest in expected.items():
        raw = source_bytes.get(relative)
        if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != digest:
            return False
        try:
            tree = ast.parse(raw, filename=relative)
        except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
            return False
        if _fixed_eval_builtin_provider_risk(tree):
            return False
    return True


def captured_sink_evidence(
    node,
    *,
    source_path,
    source_sha256,
    source_index=None,
    source_bytes=None,
    tree=None,
    max_sources=64,
    max_states=512,
    max_output_bytes=64000,
):
    """Capture a bounded source-linked sink ledger; never certify safety."""
    import json

    schema = "factory.captured-sink-evidence.v1"
    ctx = _captured_sink_source(
        source_path,
        source_sha256,
        source_index,
        source_bytes,
        tree,
        max_sources,
        max_states,
        max_output_bytes,
        schema,
    )
    if "error" in ctx:
        return ctx["error"]
    located = _captured_sink_location(node, ctx)
    if "error" in located:
        return located["error"]
    node, parents, tree = located["node"], located["parents"], ctx["tree"]
    base, digest, text, limits = (ctx[k] for k in ("base", "digest", "text", "limits"))
    truncation = []

    def fact(item, state="OBSERVED"):
        """Bind a sink fact to this captured source and digest."""
        return _captured_sink_fact(item, base["source"]["path"], digest, state)

    def excerpt(item):
        """Render a bounded excerpt and retain any truncation evidence."""
        return _captured_sink_excerpt(item, text, truncation)

    scope = _captured_sink_scope(node, parents, fact, limits[1], base)
    if "error" in scope:
        return scope["error"]
    nodes, body, statement = scope["nodes"], scope["body"], scope["statement"]
    arguments, names, callee_names = _captured_sink_arguments(node, fact, excerpt)
    imports = _captured_sink_imports(
        tree, scope["scope"], nodes, parents, fact, limits[1], base
    )
    if "error" in imports:
        return imports["error"]
    values = _captured_sink_values(
        node,
        names,
        scope["scope"],
        body,
        statement,
        nodes,
        parents,
        tree,
        fact,
        excerpt,
    )
    callers = {"status": "UNKNOWN", "reason": "caller_expansion_not_performed"}
    states_used = len(nodes) + imports["states_used"]
    result = {
        **base,
        "status": "INCOMPLETE" if truncation else "COMPLETE",
        "source": {**base["source"], "line_count": len(text.splitlines())},
        "sink": {
            "status": "OBSERVED",
            "call": excerpt(node.func),
            "span": _fixed_program_span(node),
            "arguments": arguments,
            **fact(node),
        },
        "scope": scope["row"],
        "imports": imports["rows"],
        "values": values,
        "guards": _captured_sink_guards(node, scope["scope"], parents, fact, excerpt),
        "callee_binding": _captured_sink_callee_binding(
            callee_names, scope["scope"], body, tree, imports["module_imports"], fact
        ),
        "callers": callers,
        "provider": {
            "status": "UNKNOWN",
            "reason": "provider_identity_not_established",
        },
        "effects": {"status": "UNKNOWN", "reason": "runtime_effects_not_observed"},
        "authority": {"status": "UNKNOWN", "reason": "trust_boundary_not_declared"},
        "budget": {
            "sources_used": 1,
            "sources_limit": limits[0],
            "states_used": states_used,
            "states_limit": limits[1],
            "source_ast_nodes_examined": located["source_ast_nodes_examined"],
            "source_ast_limit": 200_000,
            "snapshot_index_reused": ctx["indexed"],
            "serialized_bytes_limit": limits[2],
        },
        "truncation": truncation,
    }
    size = len(json.dumps(result, sort_keys=True, separators=(",", ":")).encode())
    return (
        result
        if size <= limits[2]
        else _captured_sink_failure(
            schema, "SINK_BUDGET_EXHAUSTED", "max_output_bytes", base
        )
    )


def _captured_sink_failure(schema, code, reason, base=None):
    return {
        **(base or {"schema": schema, "status": "INCOMPLETE"}),
        "code": code,
        "truncation": [reason],
    }


def _captured_sink_source(
    path_arg, expected, index, raw, tree, max_sources, max_states, max_output, schema
):
    import io
    import tokenize

    limits = (max_sources, max_states, max_output)
    if any(type(value) is not int or value < 1 for value in limits) or max_output < 256:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_INVALID", "invalid_limit"
            )
        }
    limits = tuple(
        min(value, ceiling) for value, ceiling in zip(limits, (64, 512, 64000))
    )
    path = path_arg.as_posix() if hasattr(path_arg, "as_posix") else path_arg
    tree_supplied = tree is not None
    indexed = index is not None
    if indexed:
        capture = _captured_sink_index(index, path_arg, raw, path, schema)
        if "error" in capture:
            return capture
        raw, tree, parents = capture["raw"], capture["tree"], capture["parents"]
    else:
        parents = None
    if not isinstance(path, str) or not path:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "invalid_source_path"
            )
        }
    if not isinstance(raw, bytes) or len(raw) > 1_000_000:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_EXHAUSTED", "max_source_bytes"
            )
        }
    digest = hashlib.sha256(raw).hexdigest()
    if not isinstance(expected, str) or expected != digest:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_hash_mismatch"
            )
        }
    if not indexed:
        capture = _captured_sink_raw_tree(path, raw, tree, schema)
        if "error" in capture:
            return capture
        tree, parents = capture["tree"], capture["parents"]
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        text = raw.decode(encoding)
    except (SyntaxError, UnicodeError, LookupError):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_encoding_invalid"
            )
        }
    base = {
        "schema": schema,
        "status": "INCOMPLETE",
        "source": {"path": path[:1024], "sha256": digest, "bytes": len(raw)},
        "source_count": 1,
    }
    return {
        "tree": tree,
        "parents": parents,
        "text": text,
        "base": base,
        "digest": digest,
        "limits": limits,
        "indexed": indexed,
        "tree_supplied": tree_supplied,
    }


def _captured_sink_index(index, path_arg, raw, path, schema):
    inventory = getattr(index, "source_bytes", {})
    if not isinstance(path, str) or path_arg not in getattr(index, "snapshots", {}):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_not_indexed"
            )
        }
    if (
        sum(len(value) for value in inventory.values() if isinstance(value, bytes))
        > 32_000_000
    ):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_EXHAUSTED", "max_inventory_bytes"
            )
        }
    captured = inventory.get(path_arg)
    if raw is not None and raw != captured:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_bytes_changed"
            )
        }
    if not isinstance(captured, bytes) or len(captured) > 1_000_000:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_BUDGET_EXHAUSTED", "max_source_bytes"
            )
        }
    validation_inputs = getattr(index, "_validation_inputs", None)
    if not isinstance(validation_inputs, dict):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_validation_cache_unavailable"
            )
        }
    validation_inputs.pop(path_arg, None)
    if not index.validate(path_arg):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_snapshot_invalid"
            )
        }
    return {
        "raw": captured,
        "tree": index.snapshots[path_arg],
        "parents": index.parents[path_arg],
    }


def _captured_sink_raw_tree(path, raw, tree, schema):
    try:
        parsed = ast.parse(raw, filename=path)
        if tree is not None and ast.dump(parsed, include_attributes=True) != ast.dump(
            tree, include_attributes=True
        ):
            return {
                "error": _captured_sink_failure(
                    schema, "SINK_SOURCE_STALE", "ast_source_mismatch"
                )
            }
        tree = tree or parsed
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return {
            "error": _captured_sink_failure(
                schema, "SINK_SOURCE_STALE", "source_parse_failed"
            )
        }
    return {"tree": tree, "parents": {}}


def _captured_sink_location(node, ctx):
    base, tree, parents = ctx["base"], ctx["tree"], ctx["parents"]
    schema = base["schema"]
    span = _fixed_program_span(node) if isinstance(node, ast.AST) else None
    if span is None:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_LOCATION_UNRESOLVED", "invalid_sink_span", base
            )
        }
    if ctx["indexed"] and isinstance(node, ast.Call) and id(node) in parents:
        return {"node": node, "parents": parents, "source_ast_nodes_examined": 0}
    if ctx["indexed"]:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_LOCATION_UNRESOLVED", "sink_not_in_captured_tree", base
            )
        }
    matches = []
    for count, item in enumerate(ast.walk(tree), 1):
        if count > 200_000:
            return {
                "error": _captured_sink_failure(
                    schema, "SINK_BUDGET_EXHAUSTED", "max_source_ast_nodes", base
                )
            }
        parents.update({id(child): item for child in ast.iter_child_nodes(item)})
        if (
            isinstance(item, ast.Call)
            and _fixed_program_span(item) == span
            and ast.dump(item, include_attributes=True)
            == ast.dump(node, include_attributes=True)
        ):
            matches.append(item)
    if ctx["tree_supplied"] and id(node) not in parents:
        return {
            "error": _captured_sink_failure(
                schema, "SINK_LOCATION_UNRESOLVED", "sink_not_in_supplied_tree", base
            )
        }
    if len(matches) == 1:
        return {
            "node": matches[0],
            "parents": parents,
            "source_ast_nodes_examined": count,
        }
    return {
        "error": _captured_sink_failure(
            schema, "SINK_LOCATION_UNRESOLVED", "sink_span_not_unique", base
        )
    }


def _captured_sink_fact(item, path, digest, status="OBSERVED"):
    span = _fixed_program_span(item)
    return (
        {"status": status, "source": {"path": path, "sha256": digest, "span": span}}
        if span is not None
        else {"status": "UNKNOWN", "reason": "span_unavailable"}
    )


def _captured_sink_excerpt(item, text, truncation):
    excerpt = ast.get_source_segment(text, item)
    if not isinstance(excerpt, str):
        return ""
    if len(excerpt) > 512:
        if "excerpt_truncated" not in truncation:
            truncation.append("excerpt_truncated")
        return excerpt[:512] + "[truncated]"
    return excerpt


def _captured_sink_scope(node, parents, fact, budget, base):
    scope = node
    while id(scope) in parents:
        scope = parents[id(scope)]
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            break
    else:
        scope = None
    row, body, statement = (
        {"status": "UNKNOWN", "reason": "no_enclosing_callable"},
        None,
        None,
    )
    if scope is not None:
        statement = node
        while id(statement) in parents and parents[id(statement)] is not scope:
            statement = parents[id(statement)]
        if (
            isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
            and statement in scope.body
        ):
            body = scope.body
            row = {
                "status": "OBSERVED",
                "name": scope.name,
                "kind": type(scope).__name__,
                **fact(scope),
            }
        else:
            row = {
                "status": "UNKNOWN",
                "reason": "sink_outside_callable_body",
                **fact(scope),
            }
    nodes, stack = [], [scope] if body is not None else []
    while stack:
        item = stack.pop()
        nodes.append(item)
        if len(nodes) > budget:
            return {
                "error": _captured_sink_failure(
                    base["schema"], "SINK_BUDGET_EXHAUSTED", "max_states", base
                )
            }
        if item is not scope and isinstance(
            item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        stack.extend(ast.iter_child_nodes(item))
    return {
        "scope": scope,
        "body": body,
        "statement": statement,
        "nodes": nodes,
        "row": row,
    }


def _captured_sink_arguments(node, fact, excerpt):
    arguments, names = [], set()
    for index, value in enumerate(node.args):
        arguments.append(
            {
                "position": index,
                "kind": "starred" if isinstance(value, ast.Starred) else "positional",
                "expression": excerpt(value),
                "span": _fixed_program_span(value),
                **fact(value),
            }
        )
        names.update(
            item.id
            for item in ast.walk(value)
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
        )
    for keyword in node.keywords:
        value = keyword.value
        arguments.append(
            {
                "keyword": keyword.arg,
                "kind": "expanded_keyword" if keyword.arg is None else "keyword",
                "expression": excerpt(value),
                "span": _fixed_program_span(value),
                **fact(value),
            }
        )
        names.update(
            item.id
            for item in ast.walk(value)
            if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
        )
    callees = [
        item
        for item in ast.walk(node.func)
        if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)
    ]
    names.update(item.id for item in callees)
    return arguments, names, callees


def _captured_sink_imports(tree, scope, nodes, parents, fact, budget, base):
    from .credential_role_constructor_provider import binding_occurrences

    modules = [
        item for item in tree.body if isinstance(item, (ast.Import, ast.ImportFrom))
    ]
    if len(nodes) + len(modules) > budget:
        return {
            "error": _captured_sink_failure(
                base["schema"], "SINK_BUDGET_EXHAUSTED", "max_states", base
            )
        }
    rows, params = [], _captured_sink_parameter_names(scope)
    for item in modules + [
        row for row in nodes if isinstance(row, (ast.Import, ast.ImportFrom))
    ]:
        owner = _captured_sink_enclosing_callable(item, parents)
        if owner not in (None, scope):
            continue
        container = owner.body if owner is not None else tree.body
        for alias in item.names:
            name = alias.asname or (
                alias.name.split(".")[0] if isinstance(item, ast.Import) else alias.name
            )
            wildcard = isinstance(item, ast.ImportFrom) and alias.name == "*"
            stable = (
                not wildcard
                and binding_occurrences(container, name) == [item]
                and name not in params
            )
            status = "OBSERVED" if stable else "UNKNOWN"
            rows.append(
                {
                    "name": name,
                    "module": item.module
                    if isinstance(item, ast.ImportFrom)
                    else alias.name,
                    "kind": type(item).__name__,
                    "status": status,
                    "reason": None if stable else "binding_replaced_or_ambiguous",
                    "span": _fixed_program_span(item),
                    **fact(item, status),
                }
            )
    return {
        "rows": rows,
        "module_imports": modules,
        "states_used": sum(len(item.names) for item in modules),
        "binding_occurrences": binding_occurrences,
    }


def _captured_sink_values(
    node, names, scope, body, statement, nodes, parents, tree, fact, excerpt
):
    from .credential_role_constructor_provider import binding_occurrences

    if body is None:
        return [
            {
                "name": name,
                "status": "UNKNOWN",
                "reason": "no_supported_callable_scope",
                "origin": "UNRESOLVED",
                "definitions": [],
                "replacements": [],
            }
            for name in sorted(names)
        ]
    params = _captured_sink_parameter_names(scope)
    reflective = any(
        isinstance(row, ast.Call)
        and isinstance(row.func, ast.Name)
        and row.func.id
        in {"exec", "eval", "globals", "locals", "vars", "setattr", "delattr"}
        for row in nodes
    )
    pending, visited, result = sorted(names), set(), []
    while pending:
        name = pending.pop(0)
        if name in visited:
            continue
        visited.add(name)
        evidence = _captured_sink_value(
            name,
            scope,
            body,
            statement,
            parents,
            tree,
            params,
            fact,
            excerpt,
            binding_occurrences,
        )
        value, assignment = evidence["value"], evidence["assignment"]
        if assignment is not None:
            pending.extend(
                row.id
                for row in ast.walk(assignment.value)
                if isinstance(row, ast.Name)
                and isinstance(row.ctx, ast.Load)
                and row.id not in visited
                and row.id not in pending
            )
        if reflective:
            value.update(
                status="UNKNOWN",
                reason="reflective_binding_possible",
                origin="UNRESOLVED",
            )
            value["replacements"].append(
                {"kind": "REFLECTIVE_WRITE_POSSIBLE", **fact(node, "UNKNOWN")}
            )
        result.append(value)
    return result


def _captured_sink_value(
    name,
    scope,
    body,
    statement,
    parents,
    tree,
    params,
    fact,
    excerpt,
    binding_occurrences,
):
    bindings = binding_occurrences(body, name)
    rows = []
    for binding in bindings:
        statement_node = (
            parents.get(id(binding)) if isinstance(binding, ast.Name) else binding
        )
        if statement_node is None:
            statement_node = binding
        rows.append(
            {
                "kind": type(binding).__name__,
                "binding_span": _fixed_program_span(binding),
                "expression": excerpt(statement_node),
                **fact(statement_node, "UNKNOWN"),
            }
        )
    assignment = None
    if (
        len(bindings) == 1
        and isinstance(bindings[0], ast.Name)
        and isinstance(bindings[0].ctx, ast.Store)
    ):
        candidate = parents.get(id(bindings[0]))
        targets = (
            candidate.targets
            if isinstance(candidate, ast.Assign)
            else [candidate.target]
            if isinstance(candidate, ast.AnnAssign)
            else []
        )
        if (
            candidate in body
            and body.index(candidate) < body.index(statement)
            and getattr(candidate, "value", None) is not None
            and len(targets) == 1
            and targets[0] is bindings[0]
        ):
            assignment = candidate
    if assignment is not None:
        value = {
            "name": name,
            "status": "INFERRED",
            "reason": None,
            "origin": "LOCAL_DEFINITION",
            "definitions": [
                {
                    "expression": excerpt(assignment.value),
                    "span": _fixed_program_span(assignment),
                    **fact(assignment),
                }
            ],
            "replacements": [],
        }
        value["definitions"][0]["target_source"] = fact(
            assignment.targets[0]
            if isinstance(assignment, ast.Assign)
            else assignment.target
        )
    elif not bindings and name in params:
        args = (
            *scope.args.posonlyargs,
            *scope.args.args,
            *scope.args.kwonlyargs,
            *([scope.args.vararg] if scope.args.vararg else []),
            *([scope.args.kwarg] if scope.args.kwarg else []),
        )
        arg = next(row for row in args if row.arg == name)
        value = {
            "name": name,
            "status": "INFERRED",
            "reason": None,
            "origin": "CALLABLE_PARAMETER",
            "definitions": [
                {"kind": "PARAMETER", "span": _fixed_program_span(arg), **fact(arg)}
            ],
            "replacements": [],
        }
    elif not bindings and any(
        row in tree.body for row in binding_occurrences(tree.body, name)
    ):
        module_bindings = binding_occurrences(tree.body, name)
        if len(module_bindings) == 1 and isinstance(
            module_bindings[0], (ast.Import, ast.ImportFrom)
        ):
            value = {
                "name": name,
                "status": "INFERRED",
                "reason": None,
                "origin": "LEXICAL_IMPORT",
                "definitions": [
                    {
                        "kind": type(module_bindings[0]).__name__,
                        "span": _fixed_program_span(module_bindings[0]),
                        **fact(module_bindings[0]),
                    }
                ],
                "replacements": [],
            }
        else:
            value = {
                "name": name,
                "status": "UNKNOWN",
                "reason": "module_binding_ambiguous",
                "origin": "UNRESOLVED",
                "definitions": [],
                "replacements": rows,
            }
    else:
        value = {
            "name": name,
            "status": "UNKNOWN",
            "reason": "binding_replaced_or_not_straight_line"
            if bindings
            else "no_source_definition_or_parameter",
            "origin": "UNRESOLVED",
            "definitions": [],
            "replacements": rows,
        }
    return {"value": value, "assignment": assignment}


def _captured_sink_guards(node, scope, parents, fact, excerpt):
    guards, current = [], node
    control = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.TryStar,
        ast.With,
        ast.AsyncWith,
        ast.Match,
        ast.Assert,
    )
    while id(current) in parents and parents[id(current)] is not scope:
        current = parents[id(current)]
        if isinstance(current, control):
            test = getattr(current, "test", None) or getattr(current, "subject", None)
            guards.append(
                {
                    "kind": type(current).__name__,
                    "expression": excerpt(test) if test is not None else "",
                    "semantics": "UNKNOWN",
                    "span": _fixed_program_span(current),
                    **fact(current),
                }
            )
    return guards


def _captured_sink_callee_binding(names, scope, body, tree, module_imports, fact):
    from .credential_role_constructor_provider import binding_occurrences

    name = names[0].id if names else None
    row = {"status": "UNKNOWN", "reason": "unresolved_callee_binding", "name": name}
    if name is None or body is None:
        return row
    if any(
        isinstance(item, ast.ImportFrom)
        and any(alias.name == "*" for alias in item.names)
        for item in module_imports
    ):
        row["reason"] = "wildcard_import_may_bind_name"
    elif not binding_occurrences(
        body, name
    ) and name not in _captured_sink_parameter_names(scope):
        bindings = binding_occurrences(tree.body, name)
        if (
            len(bindings) == 1
            and bindings[0] in tree.body
            and isinstance(bindings[0], (ast.Import, ast.ImportFrom))
        ):
            row = {
                "status": "INFERRED",
                "reason": None,
                "name": name,
                "declaration": fact(bindings[0]),
            }
    return row


def _captured_sink_enclosing_callable(node, parents):
    current = node
    while id(current) in parents:
        current = parents[id(current)]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return current
    return None


def _captured_sink_parameter_names(scope):
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return set()
    args = scope.args
    parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    parameters.extend(item for item in (args.vararg, args.kwarg) if item is not None)
    return {item.arg for item in parameters}


def _fixed_eval_sink_context(node, call_name, source_bytes, source_path):
    if (
        not isinstance(source_bytes, bytes)
        or not isinstance(source_path, str)
        or not source_path
    ):
        return None
    if call_name != "eval" or not isinstance(node, ast.Call):
        return None
    span = _fixed_program_span(node)
    if span is None:
        return None
    try:
        tree = ast.parse(source_bytes, filename=source_path)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return None
    expected = ast.dump(node, include_attributes=False)
    calls = [
        item
        for item in ast.walk(tree)
        if isinstance(item, ast.Call)
        and _fixed_program_span(item) == span
        and ast.dump(item, include_attributes=False) == expected
    ]
    if len(calls) != 1:
        return None
    sink = calls[0]
    if not (isinstance(sink.func, ast.Name) and sink.func.id == "eval"):
        return None
    if len(sink.args) != 1 or sink.keywords or not isinstance(sink.args[0], ast.Name):
        return None
    scopes = [
        item
        for item in ast.walk(tree)
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.lineno <= sink.lineno <= item.end_lineno
        and item.col_offset <= sink.col_offset
        and (item.end_lineno, item.end_col_offset)
        >= (sink.end_lineno, sink.end_col_offset)
    ]
    if not scopes or not _fixed_eval_builtin_source_clear(tree, sink):
        return None
    scope = min(
        scopes,
        key=lambda item: (
            item.end_lineno - item.lineno,
            item.end_col_offset - item.col_offset,
        ),
    )
    return tree, sink, scope, span


def _fixed_eval_control_flow(scope):
    blocked = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.With,
        ast.AsyncWith,
        ast.Lambda,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
        ast.NamedExpr,
        ast.Global,
        ast.Nonlocal,
        ast.AugAssign,
        ast.Delete,
        ast.Match,
        ast.TryStar,
    )
    nested = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    return any(
        isinstance(item, blocked) or (isinstance(item, nested) and item is not scope)
        for item in ast.walk(scope)
    )


def _fixed_eval_sink_statement(scope, sink):
    if _fixed_eval_control_flow(scope):
        return None
    rows = [
        (index, statement)
        for index, statement in enumerate(scope.body)
        if any(item is sink for item in ast.walk(statement))
    ]
    if len(rows) != 1:
        return None
    index, statement = rows[0]
    valid_assignment = (
        isinstance(statement, ast.Assign)
        and statement.value is sink
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
    )
    valid_value_statement = (
        isinstance(statement, (ast.Expr, ast.Return)) and statement.value is sink
    )
    return index if valid_assignment or valid_value_statement else None


def _fixed_eval_parameters(scope):
    args = (*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs)
    names = {argument.arg for argument in args}
    if scope.args.vararg is not None:
        names.add(scope.args.vararg.arg)
    if scope.args.kwarg is not None:
        names.add(scope.args.kwarg.arg)
    return names


def _fixed_eval_external_state(name):
    return {
        "kind": "EXTERNAL_INPUT",
        "value": None,
        "trace": [],
        "names": {name},
        "origin_span": None,
        "decode_encoding": None,
    }


def _fixed_eval_row(
    target, statement, sequence, operation, kind, source_name=None, encoding=None
):
    value = statement.value
    row = {
        "sequence": sequence,
        "name": target.id,
        "operation": operation,
        "value_kind": kind,
        "assignment_span": _fixed_program_span(statement),
        "target_span": _fixed_program_span(target),
        "value_span": _fixed_program_span(value),
        "source_name": source_name,
        "source_use_span": None,
        "encoding": encoding,
    }
    if source_name is not None and isinstance(value, ast.Name):
        row["source_use_span"] = _fixed_program_span(value)
    elif source_name is not None and isinstance(value, ast.Attribute):
        row["source_use_span"] = _fixed_program_span(value.value)
    elif source_name is not None and isinstance(value, ast.Call):
        row["source_use_span"] = _fixed_program_span(value.func.value)
    return row


def _fixed_eval_is_bytes_decode(value):
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and value.func.attr == "decode"
        and isinstance(value.func.value, ast.Name)
        and not value.keywords
        and len(value.args) <= 1
    )


def _fixed_eval_decode_state(target, statement, states, sequence):
    value = statement.value
    if not _fixed_eval_is_bytes_decode(value):
        return None
    name = value.func.value.id
    receiver = states.get(name)
    if receiver is None or receiver["kind"] != "IMMUTABLE_BYTES":
        return None
    if value.args:
        encoding = value.args[0]
        if not (
            isinstance(encoding, ast.Constant)
            and type(encoding.value) is str
            and encoding.value.casefold() in {"utf-8", "utf8"}
        ):
            return None
    try:
        decoded = receiver["value"].decode("utf-8")
    except (UnicodeDecodeError, LookupError, TypeError, ValueError):
        return None
    row = _fixed_eval_row(
        target,
        statement,
        sequence,
        "BUILTIN_BYTES_DECODE",
        "IMMUTABLE_STRING",
        name,
        "utf-8",
    )
    state = {
        "kind": "IMMUTABLE_STRING",
        "value": decoded,
        "trace": [*receiver["trace"], row],
        "names": set(receiver["names"]) | {target.id},
        "origin_span": receiver["origin_span"],
        "decode_encoding": "utf-8",
    }
    return row, state


def _fixed_eval_assignment_state(target, statement, states, parameters, sequence):
    value = statement.value
    if isinstance(value, ast.Constant) and type(value.value) in {bytes, str}:
        kind = "IMMUTABLE_BYTES" if type(value.value) is bytes else "IMMUTABLE_STRING"
        row = _fixed_eval_row(target, statement, sequence, "LITERAL_ASSIGNMENT", kind)
        state = {
            "kind": kind,
            "value": value.value,
            "trace": [row],
            "names": {target.id},
            "origin_span": _fixed_program_span(value),
            "decode_encoding": None,
        }
        return row, state
    if isinstance(value, ast.Name):
        prior = states.get(value.id, _fixed_eval_external_state(value.id))
        row = _fixed_eval_row(
            target, statement, sequence, "LOCAL_ALIAS", prior["kind"], value.id
        )
        state = {
            **prior,
            "trace": [*prior["trace"], row],
            "names": set(prior["names"]) | {target.id},
        }
        return row, state
    body_read = (
        isinstance(value, ast.Attribute)
        and value.attr == "body"
        and isinstance(value.value, ast.Name)
        and value.value.id in parameters
    )
    if body_read:
        row = _fixed_eval_row(
            target,
            statement,
            sequence,
            "EXTERNAL_BODY_READ",
            "EXTERNAL_INPUT",
            value.value.id,
        )
        return row, {
            "kind": "EXTERNAL_INPUT",
            "value": None,
            "trace": [row],
            "names": {target.id},
            "origin_span": None,
            "decode_encoding": None,
        }
    return _fixed_eval_decode_state(target, statement, states, sequence)


def _fixed_eval_local_states(scope, sink_index):
    parameters = _fixed_eval_parameters(scope)
    states = {name: _fixed_eval_external_state(name) for name in parameters}
    history = defaultdict(list)
    sequence = 0
    for index, statement in enumerate(scope.body[:sink_index]):
        docstring = (
            index == 0
            and isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and type(statement.value.value) is str
        )
        if docstring:
            continue
        if not (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        ):
            return None
        target = statement.targets[0]
        if target.id in {"eval", "exec"}:
            return None
        sequence += 1
        result = _fixed_eval_assignment_state(
            target, statement, states, parameters, sequence
        )
        if result is None:
            return None
        row, state = result
        history[target.id].append(row)
        states[target.id] = state
    return states, history


def _fixed_eval_definition_rows(final_state, history):
    reaching = final_state["trace"]
    reaching_sequences = {row["sequence"] for row in reaching}
    names = final_state["names"]
    rows = sorted(
        (row for name in names for row in history.get(name, [])),
        key=lambda row: row["sequence"],
    )
    overwritten = [
        dict(row) for row in rows if row["sequence"] not in reaching_sequences
    ]
    return [dict(row) for row in reaching], overwritten


def _fixed_eval_proof(sink, call_span, source_bytes, source_path, states, history):
    import json

    final = states.get(sink.args[0].id)
    if final is None or final["kind"] != "IMMUTABLE_STRING":
        return {}
    if type(final["value"]) is not str or final["origin_span"] is None:
        return {}
    program = final["value"]
    try:
        program_bytes = program.encode("utf-8")
    except UnicodeEncodeError:
        return {}
    if len(program_bytes) > 16 * 1024:
        return {}
    statement_kinds, _ = _fixed_literal_program_kinds(program, "eval")
    if statement_kinds is None:
        return {}
    reaching, overwritten = _fixed_eval_definition_rows(final, history)
    proof = {
        "schema": "factory.fixed-program-local-def-use.v1",
        "source_path": source_path,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "call": "eval",
        "call_span": call_span,
        "argument_span": _fixed_program_span(sink.args[0]),
        "program_source_span": final["origin_span"],
        "program_sha256": hashlib.sha256(program_bytes).hexdigest(),
        "program_kind": final["kind"],
        "decode_encoding": final["decode_encoding"],
        "statement_kinds": statement_kinds,
        "reaching_definitions": reaching,
        "overwritten_definitions": overwritten,
        "target_execution": "not_performed",
    }
    proof["def_use_sha256"] = hashlib.sha256(
        json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return proof


def fixed_eval_local_input_witness(node, call_name, *, source_bytes, source_path):
    """Bind a fixed eval value to straight-line local definitions and source spans."""
    parsed = _fixed_eval_sink_context(node, call_name, source_bytes, source_path)
    if parsed is None:
        return {}
    _, sink, scope, call_span = parsed
    sink_index = _fixed_eval_sink_statement(scope, sink)
    if sink_index is None:
        return {}
    states = _fixed_eval_local_states(scope, sink_index)
    if states is None:
        return {}
    return _fixed_eval_proof(sink, call_span, source_bytes, source_path, *states)


def _fixed_literal_program_kinds(program, normalized, node_limit=1024):
    mode = "eval" if normalized == "eval" else "exec"
    try:
        tree = ast.parse(program, mode=mode)
        limit = min(1024, node_limit) if type(node_limit) is int else 0
        nodes_examined = 0
        for _ in ast.walk(tree):
            nodes_examined += 1
            if nodes_examined > limit:
                return None, nodes_examined
        if mode == "eval":
            kinds = ["Expression"] if _fixed_literal_value(tree.body) else None
            return kinds, nodes_examined
        kinds = []
        for statement in tree.body:
            if isinstance(statement, ast.Pass):
                pass
            elif isinstance(statement, ast.Expr) and _fixed_literal_value(
                statement.value
            ):
                pass
            elif (
                isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and statement.targets[0].id != "__builtins__"
                and _fixed_literal_value(statement.value)
            ):
                pass
            else:
                return None, nodes_examined
            kinds.append(type(statement).__name__)
        return kinds, nodes_examined
    except (
        SyntaxError,
        ValueError,
        TypeError,
        MemoryError,
        RecursionError,
        OverflowError,
    ):
        return None, 0
