"""Values and exact text operations for the source-bound fixture model."""

import ast
import fnmatch


def _scope_value_roots(value):
    """Return all roots only for closed, non-escaping modeled values."""
    if value.unknown or value.content_unknown or value.class_roots:
        return None
    roots = set(value.roots)
    for _, item in value.items:
        nested = _scope_value_roots(item)
        if nested is None:
            return None
        roots.update(nested)
    return roots


def _scope_bind(arguments, keywords, names, required):
    if len(arguments) > len(names) or set(keywords) - set(names):
        return None
    bound = dict(zip(names, arguments))
    if set(bound) & set(keywords):
        return None
    bound.update(keywords)
    return bound if set(required) <= set(bound) else None


def _scope_closed(bound, tracked_roles):
    for role, value in bound.items():
        roots = _scope_value_roots(value)
        if roots is None or (roots and role not in tracked_roles):
            return False
    return True


def _scope_exact_text(value):
    scalar = value._exact_scalar
    if (
        value.inert_kind == "scalar"
        and value.scalar_kind == "text"
        and _scope_value_roots(value) == set()
        and len(scalar) == 1
    ):
        return scalar[0] if type(scalar[0]) is str else None
    return None


def _closed_text_binary(operator, left, right):
    """Interpret only bounded text operations with untracked, exact operands."""
    left, right = _scope_exact_text(left), _scope_exact_text(right)
    if left is None or right is None or len(left) + len(right) > 8192:
        return None
    if isinstance(operator, ast.Add):
        return left + right
    if left.count("%") == 1 and "%s" in left:
        return left.replace("%s", right)
    return None


class _TestScopeContractEpoch:
    """Retain actual immutable model bindings for role-cache generations."""

    __name__ = "test_scope_contract_epoch"

    @property
    def __code__(self):
        from . import credential_role_method_use_getter_audit as getter
        from .unittest_client_audit import _StoredTestClientCredential

        names = sorted(
            name
            for name in vars(getter)
            if name.startswith("_SCOPE_") or name == "SCOPE_API_CONTRACT_EPOCH"
        )
        values = (
            *(getattr(getter, name) for name in names),
            getter._source_test_scope_evidence,
            getter._closed_text_binary,
            getter._scope_exact_text,
            getter._scope_value_roots,
            *(
                getattr(owner, name)
                for owner in (
                    _StoredTestClientCredential,
                    getter._SourceTestScope,
                    getter._CredentialRoleFlow,
                )
                for name in sorted(vars(owner))
                if callable(getattr(owner, name))
            ),
        )
        key = tuple(
            (id(value), id(getattr(value, "__code__", None))) for value in values
        )
        current = getattr(self, "current", None)
        if current is None or current[0] != key:
            current = (key, object(), values)
            self.current = current
        return current[1]


_TEST_SCOPE_CONTRACT_EPOCH = _TestScopeContractEpoch()


def _reference_roundtrip_frame(tree, load):
    match load:
        case ast.Call(
            func=ast.Attribute(value=ast.Name(id=module), attr="loads"),
            args=[
                ast.Call(
                    func=ast.Attribute(value=ast.Name(id=dumper), attr="dumps"),
                    args=[ast.Name(id=refs)],
                    keywords=[],
                ) as dump
            ],
            keywords=[],
        ) if module == dumper:
            pass
        case _:
            return None
    if not _reference_module_import(tree, module, "pickle"):
        return None
    owners = [
        item
        for item in tree.body
        if isinstance(item, ast.FunctionDef) and load in ast.walk(item)
    ]
    if len(owners) != 1:
        return None
    owner = owners[0]
    args = owner.args
    if (
        owner.decorator_list
        or not owner.name.startswith("test_")
        or args.posonlyargs
        or args.vararg
        or args.kwonlyargs
        or args.kwarg
        or args.defaults
        or [arg.arg for arg in args.args] != ["tmp_path"]
    ):
        return None
    match owner.body:
        case [
            ast.Assign(targets=[ast.Name(id=store_name)], value=ast.Call() as store),
            ast.Assign(targets=[ast.Name(id=values_name)], value=ast.Dict() as values),
            ast.Assign(
                targets=[ast.Name(id=bound)],
                value=ast.Call(
                    func=ast.Name(id=producer),
                    args=[ast.Name(id=receiver), ast.Name(id=argument)],
                    keywords=[
                        ast.keyword(
                            arg="submission_id", value=ast.Constant(value=str())
                        )
                    ],
                ) as publication,
            ),
            *suffix,
        ] if (bound, receiver, argument) == (refs, store_name, values_name):
            pass
        case _:
            return None
    if len({module, store_name, values_name, refs, producer, "tmp_path"}) != 6:
        return None
    if not _reference_roundtrip_flow(suffix, load, producer, store_name, refs):
        return None
    if any(
        isinstance(item, ast.Name)
        and isinstance(item.ctx, (ast.Store, ast.Del))
        and item.id in {module, producer, "tmp_path"}
        for item in ast.walk(owner)
    ):
        return None
    return owner, dump, store, values, publication


def _reference_roundtrip_flow(statements, load, producer, store, refs):
    """Restrict the prefix to local publish, observation and closed-store steps."""
    from .review_audits import _name

    for statement in statements:
        if load in ast.walk(statement):
            match statement:
                case ast.For(
                    iter=ast.Call(
                        func=ast.Name(id="zip"), args=[first, *_], keywords=keywords
                    )
                ) if first is load and all(
                    item.arg == "strict" and isinstance(item.value, ast.Constant)
                    for item in keywords
                ):
                    return True
                case ast.Assert(test=assertion, msg=None) if assertion is load:
                    return True
                case _:
                    return False
        if isinstance(statement, ast.Assert) and not any(
            isinstance(item, ast.Name) and item.id in {refs, store, producer}
            for item in ast.walk(statement)
        ):
            if all(
                not isinstance(item, ast.Call)
                or _name(item.func) in {"len", "list", "tmp_path.rglob"}
                for item in ast.walk(statement)
            ):
                continue
            return False
        if _reference_local_publish_step(statement, producer, store, refs):
            continue
        if _reference_ast_equal(statement, f"{store}.close()"):
            continue
        return False
    return False


def _reference_local_publish_step(node, producer, store, refs):
    match node:
        case ast.For(
            target=ast.Name(id=counter),
            iter=ast.Call(
                func=ast.Name(id="range"), args=[ast.Constant(value=int())], keywords=[]
            ),
            body=[
                ast.Expr(
                    value=ast.Call(
                        func=ast.Name(id=called),
                        args=[ast.Name(id=receiver), ast.Dict() as values],
                        keywords=[
                            ast.keyword(
                                arg="submission_id",
                                value=ast.Call(
                                    func=ast.Name(id="str"),
                                    args=[ast.Name(id=token)],
                                    keywords=[],
                                ),
                            )
                        ],
                    )
                )
            ],
            orelse=[],
        ) if (called, receiver, token) == (producer, store, counter):
            return counter not in {
                producer,
                store,
                refs,
                "tmp_path",
            } and _reference_tensor_literals(values, frozenset({counter}))
        case _:
            return False


def _reference_tensor_literals(node, allowed=frozenset()):
    from .review_audits import _name

    if isinstance(node, ast.Dict):
        return (
            len(node.keys) <= 32
            and all(
                isinstance(k, ast.Constant) and type(k.value) is str for k in node.keys
            )
            and all(_reference_tensor_literals(item, allowed) for item in node.values)
        )
    if isinstance(node, ast.Constant):
        return type(node.value) in {int, float, str, bool, type(None)}
    if isinstance(node, ast.Tuple):
        return all(_reference_tensor_literals(item, allowed) for item in node.elts)
    if isinstance(node, ast.Name):
        return node.id in allowed
    if isinstance(node, ast.Attribute):
        return _name(node) in {"np.int32", "np.int64", "torch.bfloat16"}
    if isinstance(node, ast.Call):
        if not _reference_tensor_call(node, allowed):
            return False
        return all(
            _reference_tensor_literals(item, allowed) for item in node.args
        ) and all(
            item.arg == "dtype" and _reference_tensor_literals(item.value, allowed)
            for item in node.keywords
        )
    return False


def _reference_tensor_call(node, allowed):
    from .review_audits import _name

    match node.func:
        case ast.Attribute(value=ast.Call() as receiver, attr="reshape"):
            return _reference_tensor_literals(receiver, allowed)
        case _:
            return _name(node.func) in {
                "np.arange",
                "np.array",
                "torch.arange",
                "torch.empty",
                "torch.tensor",
            }


def _reference_module_import(tree, local, provider):
    from .credential_role_constructor_provider import binding_occurrences

    bindings = binding_occurrences(tree.body, local)
    match bindings:
        case [ast.Import(names=aliases) as statement] if statement in tree.body:
            return any(
                (item.asname or item.name, item.name) == (local, provider)
                for item in aliases
            )
        case _:
            return False


def _reference_imported_member(tree, expression, module, member):
    """Bind an imported provider to its only stable module-scope declaration."""
    from .credential_role_constructor_provider import binding_occurrences

    match expression:
        case ast.Attribute(value=ast.Name(id=local), attr=attribute) if (
            attribute == member
        ):
            return _reference_module_import(tree, local, module)
        case ast.Name(id=local):
            match binding_occurrences(tree.body, local):
                case [
                    ast.ImportFrom(module=provider, level=0, names=names) as declaration
                ] if declaration in tree.body and provider == module:
                    return any(
                        (item.asname or item.name, item.name) == (local, member)
                        for item in names
                    )
                case _:
                    return False
        case _:
            return False


def _reference_ast_equal(node, source):
    candidate = (
        ast.parse(source, mode="eval").body
        if isinstance(node, ast.expr)
        else ast.parse(source).body[0]
    )
    return ast.dump(node) == ast.dump(candidate)


def _reference_assignment(fn, index, body_source):
    body = fn.body[1:] if ast.get_docstring(fn) is not None else fn.body
    return index < len(body) and _reference_ast_equal(body[index], body_source)


def _reference_local_export(index, path, name, seen=()):
    from .credential_role_constructor_provider import binding_occurrences

    identity = path, name
    if identity in seen or len(seen) >= 4 or not index.validate(path):
        return None
    tree = index.snapshots[path]
    match binding_occurrences(tree.body, name):
        case [ast.ClassDef() | ast.FunctionDef() as item] if (
            item in tree.body and not getattr(item, "type_params", ())
        ):
            return path, item
        case [ast.ImportFrom() as statement] if statement in tree.body:
            return _reference_export_from(
                index, path, name, statement, (*seen, identity)
            )
        case _:
            return None


def _reference_export_from(index, path, name, statement, seen):
    candidates = [
        item.name for item in statement.names if (item.asname or item.name) == name
    ]
    if len(candidates) != 1 or not statement.module:
        return None
    leaves = statement.module.split(".")
    if statement.level == 1:
        location = path.parent.joinpath(*leaves)
        choices = [location.with_suffix(".py"), location / "__init__.py"]
        targets = [choice for choice in choices if choice in index.snapshots]
    elif statement.level == 0:
        indexed = index.module_paths()
        if indexed is None:
            return None
        stem = "/".join(leaves)
        targets = [
            indexed.get(key)
            for key in (stem + ".py", stem + "/__init__.py")
            if key in indexed
        ]
    else:
        return None
    return (
        _reference_local_export(index, targets[0], candidates[0], seen)
        if len(targets) == 1 and targets[0] is not None
        else None
    )


def _reference_builtin_bindings_clear(tree, names):
    from .credential_role_constructor_provider import binding_occurrences

    return all(not binding_occurrences(tree.body, name) for name in names)


def _reference_dataclass_member_clear(member, aliases, audit):
    """Exclude custom state hooks and definition-time effects on reference types."""
    match member:
        case ast.AnnAssign(target=ast.Name(id=name), value=default) if (
            not name.startswith("__")
        ):
            if default is None or isinstance(default, ast.Constant):
                return True
            if isinstance(default, ast.Tuple):
                return all(isinstance(item, ast.Constant) for item in default.elts)
            match default:
                case ast.Call(
                    func=provider,
                    args=[],
                    keywords=[
                        ast.keyword(arg="default_factory", value=ast.Name(id="dict"))
                    ],
                ):
                    return (
                        audit._resolved_ast_name(provider, aliases)
                        == "dataclasses.field"
                    )
                case ast.UnaryOp(
                    op=ast.USub(), operand=ast.Constant(value=int() | float())
                ):
                    return True
                case _:
                    return False
        case ast.FunctionDef(name=name, decorator_list=decorators) if (
            not name.startswith("__") or name in {"__len__", "__getitem__"}
        ):
            return _reference_dataclass_formals_clear(member) and (
                len(decorators) <= 1
                and all(
                    isinstance(item, ast.Name)
                    and item.id in {"classmethod", "property"}
                    for item in decorators
                )
            )
        case ast.Expr(value=ast.Constant(value=str())):
            return True
        case _:
            return False


def _reference_dataclass_formals_clear(member):
    """Limit definition-time argument values to inert constants."""
    arguments = member.args
    defaults = [*arguments.defaults, *arguments.kw_defaults]
    return not getattr(member, "type_params", ()) and all(
        item is None or isinstance(item, ast.Constant) for item in defaults
    )


def _reference_publication_descriptor_clear(owner):
    """The record holder has only its generated data constructor and fields."""
    body = owner.body[1:] if ast.get_docstring(owner) is not None else owner.body
    return (
        len(body) == 2
        and _reference_ast_equal(body[0], "records: tuple[Record, ...]")
        and _reference_ast_equal(
            body[1], "dependencies: tuple[RecordSetRef | int, ...] = ()"
        )
    )


def _reference_dataclass_fields_clear(owner, role):
    """Bind the exact constructor positions and serialized field descriptors."""
    from .credential_role_constructor_provider import binding_occurrences

    layouts = {
        "Record": (
            "record_id: str",
            "payload: bytes",
            'codec: str = "bytes.v1"',
            "metadata: dict = field(default_factory=dict)",
            "tokens: int = 0",
        ),
        "RecordRef": ("segment: SegmentRef", "ordinal: int"),
        "RecordSetRef": (
            "manifest: RecordRef",
            "digest: str",
            "records: int",
            "payload_bytes: int",
            "tokens: int",
        ),
        "SegmentRef": (
            "run_id: str",
            "path: str",
            "segment_id: str",
            "size: int",
            "checksum: str",
            "version: int = 1",
            'checksum_algorithm: str = "sha256"',
            "offset: int = 0",
        ),
        "TensorRef": (
            "path: str",
            "shape: tuple[int, ...]",
            "dtype: str",
            "nbytes: int",
            "kind: str | None = None",
            "validated: bool = False",
            "offset: int | None = -1",
            "checksum: int | None = None",
            'codecs: tuple[str, ...] = ("bytes.v1", "json.v1", "tensor.v1")',
            "record_ref: RecordRef | None = None",
            'root: str = ""',
            'run_id: str = ""',
            "blob_set: RecordSetRef | None = None",
            "blob_ordinal: int = 0",
        ),
    }
    if role == "Publication":
        return _reference_publication_descriptor_clear(owner)
    fields = [node for node in owner.body if isinstance(node, ast.AnnAssign)]
    layout = layouts.get(role, ())
    return len(fields) == len(layout) and all(
        _reference_ast_equal(node, source)
        and binding_occurrences(owner.body, node.target.id) == [node.target]
        for node, source in zip(fields, layout, strict=True)
    )


def _reference_plain_store_members(owner):
    reserved = {"backend", "codecs", "run_id", "_native", "_config"}
    allowed_dunders = {"__init__", "__enter__", "__exit__"}
    return all(
        isinstance(item, ast.Expr)
        and isinstance(item.value, ast.Constant)
        and isinstance(item.value.value, str)
        or isinstance(item, ast.FunctionDef)
        and item.name not in reserved
        and (not item.name.startswith("__") or item.name in allowed_dunders)
        for item in owner.body
    )


def _reference_selected_store_method(owner, name, *, inherited_from=None):
    from .credential_role_constructor_provider import binding_occurrences

    if inherited_from is not None:
        if binding_occurrences(owner.body, name):
            return None
        owner = inherited_from
    match binding_occurrences(owner.body, name):
        case [ast.FunctionDef(decorator_list=[]) as function] if function in owner.body:
            return function
        case _:
            return None


def _reference_store_closed_methods(
    initializer, publish, batch, close, validate, inputs, fault
):
    """Check every reachable statement before returning the reference graph."""
    initializer_shape = """
        self.backend = backend or FilesystemBackend(root)
        if self.backend.root != FilesystemBackend(root).root:
            raise ValueError("Backend root differs from store root")
        self.run_id = run_id
        self.codecs = frozenset(codecs) | {"record-set.v1", "record-set.v2"}
        self.max_record_bytes, self.max_buffer_bytes = max_record_bytes, max_buffer_bytes
        self.segment_target_bytes = segment_target_bytes
        self._config = json.dumps(dict(
            root=str(self.backend.root), run_id=run_id, codecs=sorted(self.codecs),
            max_record_bytes=max_record_bytes, max_buffer_bytes=max_buffer_bytes,
            segment_target_bytes=segment_target_bytes, online_gc=online_gc,
        ))
        self._native = NativeStore(self._config)
    """
    batch_shape = """
        records, groups = [], []
        for publication in publications:
            start = len(records)
            records.extend(publication.records)
            groups.append(dict(
                records=list(range(start, len(records))),
                dependencies=[dep if type(dep) is int else asdict(dep) for dep in publication.dependencies],
            ))
        metadata, payloads = self._inputs(records) if records else ("[]", [])
        started = time.monotonic()
        result = tuple(RecordSetRef.from_dict(r) for r in json.loads(
            self._native.publish(encode(groups).decode(), metadata, payloads, submission_id, self._fault)
        ))
        emit("write", root=self.backend.root, size=result[0].manifest.segment.size,
             seconds=time.monotonic() - started, records=records)
        return result
    """
    inputs_shape = """
        metadata, payloads = [], []
        for record in records:
            if not isinstance(record.payload, (bytes, bytearray, memoryview)):
                raise TypeError("Store payloads must support a contiguous byte buffer")
            metadata.append(dict(record_id=record.record_id, codec=record.codec, metadata=record.metadata, tokens=record.tokens))
            payloads.append(record.payload)
        return encode(metadata).decode(), payloads
    """
    fault_shape = """
        self.backend.fault(phase)
        if phase in {"before_file_sync", "before_directory_sync"}:
            self.backend.metrics["syncs"] += 1
    """
    profiles = (
        (
            initializer,
            'self, root, run_id, *, backend=None, codecs=("bytes.v1", "json.v1"), max_record_bytes=16 * 1024**3, max_buffer_bytes=512 * 1024**2, segment_target_bytes=1024**3, online_gc=False',
            initializer_shape,
        ),
        (
            publish,
            "self, records, *, submission_id, dependencies=()",
            "return self.publish_many([Publication(tuple(records), tuple(dependencies))], submission_id=submission_id)[0]",
        ),
        (batch, "self, publications, *, submission_id", batch_shape),
        (close, "self", "self._native.close()"),
        (inputs, "self, records", inputs_shape),
        (fault, "self, phase", fault_shape),
        (
            validate,
            "self, ref, *, task_id=None, attempt_id=None",
            "return tuple(RecordRef.from_dict(r) for r in json.loads(self._native.validate(encode(asdict(ref)).decode(), task_id, attempt_id)))",
        ),
    )
    return all(
        _reference_function_shape(method, formals, body)
        for method, formals, body in profiles
    )


def _reference_function_shape(method, formals, source):
    from textwrap import dedent, indent

    if method is None:
        return False
    expected = ast.parse(
        f"def reference({formals}):\n" + indent(dedent(source).strip(), "    ")
    ).body[0]
    body = method.body[1:] if ast.get_docstring(method) is not None else method.body
    return ast.dump(method.args) == ast.dump(expected.args) and [
        ast.dump(item) for item in body
    ] == [ast.dump(item) for item in expected.body]


def _reference_trace_projection(node):
    """Allow only the primitive record fields projected to the JSON observer."""
    return _reference_ast_equal(
        node,
        """if records is not None:
    event["records"] = [
        {
            "bytes": r.payload.nbytes if isinstance(r.payload, memoryview) else len(r.payload),
            "codec": r.codec,
            "tokens": r.tokens,
            **{k: r.metadata[k] for k in ("shape", "dtype", "kind") if k in r.metadata},
        }
        for r in records
    ]""",
    )


def _reference_trace_body(method):
    """Require observation and JSON output on every trace path."""
    from copy import copy
    from textwrap import dedent

    if method.decorator_list or len(method.body) != 4:
        return False
    match method.body:
        case [
            ast.Assign(
                value=ast.Call(args=[ast.Constant(value=str() as setting)], keywords=[])
            ),
            _,
            _,
            ast.With(body=[_, _, _, projection, _]) as locked,
        ]:
            pass
        case _:
            return False
    if not _reference_trace_projection(projection):
        return False
    controlled = copy(method)
    block = copy(locked)
    block.body = [*locked.body[:3], ast.Pass(), locked.body[-1]]
    controlled.body = [*method.body[:3], block]
    expected = dedent("""
        directory = os.environ.get({setting})
        if not directory:
            return
        global _stream, _pid, _directory
        with _lock:
            if _stream is None or _pid != os.getpid() or _directory != directory:
                if _stream is not None:
                    _stream.close()
                _directory = directory
                Path(directory).mkdir(parents=True, exist_ok=True)
                _pid = os.getpid()
                _stream = (Path(directory) / f"{{socket.gethostname()}}-{{_pid}}.jsonl").open("a", buffering=1)
                atexit.register(_stream.close)
            event = {{
                "op": operation, "time": time.time(), "pid": _pid, "host": socket.gethostname(),
                "root": str(root), "bytes": size, "seconds": seconds,
            }}
            if checked_bytes is not None:
                event["checked_bytes"] = checked_bytes
            pass
            _stream.write(json.dumps(event, separators=(",", ":")) + "\\n")
    """).format(setting=repr(setting))
    return _reference_function_shape(
        controlled,
        "operation, *, root, size, seconds, records=None, checked_bytes=None",
        expected,
    )


def _reference_trace_globals(tree, fn):
    """Bind the observer's imports and initial state to captured declarations."""
    modules = {"atexit", "json", "os", "socket", "threading", "time"}
    expected_imports = {
        ast.dump(ast.parse(source).body[0])
        for source in (
            "from pathlib import Path",
            *(f"import {name}" for name in modules),
        )
    }
    expected = (
        "_lock = threading.Lock()",
        "_stream = None",
        "_pid = None",
        "_directory = None",
    )
    body = tree.body[1:] if ast.get_docstring(tree) is not None else tree.body
    imports, active = body[: len(expected_imports)], body[len(expected_imports) :]
    return (
        {ast.dump(item) for item in imports} == expected_imports
        and len(active) == len(expected) + 1
        and active[-1] is fn
        and all(
            _reference_ast_equal(item, source)
            for item, source in zip(active[:-1], expected, strict=True)
        )
    )


def _reference_readonly_trace(index, store_path):
    selected = _reference_local_export(index, store_path, "emit")
    if selected is None or not isinstance(selected[1], ast.FunctionDef):
        return False
    path, trace = selected
    tree = index.snapshots[path]
    return _reference_trace_globals(tree, trace) and _reference_trace_body(trace)


def _reference_inventory_nodes(index, path, tree, protected, aliases, test_name, audit):
    for item in ast.walk(tree):
        if isinstance(item, ast.Name) and item.id in {test_name, "__builtins__"}:
            return False
        if isinstance(item, ast.alias) and (
            item.name == test_name or not _reference_inventory_import_clear(item.name)
        ):
            return False
        if isinstance(item, ast.ImportFrom) and (
            not _reference_inventory_import_clear(item.module or "")
            or any(part.name == "*" for part in item.names)
        ):
            return False
        if isinstance(item, ast.Attribute):
            if not _reference_inventory_attribute_clear(
                item, protected, aliases, audit
            ):
                return False
        if isinstance(item, ast.Call) and not _reference_mutation_call_clear(
            index, path, item, protected, aliases, audit
        ):
            return False
    return True


def _reference_inventory_import_clear(origin):
    opaque = {"builtins", "copyreg", "ctypes", "importlib", "mock", "unittest", "_imp"}
    return origin.split(".", 1)[0] not in opaque


def _reference_inventory_attribute_clear(item, protected, aliases, audit):
    origin = audit._resolved_ast_name(item, aliases)
    opaque = {
        "__builtins__",
        "__dict__",
        "__getattribute__",
        "__globals__",
        "__subclasses__",
    }
    if origin == "sys.modules" or item.attr in opaque or ".patch.object" in origin:
        return False
    return not (
        isinstance(item.ctx, (ast.Store, ast.Del))
        and (origin.split(".")[0] in protected or item.attr in protected)
    )


def _reference_mutation_call_clear(index, path, call, protected, aliases, audit):
    callee = audit._resolved_ast_name(call.func, aliases)
    name = callee.rsplit(".", 1)[-1]
    if name in {"exec", "eval", "globals", "compile"} or callee.endswith(
        "patch.object"
    ):
        return False
    if name == "__import__":
        return _reference_captured_encoder_import(index, path, call)
    if name not in {"setattr", "delattr", "patch"}:
        return True
    match call.args:
        case [target, ast.Constant(value=str() as member), *_]:
            if isinstance(target, ast.Constant) and isinstance(target.value, str):
                owner_path = set(target.value.split("."))
            else:
                owner = audit._resolved_ast_name(target, aliases)
                owner_path = {owner.split(".", 1)[0]}
            return not (owner_path & protected) and member not in protected
        case _:
            return False


def _reference_captured_encoder_import(index, path, call):
    """Treat only a direct call of the source-owned JSON encoder as a data lookup."""
    match call:
        case ast.Call(
            func=ast.Name(id="__import__"),
            args=[ast.Constant(value=str() as module)],
            keywords=[
                ast.keyword(
                    arg="fromlist", value=ast.List(elts=[ast.Constant(value="encode")])
                )
            ],
        ):
            pass
        case _:
            return False
    parents = index.parents[path]
    attribute = parents.get(id(call))
    consumer = parents.get(id(attribute))
    if not (
        isinstance(attribute, ast.Attribute)
        and attribute.attr == "encode"
        and isinstance(consumer, ast.Call)
        and consumer.func is attribute
    ):
        return False
    paths = index.module_paths()
    if paths is None:
        return False
    stem = module.replace(".", "/")
    targets = [
        paths[key] for key in (stem + ".py", stem + "/__init__.py") if key in paths
    ]
    if len(targets) != 1 or targets[0] is None:
        return False
    return _reference_source_owned_encoder(index, targets[0])


def _reference_source_owned_encoder(index, path):
    """Resolve a declared encoder through its only captured module binding."""
    selected = _reference_local_export(index, path, "encode")
    if selected is None or not isinstance(selected[1], ast.FunctionDef):
        return False
    provider_path, provider = selected
    tree = index.snapshots[provider_path]
    return (
        _reference_module_import(tree, "json", "json")
        and not provider.decorator_list
        and _reference_function_shape(
            provider,
            "value: Any",
            'return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()',
        )
    )


_REFERENCE_FIXTURE_HELPERS = tuple(
    name
    for name, value in globals().items()
    if name.startswith("_reference_") and callable(value)
)


def _reference_fixture_cache_helpers():
    return tuple(globals()[name] for name in _REFERENCE_FIXTURE_HELPERS)


_VALIDATION_BUILTINS = frozenset(
    {"str", "int", "bool", "list", "dict", "tuple", "len", "ValueError", "staticmethod"}
)
_VALIDATION_NAMESPACE_NAMES = frozenset(
    {
        "__import__",
        "__builtins__",
        "eval",
        "exec",
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "delattr",
        "__dict__",
        "__globals__",
        "__closure__",
        "__code__",
        "f_globals",
        "f_builtins",
        "f_locals",
        "modules",
        "__class__",
        "__bases__",
        "__mro__",
    }
)
_VALIDATION_OPAQUE_IMPORTS = frozenset(
    {
        "builtins",
        "ctypes",
        "importlib",
        "inspect",
        "mock",
        "runpy",
        "types",
        "unittest",
        "_pytest",
    }
)
_VALIDATION_TEXT_OPERATIONS = frozenset(
    {"text", "integer", "boolean", "operand_length", "operand_check"}
)


def captured_password_validation_proof(index, path, node):
    """Show that one exact test-local literal reaches only inert format validation."""
    from .runtime_audit_integrity import _source_span

    finding = _validation_literal_caller(index, path, node)
    if finding is None:
        return None
    function, call, assertion, role = finding
    selected = _validation_resolve_receiver(index, path, call)
    if selected is None:
        return None
    producer_path, owner, validator, canonical = selected
    if not _validation_provider_closed(
        index, (path, function), producer_path, owner, validator, canonical, node.value
    ):
        return None
    return {
        "hypothesis": "CAPTURED_HARDCODED_CREDENTIAL_AUTHORITY",
        "scope": "CAPTURED_PYTHON_SOURCE",
        "operand_role": "TEST_LOCAL_FORMAT_VALIDATION_SAMPLE",
        "test_consumer": {"role": role, "span": _source_span(assertion)},
        "declaration_span": _source_span(node),
        "call_span": _source_span(call),
        "fixture": {"span": _source_span(function)},
        "validator": {
            "path": index.relative(producer_path),
            "span": _source_span(validator),
        },
        "runtime_effects": "UNASSESSED",
    }


def _validation_literal_caller(index, path, node):
    if (
        not isinstance(node, ast.Assign)
        or not index.bounded
        or len(index.snapshots) > 128
    ):
        return None
    match node:
        case ast.Assign(
            targets=[ast.Name(id=name)], value=ast.Constant(value=str() as value)
        ):
            if not value or len(value) > 1024 or name in _VALIDATION_BUILTINS:
                return None
        case _:
            return None
    if not index.validate(path):
        return None
    tree = index.snapshots[path]
    owner = index.parents[path].get(id(node))
    if not _validation_test_owner(index, path, tree, owner, node):
        return None
    match _validation_body(owner, declaration=node):
        case [
            ast.Assert(
                test=ast.Compare(
                    left=ast.Call() as call,
                    ops=[ast.Eq()],
                    comparators=[ast.Name(id=observed)],
                ),
                msg=None,
            ) as assertion
        ] if observed == name:
            if _validation_operand_call(call, name):
                return owner, call, assertion, "IDENTITY_ASSERTION"
        case rest:
            observed = _validation_raises_call(tree, rest, name)
            if observed is not None:
                call, assertion = observed
                return owner, call, assertion, "EXPECTED_FORMAT_ERROR"
    return None


def _validation_body(owner, *, declaration=None):
    body = owner.body[1:] if ast.get_docstring(owner) is not None else owner.body
    if declaration is None:
        return body
    return body[1:] if body and body[0] is declaration else []


def _validation_test_owner(index, path, tree, owner, node):
    from .credential_role_constructor_provider import binding_occurrences
    from .pytest_collection_audit import (
        _pytest_collection_settings,
        _pytest_file_matches,
        _pytest_name_matches,
        captured_pytest_configuration,
        captured_pytest_documents,
    )

    if (
        not isinstance(owner, ast.FunctionDef)
        or owner not in tree.body
        or owner.decorator_list
    ):
        return False
    if not _validation_fixed_signature(owner, 0) or binding_occurrences(
        tree.body, owner.name
    ) != [owner]:
        return False
    if not _validation_body(
        owner, declaration=node
    ) or not _validation_module_definition_clear(tree):
        return False
    documents = captured_pytest_documents(tree)
    selected = captured_pytest_configuration(
        documents, complete_precedence=True, source_role_only=True
    )
    if selected is None:
        return False
    settings = _pytest_collection_settings(selected["identity"])
    return _pytest_file_matches(
        index.relative(path), settings["python_files"]
    ) and _pytest_name_matches(owner.name, settings["python_functions"])


def _validation_operand_call(call, name):
    match call:
        case ast.Call(
            func=ast.Attribute(value=ast.Name(id=receiver)),
            args=[ast.Name(id=argument)],
            keywords=[],
        ):
            return argument == name and receiver != name
        case _:
            return False


def _validation_raises_call(tree, body, name):
    expected = None
    if len(body) == 3:
        match body[0]:
            case ast.Assign(
                targets=[ast.Name(id=identifier)], value=ast.Constant(value=str())
            ):
                expected = identifier
                body = body[1:]
    match body:
        case [
            ast.With(
                items=[
                    ast.withitem(
                        context_expr=ast.Call(
                            func=provider, args=[ast.Name(id="ValueError")], keywords=[]
                        ),
                        optional_vars=ast.Name(id=error),
                    )
                ],
                body=[ast.Expr(value=ast.Call() as call)],
            ) as terminal,
            *rest,
        ] if len(rest) <= 1:
            if not _reference_imported_member(tree, provider, "pytest", "raises"):
                return None
            if not _validation_operand_call(call, name):
                return None
            provider_root = (
                provider.value if isinstance(provider, ast.Attribute) else provider
            )
            if not isinstance(provider_root, ast.Name) or provider_root.id == name:
                return None
            names = {name, call.func.value.id, "str", "ValueError", provider_root.id}
            if error in names or expected in names | {error}:
                return None
            if not rest:
                return (call, terminal) if expected is None else None
            return (
                (call, rest[0])
                if _validation_error_assertion(rest[0], error, expected)
                else None
            )
        case _:
            return None


def _validation_error_assertion(node, error, expected):
    match node:
        case ast.Assert(
            test=ast.Compare(
                left=ast.Call(
                    func=ast.Name(id="str"),
                    args=[ast.Attribute(value=ast.Name(id=receiver), attr="value")],
                    keywords=[],
                ),
                ops=[ast.Eq()],
                comparators=[observed],
            ),
            msg=None,
        ) if receiver == error:
            if isinstance(observed, ast.Constant):
                return expected is None and type(observed.value) is str
            return (
                expected is not None
                and isinstance(observed, ast.Name)
                and observed.id == expected
            )
        case _:
            return False


def _validation_resolve_receiver(index, path, call):
    from .credential_role_constructor_provider import binding_occurrences
    from .runtime_audit_integrity import _conditional_module_name

    tree = index.snapshots[path]
    receiver = call.func.value.id
    match binding_occurrences(tree.body, receiver):
        case [ast.ImportFrom(module=module, level=0) as imported] if (
            imported in tree.body and module
        ):
            pass
        case _:
            return None
    resolved = _reference_local_export(index, path, receiver)
    if resolved is None or not isinstance(resolved[1], ast.ClassDef):
        return None
    producer_path, owner = resolved
    if _conditional_module_name(index.relative(producer_path)) != module:
        return None
    declarations = binding_occurrences(owner.body, call.func.attr)
    if len(declarations) != 1 or not isinstance(declarations[0], ast.FunctionDef):
        return None
    validator = declarations[0]
    return producer_path, owner, validator, f"{module}.{owner.name}"


def _validation_signature_clear(function):
    args = function.args
    formals = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    formals.extend(item for item in (args.vararg, args.kwarg) if item is not None)
    annotations = [function.returns, *(arg.annotation for arg in formals)]
    return (
        not getattr(function, "type_params", ())
        and not args.defaults
        and all(item is None for item in args.kw_defaults)
        and all(_validation_annotation(item) for item in annotations)
    )


def _validation_annotation(node):
    match node:
        case None | ast.Constant(value=None):
            return True
        case ast.Name(id=name):
            return name in _VALIDATION_BUILTINS
        case ast.Subscript(value=ast.Name(id=name), slice=item) if name in {
            "list",
            "dict",
            "tuple",
        }:
            return _validation_annotation(item)
        case ast.Tuple(elts=items):
            return all(_validation_annotation(item) for item in items)
        case ast.BinOp(left=left, op=ast.BitOr(), right=right):
            return _validation_annotation(left) and _validation_annotation(right)
        case _:
            return False


def _validation_fixed_signature(function, count):
    args = function.args
    return (
        _validation_signature_clear(function)
        and len(args.args) == count
        and not any((args.posonlyargs, args.kwonlyargs, args.vararg, args.kwarg))
    )


def _validation_class_definition_clear(cls):
    if (
        cls.bases
        or cls.keywords
        or cls.decorator_list
        or getattr(cls, "type_params", ())
    ):
        return False
    return all(
        isinstance(stmt, ast.FunctionDef)
        and not stmt.name.startswith("__")
        and stmt.name not in _VALIDATION_BUILTINS
        and (not stmt.decorator_list or _validation_staticmethod(stmt))
        and _validation_signature_clear(stmt)
        for stmt in _validation_body(cls)
    )


def _validation_staticmethod(function):
    return (
        len(function.decorator_list) == 1
        and isinstance(function.decorator_list[0], ast.Name)
        and function.decorator_list[0].id == "staticmethod"
    )


def _validation_module_definition_clear(tree):
    if not _reference_builtin_bindings_clear(tree, _VALIDATION_BUILTINS):
        return False
    for stmt in _validation_body(tree):
        match stmt:
            case ast.Import() | ast.ImportFrom() if all(
                item.name != "*" for item in stmt.names
            ):
                continue
            case ast.FunctionDef(decorator_list=[]) if _validation_signature_clear(
                stmt
            ):
                continue
            case ast.ClassDef() if _validation_class_definition_clear(stmt):
                continue
            case _:
                return False
    return True


def _validation_provider_closed(index, fixture, path, owner, method, canonical, sample):
    tree = index.snapshots[path]
    if not _validation_module_definition_clear(tree) or not _validation_staticmethod(
        method
    ):
        return False
    if not _validation_fixed_signature(method, 1) or not _validation_format_body(
        tree, method
    ):
        return False
    if not all(
        _validation_package_initializers_clear(index, member)
        for member in (fixture[0], path)
    ):
        return False
    protected = _validation_lexical_slots(index, (fixture, (path, method)))
    return bool(protected) and _validation_inventory_clear(
        index, path, owner, canonical, sample, protected
    )


def _validation_lexical_slots(index, functions):
    """Seal actual module lookups as well as their canonical providers."""
    from .credential_role_constructor_provider import binding_occurrences
    from .runtime_audit_integrity import _conditional_module_name

    modules = index.module_paths()
    if modules is None:
        return ()
    protected = []
    for path, function in functions:
        paths = {
            _conditional_module_name(name)
            for name, owner in modules.items()
            if owner == path
        }
        if not paths or "" in paths:
            return ()
        # Pytest can import a non-package test by its basename.
        paths.add(path.stem)
        args = {arg.arg for arg in function.args.args}
        reads = {
            node.id
            for node in ast.walk(function)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        }
        globals_used = {
            name
            for name in reads - args
            if not binding_occurrences(function.body, name)
        }
        protected.extend(
            (
                f"{module}.{name}",
                (path, name) if name not in _VALIDATION_BUILTINS else None,
            )
            for module in sorted(paths)
            for name in sorted(globals_used | _VALIDATION_BUILTINS)
        )
    return tuple(dict.fromkeys(protected))


def _validation_package_initializers_clear(index, path):
    for parent in path.parents:
        if parent == index.root:
            return True
        initializer = parent / "__init__.py"
        if initializer in index.snapshots and (
            not index.validate(initializer)
            or _validation_body(index.snapshots[initializer])
        ):
            return False
    return False


def _validation_inventory_clear(index, path, owner, canonical, sample, protected):
    from . import review_audits as audit
    from .credential_role_constructor_provider import (
        _captured_terminal_provider_mutation,
    )

    size = 0
    for peer, module in index.snapshots.items():
        if not index.validate(peer) or not _validation_no_provider_shadow(index, peer):
            return False
        nodes = tuple(ast.walk(module))
        size += len(nodes)
        if size > 100_000 or not all(
            _validation_inventory_node_clear(item)
            and (
                not isinstance(item, ast.Constant)
                or item is sample
                or item.value != sample.value
            )
            for item in nodes
        ):
            return False
    return not _captured_terminal_provider_mutation(
        index,
        audit,
        canonical,
        local_binding=(path, owner.name),
        additional_bindings=(("re", None), ("pytest", None), *protected),
    )


def _validation_no_provider_shadow(index, path):
    relative = index.relative(path)
    if relative is None:
        return False
    parts = relative.split("/")
    return not ({"pytest", "re"} & set(parts[:-1])) and parts[-1] not in {
        "pytest.py",
        "re.py",
    }


def _validation_inventory_node_clear(node):
    match node:
        case ast.Name(id=name):
            return name not in _VALIDATION_NAMESPACE_NAMES and not (
                name in {"__test__", "pytestmark", "pytest_plugins"}
                and isinstance(node.ctx, (ast.Store, ast.Del))
            )
        case ast.Attribute(attr=name):
            return name not in _VALIDATION_NAMESPACE_NAMES and not (
                name in {"__test__", "pytestmark", "pytest_plugins"}
                and isinstance(node.ctx, (ast.Store, ast.Del))
            )
        case ast.ImportFrom(module=name) | ast.alias(name=name) if name:
            return name.split(".", 1)[
                0
            ] not in _VALIDATION_OPAQUE_IMPORTS and name.rpartition(".")[2] not in {
                "patch",
                "MonkeyPatch",
                "mock",
            }
        case ast.Global() | ast.Nonlocal():
            return False
        case ast.FunctionDef(name=name) | ast.AsyncFunctionDef(name=name):
            return not name.startswith("pytest_") and name not in {
                "setup_module",
                "setup_function",
                "teardown_module",
                "teardown_function",
            }
        case ast.keyword(arg="autouse", value=value):
            return isinstance(value, ast.Constant) and value.value is False
        case _:
            return True


def _validation_format_body(tree, method):
    from .credential_role_constructor_provider import binding_occurrences

    operand = method.args.args[0].arg
    if operand in _VALIDATION_BUILTINS or binding_occurrences(method.body, operand):
        return False
    if not _validation_regex_binding_clear(tree, method):
        return False
    body = _validation_body(method)
    if len(body) < 2 or len(body) > 40:
        return False
    match body[-1]:
        case ast.Return(value=ast.Name(id=name)) if name == operand:
            pass
        case _:
            return False
    state = {operand: "operand"}
    checked = False
    for stmt in body[:-1]:
        match stmt:
            case ast.Assign(targets=[ast.Name(id=name)], value=value) if (
                name not in state and name not in _VALIDATION_BUILTINS
            ):
                kind = _validation_expression(value, state, tree)
                if kind is None:
                    return False
                state[name] = kind
            case ast.If() | ast.For():
                if not _validation_guard(stmt, state, tree):
                    return False
                checked = True
            case _:
                return False
    return checked


def _validation_regex_binding_clear(tree, method):
    from .credential_role_constructor_provider import binding_occurrences

    for call in ast.walk(method):
        if not isinstance(call, ast.Call) or not _reference_imported_member(
            tree, call.func, "re", "search"
        ):
            continue
        root = call.func.value if isinstance(call.func, ast.Attribute) else call.func
        if not isinstance(root, ast.Name) or binding_occurrences(method.body, root.id):
            return False
    return True


def _validation_guard(node, state, tree):
    match node:
        case ast.If(
            test=test,
            body=[
                ast.Raise(
                    exc=ast.Call(
                        func=ast.Name(id="ValueError"), args=[message], keywords=[]
                    ),
                    cause=None,
                )
            ],
            orelse=[],
        ):
            return (
                _validation_expression(test, state, tree) == "operand_check"
                and _validation_expression(message, state, tree) == "text"
            )
        case ast.For(
            target=ast.Name(id=name), iter=iterable, body=[ast.If() as guard], orelse=[]
        ) if name not in state and name not in _VALIDATION_BUILTINS:
            kinds = _validation_expression(iterable, state, tree)
            return (
                isinstance(kinds, tuple)
                and bool(kinds)
                and all(
                    _validation_guard(guard, {**state, name: kind}, tree)
                    for kind in kinds
                )
            )
        case _:
            return False


def _validation_expression(node, state, tree):
    match node:
        case ast.Name(id=name):
            return state.get(name)
        case ast.Constant(value=None):
            return "none"
        case ast.Constant(value=value):
            return _validation_literal_kind(value)
        case ast.Tuple(elts=items) if 0 < len(items) <= 12:
            kinds = tuple(_validation_expression(item, state, tree) for item in items)
            return kinds if None not in kinds else None
        case ast.Subscript(
            value=ast.Name(id=name), slice=ast.Constant(value=position)
        ) if type(position) is int:
            kinds = state.get(name)
            return (
                kinds[position]
                if isinstance(kinds, tuple) and 0 <= position < len(kinds)
                else None
            )
        case _:
            return _validation_computed_expression(node, state, tree)


def _validation_computed_expression(node, state, tree):
    match node:
        case ast.JoinedStr(values=items) if 0 < len(items) <= 16:
            return (
                "text"
                if all(_validation_format_part(item, state, tree) for item in items)
                else None
            )
        case ast.BinOp(left=left, op=ast.Add(), right=right):
            return (
                "text"
                if _validation_expression(left, state, tree)
                == _validation_expression(right, state, tree)
                == "text"
                else None
            )
        case ast.UnaryOp(op=ast.Not(), operand=operand):
            kind = _validation_expression(operand, state, tree)
            return kind if kind in {"boolean", "operand_check"} else None
        case ast.Compare(left=left, ops=[operator], comparators=[right]):
            return _validation_comparison(
                operator,
                _validation_expression(left, state, tree),
                _validation_expression(right, state, tree),
            )
        case ast.Call() as call:
            return _validation_format_call(call, state, tree)
        case _:
            return None


def _validation_literal_kind(value):
    if type(value) is bool:
        return "boolean"
    if type(value) is int and value.bit_length() <= 32:
        return "integer"
    if type(value) is str and len(value) <= 1024:
        return "text"
    return None


def _validation_format_part(part, state, tree):
    match part:
        case ast.Constant(value=literal):
            return type(literal) is str and len(literal) <= 1024
        case ast.FormattedValue(value=value, conversion=-1, format_spec=None):
            return (
                _validation_expression(value, state, tree)
                in _VALIDATION_TEXT_OPERATIONS
            )
        case _:
            return False


def _validation_comparison(operator, left, right):
    if isinstance(operator, (ast.Is, ast.IsNot)) and (left, right) in {
        ("regex_result", "none"),
        ("none", "regex_result"),
    }:
        return "operand_check"
    if isinstance(operator, (ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Eq, ast.NotEq)) and (
        left,
        right,
    ) in {("integer", "operand_length"), ("operand_length", "integer")}:
        return "operand_check"
    return None


def _validation_format_call(call, state, tree):
    match call:
        case ast.Call(
            func=ast.Name(id="len"), args=[ast.Name(id=name)], keywords=[]
        ) if state.get(name) == "operand":
            return "operand_length"
        case ast.Call(
            func=provider, args=[pattern, ast.Name(id=name)], keywords=[]
        ) if state.get(name) == "operand":
            root = provider.value if isinstance(provider, ast.Attribute) else provider
            if not isinstance(root, ast.Name) or root.id in state:
                return None
            if (
                _reference_imported_member(tree, provider, "re", "search")
                and _validation_expression(pattern, state, tree) == "text"
            ):
                return "regex_result"
    return None


_PASSWORD_VALIDATION_HELPERS = tuple(
    name
    for name, value in globals().items()
    if name.startswith("_validation_") and callable(value)
)


def password_validation_proof_helpers():
    """Bind live source-role and mutation-check lookups to the scan cache."""
    from . import credential_role_constructor_provider as provider
    from . import pytest_collection_audit as collection
    from . import runtime_audit_integrity as runtime

    return (
        captured_password_validation_proof,
        *(globals()[name] for name in _PASSWORD_VALIDATION_HELPERS),
        _VALIDATION_BUILTINS,
        _VALIDATION_NAMESPACE_NAMES,
        _VALIDATION_OPAQUE_IMPORTS,
        _VALIDATION_TEXT_OPERATIONS,
        _reference_local_export,
        _reference_imported_member,
        _reference_builtin_bindings_clear,
        provider.binding_occurrences,
        provider._captured_terminal_provider_mutation,
        collection._pytest_collection_settings,
        collection._pytest_file_matches,
        collection._pytest_name_matches,
        collection.captured_pytest_configuration,
        collection.captured_pytest_documents,
        runtime._conditional_module_name,
        runtime._source_span,
    )


HASH_FIXTURE_MAX_SNAPSHOTS = 512
_HASH_CONTEXT_PROVIDER = "passlib.context.CryptContext"
_HASH_SCHEMES = frozenset(
    {"pbkdf2_sha256", "pbkdf2_sha512", "bcrypt", "argon2", "scrypt"}
)
_HASH_THREAD_PROVIDER = "anyio.to_thread.run_sync"
_HASH_REFLECTION = (
    _VALIDATION_NAMESPACE_NAMES - {"vars", "getattr", "setattr", "delattr", "__class__"}
) | {
    "__getattribute__",
    "__setattr__",
    "__delattr__",
    "settrace",
    "setprofile",
    "_getframe",
    "__path__",
    "meta_path",
    "path_hooks",
    "path_importer_cache",
}
_HASH_REPORT_FLAGS = frozenset({"-s", "--tb=short"})
_HASH_PYTEST_NORECURSEDIRS = (
    "*.egg",
    ".*",
    "_darcs",
    "build",
    "CVS",
    "dist",
    "node_modules",
    "venv",
    "{arch}",
)
_HASH_PYTEST_COLLECTION_BINDINGS = frozenset(
    {
        "__test__",
        "pytestmark",
        "collect_ignore",
        "collect_ignore_glob",
        "setup_module",
        "setup_function",
        "teardown_module",
        "teardown_function",
    }
)


def captured_hash_fixture_proof(index, path, node):
    """Prove a captured test-local password/hash pair ends in boolean assertions."""
    from .runtime_audit_integrity import _source_span

    declaration = _hash_fixture_declaration(index, path, node)
    if declaration is None:
        return None
    owner, name, body = declaration
    trace = _HashFixtureTrace(index, path, owner, name)
    if not trace.follow(body) or not _hash_fixture_inventory_clear(trace):
        return None
    return {
        "hypothesis": "CAPTURED_HARDCODED_CREDENTIAL_AUTHORITY",
        "scope": "CAPTURED_PYTHON_SOURCE",
        "operand_role": "TEST_LOCAL_PASSWORD_HASH_FIXTURE",
        "declaration_span": _source_span(node),
        "fixture": {"span": _source_span(owner)},
        "test_consumers": trace.observations,
        "runtime_effects": "UNASSESSED",
    }


def _hash_fixture_declaration(index, path, node):
    match node:
        case ast.Assign(
            targets=[ast.Name(id=name)], value=ast.Constant(value=str() as value)
        ) if 0 < len(value) <= 1024:
            pass
        case _:
            return None
    if (
        not index.bounded
        or len(index.snapshots) > HASH_FIXTURE_MAX_SNAPSHOTS
        or not index.validate(path)
    ):
        return None
    tree = index.snapshots[path]
    owner = index.parents[path].get(id(node))
    if not _hash_fixture_owner_clear(tree, owner):
        return None
    body = _validation_body(owner, declaration=node)
    if not 2 <= len(body) <= 32 or not _hash_fixture_selected(index, path, owner):
        return None
    return owner, name, body


def _hash_fixture_owner_clear(tree, owner):
    from .credential_role_constructor_provider import binding_occurrences

    return (
        isinstance(owner, ast.FunctionDef)
        and owner in tree.body
        and not owner.decorator_list
        and _validation_fixed_signature(owner, 0)
        and binding_occurrences(tree.body, owner.name) == [owner]
        and _hash_fixture_module_clear(tree)
    )


def _hash_fixture_selected(index, path, function):
    from .pytest_collection_audit import (
        _pytest_collection_settings,
        _pytest_file_matches,
        _pytest_name_matches,
        _select_captured_pytest_configuration,
        captured_pytest_documents,
    )

    documents = captured_pytest_documents(index.snapshots[path])
    if not isinstance(documents, dict) or "tox.ini" in documents:
        return False
    selected = _select_captured_pytest_configuration(documents, True)
    if selected is None:
        return False
    identity, options = selected
    if not _hash_fixture_collection_options_clear(documents, options):
        return False
    if not _hash_fixture_collection_path_clear(path.relative_to(index.root), options):
        return False
    settings = _pytest_collection_settings(identity)
    return _pytest_file_matches(
        index.relative(path), settings["python_files"]
    ) and _pytest_name_matches(function.name, settings["python_functions"])


def _hash_fixture_collection_path_clear(path, options):
    from .pytest_collection_audit import _pytest_pattern_list

    roots = _pytest_pattern_list(options.get("testpaths", []))
    excluded = _pytest_pattern_list(
        options.get("norecursedirs", list(_HASH_PYTEST_NORECURSEDIRS))
    )
    if not all(
        isinstance(items, list) and all(isinstance(item, str) for item in items)
        for items in (roots, excluded)
    ):
        return False
    if any(pattern.startswith("/") or "\\" in pattern for pattern in excluded):
        return False
    relative = path.as_posix()
    if roots and not any(
        relative == root or relative.startswith(root.rstrip("/") + "/")
        for root in roots
    ):
        return False
    return not any(
        fnmatch.fnmatchcase("/" + parent.as_posix(), "*/" + pattern)
        if "/" in pattern
        else fnmatch.fnmatchcase(parent.name, pattern)
        for parent in path.parents
        if parent.parts
        for pattern in ("__pycache__", *excluded)
    )


def _hash_fixture_collection_options_clear(documents, options):
    import shlex

    from .pytest_collection_audit import _pytest_argument_effect

    if set(options) - {
        "addopts",
        "asyncio_default_fixture_loop_scope",
        "asyncio_mode",
        "norecursedirs",
        "python_classes",
        "python_files",
        "python_functions",
        "testpaths",
    }:
        return False
    raw = options.get("addopts", "")
    try:
        tokens = shlex.split(raw) if isinstance(raw, str) else raw
    except ValueError:
        return False
    if not isinstance(tokens, list) or not all(
        isinstance(token, str) for token in tokens
    ):
        return False
    coverage = _hash_fixture_coverage_available(documents, tokens)
    arguments = iter(tokens)
    for token in arguments:
        if token in _HASH_REPORT_FLAGS or coverage and token == "--no-cov-on-fail":
            continue
        if (
            _pytest_argument_effect(
                token, arguments, coverage_provider=coverage, source_role_only=False
            )
            != {}
        ):
            return False
    return True


def _hash_fixture_coverage_available(documents, tokens):
    from .pytest_collection_audit import _PYTEST_ARGUMENT_EFFECTS, _pytest_cov_provider

    coverage_flags = {
        flag for flag, (_, effect) in _PYTEST_ARGUMENT_EFFECTS if effect == "coverage"
    }
    return any(
        token == "--no-cov-on-fail" or token.partition("=")[0] in coverage_flags
        for token in tokens
    ) and _pytest_cov_provider(documents)


class _HashFixtureTrace:
    """Track only fresh local context instances and fixture-derived digests."""

    def __init__(self, index, path, owner, literal):
        self.index, self.path, self.owner, self.literal = index, path, owner, literal
        self.contexts, self.digests, self.observations = {}, {}, []
        self.verified, self.bindings, self.readonly = set(), set(), set()
        self.shared_contexts = set()
        self.local_names = set()

    def follow(self, body):
        self.local_names = {self.literal} | {
            statement.targets[0].id
            for statement in body
            if isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        }
        return (
            all(self.step(stmt) for stmt in body)
            and bool(self.digests)
            and (self.verified == set(self.digests))
        )

    def step(self, statement):
        match statement:
            case ast.Assign(targets=[ast.Name(id=name)], value=ast.Call() as call):
                return self.assign(name, call)
            case ast.Assert(test=ast.Call() as call, msg=None):
                return self.verify(call, statement)
            case _:
                return False

    def assign(self, name, call):
        from .runtime_audit_integrity import _source_span

        if name == self.literal or name in self.digests:
            return False
        constructor = _hash_fixture_context(
            self.index, self.path, call, self.local_names
        )
        if constructor is not None:
            schemes, binding = constructor
            self.contexts[name] = schemes, _source_span(call)
            return self.protect(self.path, *binding)
        if name in self.contexts:
            return False
        operation = self.operation(call, "hash")
        if operation is None:
            return False
        schemes, operands, evidence = operation
        if operands != [self.literal]:
            return False
        self.digests[name] = schemes[0], _source_span(call)
        self.observations.append(
            {"role": "HASH", "call_span": _source_span(call), **evidence}
        )
        return True

    def verify(self, call, statement):
        from .runtime_audit_integrity import _source_span

        operation = self.operation(call, "verify")
        if operation is None:
            return False
        schemes, (literal, digest), evidence = operation
        generated = self.digests.get(digest)
        if literal != self.literal or generated is None or generated[0] not in schemes:
            return False
        self.verified.add(digest)
        self.observations.append(
            {
                "role": "VERIFICATION_ASSERTION",
                "call_span": _source_span(call),
                "assertion_span": _source_span(statement),
                "hash_span": generated[1],
                **evidence,
            }
        )
        return True

    def operation(self, call, operation):
        from .runtime_audit_integrity import _source_span

        args = _hash_fixture_operands(call, operation)
        if args is None:
            return None
        match call.func:
            case ast.Attribute(value=ast.Name(id=name), attr=member) if (
                member == operation and name in self.contexts
            ):
                schemes, constructor_span = self.contexts[name]
                return (
                    schemes,
                    args,
                    {
                        "provider": f"{_HASH_CONTEXT_PROVIDER}.{operation}",
                        "context_span": constructor_span,
                    },
                )
            case ast.Name(id=name) if name not in self.local_names:
                selected = _hash_fixture_wrapper(self.index, self.path, name, operation)
                if selected is not None:
                    (
                        path,
                        helper,
                        context,
                        constructor,
                        schemes,
                        order,
                        bindings,
                        readonly,
                    ) = selected
                    if all(
                        self.protect(p, alias, canonical)
                        for p, alias, canonical in bindings
                    ):
                        self.readonly.update(readonly)
                        self.shared_contexts.add(context)
                        return (
                            schemes,
                            [args[position] for position in order],
                            {
                                "provider": f"{_HASH_CONTEXT_PROVIDER}.{operation}",
                                "helper": {
                                    "path": self.index.relative(path),
                                    "span": _source_span(helper),
                                    "context_span": _source_span(constructor),
                                },
                            },
                        )
        return None

    def protect(self, path, alias, canonical):
        from .runtime_audit_integrity import _conditional_module_name

        names = self.index.module_paths()
        if names is None:
            return False
        modules = {
            _conditional_module_name(name)
            for name, owner in names.items()
            if owner == path
        }
        if not modules or "" in modules:
            return False
        modules.add(path.stem)
        self.bindings.add((canonical, None))
        self.bindings.update((f"{module}.{alias}", (path, alias)) for module in modules)
        return True


def _hash_fixture_import(index, path, alias):
    from .credential_role_constructor_provider import _direct_terminal_import

    if not index.validate(path):
        return None
    return _direct_terminal_import(index, path, alias)


def _hash_fixture_context(index, path, call, locals_=()):
    from .credential_role_constructor_provider import _captured_module_shadows_terminal

    match call:
        case ast.Call(
            func=ast.Name(id=name),
            args=[],
            keywords=[
                ast.keyword(
                    arg="schemes", value=ast.List(elts=items) | ast.Tuple(elts=items)
                )
            ],
        ) if name not in locals_ and 1 <= len(items) <= len(_HASH_SCHEMES):
            if not all(
                isinstance(item, ast.Constant)
                and isinstance(item.value, str)
                and item.value in _HASH_SCHEMES
                for item in items
            ):
                return None
            imported = _hash_fixture_import(index, path, name)
            if (
                imported is None
                or imported[0] != _HASH_CONTEXT_PROVIDER
                or _captured_module_shadows_terminal(
                    index, path, imported[1], imported[0]
                )
            ):
                return None
            schemes = tuple(item.value for item in items)
            if len(set(schemes)) == len(schemes):
                return schemes, (name, imported[0])
    return None


def _hash_fixture_operands(call, operation):
    count = 1 if operation == "hash" else 2
    if (
        call.keywords
        or len(call.args) != count
        or not all(isinstance(arg, ast.Name) for arg in call.args)
    ):
        return None
    return [argument.id for argument in call.args]


def _hash_fixture_wrapper(index, path, alias, operation):
    from .credential_role_constructor_provider import binding_occurrences
    from .import_context import captured_import_module

    imported = _hash_fixture_import(index, path, alias)
    if imported is None:
        return None
    canonical, _statement = imported
    module, _, member = canonical.rpartition(".")
    _, provider_path = captured_import_module(index, path, module)
    if provider_path is None or provider_path == path:
        return None
    tree = index.snapshots[provider_path]
    match binding_occurrences(tree.body, member):
        case [ast.FunctionDef(decorator_list=[]) as helper] if helper in tree.body:
            pass
        case _:
            return None
    count = 1 if operation == "hash" else 2
    if not _validation_fixed_signature(helper, count):
        return None
    match _validation_body(helper):
        case [
            ast.Return(
                value=ast.Call(
                    func=ast.Attribute(value=ast.Name(id=context), attr=method)
                ) as call
            )
        ] if method == operation:
            pass
        case _:
            return None
    operands = _hash_fixture_operands(call, operation)
    formals = [argument.arg for argument in helper.args.args]
    if operands is None or set(operands) != set(formals) or context in formals:
        return None
    match binding_occurrences(tree.body, context):
        case [ast.Name() as binding]:
            assignment = index.parents[provider_path].get(id(binding))
        case _:
            return None
    match assignment:
        case ast.Assign(targets=[target], value=ast.Call() as constructor) if (
            assignment in tree.body and target is binding
        ):
            proof = _hash_fixture_context(index, provider_path, constructor)
        case _:
            return None
    if proof is None or not _hash_fixture_module_clear(tree, assignment):
        return None
    schemes, (ctor_alias, ctor_provider) = proof
    readonly, forwarders = _hash_fixture_forwarders(index, provider_path, helper)
    context_binding = (provider_path, context, f"{module}.{context}")
    bindings = (
        (path, alias, canonical),
        (provider_path, member, canonical),
        context_binding,
        (provider_path, ctor_alias, ctor_provider),
        *forwarders,
    )
    return (
        provider_path,
        helper,
        context_binding,
        constructor,
        schemes,
        [formals.index(arg) for arg in operands],
        bindings,
        readonly,
    )


def _hash_fixture_forwarders(index, path, helper):
    """Permit a supported thread adapter to call the same side-effect-free wrapper."""
    from .credential_role_constructor_provider import (
        _captured_module_shadows_terminal,
        binding_occurrences,
    )

    tree = index.snapshots[path]
    nodes, bindings = [], []
    for function in _validation_body(tree):
        if not isinstance(function, ast.AsyncFunctionDef):
            continue
        match _validation_body(function):
            case [
                ast.Return(
                    value=ast.Await(
                        value=ast.Call(
                            func=ast.Name(id=name),
                            args=[ast.Name(id=callback_name) as callback, *args],
                            keywords=[],
                        )
                    )
                )
            ] if callback_name == helper.name:
                pass
            case _:
                continue
        if (
            not _validation_fixed_signature(function, len(helper.args.args))
            or not all(isinstance(item, ast.Name) for item in args)
            or [item.id for item in args] != [arg.arg for arg in function.args.args]
            or any(arg.arg in {name, callback.id} for arg in function.args.args)
            or binding_occurrences(tree.body, function.name) != [function]
        ):
            continue
        imported = _hash_fixture_import(index, path, name)
        if (
            imported is not None
            and imported[0] == _HASH_THREAD_PROVIDER
            and not _captured_module_shadows_terminal(
                index, path, imported[1], imported[0]
            )
        ):
            nodes.append(callback)
            bindings.append((path, name, imported[0]))
    return tuple(nodes), tuple(bindings)


def _hash_fixture_module_clear(tree, context=None):
    if not _reference_builtin_bindings_clear(
        tree, {"str", "bytes", "bool", "int", "list", "dict", "tuple"}
    ):
        return False
    for stmt in _validation_body(tree):
        if stmt is context:
            continue
        match stmt:
            case ast.Import() | ast.ImportFrom() if all(
                item.name != "*" for item in stmt.names
            ):
                continue
            case (
                ast.FunctionDef(decorator_list=[])
                | ast.AsyncFunctionDef(decorator_list=[])
            ):
                args = stmt.args
                annotations = [stmt.returns, *(arg.annotation for arg in args.args)]
                if (
                    not getattr(stmt, "type_params", ())
                    and not any(
                        (args.posonlyargs, args.kwonlyargs, args.vararg, args.kwarg)
                    )
                    and all(
                        _hash_fixture_annotation_clear(item) for item in annotations
                    )
                    and all(isinstance(item, ast.Constant) for item in args.defaults)
                ):
                    continue
        return False
    return True


def _hash_fixture_annotation_clear(node):
    match node:
        case ast.Name(id="bytes"):
            return True
        case ast.BinOp(left=left, op=ast.BitOr(), right=right):
            return _hash_fixture_annotation_clear(
                left
            ) and _hash_fixture_annotation_clear(right)
        case _:
            return _validation_annotation(node)


def _hash_fixture_inventory_clear(trace):
    from . import review_audits as audit
    from .credential_role_constructor_provider import (
        _captured_terminal_provider_mutation,
    )
    from .runtime_audit_integrity import _conditional_module_name

    index = trace.index
    module_paths = index.module_paths()
    fixture_modules = {
        _conditional_module_name(name)
        for name, path in module_paths.items()
        if path == trace.path
    } | {trace.path.stem}
    conftest_modules = {
        _conditional_module_name(name)
        for name, path in module_paths.items()
        if path is not None and path.name == "conftest.py"
    }
    if conftest_modules:
        conftest_modules.add("conftest")
    bindings = tuple(
        sorted(
            {
                ("passlib", None),
                ("pytest", None),
                *((module, None) for module in conftest_modules),
                *trace.bindings,
                *(
                    (f"{module}.{trace.owner.name}", (trace.path, trace.owner.name))
                    for module in fixture_modules
                ),
            },
            key=lambda item: (item[0], str(item[1])),
        )
    )
    names = frozenset(name for name, _ in bindings)
    contexts = {canonical for _, _, canonical in trace.shared_contexts}
    size = 0
    for path, tree in index.snapshots.items():
        if not index.validate(path):
            return False
        nodes = tuple(ast.walk(tree))
        size += len(nodes)
        if size > 150_000:
            return False
        aliases = audit._security_aliases(nodes)
        aliases.update(
            (local, canonical)
            for provider_path, local, canonical in trace.shared_contexts
            if path == provider_path
        )
        if not all(
            _hash_fixture_inventory_node_clear(
                node, index.parents[path], names, contexts, aliases, audit
            )
            for node in nodes
        ):
            return False
    return not _captured_terminal_provider_mutation(
        index,
        audit,
        bindings[0][0],
        local_binding=bindings[0][1],
        additional_bindings=bindings[1:],
        readonly_nodes=trace.readonly,
    )


def _hash_fixture_collection_binding(name):
    return name.startswith("pytest_") or name in _HASH_PYTEST_COLLECTION_BINDINGS


def _hash_fixture_lexical_clear(node, name, aliases, audit):
    if name == "__path__" and isinstance(node, ast.Attribute):
        return isinstance(node.ctx, ast.Load)
    if name in _HASH_REFLECTION:
        return False
    if name == "path" and audit._resolved_ast_name(node, aliases) == "sys.path":
        return False
    return not (
        isinstance(node.ctx, (ast.Store, ast.Del))
        and _hash_fixture_collection_binding(name)
    )


def _hash_fixture_inventory_node_clear(
    node, parents, providers, contexts, aliases, audit
):
    match node:
        case ast.Name(id=name) | ast.Attribute(attr=name):
            return _hash_fixture_lexical_clear(node, name, aliases, audit)
        case ast.Global() | ast.Nonlocal():
            return False
        case ast.alias(name=name, asname=alias):
            root = name.split(".", 1)[0]
            return (
                name != "*"
                and root not in {"builtins", "ctypes", "inspect"}
                and not _hash_fixture_collection_binding(alias or root)
            )
        case ast.ImportFrom(module=module) if module:
            return module.split(".", 1)[0] not in {
                "builtins",
                "ctypes",
                "inspect",
            }
        case (
            ast.FunctionDef(name=name)
            | ast.AsyncFunctionDef(name=name)
            | ast.ClassDef(name=name)
            | ast.ExceptHandler(name=str() as name)
            | ast.MatchAs(name=str() as name)
            | ast.MatchStar(name=str() as name)
            | ast.MatchMapping(rest=str() as name)
        ):
            return not _hash_fixture_collection_binding(name)
        case ast.Subscript(
            slice=ast.Constant(value=str() as name), ctx=ast.Store() | ast.Del()
        ):
            return not _hash_fixture_collection_binding(name)
        case ast.Call(func=func):
            return _hash_fixture_reflection_clear(
                node, func, parents, providers, contexts, aliases, audit
            )
        case _:
            return True


def _hash_fixture_reflection_clear(
    call, func, parents, providers, contexts, aliases, audit
):
    canonical = audit._resolved_ast_name(func, aliases)
    if canonical.startswith("passlib.registry."):
        return False
    if canonical in contexts or any(
        canonical.startswith(context + ".") for context in contexts
    ):
        receiver, _, method = canonical.rpartition(".")
        return receiver in contexts and method in {"hash", "verify"}
    if canonical.startswith("runpy."):
        match call:
            case ast.Call(
                args=[ast.Constant(value=str() as target)],
                keywords=[
                    ast.keyword(arg="run_name", value=ast.Constant(value="__main__"))
                ],
            ):
                return (
                    canonical == "runpy.run_module"
                    and all(part.isidentifier() for part in target.split("."))
                    and isinstance(parents.get(id(call)), ast.Expr)
                )
            case _:
                return False
    if canonical == "importlib.import_module":
        receiver = parents.get(id(call))
        consumer = parents.get(id(receiver))
        return isinstance(receiver, ast.Expr) or (
            isinstance(receiver, ast.Attribute)
            and receiver.attr == "__path__"
            and isinstance(consumer, ast.Subscript)
            and isinstance(consumer.ctx, ast.Load)
        )
    member = func.attr if isinstance(func, ast.Attribute) else canonical
    return _hash_fixture_patch_clear(call, member, canonical, providers)


def _hash_fixture_patch_clear(call, member, canonical, providers):
    from .credential_role_constructor_provider import _terminal_provider_related

    patch = canonical in {"mock.patch", "unittest.mock.patch"}
    patch_object = canonical in {"mock.patch.object", "unittest.mock.patch.object"}
    if not patch and not patch_object and member not in {"setattr", "delattr"}:
        return True
    if not call.args:
        return False
    match call.args[0]:
        case ast.Constant(value=str() as target):
            if _hash_fixture_collection_binding(target.rsplit(".", 1)[-1]):
                return False
            names = {target, target.removeprefix("builtins.")}
            return not any(
                _terminal_provider_related(name, provider)
                for name in names
                for provider in providers
            )
        case ast.Name() | ast.Attribute() if not patch:
            attribute = call.args[1] if len(call.args) > 1 else None
            return not (
                isinstance(attribute, ast.Constant)
                and isinstance(attribute.value, str)
                and _hash_fixture_collection_binding(attribute.value)
            )
        case _:
            return False


_HASH_FIXTURE_HELPERS = tuple(
    name
    for name, value in globals().items()
    if name.startswith("_hash_fixture_") and callable(value)
)


def hash_fixture_proof_helpers():
    """Bind live captured-argument and mutation lookups to the audit cache."""
    from . import credential_role_constructor_provider as provider
    from . import import_context
    from . import pytest_collection_audit as collection
    from . import runtime_audit_integrity as runtime

    return (
        captured_hash_fixture_proof,
        *(globals()[name] for name in _HASH_FIXTURE_HELPERS),
        _HashFixtureTrace,
        _HashFixtureTrace.__init__,
        _HashFixtureTrace.follow,
        _HashFixtureTrace.step,
        _HashFixtureTrace.assign,
        _HashFixtureTrace.verify,
        _HashFixtureTrace.operation,
        _HashFixtureTrace.protect,
        HASH_FIXTURE_MAX_SNAPSHOTS,
        _HASH_CONTEXT_PROVIDER,
        _HASH_THREAD_PROVIDER,
        _HASH_SCHEMES,
        _HASH_REFLECTION,
        _HASH_REPORT_FLAGS,
        _HASH_PYTEST_NORECURSEDIRS,
        _HASH_PYTEST_COLLECTION_BINDINGS,
        fnmatch.fnmatchcase,
        _validation_body,
        _validation_fixed_signature,
        _validation_signature_clear,
        _validation_annotation,
        _VALIDATION_BUILTINS,
        _reference_builtin_bindings_clear,
        provider.binding_occurrences,
        provider._direct_terminal_import,
        provider._captured_module_shadows_terminal,
        provider._captured_terminal_provider_mutation,
        provider._terminal_provider_related,
        import_context.captured_import_module,
        collection.captured_pytest_documents,
        collection._select_captured_pytest_configuration,
        collection._PYTEST_ARGUMENT_EFFECTS,
        collection._pytest_argument_effect,
        collection._pytest_cov_provider,
        collection._pytest_collection_settings,
        collection._pytest_file_matches,
        collection._pytest_name_matches,
        collection._pytest_pattern_list,
        collection.fnmatchcase,
        runtime._source_span,
        runtime._conditional_module_name,
    )
