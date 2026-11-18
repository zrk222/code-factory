"""Values and exact text operations for the source-bound fixture model."""

import ast


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
