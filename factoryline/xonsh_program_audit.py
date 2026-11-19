"""Captured program operand proof for Xonsh pipeline workers."""

from __future__ import annotations

import ast
from hashlib import sha256
from pathlib import PurePosixPath

from .audit_action_refs import _declaration_bindings
from .runtime_audit_common import canonical_bytes
from .runtime_audit_integrity import _exact_source_call


def stage_xonsh_program_refutation(relative, node, finding):
    """Refute captured source injection while preserving the eval observation."""
    if finding["facts"].get("security_precondition") is not None:
        return

    from .captured_security_audit import _native_span
    from .pytest_collection_audit import _captured_pytest_inputs
    from .semantic_credential_sensor import _security_helper_source_context

    module, index, path = _security_helper_source_context(node, None)
    staged = getattr(_captured_pytest_inputs(module)[1], "provisional_exclusions", None)
    if path is None or len(index.snapshots) > 128:
        return
    span = _native_span(node)
    if span is None or index.relative(path) != relative or not index.validate(path):
        return
    try:
        authority = _xonsh_program_authority(index, path, node)
    except (SyntaxError, TypeError, ValueError, RecursionError):
        return
    if authority is None:
        return
    # Always reproduce these facts from source, including on a seal-only replay
    # that does not collect provisional exclusions.
    finding["facts"]["captured_program_role"] = {
        "hypothesis": "CAPTURED_SOURCE_INJECTION",
        "scope": "CAPTURED_PYTHON_SOURCE",
        "program_role": "OPERATOR_SELECTED_PROGRAM",
        "record_role": "SEPARATE_CONTEXT_DATA",
        "external_callers": "UNASSESSED",
        "runtime_effects": "UNASSESSED",
        "dynamic_execution_primitive": "RETAINED",
        "source_authority_sha256": authority,
    }
    if type(staged) is set:
        staged.add((finding["code"], relative, *span, finding["severity"], authority))


def xonsh_program_role_helpers():
    """Bind the proof implementation to the native verifier replay identity."""
    from . import (
        captured_security_audit,
        finite_capture,
        pytest_collection_audit,
        semantic_credential_sensor,
    )

    return (
        *(globals()[name] for name in _XONSH_HELPER_NAMES),
        _declaration_bindings,
        _exact_source_call,
        canonical_bytes,
        captured_security_audit._native_span,
        finite_capture._fixed_eval_builtin_provider_risk,
        pytest_collection_audit._captured_pytest_inputs,
        semantic_credential_sensor._security_helper_source_context,
    )


def _parents(tree):
    return {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }


def _formals(function, arity):
    args = function.args
    if (
        len(args.args) != arity
        or args.defaults
        or args.posonlyargs
        or args.kwonlyargs
        or args.vararg
        or args.kwarg
        or getattr(function, "returns", None)
        or any(argument.annotation is not None for argument in args.args)
        or getattr(function, "type_params", ())
    ):
        return ()
    return tuple(item.arg for item in args.args)


def _same(node, expression):
    """Compare a source node against a parsed expression with bound AST names."""
    return isinstance(node, ast.AST) and ast.dump(node) == ast.dump(
        ast.parse(expression, mode="eval").body
    )


def _xonsh_program_authority(index, path, node):
    """Verify the class, worker call, and every captured allocator of the class."""
    relative = PurePosixPath(index.relative(path))
    if len(relative.parts) != 3 or relative.parts[0] != "xontrib":
        return None
    registration = path.with_name("__init__.py")
    if registration == path or not index.validate(registration):
        return None
    if (
        path.with_suffix("").joinpath("__init__.py") in index.snapshots
        or len(index.source_bytes[path]) > 128_000
        or len(index.source_bytes[registration]) > 128_000
    ):
        return None
    exact = _exact_source_call(index.source_bytes[path], node)
    if exact is None:
        return None
    tree, sink = exact
    module = ".".join(relative.with_suffix("").parts)
    worker = _worker_class(tree, sink)
    if worker is None:
        return None
    class_node, dispatch, demo = worker
    entry = ast.parse(index.source_bytes[registration])
    binding = _xonsh_registration(entry, module, class_node.name, dispatch)
    if binding is None:
        return None
    callback, installations, package = binding
    if not _program_source_inventory(
        index,
        path,
        registration,
        entry,
        tree,
        module,
        package,
        installations,
        demo,
        class_node.name,
    ):
        return None
    manifest = sorted(
        (index.relative(peer), index.inventory[peer]) for peer in index.snapshots
    )
    return sha256(
        canonical_bytes(["xonsh-pipeline-program-v1", manifest, callback.lineno])
    ).hexdigest()


def _worker_class(tree, sink):
    parents = _parents(tree)
    statement = parents.get(sink)
    gate = parents.get(statement)
    worker = parents.get(gate)
    match statement, gate, worker:
        case ast.Return(), ast.Try(body=[_], orelse=[], finalbody=[]), ast.FunctionDef(
            decorator_list=[]
        ):
            pass
        case ast.Return(), ast.FunctionDef(decorator_list=[]) as worker, _:
            gate = statement
        case _:
            return None
    owner = parents.get(worker)
    methods = _worker_methods(tree, owner)
    if not methods:
        return None
    if not {
        "__init__",
        "__call__",
        worker.name,
    } <= methods.keys() or worker.name.startswith("__"):
        return None
    dispatch = next(
        item
        for name, item in methods.items()
        if name not in {worker.name, "__init__", "__call__"}
    )
    if dispatch.name.startswith("__"):
        return None
    attribute, scope = sink.args
    if not _worker_operands(tree, worker, gate, attribute, scope):
        return None
    constructor, forward = methods["__init__"], methods["__call__"]
    if not _worker_constructor(constructor, attribute.attr) or not _worker_forward(
        forward, worker.name
    ):
        return None
    if not _worker_pool(tree, dispatch):
        return None
    # A constructor, forwarding call, or interpreter may each use the receiver only
    # at the checked site. This also rules out writes to the selected program field.
    if not all(_worker_receiver_is_single_use(method) for method in methods.values()):
        return None
    demo = _owner_constructor_sites(tree, owner)
    return None if demo is None else (owner, dispatch.name, demo)


def _worker_methods(tree, owner):
    """Accept ordinary class construction and four source-owned method slots."""
    if not (
        isinstance(owner, ast.ClassDef)
        and owner in tree.body
        and len(owner.body) == 4
        and not (
            owner.keywords or owner.decorator_list or getattr(owner, "type_params", ())
        )
        and (
            not owner.bases or len(owner.bases) == 1 and _same(owner.bases[0], "object")
        )
        and not _declaration_bindings(
            list(ast.walk(tree)), {"eval", "object", "globals", "__xonsh__", "__name__"}
        )
        and not any(
            isinstance(item, ast.Name) and item.id in {"__class__", "super"}
            for item in ast.walk(owner)
        )
    ):
        return None
    methods = {
        item.name: item
        for item in owner.body
        if isinstance(item, ast.FunctionDef) and not item.decorator_list
    }
    return methods if len(methods) == 4 else None


def _worker_operands(tree, worker, gate, attribute, scope):
    names = _formals(worker, 2)
    if (
        not names
        or attribute.attr.startswith("_")
        or not _same(attribute.value, names[0])
    ):
        return False
    if worker.body[-1] is not gate:
        return False
    context = scope.id
    match worker.body[:-1]:
        case [
            ast.Assign(
                targets=[ast.Name(id=name) as target],
                value=ast.Dict(keys=[], values=[]),
            ),
            *remaining,
        ] if name == context:
            pass
        case _:
            return False
    bindings = {target}
    hosts = set()
    if remaining and isinstance(remaining[0], ast.Try):
        match remaining.pop(0):
            case ast.Try(
                body=[
                    ast.Assign(targets=[ast.Name(id=name) as host_target], value=host)
                ],
                handlers=[ast.ExceptHandler(type=None, name=None, body=[ast.Pass()])],
                orelse=[],
                finalbody=[],
            ) if name == context and _same(host, "__xonsh__.ctx"):
                bindings.add(host_target)
                hosts.add(host.value)
            case _:
                return False
    keys = [
        _worker_context_slot(statement, context, names[1], position)
        for position, statement in enumerate(remaining)
    ]
    return (
        len(keys) == 2
        and None not in keys
        and len(set(keys)) == 2
        and _host_names(tree) == hosts
        and _declaration_bindings(list(ast.walk(worker)), {context}) == bindings
        and {
            name
            for name in ast.walk(worker)
            if isinstance(name, ast.Name) and name.id == context
        }
        == bindings | {scope, *(statement.targets[0].value for statement in remaining)}
    )


def _worker_context_slot(statement, context, packet, position):
    match statement:
        case ast.Assign(
            targets=[
                ast.Subscript(
                    value=ast.Name(id=name), slice=ast.Constant(value=str() as key)
                )
            ],
            value=value,
        ) if (
            name == context
            and key.isidentifier()
            and not key.startswith("_")
            and _same(value, f"{packet}[{position}]")
        ):
            return key
    return None


def _worker_constructor(function, field):
    names = _formals(function, 2)
    if not names:
        return False
    match function.body:
        case [
            ast.Assign(
                targets=[ast.Attribute(value=ast.Name(id=receiver), attr=assigned)],
                value=value,
            )
        ]:
            return receiver == names[0] and assigned == field and _same(value, names[1])
    return False


def _worker_forward(function, worker):
    names = _formals(function, 2)
    return bool(
        names
        and len(function.body) == 1
        and isinstance(function.body[0], ast.Return)
        and _same(function.body[0].value, f"{names[0]}.{worker}({names[1]})")
    )


def _worker_pool(tree, dispatch):
    names = _formals(dispatch, 3)
    if not names:
        return False
    match dispatch.body:
        case [
            ast.With(
                items=[
                    ast.withitem(
                        context_expr=pool,
                        optional_vars=ast.Name(id=process) as assigned,
                    )
                ],
                body=[ast.Assign(value=call), *_],
            )
        ]:
            pass
        case _:
            return False
    if not _same(pool, "Pool(cpu_count())") or not _same(
        call, f"{process}.imap_unordered({names[0]}, {names[1]})"
    ):
        return False
    imports = {
        alias
        for statement in tree.body
        if isinstance(statement, ast.ImportFrom)
        and statement.module == "multiprocessing"
        and statement.level == 0
        for alias in statement.names
        if alias.name in {"Pool", "cpu_count"} and alias.asname is None
    }
    return (
        len(imports) == 2
        and _declaration_bindings(list(ast.walk(tree)), {"Pool", "cpu_count"})
        == imports
        and _declaration_bindings(list(ast.walk(dispatch)), {process}) == {assigned}
    )


def _worker_receiver_is_single_use(function):
    receiver = function.args.args[0].arg
    nodes = list(ast.walk(function))
    return (
        _declaration_bindings(nodes, {receiver}) == {function.args.args[0]}
        and sum(isinstance(item, ast.Name) and item.id == receiver for item in nodes)
        == 1
    )


def _owner_constructor_sites(tree, class_node):
    """Closed standalone calls must use a literal or fail ordinary argument binding."""
    parents = _parents(tree)
    sites = set()
    for name in ast.walk(tree):
        if not isinstance(name, ast.Name) or name.id != class_node.name:
            continue
        match parents[name]:
            case (
                ast.Call(
                    func=callee, args=[ast.Constant(value=str()), *extra], keywords=[]
                ) as call
            ) if callee is name:
                if extra and (len(extra) != 1 or not _same(extra[0], "globals()")):
                    return None
            case _:
                return None
        match parents[call]:
            case ast.Assign(value=value) as statement if value is call:
                block = parents[statement]
            case _:
                return None
        if not (
            isinstance(block, ast.If)
            and block in tree.body
            and statement in block.body
            and not block.orelse
            and _same(block.test, "__name__ == '__main__'")
        ):
            return None
        # The pinned standalone demo supplies an extra positional argument. The
        # verified initializer accepts one argument, so this call makes no worker.
        if not extra:
            return None
        sites.add(statement)
    return (
        sites
        if _declaration_bindings(list(ast.walk(tree)), {class_node.name})
        == {class_node}
        else None
    )


def _xonsh_registration(tree, module, class_name, dispatch):
    imports = [
        (statement, alias)
        for statement in ast.walk(tree)
        if isinstance(statement, ast.ImportFrom)
        and statement.module == module
        and statement.level == 0
        for alias in statement.names
        if alias.name == class_name
    ]
    if len(imports) != 1 or imports[0][0] not in tree.body:
        return None
    _, binding = imports[0]
    local = binding.asname or class_name
    nodes = list(ast.walk(tree))
    if _declaration_bindings(nodes, {local}) != {binding} or _declaration_bindings(
        nodes, {"aliases", "__xonsh__", "len", "eval"}
    ):
        return None
    parents = _parents(tree)
    installations = _xonsh_installations(tree, nodes, parents)
    if not installations:
        return None
    allocators = [
        name for name in nodes if isinstance(name, ast.Name) and name.id == local
    ]
    if not allocators:
        return None
    callback = _top_level_function(tree, allocators[0], parents)
    names = _formals(callback, 3) if callback else ()
    if not names or any(
        _top_level_function(tree, site, parents) is not callback for site in allocators
    ):
        return None
    if not _pipeline_callback(tree, callback, installations, parents):
        return None
    if not _registration_host_reads_closed(tree, callback, installations, parents):
        return None
    if not _pipeline_allocators(callback, allocators, parents, dispatch, names):
        return None
    return callback, set(installations.values()), module.rsplit(".", 1)[0]


def _host_names(tree):
    return {
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and node.id == "__xonsh__"
    }


def _registration_host_reads_closed(tree, selected, installations, parents):
    """Allow the neighboring line evaluator's exact preset and globals slots."""
    hosts = _host_names(tree)
    if not hosts:
        return True
    owners = {_top_level_function(tree, host, parents) for host in hosts}
    if len(hosts) != 3 or len(owners) != 1:
        return False
    owner = next(iter(owners))
    if (
        owner is None
        or owner is selected
        or not _registered_neighbor(owner, installations)
    ):
        return False
    return _neighbor_host_slots(hosts, owner, parents)


def _registered_neighbor(function, installations):
    return any(
        isinstance(statement.value, ast.Name) and statement.value.id == function.name
        for statement in installations.values()
    )


def _neighbor_host_slots(hosts, function, parents):
    names = _formals(function, 3)
    if not names:
        return False
    slots = {_neighbor_host_slot(host, parents) for host in hosts}
    if None in slots or len(slots) != 3:
        return False
    by_role = {role: (name, target) for role, name, target in slots}
    if set(by_role) != {"presets", "option", "selected"}:
        return False
    table, _ = by_role["presets"]
    option, direct_target = by_role["option"]
    selected, preset_target = by_role["selected"]
    if option != names[0] or direct_target.id != preset_target.id:
        return False
    nodes = list(ast.walk(function))
    bindings = _declaration_bindings(nodes, {selected})
    if len(bindings) != 1:
        return False
    definition = next(iter(bindings))
    match parents.get(definition):
        case ast.Assign(targets=[target], value=value) if target is definition:
            pass
        case _:
            return False
    if not _same(value, f"{table}[{names[0]}[0]]"):
        return False
    return _neighbor_function_use_closed(nodes, parents, direct_target.id)


def _neighbor_function_use_closed(nodes, parents, name):
    return all(
        isinstance(call := parents.get(node), ast.Call) and call.func is node
        for node in nodes
        if isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, ast.Load)
    )


def _neighbor_host_slot(host, parents):
    member = parents.get(host)
    if _same(member, "__xonsh__.ctx"):
        return _neighbor_eval_slot(member, parents)
    if not _same(member, "__xonsh__.env"):
        return None
    call = parents.get(parents.get(member))
    if not _same(call, "__xonsh__.env.get('XONTRIB_PIPELINER_PRESETS', {})"):
        return None
    table = parents.get(call)
    declaration = parents.get(table)
    match table, declaration:
        case ast.Dict(keys=[None, None], values=[ast.Name(), value]), ast.Assign(
            targets=[ast.Name(id=name)], value=assigned
        ) if value is call and assigned is table:
            return "presets", name, None
    return None


def _neighbor_eval_slot(member, parents):
    call = parents.get(member)
    declaration = parents.get(call)
    match call, declaration:
        case ast.Call(
            func=ast.Name(id="eval"),
            args=[
                ast.BinOp(
                    left=ast.Constant(value="lambda line, num, args:"),
                    op=ast.Add(),
                    right=program,
                ),
                namespace,
            ],
            keywords=[],
        ), ast.Assign(targets=[ast.Name() as target], value=value) if (
            namespace is member and value is call
        ):
            match program:
                case ast.Name(id=selected):
                    return "selected", selected, target
                case ast.Subscript(
                    value=ast.Name(id=options), slice=ast.Constant(value=0)
                ):
                    return "option", options, target
    return None


def _xonsh_installations(tree, nodes, parents):
    """Resolve each constant Xonsh alias slot to one source-owned callback."""
    installations = {}
    for name in nodes:
        if not isinstance(name, ast.Name) or name.id != "aliases":
            continue
        slot = parents[name]
        if not (
            isinstance(slot, ast.Subscript)
            and slot.value is name
            and isinstance(slot.slice, ast.Constant)
            and type(slot.slice.value) is str
        ):
            return None
        key = slot.slice.value
        if isinstance(slot.ctx, ast.Store):
            statement = parents[slot]
            if not (
                key not in installations
                and statement in tree.body
                and isinstance(statement, ast.Assign)
                and statement.targets == [slot]
                and isinstance(statement.value, (ast.Name, ast.Lambda))
            ):
                return None
            installations[key] = statement
        elif not isinstance(slot.ctx, ast.Load):
            return None
    return installations


def _top_level_function(tree, node, parents):
    while node in parents:
        node = parents[node]
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            return (
                node
                if isinstance(node, ast.FunctionDef)
                and node in tree.body
                and not node.decorator_list
                else None
            )
    return None


def _pipeline_callback(tree, callback, installations, parents):
    if not callback.name.startswith("_"):
        return False
    named = [
        (key, statement.value)
        for key, statement in installations.items()
        if isinstance(statement.value, ast.Name) and statement.value.id == callback.name
    ]
    if len(named) != 1:
        return False
    key, selected = named[0]
    nodes = list(ast.walk(tree))
    if any(
        node is not callback
        and not (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Del)
            and isinstance(parents[node], ast.Delete)
            and parents[node] in tree.body
            and tree.body.index(parents[node]) > tree.body.index(parents[selected])
        )
        for node in _declaration_bindings(nodes, {callback.name})
    ):
        return False
    if any(
        isinstance(node, ast.Name)
        and node.id == callback.name
        and isinstance(node.ctx, ast.Load)
        and node is not selected
        for node in nodes
    ):
        return False
    return _pipeline_aliases_closed(key, nodes, installations, parents)


def _pipeline_aliases_closed(primary, nodes, installations, parents):
    """Walk every consumer of the primary alias and its forwarding aliases."""
    uses = {}
    for node in nodes:
        match node:
            case ast.Subscript(
                value=ast.Name(id="aliases"),
                slice=ast.Constant(value=str() as key),
                ctx=ast.Load(),
            ):
                uses.setdefault(key, []).append(node)
    keys = {statement: key for key, statement in installations.items()}
    pending, visited = [primary], set()
    while pending:
        key = pending.pop()
        if key in visited:
            continue
        visited.add(key)
        for use in uses.get(key, ()):
            wrapper = _pipeline_alias_wrapper(use, parents)
            if wrapper not in keys:
                return False
            pending.append(keys[wrapper])
    return True


def _pipeline_alias_wrapper(node, parents):
    match parents[node]:
        case (
            ast.Call(
                func=callee,
                args=[ast.List(elts=[program]), source, output],
                keywords=[],
            ) as call
        ) if callee is node:
            wrapper = parents[call]
        case _:
            return None
    if not isinstance(wrapper, ast.Lambda):
        return None
    names = _formals(wrapper, 3)
    if not names or not _same(source, names[1]) or not _same(output, names[2]):
        return None
    transparent = (
        _same(program, f"{names[0]}[0]")
        or isinstance(program, ast.JoinedStr)
        and all(
            isinstance(part, ast.Constant)
            or isinstance(part, ast.FormattedValue)
            and part.format_spec is None
            and _same(part.value, f"{names[0]}[0]")
            for part in program.values
        )
    )
    return parents[wrapper] if transparent else None


def _pipeline_allocators(callback, allocators, parents, dispatch, names):
    arguments, stream, output = names
    nodes = list(ast.walk(callback))
    if _declaration_bindings(nodes, set(names)) != set(callback.args.args):
        return False
    runner_names, runner_refs, batches, data_uses = set(), set(), set(), set()
    for site in allocators:
        if site not in nodes:
            return False
        worker_use = _pipeline_worker_use(site, parents, arguments, output, dispatch)
        if worker_use is None:
            return False
        target, use, data = worker_use
        runner_refs.update((target, use))
        runner_names.add(target.id)
        batches.add(data.id)
        data_uses.add(data)
    if {
        node for node in nodes if isinstance(node, ast.Name) and node.id in runner_names
    } != runner_refs:
        return False
    for node in nodes:
        if isinstance(node, ast.Name) and node.id == arguments:
            parent = parents[node]
            if not (
                _same(parent, f"{arguments}[0]") or _same(parent, f"len({arguments})")
            ):
                return False
    return all(
        _pipeline_batch(callback, batch, stream, parents, nodes, data_uses)
        for batch in batches
    )


def _pipeline_worker_use(site, parents, arguments, output, dispatch):
    match parents[site]:
        case ast.Call(func=callee, args=[program], keywords=[]) as call if (
            callee is site and _same(program, f"{arguments}[0]")
        ):
            pass
        case _:
            return None
    statement = parents[call]
    match statement:
        case ast.Assign(targets=[ast.Name(id=runner) as target], value=value) if (
            value is call
        ):
            pass
        case _:
            return None
    # Bind the receiver at its immediate dispatch, including branch-local
    # allocations of the same name.
    suite = getattr(parents[statement], "body", ())
    if not (
        isinstance(suite, list) and statement in suite and suite[-1] is not statement
    ):
        return None
    match suite[suite.index(statement) + 1]:
        case ast.Expr(
            value=ast.Call(
                func=ast.Attribute(value=ast.Name(id=receiver) as use, attr=method),
                args=[ast.Name() as batch, sink],
                keywords=[],
            )
        ) if receiver == runner and method == dispatch and _same(sink, output):
            return target, use, batch
    return None


def _pipeline_batch(callback, batch, stream, parents, nodes, data_uses):
    """Bind data batches to stream records in the same host callback."""
    assignments = _declaration_bindings(nodes, {batch})
    if not assignments or not all(
        isinstance(node, ast.Name)
        and isinstance(parents[node], ast.Assign)
        and parents[node].targets == [node]
        and _same(parents[node].value, "[]")
        for node in assignments
    ):
        return False
    appends = []
    for node in nodes:
        if not isinstance(node, ast.Name) or node.id != batch or node in assignments:
            continue
        parent = parents[node]
        if isinstance(parent, ast.If) and parent.test is node:
            continue
        if node in data_uses:
            continue
        if not isinstance(parent, ast.Attribute) or parent.attr != "append":
            return False
        call = parents[parent]
        match call:
            case ast.Call(
                func=callee,
                args=[ast.List(elts=[line, counter]) | ast.Tuple(elts=[line, counter])],
                keywords=[],
            ) if callee is parent:
                appends.append((call, line, counter))
            case _:
                return False
    if len(appends) != 1:
        return False
    call, line, counter = appends[0]
    loops = [
        item
        for item in callback.body
        if isinstance(item, ast.For)
        and isinstance(item.target, ast.Name)
        and _same(item.iter, f"{stream}.readlines()")
        and call in ast.walk(item)
    ]
    if len(loops) != 1:
        return False
    loop = loops[0]
    return bool(
        (
            _same(line, loop.target.id)
            or _same(line, f"{loop.target.id}.rstrip(os.linesep)")
        )
        and _declaration_bindings(nodes, {loop.target.id}) == {loop.target}
        and isinstance(counter, ast.Name)
        and _pipeline_counter(counter.id, nodes, parents)
    )


def _pipeline_counter(name, nodes, parents):
    writes = _declaration_bindings(nodes, {name})
    return bool(writes) and all(
        (
            isinstance(parent := parents[node], ast.Assign)
            and parent.targets == [node]
            and _same(parent.value, "0")
        )
        or (
            isinstance(parent, ast.AugAssign)
            and parent.target is node
            and isinstance(parent.op, ast.Add)
            and _same(parent.value, "1")
        )
        for node in writes
    )


def _program_source_inventory(
    index,
    target,
    registration,
    entry,
    worker,
    module,
    package,
    installations,
    demo,
    class_name,
):
    """Reject other captured importers, provider writes, and interpreter effects."""
    from .finite_capture import _fixed_eval_builtin_provider_risk

    peers = set()
    for path in index.snapshots:
        relative = index.relative(path)
        if relative is None or relative in peers or not index.validate(path):
            return False
        peers.add(relative)
        parts = PurePosixPath(relative).parts
        if parts[0] in {"multiprocessing.py", "multiprocessing", "xonsh.py", "xonsh"}:
            return False
        tree = (
            entry
            if path == registration
            else worker
            if path == target
            else index.snapshots[path]
        )
        if not _program_importers_closed(
            tree,
            relative,
            module,
            package,
            class_name,
            path == registration,
            path == target,
        ):
            return False
        body = tree.body
        if path == registration:
            body = _registration_import_effects(tree, installations)
        elif path == target:
            body = [
                ast.If(
                    test=statement.test,
                    body=[item for item in statement.body if item not in demo],
                    orelse=[],
                )
                if isinstance(statement, ast.If)
                and any(item in demo for item in statement.body)
                else statement
                for statement in body
            ]
        projected = ast.Module(body=body, type_ignores=[])
        if _opaque_program_access(projected) or _fixed_eval_builtin_provider_risk(
            projected
        ):
            return False
    return True


def _registration_import_effects(tree, installations):
    """Project inert callable references while retaining their definitions."""
    local_functions = {
        statement.name
        for statement in tree.body
        if isinstance(statement, ast.FunctionDef) and not statement.decorator_list
    }
    body = []
    for statement in tree.body:
        if statement in installations:
            if isinstance(statement.value, ast.Lambda):
                body.append(ast.Expr(value=statement.value))
            continue
        if (
            isinstance(statement, ast.Assign)
            and isinstance(table := statement.value, ast.Dict)
            and all(isinstance(key, ast.Constant) for key in table.keys)
        ):
            values = [
                ast.Constant(None)
                if isinstance(value, ast.Name) and value.id in local_functions
                else value
                for value in table.values
            ]
            statement = ast.Assign(
                targets=statement.targets,
                value=ast.Dict(keys=table.keys, values=values),
            )
        body.append(statement)
    return body


def _program_importers_closed(
    tree, relative, module, package, class_name, is_registration, is_worker
):
    nodes = list(ast.walk(tree))
    if not _program_namespace_reads_closed(nodes, is_registration, is_worker):
        return False
    for item in nodes:
        if isinstance(item, ast.Import) and any(
            _restricted_import(alias.name, package) for alias in item.names
        ):
            return False
        if isinstance(item, ast.ImportFrom):
            if any(alias.name == "*" for alias in item.names):
                return False
            prefix = _absolute_import_prefix(item, relative)
            if _restricted_import(prefix, package) and not _permitted_program_import(
                tree, item, prefix, module, class_name, is_registration, is_worker
            ):
                return False
    return True


def _permitted_program_import(
    tree, item, prefix, module, class_name, is_registration, is_worker
):
    if prefix == module and is_registration:
        return (
            item.level == 0
            and item in tree.body
            and all(alias.name == class_name for alias in item.names)
        )
    if prefix == "multiprocessing" and is_worker:
        return all(alias.name in {"Pool", "cpu_count"} for alias in item.names)
    return (is_registration or is_worker) and _safe_xonsh_print_import(
        tree, item, prefix
    )


def _program_namespace_reads_closed(nodes, is_registration, is_worker):
    return all(
        (
            not _ambient_alias_access(item)
            or is_registration
            and isinstance(item, ast.Name)
        )
        and (
            not _host_namespace_access(item)
            or isinstance(item, ast.Name)
            and (is_registration or is_worker)
        )
        for item in nodes
    )


def _restricted_import(prefix, package):
    return prefix in {
        package,
        "xontrib",
        "xonsh",
        "multiprocessing",
        "importlib",
        "builtins",
    } or prefix.startswith(("xontrib.", "xonsh.", "multiprocessing.", "importlib."))


def _safe_xonsh_print_import(tree, item, prefix):
    return (
        not item.level
        and item in tree.body
        and prefix == "xonsh.tools"
        and len(item.names) == 1
        and item.names[0].name == "print_color"
        and item.names[0].asname is None
        and _reporter_call_only(tree, item.names[0])
    )


def _reporter_call_only(tree, imported):
    nodes = list(ast.walk(tree))
    return _declaration_bindings(nodes, {"print_color"}) == {
        imported
    } and _neighbor_function_use_closed(nodes, _parents(tree), "print_color")


def _absolute_import_prefix(item, relative):
    if not item.level:
        return item.module or ""
    directories = PurePosixPath(relative).parts[:-1]
    base = directories[: max(0, len(directories) - item.level + 1)]
    return ".".join((*base, *filter(None, (item.module,))))


def _opaque_program_access(tree):
    return any(
        isinstance(item, ast.Name)
        and item.id in {"__import__", "globals", "locals", "vars"}
        or isinstance(item, ast.Attribute)
        and item.attr in {"import_module", "modules"}
        for item in ast.walk(tree)
    )


def _ambient_alias_access(item):
    """Keep unmodeled host registrations and callable dispatch in raw review."""
    return (
        isinstance(item, ast.Name)
        and item.id == "aliases"
        or isinstance(item, ast.Attribute)
        and item.attr == "aliases"
        or isinstance(item, ast.alias)
        and (item.asname or item.name) == "aliases"
    )


def _host_namespace_access(item):
    return (
        isinstance(item, ast.Name)
        and item.id == "__xonsh__"
        or isinstance(item, ast.Attribute)
        and item.attr == "__xonsh__"
        or isinstance(item, ast.alias)
        and (item.asname or item.name) == "__xonsh__"
    )


_XONSH_HELPER_NAMES = tuple(
    name
    for name, function in globals().items()
    if getattr(function, "__module__", None) == __name__
)
