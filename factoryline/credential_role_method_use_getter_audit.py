"""Bounded getter and reflective-use closure over validated source snapshots."""

import ast

from .credential_role_bindings import class_chain
from .credential_role_scope_bindings import instance_receiver
from .credential_role_forwarding_decorator import method_rows
from .credential_role_method_contracts import verified_instance_receiver
from .credential_role_method_use_audit import (
    ancestor,
    coordinates,
    coordinates as _node_coordinates,
    span_key,
)
from .credential_role_scope_bindings import binding_occurrences


def audit_getter_uses(
    traces, nodes, index, unknown, *, context=None, related_owners=None
):
    witnessed, names, owners, fields = _trace_context(
        traces, nodes, index, related_owners
    )
    if not names:
        return
    if not owners:
        unknown.append({"reason": "getter_candidate_class_unresolved"})
        return
    imports, classes, audit = context if context else ({}, {}, None)
    snapshots = snapshot_candidates(index)
    if len(snapshots) != len(index.snapshots):
        unknown.append({"reason": "getter_snapshot_validation_incomplete"})
    for path, tree, candidates in snapshots:
        _audit_snapshot(
            path,
            tree,
            candidates,
            names,
            fields,
            witnessed,
            owners,
            index,
            context,
            related_owners,
            imports,
            classes,
            audit,
            unknown,
        )


def _trace_context(traces, nodes, index, related):
    witnessed, names, owners = set(), set(), owner_keys(index, related)
    fields = candidate_getter_fields(traces, nodes, index)
    paths = {index.relative(path): path for path in index.snapshots}
    for trace in traces:
        for row in trace:
            if row.get("role") == "declared_literal":
                literal = nodes.get(span_key(row))
                path = paths.get(row["path"])
                owner = class_identity(literal, index, path) if path else None
                if owner and not owners:
                    owners.add(owner)
            if row.get("role") == "method_call":
                call = nodes.get(span_key(row))
                if _self_call(call):
                    witnessed.add((row["path"], coordinates(call)))
                    names.add(call.func.attr)
    return witnessed, names, owners, fields


def _audit_snapshot(
    path,
    tree,
    candidates,
    names,
    fields,
    witnessed,
    owners,
    index,
    context,
    related,
    imports,
    classes,
    audit,
    unknown,
):
    relative = index.relative(path)
    aliases = audit._module_security_aliases(tree) if audit else {}
    calls = [node for node in candidates if isinstance(node, ast.Call)]
    for node in candidates:
        if isinstance(node, ast.Attribute) and node.attr in names:
            if audit and _consumer_role(node, index, path, audit):
                continue
            _audit_attribute(
                node,
                path,
                relative,
                calls,
                witnessed,
                owners,
                fields,
                index,
                context,
                related,
                imports,
                classes,
                audit,
                unknown,
            )
        elif isinstance(node, ast.Call) and _reflective_getter(node, names, aliases):
            audit_reflective(
                node,
                path,
                relative,
                calls,
                owners,
                names,
                fields,
                index,
                context,
                related,
                imports,
                classes,
                audit,
                aliases,
                unknown,
                _related_receiver,
            )


def _consumer_role(node, index, path, audit):
    from .credential_role_getter_consumers import getter_consumer_role

    memo = getattr(index, "class_chain_memo", None)
    if memo is not None:
        return memo.getter_role(node, path, audit, getter_consumer_role)
    return getter_consumer_role(node, index, path, audit) is not None


def _audit_attribute(
    node,
    path,
    relative,
    calls,
    witnessed,
    owners,
    fields,
    index,
    context,
    related,
    imports,
    classes,
    audit,
    unknown,
):
    parent = index.parents[path].get(id(node))
    lexical = class_identity(node, index, path)
    stable = _stable_self(node.value, index, path, context)
    unrelated = stable and different_field_origin(
        lexical, node.attr, fields, index, imports, classes, audit
    )
    relation = _related_receiver(
        stable and lexical in owners and not unrelated,
        node.value,
        path,
        calls,
        node.attr,
        fields,
        index,
        context,
        related,
        imports,
        classes,
    )
    linked = relation == "LINKED"
    unrelated = unrelated or relation == "UNRELATED"
    if not linked and not unrelated:
        unknown.append(_unknown("getter_receiver_relation_unresolved", relative, node))
    elif linked and not _witnessed_call(parent, node, relative, witnessed):
        reason = "unrepresented_getter_reference"
        if isinstance(parent, ast.Call) and parent.func is node:
            reason = "unwitnessed_sibling_getter_call"
        unknown.append(_unknown(reason, relative, node))


def _related_receiver(
    linked,
    receiver,
    path,
    calls,
    getter,
    fields,
    index,
    context,
    related,
    imports,
    classes,
):
    if linked:
        return "LINKED"
    if not context:
        return "UNKNOWN"
    if isinstance(receiver, ast.Name):
        # An exact unrelated receiver must not be widened by ancestor overlap.
        # UNKNOWN still falls through to the conservative origin/parameter links.
        relation = exact_local_receiver_relation(
            path,
            receiver,
            getter,
            index,
            imports,
            classes,
            context[2],
            related or set(),
            fields,
        )
        if relation != "UNKNOWN":
            return relation
    from .credential_role_scope_bindings import declared_origins

    origins = declared_origins(path, receiver, index, imports, classes)
    if origins & (related or set()):
        return "LINKED"
    if isinstance(receiver, ast.Name):
        if parameter_linked(
            path, receiver, calls, index, imports, classes, related or set()
        ):
            return "LINKED"
    return "UNKNOWN"


def _witnessed_call(parent, node, relative, witnessed):
    return bool(
        isinstance(parent, ast.Call)
        and parent.func is node
        and (relative, coordinates(parent)) in witnessed
    )


def parameter_linked(path, receiver, calls, index, imports, classes, owners):
    function = ancestor(
        receiver, index, index.relative(path), (ast.FunctionDef, ast.AsyncFunctionDef)
    )
    if function is None:
        return False
    _, possible_parameters = _parameter_alias(function, receiver.id)
    if not possible_parameters:
        return False
    for call in calls:
        if not _targets_function(call, function, path, index):
            continue
        from .review_integrity import bind_source_call

        try:
            actuals = bind_source_call(call, function, apply_defaults=False)
        except (TypeError, ValueError):
            continue
        from .credential_role_scope_bindings import declared_origins

        for name in possible_parameters:
            actual = actuals.get(name)
            if actual is None:
                continue
            if declared_origins(path, actual, index, imports, classes) & owners or (
                isinstance(actual, ast.Name)
                and _related_method_self(call, actual, index, path, owners)
            ):
                return True
    return False


def _related_method_self(call, actual, index, path, owners):
    relative = index.relative(path)
    owner = class_identity(call, index, path)
    if owner is None or (index.root / owner[0], owner[1]) not in owners:
        return False
    caller = ancestor(call, index, relative, (ast.FunctionDef, ast.AsyncFunctionDef))
    if caller is None or class_identity(caller, index, path) != owner:
        return False
    positional = [*caller.args.posonlyargs, *caller.args.args]
    return bool(
        positional
        and positional[0].arg == actual.id
        and not binding_occurrences(caller.body, actual.id)
    )


def _parameter_alias(function, name):
    parameters = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    parameter_names = {item.arg for item in parameters}
    exact, seen = name, set()
    for _ in range(5):
        if exact in parameter_names:
            return exact, {exact}
        if exact in seen:
            break
        seen.add(exact)
        bindings = binding_occurrences(function.body, exact)
        assignment = _assignment_for_bindings(function, bindings)
        if len(bindings) != 1 or assignment is None:
            break
        if not isinstance(assignment.value, ast.Name):
            break
        exact = assignment.value.id
    return None, _possible_formals(function, name, parameter_names)


def _possible_formals(function, name, parameters):
    found, pending, seen = set(), [name], set()
    while pending and len(seen) < 5:
        current = pending.pop()
        if current in parameters:
            found.add(current)
            continue
        if current in seen:
            continue
        seen.add(current)
        bindings = binding_occurrences(function.body, current)
        for assignment in _assignments_for_bindings(function, bindings):
            if assignment.value is None:
                continue
            pending.extend(
                node.id
                for node in ast.walk(assignment.value)
                if isinstance(node, ast.Name)
            )
    return found


def _assignments_for_bindings(function, bindings):
    return [
        node
        for node in ast.walk(function)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and any(
            target in bindings
            for target in (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            )
        )
    ]


def _assignment_for_bindings(function, bindings):
    assignments = _assignments_for_bindings(function, bindings)
    return assignments[0] if len(assignments) == 1 else None


def _targets_function(call, function, path, index):
    if not isinstance(call.func, ast.Name):
        return False
    if call.func.id == function.name:
        return True
    tree = index.snapshots[path]
    caller = ancestor(
        call, index, index.relative(path), (ast.FunctionDef, ast.AsyncFunctionDef)
    )
    scopes = [caller.body] if caller else []
    scopes.append(tree.body)
    for statements in scopes:
        aliases, targets = _scope_aliases(statements)
        alias, seen = call.func.id, set()
        while alias in aliases and alias not in seen:
            seen.add(alias)
            binding = targets.get(alias)
            if binding is None or binding_occurrences(statements, alias) != [binding]:
                break
            alias = aliases[alias]
        if alias == function.name:
            return True
    return False


def _scope_aliases(statements):
    aliases, targets = {}, {}
    for node in statements:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        values = node.targets if isinstance(node, ast.Assign) else [node.target]
        if len(values) == 1 and isinstance(values[0], ast.Name):
            targets[values[0].id] = values[0]
            if isinstance(node.value, ast.Name):
                aliases[values[0].id] = node.value.id
    return aliases, targets


def class_identity(node, index, path):
    owner = node
    while owner is not None:
        if isinstance(owner, ast.ClassDef):
            return (index.relative(path), owner.name)
        owner = index.parents[path].get(id(owner))
    return None


def _reflective_getter(call, getter_names, aliases):
    from .security_configuration import _canonical

    name = _canonical(call, aliases)
    if name in {"builtins.getattr", "getattr"} and len(call.args) >= 2:
        return (
            isinstance(call.args[1], ast.Constant)
            and call.args[1].value in getter_names
        )
    return bool(
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "__getattribute__"
        and call.args
        and isinstance(call.args[0], ast.Constant)
        and call.args[0].value in getter_names
    )


def _reflective_receiver(call):
    if isinstance(call.func, ast.Attribute) and call.func.attr == "__getattribute__":
        return call.func.value
    return call.args[0] if call.args else None


def _getter_name(call, getter_names, aliases):
    if not _reflective_getter(call, getter_names, aliases):
        return None
    position = (
        0
        if isinstance(call.func, ast.Attribute) and call.func.attr == "__getattribute__"
        else 1
    )
    return call.args[position].value


def _self_call(node):
    return bool(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "self"
    )


def _stable_self(node, index, path, context=None):
    if not isinstance(node, ast.Name) or node.id != "self":
        return False
    function = ancestor(
        node, index, index.relative(path), (ast.FunctionDef, ast.AsyncFunctionDef)
    )
    owner = ancestor(node, index, index.relative(path), (ast.ClassDef,))
    if function is None or owner is None:
        return False
    if not function.decorator_list:
        return instance_receiver(node, function, owner, index, path)
    if context is None:
        return False
    imports, classes, audit = context
    chain = class_chain(
        index, index.root / index.relative(path), owner.name, imports, classes, audit
    )
    if not chain:
        return False
    methods, proofs = method_rows(chain, index, imports)
    row = methods.get(function.name)
    return bool(
        row
        and row[0] == path
        and row[1] is function
        and row[2] is owner
        and verified_instance_receiver(
            node, function, owner, index, path, bool(proofs.get(function.name))
        )
    )


def audit_reflective(
    node,
    path,
    relative,
    calls,
    owners,
    names,
    fields,
    index,
    context,
    related,
    imports,
    classes,
    audit,
    aliases,
    unknown,
    link_receiver,
):
    receiver = _reflective_receiver(node)
    lexical = class_identity(node, index, path)
    stable = _stable_self(receiver, index, path, context)
    getter = _getter_name(node, names, aliases)
    unrelated = stable and different_field_origin(
        lexical, getter, fields, index, imports, classes, audit
    )
    relation = link_receiver(
        stable and lexical in owners and not unrelated,
        receiver,
        path,
        calls,
        getter,
        fields,
        index,
        context,
        related,
        imports,
        classes,
    )
    linked = relation == "LINKED"
    unrelated = unrelated or relation == "UNRELATED"
    if not linked and not unrelated:
        unknown.append(
            _unknown("reflective_getter_receiver_unresolved", relative, node)
        )
    elif linked:
        unknown.append(_unknown("reflective_getter_use", relative, node))


def _unknown(reason, relative, node):
    return {
        "reason": reason,
        "path": relative,
        "line": node.lineno,
        "column": node.col_offset,
    }


def owner_keys(index, owners):
    return {(index.relative(path), name) for path, name in owners or ()}


def candidate_getter_fields(traces, nodes, index):
    result = {}
    for trace in traces:
        members = []
        for position, row in enumerate(trace):
            if row.get("role") != "declared_member_read":
                continue
            member = nodes.get(span_key(row))
            literal_row = next(
                (
                    item
                    for item in reversed(trace[:position])
                    if item.get("role") == "declared_literal"
                ),
                None,
            )
            literal = nodes.get(span_key(literal_row)) if literal_row else None
            identity = _literal_field_identity(literal, member, literal_row)
            if identity:
                members.append((member.attr, identity))
        for row in trace:
            if row.get("role") != "method_call":
                continue
            call = nodes.get(span_key(row))
            if _self_call(call):
                result.setdefault(call.func.attr, set()).update(members)
    return result


def different_field_origin(
    owner, getter, getter_fields, index, imports, classes, audit
):
    fields = getter_fields.get(getter, ())
    if owner is None or not fields or audit is None:
        return False
    from .credential_role_bindings import class_chain
    from .credential_role_field_origin import resolve_declared_field_origin

    chain = class_chain(index, index.root / owner[0], owner[1], imports, classes, audit)
    if not chain:
        return False
    for member, candidate in fields:
        if _candidate_ancestor(owner, candidate, index, imports, classes, audit):
            return False
        resolved = resolve_declared_field_origin(chain, member, index)
        if resolved.get("state") != "EXACT":
            return False
        origin = resolved["origin"]
        identity = origin["path"], tuple(origin["span"]), origin["source_sha256"]
        if identity == candidate:
            return False
    return True


def exact_local_receiver_relation(
    path, receiver, getter, index, imports, classes, audit, related_owners, fields
):
    """Classify a receiver with the witnessed getter and exact field origins."""
    candidates = fields.get(getter, ())
    if not candidates:
        return "UNKNOWN"
    from .credential_role_receiver_class import exact_receiver_class

    class_ref = exact_receiver_class(path, receiver, index, imports, classes, audit)
    if class_ref is None:
        return "UNKNOWN"
    from .credential_role_bindings import class_chain

    chain = class_chain(index, class_ref[0], class_ref[1], imports, classes, audit)
    if not chain:
        return "UNKNOWN"
    from .credential_role_receiver_lifetime import local_receiver_stable

    if not local_receiver_stable(path, receiver, getter, chain, index):
        return "UNKNOWN"
    candidate_methods = _candidate_getter_methods(
        candidates, getter, index, imports, classes, audit
    )
    if candidate_methods is None:
        return "UNKNOWN"
    if len(candidate_methods) != 1:
        return "UNKNOWN"
    from .credential_role_scope_bindings import effective_method

    candidate_identity = next(iter(candidate_methods))
    effective = effective_method(chain, getter)
    if not effective or _method_identity(effective, index) != candidate_identity:
        return "UNKNOWN"

    return _receiver_field_relation(candidates, chain, index)


def _candidate_getter_methods(candidates, getter, index, imports, classes, audit):
    from .credential_role_bindings import class_chain
    from .credential_role_scope_bindings import effective_method

    methods = set()
    for _, candidate in candidates:
        candidate_class = _candidate_class(candidate, index)
        if candidate_class is None:
            return None
        chain = class_chain(
            index, candidate_class[0], candidate_class[1], imports, classes, audit
        )
        row = effective_method(chain, getter) if chain else None
        if row is None:
            return None
        methods.add(_method_identity(row, index))
    return methods


def _receiver_field_relation(candidates, chain, index):
    from .credential_role_field_origin import resolve_declared_field_origin

    matches = []
    for member, candidate in candidates:
        resolved = resolve_declared_field_origin(chain, member, index)
        if resolved.get("state") != "EXACT":
            return "UNKNOWN"
        origin = resolved["origin"]
        identity = origin["path"], tuple(origin["span"]), origin["source_sha256"]
        matches.append(identity == candidate)
    if all(matches):
        return "LINKED"
    if not any(matches):
        return "UNRELATED"
    return "UNKNOWN"


def _candidate_class(candidate, index):
    relative, coordinates, digest = candidate
    paths = [path for path in index.snapshots if index.relative(path) == relative]
    if len(paths) != 1 or not index.validate(paths[0]):
        return None
    path = paths[0]
    declarations = [
        node
        for node in ast.walk(index.snapshots[path])
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and _node_coordinates(node) == tuple(coordinates)
        and index.inventory[path] == digest
    ]
    if len(declarations) != 1:
        return None
    owner = class_identity(declarations[0], index, path)
    return (path, owner[1]) if owner else None


def _method_identity(row, index):
    path, method = row
    return index.relative(path), _node_coordinates(method), index.inventory[path]


def _candidate_ancestor(owner, candidate, index, imports, classes, audit):
    from .credential_role_bindings import class_chain

    path = index.root / candidate[0]
    if not index.validate(path):
        return True
    declarations = [
        node
        for node in ast.walk(index.snapshots[path])
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and _node_coordinates(node) == tuple(candidate[1])
    ]
    if len(declarations) != 1:
        return True
    enclosing = index.parents[path].get(id(declarations[0]))
    if not isinstance(enclosing, ast.ClassDef):
        return True
    chain = class_chain(index, path, enclosing.name, imports, classes, audit)
    return not chain or any((index.relative(p), name) == owner for p, name, _ in chain)


def _literal_field_identity(literal, member, row):
    if not isinstance(member, ast.Attribute) or row is None:
        return None
    if not isinstance(literal, (ast.Assign, ast.AnnAssign)):
        return None
    targets = literal.targets if isinstance(literal, ast.Assign) else [literal.target]
    value = literal.value
    if not any(
        isinstance(target, ast.Name) and target.id == member.attr for target in targets
    ):
        return None
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        return None
    return row["path"], _node_coordinates(literal), row["source_sha256"]


def snapshot_candidates(index):
    signature = tuple(
        (path, index.inventory.get(path), id(tree))
        for path, tree in index.snapshots.items()
    )
    cached = getattr(index, "_credential_method_getter_candidates", None)
    if cached and cached[0] == signature:
        return cached[1]
    rows = []
    for path, tree in index.snapshots.items():
        if not index.validate(path):
            continue
        candidates = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Attribute, ast.Call))
        ]
        rows.append((path, tree, candidates))
    index._credential_method_getter_candidates = (signature, rows)
    return rows
