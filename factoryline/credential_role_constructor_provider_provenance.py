"""Exact class-field aliases and source-proven constructor consumers."""

import ast
from types import SimpleNamespace

from .credential_role_identity_effects import summarize_identity_effect
from .credential_role_scope_bindings import binding_occurrences
from .provider_mutations import finite_provider_mutation_index
from .review_audits import _resolved_ast_name
from .review_integrity import bind_source_call


def class_binding(owner, name, parents):
    """Resolve a unique direct class binding to its name or attribute expression; return None when absent and false when ambiguous."""
    bindings = binding_occurrences(owner.body, name)
    if not bindings:
        return None
    if len(bindings) != 1:
        return False
    target = bindings[0]
    statement = parents.get(id(target))
    if parents.get(id(statement)) is not owner:
        return False
    targets = getattr(statement, "targets", [getattr(statement, "target", None)])
    if (
        len(targets) != 1
        or targets[0] is not target
        or not isinstance(getattr(statement, "value", None), (ast.Name, ast.Attribute))
    ):
        return False
    return statement.value


def init_override(owner, parents):
    """Report whether a class defines exactly one direct __init__ method, distinguishing absence from an unsafe override."""
    bindings = binding_occurrences(owner.body, "__init__")
    if not bindings:
        return None
    return (
        len(bindings) == 1
        and isinstance(bindings[0], (ast.FunctionDef, ast.AsyncFunctionDef))
        and parents.get(id(bindings[0])) is owner
    )


def capture_holder_instances(
    tree, parents, aliases, owners, roots, path, filtered, field_aliases, resolve
):
    """Track holder instances and class aliases into provider roots; stop when a holder escapes or its selector use is ambiguous."""
    for node, target in _single_name_assignments(tree):
        name, parent = target.id, parents.get(id(node))
        value = node.value
        if name != "client_class" and isinstance(value, (ast.Name, ast.Attribute)):
            holder = resolve(value, aliases)
            if holder in owners:
                if not _capture_class_alias(
                    tree, parent, name, holder, aliases, field_aliases, resolve
                ):
                    return False
                filtered.setdefault(path, set()).add(id(node))
            continue
        if not isinstance(value, ast.Call):
            continue
        holder = resolve(value.func, aliases)
        if holder not in owners:
            continue
        if not isinstance(parent, ast.Module):
            if not _local_holder_unused_selector(parent, parents, name):
                return False
            continue
        if len(binding_occurrences(tree.body, name)) != 1:
            return False
        aliases[name] = holder
        roots.add(holder + ".client_class")
    return True


def _single_name_assignments(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) == 1 and isinstance(targets[0], ast.Name):
                yield node, targets[0]


def _local_holder_unused_selector(parent, parents, name):
    scope = parent
    while scope is not None and not isinstance(
        scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    ):
        scope = parents.get(id(scope))
    return isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and not any(
        isinstance(item, ast.Attribute)
        and item.attr == "client_class"
        and isinstance(item.value, ast.Name)
        and item.value.id == name
        for item in ast.walk(scope)
    )


def _capture_class_alias(tree, parent, name, holder, aliases, fields, resolve):
    scope = parent if parent is tree or isinstance(parent, ast.ClassDef) else None
    if scope is None or len(binding_occurrences(scope.body, name)) != 1:
        return False
    if scope is tree:
        aliases[name] = holder
    else:
        class_path = resolve(ast.Name(scope.name, ast.Load()), aliases)
        if not class_path.startswith("captured_"):
            return False
        fields[class_path + "." + name] = holder
    return True


def instance_selector_edges(tree, aliases, owners, roots, path, filtered, resolve):
    """Record unique captured client_class assignments and extend the provider roots and owner set."""
    selected = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Attribute):
            continue
        target = targets[0]
        owner = resolve(target.value, aliases)
        if (
            target.attr == "client_class"
            and owner.startswith("captured_")
            and resolve(node.value, aliases) in roots
        ):
            selected.append((node, owner))
    for node, owner in selected:
        if sum(item == owner for _, item in selected) != 1:
            return False
        owners.add(owner)
        roots.add(owner + ".client_class")
        filtered.setdefault(path, set()).add(id(node))
    return True


def field_alias_path(provider, aliases):
    """Rewrite a provider path through the longest matching captured field alias, preserving unmatched paths."""
    return next(
        (
            owner + provider[len(alias) :]
            for alias, owner in aliases.items()
            if provider == alias or provider.startswith(alias + ".")
        ),
        provider,
    )


def owner_path(node, aliases, fields):
    """Resolve a node's canonical provider name through imports and captured field aliases."""
    return field_alias_path(_resolved_ast_name(node, aliases), fields)


def class_index(index, aliases_by_path):
    """Index top-level classes by resolved name across validated snapshots, omitting names that cannot be resolved."""
    rows = {}
    for path, tree in index.snapshots.items():
        aliases = aliases_by_path[path]
        for owner in tree.body:
            if isinstance(owner, ast.ClassDef):
                rows[aliases.get(owner.name)] = (path, owner, aliases, tree)
    return {name: row for name, row in rows.items() if name}


def constructor_provider_provenance_epoch():
    """Return the functions and binding helpers used to invalidate constructor-provider provenance caches."""
    return (
        class_binding,
        init_override,
        capture_holder_instances,
        _capture_class_alias,
        _local_holder_unused_selector,
        _single_name_assignments,
        instance_selector_edges,
        field_alias_path,
        owner_path,
        class_index,
        source_owner_consumer,
        _captured_method,
        _classmethod,
        _is_call_argument,
        _consumer_effect_safe,
        _is_safe_isinstance_value,
        binding_occurrences,
        summarize_identity_effect,
        bind_source_call,
        _resolved_ast_name,
    )


def source_owner_consumer(
    node,
    path,
    tree,
    parents,
    index,
    aliases,
    classes,
    owners,
    builtin_stable,
    aliases_by_path=None,
):
    """Return a consumer method name only when the captured owner call maps to a safe class method and ordinary type operand."""
    call = parents.get(id(node))
    if (
        _resolved_ast_name(node, aliases) not in owners
        or not _is_call_argument(node, call)
        or not isinstance(call.func, ast.Attribute)
    ):
        return None
    receiver = call.func.value
    row = _captured_method(
        _resolved_ast_name(receiver, aliases), call.func.attr, classes, set()
    )
    if row is None:
        return None
    method_owner_path, method_path, owner, method = row
    if not _classmethod(method, owner, classes, builtin_stable):
        return None
    try:
        bound = bind_source_call(call, method, receiver=receiver, apply_defaults=False)
    except (TypeError, ValueError):
        return None
    formals = [name for name, value in bound.items() if value is node]
    if len(formals) != 1 or not _consumer_effect_safe(
        method,
        method_path,
        index,
        formals[0],
        builtin_stable,
        (classes, classes[method_owner_path][2], owners, aliases_by_path),
    ):
        return None
    if aliases_by_path is None or not ordinary_type_operand(
        node, tree, parents, index, classes, aliases, owners, aliases_by_path
    ):
        return None
    return method_owner_path + "." + method.name


def _captured_method(path, name, classes, seen):
    if path in seen:
        return None
    row = classes.get(path)
    if row is None:
        return None
    file_path, owner, aliases, _ = row
    definitions = binding_occurrences(owner.body, name)
    if definitions:
        if (
            len(definitions) == 1
            and isinstance(definitions[0], ast.FunctionDef)
            and definitions[0] in owner.body
        ):
            return path, file_path, owner, definitions[0]
        return None
    if len(owner.bases) == 1:
        return _captured_method(
            _resolved_ast_name(owner.bases[0], aliases), name, classes, seen | {path}
        )
    if owner.bases:
        first_path = _resolved_ast_name(owner.bases[0], aliases)
        first = classes.get(first_path)
        if first is not None:
            base = binding_occurrences(first[1].body, name)
            if (
                len(base) == 1
                and isinstance(base[0], ast.FunctionDef)
                and base[0] in first[1].body
            ):
                return first_path, first[0], first[1], base[0]
    return None


def _classmethod(method, owner, classes, builtin_stable):
    row = next((entry for entry in classes.values() if entry[1] is owner), None)
    return bool(
        row
        and builtin_stable
        and len(method.decorator_list) == 1
        and isinstance(method.decorator_list[0], ast.Name)
        and method.decorator_list[0].id == "classmethod"
        and not binding_occurrences(row[3].body, "classmethod")
        and binding_occurrences(owner.body, method.name) == [method]
    )


def _is_call_argument(node, call):
    return bool(
        isinstance(call, ast.Call)
        and (
            any(value is node for value in call.args)
            or any(k.value is node for k in call.keywords)
        )
    )


def _consumer_effect_safe(method, path, index, parameter, builtin_stable, types=None):
    nested = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
    if any(
        node is not method and isinstance(node, nested) for node in ast.walk(method)
    ):
        return False
    tree, parents = index.snapshots[path], index.parents[path]

    def ordinary_type(operand):
        if types is None:
            return False
        classes, aliases, owners, aliases_by_path = types
        if aliases_by_path is None:
            return False
        return ordinary_type_operand(
            operand, tree, parents, index, classes, aliases, owners, aliases_by_path
        )

    uses = [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Name)
        and node.id == parameter
        and isinstance(node.ctx, ast.Load)
    ]
    if not all(
        _is_safe_isinstance_value(node, tree, parents, builtin_stable, ordinary_type)
        for node in uses
    ):
        return False
    effects = summarize_identity_effect(method, path, index, {parameter: "owner"})
    allowed_unknowns = {
        "implicit special-method dispatch on tracked root",
        "return/yield contains unresolved tracked value",
    }
    return bool(
        not effects.class_writes
        and set(effects.escapes) <= {"owner"}
        and set(effects.unknowns) <= allowed_unknowns
    )


def _is_safe_isinstance_value(node, tree, parents, builtin_stable, ordinary_type=None):
    call = parents.get(id(node))
    if not (
        builtin_stable
        and isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "isinstance"
        and len(call.args) == 2
        and call.args[0] is node
        and not call.keywords
        and not binding_occurrences(tree.body, "isinstance")
        and ordinary_type is not None
        and ordinary_type(call.args[1])
    ):
        return False
    scope = parents.get(id(call))
    while scope is not None:
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
            if any(arg.arg == "isinstance" for arg in params) or binding_occurrences(
                scope.body, "isinstance"
            ):
                return False
        elif isinstance(scope, ast.ClassDef) and binding_occurrences(
            scope.body, "isinstance"
        ):
            return False
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
            isinstance(item, (ast.Global, ast.Nonlocal)) and "isinstance" in item.names
            for item in ast.walk(scope)
        ):
            return False
        scope = parents.get(id(scope))
    return True


def ordinary_type_operand(
    node, tree, parents, index, classes, aliases, owners, aliases_by_path
):
    """Confirm that a name or attribute denotes a stable ordinary class whose type metadata is not provider-controlled."""
    if not isinstance(node, (ast.Name, ast.Attribute)):
        return False
    root = node
    while isinstance(root, ast.Attribute):
        root = root.value
    if not isinstance(root, ast.Name) or not _lexical_binding_stable(root, parents):
        return False
    canonical = _resolved_ast_name(node, aliases)
    return _ordinary_class(canonical, classes, set()) and _type_metadata_stable(
        canonical, index, owners, aliases_by_path
    )


def _lexical_binding_stable(node, parents):
    scope = parents.get(id(node))
    while scope is not None:
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
            args.extend(arg for arg in (scope.args.vararg, scope.args.kwarg) if arg)
            if any(arg.arg == node.id for arg in args):
                return False
            body = scope.body if isinstance(scope.body, list) else [scope.body]
            if binding_occurrences(body, node.id):
                return False
        scope = parents.get(id(scope))
    return True


def _ordinary_class(canonical, classes, seen):
    row = classes.get(canonical)
    if row is None or canonical in seen:
        return False
    _, owner, aliases, tree = row
    if owner.keywords or owner.decorator_list:
        return False
    for base in owner.bases:
        if isinstance(base, ast.Name) and base.id == "object":
            if binding_occurrences(tree.body, "object"):
                return False
        elif not _ordinary_class(
            _resolved_ast_name(base, aliases), classes, seen | {canonical}
        ):
            return False
    return True


def _type_metadata_stable(canonical, index, owners, aliases_by_path):
    audit = SimpleNamespace(_resolved_ast_name=_resolved_ast_name)
    for path, tree in index.snapshots.items():
        aliases = aliases_by_path.get(path)
        if aliases is None or not index.validate(path):
            return False
        parents = index.parents[path]
        nodes = [
            item
            for item in ast.walk(tree)
            if not _exact_type_argument(item, parents, tree)
        ]
        if canonical not in owners and any(
            isinstance(item, (ast.Name, ast.Attribute))
            and _resolved_ast_name(item, aliases) == canonical
            for item in nodes
        ):
            return False
        facts = finite_provider_mutation_index(nodes, aliases, audit, parents)
        if any(
            _metadata_overlap(provider, attr, canonical, owners)
            for provider, attr in facts
        ):
            return False
    return True


def _exact_type_argument(node, parents, tree):
    call = parents.get(id(node))
    return bool(
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "isinstance"
        and len(call.args) == 2
        and call.args[1] is node
        and not call.keywords
        and not binding_occurrences(tree.body, "isinstance")
        and _lexical_binding_stable(call.func, parents)
    )


def _metadata_overlap(provider, attribute, canonical, owners):
    if attribute == "*":
        return provider == canonical and canonical not in owners
    path = provider + "." + attribute
    return any(
        path == canonical + "." + name or path.startswith(canonical + "." + name + ".")
        for name in ("__bases__", "__class__", "__instancecheck__")
    )
