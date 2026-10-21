"""Check captured constructor and selector providers without executing code."""

import ast
import hashlib
from functools import partial
from types import SimpleNamespace

from . import provider_mutations
from .credential_role_scope_bindings import binding_occurrences
from .credential_role_constructor_provider_provenance import (
    capture_holder_instances,
    class_binding,
    class_index,
    constructor_provider_provenance_epoch,
    field_alias_path,
    init_override,
    instance_selector_edges,
    ordinary_type_operand,
    owner_path,
    source_owner_consumer,
)
from .provider_mutations import finite_provider_mutation_index


def constructor_provider_bindings_inert(chain, index, imports):
    """Reject source-bound constructor/selector mutation, escape, or unknowns."""
    if not chain or not index.bounded:
        return False
    selected = {_source_module(path) + "." + name for path, name, _ in chain}
    model = constructor_provider_model(
        selected, index, imports, _source_aliases, _has_opaque_owner_capture
    )
    if model is None:
        return False
    roots, aliases, filtered, shared, field_aliases, consumers = model
    return _captured_mutations_inert(
        index, roots, aliases, filtered, shared, field_aliases, consumers
    )


def _captured_mutations_inert(
    index, roots, aliases_by_path, filtered, shared, field_aliases, consumers
):
    from .review_audits import _resolved_ast_name

    audit = SimpleNamespace(_resolved_ast_name=_resolved_ast_name)
    for path, tree in index.snapshots.items():
        aliases = aliases_by_path[path]
        ignored = filtered.get(path, set())
        nodes = [node for node in ast.walk(tree) if id(node) not in ignored]
        mutations = finite_provider_mutation_index(
            nodes, aliases, audit, index.parents[path]
        )
        mutations = {
            (field_alias_path(provider, field_aliases), attribute)
            for provider, attribute in mutations
        }
        if any(
            _mutation_overlaps(provider, attribute, consumer)
            for provider, attribute in mutations
            for consumer in consumers
        ):
            return False
        owners = {root[:-13] for root in roots if root.endswith(".client_class")}
        if _owner_method_mutation(
            tree, aliases, owners, roots, audit, index.parents[path]
        ):
            return False
        if any(
            _mutation_overlaps(provider, attribute, root)
            for provider, attribute in mutations
            for root in roots
        ) or any(
            _shared_function_mutation(provider, attribute, item)
            for provider, attribute in mutations
            for item in shared
        ):
            return False
    return True


def _overlaps(provider, root):
    return provider == root or provider.startswith(root + ".")


def _mutation_overlaps(provider, attribute, root):
    return _overlaps(provider if attribute == "*" else provider + "." + attribute, root)


def _shared_function_mutation(provider, attribute, function):
    path = provider if attribute == "*" else provider + "." + attribute
    return path == function and attribute == "*" or path.startswith(function + ".")


def _source_aliases(path, tree, imports, index):
    from .credential_role_chain_memo import _import_binding_is_exact

    module, aliases = _source_module(path), {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            defs = binding_occurrences(tree.body, node.name)
            if len(defs) == 1 and defs[0] is node:
                aliases[node.name] = f"{module}.{node.name}"
    for name, imported in imports.items():
        if _import_binding_is_exact(index, path, name, imported):
            target, symbol = imported
            aliases[name] = _source_module(target) + (f".{symbol}" if symbol else "")
    return aliases


def _source_module(path):
    return "captured_" + hashlib.sha256(str(path).encode()).hexdigest()


def _resolved_name(node, aliases):
    from .review_audits import _resolved_ast_name

    return _resolved_ast_name(node, aliases)


def _owner_method_mutation(tree, aliases, owners, roots, audit, parents):
    for owner in (n for n in tree.body if isinstance(n, ast.ClassDef)):
        owner_class_path = _resolved_name(ast.Name(owner.name, ast.Load()), aliases)
        if owner_class_path not in owners:
            continue
        for method in (
            n
            for n in owner.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            params = [*method.args.posonlyargs, *method.args.args]
            if not params:
                continue
            scoped = dict(aliases, **{params[0].arg: owner_class_path})
            nodes = [
                node
                for node in ast.walk(method)
                if not (
                    isinstance(parents.get(id(node)), ast.Attribute)
                    and parents[id(node)].value is node
                )
            ]
            mutations = finite_provider_mutation_index(nodes, scoped, audit, parents)
            _owner_container_paths(nodes, scoped, audit, parents, mutations)
            if any(
                _mutation_overlaps(p, a, r) or (a == "*" and r.startswith(p + "."))
                for p, a in mutations
                for r in roots
            ):
                return True
    return False


def _owner_container_paths(nodes, aliases, audit, parents, mutations):
    bindings = provider_mutations._provider_alias_bindings(nodes)
    containers = (
        ast.List,
        ast.Tuple,
        ast.Set,
        ast.Dict,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
    )
    for node in nodes:
        if not isinstance(node, containers):
            continue
        for item in ast.walk(node):
            parent = parents.get(id(item))
            if isinstance(parent, ast.Attribute) and parent.value is item:
                continue
            if isinstance(item, (ast.Name, ast.Attribute)):
                provider_mutations._record_provider_paths(
                    item, "*", aliases, audit, bindings, mutations
                )


def constructor_provider_helper_epoch():
    """Return semantic helper identities for batch-cache freshness checks."""
    from .credential_role_chain_memo import _import_binding_is_exact
    from .provider_mutations import _provider_call_argument
    from .review_audits import _resolved_ast_name

    model_helpers = constructor_provider_model_helper_epoch()
    return (
        constructor_provider_bindings_inert,
        constructor_provider_model,
        constructor_provider_model_helper_epoch,
        _captured_mutations_inert,
        finite_provider_mutation_index,
        _import_binding_is_exact,
        _resolved_ast_name,
        _overlaps,
        _mutation_overlaps,
        _shared_function_mutation,
        _source_aliases,
        _source_module,
        _has_opaque_owner_capture,
        _owner_call_argument,
        _captured_builtins_mutate_isinstance,
        _owner_reflection_access,
        _contains_owner_escape,
        _safe_isinstance_type,
        _resolved_name,
        _owner_method_mutation,
        _owner_container_paths,
        *constructor_provider_provenance_epoch(),
        _provider_call_argument,
        provider_mutations._record_provider_paths,
        provider_mutations._record_provider_capture,
        provider_mutations._provider_alias_bindings,
        provider_mutations._provider_paths,
        provider_mutations._reflective_provider_write,
        *model_helpers,
    )


def _has_opaque_owner_capture(
    index, aliases_by_path, owners, filtered, field_aliases, consumers
):
    builtin_stable = not _captured_builtins_mutate_isinstance(index)
    classes = class_index(index, aliases_by_path)
    for path, tree in index.snapshots.items():
        aliases, parents = aliases_by_path[path], index.parents[path]
        fields = field_aliases

        ordinary_type = partial(
            ordinary_type_operand,
            tree=tree,
            parents=parents,
            index=index,
            classes=classes,
            aliases=aliases,
            owners=owners,
            aliases_by_path=aliases_by_path,
        )

        for node in ast.walk(tree):
            if id(node) in filtered.get(path, set()):
                continue
            if _owner_reflection_access(node, aliases, owners, fields):
                return True
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                value = node.value
                if (
                    isinstance(value, ast.Call)
                    and not value.args
                    and not value.keywords
                    and owner_path(value.func, aliases, fields) in owners
                ):
                    continue
                if _contains_owner_escape(
                    value,
                    tree,
                    parents,
                    aliases,
                    owners,
                    builtin_stable,
                    fields,
                    ordinary_type,
                ):
                    return True
            returned = _returned_value(node)
            if returned is not None and _contains_owner_escape(
                returned,
                tree,
                parents,
                aliases,
                owners,
                builtin_stable,
                fields,
                ordinary_type,
            ):
                return True
            if isinstance(node, (ast.Name, ast.Attribute)) and _owner_call_argument(
                node,
                path,
                tree,
                parents,
                index,
                aliases,
                classes,
                owners,
                builtin_stable,
                fields,
                consumers,
                ordinary_type,
                aliases_by_path,
            ):
                return True
    return False


def _returned_value(node):
    return (
        node.value if isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)) else None
    )


def _captured_builtins_mutate_isinstance(index):
    return any(
        isinstance(node, ast.Name)
        and node.id == "__builtins__"
        or isinstance(node, ast.Constant)
        and node.value in {"builtins", "__builtins__"}
        or isinstance(node, ast.Import)
        and any(item.name == "builtins" for item in node.names)
        or isinstance(node, ast.ImportFrom)
        and node.module == "builtins"
        or isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"exec", "eval"}
        for tree in index.snapshots.values()
        for node in ast.walk(tree)
    )


def _owner_reflection_access(node, aliases, owners, fields):
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return owner_path(node.value, aliases, fields) in owners
    return bool(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "client_class"
        and owner_path(node.args[0], aliases, fields) in owners
    )


def _owner_call_argument(
    node,
    path,
    tree,
    parents,
    index,
    aliases,
    classes,
    owners,
    builtin_stable,
    fields,
    consumers,
    ordinary_type,
    aliases_by_path,
):
    from .provider_mutations import _provider_call_argument

    if (
        owner_path(node, aliases, fields) not in owners
        or not _provider_call_argument(node, parents)
        or _safe_isinstance_type(node, tree, parents, builtin_stable, ordinary_type)
    ):
        return False
    consumer = source_owner_consumer(
        node,
        path,
        tree,
        parents,
        index,
        aliases,
        classes,
        owners,
        builtin_stable,
        aliases_by_path,
    )
    if consumer is None:
        return True
    consumers.add(consumer)
    return False


def _contains_owner_escape(
    value, tree, parents, aliases, owners, builtin_stable, fields, ordinary_type
):
    return any(
        owner_path(item, aliases, fields) in owners
        and not _safe_isinstance_type(
            item, tree, parents, builtin_stable, ordinary_type
        )
        and getattr(parents.get(id(item)), "func", None) is not item
        for item in ast.walk(value)
        if isinstance(item, (ast.Name, ast.Attribute))
    )


def _safe_isinstance_type(node, tree, parents, builtin_stable, ordinary_type=None):
    call = parents.get(id(node))
    while call is not None and not isinstance(call, ast.Call):
        call = parents.get(id(call))
    if (
        not isinstance(call, ast.Call)
        or not isinstance(call.func, ast.Name)
        or call.func.id != "isinstance"
        or len(call.args) != 2
        or call.args[1] is not node
        or call.keywords
        or not builtin_stable
        or binding_occurrences(tree.body, "isinstance")
        or ordinary_type is None
        or not ordinary_type(call.args[1])
    ):
        return False
    scope = parents.get(id(call))
    while scope is not None:
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
            args.extend(arg for arg in (scope.args.vararg, scope.args.kwarg) if arg)
            if any(arg.arg == "isinstance" for arg in args) or binding_occurrences(
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


def constructor_provider_model(selected, index, imports, source_aliases, capture_guard):
    """Construct the provider model only when every source snapshot and selector, inheritance, alias, and capture guard is complete."""
    from .review_audits import _resolved_ast_name

    roots, owners, shared = set(selected), set(), set()
    filtered, aliases_by_path, field_aliases, consumers = {}, {}, {}, set()
    for path, tree in index.snapshots.items():
        if not index.validate(path):
            return None
        aliases_by_path[path] = source_aliases(path, tree, imports.get(path, {}), index)
    if (
        not _class_selector_edges(
            index, aliases_by_path, roots, owners, filtered, _resolved_ast_name
        )
        or not _class_descendant_edges(
            index, aliases_by_path, selected, owners, roots, shared, _resolved_ast_name
        )
        or not _instance_aliases(
            index,
            aliases_by_path,
            owners,
            roots,
            filtered,
            field_aliases,
            _resolved_ast_name,
        )
        or capture_guard(
            index, aliases_by_path, owners, filtered, field_aliases, consumers
        )
    ):
        return None
    return roots, aliases_by_path, filtered, shared, field_aliases, consumers


def _class_selector_edges(index, aliases_by_path, roots, owners, filtered, resolve):
    for path, tree in index.snapshots.items():
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            owner = index.parents[path].get(id(node))
            if (
                len(targets) != 1
                or not isinstance(targets[0], ast.Name)
                or targets[0].id != "client_class"
                or not isinstance(node.value, (ast.Name, ast.Attribute))
                or not isinstance(owner, ast.ClassDef)
            ):
                continue
            owner = ast.Name(id=owner.name, ctx=ast.Load())
            owner_path = resolve(owner, aliases_by_path[path])
            if resolve(node.value, aliases_by_path[path]) not in roots:
                continue
            if not owner_path.startswith("captured_"):
                return False
            roots.add(owner_path + ".client_class")
            owners.add(owner_path)
            filtered.setdefault(path, set()).add(id(node))
    return True


def _class_descendant_edges(
    index, aliases_by_path, selected, owners, roots, shared, resolve
):
    init_classes = set(selected)
    for _ in range(16):
        changed = False
        for path, tree in index.snapshots.items():
            aliases, parents = aliases_by_path[path], index.parents[path]
            for child in (item for item in tree.body if isinstance(item, ast.ClassDef)):
                result = _descendant_edges_for_class(
                    child,
                    aliases,
                    parents,
                    owners,
                    roots,
                    init_classes,
                    shared,
                    resolve,
                )
                if result is None:
                    return False
                changed |= result
        if not changed:
            return True
    return False


def _descendant_edges_for_class(
    child, aliases, parents, owners, roots, init_classes, shared, resolve
):
    path = resolve(ast.Name(child.name, ast.Load()), aliases)
    bases = [resolve(base, aliases) for base in child.bases]
    selector_parent = any(base in owners for base in bases)
    init_parent = any(base in init_classes for base in bases)
    if not selector_parent and not init_parent:
        return False
    if len(bases) != 1 or not path.startswith("captured_"):
        return None
    changed = False
    if selector_parent and path not in owners:
        field = class_binding(child, "client_class", parents)
        value = (
            resolve(field, aliases) if field is not None and field is not False else ""
        )
        if field is False or (
            field is not None
            and value not in roots
            and not value.startswith("captured_")
        ):
            return None
        if field is None or value in roots:
            owners.add(path)
            roots.add(path + ".client_class")
            changed = True
    if init_parent:
        override = init_override(child, parents)
        if override is False:
            return None
        if override is None and path not in init_classes:
            init_classes.add(path)
            shared.add(path + ".__init__")
            changed = True
    return changed


def _instance_aliases(
    index, aliases_by_path, owners, roots, filtered, field_aliases, resolve
):
    for path, tree in index.snapshots.items():
        aliases = aliases_by_path[path]
        if not capture_holder_instances(
            tree,
            index.parents[path],
            aliases,
            owners,
            roots,
            path,
            filtered,
            field_aliases,
            resolve,
        ):
            return False
        if not instance_selector_edges(
            tree, aliases, owners, roots, path, filtered, resolve
        ):
            return False
    return True


def constructor_provider_model_helper_epoch():
    """Return the helper functions that determine constructor-provider model cache epochs."""
    from .review_audits import _resolved_ast_name

    return (
        constructor_provider_model,
        _class_selector_edges,
        _class_descendant_edges,
        _descendant_edges_for_class,
        _instance_aliases,
        binding_occurrences,
        _resolved_ast_name,
        *constructor_provider_provenance_epoch(),
    )
