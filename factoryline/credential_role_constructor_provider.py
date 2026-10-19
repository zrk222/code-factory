"""Check captured constructor and selector providers without executing code."""

import ast

from .credential_role_constructor_capture import (
    _captured_builtins_mutate_isinstance,
    _contains_owner_escape,
    _has_opaque_owner_capture,
    _owner_call_argument,
    _owner_reflection_access,
    _safe_isinstance_type,
)
import hashlib
from types import SimpleNamespace

from .credential_role_scope_bindings import binding_occurrences
from .credential_role_constructor_provider_model import (
    constructor_provider_model,
    constructor_provider_model_helper_epoch,
)
from .credential_role_constructor_provider_provenance import (
    constructor_provider_provenance_epoch,
    field_alias_path,
)
from . import provider_mutations
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
