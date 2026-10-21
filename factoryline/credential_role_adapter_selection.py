"""Conditional source evidence for a declared default HTTP Session adapter."""

import ast
from .credential_role_default_contract import property_default as _property_default
from .credential_role_scope_bindings import effective_method
from .credential_endpoint_admission import session_factory_witness
from .credential_role_setting_boundary import (
    _setting_getter_shape,
    module_name as _module_name,
    module_path as _module_path,
    setting_boundary_nodes,
    source_hop as _hop,
)


def _returns(function):
    return [node for node in function.body if isinstance(node, ast.Return)]


def _get_adapter(path, tree, aliases, imports, expected_settings_path):
    from .security_configuration import _canonical
    from .credential_role_scope_bindings import binding_statements

    bindings = binding_statements(tree.body, "get_adapter")
    if len(bindings) != 1 or not isinstance(bindings[0], ast.FunctionDef):
        return None
    matches = []
    for function in tree.body:
        if (
            not isinstance(function, ast.FunctionDef)
            or function.name != "get_adapter"
            or function.decorator_list
        ):
            continue
        returns = _returns(function)
        if len(returns) != 1 or not isinstance(returns[0].value, ast.Call):
            continue
        outer = returns[0].value
        inner = outer.func
        if not isinstance(inner, ast.Call) or not isinstance(outer.func, ast.Call):
            continue
        if not (
            isinstance(inner.func, (ast.Name, ast.Attribute)) and len(inner.args) == 1
        ):
            continue
        canonical_import = _canonical(inner, aliases)
        source = inner.args[0]
        imported = (
            imports.get(path, {}).get(source.value.id)
            if isinstance(source, ast.Attribute) and isinstance(source.value, ast.Name)
            else None
        )
        if (
            canonical_import == "django.utils.module_loading.import_string"
            and isinstance(source, ast.Attribute)
            and source.attr == "ADAPTER"
            and imported
            and imported[0] == expected_settings_path
            and len(outer.args) == 1
            and not outer.keywords
        ):
            matches.append((function, returns[0], inner))
    return matches[0] if len(matches) == 1 else None


def _declared_default(index, snapshots):
    defaults = []
    for path, tree in snapshots.items():
        if not isinstance(tree, ast.Module):
            continue
        from .credential_role_scope_bindings import binding_occurrences

        if binding_occurrences(tree.body, "property"):
            continue
        for owner in (node for node in tree.body if isinstance(node, ast.ClassDef)):
            found = _property_default(owner)
            if found:
                module, name = found[-1].rsplit(".", 1)
                target_path = _module_path(index, module)
                target = snapshots.get(target_path)
                owners = (
                    [
                        n
                        for n in target.body
                        if isinstance(n, ast.ClassDef) and n.name == name
                    ]
                    if isinstance(target, ast.Module)
                    else []
                )
                if len(owners) == 1 and effective_method(
                    [(target_path, name, owners[0])], "get_requests_session"
                ):
                    defaults.append((path, owner, *found))
    getter_shape = _setting_getter_shape(snapshots)
    if len(defaults) != 1 or getter_shape is None:
        return None
    settings_path, settings_owner, prop, prop_return, literal, default = defaults[0]
    module, class_name = default.rsplit(".", 1)
    adapter_path = _module_path(index, module)
    settings_module = _module_name(index, settings_path)
    if adapter_path is None or settings_module is None:
        return None
    getter_path, getter_function = getter_shape
    return (
        settings_path,
        prop,
        prop_return,
        literal,
        default,
        module,
        class_name,
        adapter_path,
        settings_module,
        getter_path,
        getter_function,
        settings_owner,
    )


def _selected_adapter(index, snapshots, imports, classes, aliases, audit, selected):
    (
        settings_path,
        _,
        _,
        _,
        _,
        module,
        class_name,
        adapter_path,
        settings_module,
        getter_path,
        getter_function,
        _,
    ) = selected
    adapter_tree = snapshots.get(adapter_path)
    if not isinstance(adapter_tree, ast.Module):
        return None
    getter = _get_adapter(
        adapter_path, adapter_tree, aliases[adapter_path], imports, settings_path
    )
    if getter is None or (adapter_path, class_name) not in classes:
        return None
    owner = classes.get((adapter_path, class_name))
    method_row = effective_method(
        [(adapter_path, class_name, owner)] if owner is not None else (),
        "get_requests_session",
    )
    if method_row is None:
        return None
    factory_path, factory = method_row
    factory_record = session_factory_witness(
        factory_path, factory, index, aliases[factory_path]
    )
    if factory_record is None or _module_name(index, adapter_path) != module:
        return None
    _, getter_return, import_call = getter
    return (
        factory_record,
        factory_path,
        factory,
        getter_path,
        getter_function,
        adapter_path,
        getter_return,
        import_call,
    )


def default_session_evidence(index, snapshots, imports, classes, aliases, audit):
    """Bind the declared default class to its validated Session factory summary."""
    selected = _declared_default(index, snapshots)
    if selected is None:
        return None
    settings_path, settings_owner = selected[0], selected[-1]
    boundary = setting_boundary_nodes(
        index, snapshots, settings_path, settings_owner, aliases[settings_path]
    )
    if boundary is None:
        return None
    defaulted = _selected_adapter(
        index, snapshots, imports, classes, aliases, audit, selected
    )
    if defaulted is None:
        return None
    (
        factory_record,
        factory_path,
        factory,
        getter_path,
        getter_function,
        adapter_path,
        getter_return,
        import_call,
    ) = defaulted
    settings_path, prop, prop_return, _, _, _, _, _, _, _, _, _ = selected
    path_module = _module_name(index, adapter_path)
    hops = [
        _hop(index, settings_path, prop, "declared_default_adapter"),
        _hop(index, settings_path, prop_return, "settings_default_transfer"),
        _hop(index, *boundary["module_getattr"], "settings_module_getattr"),
        _hop(index, *boundary["settings_instance"], "settings_module_instance"),
        _hop(index, *boundary["setting_method"], "settings_get_setting_transfer"),
        _hop(index, *boundary["setting_transfer"], "settings_get_setting_call"),
        _hop(index, *boundary["get_setting"], "runtime_setting_override"),
        _hop(index, getter_path, getter_function, "runtime_setting_override_boundary"),
        _hop(index, adapter_path, getter_return, "adapter_factory_selection"),
        _hop(index, adapter_path, import_call, "default_adapter_import"),
        *factory_record["hops"],
    ]
    if not all(hops):
        return None
    return {
        "provider": factory_record["provider"],
        "profile": "DECLARED_DEFAULT_MAY_FLOW",
        "get_adapter_canonical": path_module + ".get_adapter",
        "runtime_setting_getter": "UNASSESSED",
        "runtime_adapter_override": "UNASSESSED",
        "hops": hops,
    }
