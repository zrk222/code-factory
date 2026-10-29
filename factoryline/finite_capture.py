"""Bounded source-origin capture for finite templates."""

import ast
from .import_context import (
    security_literal_branch_blocks as security_literal_branch_blocks,
)
from .import_context import _SecurityFlowState as _SecurityFlowState
import copy
import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass as dataclass
from .import_context import _shell_import_aliases as _shell_import_aliases
from .semantic_credential_sensor import (
    _SecurityFlowValue as _SecurityFlowValue,
    _captured_path_expression as _captured_path_expression,
    _captured_sink_arguments as _captured_sink_arguments,
    _captured_sink_callee_binding as _captured_sink_callee_binding,
    _captured_sink_enclosing_callable as _captured_sink_enclosing_callable,
    _captured_sink_excerpt as _captured_sink_excerpt,
    _captured_sink_fact as _captured_sink_fact,
    _captured_sink_failure as _captured_sink_failure,
    _captured_sink_guards as _captured_sink_guards,
    _captured_sink_imports as _captured_sink_imports,
    _captured_sink_index as _captured_sink_index,
    _captured_sink_location as _captured_sink_location,
    _captured_sink_parameter_names as _captured_sink_parameter_names,
    _captured_sink_raw_tree as _captured_sink_raw_tree,
    _captured_sink_scope as _captured_sink_scope,
    _captured_sink_source as _captured_sink_source,
    _captured_sink_value as _captured_sink_value,
    _captured_sink_values as _captured_sink_values,
    _captured_sink_reflective_barrier as _captured_sink_reflective_barrier,
    _captured_method_path_call as _captured_method_path_call,
    _captured_standard_path_call as _captured_standard_path_call,
    _legacy_security_value as _legacy_security_value,
    _security_flow_combine as _security_flow_combine,
    _security_flow_name_value as _security_flow_name_value,
    _security_flow_request_leaf as _security_flow_request_leaf,
    _security_flow_shaped as _security_flow_shaped,
    _security_flow_step as _security_flow_step,
    _security_flow_tainted as _security_flow_tainted,
    _security_flow_value as _security_flow_value,
    _security_helper_initial as _security_helper_initial,
    _security_helper_source_context as _security_helper_source_context,
    _security_source_path as _security_source_path,
    security_helper_return_value as security_helper_return_value,
    security_input_value_flow as security_input_value_flow,
    source_built_ast_program_witness as source_built_ast_program_witness,
)


from .pickle_model_audit import _PROVIDER_ASSUMPTIONS as _PROVIDER_ASSUMPTIONS
from .pickle_model_audit import _PROVIDER_MODEL as _PROVIDER_MODEL
from .pickle_model_audit import _PROVIDER_MODEL_V2 as _PROVIDER_MODEL_V2
from .pickle_model_audit import _PROVIDER_MODEL_V3 as _PROVIDER_MODEL_V3
from .pickle_model_audit import _PROVIDER_MODEL_V4 as _PROVIDER_MODEL_V4
from .pickle_model_audit import _PROVIDER_MODELS as _PROVIDER_MODELS
from .pickle_model_audit import _ProviderV3EnumMember as _ProviderV3EnumMember
from .pickle_model_audit import _ProviderV4SourceObject as _ProviderV4SourceObject
from .pickle_model_audit import _ProviderV4Iterator as _ProviderV4Iterator
from .pickle_model_audit import _ProviderV4OrderedDict as _ProviderV4OrderedDict
from .pickle_model_audit import _ProviderV4AbstractScalar as _ProviderV4AbstractScalar
from .pickle_model_audit import _ProviderV4Return as _ProviderV4Return
from .pickle_model_audit import _ProviderV4Graph as _ProviderV4Graph
from .pickle_model_audit import _provider_v4_scalar as _provider_v4_scalar
from .pickle_model_audit import (
    _provider_v4_protocol_recipes as _provider_v4_protocol_recipes,
)
from .pickle_model_audit import (
    _ProviderV4SourceInterpreter as _ProviderV4SourceInterpreter,
)
from .pickle_model_audit import _provider_v4_mapping_key as _provider_v4_mapping_key
from .pickle_model_audit import (
    _provider_v4_super_call_shape as _provider_v4_super_call_shape,
)
from .pickle_model_audit import _provider_v4_ast_digest as _provider_v4_ast_digest
from .pickle_model_audit import _provider_v4_method_use as _provider_v4_method_use
from .pickle_model_audit import (
    _provider_v4_replayed_state_matches as _provider_v4_replayed_state_matches,
)
from .pickle_model_audit import (
    _provider_v4_source_classes as _provider_v4_source_classes,
)
from .pickle_model_audit import _provider_v4_class_model as _provider_v4_class_model
from .pickle_model_audit import (
    _provider_v4_class_constant as _provider_v4_class_constant,
)
from .pickle_model_audit import _provider_v4_base_symbol as _provider_v4_base_symbol
from .pickle_model_audit import _provider_v4_resolve_mro as _provider_v4_resolve_mro
from .pickle_model_audit import _provider_v4_c3_merge as _provider_v4_c3_merge
from .pickle_model_audit import _provider_v4_apply_mro as _provider_v4_apply_mro
from .pickle_model_audit import (
    _provider_v4_forbidden_methods as _provider_v4_forbidden_methods,
)
from .pickle_model_audit import (
    _provider_v4_inert_class_member as _provider_v4_inert_class_member,
)
from .pickle_model_audit import _provider_v4_class_slots as _provider_v4_class_slots
from .pickle_model_audit import (
    _provider_v4_class_slots_value as _provider_v4_class_slots_value,
)
from .pickle_model_audit import (
    _provider_v4_reduce_delegation as _provider_v4_reduce_delegation,
)
from .pickle_model_audit import (
    _provider_v4_resolve_symbol as _provider_v4_resolve_symbol,
)
from .pickle_model_audit import _provider_v4_bind_values as _provider_v4_bind_values
from .pickle_model_audit import _provider_v4_builtin_call as _provider_v4_builtin_call
from .pickle_model_audit import (
    _provider_v4_builtin_method as _provider_v4_builtin_method,
)
from .pickle_model_audit import (
    provider_pickle_graph_record as provider_pickle_graph_record,
)
from .pickle_model_audit import (
    _provider_v4_caller_expression as _provider_v4_caller_expression,
)
from .pickle_model_audit import (
    _provider_v4_builtins_source_closed as _provider_v4_builtins_source_closed,
)
from .pickle_model_audit import _provider_v4_source_root as _provider_v4_source_root
from .pickle_model_audit import _provider_v4_graph_record as _provider_v4_graph_record
from .pickle_model_audit import _provider_profile_error as _provider_profile_error
from .pickle_model_audit import _provider_runtime_identity as _provider_runtime_identity
from .pickle_model_audit import (
    provider_runtime_identity_v3 as provider_runtime_identity_v3,
)
from .pickle_model_audit import (
    provider_runtime_identity_v4 as provider_runtime_identity_v4,
)
from .pickle_model_audit import (
    _provider_runtime_for_model as _provider_runtime_for_model,
)
from .pickle_model_audit import _provider_digest as _provider_digest
from .pickle_model_audit import (
    _provider_artifact_module_identity as _provider_artifact_module_identity,
)
from .pickle_model_audit import _provider_artifacts_valid as _provider_artifacts_valid
from .pickle_model_audit import _provider_class_rows_valid as _provider_class_rows_valid
from .pickle_model_audit import _provider_contract_valid as _provider_contract_valid
from .pickle_model_audit import provider_analysis_profile as provider_analysis_profile
from .pickle_model_audit import (
    _provider_analysis_profile_v2 as _provider_analysis_profile_v2,
)
from .pickle_model_audit import (
    _provider_contract_sort_key as _provider_contract_sort_key,
)
from .pickle_model_audit import (
    _provider_contract_set_unambiguous as _provider_contract_set_unambiguous,
)
from .pickle_model_audit import _provider_model_descriptor as _provider_model_descriptor
from .pickle_model_audit import provider_contract_view as provider_contract_view
from .pickle_model_audit import (
    _provider_v2_selected_contract as _provider_v2_selected_contract,
)
from .pickle_model_audit import _provider_record_classes as _provider_record_classes
from .pickle_model_audit import _provider_annotation_names as _provider_annotation_names
from .pickle_model_audit import _provider_annotation_kind as _provider_annotation_kind
from .pickle_model_audit import (
    _provider_annotation_supported as _provider_annotation_supported,
)
from .pickle_model_audit import (
    _provider_record_constructor as _provider_record_constructor,
)
from .pickle_model_audit import _provider_record_export as _provider_record_export
from .pickle_model_audit import _provider_v3_record_export as _provider_v3_record_export
from .pickle_model_audit import provider_export_chain_v3 as provider_export_chain_v3
from .pickle_model_audit import _provider_v3_export_chain as _provider_v3_export_chain
from .pickle_model_audit import (
    _provider_v3_export_chain_step as _provider_v3_export_chain_step,
)
from .pickle_model_audit import (
    _provider_v3_final_export_class as _provider_v3_final_export_class,
)
from .pickle_model_audit import (
    _provider_v3_export_packages_closed as _provider_v3_export_packages_closed,
)
from .pickle_model_audit import (
    _provider_v3_package_initializers_present as _provider_v3_package_initializers_present,
)
from .pickle_model_audit import (
    _provider_v3_package_initializer_closed as _provider_v3_package_initializer_closed,
)
from .pickle_model_audit import (
    _provider_v3_reexport_module_closed as _provider_v3_reexport_module_closed,
)
from .pickle_model_audit import (
    _provider_v3_import_from_path as _provider_v3_import_from_path,
)
from .pickle_model_audit import _provider_import_target as _provider_import_target
from .pickle_model_audit import _provider_source_trees as _provider_source_trees
from .pickle_model_audit import _provider_global_callable as _provider_global_callable
from .pickle_model_audit import (
    provider_constructor_binding as provider_constructor_binding,
)
from .pickle_model_audit import _provider_binding_contract as _provider_binding_contract
from .pickle_model_audit import (
    _provider_constructor_binding_source as _provider_constructor_binding_source,
)
from .pickle_model_audit import (
    _provider_constructor_scope as _provider_constructor_scope,
)
from .pickle_model_audit import (
    _provider_constructor_import_is_closed as _provider_constructor_import_is_closed,
)
from .pickle_model_audit import _provider_import_target_v2 as _provider_import_target_v2
from .pickle_model_audit import (
    _provider_import_name_matches as _provider_import_name_matches,
)
from .pickle_model_audit import _provider_v2_preload_path as _provider_v2_preload_path
from .pickle_model_audit import (
    _provider_v2_top_level_imports as _provider_v2_top_level_imports,
)
from .pickle_model_audit import (
    _provider_v2_child_binding_stable as _provider_v2_child_binding_stable,
)
from .pickle_model_audit import (
    _provider_v2_child_name_stable as _provider_v2_child_name_stable,
)
from .pickle_model_audit import (
    _provider_v2_target_binding_stable as _provider_v2_target_binding_stable,
)
from .pickle_model_audit import _provider_record_value as _provider_record_value
from .pickle_model_audit import _provider_record_block as _provider_record_block
from .pickle_model_audit import _provider_record_state as _provider_record_state
from .pickle_model_audit import _provider_v2_class_chain as _provider_v2_class_chain
from .pickle_model_audit import _provider_v2_class_row as _provider_v2_class_row
from .pickle_model_audit import _provider_v2_class_members as _provider_v2_class_members
from .pickle_model_audit import (
    _provider_v2_method_header_supported as _provider_v2_method_header_supported,
)
from .pickle_model_audit import _provider_v2_class_value as _provider_v2_class_value
from .pickle_model_audit import (
    _provider_v2_immutable_value as _provider_v2_immutable_value,
)
from .pickle_model_audit import _provider_v2_header_effect as _provider_v2_header_effect
from .pickle_model_audit import _provider_v2_value as _provider_v2_value
from .pickle_model_audit import _provider_v2_text_size as _provider_v2_text_size
from .pickle_model_audit import _provider_v2_fstring as _provider_v2_fstring
from .pickle_model_audit import _provider_v2_ast_value as _provider_v2_ast_value
from .pickle_model_audit import (
    _provider_v2_initializer_call as _provider_v2_initializer_call,
)
from .pickle_model_audit import _provider_v2_super_call as _provider_v2_super_call
from .pickle_model_audit import _provider_v2_call_values as _provider_v2_call_values
from .pickle_model_audit import _provider_v2_run_block as _provider_v2_run_block
from .pickle_model_audit import _provider_v2_run_statement as _provider_v2_run_statement
from .pickle_model_audit import (
    _provider_v2_selected_branch as _provider_v2_selected_branch,
)
from .pickle_model_audit import _provider_v2_assignment as _provider_v2_assignment
from .pickle_model_audit import _provider_v2_run_parent as _provider_v2_run_parent
from .pickle_model_audit import _provider_v2_construct as _provider_v2_construct
from .pickle_model_audit import (
    _provider_v2_instance_state_walk as _provider_v2_instance_state_walk,
)
from .pickle_model_audit import _provider_record_state_v2 as _provider_record_state_v2
from .pickle_model_audit import provider_exception_record as provider_exception_record
from .pickle_model_audit import (
    _provider_exception_record_v1 as _provider_exception_record_v1,
)
from .pickle_model_audit import (
    _provider_exception_record_v2 as _provider_exception_record_v2,
)
from .pickle_model_audit import _provider_v2_model_record as _provider_v2_model_record
from .pickle_model_audit import _provider_v3_model_record as _provider_v3_model_record
from .pickle_model_audit import _provider_v3_model_context as _provider_v3_model_context
from .pickle_model_audit import (
    _provider_v3_constructed_state as _provider_v3_constructed_state,
)
from .pickle_model_audit import _provider_v3_graph_record as _provider_v3_graph_record
from .pickle_model_audit import _provider_v3_source_call as _provider_v3_source_call
from .pickle_model_audit import (
    _provider_v3_source_name_call as _provider_v3_source_name_call,
)
from .pickle_model_audit import (
    _provider_v3_source_call_matches as _provider_v3_source_call_matches,
)
from .pickle_model_audit import _provider_v3_scope_nodes as _provider_v3_scope_nodes
from .pickle_model_audit import _provider_v3_span as _provider_v3_span
from .pickle_model_audit import _provider_v3_class_models as _provider_v3_class_models
from .pickle_model_audit import _provider_v3_class_model as _provider_v3_class_model
from .pickle_model_audit import (
    _provider_v3_exception_class as _provider_v3_exception_class,
)
from .pickle_model_audit import (
    _provider_v3_display_method as _provider_v3_display_method,
)
from .pickle_model_audit import (
    _provider_v3_cast_return_shape as _provider_v3_cast_return_shape,
)
from .pickle_model_audit import (
    _provider_v3_typing_cast_source_closed as _provider_v3_typing_cast_source_closed,
)
from .pickle_model_audit import (
    _provider_v3_method_header_supported as _provider_v3_method_header_supported,
)
from .pickle_model_audit import (
    _provider_v3_int_enum_class as _provider_v3_int_enum_class,
)
from .pickle_model_audit import (
    _provider_v3_caller_enum_aliases as _provider_v3_caller_enum_aliases,
)
from .pickle_model_audit import _provider_v3_value as _provider_v3_value
from .pickle_model_audit import (
    _provider_v3_container_value as _provider_v3_container_value,
)
from .pickle_model_audit import (
    _provider_v3_validate_scalar as _provider_v3_validate_scalar,
)
from .pickle_model_audit import (
    _provider_v3_run_initializer as _provider_v3_run_initializer,
)
from .pickle_model_audit import (
    _provider_v3_external_instance_state as _provider_v3_external_instance_state,
)
from .pickle_model_audit import (
    _provider_v3_python_literal as _provider_v3_python_literal,
)
from .pickle_model_audit import (
    _provider_v3_instance_aliases as _provider_v3_instance_aliases,
)
from .pickle_model_audit import _provider_v3_graph_node as _provider_v3_graph_node
from .pickle_model_audit import _provider_v3_graph_scalar as _provider_v3_graph_scalar
from .pickle_model_audit import (
    _provider_v3_graph_enum_member as _provider_v3_graph_enum_member,
)
from .pickle_model_audit import (
    _provider_v3_graph_container as _provider_v3_graph_container,
)
from .pickle_model_audit import (
    _provider_v3_deduplicate_enum_uses as _provider_v3_deduplicate_enum_uses,
)
from .pickle_model_audit import (
    _provider_v2_instance_state_map as _provider_v2_instance_state_map,
)
from .pickle_model_audit import (
    _provider_v2_instance_state_cost as _provider_v2_instance_state_cost,
)

_AST_TRY_NODES = (ast.Try, getattr(ast, "TryStar", ast.Try))


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


def _security_merge_structural_states(target, branches):
    from .credential_role_identity_effects import _Value

    if not isinstance(target, _SecurityFlowState):
        return
    target.proven = set().union(
        *(getattr(branch, "proven", set(branch)) for branch in branches)
    )
    target.path_supported = any(
        getattr(branch, "path_supported", True) for branch in branches
    )
    target.bound = set.intersection(
        *(getattr(branch, "bound", set()) for branch in branches)
    )
    names = set().union(*(getattr(branch, "values", {}) for branch in branches))
    target.values = {
        name: security_structural_join(
            [
                getattr(branch, "values", {}).get(name, _Value(unknown=True))
                for branch in branches
            ]
        )
        for name in names
    }


def _security_structural_expression(node, requests, aliases):
    if not isinstance(node, ast.expr) or not isinstance(requests, _SecurityFlowState):
        return None
    return security_structural_value(node, requests.values, aliases)


def _security_store_structural_targets(statement, environment, value):
    targets = getattr(statement, "targets", None) or [
        getattr(statement, "target", None)
    ]
    for target in targets:
        if isinstance(target, ast.Name):
            environment[target.id] = value


def security_structural_value(
    expression, environment, aliases=None, *, request_aliases=None
):
    """Project an expression into the shared source-origin value domain.

    Environment entries may already be `_Value`s. Legacy scalar tags are
    accepted as compatibility inputs but are marked UNKNOWN because their
    source identity was not retained.
    """
    from .credential_role_identity_effects import _Value, identity_value

    if not isinstance(expression, ast.expr) or not isinstance(environment, dict):
        return _Value(unknown=True)
    request_aliases = dict(
        request_aliases if request_aliases is not None else aliases or {}
    )
    aliases = {
        name: _structural_compat_value(value, name)
        for name, value in environment.items()
        if isinstance(name, str)
    }
    if isinstance(expression, ast.Call):
        codec = _security_structural_codec(expression, environment, request_aliases)
        if codec is not None:
            return codec
        result = _security_structural_helper_call(expression, aliases, request_aliases)
        if result is not None:
            return result
    leaf_known, leaf = _security_flow_request_leaf(
        expression, environment, request_aliases
    )
    if leaf_known:
        from .credential_role_identity_effects import _security_structural_request_value

        return _security_structural_request_value(expression, leaf, _Value)
    return identity_value(expression, aliases, strict_calls=True, material_values=True)


def _security_structural_codec(expression, environment, request_aliases):
    from .credential_role_identity_effects import _Value

    if not (
        isinstance(expression.func, ast.Attribute)
        and expression.func.attr in {"encode", "decode"}
        and not expression.args
        and not expression.keywords
    ):
        return None
    receiver = security_structural_value(
        expression.func.value,
        environment,
        request_aliases,
        request_aliases=request_aliases,
    )
    incoming, outgoing = (
        ("text", "bytes") if expression.func.attr == "encode" else ("bytes", "text")
    )
    if (
        not isinstance(receiver, _Value)
        or receiver.scalar_kind != incoming
        or receiver.unknown
        or receiver.content_unknown
    ):
        return None
    from dataclasses import replace

    return replace(
        receiver,
        scalar_kind=outgoing,
        trace=(*receiver.trace, _security_flow_step(expression, "BUILTIN_CODEC")),
    )


def _security_structural_helper_call(expression, aliases, request_aliases):
    from .credential_role_identity_effects import _Value, resolve_source_identity_call
    from . import review_integrity as flow

    function = flow._security_local_helper_definition(expression)
    module, source_index, source_path = _security_helper_source_context(
        expression, function
    )
    if function is not None and source_index is not None and source_path is not None:
        summary = security_structural_helper_summary(
            expression,
            function,
            aliases,
            path=source_path,
            index=source_index,
            request_aliases=request_aliases,
        )
        return _security_summary_value(summary, _Value)
    if source_index is None or source_path is None:
        return None
    resolved = resolve_source_identity_call(
        expression, source_path, source_index, defer_negative_binding=True
    )
    if resolved is None:
        return None
    summary = security_structural_helper_summary(
        expression,
        resolved.function,
        aliases,
        path=source_path,
        index=source_index,
        callee_path=resolved.path,
        source_resolved=True,
        negative_binding_closed=resolved.negative_binding_closed,
        negative_binding_check=resolved.negative_binding_check,
        request_aliases=request_aliases,
        resolve_call=lambda candidate, candidate_path: resolve_source_identity_call(
            candidate,
            candidate_path,
            source_index,
            defer_negative_binding=True,
        ),
    )
    return _security_summary_value(summary, _Value)


def _security_summary_value(summary, value_type):
    if summary.return_values:
        return security_structural_join(
            [projection.value for projection in summary.return_values]
        )
    return value_type(unknown=True)


def _structural_compat_value(value, name):
    from .credential_role_identity_effects import _Value

    if isinstance(value, _Value):
        return value
    if isinstance(value, _SecurityFlowValue):
        source = next(
            (
                step[2]
                for step in value.steps
                if isinstance(step, tuple) and len(step) == 3
            ),
            "unknown-source",
        )
        return _Value(
            roots=frozenset({"source:" + source}) if value.tainted else frozenset(),
            inert_kind="scalar" if value.kind in {"text", "bytes"} else None,
            unknown=False,
            scalar_kind=value.kind,
            trace=tuple(value.steps),
        )
    if value is True:
        return _Value(
            roots=frozenset({"legacy-unknown:" + name}),
            unknown=True,
            content_unknown=True,
        )
    if value is False:
        return _Value(inert_kind="scalar", scalar_kind="boolean")
    return _Value(unknown=True)


def security_structural_join(values):
    """Join source-origin values while preserving unknown and may-origin facts."""
    from .credential_role_identity_effects import structural_value_join

    return structural_value_join(values)


def security_structural_helper_summary(
    call,
    function,
    roots,
    *,
    path,
    index,
    resolve_call=None,
    field_roots=None,
    role_view=False,
    callee_path=None,
    source_resolved=False,
    negative_binding_closed=False,
    negative_binding_check=None,
    request_aliases=None,
):
    """Bind and summarize one captured helper with separate return and effect facts."""
    from .credential_role_identity_effects import (
        IdentityEffectSummary,
        IdentityReturnProjection,
        _Value,
        _security_structural_exact_resolver,
        _source_index_request_leaf_values,
        _security_structural_summary_context,
        summarize_identity_call,
    )

    empty = IdentityEffectSummary(
        "UNKNOWN",
        unknowns=("invalid structural helper context",),
        return_status="UNKNOWN",
    )
    context = _security_structural_summary_context(
        call, function, roots, path, index, source_resolved, callee_path
    )
    if context is None:
        return empty
    if isinstance(context, str):
        return IdentityEffectSummary(
            "UNKNOWN", unknowns=(context,), return_status="UNKNOWN"
        )
    _module, actuals, callee_path, _source_index = context
    resolver = _security_structural_exact_resolver(
        call,
        function,
        callee_path,
        actuals,
        source_resolved,
        negative_binding_closed,
        negative_binding_check,
        resolve_call,
    )
    bound_roots = dict(roots)
    bound_roots.update(_source_index_request_leaf_values(function, callee_path, index))
    if request_aliases is not None:
        for actual in actuals.values():
            projected = security_structural_value(
                actual, roots, request_aliases=request_aliases
            )
            if isinstance(projected, _Value):
                bound_roots[("expression", id(actual))] = projected
    summary = summarize_identity_call(
        call,
        path,
        index,
        bound_roots,
        resolve_call=resolver,
        field_roots=field_roots,
        role_view=role_view,
    )
    if summary.return_values:
        return summary
    return _structural_unknown_return(
        summary, call, path, _Value, IdentityReturnProjection
    )


def _structural_helper_binding(call, function, source_resolved):
    if source_resolved:
        if not isinstance(call.func, ast.expr):
            return None
        from .review_integrity import bind_source_call

        try:
            return None, bind_source_call(call, function, apply_defaults=True)
        except (TypeError, ValueError):
            return None
    if not isinstance(call.func, ast.Name):
        return None
    return _security_helper_binding(call, function)


def _structural_helper_invalid_reason(source_index, index, path, callee_path, function):
    if source_index is not None and source_index is not index:
        return "mixed source snapshot generation"
    if (
        not index.validate(path)
        or not index.validate(callee_path)
        or id(function) not in index.parents[callee_path]
    ):
        return "helper is outside validated source snapshot"
    return None


def _structural_unknown_return(summary, call, path, value_type, projection_type):
    from dataclasses import replace

    unknown = value_type(
        unknown=True, trace=(_security_flow_step(call, "NO_RETURN_PROJECTION"),)
    )
    return replace(
        summary,
        return_values=(
            projection_type(
                path,
                (
                    str(path),
                    call.lineno,
                    call.col_offset,
                    call.end_lineno,
                    call.end_col_offset,
                ),
                unknown,
            ),
        ),
        return_status="UNKNOWN",
    )


def security_helper_return_tainted(call, function, requests, parameters, aliases):
    """Boolean compatibility view of the one native helper summary."""
    return _security_flow_tainted(
        security_helper_return_value(call, function, requests, parameters, aliases)
    )


def security_helper_return_kind(call, requests, aliases):
    """Return the exact scalar kind only when a helper result is source-traced."""
    from . import review_integrity as flow

    function = (
        flow._security_local_helper_definition(call)
        if isinstance(call, ast.Call)
        else None
    )
    value = security_helper_return_value(call, function, requests, set(), aliases)
    return (
        value.kind if isinstance(value, _SecurityFlowValue) and value.tainted else None
    )


def _security_forward_helper_candidate(call, requests, aliases, flow):
    actual_values = [*call.args, *(keyword.value for keyword in call.keywords)]
    if not any(
        flow._security_expr_tainted(value, requests, set(), aliases)
        for value in actual_values
    ):
        return None
    function = flow._security_local_helper_definition(call)
    binding = _security_helper_binding(call, function)
    if binding is None:
        return None
    module, actuals = binding
    initial = _security_helper_initial(call, actuals, requests, set(), aliases)
    if any(value is None for value in initial.values()):
        return None
    sources = {name for name, value in initial.items() if _security_flow_tainted(value)}
    if not sources:
        return None
    return function, module, actuals, initial, sources


def _security_forward_helper_supported(function, initial, aliases, relative):
    return (
        not any(
            not isinstance(
                statement, (ast.Assign, ast.AnnAssign, ast.Expr, ast.Return, ast.Pass)
            )
            for statement in function.body
        )
        and _security_helper_sink_calls_supported(function, aliases, relative)
        and _security_helper_prefix_supported(function, initial, aliases)
    )


def _security_forward_helper_request_sources(
    actuals, requests, aliases, sources, request_payload_value_kind, flow, initial
):
    for name in tuple(sources):
        value = initial[name]
        kind = (
            value.kind
            if isinstance(value, _SecurityFlowValue)
            else request_payload_value_kind(
                actuals[name], requests, aliases, flow._security_scope_request_aliases
            )
        )
        if kind:
            sources.add(("request-type:" + kind, name))


def _security_forward_helper_run(
    function, module, relative, aliases, sources, helpers, flow
):
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


def security_forward_helper_sources(relative, call, aliases, requests, helpers):
    """Feed proven actual-argument sources into the existing callee sink pass."""
    from . import review_integrity as flow
    from .semantic_credential_sensor import (
        security_precondition_path_possible,
        request_payload_value_kind,
    )

    if not security_precondition_path_possible(call):
        return
    candidate = _security_forward_helper_candidate(call, requests, aliases, flow)
    if candidate is None:
        return
    function, module, actuals, initial, sources = candidate
    if not _security_forward_helper_supported(function, initial, aliases, relative):
        return
    _security_forward_helper_request_sources(
        actuals, requests, aliases, sources, request_payload_value_kind, flow, initial
    )
    _security_forward_helper_run(
        function, module, relative, aliases, sources, helpers, flow
    )


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


def _helper_flow_admission(function, initial, evaluate_expression, max_states):
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
    return None


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
    invalid = _helper_flow_admission(function, initial, evaluate_expression, max_states)
    if invalid is not None:
        return invalid
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
    function,
    node,
    parents,
    scope_of,
    return_callers,
    consumer,
    *,
    field_successors=None,
    max_states=512,
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
        successors = _captured_field_successors(
            current,
            value,
            parents,
            scope_of,
            field_successors,
            max_states - len(seen),
        )
        if successors is _INVALID_CAPTURED_SUCCESSORS:
            return None
        if successors is None:
            successors = _captured_value_use_successors(
                current, value, parents, scope_of, return_callers
            )
        if not successors:
            return None
        pending.extend((scope, child, ancestors | {key}) for scope, child in successors)
    return {"sinks": tuple(sinks.values()), "nodes": tuple(nodes)} if sinks else None


_INVALID_CAPTURED_SUCCESSORS = object()


def _captured_field_successors(
    function, value, parents, scope_of, field_successors, budget
):
    if field_successors is None:
        return None
    successors = field_successors(function, value, parents)
    if successors is None:
        return None
    from itertools import islice

    try:
        edges = tuple(islice(iter(successors), budget + 1))
    except (TypeError, ValueError):
        return _INVALID_CAPTURED_SUCCESSORS
    if len(edges) > budget or not edges:
        return _INVALID_CAPTURED_SUCCESSORS
    if any(not isinstance(edge, (tuple, list)) or len(edge) != 2 for edge in edges):
        return _INVALID_CAPTURED_SUCCESSORS
    normalized = tuple((edge[0], edge[1]) for edge in edges)
    if any(
        not isinstance(scope, ast.AST)
        or not isinstance(child, ast.AST)
        or scope_of(child) is not scope
        for scope, child in normalized
    ):
        return _INVALID_CAPTURED_SUCCESSORS
    return normalized


def captured_registered_fixture_helper_role(finding, inventory):
    """Bind a one-return eval helper to registered fixture-test callers."""
    context = _registered_fixture_helper_context(finding, inventory)
    if context is None:
        return None
    roles, path, trees, sources, tree, sink, helper, parents, calls = context
    if not _registered_fixture_peers_closed(roles, path, helper, trees, sources):
        return None
    if not _registered_fixture_bindings_closed(roles, tree, helper, parents, calls):
        return None
    callers = []
    for call in calls:
        row = _registered_fixture_caller(
            roles, finding, inventory, path, tree, helper, call, trees, sources
        )
        if row is None:
            return None
        callers.append(row)
    return _registered_fixture_report(
        roles, finding, path, helper, sink, inventory, sources, callers
    )


def _registered_fixture_helper_context(finding, inventory):
    from . import primitive_observation_binding as roles
    from .credential_role_constructor_provider import (
        binding_occurrences,
    )

    if not isinstance(inventory, dict):
        return None
    path = finding.get("path")
    trees, sources = inventory.get("trees"), inventory.get("sources")
    if not _registered_fixture_file_valid(roles, finding, path, trees, sources):
        return None
    tree = trees[path]
    sink = _registered_fixture_sink(tree, finding)
    if sink is None:
        return None
    helper = _registered_fixture_owner(tree, sink)
    if helper is None or not _registered_fixture_wrapper_shape(helper):
        return None
    if not _registered_fixture_eval_body(helper) or binding_occurrences(
        tree.body, "eval"
    ):
        return None
    if roles._pickle_role_native_match(finding, inventory) is not True:
        return None
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == helper.name
    ]
    if not calls:
        return None
    return roles, path, trees, sources, tree, sink, helper, parents, calls


def _registered_fixture_file_valid(roles, finding, path, trees, sources):
    from .credential_role_constructor_provider import _ast_matches_source

    return (
        isinstance(trees, dict)
        and finding.get("code") == "SECURITY_DYNAMIC_EXECUTION"
        and path in trees
        and isinstance(sources, dict)
        and path in sources
        and not roles._pickle_operational_importer(path, trees)
        and _ast_matches_source(sources[path], trees[path])
    )


def _registered_fixture_sink(tree, finding):
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (node.lineno, node.col_offset)
        == (finding.get("line"), finding.get("column", 0))
    ]
    if (
        len(matches) != 1
        or not isinstance(matches[0].func, ast.Name)
        or matches[0].func.id != "eval"
    ):
        return None
    return matches[0]


def _registered_fixture_owner(tree, sink):
    owners = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and sink in ast.walk(node)
    ]
    return owners[0] if len(owners) == 1 else None


def _registered_fixture_wrapper_shape(helper):
    args = helper.args
    return not (
        helper.decorator_list
        or helper.returns
        or len(args.args) != 1
        or args.posonlyargs
        or args.kwonlyargs
        or args.vararg
        or args.kwarg
        or args.defaults
        or args.kw_defaults
        or args.args[0].annotation
        or len(helper.body) != 1
        or not isinstance(helper.body[0], ast.Return)
    )


def _registered_fixture_eval_body(helper):
    expression = helper.body[0].value
    return (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Name)
        and expression.func.id == "eval"
        and len(expression.args) == 1
        and not expression.keywords
        and isinstance(expression.args[0], ast.Name)
        and expression.args[0].id == helper.args.args[0].arg
    )


def _registered_fixture_peers_closed(roles, path, helper, trees, sources):
    from .credential_role_constructor_provider import _ast_matches_source

    module_name = path[:-3].replace("/", ".") if path.endswith(".py") else ""
    parts = module_name.split(".")
    candidates = {".".join(parts[index:]) for index in range(len(parts))}
    for other_path, other in trees.items():
        if other_path == path:
            continue
        if other_path not in sources or not _ast_matches_source(
            sources[other_path], other
        ):
            return False
        if not _registered_fixture_peer_tree_clear(
            roles, other, other_path, candidates, helper.name
        ):
            return False
    return True


def _registered_fixture_peer_tree_clear(roles, tree, path, candidates, helper_name):
    for item in ast.walk(tree):
        if isinstance(item, ast.ImportFrom) and roles._pickle_role_imports_target(
            item, path, candidates
        ):
            return False
        if (
            isinstance(item, ast.Import)
            and any(alias.name in candidates for alias in item.names)
            and any(
                isinstance(node, ast.Attribute) and node.attr == helper_name
                for node in ast.walk(tree)
            )
        ):
            return False
        if _registered_fixture_mutates_name(item, {helper_name, "eval"}):
            return False
    return True


def _registered_fixture_mutates_name(node, names):
    if (
        isinstance(node, ast.Attribute)
        and node.attr in names
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ):
        return True
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and isinstance(node.slice, ast.Constant)
        and node.slice.value in names
    ):
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"setattr", "delattr"}
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value in names
    )


def _registered_fixture_bindings_closed(roles, tree, helper, parents, calls):
    from .credential_role_constructor_provider import binding_occurrences

    for reference in (
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == helper.name
        and isinstance(node.ctx, ast.Load)
    ):
        parent = parents.get(id(reference))
        if (
            not isinstance(parent, ast.Call)
            or parent.func is not reference
            or parent not in calls
        ):
            return False
    return binding_occurrences(tree.body, helper.name) == [helper]


def _registered_fixture_caller(
    roles, finding, inventory, path, tree, helper, call, trees, sources
):
    from .credential_role_constructor_provider import binding_occurrences

    owners = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and call in ast.walk(node)
    ]
    if (
        len(owners) != 1
        or len(call.args) != 1
        or call.keywords
        or any(isinstance(node, ast.Starred) for node in call.args)
    ):
        return None
    owner = owners[0]
    if binding_occurrences(owner.body, helper.name) or any(
        arg.arg == helper.name
        for arg in (*owner.args.posonlyargs, *owner.args.args, *owner.args.kwonlyargs)
    ):
        return None
    registration = roles._registered_fixture_registration(tree, owner)
    if registration is None:
        return None
    statement, marker, parameters = registration
    entry = roles._registered_fixture_entry(tree, path, marker, inventory)
    flow = _registered_fixture_projected_flow(roles, tree, owner, call, parameters)
    if not _registered_fixture_entry_valid(roles, entry, flow, tree, trees, sources):
        return None
    return {
        "function_span": roles._pickle_span(owner),
        "registration_span": roles._pickle_span(statement),
        "call_span": roles._pickle_span(call),
        "harness": entry,
        "transparent_wrapper_span": roles._pickle_span(helper),
        "wrapper_ast_sha256": roles._tier_sha256(
            ast.dump(helper, include_attributes=False)
        ),
        "input_flow": flow,
    }


def _registered_fixture_projected_flow(roles, tree, owner, call, parameters):
    projected_owner = copy.deepcopy(owner)
    projected_call = next(
        (
            node
            for node in ast.walk(projected_owner)
            if isinstance(node, ast.Call)
            and roles._pickle_span(node) == roles._pickle_span(call)
        ),
        None,
    )
    if projected_call is None:
        return None
    projected_call.func = ast.copy_location(
        ast.Name(id="eval", ctx=ast.Load()), projected_call.func
    )
    return roles._registered_fixture_flow(
        projected_owner, projected_call, parameters, tree
    )


def _registered_fixture_entry_valid(roles, entry, flow, tree, trees, sources):
    from .credential_role_constructor_provider import _ast_matches_source

    return (
        entry is not None
        and flow is not None
        and entry["path"] in sources
        and _ast_matches_source(sources[entry["path"]], trees.get(entry["path"]))
        and roles._registered_fixture_module_clear(tree, entry["entry_span"])
    )


def _registered_fixture_report(
    roles, finding, path, helper, sink, inventory, sources, callers
):
    return {
        "schema": "factory.security.registered-fixture-helper-context.v1",
        "role": "REGISTERED_FIXTURE_HARNESS_OPERATION",
        "tier": "NEEDS_CONTEXT",
        "source_path": path,
        "source_sha256": hashlib.sha256(sources[path]).hexdigest(),
        "sources_sha256": inventory["sources_sha256"],
        "helper_span": roles._pickle_span(helper),
        "sink_span": roles._pickle_span(sink),
        "callers": callers,
        "safe_operation": False,
        "fixture_payloads": "UNASSESSED",
        "filesystem_authority": "UNASSESSED",
        "dynamic_deployment": "UNASSESSED",
        "original_severity": finding.get("severity"),
        "policy_sha256": roles._tier_sha256(roles._SOURCE_ROLE_POLICY_V2),
    }


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


def _captured_branch_known_arguments(source, caller_path, caller, bound, path):
    known = {}
    for name, actual in bound.items():
        value = captured_call_scalar(source, caller_path, caller, actual, path)
        if value is not None:
            known[name] = value[0]
    return known


def _captured_branch_field_statement(
    constructor, receiver, field, known, builtin_stable
):
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
    return statements[0]


def _captured_branch_selected_formal(statement, known, builtin_stable, bound):
    value = statement.value
    while isinstance(value, ast.IfExp):
        truth = captured_scalar_guard(value.test, known, builtin_stable)
        if truth is None:
            return None
        value = value.body if truth else value.orelse
    if not isinstance(value, ast.Name) or value.id not in bound:
        return None
    return value.id


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
    known = _captured_branch_known_arguments(source, caller_path, caller, bound, path)
    statement = _captured_branch_field_statement(
        constructor, receiver, field, known, builtin_stable
    )
    if statement is None:
        return None
    formal = _captured_branch_selected_formal(statement, known, builtin_stable, bound)
    if formal is None:
        return None
    return {
        "path": path,
        "constructor": constructor,
        "statement": statement,
        "formal": formal,
        "actual": bound[formal],
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


def _captured_call_scalar_context(source, path, caller, expression, default_path):
    if (
        not source.validate(path)
        or not isinstance(caller, (ast.FunctionDef, ast.AsyncFunctionDef))
        or id(caller) not in source.parents[path]
    ):
        return False
    if id(expression) not in source.parents[path]:
        if default_path is None or not source.validate(default_path):
            return False
        if id(expression) not in source.parents[default_path]:
            return False
    return True


def _captured_unique_scalar_assignment(caller, expression, binding_occurrences):
    rows = [
        row
        for row in caller.body
        if isinstance(row, ast.Assign)
        and len(row.targets) == 1
        and isinstance(row.targets[0], ast.Name)
        and row.targets[0].id == expression.id
    ]
    if len(rows) != 1 or len(binding_occurrences(caller.body, expression.id)) != 1:
        return None
    return rows[0]


def _captured_call_scalar_expression(source, path, caller, expression):
    if isinstance(expression, ast.Name):
        from .credential_role_constructor_provider import binding_occurrences

        if not source.validate(path):
            return False, None
        assignment = _captured_unique_scalar_assignment(
            caller, expression, binding_occurrences
        )
        if (
            assignment is None
            or assignment not in caller.body
            or assignment.lineno >= expression.lineno
        ):
            return False, None
        return True, assignment.value
    return True, expression


def _captured_call_scalar_constant(expression):
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


def captured_call_scalar(source, path, caller, expression, default_path=None):
    """Resolve a bounded immutable scalar argument from current captured source bindings."""
    if not _captured_call_scalar_context(
        source, path, caller, expression, default_path
    ):
        return None
    resolved, value = _captured_call_scalar_expression(source, path, caller, expression)
    if not resolved:
        return None
    return _captured_call_scalar_constant(value)


def _captured_scalar_isinstance_guard(expression, known, builtin_stable):
    if (
        len(expression.args) != 2
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


def _captured_scalar_bool_guard(expression, known, builtin_stable):
    values = [
        captured_scalar_guard(child, known, builtin_stable)
        for child in expression.values
    ]
    if any(value is None for value in values):
        return None
    return all(values) if isinstance(expression.op, ast.And) else any(values)


def _captured_scalar_not_guard(expression, known, builtin_stable):
    truth = captured_scalar_guard(expression.operand, known, builtin_stable)
    return None if truth is None else not truth


def _captured_scalar_guard_ast_supported(expression):
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
        return False
    if isinstance(expression, ast.Compare) and any(
        isinstance(operator, (ast.Is, ast.IsNot)) for operator in expression.ops
    ):
        values = [expression.left, *expression.comparators]
        if not any(
            isinstance(value, ast.Constant) and value.value is None for value in values
        ):
            return False
    return True


def captured_scalar_guard(expression, known, builtin_stable):
    """Evaluate a modeled scalar guard, retaining unknown outcomes when identity is not closed."""
    from . import review_audits as audit

    if isinstance(expression, ast.Call):
        if (
            not isinstance(expression.func, ast.Name)
            or expression.func.id != "isinstance"
        ):
            return None
        return _captured_scalar_isinstance_guard(expression, known, builtin_stable)
    if isinstance(expression, ast.BoolOp):
        return _captured_scalar_bool_guard(expression, known, builtin_stable)
    if isinstance(expression, ast.UnaryOp) and isinstance(expression.op, ast.Not):
        return _captured_scalar_not_guard(expression, known, builtin_stable)
    if not _captured_scalar_guard_ast_supported(expression):
        return None
    return audit._constant_truth_value(expression, known)


def _captured_selected_field_writes(statement, receiver, field):
    return [
        node
        for node in ast.walk(statement)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == receiver
        and node.attr == field
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]


def _captured_selected_field_branch(
    statement, receiver, field, known, guard, budget, writes
):
    truth = guard(statement.test, known)
    if truth is None:
        if writes:
            return None
        return []
    branch = statement.body if truth else statement.orelse
    return captured_selected_field_assignments(
        branch, receiver, field, known, guard, budget
    )


def _captured_selected_field_assignment(statement, writes):
    targets = (
        statement.targets
        if isinstance(statement, ast.Assign)
        else [statement.target]
        if isinstance(statement, ast.AnnAssign)
        else []
    )
    target = targets[0] if len(targets) == 1 else None
    return isinstance(statement, (ast.Assign, ast.AnnAssign)) and writes == [target]


def captured_selected_field_assignments(body, receiver, field, known, guard, budget):
    """Collect bounded field assignments along modeled scalar branches without executing source."""
    rows = []
    for statement in body:
        budget[0] -= 1
        if budget[0] < 0:
            return None
        writes = _captured_selected_field_writes(statement, receiver, field)
        if isinstance(statement, ast.If):
            selected = _captured_selected_field_branch(
                statement, receiver, field, known, guard, budget, writes
            )
            if selected is None:
                return None
            rows.extend(selected)
        elif writes:
            if not _captured_selected_field_assignment(statement, writes):
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
    from .credential_role_constructor_provider import _scope_scope_bindings

    for node in nodes:
        if not isinstance(node, (ast.Name, ast.Attribute)):
            continue
        canonical = audit._resolved_ast_name(node, aliases).removeprefix("builtins.")
        if canonical not in {"globals", "locals", "vars"}:
            continue
        scope = _scope_scope_bindings(node, parents, None)
        if (
            isinstance(node, ast.Name)
            and isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
            and not any(
                isinstance(item, (ast.Global, ast.Nonlocal)) and node.id in item.names
                for item in ast.walk(scope)
            )
            and (
                node.id in audit._scope_parameters(scope)
                or audit._scope_binds_name(scope, node.id)
            )
        ):
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


def captured_literal_caller_program_role(finding, inventory):
    """Bind a method's program argument to every source-visible literal caller."""
    context = _literal_caller_context(finding, inventory)
    if context is None:
        return None
    (
        binding_occurrences,
        path,
        tree,
        parents,
        sink,
        owner,
        helper,
        receiver,
        argument,
        value,
    ) = context
    if not _literal_caller_uses_closed(tree, owner, helper, argument, value):
        return None
    programs = _literal_caller_programs(
        inventory, tree, parents, owner, helper, binding_occurrences
    )
    if not programs or len(programs) > 64:
        return None
    return _literal_caller_report(finding, inventory, path, sink, programs)


def _literal_caller_context(finding, inventory):
    from .credential_role_constructor_provider import binding_occurrences

    path = finding.get("path")
    trees = inventory.get("trees") if isinstance(inventory, dict) else None
    if (
        finding.get("code") != "SECURITY_DYNAMIC_EXECUTION"
        or not isinstance(trees, dict)
        or path not in trees
    ):
        return None
    tree = trees[path]
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    sink = _literal_caller_sink(tree, finding)
    helper = _source_built_ast_scope(sink, parents) if sink is not None else None
    owner = parents.get(helper) if helper is not None else None
    if not _literal_caller_method_shape(sink, helper, owner):
        return None
    if binding_occurrences(owner.body, helper.name) != [helper]:
        return None
    receiver, argument = (item.arg for item in helper.args.args)
    value = _literal_caller_argument(tree, sink, argument, inventory)
    if value is None:
        return None
    return (
        binding_occurrences,
        path,
        tree,
        parents,
        sink,
        owner,
        helper,
        receiver,
        argument,
        value,
    )


def _literal_caller_sink(tree, finding):
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (node.lineno, node.col_offset)
        == (finding.get("line"), finding.get("column", 0))
    ]
    if (
        len(calls) != 1
        or not isinstance(calls[0].func, ast.Name)
        or calls[0].func.id != "exec"
    ):
        return None
    return calls[0]


def _literal_caller_method_shape(sink, helper, owner):
    return not (
        not isinstance(helper, ast.FunctionDef)
        or helper.decorator_list
        or not isinstance(owner, ast.ClassDef)
        or owner.bases
        or owner.keywords
        or helper.args.posonlyargs
        or helper.args.kwonlyargs
        or helper.args.defaults
        or helper.args.vararg
        or helper.args.kwarg
        or len(helper.args.args) != 2
        or len(sink.args) != 2
        or sink.keywords
    )


def _literal_caller_argument(tree, sink, argument, inventory):
    value = sink.args[0]
    if isinstance(value, ast.Call):
        if (
            ast.unparse(value.func) != "textwrap.dedent"
            or len(value.args) != 1
            or value.keywords
            or not any(
                isinstance(node, ast.Import)
                and any(
                    alias.name == "textwrap" and alias.asname is None
                    for alias in node.names
                )
                for node in tree.body
            )
        ):
            return None
        imports = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
            if (alias.asname or alias.name.split(".")[0]) == "textwrap"
        ]
        if (
            len(imports) != 1
            or imports[0] not in tree.body
            or not isinstance(imports[0], ast.Import)
        ):
            return None
        from . import review_audits as audit

        for peer in inventory["trees"].values():
            risks = finite_provider_mutation_index(
                ast.walk(peer),
                audit._security_aliases(ast.walk(peer)),
                audit,
                {
                    id(child): parent
                    for parent in ast.walk(peer)
                    for child in ast.iter_child_nodes(parent)
                },
            )
            if any(
                provider == "textwrap" or provider.startswith("textwrap.")
                for provider, _ in risks
            ):
                return None
        value = value.args[0]
    if not isinstance(value, ast.Name) or value.id != argument:
        return None
    return value


def _literal_caller_uses_closed(tree, owner, helper, argument, value):
    if any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id
        in {"getattr", "setattr", "vars", "globals", "locals", "__import__"}
        for node in ast.walk(owner)
    ):
        return False
    if any(
        isinstance(node, ast.Name)
        and node.id in {argument, "exec", "textwrap"}
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in ast.walk(helper)
    ):
        return False
    loads = [
        node
        for node in ast.walk(helper)
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id == argument
    ]
    return loads == [value] and _literal_caller_tree_names_closed(
        tree, owner, helper.name
    )


def _literal_caller_tree_names_closed(tree, owner, helper_name):
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id in {"textwrap", "exec"}
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            return False
        if isinstance(node, ast.arg) and node.arg in {"textwrap", "exec"}:
            return False
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in {
            "textwrap",
            "exec",
        }:
            return False
        if (
            isinstance(node, ast.Attribute)
            and node.attr in {"dedent", helper_name}
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            return False
        if isinstance(node, ast.ImportFrom) and any(
            alias.name == "*" for alias in node.names
        ):
            return False
        if isinstance(node, ast.Name) and node.id == owner.name:
            return False
    return True


def _literal_caller_programs(
    inventory, tree, parents, owner, helper, binding_occurrences
):
    programs = []
    for other in inventory["trees"].values():
        if not _literal_caller_tree_programs(
            other, tree, parents, owner, helper, binding_occurrences, programs
        ):
            return None
    return programs


def _literal_caller_tree_programs(
    other, tree, parents, owner, helper, binding_occurrences, programs
):
    for node in ast.walk(other):
        if not isinstance(node, ast.Attribute) or node.attr != helper.name:
            continue
        if other is not tree or not _literal_test_call(
            node, parents, owner, binding_occurrences
        ):
            return False
        caller = parents.get(node)
        programs.append(
            {
                "caller_span": _fixed_program_span(caller),
                "program_sha256": hashlib.sha256(
                    caller.args[0].value.encode()
                ).hexdigest(),
            }
        )
    return True


def _literal_test_call(node, parents, owner, binding_occurrences):
    caller = parents.get(node)
    scope = _source_built_ast_scope(node, parents)
    return (
        isinstance(caller, ast.Call)
        and caller.func is node
        and scope in owner.body
        and isinstance(scope, ast.FunctionDef)
        and scope.name.startswith("test_")
        and bool(scope.args.args)
        and isinstance(node.value, ast.Name)
        and node.value.id == scope.args.args[0].arg
        and not binding_occurrences(scope.body, scope.args.args[0].arg)
        and len(caller.args) == 1
        and not caller.keywords
        and isinstance(caller.args[0], ast.Constant)
        and type(caller.args[0].value) is str
        and len(caller.args[0].value.encode()) <= 16 * 1024
    )


def _literal_caller_report(finding, inventory, path, sink, programs):
    return {
        "schema": "factory.security.literal-caller-program-context.v1",
        "role": "CAPTURED_TEST_LITERAL_PROGRAM_INPUT",
        "tier": "NEEDS_CONTEXT",
        "source_path": path,
        "source_sha256": hashlib.sha256(inventory["sources"][path]).hexdigest(),
        "sources_sha256": inventory["sources_sha256"],
        "call_span": _fixed_program_span(sink),
        "literal_callers": programs,
        "program_effects": "UNASSESSED",
        "external_callers": "UNASSESSED",
        "safe_execution": False,
        "target_execution": "not_performed",
        "original_severity": finding.get("severity"),
    }


class _CapturedFileProgramTrace:
    def __init__(self, path, tree, sink, parents, scopes, aliases, binding_occurrences):
        """Store one captured file-input context for bounded path resolution."""
        from pathlib import PurePosixPath

        self.path = path
        self.tree = tree
        self.sink = sink
        self.parents = parents
        self.scopes = scopes
        self.aliases = aliases
        self.binding_occurrences = binding_occurrences
        self.path_type = PurePosixPath
        self.steps = []

    def callee(self, node):
        """Resolve a captured name or attribute through the module aliases."""
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return self.callee(node.value) + "." + node.attr
        return ""

    def preceding(self, owner, scope):
        """Require an assignment to precede the sink on an unconditional path."""
        current = self.sink
        while current in self.parents:
            container = self.parents[current]
            if container is scope or isinstance(container, ast.With):
                if owner in container.body and current in container.body:
                    return container.body.index(owner) < container.body.index(current)
            if isinstance(
                container,
                (ast.If, ast.For, ast.AsyncFor, ast.While, *_AST_TRY_NODES, ast.Match),
            ):
                return False
            current = container
        return False

    def definition(self, node, seen):
        """Resolve one unique prior local binding without crossing control flow."""
        if node.id in seen:
            return None
        for scope in self.scopes:
            parameters = getattr(scope, "args", None)
            if parameters and any(
                arg.arg == node.id
                for arg in ast.walk(parameters)
                if isinstance(arg, ast.arg)
            ):
                return None
            bindings = self.binding_occurrences(scope.body, node.id)
            if self.scopes[0] is self.tree:
                bindings = [item for item in bindings if item.lineno < self.sink.lineno]
            if not bindings:
                continue
            if len(bindings) != 1 or not isinstance(bindings[0], ast.Name):
                return None
            owner = self.parents.get(bindings[0])
            if not isinstance(owner, (ast.Assign, ast.AnnAssign)) or not self.preceding(
                owner, scope
            ):
                return None
            targets = owner.targets if isinstance(owner, ast.Assign) else [owner.target]
            if len(targets) != 1 or targets[0] is not bindings[0]:
                return None
            self.steps.append(_fixed_program_span(owner))
            return self.resolve(owner.value, seen | {node.id})
        return None

    def resolve(self, node, seen=frozenset()):
        """Resolve the bounded path expressions accepted for captured inputs."""
        if len(seen) > 24:
            return None
        if isinstance(node, ast.Constant) and type(node.value) is str:
            return node.value
        if isinstance(node, ast.Name):
            return (
                self.path_type(self.path)
                if node.id == "__file__"
                else self.definition(node, seen)
            )
        if isinstance(node, (ast.Attribute, ast.BinOp, ast.Call)):
            return _captured_path_expression(
                node, seen, self.resolve, self.callee, self.path_type
            )
        return None

    def read_input(self, node, seen=frozenset()):
        """Trace a sink argument to a captured file read or compiled input."""
        if len(seen) > 24:
            return None
        if isinstance(node, ast.Name):
            return _captured_read_binding(
                node,
                seen,
                self.scopes,
                self.tree,
                self.sink,
                self.parents,
                self.preceding,
                self.steps,
                self.read_input,
                self.binding_occurrences,
            )
        if isinstance(node, ast.Call):
            return _captured_read_call(
                node,
                seen,
                self.resolve,
                self.read_input,
                self.callee,
                self.sink,
                self.parents,
            )
        return None


def captured_file_program_role(finding, inventory):
    """Trace captured source-file input; never claim runtime file or code safety."""
    from pathlib import PurePosixPath
    import posixpath
    from .credential_role_constructor_provider import binding_occurrences

    path = finding.get("path")
    context = _captured_file_program_context(
        finding, inventory, path, binding_occurrences
    )
    if context is None:
        return None
    path, tree, parents, sink, scopes, aliases = context
    tracer = _CapturedFileProgramTrace(
        path, tree, sink, parents, scopes, aliases, binding_occurrences
    )
    resolved = tracer.read_input(sink.args[0])
    if not isinstance(resolved, PurePosixPath):
        return None
    payload = posixpath.normpath(resolved.as_posix())
    if (
        payload.startswith("../")
        or payload.startswith("/")
        or payload not in inventory["sources"]
    ):
        return None
    return dict(
        schema="factory.security.captured-file-program-context.v1",
        role="CAPTURED_SOURCE_FILE_PROGRAM_INPUT",
        tier="NEEDS_CONTEXT",
        source_path=path,
        source_sha256=hashlib.sha256(inventory["sources"][path]).hexdigest(),
        sources_sha256=inventory["sources_sha256"],
        call_span=_fixed_program_span(sink),
        producer_spans=tracer.steps,
        payload_path=payload,
        payload_sha256=hashlib.sha256(inventory["sources"][payload]).hexdigest(),
        runtime_file_authority="UNASSESSED",
        program_effects="UNASSESSED",
        safe_execution=False,
        target_execution="not_performed",
        original_severity=finding.get("severity"),
    )


def _captured_file_program_context(finding, inventory, path, binding_occurrences):
    if (
        finding.get("code") != "SECURITY_DYNAMIC_EXECUTION"
        or path not in inventory["trees"]
    ):
        return None
    tree = inventory["trees"][path]
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    span = (finding.get("line"), finding.get("column", 0))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and (node.lineno, node.col_offset) == span
    ]
    if len(calls) != 1 or not isinstance(calls[0].func, ast.Name):
        return None
    sink = calls[0]
    if sink.func.id != "exec" or not sink.args or sink.keywords or len(sink.args) > 3:
        return None
    scopes = [tree]
    current = sink
    while current in parents:
        current = parents[current]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scopes.insert(0, current)
            break
    from .review_audits import _security_aliases

    aliases = _security_aliases(tree.body)
    protected = {"exec", "compile", "open", "__file__", "__builtins__"}
    provider_roots = {
        name
        for name, value in aliases.items()
        if value in {"os", "os.path", "pathlib", "pathlib.Path"}
    }
    if not _captured_file_provider_guard(
        tree, sink, parents, scopes, protected, provider_roots
    ):
        return None
    return path, tree, parents, sink, scopes, aliases


def _captured_file_provider_guard(
    tree, sink, parents, scopes, protected, provider_roots
):
    return all(
        _captured_file_provider_node_clear(
            node, tree, sink, parents, scopes, protected, provider_roots
        )
        for node in ast.walk(tree)
    )


def _captured_file_provider_node_clear(
    node, tree, sink, parents, scopes, protected, provider_roots
):
    protected_names = protected | provider_roots
    if (
        isinstance(node, ast.Name)
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node.id in protected_names
    ):
        return False
    if isinstance(node, ast.arg) and node.arg in protected_names:
        return False
    if (
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.name in protected_names
    ):
        return False
    if isinstance(node, ast.ImportFrom) and any(
        item.name == "*" for item in node.names
    ):
        if scopes[0] is not tree or node.lineno <= sink.lineno:
            return False
    if isinstance(
        node, (ast.Import, ast.ImportFrom)
    ) and _captured_file_import_conflict(node, tree, protected, provider_roots):
        return False
    if _captured_file_reflective_call(node, sink, parents, scopes):
        return False
    if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
        node.ctx, (ast.Store, ast.Del)
    ):
        return not any(
            isinstance(part, ast.Name) and part.id in provider_roots | {"__builtins__"}
            for part in ast.walk(node)
        )
    return True


def _captured_file_import_conflict(node, tree, protected, provider_roots):
    return any(
        (item.asname or item.name.split(".")[0]) in protected
        or node not in tree.body
        and (item.asname or item.name.split(".")[0]) in provider_roots
        or item.name == "builtins"
        or isinstance(node, ast.ImportFrom)
        and node.module == "builtins"
        for item in node.names
    )


def _captured_file_reflective_call(node, sink, parents, scopes):
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id
        in {"globals", "locals", "vars", "setattr", "delattr", "__import__"}
    ):
        return False
    owner = parents.get(node)
    while owner is not None and not isinstance(
        owner, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        owner = parents.get(owner)
    return node not in sink.args[1:] and node.lineno <= sink.lineno and owner in scopes


def _captured_read_binding(
    node,
    seen,
    scopes,
    tree,
    sink,
    parents,
    preceding,
    steps,
    read_input,
    binding_occurrences,
):
    for scope in scopes:
        matches = binding_occurrences(scope.body, node.id)
        if scopes[0] is tree:
            matches = [item for item in matches if item.lineno < sink.lineno]
        if not matches:
            continue
        if len(matches) != 1 or not isinstance(matches[0], ast.Name):
            return None
        owner = parents.get(matches[0])
        if (
            not isinstance(owner, (ast.Assign, ast.AnnAssign))
            or not preceding(owner, scope)
            or node.id in seen
        ):
            return None
        targets = owner.targets if isinstance(owner, ast.Assign) else [owner.target]
        if len(targets) != 1 or targets[0] is not matches[0]:
            return None
        steps.append(_fixed_program_span(owner))
        return read_input(owner.value, seen | {node.id})
    return None


def _captured_read_call(node, seen, resolve, read_input, callee, sink, parents):
    if node.keywords:
        return None
    if (
        callee(node.func) == "compile"
        and len(node.args) == 3
        and isinstance(node.args[2], ast.Constant)
        and node.args[2].value == "exec"
    ):
        return read_input(node.args[0], seen)
    if not isinstance(node.func, ast.Attribute) or node.args:
        return None
    if node.func.attr == "read_text":
        return resolve(node.func.value)
    if node.func.attr != "read" or not isinstance(node.func.value, ast.Name):
        return None
    return _captured_read_handle(node, sink, parents, callee, resolve)


def _captured_read_handle(node, sink, parents, callee, resolve):
    handle = node.func.value.id
    ancestors, current = [], sink
    while current in parents:
        current = parents[current]
        ancestors.append(current)
    handles = [
        item
        for owner in ancestors
        if isinstance(owner, ast.With)
        for item in owner.items
        if isinstance(item.optional_vars, ast.Name) and item.optional_vars.id == handle
    ]
    if len(handles) != 1:
        return None
    scope = next(
        owner
        for owner in ancestors
        if isinstance(owner, ast.With) and handles[0] in owner.items
    )
    if not _captured_handle_uses_closed(scope, handles[0], handle, node, parents):
        return None
    return _captured_open_path(handles[0].context_expr, callee, resolve)


def _captured_handle_uses_closed(scope, binding, handle, node, parents):
    for part in ast.walk(scope):
        if (
            isinstance(part, ast.Name)
            and part.id == handle
            and isinstance(part.ctx, (ast.Store, ast.Del))
            and part is not binding.optional_vars
        ):
            return False
        if (
            isinstance(part, (ast.Attribute, ast.Subscript))
            and isinstance(part.ctx, (ast.Store, ast.Del))
            and any(
                isinstance(name, ast.Name) and name.id == handle
                for name in ast.walk(part)
            )
        ):
            return False
        if (
            isinstance(part, ast.Name)
            and part.id == handle
            and isinstance(part.ctx, ast.Load)
            and not (parents.get(part) is node.func and node.func.value is part)
        ):
            return False
    return True


def _captured_open_path(opened, callee, resolve):
    if not isinstance(opened, ast.Call) or opened.keywords:
        return None
    if callee(opened.func) == "open" and len(opened.args) in {1, 2}:
        if len(opened.args) == 2 and not (
            isinstance(opened.args[1], ast.Constant)
            and opened.args[1].value in {"r", "rt"}
        ):
            return None
        return resolve(opened.args[0])
    if (
        isinstance(opened.func, ast.Attribute)
        and opened.func.attr == "open"
        and not opened.args
    ):
        return resolve(opened.func.value)
    return None


def source_built_ast_workspace_provider_clear(sources, source_path, root=None):
    """Require source-visible AST and builtin providers to have closed import/write paths."""
    if (
        not isinstance(sources, dict)
        or not isinstance(source_path, str)
        or len(sources) > 2048
    ):
        return False
    from .credential_role_constructor_provider import _SourceBuiltAstWorkspace

    workspace = _SourceBuiltAstWorkspace(sources, source_path, root)
    return (
        workspace.capture_sources()
        and workspace.close_aliases()
        and workspace.close_writes()
        and workspace.unique_target()
    )


def _source_built_ast_module_alias(node, aliases):
    """Recognize module capabilities without confusing parsed AST nodes for providers."""
    if isinstance(node, ast.Name):
        return node.id in aliases
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name):
            return (
                node.value.id in aliases
                and node.value.id not in {"ast", "builtins", "__builtins__"}
                and node.attr == "ast"
            )
        return _source_built_ast_module_alias(node.value, aliases)
    if isinstance(node, ast.Subscript):
        if (
            isinstance(node.value, ast.Attribute)
            and ast.unparse(node.value) == "sys.modules"
            and isinstance(node.slice, ast.Constant)
            and node.slice.value in {"ast", "builtins", "werkzeug.routing.rules"}
        ):
            return True
        return _source_built_ast_module_alias(node.value, aliases)
    if isinstance(node, ast.Call):
        name = ast.unparse(node.func)
        return bool(
            node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and node.args[0].value in {"ast", "builtins", "werkzeug.routing.rules"}
            and (name == "__import__" or name.endswith(".import_module"))
        )
    return False


def _source_built_ast_provider_expr(node, rule_module_aliases):
    names = {"ast", "builtins", "__builtins__", *rule_module_aliases}
    parts = list(ast.walk(node))
    if any(isinstance(item, ast.Name) and item.id in names for item in parts):
        return True
    if any(
        isinstance(item, ast.Attribute)
        and item.attr == "modules"
        and isinstance(item.value, ast.Name)
        and item.value.id == "sys"
        for item in parts
    ):
        return True
    return any(
        isinstance(item, ast.Call)
        and (
            ast.unparse(item.func) == "__import__"
            or ast.unparse(item.func).endswith(".import_module")
        )
        for item in parts
    )


def _source_built_ast_sensitive_attribute(node):
    return isinstance(node, ast.Constant) and node.value in {
        "compile",
        "exec",
        "parse",
        "walk",
        "FunctionDef",
        "Call",
        "Name",
        "Constant",
        "Return",
        "Tuple",
        "JoinedStr",
        "_get_func_code",
        "_prefix_names",
        "_IF_KWARGS_URL_ENCODE_AST",
        "_URL_ENCODE_AST_NAMES",
    }


def _source_built_ast_scope(node, parents):
    current = parents.get(node)
    while current is not None and not isinstance(
        current, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        current = parents.get(current)
    return current


def _source_built_ast_sink(function, node):
    expected = ast.parse(
        "@staticmethod\n"
        "def _get_func_code(code: CodeType, name: str) -> t.Callable[..., tuple[str, str]]:\n"
        " globs: dict[str, t.Any] = {}\n locs: dict[str, t.Any] = {}\n"
        " exec(code, globs, locs)\n return locs[name]\n"
    ).body[0]
    return bool(
        ast.dump(function, include_attributes=False)
        == ast.dump(expected, include_attributes=False)
        and len(function.decorator_list) == 1
        and isinstance(function.decorator_list[0], ast.Name)
        and function.decorator_list[0].id == "staticmethod"
        and any(item is node for item in ast.walk(function))
    )


def _source_built_ast_builder(tree, builder, sink, parents):
    if (
        not isinstance(builder, ast.FunctionDef)
        or builder.decorator_list
        or ast.unparse(builder.returns) != "t.Callable[..., tuple[str, str]]"
    ):
        return False

    def name(item):
        return ast.unparse(item.func) if isinstance(item, ast.Call) else ""

    calls = [item for item in ast.walk(tree) if isinstance(item, ast.Call)]
    helper_calls = [item for item in calls if name(item).endswith("_get_func_code")]
    compile_calls = [item for item in calls if name(item) == "compile"]
    if (
        len(helper_calls) != 1
        or len(compile_calls) != 1
        or _source_built_ast_scope(helper_calls[0], parents) is not builder
        or not isinstance(helper_calls[0].func, ast.Attribute)
        or ast.unparse(helper_calls[0]) != "self._get_func_code(code, func_ast.name)"
        or not isinstance(helper_calls[0], ast.Call)
        or helper_calls[0]
        not in [item for item in ast.walk(builder) if isinstance(item, ast.Call)]
        or not isinstance(parents.get(helper_calls[0]), ast.Return)
        or parents[helper_calls[0]].value is not helper_calls[0]
    ):
        return False
    compiled = compile_calls[0]
    if (
        _source_built_ast_scope(compiled, parents) is not builder
        or ast.unparse(compiled) != "compile(module, '<werkzeug routing>', 'exec')"
        or not isinstance(compiled.args[0], ast.Name)
        or compiled.args[0].id != "module"
        or not isinstance(parents.get(compiled), ast.Assign)
        or len(parents[compiled].targets) != 1
        or not isinstance(parents[compiled].targets[0], ast.Name)
        or parents[compiled].targets[0].id != "code"
    ):
        return False
    if not any(
        isinstance(item, ast.Assign)
        and len(item.targets) == 1
        and isinstance(item.targets[0], ast.Name)
        and item.targets[0].id == "module"
        and ast.unparse(item.value) == "ast.parse('')"
        for item in ast.walk(builder)
    ):
        return False
    if not any(
        isinstance(item, ast.Assign)
        and isinstance(item.targets[0], ast.Attribute)
        and ast.unparse(item.targets[0]) == "module.body"
        and ast.unparse(item.value) == "[func_ast]"
        for item in ast.walk(builder)
        if isinstance(item, ast.Assign) and len(item.targets) == 1
    ):
        return False
    if not any(
        isinstance(item, ast.Assign)
        and isinstance(item.targets[0], ast.Name)
        and item.targets[0].id == "func_ast"
        and ast.unparse(item.value) == "_prefix_names('def _(): pass', ast.FunctionDef)"
        for item in ast.walk(builder)
        if isinstance(item, ast.Assign) and len(item.targets) == 1
    ):
        return False
    if not _source_built_ast_effects_closed(tree, builder, sink, parents):
        return False
    if not _source_built_ast_owned_values(builder, compiled, parents):
        return False
    return True


def _source_built_ast_owned_values(builder, compiled, parents):
    """Keep generated code and its AST inputs under one closed set of writes."""
    writes = [
        item
        for item in ast.walk(builder)
        if isinstance(item, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr))
    ]

    def targets(statement):
        if isinstance(statement, ast.Assign):
            return statement.targets
        if isinstance(statement, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            return [statement.target]
        return []

    def name_writes(name):
        return [
            statement
            for statement in writes
            if any(
                isinstance(target, ast.Name) and target.id == name
                for target in targets(statement)
            )
        ]

    def exact_name_write(name, value):
        found = name_writes(name)
        return len(found) == 1 and ast.unparse(found[0].value) == value

    if not (
        exact_name_write("code", "compile(module, '<werkzeug routing>', 'exec')")
        and name_writes("code")[0].value is compiled
        and exact_name_write("module", "ast.parse('')")
        and exact_name_write(
            "func_ast", "_prefix_names('def _(): pass', ast.FunctionDef)"
        )
    ):
        return False

    return _source_built_ast_owned_mutations_closed(writes, compiled)


def _source_built_ast_owned_mutations_closed(writes, compiled):
    """Close writes and aliases over the owned generated AST objects."""
    observed = _source_built_ast_observed_writes(writes)
    allowed = {
        "module.body": 1,
        "func_ast.name": 1,
        "func_ast.args.kwarg": 1,
        "func_ast.body": 1,
    }
    if observed is None or observed != allowed:
        return False
    return _source_built_ast_aliases_closed(writes, compiled)


def _source_built_ast_targets(statement):
    if isinstance(statement, ast.Assign):
        return statement.targets
    if isinstance(statement, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
        return [statement.target]
    return []


def _source_built_ast_observed_writes(writes):
    observed = {}
    for statement in writes:
        for root in _source_built_ast_targets(statement):
            for target in ast.walk(root):
                if isinstance(target, ast.Attribute) and isinstance(
                    target.ctx, (ast.Store, ast.Del)
                ):
                    text = ast.unparse(target)
                    if text.startswith(("module", "func_ast")):
                        observed[text] = observed.get(text, 0) + 1
                if isinstance(target, ast.Subscript) and isinstance(
                    target.ctx, (ast.Store, ast.Del)
                ):
                    if any(
                        isinstance(part, ast.Name)
                        and part.id in {"module", "func_ast", "code"}
                        for part in ast.walk(target.value)
                    ):
                        return None
    return observed


def _source_built_ast_aliases_closed(writes, compiled):
    # Reject copied aliases of owned objects. Their later mutation or use in a
    # different call would otherwise escape the local write inventory.
    for statement in writes:
        value = getattr(statement, "value", None)
        if value is None:
            continue
        owned_loads = {
            item.id
            for item in ast.walk(value)
            if isinstance(item, ast.Name)
            and isinstance(item.ctx, ast.Load)
            and item.id in {"module", "func_ast", "code"}
        }
        if owned_loads and not (
            statement.value is compiled
            or isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and ast.unparse(statement.targets[0]) == "module.body"
            and ast.unparse(value) == "[func_ast]"
        ):
            return False
    return True


def _source_built_ast_initial_mutations_closed(tree):
    module_ast_imports = [
        item
        for item in tree.body
        if isinstance(item, ast.Import)
        and any(alias.name == "ast" and alias.asname is None for alias in item.names)
    ]
    if len(module_ast_imports) != 1:
        return False
    if any(
        isinstance(item, ast.Name)
        and item.id in {"ast", "compile", "exec"}
        and isinstance(item.ctx, (ast.Store, ast.Del))
        for item in ast.walk(tree)
    ):
        return False
    if any(
        isinstance(item, ast.Attribute)
        and item.attr
        in {
            "parse",
            "walk",
            "FunctionDef",
            "arg",
            "Call",
            "Name",
            "Constant",
            "Load",
            "Return",
            "Tuple",
            "JoinedStr",
            "If",
        }
        and isinstance(item.ctx, (ast.Store, ast.Del))
        for item in ast.walk(tree)
    ):
        return False
    if any(
        isinstance(item, ast.Attribute)
        and isinstance(item.ctx, (ast.Store, ast.Del))
        and (
            isinstance(item.value, ast.Name)
            and item.value.id == "ast"
            or isinstance(item.value, ast.Name)
            and item.value.id == "func_ast"
            and item.attr not in {"name", "args", "body"}
            or isinstance(item.value, ast.Name)
            and item.value.id == "module"
            and item.attr != "body"
            or isinstance(item.value, ast.Name)
            and item.value.id == "ret"
            and item.attr != "args"
        )
        for item in ast.walk(tree)
    ):
        return False
    return True


def _source_built_ast_prefix_closed(tree):
    prefix = [
        item
        for item in ast.walk(tree)
        if isinstance(item, ast.FunctionDef) and item.name == "_prefix_names"
    ]
    expected_prefix = ast.parse('''
def _prefix_names(src: str, expected_type: type[_ASTT]) -> _ASTT:
    """ast parse and prefix names with `.` to avoid collision with user vars"""
    tree: ast.AST = ast.parse(src).body[0]
    if isinstance(tree, ast.Expr):
        tree = tree.value
    if not isinstance(tree, expected_type):
        raise TypeError(f"AST node is of type {type(tree).__name__}, not {expected_type.__name__}")
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            node.id = f".{node.id}"
    return tree
''').body[0]
    if len(prefix) != 1 or ast.dump(prefix[0], include_attributes=False) != ast.dump(
        expected_prefix, include_attributes=False
    ):
        return False
    prefix_calls = [
        item
        for item in ast.walk(tree)
        if isinstance(item, ast.Call) and ast.unparse(item.func) == "_prefix_names"
    ]
    expected_prefix_calls = {
        "_prefix_names(_IF_KWARGS_URL_ENCODE_CODE, ast.If)",
        "_prefix_names('q', ast.Name)",
        "_prefix_names('params', ast.Name)",
        "_prefix_names(_CALL_CONVERTER_CODE_FMT.format(elem=elem), ast.Call)",
        "_prefix_names('def _(): pass', ast.FunctionDef)",
    }
    if (
        len(prefix_calls) != len(expected_prefix_calls)
        or {ast.unparse(item) for item in prefix_calls} != expected_prefix_calls
    ):
        return False
    return True


def _source_built_ast_builder_conforms(tree, builder, parents):
    nested = [item for item in builder.body if isinstance(item, ast.FunctionDef)]
    if {item.name for item in nested} != {"_convert", "_parts", "_join"} or len(
        nested
    ) != 3:
        return False
    if any(
        item.decorator_list
        or item.args.defaults
        or item.args.kw_defaults
        or item.args.kwarg is not None
        or item.args.vararg is not None
        or not _source_built_ast_annotations_static(item)
        for item in nested
    ):
        return False
    body_assignments = [
        item
        for item in ast.walk(builder)
        if isinstance(item, ast.Assign)
        and len(item.targets) == 1
        and isinstance(item.targets[0], ast.Name)
        and item.targets[0].id == "body"
    ]
    if len(body_assignments) != 2 or {
        ast.unparse(item) for item in body_assignments
    } != {
        "body = []",
        "body = [_IF_KWARGS_URL_ENCODE_AST]",
    }:
        return False
    if not any(
        isinstance(item, ast.Assign)
        and len(item.targets) == 1
        and isinstance(item.targets[0], ast.Attribute)
        and ast.unparse(item.targets[0]) == "func_ast.body"
        and ast.unparse(item.value) == "body"
        for item in ast.walk(builder)
    ):
        return False
    if not any(
        isinstance(item, ast.Assign)
        and len(item.targets) == 1
        and isinstance(item.targets[0], ast.Attribute)
        and ast.unparse(item.targets[0]) == "func_ast.args.kwarg"
        and ast.unparse(item.value) == "ast.arg('.kwargs', None)"
        for item in ast.walk(builder)
    ):
        return False
    if not any(
        isinstance(item, ast.Assign)
        and len(item.targets) == 1
        and isinstance(item.targets[0], ast.Attribute)
        and ast.unparse(item.targets[0]) == "func_ast.name"
        and ast.unparse(item.value) == "f'<builder:{self.rule!r}>'"
        for item in ast.walk(builder)
    ):
        return False
    generated_defaults = [
        item
        for item in ast.walk(builder)
        if isinstance(item, ast.Call)
        and ast.unparse(item.func) == "func_ast.args.defaults.append"
    ]
    if (
        len(generated_defaults) != 1
        or ast.unparse(generated_defaults[0])
        != "func_ast.args.defaults.append(ast.Constant(''))"
    ):
        return False
    generated_args = [
        item
        for item in ast.walk(builder)
        if isinstance(item, ast.Call)
        and ast.unparse(item.func) == "func_ast.args.args.append"
    ]
    if {ast.unparse(item) for item in generated_args} != {
        "func_ast.args.args.append(ast.arg('.self', None))",
        "func_ast.args.args.append(ast.arg(arg, None))",
    } or len(generated_args) != 2:
        return False
    return True


def _source_built_ast_workspace_contract(tree, builder, parents):
    for global_name in {"_IF_KWARGS_URL_ENCODE_AST", "_URL_ENCODE_AST_NAMES"}:
        writes = [
            item
            for item in ast.walk(tree)
            if isinstance(item, ast.Name)
            and item.id == global_name
            and isinstance(item.ctx, (ast.Store, ast.Del))
        ]
        if len(writes) != 1 or not isinstance(parents.get(writes[0]), ast.Assign):
            return False
    parse_calls = [
        item
        for item in ast.walk(tree)
        if isinstance(item, ast.Call) and ast.unparse(item.func) == "ast.parse"
    ]
    if {ast.unparse(item) for item in parse_calls} != {
        "ast.parse(src)",
        "ast.parse('')",
    } or len(parse_calls) != 2:
        return False
    if (
        len(
            [
                item
                for item in ast.walk(tree)
                if isinstance(item, ast.Call)
                and isinstance(item.func, ast.Name)
                and item.func.id == "exec"
            ]
        )
        != 1
    ):
        return False
    if (
        len(
            [
                item
                for item in ast.walk(tree)
                if isinstance(item, ast.FunctionDef) and item.name == "_get_func_code"
            ]
        )
        != 1
    ):
        return False
    if any(
        isinstance(item, ast.Attribute)
        and item.attr in {"_get_func_code", "_compile_builder"}
        and isinstance(item.ctx, (ast.Store, ast.Del))
        for item in ast.walk(tree)
    ):
        return False
    return True


def _source_built_ast_effects_closed(tree, builder, sink, parents):
    if not _source_built_ast_declaration_contract(tree):
        return False
    if not _source_built_ast_workspace_contract(tree, builder, parents):
        return False
    if not _source_built_ast_constants(tree, builder, parents):
        return False
    if not _source_built_ast_builder_conforms(tree, builder, parents):
        return False
    nested = [item for item in builder.body if isinstance(item, ast.FunctionDef)]
    if any(
        isinstance(item, ast.Call)
        and ast.unparse(item.func) == "ast.parse"
        and _source_built_ast_scope(item, parents) in {builder, *nested}
        and ast.unparse(item) != "ast.parse('')"
        for item in ast.walk(builder)
    ):
        return False
    builder_scopes = {builder, *nested}
    for item in ast.walk(builder):
        if (
            isinstance(item, ast.Call)
            and _source_built_ast_scope(item, parents) in builder_scopes
        ):
            callee = ast.unparse(item.func)
            if callee in {"compile", "self._get_func_code"}:
                continue
            if callee not in {
                "_parts",
                "_join",
                "body.append",
                "_prefix_names",
                "ast.parse",
                "ast.walk",
                "ast.arg",
                "func_ast.args.args.append",
                "func_ast.args.defaults.append",
                "ast.Constant",
                "ast.Name",
                "ast.Load",
                "ast.JoinedStr",
                "ast.Return",
                "ast.Tuple",
                "str",
                "quote",
                "self._converters[data].to_url",
                "_CALL_CONVERTER_CODE_FMT.format",
                "_convert",
                "len",
                "isinstance",
                "opl.append",
                "ret.append",
                "url_parts.extend",
            }:
                return False
    return True


def _source_built_ast_declaration_contract(tree):
    return _source_built_ast_initial_mutations_closed(
        tree
    ) and _source_built_ast_prefix_closed(tree)


def _source_built_ast_annotations_static(function):
    allowed = (
        ast.Name,
        ast.Attribute,
        ast.Subscript,
        ast.Tuple,
        ast.Constant,
        ast.Load,
    )
    annotations = [
        arg.annotation
        for arg in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
        if arg.annotation is not None
    ]
    annotations.extend(
        item
        for item in (function.args.vararg, function.args.kwarg)
        if item is not None
        for item in (item.annotation,)
    )
    annotations.extend(item for item in (function.returns,) if item is not None)
    return all(
        all(isinstance(node, allowed) for node in ast.walk(annotation))
        for annotation in annotations
    )


def _source_built_ast_constants(tree, builder, parents):
    values = {}
    for item in tree.body:
        if (
            isinstance(item, ast.Assign)
            and len(item.targets) == 1
            and isinstance(item.targets[0], ast.Name)
        ):
            try:
                values[item.targets[0].id] = ast.literal_eval(item.value)
            except (ValueError, TypeError):
                pass
    if values.get("_CALL_CONVERTER_CODE_FMT") != "self._converters[{elem!r}].to_url()":
        return False
    expected = (
        "if kwargs:\n"
        "    params = self._encode_query_vars(kwargs)\n"
        '    q = "?" if params else ""\n'
        "else:\n"
        '    q = params = ""\n'
    )
    if values.get("_IF_KWARGS_URL_ENCODE_CODE") != expected:
        return False
    if (
        len(
            [
                item
                for item in tree.body
                if isinstance(item, ast.Assign)
                and len(item.targets) == 1
                and isinstance(item.targets[0], ast.Name)
                and item.targets[0].id == "_CALL_CONVERTER_CODE_FMT"
            ]
        )
        != 1
    ):
        return False
    rule_re = next(
        (
            item
            for item in tree.body
            if isinstance(item, ast.Assign)
            and len(item.targets) == 1
            and isinstance(item.targets[0], ast.Name)
            and item.targets[0].id == "_part_re"
        ),
        None,
    )
    if (
        rule_re is None
        or not isinstance(rule_re.value, ast.Call)
        or ast.unparse(rule_re.value.func) != "re.compile"
    ):
        return False
    pattern = rule_re.value.args[0] if rule_re.value.args else None
    if (
        not isinstance(pattern, ast.Constant)
        or type(pattern.value) is not str
        or not re.search(r"\(\?P<variable>\[a-zA-Z_\]\[a-zA-Z0-9_\]\*\)", pattern.value)
    ):
        return False
    return True


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
    node,
    aliases,
    audit,
    parents,
    bindings,
    facts,
    capture_predicate,
    argument_predicate,
):
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
        _record_provider_paths(node.value, node.attr, aliases, audit, bindings, facts)
    elif isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
        _record_provider_paths(node.value, "*", aliases, audit, bindings, facts)
    elif isinstance(node, ast.Call):
        _reflective_provider_write(node, aliases, audit, bindings, facts)
    elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
        if capture_predicate is None or capture_predicate(node):
            _record_provider_capture(node, aliases, audit, bindings, facts)
    elif isinstance(node, (ast.Name, ast.Attribute)) and _provider_call_argument(
        node, parents
    ):
        if argument_predicate is None or argument_predicate(node, aliases, parents):
            _record_provider_paths(node, "*", aliases, audit, bindings, facts)
    elif isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)):
        _record_provider_paths(node.value, "*", aliases, audit, bindings, facts)


def finite_provider_mutation_index(
    nodes,
    aliases,
    audit,
    parents,
    *,
    capture_predicate=None,
    argument_predicate=None,
    inventory_projector=None,
    inventory_dependencies=(),
):
    """Collect provider mutation facts from writes, reflective calls, captured assignments, passed aliases, and returned aliases."""
    nodes = tuple(nodes)
    bindings = _provider_alias_bindings(nodes)
    facts = set()
    _provider_mutation_facts(
        nodes,
        aliases,
        audit,
        parents,
        bindings,
        facts,
        capture_predicate,
        argument_predicate,
    )
    facts.update(
        _foreign_provider_mutation_facts(
            nodes,
            aliases,
            audit,
            capture_predicate,
            argument_predicate,
            inventory_projector,
            inventory_dependencies,
        )
    )
    return facts


def _foreign_provider_mutation_facts(
    nodes,
    aliases,
    audit,
    capture_predicate,
    argument_predicate,
    inventory_projector,
    inventory_dependencies,
):
    facts = set()
    module = next((node for node in nodes if isinstance(node, ast.Module)), None)
    context = getattr(module, "_security_source_context", None)
    current_hash = getattr(module, "_oracle_source_sha256", None)
    if isinstance(context, tuple) and len(context) == 2 and current_hash:
        _, sources = context
        if isinstance(sources, dict):
            from .review_audits import _security_aliases

            if len(sources) > 2048:
                facts.update((path.partition(".")[0], "*") for path in aliases.values())
            total = 0
            for source_path, source in () if len(sources) > 2048 else sources.items():
                if not str(source_path).lower().endswith(".py"):
                    continue
                data = _foreign_provider_source_bytes(source)
                if data is None:
                    facts.update(
                        (path.partition(".")[0], "*") for path in aliases.values()
                    )
                    continue
                total += len(data)
                if total > 64 * 1024 * 1024:
                    facts.update(
                        (path.partition(".")[0], "*") for path in aliases.values()
                    )
                    break
                source_hash = hashlib.sha256(data).hexdigest()
                if source_hash == current_hash:
                    continue
                facts.update(
                    _foreign_provider_source_mutations(
                        module,
                        data,
                        source_hash,
                        audit,
                        aliases,
                        _security_aliases,
                        capture_predicate,
                        argument_predicate,
                        inventory_projector,
                        inventory_dependencies,
                    )
                )
    return facts


def _foreign_provider_source_bytes(source):
    try:
        data = source.encode() if isinstance(source, str) else source
    except (UnicodeError, AttributeError, TypeError, ValueError):
        return None
    return data if isinstance(data, bytes) else None


def _foreign_provider_source_mutations(
    module,
    data,
    source_hash,
    audit,
    aliases,
    alias_reader,
    capture_predicate,
    argument_predicate,
    inventory_projector,
    inventory_dependencies,
):
    split_capture = (
        capture_predicate is not None
        and argument_predicate is None
        and inventory_projector is None
    )
    try:
        cache, key = _foreign_provider_mutation_cache(
            module,
            source_hash,
            audit,
            alias_reader,
            None if split_capture else capture_predicate,
            argument_predicate,
            inventory_projector,
            inventory_dependencies,
        )
        key = ("capture-independent", key) if split_capture else key
        if cache is not None and key in cache and not split_capture:
            return cache[key]
        nodes, foreign_aliases, parents, bindings = _foreign_provider_inputs(
            module, data, source_hash, alias_reader
        )
    except (SyntaxError, UnicodeError, AttributeError, TypeError, ValueError):
        return {(path.partition(".")[0], "*") for path in aliases.values()}
    nodes, bindings = _project_provider_inventory(
        nodes, foreign_aliases, parents, bindings, inventory_projector
    )
    captures = ()
    if split_capture:
        assignment = (ast.Assign, ast.AnnAssign, ast.NamedExpr)
        captures = tuple(node for node in nodes if isinstance(node, assignment))
        nodes = tuple(node for node in nodes if not isinstance(node, assignment))
    facts = set()
    if cache is not None and key in cache:
        facts.update(cache[key])
    else:
        _provider_mutation_facts(
            nodes,
            foreign_aliases,
            audit,
            parents,
            bindings,
            facts,
            capture_predicate,
            argument_predicate,
        )
        if cache is not None and len(cache) < 4096:
            cache[key] = frozenset(facts)
    if split_capture:
        # Full original bindings/parents are needed even for this event subset.
        _provider_mutation_facts(
            captures,
            foreign_aliases,
            audit,
            parents,
            bindings,
            facts,
            capture_predicate,
            argument_predicate,
        )
    return facts


def _project_provider_inventory(nodes, aliases, parents, bindings, projector):
    if projector is None or not nodes:
        return nodes, bindings
    tree = next(n for n in parents.values() if isinstance(n, ast.Module))
    from . import intent_quality as contracts
    from .semantic_credential_sensor import _new_security_request_alias_memo

    token = contracts._SECURITY_REQUEST_ALIAS_MEMO.set(
        _new_security_request_alias_memo(tree)
    )
    try:
        nodes = projector(tree, aliases, list(ast.walk(tree)))
    finally:
        contracts._SECURITY_REQUEST_ALIAS_MEMO.reset(token)
    return nodes, _provider_alias_bindings(nodes)


def _foreign_provider_inputs(module, data, source_hash, aliases):
    """Reuse native parse inputs; predicates and mutation interpretation still run."""
    context = getattr(module, "_security_oracle_context", {})
    cache = (
        context.get("_security_provider_mutation_cache")
        if isinstance(context, dict)
        else None
    )
    helpers = (
        ast.parse,
        ast.walk,
        ast.iter_child_nodes,
        aliases,
        _provider_alias_bindings,
        _provider_call_argument,
    )
    key = (
        "parsed",
        source_hash,
        tuple(
            (fn, getattr(fn, "__code__", None), id(getattr(fn, "__defaults__", None)))
            for fn in helpers
        ),
    )
    if isinstance(cache, dict) and key in cache:
        return cache[key]
    nodes = tuple(ast.walk(ast.parse(data.decode("utf-8"))))
    parents = {
        id(child): node for node in nodes for child in ast.iter_child_nodes(node)
    }
    events = tuple(
        node
        for node in nodes
        if isinstance(
            node,
            (
                ast.Call,
                ast.Assign,
                ast.AnnAssign,
                ast.NamedExpr,
                ast.Return,
                ast.Yield,
                ast.YieldFrom,
            ),
        )
        or isinstance(node, (ast.Attribute, ast.Subscript))
        and isinstance(node.ctx, (ast.Store, ast.Del))
        or isinstance(node, (ast.Name, ast.Attribute))
        and _provider_call_argument(node, parents)
    )
    # Keep source order and reevaluate every predicate; only inert nodes are omitted.
    result = (events, aliases(nodes), parents, _provider_alias_bindings(nodes))
    if isinstance(cache, dict) and len(cache) < 4096:
        cache[key] = result
    return result


def _foreign_provider_mutation_cache(
    module,
    source_hash,
    audit,
    aliases,
    capture,
    argument,
    inventory_projector=None,
    inventory_dependencies=(),
):
    """Reuse only unpredicated, content-bound facts inside one native scan."""
    context = getattr(module, "_security_oracle_context", {})
    cache = (
        context.get("_security_provider_mutation_cache")
        if isinstance(context, dict)
        else None
    )
    if capture is not None or argument is not None or not isinstance(cache, dict):
        return None, None
    helpers = (
        ast.parse,
        ast.walk,
        ast.iter_child_nodes,
        aliases,
        audit._resolved_ast_name,
        _provider_mutation_facts,
        _provider_mutation_for_node,
        _record_provider_paths,
        _record_provider_capture,
        _provider_alias_bindings,
        _provider_paths,
        _provider_call_argument,
        _reflective_provider_write,
        _foreign_provider_inputs,
        _project_provider_inventory,
    )
    identity = tuple(
        (
            helper,
            getattr(helper, "__code__", None),
            id(getattr(helper, "__defaults__", None)),
        )
        for helper in helpers
    )
    projector_identity = (
        inventory_projector,
        getattr(inventory_projector, "__code__", None),
        inventory_dependencies,
    )
    return cache, (source_hash, identity, projector_identity)


def _provider_mutation_facts(
    nodes, aliases, audit, parents, bindings, facts, predicate, argument_predicate
):
    for node in nodes:
        _provider_mutation_for_node(
            node,
            aliases,
            audit,
            parents,
            bindings,
            facts,
            predicate,
            argument_predicate,
        )


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
        if isinstance(node, ast.Subscript):
            paths, _ = _provider_paths(
                node.value, aliases, audit, bindings, seen, depth + 1
            )
            return paths, True
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


def _fixed_eval_workspace_python_rows(source_rows):
    if not isinstance(source_rows, list):
        return None
    python_rows = [
        row
        for row in source_rows
        if isinstance(row, dict)
        and isinstance(row.get("path"), str)
        and row["path"].endswith(".py")
    ]
    if not python_rows:
        return None
    expected = {row["path"]: row.get("sha256") for row in python_rows}
    if len(expected) != len(python_rows):
        return None
    return expected


def _fixed_eval_workspace_source_clear(relative, digest, source_bytes):
    raw = source_bytes.get(relative)
    if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != digest:
        return False
    try:
        tree = ast.parse(raw, filename=relative)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return False
    return not _fixed_eval_builtin_provider_risk(tree)


def fixed_eval_workspace_provider_clear(source_bytes, source_rows):
    """Recheck a complete hash-bound workspace for source-visible eval-provider mutation."""
    if not isinstance(source_bytes, dict):
        return False
    expected = _fixed_eval_workspace_python_rows(source_rows)
    if expected is None:
        return False
    for relative, digest in expected.items():
        if not _fixed_eval_workspace_source_clear(relative, digest, source_bytes):
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
        *_AST_TRY_NODES,
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


def _security_transfer_assignment_targets(
    statement, requests, value_kind, flags, known, upload_flags
):
    upload_object, upload_path, safe_upload_leaf = upload_flags
    targets = getattr(statement, "targets", None) or [statement.target]
    for target in targets:
        if isinstance(target, ast.Name):
            if value_kind is not None:
                requests.add(("request-type:" + value_kind, target.id))
            for tainted, names in zip(flags, known):
                if tainted:
                    names.add(target.id)
            if upload_object:
                requests.add(("flask-upload", target.id))
            if upload_path:
                requests.add(("upload-path", target.id))
            if safe_upload_leaf:
                requests.add(("secure-upload-leaf", target.id))


def _security_merge_exit_states(target, incoming):
    """Join reaching states only within the same kind of control-flow exit."""
    for kind, state in incoming.items():
        if kind not in target:
            target[kind] = [values.copy() for values in state]
        else:
            _security_merge_branch_states(target[kind], [target[kind], state])


def _security_merge_branch_states(target, branches):
    for index, values in enumerate(target):
        merged = set().union(*(branch[index] for branch in branches))
        if index == 0:
            _security_merge_structural_states(
                values, [branch[index] for branch in branches]
            )
            safe = set.intersection(*(branch[index] for branch in branches))
            unsafe_safety = {
                item
                for item in merged
                if isinstance(item, tuple)
                and item[0]
                in {"secure-upload-leaf", "request-type:bytes", "request-type:text"}
            } - safe
            merged.difference_update(unsafe_safety)
        values.clear()
        values.update(merged)
        if index == 0 and hasattr(values, "proven"):
            values.proven.intersection_update(merged)
