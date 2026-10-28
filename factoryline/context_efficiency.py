"""Deterministic, bounded context packets for fast agent hand-offs.

The packet is a read-only view of already-authorized local sources. It is not a gate, an approval token, or an instruction to execute anything. Sources are content-addressed and re-checked before use; cache reuse is exact and the token figure is explicitly an estimate (four UTF-8 bytes per token), never a usage claim."""

from __future__ import annotations

import ast
from collections.abc import Mapping
import hashlib
import io
import json
import os
import re
import sqlite3
import stat
import sys
import threading
import tokenize
from copy import deepcopy
from datetime import datetime, timezone
from math import ceil
from pathlib import Path
from statistics import median
from typing import Any, NoReturn
from .import_context import (
    application_configuration_names,
    application_profile_configuration,
)

from .context_protocol_audit import (
    protocol_call_context as protocol_call_context,
    _protocol_context_for_snapshot as _protocol_context_for_snapshot,
    _protocol_source_record as _protocol_source_record,
    _protocol_dependency as _protocol_dependency,
    _protocol_call_summary as _protocol_call_summary,
    _protocol_reachable_repr as _protocol_reachable_repr,
    _protocol_preceding_statement as _protocol_preceding_statement,
    _protocol_class_reference as _protocol_class_reference,
    _protocol_class_name as _protocol_class_name,
    _protocol_class_chain as _protocol_class_chain,
    _protocol_class_shape as _protocol_class_shape,
    _protocol_repr_method as _protocol_repr_method,
    _protocol_validate_repr_method as _protocol_validate_repr_method,
    _protocol_class_bound_names as _protocol_class_bound_names,
    _protocol_executed_nodes as _protocol_executed_nodes,
    _protocol_dependencies_closed as _protocol_dependencies_closed,
    _protocol_closed_nodes as _protocol_closed_nodes,
    _protocol_target_relevant as _protocol_target_relevant,
    _protocol_reference_use_closed as _protocol_reference_use_closed,
    _protocol_constructor_receiver_safe as _protocol_constructor_receiver_safe,
    _protocol_builtin_repr_closed as _protocol_builtin_repr_closed,
    _protocol_builtin_unshadowed as _protocol_builtin_unshadowed,
    _protocol_local_class as _protocol_local_class,
    _protocol_constructor_bindings_closed as _protocol_constructor_bindings_closed,
    _protocol_constructor_callee as _protocol_constructor_callee,
    protocol_call_helpers as protocol_call_helpers,
    _protocol_active_binding as _protocol_active_binding,
    _protocol_profile_truth as _protocol_profile_truth,
    _protocol_identity_decorator as _protocol_identity_decorator,
    _protocol_metadata_statement as _protocol_metadata_statement,
    _protocol_annotate_finding as _protocol_annotate_finding,
    _protocol_demand_summary as _protocol_demand_summary,
    _protocol_demand_visit as _protocol_demand_visit,
    _protocol_demand_target as _protocol_demand_target,
    _protocol_reachable_call as _protocol_reachable_call,
    _protocol_parameter_decorator as _protocol_parameter_decorator,
    _protocol_fresh_list_append as _protocol_fresh_list_append,
    _protocol_receiver_transfer as _protocol_receiver_transfer,
    _protocol_chain_bindings as _protocol_chain_bindings,
    _PROTOCOL_EXTERNAL_BINDINGS as _PROTOCOL_EXTERNAL_BINDINGS,
)

from .ops_telemetry import _measured_source_read
from .runtime_audit_common import RuntimeAuditError, canonical_bytes

from .runtime_audit_integrity import (
    _test_serialization_roundtrip as _test_serialization_roundtrip,
    _local_pickle_roundtrip as _local_pickle_roundtrip,
    _plain_scope_statement_index as _plain_scope_statement_index,
    _simple_scope_assignment as _simple_scope_assignment,
    _prior_pickle_dump as _prior_pickle_dump,
    _pickle_protocol_integer as _pickle_protocol_integer,
    _pickle_protocol_options_closed as _pickle_protocol_options_closed,
    _pickle_protocol_parameter as _pickle_protocol_parameter,
    _local_pickle_value as _local_pickle_value,
    _pickle_nested_effect as _pickle_nested_effect,
    _pickle_lambda_parameters as _pickle_lambda_parameters,
    _pickle_mentions as _pickle_mentions,
    _pickle_call_imported as _pickle_call_imported,
    _single_local_pickle_bytes_flow as _single_local_pickle_bytes_flow,
)
from .type_intent_provider_provenance import (
    bind_provider_context as bind_provider_context,
    provider_source_inventory as provider_source_inventory,
    bind_provider_inventory as bind_provider_inventory,
    provider_cache_fields as provider_cache_fields,
    _module_import_alias_candidates as _module_import_alias_candidates,
    _module_path_controls_target as _module_path_controls_target,
    _module_has_dynamic_capability_access as _module_has_dynamic_capability_access,
    _capability_reflection_names as _capability_reflection_names,
)

from .import_context import (
    _full_repository_workspace_cached_source_entry as _full_repository_workspace_cached_source_entry,
    _full_repository_workspace_cache_load_source as _full_repository_workspace_cache_load_source,
)

_FULL_REPOSITORY_WORKSPACE_PREFIX_CACHE = None
# 64 MiB source retention plus 16 MiB for measured cache rows and containers.
FULL_REPOSITORY_WORKSPACE_CACHE_MAX_BYTES = 80 * 1024 * 1024


def _full_repository_workspace_cache_size(value, seen=None, active=None):
    """Measure exact built-in payloads; reject subclasses and recursive containers."""
    kind = type(value)
    if kind not in (dict, list, tuple, type(None), bool, int, float, str, bytes):
        raise ValueError("unsupported cache payload type")
    seen, active = set() if seen is None else seen, set() if active is None else active
    marker = id(value)
    if marker in active:
        raise ValueError("recursive cache payload")
    if marker in seen:
        return 0
    seen.add(marker)
    if kind not in (dict, list, tuple):
        return sys.getsizeof(value)
    active.add(marker)
    try:
        children = value.items() if kind is dict else value
        size = sys.getsizeof(value)
        for child in children:
            size += sum(
                _full_repository_workspace_cache_size(item, seen, active)
                for item in (child if kind is dict else (child,))
            )
        return size
    finally:
        active.remove(marker)


def _full_repository_workspace_cache_store_prefix(
    key, result_digest, context_digest, rows, digest, source_capture=None, identity=None
):
    global _FULL_REPOSITORY_WORKSPACE_PREFIX_CACHE
    try:
        if (
            _full_repository_workspace_cache_size(
                (key, result_digest, context_digest, rows, source_capture, identity)
            )
            > FULL_REPOSITORY_WORKSPACE_CACHE_MAX_BYTES
        ):
            raise ValueError("cache input exceeds retention bound")
        source = (
            None
            if source_capture is None
            else (dict(source_capture[0]), deepcopy(source_capture[1]))
        )
        owned = deepcopy(rows)
        entry = (
            key,
            result_digest,
            context_digest,
            digest(owned),
            owned,
            source,
            identity,
            0,
        )
        size = _full_repository_workspace_cache_size(entry)
        entry = (*entry[:-1], size)
        measured = _full_repository_workspace_cache_size(entry)
        if measured <= FULL_REPOSITORY_WORKSPACE_CACHE_MAX_BYTES:
            _FULL_REPOSITORY_WORKSPACE_PREFIX_CACHE = (*entry[:-1], measured)
            return measured
    except Exception:
        pass
    _FULL_REPOSITORY_WORKSPACE_PREFIX_CACHE = None
    return 0


def _full_repository_workspace_cache_identity(generation, key):
    return (
        generation["root"].as_posix(),
        generation["inventory_hash"],
        generation["configuration"],
        generation["scanner"],
        generation["runtime_epoch"],
        generation["source_retention_limit_bytes"],
        key[1],
    )


def _full_repository_workspace_cache_load_prefix(
    engine, generation, results, files, source_by_name, context_digest
):
    cached, key = (
        _FULL_REPOSITORY_WORKSPACE_PREFIX_CACHE,
        generation.get("workspace_prefix_cache_key"),
    )
    try:
        valid_size = (
            type(cached) is tuple
            and len(cached) == 8
            and (cached[7] == _full_repository_workspace_cache_size(cached))
        )
    except Exception:
        valid_size = False
    if (
        not valid_size
        or key is None
        or cached[0] != key
        or cached[7] > FULL_REPOSITORY_WORKSPACE_CACHE_MAX_BYTES
        or cached[1] != engine.digest(results)
        or cached[1] != generation.get("saved_result_digest")
        or cached[2] != context_digest
        or cached[2] != generation.get("saved_context_generation_sha256")
        or cached[3] != engine.digest(cached[4])
        or len(cached[4]) != len(results)
    ):
        return None
    rows = deepcopy(cached[4])
    for row, path, primary in zip(rows, files, results):
        if (
            not isinstance(row, dict)
            or set(row) != {"path", "binding", "findings", "status"}
            or row["path"] != path.relative_to(generation["root"]).as_posix()
            or row["path"] != primary.get("path")
            or row["status"] != primary.get("status")
            or row["findings"] != primary.get("findings")
        ):
            return None
        source, binding = source_by_name.get(row["path"]), row["binding"]
        if binding is not None and (
            not isinstance(binding, dict)
            or binding.get("sha256") != (source or {}).get("sha256")
        ):
            return None
    return rows


REQUEST_SCHEMA = "factory.context-efficiency-request.v1"
PACKET_SCHEMA = "factory.context-efficiency-packet.v1"
VERIFICATION_SCHEMA = "factory.context-efficiency-verification.v1"
STATUS_SCHEMA = "factory.context-efficiency-status.v1"
SELECTION_SCHEMA = "factory.context-efficiency-selection.v1"
EXPERIMENT_SCHEMA = "factory.context-efficiency-paired.v1"
SHARD_CANDIDATE_SCHEMA = "factory.context-shard-candidate.v1"
SHARD_REVIEW_SCHEMA = "factory.context-shard-review.v1"
MODULE_VERSION = "1"
_MAX_PROVIDER_SOURCE_MODULES = 64


def captured_import_resolver(
    root, snapshots, eligible, resolver, *, with_initializers=False
):
    """Capture imports and initializer reuse for a producer-owned no-link generation.

    Callers must validate initializer requests and reread source bindings before
    returning a scan receipt; this is not a generic live-filesystem cache.
    """
    captured_trees, captured_eligible = dict(snapshots), eligible.copy()
    imports = {
        path: resolver(root, path, tree, eligible) for path, tree in snapshots.items()
    }

    def check_generation(request_root, request_eligible):
        if (
            request_root is not root
            or request_eligible is not eligible
            or snapshots != captured_trees
            or eligible != captured_eligible
        ):
            raise ValueError(
                "Import resolver request is outside its captured generation"
            )

    def resolve(request_root, source, tree, request_eligible):
        check_generation(request_root, request_eligible)
        if source not in snapshots or snapshots[source] is not tree:
            raise ValueError(
                "Import resolver request is outside its captured generation"
            )
        return dict(imports[source])

    if not with_initializers:
        return resolve
    lookup, validate = captured_initializer_lookup(
        root, snapshots, eligible, check_generation
    )
    return resolve, lookup, validate


def captured_initializer_lookup(root, snapshots, eligible, check_generation):
    """Memoize exact requests and require a fresh final filesystem comparison."""
    initializer_helper = _provider_package_initializers
    initializer_code = initializer_helper.__code__
    initializer_cache = {}
    canonical_inventory = isinstance(eligible, dict) and all(
        key == value for key, value in eligible.items()
    )

    def check_initializers():
        check_generation(root, eligible)
        if (
            _provider_package_initializers is not initializer_helper
            or initializer_helper.__code__ is not initializer_code
        ):
            raise ValueError("Initializer helper changed during captured generation")

    def initializers(sources):
        check_initializers()
        key = tuple(sources)
        if not canonical_inventory or any(source not in eligible for source in key):
            return list(initializer_helper(root, key, eligible))
        if key not in initializer_cache:
            values = tuple(initializer_helper(root, key, eligible))
            if len(initializer_cache) < 2 * len(snapshots) + 1:
                initializer_cache[key] = values
            return list(values)
        return list(initializer_cache[key])

    def validate_initializers():
        check_initializers()
        for sources, expected in initializer_cache.items():
            if tuple(initializer_helper(root, sources, eligible)) != expected:
                raise ValueError("Initializer paths changed during captured generation")
        check_initializers()

    return initializers, validate_initializers


def captured_local_import_closure(
    root,
    imports,
    snapshots,
    eligible,
    resolver,
    extra_sources=(),
    initializer_lookup=None,
):
    """Build a bounded, hash-bound closure from already captured source trees."""
    if initializer_lookup is None:

        def initializer_lookup(sources):
            return _provider_package_initializers(root, sources, eligible)

    pending = [source for source, _symbol in imports.values()] + list(extra_sources)
    pending.extend(initializer_lookup(pending))
    seen, rows = set(), []
    while pending:
        source = pending.pop()
        if source in seen:
            continue
        seen.add(source)
        if len(seen) > _MAX_PROVIDER_SOURCE_MODULES:
            return [], False
        tree = snapshots.get(source)
        digest = getattr(tree, "_oracle_source_sha256", None)
        if not isinstance(tree, ast.Module) or not isinstance(digest, str):
            return [], False
        resolved = resolver(root, source, tree, eligible)
        try:
            relative = source.relative_to(root).as_posix()
        except ValueError:
            return [], False
        rows.append(
            {"path": relative, "sha256": digest, "local_imports": sorted(resolved)}
        )
        imported = [target for target, _symbol in resolved.values()]
        pending.extend(imported)
        pending.extend(initializer_lookup(imported))
    return sorted(rows, key=lambda row: row["path"]), True


def _provider_package_initializers(root, sources, eligible):
    paths = (
        eligible
        if isinstance(eligible, dict)
        else {path.resolve(): path for path in eligible}
    )
    resolved_root = root.resolve()
    result = set()
    for source in sources:
        for parent in source.resolve().parents:
            initializer = (parent / "__init__.py").resolve()
            if initializer in paths:
                result.add(paths[initializer])
            if parent == resolved_root:
                break
    return sorted(result)


def oracle_context_cache_context(item, decode_structural_context):
    """Rehydrate cached oracle context fields, decoding structural context and restoring source-relative import bindings."""
    return {
        "helpers": set(item["helpers"]),
        "weak_helpers": set(item["weak_helpers"]),
        "mixins": set(item["mixins"]),
        "pytest_inherited": set(item["pytest_inherited"]),
        "click_runners": set(item["click_runners"]),
        "typecheck": item["typecheck"],
        "negative_typecheck": item.get("negative_typecheck", False),
        "flask_apps": set(item.get("flask_apps", [])),
        "codspeed_benchmark": item.get("codspeed_benchmark", False),
        "async_runner_fixtures": item.get("async_runner_fixtures", {}),
        "mock_fixture_provenance": item.get("mock_fixture_provenance", {}),
        "captured_imports": cached_import_bindings(item.get("captured_imports", {})),
        "django_fixture_evidence": item.get("django_fixture_evidence", {}),
        "application_fixture_evidence": item.get("application_fixture_evidence", {}),
        "protocol_observations": item.get("protocol_observations", {}),
        "autouse_lifecycle": item.get("autouse_lifecycle", []),
        "requested_fixture_lifecycle": item.get("requested_fixture_lifecycle", []),
        "fixed_program_workspace": item.get("fixed_program_workspace", {}),
        **provider_cache_fields(item),
        **decode_structural_context(item.get("structural_context", {})),
    }


def oracle_context_cache_record(path, context, encode_structural_context):
    """Serialize oracle context fields deterministically for caching, including captured imports and encoded structural context."""
    return {
        "path": path.as_posix(),
        "helpers": sorted(context["helpers"]),
        "weak_helpers": sorted(context["weak_helpers"]),
        "mixins": sorted(context["mixins"]),
        "pytest_inherited": sorted(context["pytest_inherited"]),
        "click_runners": sorted(context["click_runners"]),
        "typecheck": bool(context["typecheck"]),
        "negative_typecheck": bool(context.get("negative_typecheck", False)),
        "flask_apps": sorted(context.get("flask_apps", set())),
        "codspeed_benchmark": context.get("codspeed_benchmark", False),
        "async_runner_fixtures": context.get("async_runner_fixtures", {}),
        "mock_fixture_provenance": context.get("mock_fixture_provenance", {}),
        "captured_imports": cached_import_bindings(context.get("captured_imports", {})),
        "django_fixture_evidence": context.get("django_fixture_evidence", {}),
        "application_fixture_evidence": context.get("application_fixture_evidence", {}),
        "protocol_observations": context.get("protocol_observations", {}),
        "autouse_lifecycle": context.get("autouse_lifecycle", []),
        "requested_fixture_lifecycle": context.get("requested_fixture_lifecycle", []),
        "fixed_program_workspace": context.get("fixed_program_workspace", {}),
        **provider_cache_fields(context),
        "structural_context": encode_structural_context(context),
    }


def cached_import_bindings(value):
    """Retain only source-relative scalar import bindings across JSON caches."""
    if not isinstance(value, dict) or len(value) > 2000:
        return {}
    result = {}
    for name, binding in value.items():
        normalized = _cached_import_binding(name, binding)
        if normalized is None:
            return {}
        result[name] = normalized
    return result


def _cached_import_binding(name, binding):
    if not isinstance(name, str) or not name:
        return None
    if not isinstance(binding, (list, tuple)) or len(binding) != 2:
        return None
    relative, symbol = binding
    if not _cached_import_path(relative) or (
        symbol is not None and not isinstance(symbol, str)
    ):
        return None
    return relative, symbol


def _cached_import_path(relative):
    return (
        isinstance(relative, str)
        and bool(relative)
        and not relative.startswith("/")
        and "\\" not in relative
        and ":" not in relative
        and ".." not in relative.split("/")
    )


def typecheck_cache_helpers(contracts):
    """Return the callable typecheck contract helpers whose implementations affect analysis reuse."""
    return tuple(
        value
        for name, value in vars(contracts).items()
        if name.startswith("_ty_") and callable(value)
    )


def _application_profile_bytes(root, bindings, read_source, limit):
    selected = {
        row["path"]: row
        for row in bindings
        if row["path"] in application_configuration_names()
    }
    result = {}
    for name, binding in selected.items():
        try:
            raw = read_source(root, name)
        except (OSError, ValueError, RuntimeError):
            return None
        if len(raw) > limit or hashlib.sha256(raw).hexdigest() != binding["sha256"]:
            return None
        result[name] = raw
    return result


def bind_application_fixture_context(
    root,
    snapshots,
    contexts,
    bindings,
    read_source,
    limit,
    *,
    source_bytes=None,
    source_inventory=None,
    imports=None,
    source_index=None,
    configuration_valid=True,
    collection_known=True,
):
    """Bind source roles independently of collection-dependent fixture authority."""
    from . import (
        mock_fixture_provenance as fixture,
        credential_role_constructor_provider as roles,
    )
    from . import review_audits as audit

    for path in snapshots:
        contexts.setdefault(path, {})["application_fixture_evidence"] = {}
    if not all(
        (
            configuration_valid is True,
            isinstance(source_bytes, dict),
            isinstance(source_inventory, dict),
        )
    ):
        return
    candidates = {
        path: _fixture_literal_candidates(tree, audit)
        for path, tree in snapshots.items()
    }
    if not any(candidates.values()):
        return
    configs = _application_profile_bytes(root, bindings, read_source, limit)
    if configs is None:
        return
    captured = {path: source_bytes.get(path) for path in snapshots}
    inventory = {path: source_inventory.get(path) for path in snapshots}
    index = (
        fixture.application_test_index(
            root, snapshots, captured, inventory, configs, source_index=source_index
        )
        if collection_known is True
        else None
    )
    source = (
        index["source"]
        if index is not None
        else roles.SourceSnapshotIndex(root, snapshots, captured, inventory)
    )
    presentation = (
        roles.PresentationRoleIndex(source, imports, audit)
        if isinstance(imports, Mapping)
        else None
    )
    manifest = {
        path.relative_to(root).as_posix(): digest for path, digest in inventory.items()
    }
    config_hashes = {
        name: hashlib.sha256(raw).hexdigest() for name, raw in configs.items()
    }
    manifest.update(config_hashes)
    digest = hashlib.sha256(
        "\n".join(
            sorted(f"{name}\0{value}" for name, value in manifest.items())
        ).encode()
    ).hexdigest()
    for path, tree in snapshots.items():
        contexts[path]["application_fixture_evidence"] = _fixture_literal_evidence(
            tree,
            audit,
            lambda node, literal: _application_literal_evidence(
                fixture, index, presentation, path, node, literal
            ),
            {"inventory_sha256": digest, "configuration_sha256": config_hashes},
            candidates[path],
        )


def _application_literal_evidence(fixture, index, presentation, path, node, literal):
    item = (
        fixture.application_test_secret_evidence(
            index, path, node.value.lineno, literal
        )
        if index is not None
        else {}
    )
    if item.get("eligible") is not True and presentation is not None:
        item = presentation.evidence(path, node)
        if item.get("eligible") is True:
            source = presentation.source
            item = {
                **item,
                "source": source.relative(path),
                "source_sha256": source.inventory[path],
                "declaration_span": [
                    node.lineno,
                    node.col_offset,
                    node.end_lineno,
                    node.end_col_offset,
                ],
                "isolation_assurance": "UNASSESSED",
            }
    return item


def bind_django_fixture_context(
    root,
    snapshots,
    contexts,
    bindings,
    read_source,
    limit,
    *,
    source_bytes=None,
    source_inventory=None,
):
    """Use existing byte bindings and parse trees; cache only evidence projections."""
    from . import mock_fixture_provenance as fixture
    from . import review_audits as audit

    if not isinstance(source_bytes, dict) or not isinstance(source_inventory, dict):
        return
    captured = {path: source_bytes.get(path) for path in snapshots}
    inventory = {path: source_inventory.get(path) for path in snapshots}
    configs = _captured_fixture_configuration(root, bindings, read_source, limit)
    if not configs or any(not isinstance(raw, bytes) for raw in captured.values()):
        return
    index = fixture.django_test_secret_index(
        root, snapshots, configs, source_bytes=captured, inventory=inventory
    )
    if index is None:
        return
    for path, tree in snapshots.items():
        contexts[path]["django_fixture_evidence"] = _fixture_literal_evidence(
            tree,
            audit,
            lambda node, literal: fixture.django_test_secret_evidence(
                index, path, node.value.lineno, literal
            ),
        )


def _fixture_literal_candidates(tree, audit):
    candidates = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        literal = audit._secret_literal(node)
        target = targets[0] if len(targets) == 1 else None
        if (
            literal is None
            or not isinstance(target, ast.Name)
            or not audit._SECRET_ASSIGNMENT.search(target.id)
        ):
            continue
        candidates.append((node, target, literal))
    return candidates


def _fixture_literal_evidence(tree, audit, resolve, metadata=None, candidates=None):
    evidence = {}
    for node, target, literal in (
        _fixture_literal_candidates(tree, audit) if candidates is None else candidates
    ):
        item = resolve(node, literal)
        if item.get("eligible") is True:
            key = f"{node.lineno}:{node.col_offset}:{target.id}"
            evidence[key] = {**item, **metadata} if metadata else item
    return evidence


def _captured_fixture_configuration(root, bindings, read_source, limit):
    """Re-read only known configuration inputs, rejecting a changed capture."""
    selected = {
        row["path"]: row
        for row in bindings
        if row["path"] in {"pyproject.toml", "tox.ini"}
    }
    if set(selected) != {"pyproject.toml", "tox.ini"}:
        return {}
    result = {}
    for name, binding in selected.items():
        try:
            raw = read_source(root, name)
        except (OSError, ValueError, RuntimeError):
            return {}
        if len(raw) > limit or hashlib.sha256(raw).hexdigest() != binding["sha256"]:
            return {}
        result[name] = raw
    return result


def provider_context_cache_helpers(contracts):
    """Return the source inventory and cache helpers in the cache epoch."""
    from . import credential_role_constructor_provider as roles

    return (
        roles.security_snapshot_model,
        roles.application_snapshot_index,
        roles.verified_security_tree,
        roles.security_source_snapshots,
        roles.consume_cached_security_snapshots,
        roles.PresentationRoleIndex,
        *(
            getattr(roles, name)
            for name in (
                "declaration_fact",
                "function_bindings",
                "binding_occurrences",
                "binding_statements",
                "declared_origins",
                "resolve_class",
                "_method_decorators_allowed",
                "_scope",
                "_assignment_target",
                "_name_origins",
                "_assigned_origins",
                "_direct_origins",
                "_imported_attribute",
                "_container_origins",
                "_scope_scope_bindings",
                "_scope_bindings",
            )
        ),
        *(
            value
            for name, value in vars(roles).items()
            if name.startswith("_presentation_")
        ),
        *(
            value
            for owner in (
                roles.PresentationRoleIndex,
                roles.SourceSnapshotIndex,
                roles.DeclarationFact,
            )
            for value in vars(owner).values()
            if callable(value)
        ),
        provider_context_cache_helpers,
        bind_provider_inventory,
        bind_provider_context,
        captured_import_resolver,
        captured_initializer_lookup,
        captured_local_import_closure,
        _provider_package_initializers,
        oracle_context_cache_context,
        oracle_context_cache_record,
        cached_import_bindings,
        _cached_import_binding,
        _cached_import_path,
        _fixture_literal_candidates,
        bind_django_fixture_context,
        bind_application_fixture_context,
        _fixture_literal_evidence,
        _application_literal_evidence,
        application_profile_configuration,
        application_configuration_names,
        _application_profile_bytes,
        _captured_fixture_configuration,
        provider_cache_fields,
        provider_source_inventory,
        typecheck_cache_helpers,
        *typecheck_cache_helpers(contracts),
    )


@_measured_source_read
def _read_bounded_workspace_source(workspace, relative, max_bytes, path_resolver):
    """Read one bounded regular workspace file without following linked entries."""
    path = path_resolver(workspace, relative)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        checked = path_resolver(workspace, relative).stat()
        if (opened.st_dev, opened.st_ino) != (checked.st_dev, checked.st_ino):
            raise OSError("source changed before read")
        data = stream.read(max_bytes + 1)
        after = path_resolver(workspace, relative).stat()
        if (opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise OSError("source changed during read")
    return data


def _consume_security_snapshots(
    workspace,
    files,
    snapshots,
    fingerprints,
    contexts,
    retained,
    scoped_reads,
    tenant_read_calls,
    tenant_read_bindings,
    test_file_patterns,
    scan_snapshot,
    source_model_out=None,
):
    """Consume trees while retaining an owned source model for later consumers."""
    from . import test_oracle_misuse as oracle
    from . import review_audits as audit

    security_only = audit._SECURITY_ONLY_SCAN.get() is True
    rows, state = (
        {},
        (
            ({}, {})
            if security_only
            else oracle.source_callback_snapshot_state(snapshots, fingerprints)
        ),
    )
    provider_mutations = {}
    try:
        for path in files:
            if (tree := snapshots.pop(path, None)) is None:
                continue
            scope = (scoped_reads or {}).get(
                path.relative_to(workspace).as_posix(), (scoped_reads or {}).get("", {})
            )
            calls = tuple(sorted(set(tenant_read_calls) | set(scope.get("calls", ()))))
            bindings = {**scope.get("bindings", {}), **tenant_read_bindings}
            context = {
                **contexts.get(path, {}),
                "_tenant_policy_applies": scope.get("_policy_applies", False),
                "_security_source_context": (workspace, retained),
                "_security_provider_mutation_cache": provider_mutations,
                "_security_source_model": (source_model_out or {}).get("source"),
            }
            if not security_only:
                bind = oracle.source_callback_snapshot_context
                context.update(
                    bind(context.get("captured_imports", {}), workspace, *state)
                )
            rows[path] = scan_snapshot(
                workspace,
                path,
                calls,
                bindings,
                context,
                test_file_patterns,
                retained.get(path),
                tree,
                fingerprints.get(path),
            )
    finally:
        snapshots.clear()
    return rows


def _scan_missing_security_snapshot(
    scanned,
    workspace,
    path,
    scoped_reads,
    tenant_read_calls,
    tenant_read_bindings,
    contexts,
    retained,
    test_file_patterns,
    scan_source,
):
    """Fall back to the captured source bytes when no producer tree is available."""
    if scanned is not None:
        return scanned
    scope = (scoped_reads or {}).get(
        path.relative_to(workspace).as_posix(), (scoped_reads or {}).get("", {})
    )
    calls = tuple(sorted(set(tenant_read_calls) | set(scope.get("calls", ()))))
    bindings = {**scope.get("bindings", {}), **tenant_read_bindings}
    source_context = {
        **contexts.get(path, {}),
        "_tenant_policy_applies": scope.get("_policy_applies", False),
        "_security_source_context": (workspace, retained),
    }
    return scan_source(
        workspace,
        path,
        calls,
        bindings,
        source_context,
        test_file_patterns,
        retained.get(path),
    )


def _verify_source_bindings(
    workspace,
    bindings,
    source_reader,
    max_bytes,
    hash_source,
    error_type,
    runtime_error,
    operation,
    *,
    captured_out=None,
):
    """Reject any source binding whose bounded bytes changed before receipt creation."""
    for binding in bindings:
        current = workspace / binding["path"]
        try:
            if current.stat().st_size > max_bytes:
                raise error_type(
                    f"Evidence changed during {operation}: {binding['path']}"
                )
            data = source_reader(workspace, binding["path"])
            if len(data) > max_bytes or current.stat().st_size > max_bytes:
                raise error_type(
                    f"Evidence changed during {operation}: {binding['path']}"
                )
        except (OSError, UnicodeError, runtime_error) as exc:
            raise error_type(
                f"Evidence changed during {operation}: {binding['path']}"
            ) from exc
        if len(data) != binding["bytes"] or hash_source(data) != binding["sha256"]:
            raise error_type(f"Evidence changed during {operation}: {binding['path']}")
        if captured_out is not None:
            captured_out[binding["path"]] = data


def _security_source_failure(
    audit, binding, relative, code, node, message, outcome, **facts
):
    finding = audit._security_finding(code, relative, node, message, "HIGH", **facts)
    return binding, [finding], outcome


def _undeclared_tenant_read_findings(relative, nodes, aliases, declared_reads, applies):
    """Report ORM reads outside an explicitly applicable declaration."""
    from . import review_audits as audit

    if not declared_reads and not applies:
        return []
    return [
        audit._security_finding(
            "SECURITY_TENANT_READ_UNDECLARED",
            relative,
            call,
            (
                f"Potential ORM read {name} needs review for tenant scope. "
                "If tenant isolation applies, declare the read in --tenant-read-call and bind its tenant scope."
            ),
            "HIGH",
            call=name,
        )
        for name, call in audit._orm_read_candidates(nodes, aliases)
        if name not in declared_reads
    ]


def _verified_security_tree(*args, **kwargs):
    from .credential_role_constructor_provider import verified_security_tree

    return verified_security_tree(*args, **kwargs)


def _scan_security_source(
    workspace,
    path,
    tenant_read_calls,
    tenant_read_bindings,
    oracle_context,
    test_file_patterns,
    source_data,
    tree=None,
    fingerprint=None,
):
    """Scan one bounded source, consuming only an internal producer-owned AST."""
    from . import review_audits as audit

    relative = path.relative_to(workspace).as_posix()
    binding = None
    try:
        initial_size = audit.local_file(workspace, relative).stat().st_size
        if initial_size > audit.MAX_BYTES:
            return _security_source_failure(
                audit,
                None,
                relative,
                "SECURITY_SOURCE_TOO_LARGE",
                ast.Module(body=[], type_ignores=[]),
                f"Source exceeds the {audit.MAX_BYTES}-byte scan limit.",
                "too_large",
                bytes=initial_size,
            )
        data = source_data
        if data is None:
            data = audit._security_source_bytes(workspace, relative)
        final_size = audit.local_file(workspace, relative).stat().st_size
        if len(data) > audit.MAX_BYTES or final_size > audit.MAX_BYTES:
            return _security_source_failure(
                audit,
                None,
                relative,
                "SECURITY_SOURCE_TOO_LARGE",
                ast.Module(body=[], type_ignores=[]),
                f"Source exceeds the {audit.MAX_BYTES}-byte scan limit.",
                "too_large",
                bytes=max(len(data), final_size),
            )
        binding = {
            "path": relative,
            "sha256": audit._measure_hash("source_hash", audit.sha256, data),
            "bytes": len(data),
        }
        tree = _verified_security_tree(
            audit,
            workspace,
            path,
            data,
            binding,
            tree,
            fingerprint,
            source_context=oracle_context,
        )
        tree._oracle_source_sha256 = binding["sha256"]
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        tree._oracle_source_lines = data.decode(encoding).splitlines()
    except (OSError, UnicodeError, audit.RuntimeAuditError) as exc:
        return _security_source_failure(
            audit,
            binding,
            relative,
            "SECURITY_SOURCE_UNREADABLE",
            ast.Module(body=[], type_ignores=[]),
            "Source could not be read for security analysis.",
            "unreadable",
            detail=type(exc).__name__,
        )
    except SyntaxError as exc:
        return _security_source_failure(
            audit,
            binding,
            relative,
            "QUALITY_SYNTAX_ERROR",
            exc,
            "Python source cannot be parsed deterministically.",
            "syntax_error",
            detail="invalid Python syntax",
        )
    security_only = (oracle_context or {}).get("_security_only", False)
    security_only = security_only is True or audit._SECURITY_ONLY_SCAN.get() is True
    findings = (
        []
        if security_only is True
        else audit.contracts.implementation_findings(
            relative, tree, data, oracle_context
        )
    )
    findings.extend(
        audit._security_scan_tree(
            workspace,
            path,
            tree,
            tenant_read_calls,
            tenant_read_bindings,
            oracle_context,
            test_file_patterns,
            (oracle_context or {}).get("_tenant_policy_applies", False),
        )
    )
    return binding, findings, "audited"


def _expected_exception_else_failure(node, aliases):
    """Recognize a specific expected exception with a failure when absent."""
    from . import review_audits as audit

    return any(
        isinstance(parent, ast.Try)
        and child in parent.orelse
        and parent.handlers
        and all(
            handler.type is not None
            and not audit._exception_type_catches_assertion(
                handler.type, handler, aliases
            )
            for handler in parent.handlers
        )
        and not _try_body_has_unmediated_raise(
            parent, getattr(node, "_oracle_scope", None), aliases, audit
        )
        and any(
            isinstance(call, ast.Call)
            and not any(
                isinstance(ancestor, ast.Raise)
                for ancestor, _ in getattr(call, "_oracle_ancestors", ())
            )
            for statement in parent.body
            for call in audit._body_nodes(statement)
        )
        and not any(
            audit._finally_suppresses_exception(statement)
            for statement in parent.finalbody
        )
        for parent, child in getattr(node, "_oracle_ancestors", ())
    )


def _try_body_has_unmediated_raise(parent, scope, aliases, audit):
    """Reject test-owned raises unless a context-managed iteration mediates them."""
    module = getattr(scope, "_oracle_module", None)
    return any(
        isinstance(child, ast.Raise)
        and not _raise_is_iteration_mediated(child, scope, module, aliases, audit)
        for statement in parent.body
        for child in audit._body_nodes(statement)
    )


def _raise_is_iteration_mediated(node, scope, module, aliases, audit):
    """Recognize a raise inside an imported retry iterator's attempt context."""
    ancestors = getattr(node, "_oracle_ancestors", ())
    for index, (parent, _child) in enumerate(ancestors):
        if not isinstance(
            parent, (ast.For, ast.AsyncFor)
        ) or not _retry_factory_is_imported(parent.iter, scope, module, aliases, audit):
            continue
        target = parent.target
        if not isinstance(target, ast.Name) or not isinstance(target.ctx, ast.Store):
            continue
        for context, _context_child in ancestors[index + 1 :]:
            if not isinstance(context, (ast.With, ast.AsyncWith)):
                continue
            for item in context.items:
                use = item.context_expr
                if (
                    isinstance(use, ast.Name)
                    and use.id == target.id
                    and isinstance(use.ctx, ast.Load)
                    and _closed_capability_use_proof(
                        scope,
                        target.id,
                        target,
                        [target, use],
                        audit=audit,
                    )
                ):
                    return True
    return False


def _retry_factory_is_imported(expression, scope, module, aliases, audit):
    """Require an intact Tenacity retry factory import for attempt mediation."""
    if not isinstance(expression, ast.Call):
        return False
    api = audit._normalized_call_name(expression, aliases)
    if api not in {
        "tenacity.AsyncRetrying",
        "tenacity.Retrying",
        "tenacity.asyncio.AsyncRetrying",
    }:
        return False
    root = _leftmost_name(expression.func)
    head = root.id if root is not None else ""
    origin = _module_import_binding_origin(module, head, api)
    capability_module = _module_import_origin_module_path(
        module, origin[0] if origin is not None else None, api
    )
    capability_module = capability_module or api.rpartition(".")[0]
    return (
        origin is not None
        and isinstance(module, ast.Module)
        and isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
        and head not in audit._scope_parameters(scope)
        and not audit._scope_binds_name(scope, head)
        and not audit._module_has_rebinding(module, head, origin[1])
        and not audit._click_receiver_mutated(scope, head)
        and not audit._click_receiver_mutated(module, head)
        and _module_import_aliases_are_closed(module, capability_module, audit, api=api)
        and _closed_capability_use_proof(
            scope, head, origin[0], [root], origin_scope=module, audit=audit
        )
    )


def _leftmost_name(node):
    """Return the root Name in a dotted expression, if one exists."""
    while isinstance(node, ast.Attribute):
        node = node.value
    return node if isinstance(node, ast.Name) else None


def _module_import_binding_origin(module, binding, api):
    """Return one imported origin using the shared API binding enumeration."""
    if not isinstance(module, ast.Module) or not binding or not isinstance(api, str):
        return None
    candidates = [
        (item, statement)
        for statement in module.body
        for local, _path, item in (
            _module_import_alias_candidates(statement, api, api) or ()
        )
        if local == binding
    ]
    return candidates[0] if len(candidates) == 1 else None


def _module_import_origin_module_path(module, origin, api):
    """Reuse import candidates to resolve the module exposing this exact API."""
    if not isinstance(module, ast.Module) or origin is None or not isinstance(api, str):
        return None
    return next(
        (
            path
            for statement in module.body
            for _local, path, item in (
                _module_import_alias_candidates(statement, api, api) or ()
            )
            if item is origin and api.startswith(path + ".")
        ),
        None,
    )


def _module_import_aliases_are_closed(
    module, target_module, audit, *, api=None, effect_nodes=None
):
    """Fail closed on equivalent imported modules that can mutate this API."""
    if not isinstance(module, ast.Module) or not isinstance(target_module, str):
        return False
    nodes = _bounded_ast_nodes(module)
    if nodes is None:
        return False
    parents = _ast_parent_map(nodes)
    candidates = []
    for statement in nodes:
        bindings = _module_import_alias_candidates(statement, target_module, api)
        if bindings is None:
            return False
        candidates.extend(
            (statement, binding, imported_path, origin)
            for binding, imported_path, origin in bindings
        )
    return (
        bool(candidates)
        and not _module_has_dynamic_capability_access(
            nodes if effect_nodes is None else effect_nodes
        )
        and all(
            _module_import_alias_is_closed(
                module, candidate, target_module, parents, audit, api
            )
            for candidate in candidates
        )
    )


def _ast_parent_map(nodes):
    """Build a bounded child-to-parent index for one AST walk."""
    parents = {}
    for parent in nodes:
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent
    return parents


def _module_import_alias_is_closed(
    module, candidate, target_module, parents, audit, api=None
):
    """Validate one equivalent module import and every use in its scope."""
    statement, binding, imported_path, _origin = candidate
    scope = _module_import_lexical_scope(statement, parents, module)
    if scope is None or _module_import_binding_reassigned(
        scope, statement, binding, audit
    ):
        return False
    if (
        api is not None
        and imported_path == api
        and not _module_path_controls_target(imported_path, target_module)
    ):
        return _module_api_alias_uses_are_closed(
            scope, binding, api, module, parents, audit
        )
    return _module_alias_uses_are_closed(
        scope, binding, imported_path, target_module, parents, api, module, audit
    )


def _module_import_lexical_scope(statement, parents, module):
    """Find the nearest scope owning one import statement."""
    current = statement
    while current is not module:
        if isinstance(
            current,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            return current
        current = parents.get(id(current))
        if current is None:
            return None
    return module


def _module_import_binding_reassigned(scope, origin_statement, binding, audit):
    """Reject rebinding or a second import of the same local alias."""
    if isinstance(
        scope, (ast.FunctionDef, ast.AsyncFunctionDef)
    ) and binding in audit._scope_parameters(scope):
        return True
    return any(
        statement is not origin_statement and binding in audit._bound_names(statement)
        for statement in getattr(scope, "body", ())
    )


def _module_alias_uses_are_closed(
    scope,
    binding,
    imported_path,
    target_module,
    parents,
    api=None,
    module=None,
    audit=None,
):
    """Allow only read-only dotted API access through a module import alias."""
    reflective_attributes = {
        "__class__",
        "__dict__",
        "__delattr__",
        "__getattribute__",
        "__setattr__",
        "__subclasses__",
    }
    nodes = _bounded_ast_nodes(scope)
    if nodes is None:
        return False
    occurrences = [
        node for node in nodes if isinstance(node, ast.Name) and node.id == binding
    ]
    for occurrence in occurrences:
        if not isinstance(occurrence.ctx, ast.Load):
            return False
        current = occurrence
        current_path = imported_path
        parent = parents.get(id(current))
        if _module_path_controls_target(current_path, target_module) and not (
            isinstance(parent, ast.Attribute) and parent.value is current
        ):
            return False
        while isinstance(parent, ast.Attribute) and parent.value is current:
            if (
                not isinstance(parent.ctx, ast.Load)
                or parent.attr in reflective_attributes
            ):
                return False
            current_path = f"{current_path}.{parent.attr}"
            current = parent
            parent = parents.get(id(current))
            if (
                api is not None
                and current_path == api
                and not _module_api_use_is_closed(
                    current, parent, parents, module, audit
                )
            ):
                return False
            if _module_path_controls_target(current_path, target_module) and not (
                isinstance(parent, ast.Attribute) and parent.value is current
            ):
                return False
    return True


def _module_api_alias_uses_are_closed(scope, binding, api, module, parents, audit):
    """Permit imported API objects only as direct calls or fixture alternatives."""
    nodes = _bounded_ast_nodes(scope)
    if nodes is None:
        return False
    return all(
        _module_api_use_is_closed(
            occurrence, parents.get(id(occurrence)), parents, module, audit
        )
        for occurrence in nodes
        if isinstance(occurrence, ast.Name) and occurrence.id == binding
    )


def _module_api_use_is_closed(node, parent, parents, module, audit):
    """Require a callable API reference to be invoked or consumed by a fixture."""
    return bool(
        isinstance(node, (ast.Name, ast.Attribute))
        and isinstance(parent, ast.Call)
        and parent.func is node
        or _module_api_use_is_fixture_parameter(node, parents, module, audit)
    )


def _module_api_use_is_fixture_parameter(node, parents, module, audit):
    """Allow an API value only in a recognized pytest fixture parameter list."""
    current = node
    function = None
    while current is not module:
        current = parents.get(id(current))
        if current is None:
            return False
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function = current
            break
    if function is None or len(function.decorator_list) != 1:
        return False
    aliases = audit._scope_security_aliases(
        audit._module_security_aliases(module), module
    )
    parameters = _async_runner_fixture_consumer_shape(function, module, aliases, audit)
    return parameters is not None and any(node is item for item in parameters.elts)


def _closed_capability_use_proof(
    scope,
    binding,
    origin,
    uses,
    *,
    origin_scope=None,
    audit=None,
    source=None,
    source_sha256=None,
    api=None,
):
    """Prove a bounded binding has one source origin and only exact named uses."""
    origin_scope = scope if origin_scope is None else origin_scope
    if not isinstance(scope, ast.AST) or not isinstance(origin_scope, ast.AST):
        return None
    scope_nodes = _bounded_ast_nodes(scope)
    if scope_nodes is None:
        return None
    origin_nodes = (
        scope_nodes if origin_scope is scope else _bounded_ast_nodes(origin_scope)
    )
    if origin_nodes is None or origin not in origin_nodes:
        return None
    if not _capability_uses_match(scope_nodes, binding, uses):
        return None
    if _scope_has_reflective_capability_access(scope_nodes):
        return None
    origin_position = _ast_position(origin)
    use_positions = sorted(
        (_ast_position(item) for item in uses),
        key=lambda position: (position["line"], position["column"]),
    )
    proof = {
        "status": "CLOSED",
        "binding": binding,
        "origin": origin_position,
        "uses": use_positions,
    }
    if api is not None:
        proof["api"] = api
    if source is not None:
        proof["source"] = source
    if source_sha256 is not None:
        if not _is_sha256(source_sha256):
            return None
        proof["sha256"] = source_sha256
    return proof


def _bounded_ast_nodes(scope):
    """Walk an AST only up to the shared proof node limit."""
    nodes = []
    for node in ast.walk(scope):
        if len(nodes) >= MAX_AST_NODES:
            return None
        nodes.append(node)
    return nodes


def _capability_uses_match(scope_nodes, binding, uses):
    """Match every binding occurrence to the exact source-origin uses."""
    if not isinstance(binding, str) or not binding or not uses:
        return False
    if any(
        not isinstance(use, ast.Name)
        or use.id != binding
        or use not in scope_nodes
        or not isinstance(use.ctx, (ast.Load, ast.Store))
        for use in uses
    ):
        return False
    occurrences = [
        item
        for item in scope_nodes
        if isinstance(item, ast.Name) and item.id == binding
    ]
    return len(occurrences) == len(uses) and {id(item) for item in occurrences} == {
        id(item) for item in uses
    }


def _ast_position(node):
    """Serialize a stable source coordinate for a static capability witness."""
    return {
        "line": int(getattr(node, "lineno", 0)),
        "column": int(getattr(node, "col_offset", 0)),
    }


def _scope_has_reflective_capability_access(nodes):
    """Fail closed on reflective or dynamic binding access within the proof scope."""
    reflective_modules = {"builtins", "importlib", "inspect", "runpy", "sys"}
    reflective_names = _capability_reflection_names() | {"compile"}
    reflective_attributes = {
        "__code__",
        "__closure__",
        "__delattr__",
        "__globals__",
        "__setattr__",
        "__import__",
        "compile",
        "delattr",
        "eval",
        "exec",
        "getattr",
        "import_module",
        "setattr",
    }
    return any(
        isinstance(node, ast.Name)
        and node.id in reflective_names | {"builtins", "importlib", "sys"}
        or isinstance(node, ast.alias)
        and node.name in reflective_names | {"builtins", "importlib", "runpy", "sys"}
        or isinstance(node, ast.ImportFrom)
        and (
            node.module in reflective_modules
            or any(
                item.name == "*" or item.name in reflective_names for item in node.names
            )
        )
        or isinstance(node, ast.Import)
        and any(item.name.split(".", 1)[0] in reflective_modules for item in node.names)
        or isinstance(node, ast.Attribute)
        and node.attr in reflective_attributes
        or isinstance(node, ast.Attribute)
        and node.attr == "modules"
        for node in nodes
    )


_ASYNC_RUNNER_CONTEXT_SCHEMA = "factory.async-runner-fixture-context.v3"
_ASYNC_RUNNER_MAX_FIXTURES = 16


def async_runner_fixture_context(root, files, snapshots):
    """Build bounded, JSON-safe provenance for inherited async runner fixtures."""
    from . import review_audits as audit

    if len(snapshots) > audit.MAX_SECURITY_SOURCE_FILES:
        return {}
    rows, candidates = _async_runner_snapshot_records(
        root, set(files), snapshots, audit
    )
    if rows is None:
        return {}
    result = {}
    for path, (source_sha, local, gap) in rows.items():
        fixtures = {}
        gaps = set()
        for source, digest, declarations, source_gap in sorted(
            candidates, key=lambda row: len(row[0].parts)
        ):
            if path.parent.is_relative_to(source.parent):
                if source_gap:
                    fixtures = {name: {"trusted": False} for name in fixtures}
                    gaps.add(source_gap)
                else:
                    fixtures.update(declarations)
        if gap:
            fixtures = {name: {"trusted": False} for name in fixtures}
            gaps.add(gap)
        else:
            fixtures.update(local)
        if "*" in fixtures:
            fixtures = {name: {"trusted": False} for name in fixtures}
        if any((fixtures, gaps)):
            result[path.relative_to(root).as_posix()] = {
                "schema": _ASYNC_RUNNER_CONTEXT_SCHEMA,
                "module_sha256": source_sha,
                "fixtures": fixtures,
                "gaps": sorted(gaps),
            }
    return result


def _async_runner_snapshot_records(root, eligible, snapshots, audit):
    """Index bounded test and conftest trees with their source identities."""
    rows = {}
    candidates = []
    for path, tree in snapshots.items():
        if path not in eligible or not _async_runner_snapshot_candidate(path, tree):
            continue
        oversized = False
        for count, _node in enumerate(ast.walk(tree), start=1):
            if count > MAX_AST_NODES:
                oversized = True
                break
        source_sha = getattr(tree, "_oracle_source_sha256", None)
        if not _is_sha256(source_sha):
            continue
        if oversized:
            if path.name == "conftest.py":
                candidates.append(
                    (path, source_sha, {}, "ANCESTOR_FIXTURE_SOURCE_NODE_LIMIT")
                )
            else:
                rows[path] = (source_sha, {}, "TEST_MODULE_NODE_LIMIT")
            continue
        declared = _async_runner_fixture_declarations(
            path.relative_to(root).as_posix(), tree, audit
        )
        if path.name == "conftest.py":
            candidates.append((path, source_sha, declared, None))
        else:
            rows[path] = (source_sha, declared, None)
    return rows, candidates


def _async_runner_snapshot_candidate(path, tree):
    """Limit analysis to fixture sources and modules declaring tests."""
    return isinstance(tree, ast.Module) and (
        path.name == "conftest.py"
        or any(
            isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name.startswith("test_")
            for item in tree.body
        )
    )


def _async_runner_fixture_declarations(relative, tree, audit):
    """Record local fixture definitions, retaining invalid overrides as blockers."""
    aliases = audit._scope_security_aliases(audit._module_security_aliases(tree), tree)
    declarations = {}
    functions = [item for item in tree.body if isinstance(item, ast.FunctionDef)]
    fixtures = [
        item
        for item in tree.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and _async_runner_fixture_like(item, tree, aliases, audit)
    ]
    duplicates = set()
    for function in fixtures:
        name = _async_runner_declared_fixture_name(function)
        if name in declarations:
            duplicates.add(name)
            declarations[name] = {"trusted": False}
            continue
        if name in duplicates:
            continue
        if not _async_runner_fixture_decorator(function, tree, aliases, audit):
            declarations[name] = {"trusted": False}
            continue
        alternatives = _async_runner_fixture_contract(
            function, tree, functions, aliases, audit
        )
        source_sha = getattr(tree, "_oracle_source_sha256", None)
        if not alternatives:
            declarations[name] = {
                "trusted": False,
                "source": relative,
                "sha256": source_sha,
            }
            continue
        declarations[name] = {
            "trusted": True,
            "source": relative,
            "sha256": source_sha,
            "alternatives": alternatives,
        }
    proof_groups = _async_runner_capability_groups(declarations)
    proofs = {
        key: (
            None
            if group["invalid"]
            else _closed_capability_use_proof(
                tree,
                group["binding"],
                group["origin"],
                group["uses"],
                origin_scope=tree,
                audit=audit,
                source=relative,
                source_sha256=getattr(tree, "_oracle_source_sha256", None),
                api=group["api"],
            )
        )
        for key, group in proof_groups.items()
    }
    _async_runner_seal_declarations(declarations, proofs)
    return declarations


def _async_runner_capability_groups(declarations):
    """Aggregate exact provider uses across all valid fixture declarations."""
    groups = {}
    for declaration in declarations.values():
        if declaration.get("trusted") is not True:
            continue
        for item in declaration["alternatives"]:
            key = id(item["_cap_origin"])
            group = groups.setdefault(
                key,
                {
                    "origin": item["_cap_origin"],
                    "binding": item["_cap_binding"],
                    "api": item["api"],
                    "uses": [],
                    "invalid": False,
                },
            )
            if group["binding"] != item["_cap_binding"] or group["api"] != item["api"]:
                group["invalid"] = True
            else:
                group["uses"].extend(item["_cap_uses"])
    return groups


def _async_runner_seal_declarations(declarations, proofs):
    """Serialize only alternatives carrying the complete closed-use witness."""
    for declaration in declarations.values():
        if declaration.get("trusted") is not True:
            continue
        sealed = []
        for item in declaration["alternatives"]:
            capability = proofs.get(id(item["_cap_origin"]))
            if capability is None:
                declaration.clear()
                declaration["trusted"] = False
                break
            sealed.append(
                {
                    key: value
                    for key, value in item.items()
                    if not key.startswith("_cap_")
                }
                | {"capability": capability}
            )
        else:
            declaration["alternatives"] = sealed


def _async_runner_declared_fixture_name(function):
    """Resolve an explicit fixture rename or block on a dynamic name."""
    names = [
        keyword.value
        for decorator in function.decorator_list
        if isinstance(decorator, ast.Call)
        for keyword in decorator.keywords
        if keyword.arg == "name"
    ]
    if not names:
        return function.name
    if (
        len(names) == 1
        and isinstance(names[0], ast.Constant)
        and isinstance(names[0].value, str)
    ):
        return names[0].value
    return "*"


def _async_runner_fixture_like(function, tree, aliases, audit):
    """Treat an unresolved fixture-looking decorator as an overriding blocker."""
    for decorator in function.decorator_list:
        value = decorator.func if isinstance(decorator, ast.Call) else decorator
        if audit._resolved_ast_name(
            value, aliases
        ) == "pytest.fixture" or _async_runner_fixture_imports(tree, value):
            return True
        if (
            isinstance(value, ast.Attribute)
            and value.attr == "fixture"
            or isinstance(value, ast.Name)
            and value.id == "fixture"
        ):
            return True
    return False


def _async_runner_fixture_decorator(function, tree, aliases, audit):
    """Recognize only a directly imported pytest fixture decorator."""
    return any(
        audit._resolved_ast_name(value, aliases) == "pytest.fixture"
        and len(imports := _async_runner_fixture_imports(tree, value)) == 1
        and not audit._module_has_rebinding(
            tree, _async_runner_fixture_import_name(imports[0], value), imports[0]
        )
        for item in function.decorator_list
        for value in [item.func if isinstance(item, ast.Call) else item]
    )


def _async_runner_fixture_imports(tree, value):
    """Reuse exact imported origins for pytest module/fixture bindings."""
    root = _async_runner_fixture_import_name(None, value)
    return [
        statement
        for statement in tree.body
        if root
        and any(
            local == root and path in {"pytest", "pytest.fixture"}
            for local, path, _item in (
                _module_import_alias_candidates(statement, "pytest", "pytest.fixture")
                or ()
            )
        )
    ]


def _async_runner_fixture_import_name(statement, value):
    """Return the root name of a supported pytest fixture expression."""
    if isinstance(value, ast.Name):
        return value.id
    return getattr(value.value, "id", "") if isinstance(value, ast.Attribute) else ""


def _async_runner_fixture_consumer_shape(function, tree, aliases, audit):
    """Prove pure literal parameter transfer without assuming provider trust."""
    if (
        not isinstance(function, ast.FunctionDef)
        or len(function.decorator_list) != 1
        or not isinstance(function.decorator_list[0], ast.Call)
        or len(function.args.args) != 1
        or function.args.args[0].arg != "request"
        or function.args.posonlyargs
        or function.args.kwonlyargs
        or function.args.vararg
        or function.args.kwarg
        or function.args.defaults
        or function.args.kw_defaults
    ):
        return None
    decorator = function.decorator_list[0]
    parameters = [item.value for item in decorator.keywords if item.arg == "params"]
    if (
        len(parameters) != 1
        or decorator.args
        or any(item.arg not in {"params", "ids"} for item in decorator.keywords)
        or not isinstance(parameters[0], (ast.List, ast.Tuple))
        or not 1 <= len(parameters[0].elts) <= _ASYNC_RUNNER_MAX_FIXTURES
        or not _async_runner_fixture_ids(decorator, len(parameters[0].elts))
        or not all(
            isinstance(item, (ast.Name, ast.Attribute)) for item in parameters[0].elts
        )
        or not _async_runner_fixture_decorator(function, tree, aliases, audit)
    ):
        return None
    body = (
        function.body[1:] if _async_runner_docstring(function.body) else function.body
    )
    if (
        len(body) != 1
        or not isinstance(body[0], ast.Return)
        or not isinstance(body[0].value, ast.Attribute)
        or not isinstance(body[0].value.value, ast.Name)
        or body[0].value.value.id != "request"
        or body[0].value.attr != "param"
        or any("request" in audit._bound_names(item) for item in function.body)
    ):
        return None
    return parameters[0]


def _async_runner_fixture_contract(function, tree, functions, aliases, audit):
    """Resolve providers only after the independent consumer shape is proven."""
    parameters = _async_runner_fixture_consumer_shape(function, tree, aliases, audit)
    if parameters is None:
        return None
    alternatives = [
        _async_runner_alternative(item, tree, functions, aliases, audit)
        for item in parameters.elts
    ]
    if any(item is None for item in alternatives):
        return None
    if len({(item["api"], item["binding"]) for item in alternatives}) != len(
        alternatives
    ):
        return None
    return alternatives


def _async_runner_fixture_ids(decorator, count):
    """Accept only a literal id list aligned with every declared alternative."""
    ids = [item.value for item in decorator.keywords if item.arg == "ids"]
    return not ids or (
        len(ids) == 1
        and isinstance(ids[0], (ast.List, ast.Tuple))
        and len(ids[0].elts) == count
        and all(
            isinstance(item, ast.Constant) and isinstance(item.value, str)
            for item in ids[0].elts
        )
    )


def _async_runner_docstring(body):
    """Return whether a function begins with a string docstring."""
    return bool(
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    )


def _async_runner_alternative(expression, tree, functions, aliases, audit):
    """Resolve one fixture parameter to a local wrapper or imported trio.run."""
    if isinstance(expression, ast.Name):
        alternative = _async_runner_named_alternative(
            expression, tree, functions, aliases, audit
        )
    elif isinstance(expression, ast.Attribute):
        alternative = _async_runner_attribute_alternative(
            expression, tree, aliases, audit
        )
    else:
        return None
    if alternative is None or audit._click_receiver_mutated(
        tree, alternative["binding"]
    ):
        return None
    return alternative


def _async_runner_named_alternative(expression, tree, functions, aliases, audit):
    """Resolve a local asyncio wrapper or a direct imported trio.run alias."""
    matches = [item for item in functions if item.name == expression.id]
    if not matches:
        origin = _async_runner_import_origin(tree, expression.id, "trio", audit)
        if origin is None or not isinstance(origin[1], ast.ImportFrom):
            return None
        return {
            "api": "trio.run",
            "binding": expression.id,
            "_cap_origin": origin[0],
            "_cap_binding": expression.id,
            "_cap_uses": [expression],
        }
    if len(matches) != 1 or audit._module_has_rebinding(
        tree, expression.id, matches[0]
    ):
        return None
    receiver = _async_runner_wrapper_receiver(matches[0], tree, aliases, audit)
    if receiver is None:
        return None
    origin = _async_runner_import_origin(tree, receiver.id, "asyncio", audit)
    if origin is None:
        return None
    return {
        "api": "asyncio.run",
        "binding": expression.id,
        "_cap_origin": origin[0],
        "_cap_binding": receiver.id,
        "_cap_uses": [receiver],
    }


def _async_runner_attribute_alternative(expression, tree, aliases, audit):
    """Resolve a trio.run module attribute as a fixture alternative."""
    binding = expression.value.id if isinstance(expression.value, ast.Name) else ""
    if audit._resolved_ast_name(expression, aliases) != "trio.run":
        return None
    origin = _async_runner_import_origin(tree, binding, "trio", audit)
    if origin is None:
        return None
    return {
        "api": "trio.run",
        "binding": binding,
        "_cap_origin": origin[0],
        "_cap_binding": binding,
        "_cap_uses": [expression.value],
    }


def _async_runner_import_origin(tree, binding, module, audit):
    """Require an unchanged runner origin and the shared API closure proof."""
    api = f"{module}.run"
    origin = _module_import_binding_origin(tree, binding, api)
    if origin is None or audit._module_has_rebinding(tree, binding, origin[1]):
        return None
    item, statement = origin
    if isinstance(statement, ast.ImportFrom) and (
        statement.module != module or item.name != "run"
    ):
        return None
    return (
        origin
        if _module_import_aliases_are_closed(tree, module, audit, api=api)
        else None
    )


def _async_runner_wrapper_receiver(function, tree, aliases, audit):
    """Return the imported asyncio binding used by the exact callback wrapper."""
    parameters = [*function.args.posonlyargs, *function.args.args]
    body = (
        function.body[1:] if _async_runner_docstring(function.body) else function.body
    )
    if (
        function.decorator_list
        or len(parameters) != 1
        or function.args.posonlyargs
        or not function.args.vararg
        or function.args.kwarg
        or function.args.kwonlyargs
        or function.args.defaults
        or function.args.kw_defaults
        or len(body) != 1
        or not isinstance(body[0], ast.Return)
        or not isinstance(body[0].value, ast.Call)
    ):
        return None
    outer = body[0].value
    inner = outer.args[0] if len(outer.args) == 1 else None
    receiver = outer.func.value if isinstance(outer.func, ast.Attribute) else None
    if (
        not isinstance(receiver, ast.Name)
        or receiver.id
        in {
            item.arg
            for item in [
                *function.args.posonlyargs,
                *function.args.args,
                *function.args.kwonlyargs,
            ]
        }
        or audit._scope_binds_name(function, receiver.id)
    ):
        return None
    valid = bool(
        audit._resolved_ast_name(outer.func, aliases) == "asyncio.run"
        and (
            _async_runner_import_origin(tree, receiver.id, "asyncio", audit) is not None
        )
        and not audit._click_receiver_mutated(tree, receiver.id)
        and not outer.keywords
        and isinstance(inner, ast.Call)
        and isinstance(inner.func, ast.Name)
        and inner.func.id == parameters[0].arg
        and len(inner.args) == 1
        and isinstance(inner.args[0], ast.Starred)
        and isinstance(inner.args[0].value, ast.Name)
        and inner.args[0].value.id == function.args.vararg.arg
        and not inner.keywords
    )
    return receiver if valid else None


def _nested_async_runner_invocations(test, definitions, targets, aliases):
    """Return nested assertions consumed by a proven event-loop runner."""
    from . import review_audits as audit

    module = getattr(test, "_oracle_module", None)
    if not isinstance(module, ast.Module):
        return set()
    imports = audit._scope_security_aliases(
        audit._module_security_aliases(module), module
    )
    roots = {
        item.asname or item.name.split(".", 1)[0]
        for node in ast.walk(module)
        if isinstance(node, ast.Import)
        for item in node.names
        if item.name == "asyncio"
    }
    parents = audit._oracle_ancestor_map(module.body, module)
    if roots and any(
        isinstance(node, ast.Name)
        and node.id in roots
        and not (
            isinstance((attribute := parents[id(node)][-1][0]), ast.Attribute)
            and attribute.value is node
            and attribute.attr in {"run", "new_event_loop"}
            and isinstance(attribute.ctx, ast.Load)
            and isinstance((call := parents[id(attribute)][-1][0]), ast.Call)
            and call.func is attribute
        )
        for node in ast.walk(module)
    ):
        return set()
    aliases = audit._scope_security_aliases(imports, test)
    nodes = audit._test_oracle_body_nodes(test, aliases)
    invoked = set()
    for name in targets:
        function = definitions.get(name)
        if isinstance(function, ast.AsyncFunctionDef) and not function.decorator_list:
            parameters = audit._scope_parameters(test)
            candidates = [
                call
                for call in nodes
                if isinstance(call, ast.Call)
                and call.lineno > function.lineno
                and audit._effective_assertion(call, aliases)
            ]
            for call in candidates:
                ordinary = _nested_async_runner_call(
                    call, name, test, module, aliases, nodes, audit
                )
                fixture = _nested_fixture_runner_call(
                    call, name, test, module, targets, parents, audit
                )
                if ordinary or fixture:
                    invoked.add(name)
                    if isinstance(call.func, ast.Name) and (
                        call.func.id not in parameters or fixture
                    ):
                        invoked.add(call.func.id)
    return invoked


def _nested_fixture_runner_call(call, name, test, module, targets, parents, audit):
    """Accept direct callback use only through a source-bound runner fixture."""
    context = getattr(module, "_oracle_async_runner_fixtures", {})
    if (
        not isinstance(context, dict)
        or context.get("schema") != _ASYNC_RUNNER_CONTEXT_SCHEMA
        or not _is_sha256(context.get("module_sha256"))
        or context.get("module_sha256")
        != getattr(module, "_oracle_source_sha256", None)
        or name not in targets
        or not isinstance(call.func, ast.Name)
        or call.func.id not in audit._scope_parameters(test)
        or len(call.args) != 1
        or not isinstance(call.args[0], ast.Name)
        or call.args[0].id != name
        or call.keywords
        or not _capability_uses_match(list(ast.walk(test)), call.func.id, [call.func])
    ):
        return False
    fixture_map = context.get("fixtures", {})
    fixture = fixture_map.get(call.func.id) if isinstance(fixture_map, dict) else None
    alternatives = fixture.get("alternatives", ()) if isinstance(fixture, dict) else ()
    if (
        not isinstance(fixture, dict)
        or fixture.get("trusted") is not True
        or not fixture.get("source")
        or not _is_sha256(fixture.get("sha256"))
        or not alternatives
        or any(
            not isinstance(item, dict)
            or item.get("api") not in {"asyncio.run", "trio.run"}
            or not item.get("binding")
            or not _serialized_capability_is_closed(item, fixture)
            for item in alternatives
        )
    ):
        return False
    ancestors = parents.get(id(call), ())
    if not ancestors or not isinstance(ancestors[-1][0], (ast.Expr, ast.Assert)):
        return False
    return not any(
        isinstance(
            parent,
            (
                ast.If,
                ast.For,
                ast.AsyncFor,
                ast.While,
                ast.Try,
                ast.With,
                ast.AsyncWith,
                ast.Match,
                ast.Lambda,
            ),
        )
        for parent, _child in ancestors[:-1]
    )


def _serialized_capability_is_closed(alternative, fixture):
    """Require the inherited runner witness to match its fixture source identity."""
    capability = alternative.get("capability")
    if (
        not isinstance(capability, dict)
        or capability.get("status") != "CLOSED"
        or capability.get("api") != alternative.get("api")
        or capability.get("source") != fixture.get("source")
        or capability.get("sha256") != fixture.get("sha256")
        or not _is_sha256(capability.get("sha256"))
        or not isinstance(capability.get("binding"), str)
        or not capability.get("binding")
    ):
        return False
    origin = capability.get("origin")
    uses = capability.get("uses")
    return bool(
        _serialized_source_position(origin)
        and isinstance(uses, list)
        and uses
        and all(_serialized_source_position(position) for position in uses)
    )


def _serialized_source_position(value):
    """Validate integer coordinates; exact int rejects bool."""
    return isinstance(value, dict) and all(
        type(value.get(key)) is int and value[key] >= minimum
        for key, minimum in (("line", 1), ("column", 0))
    )


def _is_sha256(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _nested_async_runner_call(call, name, test, module, aliases, nodes, audit):
    """Prove event-loop consumption or a one-operation imported asyncio wrapper."""
    receiver = call.func.value if isinstance(call.func, ast.Attribute) else None
    if (
        isinstance(receiver, ast.Name)
        and getattr(call.func, "attr", None) == "run_until_complete"
        and len(call.args) == 1
        and isinstance(call.args[0], ast.Call)
        and isinstance(call.args[0].func, ast.Name)
        and call.args[0].func.id == name
        and not call.args[0].args
        and not call.args[0].keywords
        and not call.keywords
    ):
        bindings = [
            item for item in test.body if receiver.id in audit._bound_names(item)
        ]
        if len(bindings) == 1:
            binding = bindings[0]
            targets = (
                binding.targets
                if isinstance(binding, ast.Assign)
                else [getattr(binding, "target", None)]
            )
            creation = getattr(binding, "value", None)
            if (
                len(targets) == 1
                and isinstance(targets[0], ast.Name)
                and targets[0].id == receiver.id
                and isinstance(creation, ast.Call)
                and not creation.args
                and not creation.keywords
                and isinstance(creation.func, ast.Attribute)
                and aliases.get(audit._name(creation.func.value)) == "asyncio"
                and audit._resolved_ast_name(creation.func, aliases)
                == "asyncio.new_event_loop"
                and binding.lineno < call.lineno
                and not audit._name_rebound(
                    nodes, receiver.id, binding.lineno, call.lineno
                )
                and not audit._click_receiver_mutated(test, receiver.id)
            ):
                return True
    if (
        not isinstance(call.func, ast.Name)
        or len(call.args) != 1
        or not isinstance(call.args[0], ast.Name)
        or call.args[0].id != name
        or call.keywords
        or call.func.id in audit._scope_parameters(test)
        or audit._scope_binds_name(test, call.func.id)
    ):
        return False
    runner = next(
        (
            item
            for item in module.body
            if isinstance(item, ast.FunctionDef) and item.name == call.func.id
        ),
        None,
    )
    if runner is None or audit._module_has_rebinding(module, call.func.id, runner):
        return False
    parameters = [*runner.args.posonlyargs, *runner.args.args]
    body = (
        runner.body[1:]
        if runner.body
        and isinstance(runner.body[0], ast.Expr)
        and isinstance(runner.body[0].value, ast.Constant)
        and isinstance(runner.body[0].value.value, str)
        else runner.body
    )
    if (
        runner.decorator_list
        or len(parameters) != 1
        or runner.args.vararg
        or runner.args.kwarg
        or runner.args.kwonlyargs
        or len(body) != 1
        or call.lineno <= runner.lineno
    ):
        return False
    operation = getattr(body[0], "value", None)
    scoped = audit._scope_security_aliases(
        audit._module_security_aliases(module), runner
    )
    return (
        isinstance(operation, ast.Call)
        and isinstance(operation.func, ast.Attribute)
        and scoped.get(audit._name(operation.func.value)) == "asyncio"
        and audit._resolved_ast_name(operation.func, scoped) == "asyncio.run"
        and len(operation.args) == 1
        and not operation.keywords
        and isinstance(operation.args[0], ast.Call)
        and isinstance(operation.args[0].func, ast.Name)
        and operation.args[0].func.id == parameters[0].arg
        and not operation.args[0].args
        and not operation.args[0].keywords
    )


def async_runner_fixture_helpers():
    """Return all local helpers that define async fixture provenance behavior."""
    return (
        _expected_exception_else_failure,
        _try_body_has_unmediated_raise,
        _raise_is_iteration_mediated,
        _retry_factory_is_imported,
        _module_import_binding_origin,
        _module_import_origin_module_path,
        _module_import_aliases_are_closed,
        _ast_parent_map,
        _module_import_alias_candidates,
        _module_import_alias_is_closed,
        _module_api_alias_uses_are_closed,
        _module_api_use_is_closed,
        _module_api_use_is_fixture_parameter,
        _module_has_dynamic_capability_access,
        _module_path_controls_target,
        _module_import_lexical_scope,
        _module_import_binding_reassigned,
        _module_alias_uses_are_closed,
        _leftmost_name,
        _closed_capability_use_proof,
        _bounded_ast_nodes,
        _capability_uses_match,
        _scope_has_reflective_capability_access,
        _capability_reflection_names,
        async_runner_fixture_context,
        _async_runner_snapshot_records,
        _async_runner_snapshot_candidate,
        _async_runner_fixture_declarations,
        _async_runner_capability_groups,
        _async_runner_seal_declarations,
        _async_runner_declared_fixture_name,
        _async_runner_fixture_like,
        _async_runner_fixture_decorator,
        _async_runner_fixture_contract,
        _async_runner_fixture_consumer_shape,
        _async_runner_fixture_ids,
        _async_runner_docstring,
        _async_runner_alternative,
        _async_runner_named_alternative,
        _async_runner_attribute_alternative,
        _async_runner_import_origin,
        _async_runner_wrapper_receiver,
        _ast_position,
        _serialized_capability_is_closed,
        _serialized_source_position,
        _nested_async_runner_invocations,
        _nested_fixture_runner_call,
        _nested_async_runner_call,
        _is_sha256,
    )


def database_workspace_context(
    root: Path, python_sources: dict, read_source, python_inventory: list | None = None
) -> dict:
    """Capture static database context through the scanner's safe source reader."""
    return _database_workspace_context(
        root, python_sources, read_source, python_inventory
    )


def _database_workspace_context(
    root, python_sources, read_source, python_inventory=None, oracle_snapshots=None
):
    """Build the JSON projection without exposing parser trees to callers."""
    from .intent_quality import database_structure

    paths, gaps = _database_sql_paths(root)
    python_gaps = _database_python_inventory_gaps(python_inventory, python_sources)
    gaps.extend(python_gaps)
    database_signals = bool(paths) or any(
        any(name in raw for name in (b"sqlalchemy", b"sqlite3", b"psycopg", b"alembic"))
        for raw in python_sources.values()
    )
    selected = (
        {path.relative_to(root).as_posix(): raw for path, raw in python_sources.items()}
        if database_signals
        else {}
    )
    config, config_binding = _database_configuration(root, read_source, gaps)
    bindings = [config_binding] if config_binding else []
    bindings.extend(_database_sql_sources(root, paths, read_source, selected, gaps))
    if not selected or any("limit" in gap for gap in gaps):
        result = {
            "status": "NOT_APPLICABLE",
            "gaps": [],
            "tables": [],
            "queries": [],
            "operations": [],
            "source_manifest": [],
        }
    else:
        if oracle_snapshots is None:
            result = database_structure(
                selected,
                config.get("dialect", "postgres"),
                migration_order=config.get("migration_order"),
            )
        else:
            from .intent_quality import _database_structure

            trees = {
                path.relative_to(root).as_posix(): tree
                for path, raw in python_sources.items()
                if isinstance((tree := oracle_snapshots.get(path)), ast.Module)
                and getattr(tree, "_oracle_source_sha256", None)
                == hashlib.sha256(raw).hexdigest()
            }
            result = _database_structure(
                selected,
                config.get("dialect", "postgres"),
                config.get("migration_order"),
                trees,
            )
        if "dialect" not in config:
            gaps.append("database_dialect_confirmation_required")
    result["gaps"] = sorted(set(result["gaps"] + gaps))
    if result["gaps"]:
        result["status"] = "INCOMPLETE"
    result["discovery"] = _database_context_discovery(
        root, paths, gaps, python_gaps, python_inventory, selected, database_signals
    )
    result["configuration_sources"] = bindings
    result.pop("graph_digest", None)
    result["graph_digest"] = _sha(result)
    result["_bindings"] = bindings
    return result


def _populate_oracle_database_context(
    output, root, python_sources, read_source, python_inventory, oracle_snapshots
):
    """Populate the optional output with a database projection from fresh trees."""
    if output is not None:
        output.update(
            _database_workspace_context(
                root, python_sources, read_source, python_inventory, oracle_snapshots
            )
        )


def _database_sql_sources(root, paths, read_source, selected, gaps):
    bindings, sql_bytes = [], 0
    for relative in paths:
        try:
            raw = read_source(root, relative)
            if len(raw) > 1_000_000:
                gaps.append("database_source_size_limit:" + relative)
                continue
            sql_bytes += len(raw)
            if sql_bytes > 16_000_000:
                gaps.append("database_total_source_limit")
                break
            selected[relative] = raw
            bindings.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "bytes": len(raw),
                }
            )
        except (OSError, RuntimeAuditError):
            gaps.append("database_source_unreadable:" + relative)
    return bindings


def _database_context_discovery(
    root, paths, gaps, python_gaps, python_inventory, selected, database_signals
):
    return {
        "sql_files": len(paths),
        "paths": paths,
        "configuration_present": (root / "factory.database.json").exists()
        or (root / "factory.database.json").is_symlink(),
        "inventory_complete": not any(
            "discovery" in gap or "limit" in gap for gap in gaps
        )
        and not python_gaps,
        "python_sources_complete": not python_gaps,
        "python_sources_discovered": len(python_inventory or []),
        "python_sources_selected": sum(
            path.lower().endswith(".py") for path in selected
        ),
        "source_selection": "all_retained_python_when_database_signaled"
        if database_signals
        else "not_applicable",
    }


def _database_python_inventory_gaps(python_inventory, python_sources):
    if python_inventory is None:
        return ["database_python_inventory_unverified"]
    gaps = []
    for item in python_inventory:
        path = item.get("path", "")
        state = item.get("state")
        if state != "read":
            gaps.append(f"database_python_source_{state or 'unverified'}:{path}")
        elif not item.get("retained"):
            gaps.append(f"database_python_source_retention_limit:{path}")
    return gaps


def _database_sql_paths(root: Path) -> tuple[list[str], list[str]]:
    ignored = {
        ".git",
        ".factory",
        ".venv",
        "venv",
        "build",
        "dist",
        "tmp",
        "vendor",
        "site-packages",
        "__pycache__",
        "node_modules",
    }
    paths, gaps, entries = [], [], 0
    for directory, dirs, names in os.walk(
        root,
        followlinks=False,
        onerror=lambda _error: gaps.append("database_discovery_unreadable_directory"),
    ):
        entries += len(dirs) + len(names)
        if entries > 50_000:
            gaps.append("database_discovery_entry_limit")
            break
        dirs[:] = _database_directories(
            directory, [name for name in sorted(dirs) if name not in ignored], gaps
        )
        paths.extend(
            (Path(directory) / name).relative_to(root).as_posix()
            for name in sorted(names)
            if name.lower().endswith(".sql")
        )
        if len(paths) > 256:
            gaps.append("database_input_limit")
            return sorted(paths[:257]), gaps
    return sorted(paths), gaps


def _database_directories(directory, names, gaps):
    allowed = []
    for name in names:
        try:
            child = Path(directory) / name
            if (
                child.is_symlink()
                or getattr(child.lstat(), "st_file_attributes", 0) & 0x400
            ):
                gaps.append("database_discovery_linked_directory")
            else:
                allowed.append(name)
        except OSError:
            gaps.append("database_discovery_unreadable_directory")
    return allowed


def verify_database_context(root: Path, context: dict, error_type):
    """Reject new/deleted SQL inputs or configuration after context capture."""
    paths, gaps = _database_sql_paths(root)
    config = root / "factory.database.json"
    discovery = context["discovery"]
    if (
        paths != discovery["paths"]
        or bool(config.exists() or config.is_symlink())
        != discovery["configuration_present"]
        or (gaps and discovery["inventory_complete"])
    ):
        raise error_type("Database source inventory changed during scan")


def _database_configuration(
    root: Path, read_source, gaps: list
) -> tuple[dict, dict | None]:
    name = "factory.database.json"
    path = root / name
    if not path.exists() and not path.is_symlink():
        return {}, None
    try:
        raw = read_source(root, name)
        binding = {
            "path": name,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
        if len(raw) > 16_384:
            raise ValueError("configuration byte limit")
        config = json.loads(raw, object_pairs_hook=_database_json_pairs)
        if (
            not isinstance(config, dict)
            or not {"schema", "dialect"}
            <= set(config)
            <= {"schema", "dialect", "migration_order"}
            or config["schema"] != "factory.database-context-config.v1"
            or not isinstance(config["dialect"], str)
            or config["dialect"] not in {"postgres", "sqlite"}
        ):
            raise ValueError("configuration fields")
        order = config.get("migration_order")
        if order is not None and (
            not isinstance(order, list)
            or len(order) > 256
            or any(not isinstance(item, str) for item in order)
        ):
            raise ValueError("migration order fields")
        return config, binding
    except (OSError, RuntimeAuditError, ValueError, UnicodeError):
        gaps.append("database_configuration_invalid")
        return {}, locals().get("binding")


def _database_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate database configuration field")
        result[key] = value
    return result


MAX_SOURCES = 128
MAX_CHANGED_PATHS = 128
MAX_CACHE_FILES = 100
MAX_USAGE_ROWS = MAX_CACHE_FILES * 10
_USAGE_LOCK = threading.Lock()
MAX_CANDIDATES = 64
MAX_SELECTED_SOURCES = 64
MAX_EXPERIMENT_SAMPLES = 100
MAX_EXPERIMENT_HISTORY = 20
MAX_SHARD_CLAIMS = 64
MAX_SHARD_RECORDS = 256
MAX_SHARD_LOCATOR_BYTES = 16_384
MAX_SHARD_ARTIFACT_BYTES = 65_536
MAX_AST_NODES = 20_000
MAX_AST_SOURCE_BYTES = 65_536
MAX_SOURCE_BYTES = 1_048_576
MIN_TOKENS = 256
MAX_TOKENS = 12_000
MIN_FILE_TOKENS = 32
MAX_FILE_TOKENS = 2_000
_SECRET_NAME = re.compile(
    r"(?:^|[._-])(secret|token|password|passwd|credential|credentials|private[-_]?key|api[-_]?key)(?:$|[._-])|(?:^|[/\\])\.env(?:\.[^/\\]*)?$|(?:^|[/\\])(?:id_rsa|id_ed25519|known_hosts|credentials\.json|service[-_]?account[^/\\]*|kubeconfig)$",
    re.I,
)
_SECRET_BYTES = (
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(rb"(?:ghp_|github_pat_|pypi-|vsce[_-]?pat)[A-Za-z0-9_-]{8,}"),
    re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(rb"AIza[0-9A-Za-z_-]{30,}"),
    re.compile(
        rb"(?:sk-(?:live|proj|ant|test)-|xox[baprs]-|ya29\.)[A-Za-z0-9._-]{12,}"
    ),
)
_REDACT = (
    re.compile(
        r"(?i)(\b(?:token|password|passwd|secret|(?:[a-z0-9]+_)?api[_-]?key|authorization)\s*[:=]\s*)([^\s,;]+)"
    ),
    re.compile(r"(?i)(\b(?:bearer)\s+)([^\s]+)"),
)


class ContextEfficiencyError(ValueError):
    """Stable fail-closed error raised for malformed or changed context."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _canonical(value: Any) -> bytes:
    try:
        return canonical_bytes(value)
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ContextEfficiencyError(
            "E_CANONICAL", "value is not canonical JSON"
        ) from exc


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _safe_text(value: Any, field: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(char) < 32 for char in value)
    ):
        _invalid(
            "E_FIELD",
            f"{field} must be a non-empty printable string of at most {maximum} characters",
        )
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        _invalid("E_DIGEST", f"{field} must be a lowercase SHA-256 digest")
    return value


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        _invalid("E_FIELD", f"{field} must be an integer in {minimum}..{maximum}")
    return value


def _reject_secret_keys(value: Any, path: str = "request", depth: int = 0) -> None:
    if depth > 16:
        _invalid("E_DEPTH", "request nesting exceeds 16")
    if isinstance(value, dict):
        for key, child in value.items():
            if _SECRET_NAME.search(str(key)):
                _invalid("E_SECRET_MATERIAL", f"secret-shaped field at {path}.{key}")
            _reject_secret_keys(child, f"{path}.{key}", depth + 1)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_keys(child, f"{path}[{index}]", depth + 1)


def _relative_path(root: Path, raw: Any, field: str) -> tuple[Path, str]:
    value = _safe_text(raw, field, 512).replace("\\", "/")
    candidate_raw = Path(value)
    if candidate_raw.is_absolute() or re.match(r"^[A-Za-z]:/", value):
        _invalid("E_PATH_BOUNDARY", f"{field} must be relative to the workspace")
    if any(part in {"", ".", ".."} for part in candidate_raw.parts):
        _invalid("E_PATH_BOUNDARY", f"{field} contains traversal or empty components")
    workspace = _validated_root(root)
    candidate = workspace.joinpath(candidate_raw)
    ancestor = workspace
    for part in candidate_raw.parts:
        ancestor = ancestor / part
        if ancestor.is_symlink():
            _invalid("E_PATH_LINK", f"{field} may not traverse a symlink")
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ContextEfficiencyError(
            "E_PATH_BOUNDARY", f"{field} escapes the workspace"
        ) from exc
    if candidate.is_symlink() or resolved.is_symlink():
        _invalid("E_PATH_LINK", f"{field} may not be a symlink")
    return resolved, resolved.relative_to(workspace).as_posix()


def _stable_file(path: Path) -> tuple[bytes, str, dict[str, int]]:
    try:
        before = path.stat()
        if not path.is_file() or path.is_symlink() or before.st_size > MAX_SOURCE_BYTES:
            _invalid(
                "E_SOURCE_BOUNDARY",
                f"source is missing, a symlink, or exceeds {MAX_SOURCE_BYTES} bytes",
            )
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_SOURCE_BYTES:
                    _invalid(
                        "E_SOURCE_BOUNDARY",
                        f"source exceeds {MAX_SOURCE_BYTES} bytes while reading",
                    )
                digest.update(chunk)
                chunks.append(chunk)
        after = path.stat()
    except ContextEfficiencyError:
        raise
    except OSError as exc:
        raise ContextEfficiencyError(
            "E_SOURCE_READ", f"cannot read source: {path}"
        ) from exc
    identity_before = {
        "size": int(before.st_size),
        "mtime_ns": int(before.st_mtime_ns),
        "ino": int(getattr(before, "st_ino", 0)),
    }
    identity_after = {
        "size": int(after.st_size),
        "mtime_ns": int(after.st_mtime_ns),
        "ino": int(getattr(after, "st_ino", 0)),
    }
    if identity_before != identity_after:
        _invalid("E_SOURCE_CHANGED", f"source changed while reading: {path}")
    raw = b"".join(chunks)
    return raw, digest.hexdigest(), identity_before


def _validate_request_fields(request: Any) -> None:
    if not isinstance(request, dict):
        _invalid("E_REQUEST_FIELDS", "request has missing or unknown fields")
    _reject_secret_keys(request)
    if set(request) != {
        "schema",
        "mission_id",
        "contract_digest",
        "changed_paths",
        "sources",
        "max_tokens",
        "per_file_tokens",
    }:
        _invalid("E_REQUEST_FIELDS", "request has missing or unknown fields")
    if request["schema"] != REQUEST_SCHEMA:
        _invalid("E_SCHEMA", "unsupported request schema")


def _normalize_changed_paths(root: Path, raw_paths: Any) -> list[str]:
    changed: list[str] = []
    if not isinstance(raw_paths, list) or not 1 <= len(raw_paths) <= MAX_CHANGED_PATHS:
        _invalid("E_FIELD", f"changed_paths must contain 1..{MAX_CHANGED_PATHS} paths")
    for index, item in enumerate(raw_paths):
        _, relative = _relative_path(root, item, f"changed_paths[{index}]")
        if relative in changed:
            _invalid("E_DUPLICATE_PATH", f"duplicate changed path: {relative}")
        changed.append(relative)
    return changed


def _normalize_request_sources(root: Path, raw_sources: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_sources, list) or not 1 <= len(raw_sources) <= MAX_SOURCES:
        _invalid("E_FIELD", f"sources must contain 1..{MAX_SOURCES} entries")
    sources: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, entry in enumerate(raw_sources):
        if not isinstance(entry, dict) or set(entry) != {"path", "role", "priority"}:
            _invalid(
                "E_SOURCE_FIELDS", f"sources[{index}] has missing or unknown fields"
            )
        _, relative = _relative_path(root, entry["path"], f"sources[{index}].path")
        if relative in seen:
            _invalid("E_DUPLICATE_PATH", f"duplicate source path: {relative}")
        seen.add(relative)
        sources.append(
            {
                "path": relative,
                "role": _safe_text(entry["role"], f"sources[{index}].role", 80),
                "priority": _bounded_int(
                    entry["priority"], f"sources[{index}].priority", 0, 100
                ),
            }
        )
    sources.sort(key=lambda item: (-item["priority"], item["role"], item["path"]))
    return sources


def select_context_request(
    root: Path, manifest: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Rank only explicitly supplied candidates; never scan the workspace."""
    request, selection, _ = _select_context_request(root, manifest)
    return request, selection


def _select_context_request(
    root: Path, manifest: Any
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    task, changed, candidates, required, required_roles, max_sources = (
        _selection_inputs(root, manifest)
    )
    task_terms = set(re.findall(r"[a-z0-9]+", task.lower()))
    rows = [
        _score_candidate(root, item, index, task_terms, changed, required)
        for index, item in enumerate(candidates)
    ]
    if len({row["path"] for row in rows}) != len(rows):
        _invalid("E_DUPLICATE_PATH", "duplicate candidate path")
    if not required.issubset({row["path"] for row in rows}):
        _invalid("E_REQUIRED_EVIDENCE", "required path is absent from candidates")
    rows.sort(key=lambda row: (-row["score"], row["path"]))
    role_required = _required_role_paths(rows, required_roles)
    required.update(role_required)
    _order_selection_rows(rows, changed, required)
    selected = rows[:max_sources]
    if any(row["required"] for row in rows[len(selected) :]):
        _invalid("E_REQUIRED_EVIDENCE", "max_sources would omit required evidence")
    request, selection = _selection_outputs(
        root, manifest, task, changed, rows, selected, required, required_roles
    )
    return request, selection, rows


def _selection_inputs(
    root: Path, manifest: Any
) -> tuple[str, list[str], list[Any], set[str], list[str], int]:
    fields = {
        "schema",
        "task",
        "mission_id",
        "contract_digest",
        "changed_paths",
        "candidates",
        "required_paths",
        "required_evidence_roles",
        "max_sources",
        "max_tokens",
        "per_file_tokens",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != fields
        or manifest.get("schema") != SELECTION_SCHEMA
    ):
        _invalid(
            "E_SELECTION_FIELDS", "selection manifest has missing or unknown fields"
        )
    task = _safe_text(manifest["task"], "task", 2000)
    changed = _normalize_changed_paths(root, manifest["changed_paths"])
    candidates = manifest["candidates"]
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= MAX_CANDIDATES:
        _invalid("E_FIELD", f"candidates must contain 1..{MAX_CANDIDATES} entries")
    max_sources = _bounded_int(
        manifest["max_sources"], "max_sources", 1, MAX_SELECTED_SOURCES
    )
    required_raw = manifest["required_paths"]
    if not isinstance(required_raw, list) or len(required_raw) > MAX_CANDIDATES:
        _invalid("E_FIELD", "required_paths must be a bounded list")
    required = {
        _relative_path(root, item, "required_paths[]")[1] for item in required_raw
    }
    required_roles = manifest["required_evidence_roles"]
    if not isinstance(required_roles, list) or len(required_roles) > 16:
        _invalid("E_FIELD", "required_evidence_roles must be a bounded list")
    required_roles = sorted(
        {
            _safe_text(role, "required_evidence_roles[]", 80).lower()
            for role in required_roles
        }
    )
    return task, changed, candidates, required, required_roles, max_sources


def _score_candidate(
    root: Path,
    item: Any,
    index: int,
    task_terms: set[str],
    changed: list[str],
    required: set[str],
) -> dict[str, Any]:
    if not isinstance(item, dict) or set(item) != {"path", "role"}:
        _invalid(
            "E_CANDIDATE_FIELDS", f"candidates[{index}] must contain path and role"
        )
    _, path = _relative_path(root, item["path"], f"candidates[{index}].path")
    role = _safe_text(item["role"], f"candidates[{index}].role", 80)
    raw, digest, identity = _stable_file(root / path)
    try:
        source_text = raw.decode("utf-8")
    except UnicodeDecodeError:
        source_text = ""
    if _SECRET_NAME.search(path) or any(
        pattern.search(raw) for pattern in _SECRET_BYTES
    ):
        source_text = ""
    path_terms = set(re.findall(r"[a-z0-9]+", path.lower()))
    role_terms = set(re.findall(r"[a-z0-9]+", role.lower()))
    content_terms = set(re.findall(r"[a-z0-9]+", source_text.lower()))
    matched_terms = sorted(task_terms & (path_terms | role_terms | content_terms))[:32]
    score = (
        len(task_terms & path_terms) * 10
        + len(task_terms & role_terms) * 3
        + len(task_terms & content_terms) * 2
        + (20 if path in changed else 0)
    )
    return {
        "path": path,
        "role": role,
        "score": score,
        "priority": 0,
        "stage": 3,
        "required": path in required,
        "sha256": digest,
        "identity": identity,
        "matched_terms": matched_terms,
        "why_selected": "",
        "raw": raw,
        "structure": _structural_evidence(path, raw),
    }


class _EvidenceVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.visited = 0
        self.identifiers: set[str] = set()
        self.definitions: list[dict[str, Any]] = []
        self.imports: set[str] = set()
        self.calls: set[str] = set()

    def _count_node(self) -> None:
        self.visited += 1
        if self.visited > MAX_AST_NODES:
            raise ContextEfficiencyError(
                "E_AST_BOUNDARY", "source structure exceeds node limit"
            )

    def _add_bounded(self, target: set[str], value: str) -> None:
        if len(target) >= 2048 and value not in target:
            raise ContextEfficiencyError(
                "E_AST_BOUNDARY", "source identifiers exceed collection limit"
            )
        target.add(value)

    def generic_visit(self, node: ast.AST) -> None:
        """Collect bounded identifiers while traversing syntax without execution."""
        self._count_node()
        if isinstance(node, ast.Name):
            self._add_bounded(self.identifiers, node.id)
        super().generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Record function definition ranges and visit their bounded syntax tree."""
        self.definitions.append(
            {
                "name": node.name,
                "kind": "function",
                "start": node.lineno,
                "end": node.end_lineno or node.lineno,
            }
        )
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Record class definition ranges and visit their bounded syntax tree."""
        self.definitions.append(
            {
                "name": node.name,
                "kind": "class",
                "start": node.lineno,
                "end": node.end_lineno or node.lineno,
            }
        )
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Collect bounded direct module imports from this syntax node."""
        self._count_node()
        for item in node.names:
            self._add_bounded(self.imports, item.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Collect bounded relative or absolute imports from this syntax node."""
        self._count_node()
        self._add_bounded(self.imports, "." * node.level + (node.module or ""))
        for item in node.names:
            self._add_bounded(self.imports, item.name)

    def visit_Call(self, node: ast.Call) -> None:
        """Collect bounded syntactic call names without resolving their targets."""
        name = (
            node.func.id
            if isinstance(node.func, ast.Name)
            else node.func.attr
            if isinstance(node.func, ast.Attribute)
            else ""
        )
        if name:
            self._add_bounded(self.calls, name)
        self.generic_visit(node)


def _structural_evidence(path: str, raw: bytes) -> dict[str, Any]:
    if path.lower().endswith(".sql"):
        return _database_structural_evidence(path, raw)
    if (
        not path.endswith(".py")
        or _SECRET_NAME.search(path)
        or any(pattern.search(raw) for pattern in _SECRET_BYTES)
        or len(raw) > MAX_AST_SOURCE_BYTES
    ):
        return {
            "status": "PARSE_LIMIT"
            if path.endswith(".py") and len(raw) > MAX_AST_SOURCE_BYTES
            else "NOT_PARSED",
            "definitions": [],
            "imports": [],
            "calls": [],
            "identifiers": [],
        }
    try:
        tree = ast.parse(raw.decode("utf-8"), filename=path)
        visitor = _EvidenceVisitor()
        visitor.visit(tree)
    except (SyntaxError, UnicodeError, RecursionError, ContextEfficiencyError):
        return {
            "status": "PARSE_LIMIT_OR_ERROR",
            "definitions": [],
            "imports": [],
            "calls": [],
            "identifiers": [],
        }
    return {
        "status": "SYNTACTIC_ONLY",
        "node_count": visitor.visited,
        "definitions": sorted(
            visitor.definitions, key=lambda row: (row["start"], row["name"])
        )[:256],
        "imports": sorted(visitor.imports)[:256],
        "calls": sorted(visitor.calls)[:256],
        "identifiers": sorted(
            visitor.identifiers | _database_identifier_hints(path, raw)
        )[:512],
    }


def _database_identifier_hints(path: str, raw: bytes) -> set[str]:
    if not path.lower().endswith(".sql") and b"sqlalchemy" not in raw:
        return set()
    from .intent_quality import database_structure

    graph = database_structure({path: raw}, "postgres")
    return {table["name"] for table in graph["tables"]}


def _database_structural_evidence(path: str, raw: bytes) -> dict[str, Any]:
    empty = {
        "status": "NOT_PARSED",
        "definitions": [],
        "imports": [],
        "calls": [],
        "identifiers": [],
    }
    if (
        _SECRET_NAME.search(path)
        or any(pattern.search(raw) for pattern in _SECRET_BYTES)
        or len(raw) > MAX_AST_SOURCE_BYTES
    ):
        return empty
    from .intent_quality import database_structure

    graph = database_structure({path: raw}, "postgres")
    return {
        **empty,
        "status": "DATABASE_STATIC_ONLY"
        if graph["status"] == "COMPLETE"
        else "PARSE_LIMIT_OR_ERROR",
        "identifiers": sorted(table["name"] for table in graph["tables"])[:512],
    }


def _required_role_paths(
    rows: list[dict[str, Any]], required_roles: list[str]
) -> set[str]:
    available = {row["role"].lower() for row in rows}
    missing = sorted(set(required_roles) - available)
    if missing:
        _invalid(
            "E_REQUIRED_EVIDENCE",
            "missing candidate evidence roles: " + ", ".join(missing),
        )
    return {
        next(row["path"] for row in rows if row["role"].lower() == role)
        for role in required_roles
    }


def _order_selection_rows(
    rows: list[dict[str, Any]], changed: list[str], required: set[str]
) -> None:
    for row in rows:
        row["required"] = row["path"] in required
        row["stage"] = (
            0
            if row["required"]
            else 1
            if row["path"] in changed
            else 2
            if row["score"]
            else 3
        )
        row["priority"] = (
            100
            if row["stage"] == 0
            else 80 + min(row["score"], 19)
            if row["stage"] == 1
            else 50 + min(row["score"], 29)
            if row["stage"] == 2
            else 0
        )
        row["why_selected"] = (
            "required_evidence"
            if row["required"]
            else "changed_path"
            if row["path"] in changed
            else "task_terms:" + ",".join(row["matched_terms"])
            if row["matched_terms"]
            else "bounded_fallback"
        )
    rows.sort(key=lambda row: (row["stage"], -row["score"], row["path"]))


def _selection_outputs(
    root: Path,
    manifest: dict[str, Any],
    task: str,
    changed: list[str],
    rows: list[dict[str, Any]],
    selected: list[dict[str, Any]],
    required: set[str],
    required_roles: list[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    request = {
        "schema": REQUEST_SCHEMA,
        "mission_id": manifest["mission_id"],
        "contract_digest": manifest["contract_digest"],
        "changed_paths": changed,
        "sources": [
            {"path": row["path"], "role": row["role"], "priority": row["priority"]}
            for row in selected
        ],
        "max_tokens": manifest["max_tokens"],
        "per_file_tokens": manifest["per_file_tokens"],
    }
    selection = {
        "schema": SELECTION_SCHEMA,
        "task_sha256": hashlib.sha256(task.encode("utf-8")).hexdigest(),
        "candidate_count": len(rows),
        "candidates": [
            {
                **_context_project_fields(
                    row, "path role sha256 identity score matched_terms structure"
                ),
                "related_paths": _related_candidate_paths(row, rows),
            }
            for row in rows
        ],
        "selected": [
            {**_context_project_fields(row, "path score stage required why_selected")}
            for row in selected
        ],
        "omitted": [
            {
                **_context_project_fields(row, "path role sha256 score"),
                "reason": "lower_task_relevance",
            }
            for row in rows[len(selected) :]
        ],
        "required_paths": sorted(required),
        "required_evidence_roles": required_roles,
        "present_evidence_roles": sorted({row["role"].lower() for row in selected}),
        "missing_evidence_roles": sorted(
            set(required_roles) - {row["role"].lower() for row in selected}
        ),
        "ranking": "UNVERIFIED_HEURISTIC_task_terms_path_and_declared_role_v1",
    }
    return request, selection


def _related_candidate_paths(
    candidate: dict[str, Any], rows: list[dict[str, Any]]
) -> list[str]:
    names = set(candidate["structure"].get("identifiers", []))
    if not names:
        return []
    related = []
    for row in rows:
        if row["path"] == candidate["path"]:
            continue
        overlap = names & set(row["structure"].get("identifiers", []))
        if overlap:
            related.append((len(overlap), row["path"]))
    return [
        path for _, path in sorted(related, key=lambda item: (-item[0], item[1]))[:16]
    ]


def _validate_request(root: Path, request: Any) -> dict[str, Any]:
    _validate_request_fields(request)
    mission_id = _safe_text(request["mission_id"], "mission_id", 120)
    contract_digest = _digest(request["contract_digest"], "contract_digest")
    changed = _normalize_changed_paths(root, request["changed_paths"])
    sources = _normalize_request_sources(root, request["sources"])
    return {
        "schema": REQUEST_SCHEMA,
        "mission_id": mission_id,
        "contract_digest": contract_digest,
        "changed_paths": sorted(changed),
        "sources": sources,
        "max_tokens": _bounded_int(
            request["max_tokens"], "max_tokens", MIN_TOKENS, MAX_TOKENS
        ),
        "per_file_tokens": _bounded_int(
            request["per_file_tokens"],
            "per_file_tokens",
            MIN_FILE_TOKENS,
            MAX_FILE_TOKENS,
        ),
    }


def _redact(text: str) -> str:
    for pattern in _REDACT:
        text = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]", text)
    return text


def _selection(
    raw: bytes,
    per_file_tokens: int,
    remaining_bytes: int,
    *,
    sensitive_name: bool = False,
) -> tuple[str | None, str, int, int]:
    budget = max(0, min(per_file_tokens * 4, remaining_bytes))
    if not raw or budget == 0:
        return None, "digest_only", 0, len(raw)
    if sensitive_name or any(pattern.search(raw) for pattern in _SECRET_BYTES):
        return None, "digest_only", 0, len(raw)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, "digest_only", 0, len(raw)
    if len(raw) <= budget:
        selected = _redact(text)
        selected_bytes = len(selected.encode("utf-8"))
        if selected_bytes <= budget:
            return selected, "full", selected_bytes, max(0, len(raw) - selected_bytes)
        selected = selected.encode("utf-8")[:budget].decode("utf-8", "ignore")
        selected_bytes = len(selected.encode("utf-8"))
        return selected, "head_tail", selected_bytes, max(0, len(raw) - selected_bytes)
    # Keep both the beginning (intent/configuration) and the end (results/errors)
    # so a compact packet remains useful without pretending to be complete.
    half = max(1, budget // 2)
    head = raw[:half].decode("utf-8", "ignore")
    tail = raw[-half:].decode("utf-8", "ignore")
    selected = _redact(head) + "\nÃ¢â‚¬Â¦[context omitted]Ã¢â‚¬Â¦\n" + _redact(tail)
    selected_bytes = len(selected.encode("utf-8"))
    if selected_bytes > budget:
        selected = selected.encode("utf-8")[:budget].decode("utf-8", "ignore")
        selected_bytes = len(selected.encode("utf-8"))
    return selected, "head_tail", selected_bytes, max(0, len(raw) - selected_bytes)


def _packet_digest(packet: dict[str, Any]) -> str:
    body = {key: value for key, value in packet.items() if key != "packet_sha256"}
    return _sha(body)


def _cache_dir(root: Path) -> Path:
    return Path(root) / ".factory" / "context-efficiency"


def _validated_root(root: Path) -> Path:
    lexical = Path(root).absolute()
    if _has_reparse_ancestor(lexical):
        _invalid("E_PATH_LINK", "workspace path traverses a reparse point")
    return lexical.resolve()


def _record_cache_hit(root: Path, cache_key: str) -> bool:
    """Record bounded operational telemetry outside immutable packet bytes."""
    path = _cache_dir(root) / "usage.sqlite3"
    try:
        raw_root = Path(root).absolute()
        if _has_reparse_ancestor(raw_root):
            return False
        workspace = raw_root.resolve()
        factory_dir = workspace / ".factory"
        cache_dir = _cache_dir(workspace)
        if _unsafe_cache_path(workspace, factory_dir, cache_dir, path):
            return False
        cache_dir.mkdir(parents=True, exist_ok=True)
        if _unsafe_cache_path(workspace, factory_dir, cache_dir, path):
            return False
        with _USAGE_LOCK, sqlite3.connect(path, timeout=2) as database:
            database.execute("PRAGMA max_page_count=256")
            database.execute(
                "CREATE TABLE IF NOT EXISTS cache_usage ("
                "cache_key TEXT PRIMARY KEY, hits INTEGER NOT NULL CHECK(hits >= 0))"
            )
            database.execute("BEGIN IMMEDIATE")
            exists = database.execute(
                "SELECT 1 FROM cache_usage WHERE cache_key = ?", (cache_key,)
            ).fetchone()
            if (
                exists
                or database.execute("SELECT COUNT(*) FROM cache_usage").fetchone()[0]
                < MAX_USAGE_ROWS
            ):
                database.execute(
                    "INSERT INTO cache_usage(cache_key, hits) VALUES (?, 1) "
                    "ON CONFLICT(cache_key) DO UPDATE SET hits = hits + 1",
                    (cache_key,),
                )
                return True
            return False
    except sqlite3.Error:
        # Cache correctness does not depend on optional status telemetry.
        return False
    except (OSError, OverflowError, ValueError):
        return False


def _mark_cache_usage_unknown(root: Path) -> None:
    raw_root = Path(root).absolute()
    if _has_reparse_ancestor(raw_root):
        return
    workspace = raw_root.resolve()
    factory_dir = workspace / ".factory"
    cache_dir = _cache_dir(workspace)
    marker = cache_dir / "usage-incomplete"
    if _unsafe_cache_path(workspace, factory_dir, cache_dir, marker):
        return
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        marker.write_text("cache usage telemetry is incomplete\n", encoding="utf-8")
    except OSError:
        return


def _unsafe_cache_path(
    workspace: Path, factory_dir: Path, cache_dir: Path, database: Path
) -> bool:
    for path in (workspace, factory_dir, cache_dir, database):
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            return True
        try:
            if path.exists():
                info = path.lstat()
                attributes = getattr(info, "st_file_attributes", 0)
                if stat.S_ISLNK(info.st_mode) or attributes & getattr(
                    stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
                ):
                    return True
            path.resolve(strict=False).relative_to(workspace)
        except (OSError, ValueError):
            return True
        if path.exists() and path.is_file() and path.stat().st_size > 1_000_000:
            return True
    return False


def _has_reparse_ancestor(path: Path) -> bool:
    for ancestor in (path, *path.parents):
        try:
            if stat.S_ISLNK(ancestor.lstat().st_mode):
                return True
            attributes = getattr(ancestor.lstat(), "st_file_attributes", 0)
            if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                return True
        except FileNotFoundError:
            continue
        except OSError:
            return True
    return False


def _cache_hit_count(root: Path, cache_key: str) -> int | None:
    raw_root = Path(root).absolute()
    if _has_reparse_ancestor(raw_root):
        return None
    workspace = raw_root.resolve()
    factory_dir = workspace / ".factory"
    cache_dir = _cache_dir(workspace)
    path = cache_dir / "usage.sqlite3"
    try:
        if _unsafe_cache_path(workspace, factory_dir, cache_dir, path):
            return None
        if not path.exists():
            return None
        incomplete = cache_dir / "usage-incomplete"
        if _unsafe_cache_path(workspace, factory_dir, cache_dir, incomplete):
            return None
        if incomplete.exists():
            return None
        uri = path.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=2) as database:
            row = database.execute(
                "SELECT hits FROM cache_usage WHERE cache_key = ?", (cache_key,)
            ).fetchone()
        if row is None:
            return None
        hits = row[0]
        if (
            isinstance(hits, bool)
            or not isinstance(hits, int)
            or not 0 <= hits <= 2**31 - 1
        ):
            return None
        return hits
    except sqlite3.Error:
        return None
    except (OSError, OverflowError, ValueError):
        return None


def _read_bounded(path: Path, limit: int = 1_000_000) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        _invalid("E_INPUT_BOUNDARY", f"input exceeds {limit} bytes")
    return raw


def _read_source_rows(
    workspace: Path, normalized: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    source_digests: list[dict[str, Any]] = []
    for source in normalized["sources"]:
        path = workspace / source["path"]
        raw, digest, identity = _stable_file(path)
        source_digests.append(
            {"path": source["path"], "sha256": digest, "identity": identity}
        )
        rows.append(
            {"source": source, "raw": raw, "sha256": digest, "identity": identity}
        )
    return rows, source_digests


def _load_cached_packet(
    cache_path: Path,
    request: dict[str, Any],
    rows: list[dict[str, Any]],
    selection: dict[str, Any] | None,
) -> dict[str, Any] | None:
    try:
        cached = json.loads(_read_bounded(cache_path).decode("utf-8"))
        if (
            not isinstance(cached, dict)
            or cached.get("schema") != PACKET_SCHEMA
            or _packet_digest(cached) != cached.get("packet_sha256")
            or cached.get("request") != request
            or cached.get("selection") != selection
        ):
            return None
        packet_sources = _validate_source_rows(
            cached.get("sources"), request["sources"]
        )
        _validate_packet_cache(cached, request, _source_identity_rows(packet_sources))
        _validate_packet_snapshot(cached, request, rows, packet_sources)
        return cached
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ContextEfficiencyError,
        TypeError,
        ValueError,
    ):
        return None


def _write_packet(path: Path, packet: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(packet, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _assemble_packet(
    normalized: dict[str, Any],
    rows: list[dict[str, Any]],
    cache_key: str,
    cache_path: Path,
    selection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    max_bytes = normalized["max_tokens"] * 4
    remaining = max_bytes
    selected_rows: list[dict[str, Any]] = []
    total_source_bytes = 0
    selected_bytes = 0
    truncated = 0
    digest_only = 0
    for row in rows:
        raw = row["raw"]
        total_source_bytes += len(raw)
        excerpt, inclusion, used, omitted = _selection(
            raw,
            normalized["per_file_tokens"],
            remaining,
            sensitive_name=bool(_SECRET_NAME.search(row["source"]["path"])),
        )
        remaining -= used
        selected_bytes += used
        truncated += int(inclusion == "head_tail")
        digest_only += int(inclusion == "digest_only")
        item: dict[str, Any] = {
            "path": row["source"]["path"],
            "role": row["source"]["role"],
            "priority": row["source"]["priority"],
            "source_sha256": row["sha256"],
            "source_bytes": len(raw),
            "selected_bytes": used,
            "omitted_bytes": omitted,
            "inclusion": inclusion,
            "identity": row["identity"],
        }
        if selection is not None:
            selected_metadata = next(
                selected
                for selected in selection["selected"]
                if selected["path"] == row["source"]["path"]
            )
            item["stage"] = selected_metadata["stage"]
            item["why_selected"] = selected_metadata["why_selected"]
            candidate_metadata = next(
                candidate
                for candidate in selection["candidates"]
                if candidate["path"] == row["source"]["path"]
            )
            item["structural_evidence"] = candidate_metadata["structure"]
        if excerpt is not None:
            item["excerpt"] = excerpt
        selected_rows.append(item)
    if selection is not None:
        required = set(selection["required_paths"])
        missing = [
            row["path"]
            for row in selected_rows
            if row["path"] in required and row["inclusion"] != "full"
        ]
        if missing:
            _invalid(
                "E_REQUIRED_EVIDENCE",
                "required sources must be fully included: " + ", ".join(missing),
            )
    packet: dict[str, Any] = {
        "schema": PACKET_SCHEMA,
        "module_version": MODULE_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "request": normalized,
        "sources": selected_rows,
        "selection": selection,
        "budget": {
            "max_tokens": normalized["max_tokens"],
            "max_bytes": max_bytes,
            "estimated_tokens": ceil(selected_bytes / 4),
            "selected_bytes": selected_bytes,
            "source_bytes": total_source_bytes,
            "omitted_bytes": max(0, total_source_bytes - selected_bytes),
            "decision": "TRUNCATED"
            if truncated or digest_only or selected_bytes < total_source_bytes
            else "WITHIN_BUDGET",
            "truncated_files": truncated,
            "digest_only_files": digest_only,
            "token_quality": "estimated_from_utf8_bytes_not_provider_usage",
            "progression": [
                {
                    "stage": stage,
                    "selected_sources": sum(
                        row.get("stage") == stage for row in selected_rows
                    ),
                    "selected_bytes": sum(
                        row["selected_bytes"]
                        for row in selected_rows
                        if row.get("stage") == stage
                    ),
                    "meaning": (
                        "required",
                        "changed",
                        "task_relevant",
                        "bounded_fallback",
                    )[stage],
                }
                for stage in range(4)
            ]
            if selection is not None
            else [],
        },
        "cache": {
            "key": cache_key,
            "hit": False,
            "path": cache_path.relative_to(cache_path.parents[2]).as_posix(),
        },
        "authority": _context_read_only_authority(),
        "claim_boundary": "Read-only bounded context selection. Token counts are estimates; this packet does not authorize execution, approval, repair, merge, publication, deployment, or credential access.",
    }
    packet["packet_sha256"] = _packet_digest(packet)
    return packet


def build_context_packet(
    root: Path,
    request: dict[str, Any],
    out: Path | None = None,
    *,
    selection: dict[str, Any] | None = None,
    source_snapshot: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build or exactly reuse one bounded packet; never executes a source."""
    workspace = _validated_root(root)
    normalized = _validate_request(workspace, request)
    if source_snapshot is None:
        rows, source_digests = _read_source_rows(workspace, normalized)
    else:
        rows, source_digests = _rows_from_selection_snapshot(
            normalized, selection, source_snapshot
        )
    cache_key = _sha(
        {
            "module_version": MODULE_VERSION,
            "request": normalized,
            "sources": source_digests,
            "selection": selection,
        }
    )
    cache_path = _cache_dir(workspace) / f"{cache_key}.json"
    if cache_path.is_file():
        cached = _load_cached_packet(cache_path, normalized, rows, selection)
        if cached is not None:
            telemetry_recorded = _record_cache_hit(workspace, cache_key)
            if not telemetry_recorded:
                _mark_cache_usage_unknown(workspace)
            result = deepcopy(cached)
            result["cache"] = {
                **result.get("cache", {}),
                "hit": True,
                "usage_count": _cache_hit_count(workspace, cache_key)
                if telemetry_recorded
                else None,
            }
            result["packet_sha256"] = _packet_digest(result)
            if out is not None:
                _write_packet(Path(out), result)
            return result
    packet = _assemble_packet(normalized, rows, cache_key, cache_path, selection)
    _write_packet(cache_path, packet)
    if out is not None:
        _write_packet(Path(out), packet)
    return packet


def build_selected_context_packet(
    root: Path, manifest: Any, out: Path | None = None
) -> dict[str, Any]:
    """Rank declared evidence candidates and build from their stable source snapshots."""
    request, selection, candidates = _select_context_request(root, manifest)
    return build_context_packet(
        root,
        request,
        out,
        selection=selection,
        source_snapshot=candidates,
    )


def _rows_from_selection_snapshot(
    request: dict[str, Any],
    selection: dict[str, Any] | None,
    candidates: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if selection is None:
        _invalid("E_SELECTION_FIELDS", "selection is required")
    candidates_by_path = {row["path"]: row for row in candidates}
    rows = []
    digests = []
    for source in request["sources"]:
        candidate = candidates_by_path.get(source["path"])
        if candidate is None or candidate["role"] != source["role"]:
            _invalid("E_SELECTION_FIELDS", "selected source is not in snapshot")
        raw = candidate["raw"]
        rows.append(
            {
                "source": source,
                "raw": raw,
                "sha256": candidate["sha256"],
                "identity": candidate["identity"],
            }
        )
        digests.append(
            {
                "path": source["path"],
                "sha256": candidate["sha256"],
                "identity": candidate["identity"],
            }
        )
    return rows, digests


def _metric(value: Any, field: str, *, maximum: float = 1_000_000) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _invalid("E_EXPERIMENT_METRIC", f"{field} must be numeric")
    result = float(value)
    if not 0 <= result <= maximum:
        _invalid("E_EXPERIMENT_METRIC", f"{field} is outside bounds")
    return result


def _experiment_header(observation: Any) -> tuple[str, list[Any]]:
    fields = {
        "schema",
        "task_sha256",
        "revision_sha256",
        "model_id",
        "tools_sha256",
        "budget_sha256",
        "rubric_sha256",
        "cost_unit",
        "evidence_level",
        "samples",
    }
    if not isinstance(observation, dict) or set(observation) != fields:
        _invalid(
            "E_EXPERIMENT_FIELDS", "paired observation has missing or unknown fields"
        )
    if (
        observation["schema"] != EXPERIMENT_SCHEMA
        or observation["evidence_level"] != "operator_supplied_unverified"
    ):
        _invalid(
            "E_EXPERIMENT_SCHEMA", "unsupported experiment schema or evidence level"
        )
    if observation["cost_unit"] not in {"USD", "not_recorded"}:
        _invalid("E_EXPERIMENT_METRIC", "cost_unit must be USD or not_recorded")
    for key in (
        "task_sha256",
        "revision_sha256",
        "tools_sha256",
        "budget_sha256",
        "rubric_sha256",
    ):
        _digest(observation[key], key)
    samples = observation["samples"]
    if not isinstance(samples, list) or not 1 <= len(samples) <= MAX_EXPERIMENT_SAMPLES:
        _invalid(
            "E_EXPERIMENT_SAMPLES", "samples must contain 1..100 paired observations"
        )
    return _safe_text(observation["model_id"], "model_id", 160), samples


def _arm_measurement(
    row: Any, arm: str
) -> tuple[float, float, float | None, float | None]:
    optional = {"phases_seconds", "quality", "cost", "tokens"}
    if (
        not isinstance(row, dict)
        or set(row) - optional
        or not {"phases_seconds", "quality"}.issubset(row)
    ):
        _invalid(
            "E_EXPERIMENT_SAMPLE", f"{arm} sample requires phase timings and quality"
        )
    phases = row["phases_seconds"]
    names = {"context_gathering", "coding", "repair"}
    if not isinstance(phases, dict) or set(phases) != names:
        _invalid(
            "E_EXPERIMENT_PHASES",
            "all context_gathering, coding, and repair timings are required",
        )
    seconds = sum(_metric(phases[name], f"{arm}.{name}") for name in names)
    quality = _metric(row["quality"], f"{arm}.quality", maximum=100)
    cost = _metric(row["cost"], f"{arm}.cost") if "cost" in row else None
    tokens = _metric(row["tokens"], f"{arm}.tokens") if "tokens" in row else None
    return seconds, quality, cost, tokens


def _collect_experiment_metrics(
    samples: list[Any],
) -> dict[str, dict[str, list[float]]]:
    metrics = {
        name: {arm: [] for arm in ("baseline", "context")}
        for name in ("seconds", "quality", "cost", "tokens")
    }
    seen: set[str] = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict) or set(sample) != {"id", "baseline", "context"}:
            _invalid("E_EXPERIMENT_SAMPLE", f"samples[{index}] is malformed")
        sample_id = _safe_text(sample["id"], f"samples[{index}].id", 120)
        if sample_id in seen:
            _invalid("E_EXPERIMENT_SAMPLE", "sample ids must be unique")
        seen.add(sample_id)
        for arm in ("baseline", "context"):
            seconds, quality, cost, tokens = _arm_measurement(sample[arm], arm)
            for key, value in (
                ("seconds", seconds),
                ("quality", quality),
                ("cost", cost),
                ("tokens", tokens),
            ):
                if value is not None:
                    metrics[key][arm].append(value)
        for key in ("cost", "tokens"):
            if (key in sample["baseline"]) != (key in sample["context"]):
                _invalid(
                    "E_EXPERIMENT_METRIC",
                    f"{key} must be measured for both arms or neither",
                )
    return metrics


def _experiment_projection(
    observation: dict[str, Any],
    model: str,
    samples: list[Any],
    metrics: dict[str, dict[str, list[float]]],
) -> dict[str, Any]:
    if (
        median(metrics["seconds"]["baseline"]) <= 0
        or median(metrics["seconds"]["context"]) <= 0
    ):
        _invalid("E_EXPERIMENT_METRIC", "median elapsed time must be positive")
    count = len(samples)
    for key in ("cost", "tokens"):
        values = metrics[key]["baseline"]
        if values and len(values) != count:
            _invalid(
                "E_EXPERIMENT_METRIC", f"{key} must be present in every pair or omitted"
            )
    has_cost = bool(metrics["cost"]["baseline"])
    if has_cost != (observation["cost_unit"] == "USD"):
        _invalid("E_EXPERIMENT_METRIC", "cost_unit does not match cost observations")
    baseline_time = median(metrics["seconds"]["baseline"])
    context_time = median(metrics["seconds"]["context"])
    baseline_quality = median(metrics["quality"]["baseline"])
    context_quality = median(metrics["quality"]["context"])
    reduction = 1 - context_time / baseline_time
    nonregressed = context_quality >= baseline_quality
    sufficient = count >= 3
    cost = metrics["cost"]
    tokens = metrics["tokens"]
    return {
        "schema": "factory.context-efficiency-experiment-result.v1",
        "state": "TARGET_MET"
        if sufficient and reduction >= 0.5 and nonregressed
        else "TARGET_NOT_MET"
        if sufficient
        else "INSUFFICIENT_SAMPLES",
        "evidence_level": "operator_supplied_unverified",
        "model_id": model,
        "paired_sample_count": count,
        "baseline_median_seconds": baseline_time,
        "context_median_seconds": context_time,
        "observed_latency_reduction": reduction,
        "quality_nonregression": nonregressed,
        "baseline_median_quality": baseline_quality,
        "context_median_quality": context_quality,
        "observed_cost_delta": median(cost["context"]) - median(cost["baseline"])
        if cost["baseline"]
        else None,
        "observed_cost_delta_unit": "USD" if cost["baseline"] else None,
        "observed_token_delta": median(tokens["context"]) - median(tokens["baseline"])
        if tokens["baseline"]
        else None,
        "observed_token_delta_unit": "tokens" if tokens["baseline"] else None,
        "claim_boundary": "Operator-supplied observations are not independently verified. Result applies only to this paired sample set; it is not a global performance claim.",
    }


def evaluate_context_experiment(observation: Any) -> dict[str, Any]:
    """Evaluate operator-supplied paired observations; never execute a model."""
    model, samples = _experiment_header(observation)
    return _experiment_projection(
        observation, model, samples, _collect_experiment_metrics(samples)
    )


def _read_experiment_history(path: Path) -> list[dict[str, Any]]:
    try:
        stored = json.loads(_read_bounded(path).decode("utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, UnicodeError, json.JSONDecodeError, ContextEfficiencyError) as exc:
        raise ContextEfficiencyError(
            "E_EXPERIMENT_STORE", "stored experiment history cannot be read"
        ) from exc
    if (
        not isinstance(stored, dict)
        or stored.get("schema") != "factory.context-efficiency-experiments.v1"
    ):
        _invalid("E_EXPERIMENT_STORE", "stored experiment history is malformed")
    entries = stored.get("results")
    if not isinstance(entries, list) or len(entries) > MAX_EXPERIMENT_HISTORY:
        _invalid("E_EXPERIMENT_STORE", "stored experiment history is malformed")
    history = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "observation",
            "observation_sha256",
            "result",
        }:
            _invalid("E_EXPERIMENT_STORE", "stored experiment record is malformed")
        if _sha(entry["observation"]) != entry["observation_sha256"]:
            _invalid("E_EXPERIMENT_STORE", "stored observation hash does not match")
        result = evaluate_context_experiment(entry["observation"])
        if entry["result"] != result:
            _invalid(
                "E_EXPERIMENT_STORE", "stored aggregate does not match observations"
            )
        history.append(result)
    return history


def record_context_experiment(root: Path, observation: Any) -> dict[str, Any]:
    """Validate and store operator-supplied paired observations as unverified evidence."""
    result = evaluate_context_experiment(observation)
    directory = _cache_dir(Path(root).resolve())
    path = directory / "experiment.json"
    _read_experiment_history(path)
    # Keep records in the file; history is used as a bounded sanity check only.
    entries: list[dict[str, Any]] = []
    if path.is_file():
        stored = json.loads(_read_bounded(path).decode("utf-8"))
        entries = stored["results"]
    directory.mkdir(parents=True, exist_ok=True)
    entry = {
        "observation": observation,
        "observation_sha256": _sha(observation),
        "result": result,
    }
    payload = {
        "schema": "factory.context-efficiency-experiments.v1",
        "results": [*entries[-(MAX_EXPERIMENT_HISTORY - 1) :], entry],
    }
    path.write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return result


def _validate_source_row_binding(
    row: Any, expected: dict[str, Any], allowed: set[str]
) -> None:
    if (
        not isinstance(row, dict)
        or set(row) - allowed
        or row.get("path") != expected["path"]
        or row.get("role") != expected["role"]
        or row.get("priority") != expected["priority"]
    ):
        _invalid("E_SOURCE_ROWS", "packet source row is not bound to the request")


def _validate_source_row_accounting(row: dict[str, Any]) -> None:
    if row.get("inclusion") not in {"full", "head_tail", "digest_only"}:
        _invalid("E_SOURCE_ROWS", "packet source inclusion is invalid")
    sizes = ("source_bytes", "selected_bytes", "omitted_bytes")
    if any(not isinstance(row.get(field), int) for field in sizes):
        _invalid("E_SOURCE_ROWS", "packet source byte accounting is invalid")
    if (
        row["selected_bytes"] < 0
        or row["selected_bytes"] > row["source_bytes"]
        or row["omitted_bytes"] != row["source_bytes"] - row["selected_bytes"]
    ):
        _invalid("E_SOURCE_ROWS", "packet source byte accounting is invalid")


def _validate_source_rows(
    packet_sources: Any, expected_sources: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if not isinstance(packet_sources, list) or len(packet_sources) != len(
        expected_sources
    ):
        _invalid("E_SOURCE_ROWS", "packet source rows do not match the request")
    allowed = {
        "path",
        "role",
        "priority",
        "source_sha256",
        "source_bytes",
        "selected_bytes",
        "omitted_bytes",
        "inclusion",
        "identity",
        "stage",
        "why_selected",
        "excerpt",
        "structural_evidence",
    }
    for row, expected in zip(packet_sources, expected_sources):
        _validate_source_row_binding(row, expected, allowed)
        _validate_source_row_accounting(row)
    return packet_sources


def _validate_packet_snapshot(
    packet: dict[str, Any],
    request: dict[str, Any],
    rows: list[dict[str, Any]],
    packet_sources: list[dict[str, Any]],
) -> None:
    if packet.get("request") != request:
        _invalid("E_REQUEST_MISMATCH", "packet request is not normalized")
    expected_sources = []
    by_path = {row["source"]["path"]: row for row in rows}
    for source in request["sources"]:
        row = by_path[source["path"]]
        expected_sources.append(
            {
                "path": source["path"],
                "sha256": row["sha256"],
                "identity": row["identity"],
            }
        )
    if _source_identity_rows(packet_sources) != expected_sources:
        _invalid("E_SOURCE_ROWS", "cached source identity does not match snapshot")
    remaining = request["max_tokens"] * 4
    for source, item in zip(request["sources"], packet_sources):
        raw = by_path[source["path"]]["raw"]
        excerpt, inclusion, selected, omitted = _selection(
            raw,
            request["per_file_tokens"],
            remaining,
            sensitive_name=bool(_SECRET_NAME.search(source["path"])),
        )
        remaining -= selected
        if (
            item["source_bytes"] != len(raw)
            or item["selected_bytes"] != selected
            or item["omitted_bytes"] != omitted
            or item["inclusion"] != inclusion
            or ("excerpt" in item) != (excerpt is not None)
            or item.get("excerpt") != excerpt
        ):
            _invalid(
                "E_EXCERPT_MISMATCH",
                f"cached excerpt does not match source: {source['path']}",
            )
    _verify_packet_budget(packet)


def _source_identity_rows(
    packet_sources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "path": item["path"],
            "sha256": item["source_sha256"],
            "identity": item["identity"],
        }
        for item in packet_sources
    ]


def _validate_packet_cache(
    packet: dict[str, Any],
    request: dict[str, Any],
    source_identities: list[dict[str, Any]],
) -> None:
    cache = packet.get("cache")
    expected_key = _sha(
        {
            "module_version": MODULE_VERSION,
            "request": request,
            "sources": source_identities,
            "selection": packet.get("selection"),
        }
    )
    if not isinstance(cache, dict) or cache.get("key") != expected_key:
        _invalid(
            "E_CACHE_KEY", "cache key does not match request and source identities"
        )


def _verify_selection_evidence(
    workspace: Path, selection: Any, packet_sources: list[dict[str, Any]]
) -> None:
    if selection is None:
        return
    expected_keys = {
        "schema",
        "task_sha256",
        "candidate_count",
        "candidates",
        "selected",
        "omitted",
        "required_paths",
        "required_evidence_roles",
        "present_evidence_roles",
        "missing_evidence_roles",
        "ranking",
    }
    if not isinstance(selection, dict) or set(selection) != expected_keys:
        _invalid(
            "E_SELECTION_FIELDS", "selection metadata has missing or unknown fields"
        )
    candidates, selected, omitted = _selection_rows(selection)
    candidate_paths = _verify_candidates(workspace, candidates)
    _verify_selection_partition(
        selection, candidates, selected, omitted, packet_sources, candidate_paths
    )


def _selection_rows(
    selection: dict[str, Any],
) -> tuple[list[Any], list[Any], list[Any]]:
    candidates = selection.get("candidates")
    selected = selection.get("selected")
    omitted = selection.get("omitted")
    if (
        not isinstance(candidates, list)
        or not 1 <= len(candidates) <= MAX_CANDIDATES
        or not isinstance(selected, list)
        or not isinstance(omitted, list)
        or len(candidates) != len(selected) + len(omitted)
    ):
        _invalid("E_SELECTION_FIELDS", "candidate evidence rows are malformed")
    if selection.get("candidate_count") != len(candidates):
        _invalid("E_SELECTION_FIELDS", "candidate count does not match rows")
    return candidates, selected, omitted


def _verify_candidates(workspace: Path, candidates: list[Any]) -> set[str]:
    candidate_paths: set[str] = set()
    for row in candidates:
        if not isinstance(row, dict) or set(row) != {
            "path",
            "role",
            "sha256",
            "identity",
            "score",
            "matched_terms",
            "structure",
            "related_paths",
        }:
            _invalid("E_SELECTION_FIELDS", "candidate evidence row is malformed")
        path, relative = _relative_path(
            workspace, row["path"], "selection.candidates.path"
        )
        if (
            relative in candidate_paths
            or _digest(row["sha256"], "selection.candidates.sha256") != row["sha256"]
        ):
            _invalid("E_SELECTION_FIELDS", "candidate evidence identity is invalid")
        candidate_paths.add(relative)
        _validate_structure(row["structure"])
        if not isinstance(row["related_paths"], list) or len(row["related_paths"]) > 16:
            _invalid("E_SELECTION_FIELDS", "related candidate list is malformed")
        raw, digest, identity = _stable_file(path)
        structural = _structural_evidence(relative, raw)
        if (
            digest != row["sha256"]
            or identity != row["identity"]
            or structural != row["structure"]
        ):
            _invalid("E_SELECTION_DRIFT", f"candidate changed: {relative}")
    return candidate_paths


def _verify_selection_partition(
    selection: dict[str, Any],
    candidates: list[Any],
    selected: list[Any],
    omitted: list[Any],
    packet_sources: list[dict[str, Any]],
    candidate_paths: set[str],
) -> None:
    source_paths = {row["path"] for row in packet_sources}
    selected_paths = {row.get("path") for row in selected if isinstance(row, dict)}
    omitted_paths = {row.get("path") for row in omitted if isinstance(row, dict)}
    if (
        selected_paths != source_paths
        or selected_paths & omitted_paths
        or selected_paths | omitted_paths != candidate_paths
    ):
        _invalid(
            "E_SELECTION_FIELDS", "selected, omitted, and candidate paths do not match"
        )
    _validate_selection_rows(selected, omitted)
    candidate_by_path = {row["path"]: row for row in candidates}
    packet_by_path = {row["path"]: row for row in packet_sources}
    _validate_selected_bindings(selected, candidate_by_path, packet_by_path)
    omitted_by_path = {row.get("path"): row for row in omitted if isinstance(row, dict)}
    for path, row in omitted_by_path.items():
        if (
            path not in candidate_by_path
            or row.get("sha256") != candidate_by_path[path]["sha256"]
        ):
            _invalid(
                "E_SELECTION_FIELDS",
                "omitted source is not bound to candidate evidence",
            )
    candidate_rows = list(candidate_by_path.values())
    for row in candidates:
        if row["related_paths"] != _related_candidate_paths(row, candidate_rows):
            _invalid("E_SELECTION_FIELDS", "related candidate references do not match")
    _verify_required_selection(selection, packet_sources, selected_paths)


def _validate_selection_rows(selected: list[Any], omitted: list[Any]) -> None:
    if any(
        not isinstance(row, dict)
        or row.get("stage") not in {0, 1, 2, 3}
        or not isinstance(row.get("why_selected"), str)
        for row in selected
    ):
        _invalid("E_SELECTION_FIELDS", "selection rationale is malformed")
    if any(
        not isinstance(row, dict)
        or set(row) != {"path", "role", "sha256", "reason", "score"}
        for row in omitted
    ):
        _invalid("E_SELECTION_FIELDS", "omitted candidate evidence is malformed")


def _validate_selected_bindings(
    selected: list[Any],
    candidate_by_path: dict[str, Any],
    packet_by_path: dict[str, Any],
) -> None:
    for row in selected:
        candidate = candidate_by_path[row["path"]]
        source = packet_by_path[row["path"]]
        if (
            candidate["sha256"] != source["source_sha256"]
            or candidate["role"] != source["role"]
        ):
            _invalid(
                "E_SELECTION_FIELDS",
                "selected source is not bound to candidate evidence",
            )


def _verify_required_selection(
    selection: dict[str, Any],
    packet_sources: list[dict[str, Any]],
    selected_paths: set[str],
) -> None:
    required = selection.get("required_paths")
    missing_roles = selection.get("missing_evidence_roles")
    required_roles = selection.get("required_evidence_roles")
    full_roles = {
        row["role"].lower() for row in packet_sources if row["inclusion"] == "full"
    }
    if (
        not isinstance(required, list)
        or not set(required).issubset(selected_paths)
        or not isinstance(missing_roles, list)
        or missing_roles
        or not isinstance(required_roles, list)
        or not set(required_roles).issubset(full_roles)
        or selection.get("present_evidence_roles")
        != sorted({row["role"].lower() for row in packet_sources})
    ):
        _invalid("E_REQUIRED_EVIDENCE", "required paths or evidence roles are missing")


def _validate_structure(value: Any) -> None:
    if not isinstance(value, dict) or value.get("status") not in {
        "SYNTACTIC_ONLY",
        "NOT_PARSED",
        "PARSE_LIMIT",
        "PARSE_LIMIT_OR_ERROR",
        "DATABASE_STATIC_ONLY",
    }:
        _invalid("E_SELECTION_FIELDS", "structural evidence is malformed")
    common = {"status", "definitions", "imports", "calls", "identifiers"}
    expected = (
        common | {"node_count"} if value["status"] == "SYNTACTIC_ONLY" else common
    )
    if set(value) != expected:
        _invalid("E_SELECTION_FIELDS", "structural evidence fields are malformed")
    if value["status"] == "SYNTACTIC_ONLY" and (
        type(value["node_count"]) is not int
        or not 1 <= value["node_count"] <= MAX_AST_NODES
    ):
        _invalid("E_SELECTION_FIELDS", "structural node count is invalid")


def _verify_packet_header(
    workspace: Path, packet: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if packet.get("schema") != PACKET_SCHEMA or packet.get(
        "packet_sha256"
    ) != _packet_digest(packet):
        _invalid("E_PACKET_DIGEST", "packet schema or digest is invalid")
    request = _validate_request(workspace, packet.get("request"))
    packet_sources = _validate_source_rows(packet.get("sources"), request["sources"])
    selection = packet.get("selection")
    if selection is not None:
        selected = selection.get("selected") if isinstance(selection, dict) else None
        required_paths = (
            selection.get("required_paths") if isinstance(selection, dict) else None
        )
        requested_paths = {row["path"] for row in packet_sources}
        required_by_priority = {
            row["path"] for row in packet_sources if row["priority"] == 100
        }
        if (
            not isinstance(selection, dict)
            or selection.get("schema") != SELECTION_SCHEMA
            or not isinstance(selection.get("task_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", selection["task_sha256"]) is None
            or not isinstance(selected, list)
            or {row.get("path") for row in selected if isinstance(row, dict)}
            != requested_paths
            or not isinstance(required_paths, list)
            or set(required_paths) != required_by_priority
            or any(
                not isinstance(row, dict) or row.get("stage") not in {0, 1, 2, 3}
                for row in selected
            )
            or any(
                row["path"] in required_paths and row["inclusion"] != "full"
                for row in packet_sources
            )
        ):
            _invalid(
                "E_REQUIRED_EVIDENCE",
                "required context evidence is missing or truncated",
            )
        _verify_selection_evidence(workspace, selection, packet_sources)
    source_identities = _source_identity_rows(packet_sources)
    _validate_packet_cache(packet, request, source_identities)
    return request, packet_sources


def _verify_packet_sources(
    workspace: Path, packet_sources: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    rows = []
    for item in packet_sources:
        source_path, relative = _relative_path(
            workspace, item.get("path"), "packet.sources.path"
        )
        raw, digest, identity = _stable_file(source_path)
        if (
            relative != item.get("path")
            or digest != item.get("source_sha256")
            or identity != item.get("identity")
            or len(raw) != item.get("source_bytes")
        ):
            _invalid("E_SOURCE_DRIFT", f"source changed: {relative}")
        rows.append(
            {
                "source": {
                    "path": relative,
                    "role": item["role"],
                    "priority": item["priority"],
                },
                "raw": raw,
                "sha256": digest,
                "identity": identity,
            }
        )
    return rows


def _verify_packet_budget(packet: dict[str, Any]) -> None:
    budget = packet.get("budget")
    if (
        not isinstance(budget, dict)
        or budget.get("selected_bytes", -1) > budget.get("max_bytes", -2)
        or budget.get("token_quality") != "estimated_from_utf8_bytes_not_provider_usage"
    ):
        _invalid("E_BUDGET", "packet budget is invalid")


def verify_context_packet(root: Path, packet_path: Path) -> dict[str, Any]:
    """Verify packet identity and every selected source without executing it."""
    workspace = _validated_root(root)
    path = (
        Path(packet_path)
        if Path(packet_path).is_absolute()
        else workspace / packet_path
    )
    try:
        packet = json.loads(_read_bounded(path).decode("utf-8"))
        if not isinstance(packet, dict):
            _invalid("E_SCHEMA", "packet must be an object")
        request, packet_sources = _verify_packet_header(workspace, packet)
        source_rows = _verify_packet_sources(workspace, packet_sources)
        _validate_packet_snapshot(
            packet,
            request,
            source_rows,
            packet_sources,
        )
        return {
            "schema": VERIFICATION_SCHEMA,
            "state": "READY",
            "valid": True,
            "packet_sha256": packet["packet_sha256"],
            "source_count": len(source_rows),
            "cache_key": packet["cache"]["key"],
            "claim_boundary": "Packet and source digests match; this is read-only evidence and estimated token accounting, not an approval or usage receipt.",
        }
    except (
        ContextEfficiencyError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        KeyError,
    ) as exc:
        return {
            "schema": VERIFICATION_SCHEMA,
            "state": "BLOCKED",
            "valid": False,
            "code": getattr(exc, "code", "E_PACKET_READ"),
            "message": getattr(exc, "message", str(exc)),
            "claim_boundary": "Verification failed closed; no execution or approval authority is granted.",
        }


def _shard_digest(value: dict[str, Any], field: str) -> str:
    body = {key: item for key, item in value.items() if key != field}
    return _sha(body)


def _shard_artifact_path(root: Path, kind: str, digest: str) -> tuple[Path, str]:
    workspace = _validated_root(root)
    relative = f".factory/context-efficiency/shards/{kind}/{digest}.json"
    path, normalized = _shard_relative_path(workspace, relative, "shard artifact")
    return path, normalized


def _shard_relative_path(root: Path, raw: Any, field: str) -> tuple[Path, str]:
    lexical_root = Path(root).absolute()
    if _has_reparse_ancestor(lexical_root):
        _invalid("E_PATH_LINK", "workspace path traverses a reparse point")
    value = _safe_text(raw, field, 512).replace("\\", "/")
    candidate = Path(value)
    if (
        candidate.is_absolute()
        or re.match(r"^[A-Za-z]:/", value)
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        _invalid("E_PATH_BOUNDARY", f"{field} must stay within workspace")
    lexical = lexical_root.joinpath(candidate)
    if _has_reparse_ancestor(lexical):
        _invalid("E_PATH_LINK", f"{field} may not traverse a reparse point")
    return _relative_path(lexical_root, value, field)


def _write_immutable_shard(path: Path, artifact: dict[str, Any]) -> None:
    raw = _canonical(artifact) + b"\n"
    if len(raw) > MAX_SHARD_ARTIFACT_BYTES:
        _invalid("E_SHARD_BOUNDARY", "shard artifact exceeds size limit")
    try:
        if _has_reparse_ancestor(path):
            _invalid("E_PATH_LINK", "shard artifact path traverses a reparse point")
        path.parent.mkdir(parents=True, exist_ok=True)
        if _has_reparse_ancestor(path):
            _invalid("E_PATH_LINK", "shard artifact path traverses a reparse point")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        if _read_bounded(path, MAX_SHARD_ARTIFACT_BYTES) != raw:
            _invalid(
                "E_SHARD_COLLISION", "immutable shard path contains different bytes"
            )
    except OSError as exc:
        raise ContextEfficiencyError(
            "E_SHARD_WRITE", "cannot write immutable shard artifact"
        ) from exc


def _shard_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        _invalid("E_SHARD_EXPIRY", f"{field} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContextEfficiencyError(
            "E_SHARD_EXPIRY", f"{field} must be a UTC timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        _invalid("E_SHARD_EXPIRY", f"{field} must include UTC timezone")
    return parsed.astimezone(timezone.utc)


def _shard_now(now: Any = None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if isinstance(now, datetime) and now.tzinfo is not None:
        return now.astimezone(timezone.utc)
    _invalid("E_SHARD_TIME", "now must be timezone-aware")


def _shard_source_rows(
    root: Path, packet: dict[str, Any]
) -> dict[str, tuple[bytes, str]]:
    rows: dict[str, tuple[bytes, str]] = {}
    for source in packet.get("sources", []):
        if not isinstance(source, dict) or source.get("inclusion") != "full":
            continue
        path, relative = _shard_relative_path(root, source.get("path"), "packet source")
        if _SECRET_NAME.search(relative):
            continue
        raw, digest, _ = _stable_file(path)
        if digest != source.get("source_sha256") or any(
            pattern.search(raw) for pattern in _SECRET_BYTES
        ):
            continue
        rows[relative] = (raw, digest)
    return rows


def _shard_locator(
    root: Path, raw_locator: Any, sources: dict[str, tuple[bytes, str]]
) -> dict[str, Any]:
    fields = {"path", "start_byte", "end_byte"}
    if not isinstance(raw_locator, dict) or set(raw_locator) != fields:
        _invalid("E_SHARD_LOCATOR", "locator must contain path and byte bounds")
    path, relative = _shard_relative_path(root, raw_locator["path"], "locator.path")
    del path
    source = sources.get(relative)
    if source is None:
        _invalid("E_SHARD_LOCATOR", "locator must refer to a full, safe packet source")
    raw, digest = source
    start = _bounded_int(raw_locator["start_byte"], "locator.start_byte", 0, len(raw))
    end = _bounded_int(raw_locator["end_byte"], "locator.end_byte", 1, len(raw))
    if end <= start or end - start > MAX_SHARD_LOCATOR_BYTES:
        _invalid("E_SHARD_LOCATOR", "locator span is empty or exceeds limit")
    span = raw[start:end]
    try:
        span.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContextEfficiencyError(
            "E_SHARD_LOCATOR", "locator must align to UTF-8 boundaries"
        ) from exc
    return {
        "path": relative,
        "raw_source_sha256": digest,
        "start_byte": start,
        "end_byte": end,
        "span_sha256": hashlib.sha256(span).hexdigest(),
    }


def _verify_shard_locator(root: Path, locator: Any) -> bool:
    try:
        if not isinstance(locator, dict) or set(locator) != {
            "path",
            "raw_source_sha256",
            "start_byte",
            "end_byte",
            "span_sha256",
        }:
            return False
        path, relative = _shard_relative_path(
            root, locator["path"], "shard locator.path"
        )
        if relative != locator["path"] or _SECRET_NAME.search(relative):
            return False
        raw, digest, _ = _stable_file(path)
        start = _bounded_int(locator["start_byte"], "locator.start_byte", 0, len(raw))
        end = _bounded_int(locator["end_byte"], "locator.end_byte", 1, len(raw))
        if end <= start or end - start > MAX_SHARD_LOCATOR_BYTES:
            return False
        span = raw[start:end]
        span.decode("utf-8")
        return (
            not any(pattern.search(raw) for pattern in _SECRET_BYTES)
            and digest == locator["raw_source_sha256"]
            and hashlib.sha256(span).hexdigest() == locator["span_sha256"]
        )
    except (ContextEfficiencyError, OSError, UnicodeError, TypeError, KeyError):
        return False


def _normalize_shard_claims(
    root: Path, claims: Any, sources: dict[str, tuple[bytes, str]]
) -> list[dict[str, Any]]:
    if not isinstance(claims, list) or not 1 <= len(claims) <= MAX_SHARD_CLAIMS:
        _invalid("E_SHARD_FIELDS", "claims must contain 1..64 entries")
    normalized = []
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict) or set(claim) != {"key", "value", "locators"}:
            _invalid("E_SHARD_FIELDS", f"claims[{index}] has invalid fields")
        key = _safe_text(claim["key"], f"claims[{index}].key", 160).strip()
        value = claim["value"]
        if not isinstance(value, (str, int, float, bool, list, dict)) or value is None:
            _invalid("E_SHARD_FIELDS", f"claims[{index}].value must be bounded JSON")
        _reject_secret_keys({"value": value}, f"claims[{index}]")
        value_bytes = _canonical(value)
        if len(value_bytes) > MAX_SHARD_LOCATOR_BYTES or any(
            pattern.search(value_bytes) for pattern in _SECRET_BYTES
        ):
            _invalid("E_SHARD_BOUNDARY", f"claims[{index}].value exceeds limit")
        locators = claim["locators"]
        if (
            not isinstance(locators, list)
            or not 1 <= len(locators) <= MAX_SHARD_RECORDS
        ):
            _invalid("E_SHARD_LOCATOR", f"claims[{index}] requires source locators")
        normalized.append(
            {
                "key": key,
                "value": value,
                "locators": [
                    _shard_locator(root, locator, sources) for locator in locators
                ],
            }
        )
    return normalized


def _normalize_shard_retention(
    root: Path, retained_records: Any, sources: dict[str, tuple[bytes, str]]
) -> dict[str, list[dict[str, Any]]]:
    categories = {"correction", "failure", "approval", "unresolved_action"}
    if not isinstance(retained_records, dict) or set(retained_records) != categories:
        _invalid(
            "E_SHARD_RETENTION", "all four retained-record categories are required"
        )
    retained = {}
    count = 0
    for category in sorted(categories):
        records = retained_records[category]
        if not isinstance(records, list):
            _invalid("E_SHARD_RETENTION", f"{category} must be a locator list")
        count += len(records)
        retained[category] = [
            _shard_locator(root, locator, sources) for locator in records
        ]
    if count > MAX_SHARD_RECORDS:
        _invalid("E_SHARD_BOUNDARY", "retained records exceed limit")
    return retained


def _candidate_source_state(
    workspace: Path, artifact: dict[str, Any], packet_path: Path
) -> str:
    verified = verify_context_packet(workspace, packet_path)
    if not verified.get("valid") or verified.get("packet_sha256") != artifact.get(
        "packet", {}
    ).get("packet_sha256"):
        return "STALE"
    try:
        packet = json.loads(_read_bounded(packet_path).decode("utf-8"))
        sources = _shard_source_rows(workspace, packet)
        locators = [
            item
            for claim in artifact.get("claims", [])
            if isinstance(claim, dict)
            for item in claim.get("locators", [])
        ]
        locators.extend(
            item
            for records in artifact.get("retained_records", {}).values()
            if isinstance(records, list)
            for item in records
        )
        if not all(_verify_shard_locator(workspace, item) for item in locators):
            return "STALE"
        if any(
            item.get("path") not in sources
            for item in locators
            if isinstance(item, dict)
        ):
            return "STALE"
        return "CANDIDATE"
    except (
        ContextEfficiencyError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        AttributeError,
    ):
        return "STALE"


def _stored_shard_matches(workspace: Path, relative: str, body: dict[str, Any]) -> bool:
    try:
        path, _ = _shard_relative_path(workspace, relative, "shard artifact path")
        return _read_bounded(path, MAX_SHARD_ARTIFACT_BYTES) == _canonical(body) + b"\n"
    except (ContextEfficiencyError, OSError):
        return False


def _accepted_shard_conflict(
    workspace: Path,
    artifact: dict[str, Any],
    digest: str,
    claims: Any,
    accepted: Any,
    now: datetime | None,
) -> dict[str, str] | None:
    if not isinstance(accepted, (list, tuple)):
        return None
    current = {
        (str(item.get("key", "")).strip().casefold(), _canonical(item.get("value")))
        for item in claims
        if isinstance(item, dict)
    }
    for pair in accepted[:MAX_SHARD_RECORDS]:
        if not isinstance(pair, dict) or set(pair) != {"candidate", "review"}:
            continue
        other, review = pair["candidate"], pair["review"]
        if not _is_reviewed_accepted_shard(workspace, artifact, other, review, now):
            continue
        for old in other.get("claims", []):
            if not isinstance(old, dict):
                continue
            key, value = (
                str(old.get("key", "")).strip().casefold(),
                _canonical(old.get("value")),
            )
            if any(
                current_key == key and current_value != value
                for current_key, current_value in current
            ):
                return {
                    "candidate_sha256": digest,
                    "accepted_candidate_sha256": other.get("candidate_sha256"),
                    "key": key,
                    "basis": "same type and normalized key with different canonical values",
                }
    return None


def _is_reviewed_accepted_shard(
    workspace: Path,
    current: dict[str, Any],
    other: Any,
    review: Any,
    now: datetime | None,
) -> bool:
    if not isinstance(other, dict) or other.get("shard_type") != current.get(
        "shard_type"
    ):
        return False
    body = {key: value for key, value in other.items() if key != "artifact_path"}
    if other.get("candidate_sha256") != _shard_digest(body, "candidate_sha256"):
        return False
    if not isinstance(other.get("artifact_path"), str) or not _stored_shard_matches(
        workspace, other["artifact_path"], body
    ):
        return False
    try:
        if not validate_context_shard_candidate(workspace, other, now=now)["valid"]:
            return False
    except ContextEfficiencyError:
        return False
    if not isinstance(review, dict):
        return False
    review_body = {
        key: value for key, value in review.items() if key != "artifact_path"
    }
    return (
        review.get("schema") == SHARD_REVIEW_SCHEMA
        and review.get("decision") == "accept"
        and review.get("state") == "CALLER_REVIEWED_ACCEPTED"
        and review.get("reviewer_identity_authenticated") is False
        and review.get("candidate_sha256") == other.get("candidate_sha256")
        and review.get("review_sha256") == _shard_digest(review_body, "review_sha256")
        and isinstance(review.get("artifact_path"), str)
        and _stored_shard_matches(workspace, review["artifact_path"], review_body)
    )


def build_context_shard_candidate(
    root: Path,
    packet_path: Path,
    shard_type: str,
    claims: Any,
    retained_records: Any,
    expires_at: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Persist a source-bound candidate shard; this never accepts or activates it."""
    if shard_type not in {"rule", "fact", "code_map"}:
        _invalid("E_SHARD_TYPE", "shard_type must be rule, fact, or code_map")
    workspace = _validated_root(root)
    packet_path_value, packet_relative = _shard_relative_path(
        workspace,
        Path(packet_path).absolute().relative_to(workspace).as_posix()
        if Path(packet_path).is_absolute()
        else str(packet_path),
        "packet_path",
    )
    verified = verify_context_packet(workspace, packet_path_value)
    if not verified.get("valid"):
        _invalid("E_SHARD_PACKET", "source packet failed verification")
    packet = json.loads(_read_bounded(packet_path_value).decode("utf-8"))
    sources = _shard_source_rows(workspace, packet)
    normalized_claims = _normalize_shard_claims(workspace, claims, sources)
    retained = _normalize_shard_retention(workspace, retained_records, sources)
    current = _shard_now(now)
    expiry = _shard_datetime(expires_at, "expires_at")
    if not current < expiry <= current.replace(year=current.year + 1):
        _invalid("E_SHARD_EXPIRY", "expiry must be within the next year")
    artifact = {
        "schema": SHARD_CANDIDATE_SCHEMA,
        "state": "CANDIDATE",
        "review_status": "UNREVIEWED",
        "shard_type": shard_type,
        "packet": {"path": packet_relative, "packet_sha256": verified["packet_sha256"]},
        "claims": normalized_claims,
        "retained_records": retained,
        "retention_inventory_status": "CALLER_DECLARED",
        "expires_at": expiry.isoformat().replace("+00:00", "Z"),
        "provenance_boundary": "Hashes and locators bind caller-proposed content to local source bytes; they do not establish truth or completeness.",
    }
    artifact["candidate_sha256"] = _shard_digest(artifact, "candidate_sha256")
    artifact_path, relative = _shard_artifact_path(
        workspace, "candidates", artifact["candidate_sha256"]
    )
    _write_immutable_shard(artifact_path, artifact)
    return {**artifact, "artifact_path": relative}


def _load_shard_candidate(
    workspace: Path, candidate: Any
) -> tuple[dict[str, Any], str | None]:
    if isinstance(candidate, (str, Path)):
        path, relative = _shard_relative_path(
            workspace, str(candidate), "candidate path"
        )
        try:
            artifact = json.loads(
                _read_bounded(path, MAX_SHARD_ARTIFACT_BYTES).decode("utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ContextEfficiencyError(
                "E_SHARD_READ", "candidate artifact cannot be read"
            ) from exc
    elif isinstance(candidate, dict):
        artifact = {
            key: value for key, value in candidate.items() if key != "artifact_path"
        }
        relative = artifact.get("artifact_path")
    else:
        _invalid("E_SHARD_FIELDS", "candidate must be an artifact or relative path")
    if not isinstance(artifact, dict):
        _invalid("E_SHARD_FIELDS", "candidate must be an object")
    return artifact, relative


def _validate_shard_claim_structure(claim: Any) -> None:
    if not isinstance(claim, dict) or set(claim) != {"key", "value", "locators"}:
        _invalid("E_SHARD_FIELDS", "candidate claim is invalid")
    _safe_text(claim["key"], "claim.key", 160)
    if (
        not isinstance(claim["value"], (str, int, float, bool, list, dict))
        or claim["value"] is None
    ):
        _invalid("E_SHARD_FIELDS", "candidate claim value is invalid")
    _reject_secret_keys({"value": claim["value"]}, "candidate.claim")
    value_bytes = _canonical(claim["value"])
    if len(value_bytes) > MAX_SHARD_LOCATOR_BYTES or any(
        pattern.search(value_bytes) for pattern in _SECRET_BYTES
    ):
        _invalid("E_SHARD_BOUNDARY", "candidate claim value exceeds limit")
    if not isinstance(claim["locators"], list) or not claim["locators"]:
        _invalid("E_SHARD_LOCATOR", "candidate claim requires locators")


def _validate_shard_structure(artifact: dict[str, Any]) -> None:
    fields = {
        "schema",
        "state",
        "review_status",
        "shard_type",
        "packet",
        "claims",
        "retained_records",
        "retention_inventory_status",
        "expires_at",
        "provenance_boundary",
        "candidate_sha256",
    }
    if set(artifact) != fields or artifact.get("shard_type") not in {
        "rule",
        "fact",
        "code_map",
    }:
        _invalid("E_SHARD_FIELDS", "candidate has invalid fields or type")
    if (
        artifact.get("review_status") != "UNREVIEWED"
        or artifact.get("retention_inventory_status") != "CALLER_DECLARED"
    ):
        _invalid("E_SHARD_FIELDS", "candidate review or retention state is invalid")
    claims = artifact.get("claims")
    if not isinstance(claims, list) or not 1 <= len(claims) <= MAX_SHARD_CLAIMS:
        _invalid("E_SHARD_FIELDS", "candidate claims are invalid")
    for claim in claims:
        _validate_shard_claim_structure(claim)
    categories = {"correction", "failure", "approval", "unresolved_action"}
    retained = artifact.get("retained_records")
    if not isinstance(retained, dict) or set(retained) != categories:
        _invalid("E_SHARD_RETENTION", "candidate retention categories are invalid")
    if any(not isinstance(records, list) for records in retained.values()):
        _invalid("E_SHARD_RETENTION", "candidate retained records are invalid")
    if sum(len(records) for records in retained.values()) > MAX_SHARD_RECORDS:
        _invalid("E_SHARD_BOUNDARY", "candidate retained records exceed limit")


def _validated_shard_reference(
    workspace: Path, artifact: dict[str, Any]
) -> tuple[str, Path, str]:
    if (
        artifact.get("schema") != SHARD_CANDIDATE_SCHEMA
        or artifact.get("state") != "CANDIDATE"
    ):
        _invalid("E_SHARD_FIELDS", "candidate schema or state is invalid")
    _validate_shard_structure(artifact)
    digest = artifact.get("candidate_sha256")
    if not isinstance(digest, str) or digest != _shard_digest(
        artifact, "candidate_sha256"
    ):
        _invalid("E_SHARD_DIGEST", "candidate digest is invalid")
    packet = artifact.get("packet")
    if not isinstance(packet, dict) or set(packet) != {"path", "packet_sha256"}:
        _invalid("E_SHARD_FIELDS", "candidate packet reference is invalid")
    path, relative = _shard_relative_path(workspace, packet["path"], "packet.path")
    return digest, path, relative


def validate_context_shard_candidate(
    root: Path,
    candidate: Any,
    *,
    accepted_shards: Any = (),
    now: datetime | None = None,
) -> dict[str, Any]:
    """Re-read and validate candidate provenance, freshness, expiry and conflicts."""
    workspace = _validated_root(root)
    artifact, relative = _load_shard_candidate(workspace, candidate)
    digest, packet_path, packet_relative = _validated_shard_reference(
        workspace, artifact
    )
    state = _candidate_source_state(workspace, artifact, packet_path)
    if state != "STALE" and _shard_now(now) >= _shard_datetime(
        artifact.get("expires_at"), "expires_at"
    ):
        state = "EXPIRED"
    claims = artifact.get("claims", [])
    if not isinstance(claims, list) or len(claims) > MAX_SHARD_CLAIMS:
        state = "BLOCKED"
    elif not isinstance(accepted_shards, (list, tuple)):
        state = "BLOCKED"
    elif len(accepted_shards) > MAX_SHARD_RECORDS:
        state = "BLOCKED"
    contradiction = _accepted_shard_conflict(
        workspace, artifact, digest, claims, accepted_shards, now
    )
    if contradiction and state == "CANDIDATE":
        state = "CONTRADICTED"
    return {
        "schema": SHARD_CANDIDATE_SCHEMA,
        "state": state,
        "valid": state == "CANDIDATE",
        "candidate_sha256": digest,
        "artifact_path": relative,
        "packet_path": packet_relative,
        "claim_count": len(claims) if isinstance(claims, list) else None,
        "retention_inventory_status": artifact.get("retention_inventory_status"),
        "contradiction": contradiction,
        "review_status": artifact.get("review_status", "UNREVIEWED"),
        "claim_boundary": "Structural hash/provenance validation only; no memory activation, semantic truth, or completeness claim.",
    }


def review_context_shard_candidate(
    root: Path,
    candidate: dict[str, Any],
    decision: str,
    reviewer_id: str,
    review_basis: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Write a separate explicit caller-review event; reviewer identity is unauthenticated."""
    validation = validate_context_shard_candidate(root, candidate, now=now)
    if not validation["valid"]:
        _invalid("E_SHARD_NOT_REVIEWABLE", f"candidate state is {validation['state']}")
    if decision not in {"accept", "reject", "defer"}:
        _invalid("E_SHARD_REVIEW", "decision must be accept, reject, or defer")
    reviewer = _safe_text(reviewer_id, "reviewer_id", 160)
    basis = _safe_text(review_basis, "review_basis", 1000)
    artifact = {
        key: value for key, value in candidate.items() if key != "artifact_path"
    }
    event = {
        "schema": SHARD_REVIEW_SCHEMA,
        "state": "CALLER_REVIEWED_ACCEPTED"
        if decision == "accept"
        else "CALLER_REVIEWED_REJECTED"
        if decision == "reject"
        else "CALLER_REVIEWED_DEFERRED",
        "decision": decision,
        "candidate_sha256": artifact["candidate_sha256"],
        "reviewer_id": reviewer,
        "reviewer_identity_authenticated": False,
        "review_basis": basis,
        "reviewed_at": _shard_now(now).isoformat().replace("+00:00", "Z"),
        "activation": "NONE",
    }
    event["review_sha256"] = _shard_digest(event, "review_sha256")
    path, relative = _shard_artifact_path(root, "reviews", event["review_sha256"])
    _write_immutable_shard(path, event)
    return {**event, "artifact_path": relative}


def context_efficiency_status(root: Path) -> dict[str, Any]:
    """Fast bounded status projection over cached packets (no source reread)."""
    workspace = _validated_root(root)
    directory = _cache_dir(workspace)
    packet_stats = _collect_packet_status(workspace, directory)
    experiment, experiment_blocked = _load_latest_experiment(directory)
    invalid = packet_stats["invalid_count"] + int(experiment_blocked)
    state = "BLOCKED" if invalid else "READY" if packet_stats["rows"] else "MISSING"
    return _status_projection(
        packet_stats, experiment, experiment_blocked, state, invalid
    )


def _collect_packet_status(workspace: Path, directory: Path) -> dict[str, Any]:
    files = (
        sorted(
            path for path in directory.glob("*.json") if path.name != "experiment.json"
        )[:MAX_CACHE_FILES]
        if directory.is_dir()
        else []
    )
    rows: list[dict[str, Any]] = []
    invalid = 0
    cache_hits: int | None = 0
    estimated_tokens = 0
    selection_count = 0
    missing_selection_evidence = 0
    structural_file_count = 0
    evidence_roles: set[str] = set()
    for path in files:
        try:
            packet = json.loads(_read_bounded(path).decode("utf-8"))
            valid = (
                isinstance(packet, dict)
                and packet.get("schema") == PACKET_SCHEMA
                and packet.get("packet_sha256") == _packet_digest(packet)
            )
            if not valid:
                invalid += 1
                continue
            budget = packet.get("budget", {})
            estimated_tokens += int(budget.get("estimated_tokens", 0))
            packet_hits = _cache_hit_count(
                workspace, packet.get("cache", {}).get("key", "")
            )
            if packet_hits is None:
                cache_hits = None
            elif cache_hits is not None:
                cache_hits += packet_hits
            selection_count += int(isinstance(packet.get("selection"), dict))
            if isinstance(packet.get("selection"), dict):
                candidates = packet["selection"].get("candidates", [])
                structural_file_count += sum(
                    isinstance(row, dict)
                    and isinstance(row.get("structure"), dict)
                    and row["structure"].get("status") == "SYNTACTIC_ONLY"
                    for row in candidates
                )
                evidence_roles.update(
                    row.get("role", "")
                    for row in candidates
                    if isinstance(row, dict) and isinstance(row.get("role"), str)
                )
                missing_selection_evidence += len(
                    packet["selection"].get("missing_evidence_roles", [])
                )
            rows.append(
                {
                    "path": path.relative_to(workspace).as_posix(),
                    "packet_sha256": packet["packet_sha256"],
                    "state": "READY",
                    "estimated_tokens": budget.get("estimated_tokens", 0),
                    "source_count": len(packet.get("sources", [])),
                }
            )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
            invalid += 1
    return {
        "rows": rows,
        "invalid_count": invalid,
        "cache_hits": cache_hits,
        "estimated_tokens": estimated_tokens,
        "selection_count": selection_count,
        "missing_selection_evidence": missing_selection_evidence,
        "structural_file_count": structural_file_count,
        "evidence_role_count": len(evidence_roles),
    }


def _load_latest_experiment(directory: Path) -> tuple[dict[str, Any] | None, bool]:
    try:
        experiment_history = _read_experiment_history(directory / "experiment.json")
        return (experiment_history[-1] if experiment_history else None), False
    except ContextEfficiencyError:
        return None, True


def _status_projection(stats, experiment, experiment_blocked, state, invalid):
    selection_count = stats["selection_count"]
    missing_roles = stats["missing_selection_evidence"]
    values = experiment or {}
    measurements = (
        "quality_nonregression",
        "observed_latency_reduction",
        "observed_cost_delta",
        "observed_cost_delta_unit",
        "observed_token_delta",
        "observed_token_delta_unit",
    )
    return {
        "schema": STATUS_SCHEMA,
        "state": state,
        "marker": "CONTEXT_EFFICIENCY_READ_ONLY",
        "packet_count": len(stats["rows"]),
        "invalid_count": invalid,
        "cache_hits": stats["cache_hits"],
        "cache_hits_semantics": "recorded_lower_bound",
        "cache_usage_completeness": "UNKNOWN",
        "estimated_tokens": stats["estimated_tokens"],
        "packets": stats["rows"],
        "source_selection_status": "CACHED_METADATA_UNVERIFIED"
        if selection_count
        else "MISSING",
        "source_evidence_status": "UNVERIFIED",
        "structural_evidence_status": "CACHED_METADATA_ONLY"
        if selection_count
        else "MISSING",
        "deep_evidence_file_count": stats["structural_file_count"],
        "evidence_role_count": stats["evidence_role_count"],
        "missing_evidence_role_count": missing_roles,
        "reusable_packet_count": None,
        "stale_packet_count": None,
        "missing_evidence_count": invalid + missing_roles + int(experiment is None),
        "experiment_status": "BLOCKED"
        if experiment_blocked
        else values.get("state", "MISSING_EVIDENCE"),
        "experiment_quality_status": "NONREGRESSED"
        if experiment and values.get("quality_nonregression") is True
        else "REGRESSED"
        if experiment
        else "UNKNOWN",
        "experiment_freshness": "UNVERIFIED" if experiment else "MISSING",
        **{key: values.get(key) for key in measurements},
        "paired_sample_count": values.get("paired_sample_count", 0),
        "experiment_evidence_level": values.get("evidence_level"),
        "claim_boundary": "Bounded cache metadata only; estimated token counts are not provider usage or guaranteed savings, and no source is executed or approved.",
        "authority": _context_read_only_authority(),
    }


def _context_read_only_authority():
    return dict.fromkeys(
        ("execution", "approval", "repair", "publication", "credential"), False
    )


def _context_project_fields(row, fields):
    return {key: row[key] for key in fields.split()}


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _invalid(code: str, message: str) -> NoReturn:
    raise ContextEfficiencyError(code, message)


def _informed_failure(status, reason, limit=64000):
    return {
        "schema": "factory.informed-sink-context.v1",
        "status": status,
        "excerpts": [],
        "edges": [],
        "dependency_sources": [],
        "unknowns": [{"status": "UNKNOWN", "reason": reason}],
        "truncation": [reason] if "BUDGET" in status else [],
        "authority": {"status": "UNKNOWN"},
        "actionability": "NEEDS_CONTEXT",
    }


def _informed_ref(index, path, node):
    return {
        "path": index.relative(path),
        "sha256": index.inventory[path],
        "start_line": node.lineno,
        "end_line": node.end_lineno,
    }


def _informed_excerpt(index, path, node, kind):
    lines = index.source_bytes[path].decode("utf-8").splitlines(keepends=True)
    end = (
        max(node.lineno, node.body[0].lineno - 1)
        if kind == "signature"
        else node.end_lineno
    )
    return {
        **_informed_ref(index, path, node),
        "kind": kind,
        "end_line": end,
        "content": "".join(lines[node.lineno - 1 : end]),
    }


def _informed_owner(index, path, node):
    parent = index.parents[path].get(id(node))
    while parent is not None:
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return parent
        parent = index.parents[path].get(id(parent))
    return index.snapshots[path]


def _informed_target(index, path, call, inventory, capture):
    from .credential_role_constructor_provider import binding_occurrences

    expr, tree = call.func, index.snapshots[path]
    owner = _informed_owner(index, path, call)
    root = expr.value if isinstance(expr, ast.Attribute) else expr
    if not isinstance(root, ast.Name) or _informed_mutation(tree, root.id):
        return None
    if not _informed_unshadowed(index, path, owner, tree, root.id):
        return None
    bindings = binding_occurrences(tree.body, root.id)
    if len(bindings) != 1 or bindings[0] not in tree.body:
        return None
    binding, selected = bindings[0], path
    if isinstance(binding, (ast.Import, ast.ImportFrom)):
        resolved = _informed_import(
            index, path, binding, root.id, expr, inventory, capture
        )
        if resolved is None:
            return None
        selected, binding = resolved
    elif isinstance(expr, ast.Attribute):
        return None
    if isinstance(binding, ast.ClassDef):
        return _informed_constructor(selected, binding, call)
    if (
        isinstance(binding, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not binding.decorator_list
    ):
        return selected, binding, None, binding
    return None


def _informed_unshadowed(index, path, owner, tree, name):
    from .credential_role_constructor_provider import binding_occurrences

    while owner is not tree:
        if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = {n.arg for n in ast.walk(owner.args) if isinstance(n, ast.arg)}
            if name in params or binding_occurrences(owner.body, name):
                return False
        elif isinstance(owner, (ast.Lambda, ast.ClassDef)):
            return False
        owner = index.parents[path].get(id(owner))
        if owner is None:
            return False
    return True


def _informed_constructor(path, declaration, call):
    from .credential_role_constructor_provider import binding_occurrences

    methods = binding_occurrences(declaration.body, "__init__")
    if len(methods) == 1 and isinstance(methods[0], ast.FunctionDef):
        if (
            not declaration.bases
            and not declaration.decorator_list
            and not methods[0].decorator_list
        ):
            return path, methods[0], call, declaration
    return None


def _informed_mutation(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
            return True
        if isinstance(node, ast.Attribute) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            if node.attr in {
                "__code__",
                "__defaults__",
                "__kwdefaults__",
                "__closure__",
            }:
                return True
            if any(
                isinstance(n, ast.Name) and n.id == name for n in ast.walk(node.value)
            ):
                return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {
                "setattr",
                "delattr",
                "globals",
                "locals",
                "vars",
                "exec",
            }:
                return True
    return False


def _informed_import(index, path, binding, name, expr, inventory, capture):
    from .import_context import resolve_import_source, import_source_symbol
    from .credential_role_constructor_provider import binding_occurrences

    alias = next(
        (a for a in binding.names if (a.asname or a.name.split(".")[0]) == name), None
    )
    if (
        alias is None
        or isinstance(binding, ast.Import)
        and "." in alias.name
        and not alias.asname
    ):
        return None
    module = binding.module if isinstance(binding, ast.ImportFrom) else alias.name
    imported = alias.name if isinstance(binding, ast.ImportFrom) else None
    selected = resolve_import_source(
        index.root, path, binding, module, inventory, imported, captured=True
    )
    if selected is None:
        return None
    if not _informed_admit(index, selected, capture):
        return None
    symbol = import_source_symbol(
        index.root,
        path,
        binding,
        module,
        imported,
        selected,
        captured=True,
        captured_inventory=inventory,
    )
    if isinstance(expr, ast.Attribute):
        if symbol is not None:
            return None
        symbol = expr.attr
    if _informed_mutation(
        index.snapshots[selected], symbol
    ) or not _informed_packages_clear(index, selected):
        return None
    declarations = binding_occurrences(index.snapshots[selected].body, symbol)
    return (selected, declarations[0]) if len(declarations) == 1 else None


def _informed_admit(index, path, capture):
    if path in capture["dependencies"]:
        return True
    if len(capture["dependencies"]) >= capture["max_sources"]:
        capture["truncation"].append("max_sources")
        return False
    if not index.validate(path):
        capture["stale"] = True
        return False
    capture["dependencies"][path] = index.inventory[path]
    package = (
        path.parent.parent if path.name == "__init__.py" else path.parent
    ) / "__init__.py"
    if package in index.snapshots and package != path:
        return _informed_admit(index, package, capture)
    return True


def _informed_packages_clear(index, path):
    directory = path.parent
    while directory.is_relative_to(index.root):
        initializer = index.snapshots.get(directory / "__init__.py")
        if initializer is not None and not _informed_initializer_clear(initializer):
            return False
        directory = directory.parent
    return True


def _informed_initializer_clear(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            return False
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                return False
    return True


def _informed_edges(index, caller_path, call, target):
    from .review_integrity import bind_source_call

    path, function, receiver, declaration = target
    bound = bind_source_call(call, function, receiver=receiver)
    formals = {a.arg: a for a in ast.walk(function.args) if isinstance(a, ast.arg)}
    actuals = {
        id(n)
        for arg in [*call.args, *(k.value for k in call.keywords)]
        for n in ast.walk(arg)
    }
    rows = []
    for name, value in bound.items():
        if not isinstance(value, ast.AST):
            raise ValueError("variadic_argument_binding_unknown")
        origin = caller_path if id(value) in actuals or value is receiver else path
        rows.append(
            {
                "kind": (
                    "actual_to_formal"
                    if id(value) in actuals or value is receiver
                    else "default_to_formal"
                ),
                "status": "OBSERVED",
                "formal": name,
                "actual": _informed_ref(index, origin, value),
                "formal_source": _informed_ref(index, path, formals[name]),
            }
        )
    returns = [
        n for n in function.body if isinstance(n, ast.Return) and n.value is not None
    ]
    if returns and returns[-1] is function.body[-1]:
        rows.append(
            {
                "kind": "return_to_call",
                "status": "OBSERVED",
                "return_source": _informed_ref(index, path, returns[-1]),
                "call_source": _informed_ref(index, caller_path, call),
                "semantics": "syntactic_return_only_control_and_effects_unknown",
            }
        )
    return rows


def _informed_expand(result, index, path, sink, inventory, max_states, capture):
    owner = _informed_owner(index, path, sink)
    pending, visited, count = [(path, owner, "body")], set(), 0
    while pending:
        current, scope, kind = pending.pop(0)
        if (current, id(scope)) in visited:
            continue
        visited.add((current, id(scope)))
        _informed_scope_excerpts(result, index, current, scope, kind)
        nodes = [scope]
        while nodes:
            node = nodes.pop()
            count += 1
            if count > max_states:
                result["truncation"].append("max_states")
                return
            if node is not scope and isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                continue
            nodes.extend(ast.iter_child_nodes(node))
            if not isinstance(node, ast.Call) or node is sink:
                continue
            target = _informed_target(index, current, node, inventory, capture)
            if target is None:
                result["unknowns"].append(
                    {
                        **_informed_ref(index, current, node),
                        "status": "UNKNOWN",
                        "reason": "callee_or_receiver_binding_unresolved",
                    }
                )
                continue
            try:
                result["edges"].extend(_informed_edges(index, current, node, target))
            except ValueError as exc:
                result["unknowns"].append(
                    {
                        **_informed_ref(index, current, node),
                        "status": "UNKNOWN",
                        "reason": str(exc),
                    }
                )
            pending.append((target[0], target[3], "helper"))
    _informed_callers(
        result, index, inventory, (path, owner), max_states - count, capture
    )


def _informed_scope_excerpts(result, index, path, scope, kind):
    if hasattr(scope, "lineno"):
        result["excerpts"].append(_informed_excerpt(index, path, scope, kind))
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        result["excerpts"].append(_informed_excerpt(index, path, scope, "signature"))
    result["excerpts"].extend(
        _informed_excerpt(index, path, node, "import")
        for node in index.snapshots[path].body
        if isinstance(node, (ast.Import, ast.ImportFrom))
    )


def _informed_callers(result, index, inventory, initial, remaining, capture):
    for current, tree in index.snapshots.items():
        if not _informed_admit(index, current, capture):
            return
        for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
            remaining -= 1
            if remaining < 0:
                result["truncation"].append("max_states")
                return
            target = _informed_target(index, current, call, inventory, capture)
            if (
                target is None
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == getattr(initial[1], "name", None)
            ):
                result["unknowns"].append(
                    {
                        **_informed_ref(index, current, call),
                        "status": "UNKNOWN",
                        "reason": "caller_receiver_binding_unknown",
                    }
                )
            if target is None or (target[0], target[1]) != initial:
                continue
            try:
                result["edges"].extend(_informed_edges(index, current, call, target))
                owner = _informed_owner(index, current, call)
                result["excerpts"].append(
                    _informed_excerpt(
                        index,
                        current,
                        owner if hasattr(owner, "lineno") else call,
                        "caller",
                    )
                )
            except (ValueError, AttributeError):
                result["unknowns"].append(
                    {
                        **_informed_ref(index, current, call),
                        "status": "UNKNOWN",
                        "reason": "caller_argument_binding_unknown",
                    }
                )


def _informed_preflight(finding, index, limits):
    if any(
        type(n) is not int or n <= 0 or n > cap
        for n, cap in zip(limits, (64, 512, 64000))
    ):
        return _informed_failure("SINK_BUDGET_INVALID", "invalid_limit")
    requested = Path(finding.get("path", ""))
    if (
        requested.is_absolute()
        or ".." in requested.parts
        or requested.as_posix() != finding.get("path")
    ):
        return _informed_failure("SINK_SOURCE_STALE", "sink_path_noncanonical")
    if (
        any(len(raw) > 1_000_000 for raw in index.source_bytes.values())
        or sum(map(len, index.source_bytes.values())) > 32_000_000
    ):
        return _informed_failure("SINK_INPUT_UNASSESSED", "input_byte_bound")


def _informed_sink_native_capture(
    finding,
    index,
    captured_sink_evidence,
    *,
    max_sources,
    max_states,
    max_output_bytes,
):
    """Bind the sink span and native evidence to the current captured source."""
    path = index.root / finding.get("path", "")
    digest = finding.get("source_sha256", finding.get("facts", {}).get("source_sha256"))
    if (
        path not in index.snapshots
        or index.inventory[path] != digest
        or index.relative(path) != finding.get("path")
    ):
        return (
            _informed_failure("SINK_SOURCE_STALE", "sink_identity_invalid"),
            None,
            None,
            None,
            None,
        )
    if not index.validate(path):
        return (
            _informed_failure("SINK_SOURCE_STALE", "sink_snapshot_invalid"),
            None,
            None,
            None,
            None,
        )
    matches = [
        node
        for node in ast.walk(index.snapshots[path])
        if isinstance(node, ast.Call)
        and node.lineno == finding.get("line")
        and node.col_offset == finding.get("column")
        and all(
            finding.get(key, getattr(node, attribute)) == getattr(node, attribute)
            for key, attribute in [
                ("end_line", "end_lineno"),
                ("end_column", "end_col_offset"),
            ]
        )
    ]
    if len(matches) != 1:
        return (
            _informed_failure("SINK_LOCATION_UNRESOLVED", "sink_span_not_unique"),
            None,
            None,
            None,
            None,
        )
    sink = matches[0]
    native = captured_sink_evidence(
        sink,
        source_path=path,
        source_sha256=digest,
        source_index=index,
        max_sources=max_sources,
        max_states=max_states,
        max_output_bytes=max_output_bytes,
    )
    result = {
        **_informed_failure(
            "CAPTURED", "caller_completeness_authority_and_opaque_effects_unknown"
        ),
        "native_ledger": native,
    }
    capture = {
        "dependencies": {path: digest},
        "max_sources": max_sources,
        "truncation": result["truncation"],
        "stale": False,
    }
    if native.get("status") not in {"COMPLETE", "INCOMPLETE"}:
        return (
            {
                **result,
                "status": native.get("status", "SINK_INPUT_UNASSESSED"),
                "truncation": native.get("truncation", []),
            },
            None,
            None,
            None,
            None,
        )
    return result, capture, native, path, sink


def _informed_sink_dependency_sources(result, index, capture):
    """Emit and revalidate every dependency reached during source expansion."""
    dependencies = capture["dependencies"]
    result["dependency_sources"] = [
        {"path": index.relative(path), "sha256": digest}
        for path, digest in dependencies.items()
    ]
    for selected in dependencies:
        index._validation_inputs.pop(selected, None)
    stale = capture["stale"] or any(
        index.inventory.get(path) != digest or not index.validate(path)
        for path, digest in dependencies.items()
    )
    return stale


def _informed_sink_finish(result, native, max_output_bytes):
    """Project native truncation and enforce the final encoded-size bound."""
    result["truncation"].extend(native.get("truncation", []))
    result["status"] = "INCOMPLETE" if result["truncation"] else "CAPTURED"
    if len(canonical_bytes(result)) > max_output_bytes:
        return _informed_failure("SINK_BUDGET_EXHAUSTED", "max_output_bytes")
    return result


def _informed_actionability_artifacts(context, candidate_commit, candidate):
    """Materialize deduplicated source excerpts and the native sink ledger."""
    artifacts, seen = [], set()
    for excerpt in context["excerpts"]:
        identity = tuple(excerpt[key] for key in ("path", "start_line", "end_line"))
        if identity in seen:
            continue
        seen.add(identity)
        artifacts.append(
            {
                "kind": "source_excerpt",
                "path": excerpt["path"],
                "content": excerpt["content"],
                "sha256": hashlib.sha256(
                    excerpt["content"].encode("utf-8")
                ).hexdigest(),
                "candidate_commit": candidate_commit,
                "candidate_sha256": candidate["sha256"],
                "source_binding": {
                    key: excerpt[key]
                    for key in ("path", "sha256", "start_line", "end_line")
                },
            }
        )
    ledger = json.dumps(
        {key: value for key, value in context.items() if key != "excerpts"},
        sort_keys=True,
        separators=(",", ":"),
    )
    artifacts.append(
        {
            "kind": "native_sink_evidence",
            "path": "evidence/native-sink.json",
            "content": ledger,
            "sha256": hashlib.sha256(ledger.encode("utf-8")).hexdigest(),
            "candidate_commit": candidate_commit,
            "candidate_sha256": candidate["sha256"],
        }
    )
    return artifacts


def _informed_actionability_item(
    finding,
    requirement,
    candidate,
    artifacts,
    context,
    candidate_commit,
    digest,
    classification_error,
):
    """Build the bounded review envelope and enforce evidence and size limits."""
    item = {
        "id": "sink-"
        + digest(
            {
                "candidate": candidate,
                "rule": finding.get("code"),
                "span": [
                    finding.get(key)
                    for key in ("line", "column", "end_line", "end_column")
                ],
                "criterion_sha256": hashlib.sha256(
                    requirement.encode("utf-8")
                ).hexdigest(),
            }
        )[:24],
        "category": "security_actionability",
        "state": {
            "requirement": requirement,
            "candidate": candidate,
            "evidence": {
                "location": {
                    "path": candidate["path"],
                    "start_line": finding["line"],
                    "end_line": finding.get("end_line", finding["line"]),
                },
                "artifacts": artifacts,
                "dependencies": context["dependency_sources"],
                "actionability": {
                    **{
                        name: {"status": "unknown", "artifacts": []}
                        for name in (
                            "input_origin",
                            "sink_behavior",
                            "callers",
                            "trust_boundary",
                            "counterevidence",
                        )
                    },
                    "unknowns": [
                        "Native source capture does not establish complete callers, authority or opaque object effects."
                    ],
                },
            },
        },
    }
    if not any(
        row["kind"] == "source_excerpt" and row["path"] == candidate["path"]
        for row in artifacts
    ):
        raise classification_error("SINK_LOCATION_UNRESOLVED")
    if (
        len(json.dumps(item, ensure_ascii=False).encode("utf-8")) > 64_000
        or len(artifacts) > 32
    ):
        raise classification_error("SINK_BUDGET_EXHAUSTED")
    return item


def build_informed_sink_context(
    finding, source_index, *, max_sources=64, max_states=512, max_output_bytes=64000
):
    """Expand captured source evidence; source closure never grants execution authority."""
    from .import_context import CapturedImportInventory
    from .runtime_audit_integrity import captured_sink_evidence

    index = source_index
    failure = _informed_preflight(
        finding, index, (max_sources, max_states, max_output_bytes)
    )
    if failure:
        return failure
    result, capture, native, path, sink = _informed_sink_native_capture(
        finding,
        index,
        captured_sink_evidence,
        max_sources=max_sources,
        max_states=max_states,
        max_output_bytes=max_output_bytes,
    )
    if capture is None:
        return result
    inventory = CapturedImportInventory(index.root, tuple(index.snapshots))
    _informed_expand(
        result,
        index,
        path,
        sink,
        inventory,
        max_states - native.get("budget", {}).get("states_used", max_states // 2),
        capture,
    )
    stale = _informed_sink_dependency_sources(result, index, capture)
    if stale:
        return _informed_failure(
            "SINK_SOURCE_STALE", "dependency_changed_after_capture"
        )
    return _informed_sink_finish(result, native, max_output_bytes)


def build_informed_actionability_case(
    finding: Mapping[str, Any],
    source_index: Any,
    *,
    candidate_commit: str,
    requirement: str,
    retriever=None,
) -> dict[str, Any]:
    """Project captured evidence without granting authority or admission."""
    from .jev_classifier import JevClassificationError, _digest
    from .audit_rule_search import build_retrieval_context

    if (
        not isinstance(candidate_commit, str)
        or len(candidate_commit) != 40
        or any(c not in "0123456789abcdef" for c in candidate_commit)
        or not isinstance(requirement, str)
        or not requirement.strip()
        or len(requirement.encode("utf-8")) > 8192
    ):
        raise JevClassificationError("invalid informed review criterion or revision")
    context = build_retrieval_context(finding, source_index, requirement, retriever)
    candidate = {
        "commit": candidate_commit,
        "path": finding["path"],
        "sha256": source_index.inventory[source_index.root / finding["path"]],
    }
    artifacts = _informed_actionability_artifacts(context, candidate_commit, candidate)
    return _informed_actionability_item(
        finding,
        requirement,
        candidate,
        artifacts,
        context,
        candidate_commit,
        _digest,
        JevClassificationError,
    )
