"""Rederive endpoint roles from captured source; serialized proofs grant no credit."""

import ast
from collections import OrderedDict
from copy import deepcopy
import hashlib
import json
import threading

from .credential_endpoint_evidence import mint_endpoint_facts
from .credential_publication_catalog import (
    catalog_content_digest,
    endpoint_publication,
)

_WORKSPACES = OrderedDict()
_LOCK = threading.RLock()
USE_AUDIT_PROFILE = "DECLARED_MEMBER_VALUE_READS_V1"


def _digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _source_bindings(root, sources):
    if not isinstance(sources, dict) or len(sources) > 2000:
        return None
    bindings, total = {}, 0
    for path, raw in sources.items():
        if not isinstance(raw, bytes) or len(raw) > 1_000_000:
            return None
        total += len(raw)
        if total > 32 * 1024 * 1024:
            return None
        try:
            relative = path.relative_to(root).as_posix()
        except (AttributeError, TypeError, ValueError):
            return None
        bindings[relative] = hashlib.sha256(raw).hexdigest()
    return bindings


def _derive(root, sources, bindings, integrity):
    from . import review_audits as audit
    from .credential_role_paths import endpoint_role_evidence

    snapshots, python_bytes, inventory = {}, {}, {}
    for path, raw in sources.items():
        if path.suffix != ".py":
            continue
        try:
            tree = ast.parse(raw)
        except (SyntaxError, ValueError, TypeError, RecursionError):
            return {}
        digest = bindings[path.relative_to(root).as_posix()]
        tree._oracle_source_sha256 = digest
        integrity.bind_security_call_scopes(tree)
        snapshots[path], python_bytes[path], inventory[path] = tree, raw, digest
    eligible = {path.resolve(): path for path in snapshots}
    imports = {
        path: audit._oracle_imports(root, path, tree, eligible)
        for path, tree in snapshots.items()
    }
    return endpoint_role_evidence(
        root, snapshots, imports, python_bytes, inventory, audit, integrity
    )


def _workspace_roles(root, sources, bindings, integrity):
    from . import review_audits as audit

    epoch = audit._oracle_context_cache_key(root, [], {"endpoint": USE_AUDIT_PROFILE})
    key = (str(root), tuple(sorted(bindings.items())), catalog_content_digest(), epoch)
    with _LOCK:
        if key not in _WORKSPACES:
            rows = _derive(root, sources, bindings, integrity)
            _WORKSPACES[key] = deepcopy(rows)
            while len(_WORKSPACES) > 2:
                _WORKSPACES.popitem(last=False)
        _WORKSPACES.move_to_end(key)
        return _WORKSPACES[key]


def _admissible(row):
    audit = row.get("value_use_audit", {})
    return bool(
        row.get("profile") == "DECLARED_CLASS_MAY_FLOW"
        and row.get("url_witnesses")
        and audit.get("state") == "COMPLETE"
        and audit.get("profile") == USE_AUDIT_PROFILE
        and row.get("known_auth_uses") == []
        and row.get("linked_unknown_uses") == []
    )


def _attach(finding, row, publication, bindings, relative, node):
    declaration = row.get("declaration", {})
    if not (
        declaration.get("source_sha256") == bindings.get(relative)
        and declaration.get("path") == relative
        and declaration.get("line") == node.lineno
        and declaration.get("column") == node.col_offset
        and declaration.get("member") == finding.get("facts", {}).get("name")
        and declaration.get("value_sha256")
        == hashlib.sha256(publication["value"].encode()).hexdigest()
    ):
        return
    facts = {
        **finding.get("facts", {}),
        "schema": "factory.public-protocol-endpoint.v1",
        "disposition": "ENDPOINT_DECLARATION_ROLE_PROVEN",
        "source_path": relative,
        "source_sha256": bindings[relative],
        "workspace_sources_sha256": _digest(sorted(bindings.items())),
        "flow_profile": row["profile"],
        "runtime_assurance": "INCOMPLETE",
        "credential_safety": "UNASSESSED",
        "target_execution": "not_performed",
        "publication": publication,
        "declaration": deepcopy(declaration),
        "url_witnesses": deepcopy(row["url_witnesses"]),
        "known_auth_uses": [],
        "linked_unknown_uses": [],
        "value_use_audit": deepcopy(row["value_use_audit"]),
    }
    finding["facts"] = mint_endpoint_facts(facts, finding, bindings)


def annotate_endpoint_findings(relative, node, findings, integrity):
    """Mint local evidence only after fresh-source role and use-audit derivation."""
    value = getattr(node, "value", None)
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        return findings
    publication = endpoint_publication(value.value)
    if publication is None or not any(
        f.get("code") == "SECURITY_HARDCODED_SECRET" for f in findings
    ):
        return findings
    module = integrity._security_module_scope(
        getattr(node, "_security_lexical_scope", None)
    )
    context = getattr(module, "_security_source_context", None)
    if not isinstance(context, tuple) or len(context) != 2:
        return findings
    root, sources = context
    bindings = _source_bindings(root, sources)
    if not bindings or bindings.get(relative) != getattr(
        module, "_oracle_source_sha256", None
    ):
        return findings
    rows = _workspace_roles(root, sources, bindings, integrity)
    for finding in findings:
        if finding.get("code") != "SECURITY_HARDCODED_SECRET":
            continue
        key = (relative, node.lineno, finding.get("facts", {}).get("name"))
        row = rows.get(key, {})
        if _admissible(row):
            _attach(finding, row, publication, bindings, relative, node)
    return findings


def endpoint_admission_helpers():
    """Include derivation semantics in the native scanner context fingerprint."""
    from importlib import import_module

    names = (
        "credential_endpoint_admission",
        "credential_publication_catalog",
        "credential_publication_excerpt",
        "credential_protocol_documents",
        "credential_role_paths",
        "credential_role_sources",
        "credential_role_bindings",
        "credential_role_chain_memo",
        "credential_role_source_models",
        "credential_role_class_binding",
        "credential_role_constructor_flow",
        "credential_role_adapter_selection",
        "credential_role_setting_boundary",
        "credential_role_session_calls",
        "credential_role_scope_bindings",
        "credential_role_name_binding",
        "credential_role_module_settings",
        "credential_role_use_audit",
        "credential_role_value_slices",
        "credential_role_transfer_hops",
        "credential_role_transfer_guards",
        "credential_role_default_contract",
        "credential_role_object_identity",
        "credential_role_method_flow",
        "credential_role_method_paths",
        "credential_role_method_call",
        "credential_role_method_contracts",
        "credential_role_method_evidence",
        "credential_role_method_return",
        "credential_role_method_use_audit",
        "credential_role_method_use_closure",
        "credential_role_method_use_common",
        "credential_role_method_use_edges",
        "credential_role_method_use_callers",
        "credential_role_method_use_getters",
        "credential_role_method_use_getter_audit",
        "credential_role_method_use_getter_reflective",
        "credential_role_method_use_relation",
        "credential_role_receiver_class",
        "credential_role_receiver_lifetime",
        "credential_role_identity_effects",
        "credential_role_identity_effect_types",
        "credential_role_identity_value_model",
        "credential_role_identity_call_model",
        "credential_role_field_origin",
        "credential_role_getter_consumers",
        "credential_role_getter_records",
        "credential_role_strategy_default",
        "credential_role_strategy_fallback",
        "credential_role_forwarding_decorator",
        "credential_session_forwarding",
        "security_configuration",
        "semantic_credential_sensor",
    )
    return tuple(
        value
        for name in names
        for module in [import_module(f".{name}", __package__)]
        for value in vars(module).values()
        if callable(value)
    )
