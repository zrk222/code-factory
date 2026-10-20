"""Source-binding checks for retained primitive observations."""

import hashlib
import json
import re


def fixed_primitive_binding(finding, sources, bindings, integrity):
    from .provenance import public_symbolic_binding, finite_template_binding
    from .credential_endpoint_evidence import endpoint_binding

    facts = finding.get("facts", {})
    if facts.get("disposition") == "PROVEN_LOCAL_CRYPTO_TEST_PRIMITIVE":
        workspace_sources = sorted((row["path"], row["sha256"]) for row in sources)
        workspace_digest = hashlib.sha256(
            json.dumps(workspace_sources, separators=(",", ":")).encode()
        ).hexdigest()
        provider = next(
            (row for row in sources if row.get("path") == facts.get("provider_path")),
            None,
        )
        span = facts.get("declaration_span")
        witness_spans = (
            "test_owner_span",
            "provider_allocation_span",
            "encode_call_span",
            "decode_call_span",
            "token_result_span",
            "payload_source_span",
        )
        return bool(
            finding.get("code") == "SECURITY_HARDCODED_SECRET"
            and finding.get("severity") == "CRITICAL"
            and facts.get("schema") == "factory.jwt-local-crypto-test-primitive.v1"
            and facts.get("source_path") == finding.get("path")
            and facts.get("source_sha256") == bindings.get(finding.get("path"))
            and facts.get("workspace_sources_sha256") == workspace_digest
            and provider is not None
            and facts.get("provider_sha256") == provider.get("sha256")
            and facts.get("operation_role")
            == "test_owned_local_sign_and_verify_roundtrip"
            and facts.get("authority_role")
            == "TEST_OWNED_SYNTHETIC_SIGNING_AUTHORITY"
            and facts.get("transport_role") == "UNASSESSED"
            and facts.get("runtime_assurance") == "INCOMPLETE"
            and facts.get("runtime_executed") is False
            and isinstance(span, list)
            and len(span) == 4
            and span[0] == finding.get("line")
            and span[1] == finding.get("column")
            and span[2] >= span[0]
            and span[3] >= span[1]
            and all(integrity._valid_source_span(facts.get(key)) for key in witness_spans)
            and facts["test_owner_span"][:2] <= facts["encode_call_span"][:2]
            and facts["encode_call_span"][:2] <= facts["decode_call_span"][:2]
        )
    if facts.get("disposition") == "TEST_OWNED_LOCAL_FIXTURE":
        return django_fixture_binding(finding, sources, bindings)
    if facts.get("disposition") == "ENDPOINT_DECLARATION_ROLE_PROVEN":
        return endpoint_binding(finding, sources, bindings)
    if facts.get("disposition") == "PROVEN_PUBLIC_SYMBOLIC_IDENTIFIER":
        return public_symbolic_binding(finding, sources, bindings)
    if facts.get("disposition") == "PROVEN_FINITE_TEMPLATE_INPUT":
        return finite_template_binding(finding, sources, bindings)
    workspace_sources = sorted((row["path"], row["sha256"]) for row in sources)
    workspace_digest = hashlib.sha256(
        json.dumps(workspace_sources, separators=(",", ":")).encode()
    ).hexdigest()
    return (
        finding.get("code") == "SECURITY_DYNAMIC_EXECUTION"
        and isinstance(facts.get("source_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", facts["source_sha256"])
        and facts.get("source_path") == finding.get("path")
        and sum(row["path"] == finding.get("path") for row in sources) == 1
        and facts["source_sha256"] == bindings.get(finding.get("path"))
        and (
            facts.get("schema") == "factory.fixed-literal-program.v1"
            if facts.get("disposition") == "PROVEN_FIXED_LITERAL_PROGRAM"
            else (
                integrity._finite_eval_binding(finding)
                if facts.get("disposition") == "PROVEN_FINITE_LITERAL_EVAL_INPUT"
                else integrity._closed_declaration_binding(finding)
            )
        )
        and facts.get("workspace_sources_sha256") == workspace_digest
    )


def rejected_primitive_proof(finding):
    """Rejected credential proofs preserve the original alert priority/message."""
    facts = finding.get("facts", {})
    if facts.get("disposition") == "ENDPOINT_DECLARATION_ROLE_PROVEN":
        return {
            **finding,
            "facts": {
                **facts,
                "disposition": "UNVERIFIED_ENDPOINT_DECLARATION",
                "state": "INCOMPLETE",
                "proof_rejection": "NATIVE_SOURCE_BINDING_OR_PUBLICATION_MISMATCH",
            },
        }
    if finding.get("code") == "SECURITY_HARDCODED_SECRET":
        jwt_role_proof = facts.get("disposition") == "PROVEN_LOCAL_CRYPTO_TEST_PRIMITIVE"
        return {
            **finding,
            "severity": "CRITICAL" if jwt_role_proof else finding.get("severity"),
            "message": (
                "The JWT test-role proof is not bound to the current source; credential risk remains active."
                if jwt_role_proof
                else finding.get("message")
            ),
            "facts": {
                **facts,
                "disposition": "UNVERIFIED_CREDENTIAL_ROLE",
                "state": "INCOMPLETE",
                "proof_rejection": "SOURCE_BINDING_MISMATCH",
            },
        }
    return {
        **finding,
        "severity": "HIGH",
        "message": "The fixed-program proof is not bound to the current source; execution risk remains unverified.",
        "facts": {
            **facts,
            "disposition": "UNVERIFIED_FIXED_PROGRAM",
            "state": "INCOMPLETE",
            "proof_rejection": "SOURCE_BINDING_MISMATCH",
        },
    }


def partition_proven_primitive_observations(core, audit):
    """Keep proved fixed programs visible without describing them as defects."""
    from .audit_action_refs import _security_scan_action_summary, _security_scan_state

    bindings = {row["path"]: row["sha256"] for row in core.get("sources", [])}
    prior = core.get("primitive_observations", [])
    retained, proved = [], []
    touched = bool(prior)
    for finding in [*core["findings"], *prior]:
        facts = finding.get("facts", {})
        if facts.get("disposition") not in {
            "PROVEN_FIXED_LITERAL_PROGRAM",
            "PROVEN_CLOSED_DECLARATION_INPUT",
            "PROVEN_FINITE_LITERAL_EVAL_INPUT",
            "PROVEN_PUBLIC_SYMBOLIC_IDENTIFIER",
            "PROVEN_FINITE_TEMPLATE_INPUT",
            "ENDPOINT_DECLARATION_ROLE_PROVEN",
            "TEST_OWNED_LOCAL_FIXTURE",
            "PROVEN_LOCAL_CRYPTO_TEST_PRIMITIVE",
        }:
            retained.append(finding)
            continue
        touched = True
        endpoint_complete = (
            facts.get("disposition")
            not in {"ENDPOINT_DECLARATION_ROLE_PROVEN", "TEST_OWNED_LOCAL_FIXTURE", "PROVEN_LOCAL_CRYPTO_TEST_PRIMITIVE"}
            or core.get("audit_coverage", {}).get("complete") is True
        )
        if endpoint_complete and _current_primitive_binding(
            finding, core, bindings, audit
        ):
            proved.append(finding)
        else:
            retained.append(rejected_primitive_proof(finding))
    if not touched:
        return
    core["primitive_observations"] = proved
    core["primitive_observation_count"] = len(core["primitive_observations"])
    core["findings"] = retained
    core["finding_counts"] = dict(
        sorted(
            (code, sum(f["code"] == code for f in retained))
            for code in {f["code"] for f in retained}
        )
    )
    core["state"] = _security_scan_state(
        core.get("sources", []),
        retained,
        core.get("database_context"),
        core.get("audit_coverage"),
    )
    core["action_summary"] = _security_scan_action_summary(core["state"])


def _current_primitive_binding(finding, core, bindings, audit):
    sources = core.get("sources", [])
    if finding.get("facts", {}).get("disposition") == "TEST_OWNED_LOCAL_FIXTURE":
        configs = core.get("oracle_context", {}).get("configuration_sources", [])
        sources = [*sources, *configs]
        bindings = {row["path"]: row["sha256"] for row in sources}
    return audit._fixed_primitive_binding(finding, sources, bindings)


def annotate_django_fixture(finding, node):
    """Retain the original severity and primitive; attach captured owner evidence."""
    from . import review_integrity as integrity

    module = integrity._security_module_scope(
        getattr(node, "_security_lexical_scope", None)
    )
    context = getattr(module, "_security_oracle_context", {})
    facts = finding.get("facts", {})
    key = f"{node.lineno}:{node.col_offset}:{facts.get('name')}"
    item = context.get("django_fixture_evidence", {}).get(key)
    if not isinstance(item, dict) or item.get("eligible") is not True:
        return finding
    if item.get("source_sha256") != getattr(module, "_oracle_source_sha256", None):
        return finding
    proof = {
        **facts,
        "schema": "factory.test-owned-credential.v1",
        "disposition": "TEST_OWNED_LOCAL_FIXTURE",
        "fixture_evidence": item,
        "declaration_span": [
            node.lineno,
            node.col_offset,
            node.end_lineno,
            node.end_col_offset,
        ],
        "runtime_assurance": "INCOMPLETE",
        "target_execution": "not_performed",
    }
    proof["proof_facts_sha256"] = hashlib.sha256(
        json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {**finding, "facts": proof}


def django_fixture_binding(finding, sources, bindings):
    """Validate the full analyzed inventory and config identity before partition."""
    facts = finding.get("facts", {})
    evidence = facts.get("fixture_evidence", {})
    if not isinstance(evidence, dict):
        return False
    configs = evidence.get("runner_config_sha256", {})
    if not isinstance(configs, dict) or set(configs) != {"pyproject.toml", "tox.ini"}:
        return False
    paths = [row["path"] for row in sources]
    if len(paths) != len(set(paths)):
        return False
    inventory = {
        row["path"]: row["sha256"] for row in sources if row["path"].endswith(".py")
    }
    if any(bindings.get(name) != digest for name, digest in configs.items()):
        return False
    inventory.update(configs)
    digest = hashlib.sha256(
        "\n".join(
            sorted(f"{name}\0{value}" for name, value in inventory.items())
        ).encode()
    ).hexdigest()
    unsigned = {
        name: value for name, value in facts.items() if name != "proof_facts_sha256"
    }
    return (
        finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and facts.get("disposition") == "TEST_OWNED_LOCAL_FIXTURE"
        and facts.get("schema") == "factory.test-owned-credential.v1"
        and evidence.get("classification") == "TEST_OWNED_LOCAL_FIXTURE"
        and evidence.get("eligible") is True
        and evidence.get("source") == finding.get("path")
        and finding.get("path") in bindings
        and isinstance(evidence.get("source_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", evidence["source_sha256"]) is not None
        and evidence.get("source_sha256") == bindings.get(finding.get("path"))
        and evidence.get("inventory_sha256") == digest
        and valid_source_span(facts.get("declaration_span"))
        and facts["declaration_span"][:2]
        == [finding.get("line"), finding.get("column")]
        and facts.get("proof_facts_sha256")
        == hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )


def closed_declaration_binding(finding, audit):
    facts = finding.get("facts", {})
    span = facts.get("call_span")
    return (
        facts.get("disposition") == "PROVEN_CLOSED_DECLARATION_INPUT"
        and facts.get("schema") == "factory.closed-declaration-input.v1"
        and facts.get("grammar_profile") == "python3.12-type-alias-subset-v1"
        and facts.get("hypothesis") == "ARGUMENT_CODE_INJECTION"
        and facts.get("input_effect") == "CLOSED_INERT_DECLARATION"
        and facts.get("runtime_assurance") == "INCOMPLETE"
        and facts.get("target_execution") == "not_performed"
        and isinstance(facts.get("program_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", facts["program_sha256"]) is not None
        and audit._valid_source_span(span)
        and span[:2] == [finding.get("line"), finding.get("column")]
        and audit._valid_source_span(facts.get("literal_span"))
        and tuple(span[:2])
        <= tuple(facts["literal_span"][:2])
        <= tuple(facts["literal_span"][2:])
        <= tuple(span[2:])
    )


def valid_source_span(span):
    return (
        isinstance(span, list)
        and len(span) == 4
        and all(type(n) is int for n in span)
        and span[0] > 0
        and min(span[1], span[3]) >= 0
        and tuple(span[:2]) <= tuple(span[2:])
    )


def finite_eval_binding(finding, audit):
    from .runtime_audit_integrity import finite_eval_binding as bind

    return bind(finding, audit._valid_source_span)


def fixed_program_builtin_identity(audit, node, module, call_name):
    if not isinstance(node.func, audit.ast.Name) or node.func.id not in {
        "exec",
        "eval",
    }:
        return False
    if call_name != node.func.id or audit._builtin_repr_names_shadowed(
        node, {node.func.id}
    ):
        return False
    direct_call_names = {
        call.func
        for call in audit.ast.walk(module)
        if isinstance(call, audit.ast.Call)
        and getattr(call.func, "id", None) in {"exec", "eval"}
        and getattr(call, "_security_lexical_scope", None)
        is getattr(node, "_security_lexical_scope", None)
    }
    for item in audit.ast.walk(module):
        if item is node.func or item in direct_call_names:
            continue
        if isinstance(item, audit.ast.Name) and item.id in {
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
        }:
            return False
        if isinstance(item, audit.ast.Attribute) and item.attr in {
            "__dict__",
            "__globals__",
            "__builtins__",
            "__getattribute__",
            "__setattr__",
            "import_module",
        }:
            return False
        if (
            isinstance(item, audit.ast.Attribute)
            and item.attr in {"exec", "eval"}
            and isinstance(item.ctx, (audit.ast.Store, audit.ast.Del))
        ):
            return False
        if isinstance(item, audit.ast.ImportFrom) and (
            item.module == "builtins" or any(a.name == "*" for a in item.names)
        ):
            return False
        if isinstance(item, audit.ast.Import) and any(
            a.name == "builtins" for a in item.names
        ):
            return False
    return True


def fixed_program_witness(audit, relative, node, call_name):
    """Bind literal-program proof to the captured source and lexical identity."""
    from .provenance import finite_template_witness
    from .runtime_audit_integrity import (
        closed_declaration_input_witness,
        finite_literal_eval_input_witness,
        fixed_literal_program_witness,
        source_generated_eval_input_witness,
    )

    scope = getattr(node, "_security_lexical_scope", None)
    if not isinstance(
        scope, (audit.ast.Module, audit.ast.FunctionDef, audit.ast.AsyncFunctionDef)
    ):
        return {}
    module = audit._security_module_scope(scope)
    workspace_profile = getattr(module, "_fixed_program_workspace", {})
    context = getattr(module, "_security_source_context", None)
    if (
        isinstance(context, tuple)
        and len(context) == 2
        and isinstance(workspace_profile, dict)
    ):
        root, sources = context
        raw = sources.get(root / relative) if isinstance(sources, dict) else None
        if isinstance(raw, bytes) and audit.hashlib.sha256(raw).hexdigest() == getattr(
            module, "_oracle_source_sha256", None
        ):
            if witness := (
                closed_declaration_input_witness(
                    node, call_name, source_bytes=raw, source_path=relative
                )
                or finite_literal_eval_input_witness(
                    node, call_name, source_bytes=raw, source_path=relative
                )
                or source_generated_eval_input_witness(
                    node,
                    call_name,
                    source_bytes=raw,
                    source_path=relative,
                    builtin_identity_proven=audit._fixed_program_builtin_identity(
                        node, module, call_name
                    ),
                )
                or finite_template_witness(
                    relative, node, call_name, root, sources, workspace_profile
                )
            ):
                witness["workspace_sources_sha256"] = workspace_profile.get(
                    "sources_sha256"
                )
                return witness
    if (
        not isinstance(workspace_profile, dict)
        or workspace_profile.get("complete") is not True
        or workspace_profile.get("namespace_mutation_risk") is not False
        or not isinstance(workspace_profile.get("sources_sha256"), str)
    ):
        return {}
    context = getattr(module, "_security_source_context", None)
    if not isinstance(context, tuple) or len(context) != 2:
        return {}
    if not audit._fixed_program_builtin_identity(node, module, call_name):
        return {}
    root, sources = context
    raw = sources.get(root / relative) if isinstance(sources, dict) else None
    if not isinstance(raw, bytes) or audit.hashlib.sha256(raw).hexdigest() != getattr(
        module, "_oracle_source_sha256", None
    ):
        return {}
    witness = fixed_literal_program_witness(
        node,
        call_name,
        source_bytes=raw,
        builtin_identity_proven=True,
        source_path=relative,
        scope_profile="native-module-or-function-omitted-namespaces",
    )
    if witness:
        witness["workspace_sources_sha256"] = workspace_profile["sources_sha256"]
    return witness


def bind_fixed_program_workspace(
    audit, root, contexts, snapshots, files, source_bytes=None, imports=None
):
    import json

    from .runtime_audit_integrity import workspace_builtin_profile

    profile = workspace_builtin_profile(snapshots, files)
    profile.pop("source_hashes", None)
    sources = sorted(
        (
            path.relative_to(root).as_posix(),
            getattr(tree, "_oracle_source_sha256", None),
        )
        for path, tree in snapshots.items()
    )
    profile["sources_sha256"] = audit.hashlib.sha256(
        json.dumps(sources, separators=(",", ":")).encode()
    ).hexdigest()
    if (
        source_bytes is not None
        and imports is not None
        and set(snapshots) == set(files)
    ):
        inventory = {
            path: getattr(tree, "_oracle_source_sha256", None)
            for path, tree in snapshots.items()
        }
        audit.bind_credential_consumers(
            root, snapshots, imports, contexts, source_bytes, inventory=inventory
        )
    for context in contexts.values():
        context["fixed_program_workspace"] = {
            **profile,
            "credential_consumers": context.get("credential_consumers", {}),
            "finite_template_inputs": context.get("finite_template_inputs", {}),
        }


def fixed_program_workspace_helpers(audit):
    from . import runtime_audit_integrity as runtime

    return (
        audit.bind_fixed_program_workspace,
        runtime.workspace_builtin_profile,
        runtime._fixed_literal_program_kinds,
        runtime._fixed_literal_value,
        runtime._closed_declaration_program,
        runtime._closed_declaration_namespace,
        runtime._closed_declaration_binding,
        runtime.closed_declaration_input_witness,
        runtime._finite_eval_comprehension,
        runtime._finite_eval_domain,
        runtime._finite_eval_module_prefix,
        runtime.finite_literal_eval_input_witness,
        runtime.finite_template_input_helpers,
        *runtime.finite_template_input_helpers(),
        audit._finite_eval_binding,
        audit._closed_declaration_binding,
        audit._valid_source_span,
        *runtime.workspace_builtin_helpers(),
        *audit.credential_consumer_helpers(),
    )


def primitive_binding_helpers():
    from .credential_endpoint_evidence import endpoint_evidence_helpers
    from .credential_endpoint_admission import endpoint_admission_helpers
    from . import credential_publication_catalog

    return (
        fixed_primitive_binding,
        rejected_primitive_proof,
        partition_proven_primitive_observations,
        _current_primitive_binding,
        annotate_django_fixture,
        django_fixture_binding,
        closed_declaration_binding,
        valid_source_span,
        finite_eval_binding,
        fixed_program_builtin_identity,
        fixed_program_witness,
        bind_fixed_program_workspace,
        fixed_program_workspace_helpers,
        credential_context_cache_schema,
        *endpoint_evidence_helpers(),
        *endpoint_admission_helpers(),
        *(
            value
            for module in (credential_publication_catalog,)
            for value in vars(module).values()
            if callable(value)
        ),
    )


def credential_context_cache_schema():
    from .credential_publication_catalog import catalog_content_digest

    return "factory.security-oracle-context-cache.v7:" + catalog_content_digest()
