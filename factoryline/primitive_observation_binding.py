"""Source-binding checks for retained primitive observations."""

import hashlib
import json
import re


def fixed_primitive_binding(finding, sources, bindings, integrity):
    from .provenance import public_symbolic_binding, finite_template_binding
    from .credential_endpoint_evidence import endpoint_binding

    facts = finding.get("facts", {})
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
        return {
            **finding,
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


def primitive_binding_helpers():
    from .credential_endpoint_evidence import endpoint_evidence_helpers
    from .credential_endpoint_admission import endpoint_admission_helpers
    from . import credential_protocol_metadata, credential_publication_catalog

    return (
        fixed_primitive_binding,
        rejected_primitive_proof,
        credential_context_cache_schema,
        *endpoint_evidence_helpers(),
        *endpoint_admission_helpers(),
        *(
            value
            for module in (credential_protocol_metadata, credential_publication_catalog)
            for value in vars(module).values()
            if callable(value)
        ),
    )


def credential_context_cache_schema():
    from .credential_publication_catalog import catalog_content_digest

    return "factory.security-oracle-context-cache.v7:" + catalog_content_digest()
