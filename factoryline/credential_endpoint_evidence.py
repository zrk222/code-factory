"""Process-local endpoint derivations; JSON evidence carries no admission authority."""

import hashlib
import json

from .credential_publication_catalog import endpoint_publication

_ISSUER = object()
_IDENTITY = ("code", "path", "line", "column", "severity", "message")


def _digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _identity(finding):
    return tuple(finding.get(key) for key in _IDENTITY)


class _NativeEndpointFacts(dict):
    """Mutation-evident local derivation marker, deliberately lost on JSON decode."""

    __slots__ = ("_attestation",)

    def __init__(self, facts, finding, bindings, issuer):
        if issuer is not _ISSUER:
            raise ValueError("native endpoint derivation issuer required")
        super().__init__(facts)
        object.__setattr__(
            self,
            "_attestation",
            (_digest(facts), _identity(finding), tuple(sorted(bindings.items()))),
        )

    def __setattr__(self, *args):
        raise AttributeError("native derivation attestation is immutable")

    __delattr__ = __setattr__

    def __copy__(self):
        return dict(self)

    def __deepcopy__(self, memo):
        import copy

        return copy.deepcopy(dict(self), memo)


def mint_endpoint_facts(facts, finding, required_bindings):
    """Internal only: caller must first rederive all paths from pinned source ASTs."""
    return _NativeEndpointFacts(facts, finding, required_bindings, _ISSUER)


def endpoint_binding(finding, sources, bindings):
    """Check native derivation and current publication/source bindings, not safety."""
    facts = finding.get("facts")
    if type(facts) is not _NativeEndpointFacts:
        return False
    try:
        digest, identity, required = facts._attestation
        publication = facts.get("publication")
        if not isinstance(publication, dict):
            return False
        current = endpoint_publication(publication.get("value"))
        manifest = [(row["path"], row["sha256"]) for row in sources]
        if len(dict(manifest)) != len(manifest):
            return False
        return bool(
            finding.get("code") == "SECURITY_HARDCODED_SECRET"
            and facts.get("schema") == "factory.public-protocol-endpoint.v1"
            and facts.get("disposition") == "ENDPOINT_DECLARATION_ROLE_PROVEN"
            and facts.get("flow_profile") == "DECLARED_CLASS_MAY_FLOW"
            and facts.get("runtime_assurance") == "INCOMPLETE"
            and facts.get("credential_safety") == "UNASSESSED"
            and facts.get("known_auth_uses") == []
            and facts.get("linked_unknown_uses") == []
            and digest == _digest(facts)
            and identity == _identity(finding)
            and current is not None
            and publication == current
            and facts.get("workspace_sources_sha256") == _digest(sorted(manifest))
            and required
            and all(
                bindings.get(path) == sha and dict(manifest).get(path) == sha
                for path, sha in required
            )
            and facts.get("source_path") == finding.get("path")
            and (facts.get("source_path"), facts.get("source_sha256")) in required
        )
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError):
        return False


def endpoint_evidence_helpers():
    """Expose the endpoint evidence digest, identity, native-facts, minting, and binding helpers as one helper tuple."""
    return (
        _digest,
        _identity,
        _NativeEndpointFacts,
        mint_endpoint_facts,
        endpoint_binding,
    )
