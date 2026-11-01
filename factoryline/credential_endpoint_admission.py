"""Admit endpoint proof from fresh source, publication, and fixture evidence."""

import ast
from collections import OrderedDict
from copy import deepcopy
import hashlib
from importlib import resources
import json
import re
import threading
from types import MappingProxyType
from pathlib import Path
from urllib.parse import urlsplit

HTTP_CLIENT_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request"}
)

SECURITY_EFFECT_WITNESS_SCHEMA = "factory.security.effect-witness.v1"
SECURITY_EFFECT_CONTRACTS = MappingProxyType(
    {
        "SECURITY_PATH_TRAVERSAL": MappingProxyType(
            {
                "source_role": "untrusted_request_filename",
                "consumer_role": "flask_file_storage_save",
                "effect_kind": "path_escape",
                "effect_facts": MappingProxyType(
                    {
                        "provider_id": "werkzeug.FileStorage.save",
                        "path_composition": ("os.path.join", "raw_string_concat"),
                        "destination_relation": "escape_capable",
                        "normalized_counterexample_relation": "outside_intended_base",
                        "normalization_profile": "python_os_path",
                        "intended_base_span": None,
                    }
                ),
                "effect_variants": MappingProxyType(
                    {
                        "direct_filename": MappingProxyType(
                            {
                                "effect_kind": "unbounded_upload_target",
                                "effect_facts": MappingProxyType(
                                    {
                                        "provider_id": "werkzeug.FileStorage.save",
                                        "path_composition": "direct_filename",
                                        "destination_relation": "attacker_selected_path",
                                        "normalized_counterexample_relation": "absolute_or_parent_relative_path",
                                        "normalization_profile": "python_os_path",
                                        "intended_base_span": None,
                                    }
                                ),
                            }
                        )
                    }
                ),
            }
        ),
        "SECURITY_TLS_VERIFY_DISABLED": MappingProxyType(
            {
                "source_role": "tls_verification_configuration",
                "consumer_role": "known_tls_client_request",
                "effect_kind": "tls_peer_authentication_bypass",
                "effect_facts": MappingProxyType(
                    {
                        "provider_id": tuple(
                            sorted(
                                {
                                    *(
                                        f"{module}.{method}"
                                        for module in ("requests", "httpx")
                                        for method in HTTP_CLIENT_METHODS
                                    ),
                                    "httpx.Client",
                                    "httpx.AsyncClient",
                                    "httpx.stream",
                                }
                            )
                        ),
                        "verification_setting": "literal_false",
                        "transport_relation": ("static_https", "https_capable"),
                        "https_operation_span": None,
                    }
                ),
            }
        ),
        "SECURITY_LOG_INJECTION": MappingProxyType(
            {
                "source_role": "newline_capable_untrusted_text",
                "consumer_role": "line_delimited_log",
                "effect_kind": "log_record_boundary_injection",
                "effect_facts": MappingProxyType(
                    {
                        "provider_id": tuple(
                            f"logging.{level}"
                            for level in (
                                "debug",
                                "info",
                                "warning",
                                "error",
                                "critical",
                                "exception",
                                "log",
                            )
                        ),
                        "newline_capability": "CR_LF",
                        "neutralization": "none",
                        "consumer_format": "%(message)s",
                        "consumer_config_path": None,
                        "consumer_config_sha256": None,
                        "consumer_config_span": None,
                        "consumer_handler_id": (
                            "logging.FileHandler",
                            "logging.StreamHandler",
                            "logging.handlers.RotatingFileHandler",
                            "logging.handlers.TimedRotatingFileHandler",
                            "logging.handlers.WatchedFileHandler",
                        ),
                        "consumer_handler_span": None,
                        "consumer_handler_key": None,
                        "consumer_logger_id": None,
                        "consumer_call_level": (
                            "debug",
                            "info",
                            "warning",
                            "error",
                            "critical",
                        ),
                        "consumer_effective_level": (
                            "NOTSET",
                            "DEBUG",
                            "INFO",
                            "WARNING",
                            "ERROR",
                            "CRITICAL",
                        ),
                        "consumer_formatter_id": "logging.Formatter",
                        "consumer_formatter_span": None,
                        "consumer_formatter_key": None,
                        "activation_path": None,
                        "activation_sha256": None,
                        "activation_span": None,
                    }
                ),
            }
        ),
    }
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


def _derive(root, sources, bindings, integrity, captured=False):
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
    if captured:
        from .import_context import CapturedImportInventory

        eligible = CapturedImportInventory(root, tuple(snapshots))
    else:
        eligible = {path.resolve(): path for path in snapshots}
    imports = {
        path: audit._oracle_imports(root, path, tree, eligible, captured=captured)
        for path, tree in snapshots.items()
    }
    return endpoint_role_evidence(
        root, snapshots, imports, python_bytes, inventory, audit, integrity
    )


def _workspace_roles(root, sources, bindings, integrity, *, purpose="producer"):
    from . import review_audits as audit

    native = purpose == "native-revalidation"
    epoch = audit._oracle_context_cache_key(
        root, [], {"endpoint": USE_AUDIT_PROFILE}, captured=native
    )
    key = (
        purpose,
        str(root),
        tuple(sorted(bindings.items())),
        catalog_content_digest(),
        epoch,
    )
    with _LOCK:
        if key not in _WORKSPACES:
            rows = (
                _derive(root, sources, bindings, integrity, True)
                if native
                else _derive(root, sources, bindings, integrity)
            )
            _WORKSPACES[key] = deepcopy(rows)
            while len(_WORKSPACES) > 2:
                _WORKSPACES.popitem(last=False)
        _WORKSPACES.move_to_end(key)
        return deepcopy(_WORKSPACES[key])


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


def _endpoint_annotation_source(relative, node, integrity):
    module = integrity._security_module_scope(
        getattr(node, "_security_lexical_scope", None)
    )
    context = getattr(module, "_security_source_context", None)
    if not isinstance(context, tuple) or len(context) != 2:
        return None
    root, sources = context
    bindings = _source_bindings(root, sources)
    if not bindings or bindings.get(relative) != getattr(
        module, "_oracle_source_sha256", None
    ):
        return None
    return root, sources, bindings


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
    source_context = _endpoint_annotation_source(relative, node, integrity)
    if source_context is None:
        return findings
    root, sources, bindings = source_context
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

    owner_names = (
        "OrderedDict",
        "deepcopy",
        "_digest",
        "_source_bindings",
        "_captured_endpoint_binding",
        "_endpoint_captured_inventory",
        "_endpoint_captured_source_row",
        "_endpoint_captured_source_binding",
        "_endpoint_captured_claim",
        "_endpoint_annotation_source",
        "_derive",
        "_workspace_roles",
        "_admissible",
        "_attach",
        "annotate_endpoint_findings",
        "factory_fixture_consumer_status",
        "_factory_fixture_uses",
        "_factory_fixture_consumer_result",
        "_single_factory_fixture_call",
        "endpoint_admission_helpers",
        "_endpoint_claim_profile_matches",
        "_endpoint_attestation_matches",
        "_reviewed_capture_matches",
        "_reviewed_publication_matches",
        "mint_endpoint_facts",
        "catalog_content_digest",
        "endpoint_publication",
    )
    excerpt_names = (
        "urlsplit",
        "_public_https",
        "digest",
        "_sha",
        "_excerpt_https",
        "_excerpt_valid",
        "reviewed_excerpt_fact",
        "_reviewed_capture_matches",
        "_reviewed_publication_matches",
    )
    protocol_names = (
        "_public_https",
        "_unique_object",
        "_invalid_constant",
        "_protocol_https",
        "_document",
        "_flow_rows",
        "_openapi_security_schemes",
        "_openapi_scheme_rows",
        "_openapi_token_url_rows",
        "_openapi_declaration_records",
        "_valid_flow",
        "openapi_endpoint_declarations",
        "matches_openapi_endpoint",
    )
    session_names = (
        "_span",
        "_hop",
        "_body",
        "_construction",
        "_request_attribute",
        "_timeout_forwarder",
        "_forwarder_provider_uncertain",
        "_factory_owner_valid",
        "session_factory_witness",
        "_session_factory_receiver",
        "_session_factory_witness_rows",
    )
    role_names = (
        "credential_role_constructor_provider",
        "credential_role_method_use_getter_audit",
        "credential_role_paths",
        "finite_capture",
        "credential_role_identity_effects",
        "security_configuration",
        "semantic_credential_sensor",
    )
    helpers = tuple(
        value
        for name in role_names
        for module in [import_module(f".{name}", __package__)]
        for value in vars(module).values()
        if callable(value)
    )
    from .credential_role_method_use_getter_audit import RecordProjectionIndex

    return (
        *_callable_values(owner_names),
        *catalog_callable_helpers(),
        *_callable_values(excerpt_names),
        *_callable_values(protocol_names),
        *_callable_values(session_names),
        _callable_values,
        catalog_callable_helpers,
        *helpers,
        *(
            method
            for method in vars(RecordProjectionIndex).values()
            if callable(method)
        ),
    )


def _callable_values(names):
    return tuple(value for name in names if callable(value := globals().get(name)))


def catalog_callable_helpers():
    """Return the exact callable inventory formerly owned by the publication catalog."""
    return _callable_values(
        (
            "urlsplit",
            "_unique_object",
            "_public_https",
            "endpoint_metadata",
            "matches_endpoint_declaration",
            "_catalog_digest",
            "_entry",
            "_reviewed_entry",
            "_declaration",
            "_read",
            "_catalog_bytes",
            "catalog_content_digest",
            "endpoint_publications",
            "endpoint_publication",
        )
    )


def validation_helpers():
    """Return the original HTTPX, JSON assertion, and router validation callables."""
    from .credential_role_method_use_getter_audit import CapturedOriginProjection

    return (
        tuple(
            value
            for owner in (
                _OperativeCredentialOrigin,
                _CredentialHandlerIndex,
                CapturedOriginProjection,
            )
            for value in vars(owner).values()
            for value in (getattr(value, "__func__", value),)
            if callable(value)
        )
        + _callable_values(
            (
                "operative_signing_default_evidence",
                "_django_default_authority",
                "_django_selected_consumers_closed",
                "_django_setting_import_closure",
                "_django_setting_import_aliases",
                "_django_setting_import_sites",
                "_django_setting_import_operand",
                "_django_importer_external",
                "_django_import_namespace_unknown",
                "_flask_credential_authority_for_key",
                "_flask_login_session_authority_witness",
                "_flask_credential_authority_witness",
                "_request_client_origin",
                "_direct_httpx_fixture",
                "_closed_fixture_decorator",
                "_client_uses_closed",
                "_cookie_write",
                "_tuple_httpx_fixture",
                "_fixture_app_uses_only_client",
                "tuple_httpx_fixture",
                "request_client_origin",
                "factory_fixture_consumer_status",
                "_factory_fixture_uses",
                "_factory_fixture_consumer_result",
                "_single_factory_fixture_call",
                "public_json_assertion",
                "_json_assertion_operands",
                "_json_detail_name",
                "_json_cast_response",
                "_json_response_name",
                "_json_response_request",
                "_assertion_values",
                "_public_expected_value",
                "_public_enum_member",
                "router_factory_call_published",
                "_router_factory_call_published",
                "_fixture_returns_factory",
                "_factory_fixture_consumers",
                "_fixture_app_consumers_closed",
                "_fixture_app_consumers_closed_uncached",
                "_app_route_lookups_closed",
                "_include_router_options",
                "_route_lookup_only",
                "_local_name_uses",
                "_memo",
                "_app_fixture_consumer_status",
            )
        )
        + (validation_helpers,)
    )


# Consolidated from factoryline/credential_endpoint_evidence.py.


_ISSUER = object()
_IDENTITY = ("code", "path", "line", "column", "severity", "message")


def _endpoint_evidence_digest(value):
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
            (
                _endpoint_evidence_digest(facts),
                _identity(finding),
                tuple(sorted(bindings.items())),
            ),
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


def endpoint_binding(finding, sources, bindings, source_bytes=None):
    """Check native derivation and current publication/source bindings, not safety."""
    if source_bytes is not None:
        try:
            return _captured_endpoint_binding(finding, sources, bindings, source_bytes)
        except (
            AttributeError,
            KeyError,
            TypeError,
            ValueError,
            UnicodeError,
            RecursionError,
        ):
            return False
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
            _endpoint_attestation_matches(
                finding,
                bindings,
                facts,
                digest,
                identity,
                required,
                publication,
                current,
                manifest,
            )
        )
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError):
        return False


def _endpoint_captured_inventory(sources, bindings, source_bytes):
    """Bind a complete canonical byte inventory before any native derivation."""
    if (
        not isinstance(source_bytes, dict)
        or len(source_bytes) > 2000
        or not isinstance(sources, (list, tuple))
        or not isinstance(bindings, dict)
    ):
        return None
    if len(sources) != len(bindings) or set(source_bytes) != set(bindings):
        return None
    captured = {}
    for row in sources:
        bound = _endpoint_captured_source_row(row, bindings, source_bytes)
        if bound is None:
            return None
        path, raw = bound
        captured[path] = raw
    return captured if _source_bindings(Path("."), captured) == bindings else None


def _endpoint_captured_source_row(row, bindings, source_bytes):
    """Validate one canonical source path and its declared byte binding."""
    from .import_context import captured_import_path

    if not isinstance(row, dict):
        return None
    name = row.get("path")
    if not isinstance(name, str):
        return None
    path = Path(name)
    if (
        not captured_import_path(Path("."), path)
        or path.as_posix() != name
        or path.suffix != ".py"
    ):
        return None
    raw = source_bytes.get(name)
    return (
        (path, raw) if _endpoint_captured_source_binding(row, raw, bindings) else None
    )


def _endpoint_captured_source_binding(row, raw, bindings):
    """Require exact producer lengths and hashes; content hashing follows once."""
    return (
        isinstance(raw, bytes)
        and type(row.get("bytes")) is int
        and len(raw) == row["bytes"]
        and len(raw) <= 1_000_000
        and bindings.get(row["path"]) == row.get("sha256")
    )


def _endpoint_captured_claim(finding, facts):
    """Keep copied proof claims at the original native literal-finding identity."""
    return (
        isinstance(facts, dict)
        and isinstance(finding.get("path"), str)
        and isinstance(facts.get("name"), str)
        and finding.get("severity") == "CRITICAL"
        and finding.get("message")
        == "Credential-like material is assigned as a source literal."
        and _endpoint_claim_profile_matches(
            finding, facts, _endpoint_evidence_digest(facts)
        )
    )


def _captured_endpoint_binding(finding, sources, bindings, source_bytes):
    """Regenerate a copied claim from current bytes; supplied facts grant no trust."""
    from . import review_integrity as integrity

    captured = _endpoint_captured_inventory(sources, bindings, source_bytes)
    if captured is None:
        return False
    facts = finding.get("facts", {})
    if not _endpoint_captured_claim(finding, facts):
        return False
    publication = facts.get("publication", {})
    if not isinstance(publication, dict):
        return False
    current = endpoint_publication(publication.get("value"))
    if current is None or current != publication:
        return False
    rows = _workspace_roles(
        Path("."), captured, bindings, integrity, purpose="native-revalidation"
    )
    relative, name = finding.get("path"), facts.get("name")
    row = rows.get((relative, finding.get("line"), name), {})
    if not _admissible(row):
        return False
    node = ast.Constant(
        value=None, lineno=finding.get("line"), col_offset=finding.get("column")
    )
    regenerated = {**finding, "facts": {"name": name}}
    _attach(regenerated, row, current, bindings, relative, node)
    return type(regenerated["facts"]) is _NativeEndpointFacts and dict(
        regenerated["facts"]
    ) == dict(facts)


def endpoint_evidence_helpers():
    """Expose the endpoint evidence digest, identity, native-facts, minting, and binding helpers as one helper tuple."""
    return (
        _endpoint_evidence_digest,
        _identity,
        _NativeEndpointFacts,
        mint_endpoint_facts,
        endpoint_binding,
        _endpoint_claim_profile_matches,
        _endpoint_attestation_matches,
    )


# Consolidated from factoryline/credential_publication_catalog.py.

CATALOG_SHA256 = "280565f7b25821dfe241ea2fb2964f4ec863e2654d4625d662fcc009580b2ec4"


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate metadata key")
        result[key] = value
    return result


def _public_https(value):
    if not isinstance(value, str) or not value or any(c.isspace() for c in value):
        return False
    try:
        value.encode("utf-8", errors="strict")
        url = urlsplit(value)
        url.port
        return bool(
            url.scheme == "https"
            and url.hostname
            and url.username is None
            and url.password is None
            and not url.fragment
            and not url.query
            and "\\" not in value
            and not any(ord(c) < 32 or ord(c) == 127 for c in value)
        )
    except (ValueError, UnicodeError):
        return False


def endpoint_metadata(raw, *, source_url, expected_issuer):
    """Return exact token-endpoint declarations, not authenticity/safety verdicts.

    The caller must independently establish the metadata origin. This pure,
    bounded parser does not fetch URLs, follow redirects, normalize endpoint
    values, grant trust, or decide whether a credential finding is actionable.
    """
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 262144:
        return None
    if not _public_https(expected_issuer) or not _public_https(source_url):
        return None
    issuer = urlsplit(expected_issuer)
    allowed_sources = {
        expected_issuer.rstrip("/") + "/.well-known/openid-configuration",
        f"{issuer.scheme}://{issuer.netloc}/.well-known/oauth-authorization-server"
        + issuer.path.rstrip("/"),
    }
    if source_url not in allowed_sources:
        return None
    try:
        document = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(document, dict) or document.get("issuer") != expected_issuer:
        return None
    endpoint = document.get("token_endpoint")
    if not _public_https(endpoint):
        return None
    return {
        "schema": "factory.protocol-endpoint-declaration.v1",
        "field": "token_endpoint",
        "value": endpoint,
        "value_sha256": hashlib.sha256(endpoint.encode("utf-8")).hexdigest(),
        "issuer": expected_issuer,
        "source_url": source_url,
        "metadata_sha256": hashlib.sha256(raw).hexdigest(),
        "origin_authenticity": "NOT_ESTABLISHED_BY_PARSER",
        "credential_safety": "NOT_ESTABLISHED_BY_PARSER",
    }


def matches_endpoint_declaration(value, declaration, raw):
    """Re-derive every field before exact matching; no prefix/path equivalence."""
    if not isinstance(declaration, dict) or not isinstance(value, str):
        return False
    verified = endpoint_metadata(
        raw,
        source_url=declaration.get("source_url"),
        expected_issuer=declaration.get("issuer"),
    )
    return (
        verified is not None and verified == declaration and value == verified["value"]
    )


def _catalog_digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _entry(row):
    if not isinstance(row, dict):
        return None
    if row.get("document_profile") == "REVIEWED_PROTOCOL_PUBLICATION_V1":
        return _reviewed_entry(row)
    capture = row.get("capture", {})
    document = row.get("document_utf8")
    if not isinstance(document, str):
        return None
    raw = document.encode("utf-8")
    if not (
        capture.get("source_url") == capture.get("final_url")
        and capture.get("status") == 200
        and capture.get("content_type") == "application/json"
        and capture.get("https_profile") == "urllib_default_certificate_verification"
        and capture.get("redirect_policy") == "reject_before_follow"
        and capture.get("bytes") == len(raw)
        and capture.get("raw_sha256") == _catalog_digest(raw)
    ):
        return None
    declaration = _declaration(row, raw, capture.get("source_url"))
    if declaration is None:
        return None
    return {
        **declaration,
        "catalog_sha256": CATALOG_SHA256,
        "capture_sha256": _catalog_digest(
            json.dumps(capture, sort_keys=True, separators=(",", ":")).encode()
        ),
        "publication_basis": "reviewed_packaged_https_capture",
        "credential_safety": "UNASSESSED",
        "runtime_assurance": "INCOMPLETE",
    }


def _reviewed_entry(row):
    fact = reviewed_excerpt_fact(row)
    return {**fact, "catalog_sha256": CATALOG_SHA256} if fact else None


def _declaration(row, raw, source_url):
    profile = row.get("document_profile")
    if profile is None:
        return endpoint_metadata(
            raw, source_url=source_url, expected_issuer=row.get("issuer")
        )
    if profile != "OPENAPI3_OAUTH2_TOKEN_URL_V1":
        return None

    declarations = openapi_endpoint_declarations(raw, source_url=source_url)
    selected = [
        fact
        for fact in declarations or ()
        if fact["json_pointer"] == row.get("json_pointer")
    ]
    return selected[0] if len(selected) == 1 else None


def _read(raw):
    if (
        not isinstance(raw, bytes)
        or len(raw) > 1048576
        or _catalog_digest(raw) != CATALOG_SHA256
    ):
        return ()
    try:
        catalog = json.loads(raw, object_pairs_hook=_unique_object)
        if catalog.get("schema") != "factory.protocol-publication-catalog.v1":
            return ()
        rows = catalog.get("entries")
        if not isinstance(rows, list) or not 0 < len(rows) <= 128:
            return ()
        facts = [_entry(row) for row in rows]
        if any(fact is None for fact in facts):
            return ()
        return tuple(facts)
    except (ValueError, UnicodeError, TypeError, RecursionError):
        return ()


def _catalog_bytes():
    try:
        resource = resources.files("factoryline").joinpath(
            "data/protocol_publications.json"
        )
        with resource.open("rb") as stream:
            raw = stream.read(1048577)
    except (OSError, ValueError):
        return None
    return raw


def catalog_content_digest():
    """Fresh data identity for native context caches, including corrupt/missing data."""
    raw = _catalog_bytes()
    return _catalog_digest(raw) if raw is not None else "MISSING"


def endpoint_publications():
    """Read one immutable historical publication snapshot; never a safety verdict."""
    from types import MappingProxyType

    return tuple(MappingProxyType(fact) for fact in _read(_catalog_bytes()))


def endpoint_publication(value):
    """Exact published endpoint equality; no prefix/template or safety verdict."""
    if not isinstance(value, str):
        return None
    matches = [fact for fact in endpoint_publications() if fact["value"] == value]
    return dict(matches[0]) if len(matches) == 1 else None


# Consolidated from factoryline/credential_publication_excerpt.py.

PROFILE = "REVIEWED_PROTOCOL_PUBLICATION_V1"


def digest(value):
    """Compute a stable SHA-256 digest for JSON-compatible evidence using sorted keys and compact separators."""
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


def _sha(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _excerpt_https(value):
    return _public_https(value) and not any(c in value for c in "?#")


def _excerpt_valid(excerpt, value, capture):
    if (
        not isinstance(excerpt, dict)
        or excerpt.get("profile") != "RAW_UTF8_BYTE_RANGE_V1"
    ):
        return False
    quote = excerpt.get("quote_utf8")
    if not isinstance(quote, str) or value not in quote:
        return False
    try:
        raw = quote.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    offset, count = excerpt.get("offset"), capture.get("bytes")
    return bool(
        0 < len(raw) <= 8192
        and type(offset) is int
        and offset >= 0
        and type(count) is int
        and 0 < count <= 8 * 1024 * 1024
        and offset + len(raw) <= count
        and excerpt.get("bytes") == len(raw)
        and excerpt.get("sha256") == hashlib.sha256(raw).hexdigest()
    )


def reviewed_excerpt_fact(row):
    """Read a historical review assertion, requiring the caller's catalog pin.

    This cannot rederive a quotation from an omitted full document or establish
    publisher authenticity. Only the reviewed source/data change admitting the
    exact pinned catalog supplies that trust. An unpinned row grants no credit.
    """
    if not isinstance(row, dict) or row.get("document_profile") != PROFILE:
        return None
    value, capture, review = (row.get("value"), row.get("capture"), row.get("review"))
    if (
        not _excerpt_https(value)
        or not isinstance(capture, dict)
        or (not isinstance(review, dict))
    ):
        return None
    source = capture.get("source_url")
    if not _reviewed_capture_matches(capture, source):
        return None
    if not _excerpt_valid(row.get("excerpt"), value, capture):
        return None
    parsed = urlsplit(source)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    payload = {key: val for key, val in row.items() if key != "review"}
    if not _reviewed_publication_matches(review, origin, payload):
        return None
    return {
        "schema": "factory.protocol-endpoint-declaration.v1",
        "document_profile": PROFILE,
        "field": "reviewed_protocol_endpoint",
        "value": value,
        "value_sha256": hashlib.sha256(value.encode()).hexdigest(),
        "source_url": source,
        "metadata_sha256": capture["raw_sha256"],
        "review_sha256": review["review_sha256"],
        "fact_sha256": review["fact_sha256"],
        "publication_basis": "reviewed_historical_publication_excerpt",
        "raw_document_rederived_at_runtime": False,
        "credential_safety": "UNASSESSED",
        "runtime_assurance": "INCOMPLETE",
    }


# Consolidated from factoryline/credential_protocol_documents.py.


MAX_DOCUMENT_BYTES = 1_048_576
MAX_DOCUMENT_NODES = 50_000
MAX_DOCUMENT_DEPTH = 48
MAX_DECLARATIONS = 128
_FLOWS = frozenset({"authorizationCode", "clientCredentials", "password"})


def _invalid_constant(value):
    raise ValueError("nonstandard JSON constant")


def _protocol_https(value):
    return (
        _public_https(value)
        and not any(c in value for c in "?#")
        and not re.search(r"%(?![0-9a-fA-F]{2})", value)
    )


def _document(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_DOCUMENT_BYTES:
        return None
    try:
        document = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        )
    except (ValueError, UnicodeError, RecursionError):
        return None
    pending, count = [(document, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if count > MAX_DOCUMENT_NODES or depth > MAX_DOCUMENT_DEPTH:
            return None
        if isinstance(value, dict):
            pending.extend(
                (child, depth + 1) for pair in value.items() for child in pair
            )
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)
        elif isinstance(value, str):
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeError:
                return None
    return document if isinstance(document, dict) else None


def _flow_rows(name, scheme):
    if not isinstance(scheme, dict) or "$ref" in scheme:
        return None
    if scheme.get("type") != "oauth2":
        return []
    flows = scheme.get("flows")
    if not isinstance(flows, dict) or not flows:
        return None
    rows = []
    for flow_name, flow in flows.items():
        if not _valid_flow(flow_name, flow):
            return None
        if flow_name != "implicit":
            rows.append((name, flow_name, flow["tokenUrl"]))
    return rows


def _valid_flow(name, flow):
    if name not in _FLOWS | {"implicit"} or not isinstance(flow, dict):
        return False
    scopes = flow.get("scopes")
    if "$ref" in flow or not isinstance(scopes, dict):
        return False
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in scopes.items()):
        return False
    if name in {"authorizationCode", "implicit"} and not _protocol_https(
        flow.get("authorizationUrl")
    ):
        return False
    if name == "implicit":
        return "tokenUrl" not in flow
    return bool(_protocol_https(flow.get("tokenUrl")))


def openapi_endpoint_declarations(raw, *, source_url):
    """Read OpenAPI 3 OAuth tokenUrl facts; never fetch, admit, or clear alerts.

    The caller must establish publisher identity and independently admit the
    complete captured document. Source URL validity alone grants no trust.
    Relative URLs and references are deliberately unsupported, not resolved.
    """
    if not _protocol_https(source_url):
        return None
    rows = _openapi_token_url_rows(raw)
    if rows is None:
        return None
    digest = hashlib.sha256(raw).hexdigest()
    return _openapi_declaration_records(rows, source_url, digest)


def _openapi_token_url_rows(raw):
    document = _document(raw)
    schemes = _openapi_security_schemes(document)
    if schemes is None:
        return None
    return _openapi_scheme_rows(schemes)


def _openapi_security_schemes(document):
    if document is None:
        return None
    version = document.get("openapi")
    if not isinstance(version, str) or not re.fullmatch(r"3\.[01]\.[0-9]+", version):
        return None
    components = document.get("components")
    if not isinstance(components, dict) or "$ref" in components:
        return None
    schemes = components.get("securitySchemes")
    return (
        schemes
        if isinstance(schemes, dict) and schemes and len(schemes) <= 128
        else None
    )


def _openapi_scheme_rows(schemes):
    rows = []
    for name, scheme in schemes.items():
        extracted = _flow_rows(name, scheme)
        if extracted is None:
            return None
        rows.extend(extracted)
        if len(rows) > MAX_DECLARATIONS:
            return None
    return rows


def _openapi_declaration_records(rows, source_url, digest):
    return tuple(
        {
            "schema": "factory.protocol-endpoint-declaration.v1",
            "document_profile": "OPENAPI3_OAUTH2_TOKEN_URL_V1",
            "json_pointer": "/components/securitySchemes/"
            + name.replace("~", "~0").replace("/", "~1")
            + "/flows/"
            + flow
            + "/tokenUrl",
            "field": "tokenUrl",
            "value": endpoint,
            "value_sha256": hashlib.sha256(endpoint.encode("utf-8")).hexdigest(),
            "source_url": source_url,
            "metadata_sha256": digest,
            "security_scheme": name,
            "flow": flow,
            "origin_authenticity": "NOT_ESTABLISHED_BY_PARSER",
            "credential_safety": "NOT_ESTABLISHED_BY_PARSER",
        }
        for name, flow, endpoint in rows
    )


def matches_openapi_endpoint(value, declaration, raw):
    """Rederive the complete fact from exact document bytes before equality."""
    if not isinstance(declaration, dict) or not isinstance(value, str):
        return False
    rows = openapi_endpoint_declarations(raw, source_url=declaration.get("source_url"))
    return rows is not None and any(
        row == declaration and row["value"] == value for row in rows
    )


# Consolidated from factoryline/credential_httpx_origins.py.


_HTTPX_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


def _request_client_origin(graph, path, function, request):
    name = request.value.func.value.id
    if any(
        arg.arg == name
        for arg in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
    ):
        return _direct_httpx_fixture(graph, path, function, name, request)
    writes = [
        node
        for node in graph._walk(function)
        if isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    if len(writes) != 1 or isinstance(writes[0].ctx, ast.Del):
        return False
    assignment = graph.parents.get(id(writes[0]))
    if not isinstance(assignment, ast.Tuple) and not isinstance(assignment, ast.List):
        return False
    owner = graph.parents.get(id(assignment))
    if (
        not isinstance(owner, ast.Assign)
        or len(owner.targets) != 1
        or owner.targets[0] is not assignment
        or not isinstance(owner.value, ast.Name)
    ):
        return False
    fixture_name = owner.value.id
    leaves = assignment.elts
    if (
        not leaves
        or leaves[0] is not writes[0]
        or any(not isinstance(leaf, ast.Name) for leaf in leaves)
    ):
        return False
    from .credential_role_constructor_provider import binding_dominates

    if not binding_dominates(owner, request, graph.parents, function):
        return False
    fixture = graph._nearest_fixture(path, fixture_name, function)
    return bool(
        fixture
        and _tuple_httpx_fixture(graph, fixture[0], fixture[1], owner.value)
        and _client_uses_closed(graph, function, name, request)
    )


def _direct_httpx_fixture(graph, path, function, name, request):
    if any(name in graph.audit._bound_names(statement) for statement in function.body):
        return False
    fixture = graph._nearest_fixture(path, name, function)
    if not fixture or not _closed_fixture_decorator(graph, fixture[0], fixture[1]):
        return False
    loops = [
        node
        for node in fixture[1].body
        if isinstance(node, ast.AsyncFor)
        and isinstance(node.iter, ast.Call)
        and isinstance(node.iter.func, ast.Name)
        and len(node.iter.args) == 1
        and isinstance(node.iter.args[0], ast.Name)
        and isinstance(node.target, ast.Name)
    ]
    return bool(
        len(loops) == 1
        and graph._test_client_fixture(
            fixture[0], fixture[1], loops[0].iter.args[0].id, loops[0].target.id
        )
        and _client_uses_closed(graph, function, name, request)
    )


def _closed_fixture_decorator(graph, path, fixture):
    if graph._is_pytest_fixture(path, fixture):
        return True
    if len(fixture.decorator_list) != 1:
        return False
    decorator = fixture.decorator_list[0]
    if not isinstance(decorator, ast.Call) or decorator.args:
        return False
    if graph.audit._resolved_ast_name(decorator.func, graph.aliases[path]) not in {
        "pytest.fixture",
        "pytest_asyncio.fixture",
    }:
        return False
    keywords = {item.arg: item.value for item in decorator.keywords}
    if set(keywords) != {"params", "ids"}:
        return False
    params, ids = keywords["params"], keywords["ids"]
    return bool(
        isinstance(params, ast.List)
        and params.elts
        and all(
            isinstance(item, ast.Constant)
            and type(item.value) in {str, int, bool, type(None)}
            for item in params.elts
        )
        and isinstance(ids, ast.List)
        and len(ids.elts) == len(params.elts)
        and all(
            isinstance(item, ast.Constant) and type(item.value) is str
            for item in ids.elts
        )
        and graph._provider_is_unmodified("pytest", {"fixture"})
    )


def _client_uses_closed(graph, function, name, request):
    for node in graph._walk(function):
        if not isinstance(node, ast.Name) or node.id != name:
            continue
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            continue
        attr = graph.parents.get(id(node))
        if isinstance(attr, ast.Attribute) and attr.value is node:
            call = graph.parents.get(id(attr))
            if (
                isinstance(call, ast.Call)
                and call.func is attr
                and attr.attr in _HTTPX_METHODS
                and call is request.value
            ):
                continue
            if _cookie_write(graph, node, attr):
                continue
        return False
    return True


def _cookie_write(graph, name, attribute):
    cookies = attribute
    setter = graph.parents.get(id(cookies))
    call = graph.parents.get(id(setter))
    return bool(
        isinstance(cookies, ast.Attribute)
        and cookies.value is name
        and cookies.attr == "cookies"
        and isinstance(setter, ast.Attribute)
        and setter.value is cookies
        and setter.attr == "set"
        and isinstance(call, ast.Call)
        and call.func is setter
        and call.args
        and all(isinstance(arg, ast.Constant) for arg in call.args)
        and not call.keywords
    )


def _tuple_httpx_fixture(graph, path, fixture, fixture_parameter):
    if not _closed_fixture_decorator(graph, path, fixture):
        return False
    loops = [
        node
        for node in fixture.body
        if isinstance(node, ast.AsyncFor)
        and isinstance(node.target, ast.Name)
        and isinstance(node.iter, ast.Call)
        and isinstance(node.iter.func, ast.Name)
        and node.iter.args
        and isinstance(node.iter.args[0], ast.Name)
    ]
    if len(loops) != 1:
        return False
    loop = loops[0]
    if (
        len(loop.body) != 1
        or not isinstance(loop.body[0], ast.Expr)
        or not isinstance(loop.body[0].value, ast.Yield)
        or not isinstance(loop.body[0].value.value, ast.Tuple)
        or not loop.body[0].value.value.elts
        or not isinstance(loop.body[0].value.value.elts[0], ast.Name)
        or loop.body[0].value.value.elts[0].id != loop.target.id
        or loop.iter.args[0].id != "app"
        or not isinstance(fixture_parameter, ast.Name)
        or not any(arg.arg == loop.iter.func.id for arg in fixture.args.args)
        or not isinstance(loop.iter.func, ast.Name)
    ):
        return False
    # The remaining tuple fields must be constants or pytest parameter echoes.
    for item in loop.body[0].value.value.elts[1:]:
        if isinstance(item, ast.Constant):
            continue
        if not isinstance(item, ast.Name):
            return False
        binding = graph._unique_name_assignment(fixture, item.id)
        if not isinstance(binding, ast.Assign) or not isinstance(
            binding.value, ast.Attribute
        ):
            return False
        if binding.value.attr != "param" or not isinstance(
            binding.value.value, ast.Name
        ):
            return False
    origin = graph._nearest_fixture(path, loop.iter.func.id)
    return bool(
        origin
        and graph._returned_httpx_client(*origin)
        and _fixture_app_uses_only_client(graph, fixture, loop)
    )


def _fixture_app_uses_only_client(graph, fixture, loop):
    app = loop.iter.args[0]
    bindings = [
        node
        for node in fixture.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(app, ast.Name)
        and node.targets[0].id == app.id
    ]
    return bool(
        len(bindings) == 1
        and isinstance(app, ast.Name)
        and graph._unique_name_assignment(fixture, app.id) is bindings[0]
        and all(
            not isinstance(node, ast.Name)
            or node.id != app.id
            or node in {bindings[0].targets[0], app}
            or graph.parents.get(id(node)) in {bindings[0], loop.iter}
            for node in graph._walk(fixture)
        )
    )


tuple_httpx_fixture = _tuple_httpx_fixture
request_client_origin = _request_client_origin


def factory_fixture_consumer_status(
    graph, path, fixture, source, caller, app_consumers_closed, route_lookup_only
):
    """Classify a fixture consumer only when its binding and use shape are closed; return false for unsupported local use and None when ownership is unknown."""
    if not isinstance(caller, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    uses = _factory_fixture_uses(graph, source, path, fixture, caller)
    if uses is None:
        return None
    if uses is False:
        return False
    return _factory_fixture_consumer_result(
        graph,
        path,
        fixture,
        source,
        caller,
        uses,
        app_consumers_closed,
        route_lookup_only,
    )


def _factory_fixture_uses(graph, source, path, fixture, caller):
    parameters = [
        arg.arg
        for arg in (
            *caller.args.posonlyargs,
            *caller.args.args,
            *caller.args.kwonlyargs,
        )
    ]
    if fixture.name not in parameters:
        return None
    if graph._nearest_fixture(source, fixture.name, caller) != (path, fixture):
        return False if source == path else None
    return [
        node
        for node in graph._walk(caller)
        if isinstance(node, ast.Name) and node.id == fixture.name
    ]


def _factory_fixture_consumer_result(
    graph, path, fixture, source, caller, uses, app_consumers_closed, route_lookup_only
):
    call = _single_factory_fixture_call(graph, fixture, uses)
    if call is None:
        return False
    parent = graph.parents.get(id(call))
    if isinstance(parent, ast.Return) and parent.value is call:
        return bool(
            graph._is_pytest_fixture(source, caller)
            and app_consumers_closed(graph, source, caller)
        )
    if route_lookup_only(graph, source, caller, call):
        return True
    if (
        isinstance(parent, ast.Assign)
        and len(parent.targets) == 1
        and isinstance(parent.targets[0], ast.Name)
    ):
        return bool(tuple_httpx_fixture(graph, source, caller, parent.targets[0]))
    return False


def _single_factory_fixture_call(graph, fixture, uses):
    if not uses or not all(
        isinstance(graph.parents.get(id(node)), ast.Call)
        and graph.parents[id(node)].func is node
        for node in uses
    ):
        return None
    calls = [graph.parents[id(node)] for node in uses]
    if len(calls) != 1:
        return None
    return calls[0]


# Consolidated from factoryline/credential_json_assertions.py.


_JSON_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


def public_json_assertion(graph, path, node, parent):
    """Accept only a source-bound JSON comparison dominated by its request."""
    from .credential_role_constructor_provider import binding_dominates

    operands = _json_assertion_operands(graph, node, parent)
    if operands is None:
        return False
    container, assertion, projection = operands
    function = graph._containing_function(assertion)
    if not isinstance(assertion, ast.Assert) or function is None:
        return False
    data_name = _json_detail_name(projection)
    if data_name is None:
        return False
    assignment = graph._unique_name_assignment(function, data_name)
    response_call = _json_cast_response(
        graph, path, assignment, assertion, function, binding_dominates
    )
    response_name = _json_response_name(response_call)
    if response_name is None:
        return False
    request = _json_response_request(
        graph, function, response_name, assignment, binding_dominates
    )
    if request is None:
        return False
    return (
        request_client_origin(graph, path, function, request)
        and graph._provider_is_unmodified("typing", {"cast"})
        and _assertion_values(
            graph, path, function, container, data_name, response_name
        )
    )


def _json_assertion_operands(graph, node, parent):
    """Find the expected JSON value and its single equality comparison."""
    container = node
    while isinstance(parent, (ast.Dict, ast.List, ast.Tuple)):
        container = parent
        parent = graph.parents.get(id(parent))
    if (
        not isinstance(container, (ast.Dict, ast.Attribute))
        or not isinstance(parent, ast.Compare)
        or len(parent.ops) != 1
        or not isinstance(parent.ops[0], ast.Eq)
        or len(parent.comparators) != 1
    ):
        return None
    projection = parent.comparators[0] if parent.left is container else parent.left
    if projection is container:
        return None
    assertion = graph.parents.get(id(parent))
    return container, assertion, projection


def _json_detail_name(projection):
    """Resolve the exact local name behind a literal detail projection."""
    if (
        not isinstance(projection, ast.Subscript)
        or not isinstance(projection.value, ast.Name)
        or not isinstance(projection.slice, ast.Constant)
        or projection.slice.value != "detail"
    ):
        return None
    return projection.value.id


def _json_cast_response(
    graph, path, assignment, assertion, function, binding_dominates
):
    """Require the dominating typing.cast assignment before reading its input."""
    if (
        not isinstance(assignment, ast.Assign)
        or not isinstance(assignment.value, ast.Call)
        or graph.audit._resolved_ast_name(assignment.value.func, graph.aliases[path])
        != "typing.cast"
        or len(assignment.value.args) != 2
        or assignment.value.keywords
        or not binding_dominates(assignment, assertion, graph.parents, function)
    ):
        return None
    return assignment.value.args[1]


def _json_response_name(response_call):
    """Accept only a zero-argument response.json call on one local name."""
    if (
        not isinstance(response_call, ast.Call)
        or not isinstance(response_call.func, ast.Attribute)
        or response_call.func.attr != "json"
        or response_call.args
        or response_call.keywords
        or not isinstance(response_call.func.value, ast.Name)
    ):
        return None
    return response_call.func.value.id


def _json_response_request(
    graph, function, response_name, assignment, binding_dominates
):
    """Bind response creation to an earlier awaited HTTP-method call."""
    response_assignment = graph._unique_name_assignment(function, response_name)
    request = (
        response_assignment.value
        if isinstance(response_assignment, ast.Assign)
        else None
    )
    if (
        not isinstance(response_assignment, ast.Assign)
        or not binding_dominates(
            response_assignment, assignment, graph.parents, function
        )
        or not isinstance(request, ast.Await)
        or not isinstance(request.value, ast.Call)
        or not isinstance(request.value.func, ast.Attribute)
        or request.value.func.attr not in _JSON_HTTP_METHODS
        or not isinstance(request.value.func.value, ast.Name)
    ):
        return None
    return request


def _assertion_values(graph, path, function, expected, data_name, response_name):
    names = [
        node
        for node in graph._walk(function)
        if isinstance(node, ast.Name) and node.id in {data_name, response_name}
    ]
    if (
        sum(node.id == data_name and isinstance(node.ctx, ast.Load) for node in names)
        != 1
    ):
        return False
    responses = [
        node
        for node in names
        if node.id == response_name and isinstance(node.ctx, ast.Load)
    ]
    if not responses:
        return False
    for node in responses:
        attribute = graph.parents.get(id(node))
        parent = graph.parents.get(id(attribute))
        if not isinstance(attribute, ast.Attribute) or attribute.value is not node:
            return False
        if attribute.attr == "json":
            if (
                not isinstance(parent, ast.Call)
                or parent.func is not attribute
                or parent.args
                or parent.keywords
            ):
                return False
        elif attribute.attr != "status_code" or isinstance(parent, ast.Call):
            return False
    if isinstance(expected, ast.Attribute):
        return _public_enum_member(graph, path, expected)
    return isinstance(expected, ast.Dict) and all(
        isinstance(key, ast.Constant)
        and type(key.value) is str
        and _public_expected_value(graph, path, value)
        for key, value in zip(expected.keys, expected.values)
    )


def _public_expected_value(graph, path, value):
    if isinstance(value, ast.Constant):
        return type(value.value) in {str, int, bool, type(None)}
    return isinstance(value, ast.Attribute) and _public_enum_member(graph, path, value)


def _public_enum_member(graph, path, value):
    if graph._json_expected_member(path, ast.Constant("detail"), value):
        return True
    origin = graph.resolve(path, tuple(graph.audit._name(value).split(".")))
    resolved_bases = []
    if origin and origin[0] == "class":
        owner = graph.objects.get(origin[1:3])
        if isinstance(owner, ast.ClassDef):
            resolved_bases = [
                graph.audit._resolved_ast_name(base, graph.aliases[path])
                for base in owner.bases
            ]
            resolved_bases = [
                graph.aliases[path].get(base, base) for base in resolved_bases
            ]
    if not origin or origin[0] != "class" or len(origin[3]) != 1:
        return False
    owner = graph.objects.get(origin[1:3])
    if (
        not isinstance(owner, ast.ClassDef)
        or owner.decorator_list
        or owner.keywords
        or resolved_bases != ["str", "enum.Enum"]
        or not graph._provider_is_unmodified("enum", {"Enum"})
    ):
        return False
    members = {}
    for statement in owner.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            return False
        target = statement.targets[0]
        if not isinstance(target, ast.Name) or not isinstance(
            statement.value, ast.Constant
        ):
            return False
        if type(statement.value.value) is not str or statement.value.value != target.id:
            return False
        members[target.id] = statement
    return origin[3][0] in members


# Consolidated from factoryline/credential_router_publication.py.


def router_factory_call_published(graph, path, call):
    """Close a router factory published through an exact pytest app factory."""
    return _memo(
        graph,
        "_credential_router_publication_cache",
        (path, id(call)),
        lambda: _router_factory_call_published(graph, path, call),
    )


def _router_factory_call_published(graph, path, call):
    parent = graph.parents.get(id(call))
    scope = getattr(call, "_security_lexical_scope", None)
    if (
        not isinstance(parent, ast.Assign)
        or len(parent.targets) != 1
        or not isinstance(parent.targets[0], ast.Name)
        or parent.value is not call
        or not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
    ):
        return False
    alias = parent.targets[0]
    if graph._unique_name_assignment(scope, alias.id) is not parent:
        return False
    fixture = graph.parents.get(id(scope))
    if (
        not isinstance(fixture, (ast.FunctionDef, ast.AsyncFunctionDef))
        or scope not in fixture.body
        or not graph._is_pytest_fixture(path, fixture)
        or scope.decorator_list
        or not _fixture_returns_factory(graph, fixture, scope)
    ):
        return False
    app_assignments = [
        node
        for node in scope.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.Call)
        and graph.integrity.security_call_name(node.value, graph.aliases[path])
        == "fastapi.FastAPI"
        and not node.value.args
        and not node.value.keywords
    ]
    returns = [node for node in scope.body if isinstance(node, ast.Return)]
    if len(app_assignments) != 1 or len(returns) != 1:
        return False
    app = app_assignments[0].targets[0]
    includes = [
        node
        for node in scope.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
        and node.value.func.attr == "include_router"
        and isinstance(node.value.func.value, ast.Name)
        and node.value.func.value.id == app.id
        and len(node.value.args) == 1
        and isinstance(node.value.args[0], ast.Name)
        and _include_router_options(node.value)
        and graph._provider_is_unmodified("fastapi", {"FastAPI"})
    ]
    published = [node for node in includes if node.value.args[0].id == alias.id]
    if (
        not isinstance(returns[0].value, ast.Name)
        or returns[0].value.id != app.id
        or graph._unique_name_assignment(scope, app.id) is not app_assignments[0]
        or not includes
        or len(published) != 1
    ):
        return False
    if not _local_name_uses(
        graph, scope, alias, {parent.targets[0], published[0].value.args[0]}
    ):
        return False
    if not _local_name_uses(
        graph,
        scope,
        app,
        {
            app_assignments[0].targets[0],
            *(node.value.func.value for node in includes),
            returns[0].value,
        },
    ):
        return False
    return _memo(
        graph,
        "_credential_app_factory_consumers_cache",
        (path, id(fixture)),
        lambda: _factory_fixture_consumers(graph, path, fixture),
    )


def _fixture_returns_factory(graph, fixture, factory):
    body = [
        node
        for node in fixture.body
        if not (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
    ]
    return (
        len(body) == 2
        and body[0] is factory
        and isinstance(body[1], ast.Return)
        and body[1].value is not None
        and isinstance(body[1].value, ast.Name)
        and body[1].value.id == factory.name
    )


def _factory_fixture_consumers(graph, path, fixture):
    found = False
    for source, tree in graph.trees.items():
        for caller in graph._walk(tree):
            status = factory_fixture_consumer_status(
                graph,
                path,
                fixture,
                source,
                caller,
                _fixture_app_consumers_closed,
                _route_lookup_only,
            )
            if status is False:
                return False
            found = found or status is True
    return found


def _fixture_app_consumers_closed(graph, path, fixture):
    return _memo(
        graph,
        "_credential_app_fixture_consumers_cache",
        (path, id(fixture)),
        lambda: _fixture_app_consumers_closed_uncached(graph, path, fixture),
    )


def _fixture_app_consumers_closed_uncached(graph, path, fixture):
    consumers = 0
    for source, tree in graph.trees.items():
        for caller in graph._walk(tree):
            status = _app_fixture_consumer_status(graph, path, fixture, source, caller)
            if status is False:
                return False
            consumers += status is True
    return consumers == 0 or consumers > 0


def _app_route_lookups_closed(graph, path, caller, parameter):
    relative = path.relative_to(graph.root)
    if "tests" not in relative.parts or not caller.name.startswith("test_"):
        return False
    uses = [
        node
        for node in graph._walk(caller)
        if isinstance(node, ast.Name) and node.id == parameter
    ]
    return bool(uses) and all(
        isinstance(node.ctx, ast.Load)
        and isinstance(graph.parents.get(id(node)), ast.Attribute)
        and graph.parents[id(node)].value is node
        and graph.parents[id(node)].attr == "url_path_for"
        and isinstance(graph.parents.get(id(graph.parents[id(node)])), ast.Call)
        and graph.parents[id(graph.parents[id(node)])].func is graph.parents[id(node)]
        for node in uses
    )


def _include_router_options(call):
    if len(call.args) != 1:
        return False
    return all(
        keyword.arg == "prefix"
        and isinstance(keyword.value, ast.Constant)
        and type(keyword.value.value) is str
        for keyword in call.keywords
    )


def _route_lookup_only(graph, path, caller, call):
    relative = path.relative_to(graph.root)
    method = graph.parents.get(id(call))
    outer = graph.parents.get(id(method))
    return bool(
        "tests" in relative.parts
        and caller.name.startswith("test_")
        and isinstance(method, ast.Attribute)
        and method.value is call
        and method.attr == "url_path_for"
        and isinstance(outer, ast.Call)
        and outer.func is method
        and outer.args
        and isinstance(outer.args[0], ast.Constant)
        and type(outer.args[0].value) is str
        and all(
            isinstance(value, ast.Constant)
            or isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Name)
            for value in [*outer.args[1:], *(kw.value for kw in outer.keywords)]
        )
    )


def _local_name_uses(graph, scope, target, allowed):
    return all(
        node in allowed
        for node in graph._walk(scope)
        if isinstance(node, ast.Name) and node.id == target.id
    )


def _memo(graph, attribute, key, compute):
    cache = getattr(graph, attribute, None)
    if cache is None:
        cache = {}
        setattr(graph, attribute, cache)
    if key in cache:
        return cache[key]
    result = compute()
    if graph.complete:
        cache[key] = result
    return result


def _app_fixture_consumer_status(graph, path, fixture, source, caller):
    if not isinstance(caller, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    parameters = [
        arg.arg
        for arg in (
            *caller.args.posonlyargs,
            *caller.args.args,
            *caller.args.kwonlyargs,
        )
        if arg.arg == fixture.name
    ]
    if not parameters:
        return None
    origin = graph._nearest_fixture(source, fixture.name, caller)
    if origin is None:
        return False if source == path else None
    if origin != (path, fixture):
        return None
    return bool(
        len(parameters) == 1
        and (
            graph._app_client_consumer(source, caller, parameters[0])
            or graph._app_openapi_consumer(source, caller, parameters[0])
            or _app_route_lookups_closed(graph, source, caller, parameters[0])
        )
    )


# Consolidated from factoryline/credential_session_forwarding.py.


def _span(node):
    return [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset]


def _hop(path, node, kind, index):
    return {
        "path": index.relative(path),
        "source_sha256": hashlib.sha256(index.source_bytes[path]).hexdigest(),
        "span": _span(node),
        "kind": kind,
    }


def _body(function):
    body = list(function.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
    ):
        if isinstance(body[0].value.value, str):
            body.pop(0)
    while body and isinstance(body[0], (ast.Import, ast.ImportFrom)):
        body.pop(0)
    return body


def _construction(statement, aliases):
    from .security_configuration import _canonical

    if not (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and isinstance(statement.value, ast.Call)
        and not statement.value.args
        and not statement.value.keywords
        and _canonical(statement.value, aliases) == "requests.Session"
    ):
        return None
    return statement.targets[0].id


def _request_attribute(node, receiver):
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "request"
        and isinstance(node.value, ast.Name)
        and node.value.id == receiver
    )


def _timeout_forwarder(statement, receiver, aliases):
    from .security_configuration import _canonical

    if not (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and _request_attribute(statement.targets[0], receiver)
        and isinstance(statement.value, ast.Call)
    ):
        return False
    call = statement.value
    return bool(
        _canonical(call, aliases) == "functools.partial"
        and len(call.args) == 1
        and _request_attribute(call.args[0], receiver)
        and len(call.keywords) == 1
        and call.keywords[0].arg == "timeout"
        and isinstance(call.keywords[0].value, (ast.Constant, ast.Name, ast.Attribute))
    )


def _forwarder_provider_uncertain(tree, statement, aliases):
    from .review_integrity import _security_flow_bindings
    from .semantic_credential_sensor import _provider_identity_uncertain

    resolved, _ = _security_flow_bindings(statement.value, aliases)
    return _provider_identity_uncertain(tree, resolved, roots=("functools",))


def _factory_owner_valid(path, function, index):
    if not index.validate(path) or not isinstance(function, ast.FunctionDef):
        return False
    if function.decorator_list or id(function) not in index.parents[path]:
        return False
    owner = index.parents[path][id(function)]
    if not isinstance(owner, (ast.Module, ast.ClassDef)):
        return False
    if isinstance(owner, ast.ClassDef) and (owner.decorator_list or owner.keywords):
        return False
    from . import review_audits as audit
    from .credential_role_constructor_provider import _class_bindings

    bindings = [
        statement
        for statement in owner.body
        if _class_bindings(statement, audit) & {function.name, "*"}
    ]
    if bindings != [function]:
        return False
    return True


def session_factory_witness(path, function, index, aliases):
    """Summarize a declared factory; never assert runtime adapter/provider identity."""
    from .review_integrity import bind_security_call_scopes, _security_flow_bindings
    from .semantic_credential_sensor import _provider_identity_uncertain

    if not _factory_owner_valid(path, function, index):
        return None
    tree = index.snapshots[path]
    if not hasattr(tree, "_security_scope_kind"):
        bind_security_call_scopes(tree)
    body = _body(function)
    receiver, returned = _session_factory_receiver(
        body, tree, aliases, _security_flow_bindings, _provider_identity_uncertain
    )
    if receiver is None or returned is None:
        return None
    return _session_factory_witness_rows(
        path, function, index, body, receiver, returned, tree, aliases
    )


def _session_factory_receiver(
    body, tree, aliases, security_flow_bindings, provider_identity_uncertain
):
    if len(body) not in {2, 3}:
        return None, None
    receiver = _construction(body[0], aliases)
    if receiver is None:
        return None, None
    resolved, _ = security_flow_bindings(body[0].value, aliases)
    if provider_identity_uncertain(tree, resolved):
        return None, None
    returned = body[-1]
    if not (
        receiver
        and isinstance(returned, ast.Return)
        and isinstance(returned.value, ast.Name)
        and returned.value.id == receiver
    ):
        return None, None
    return receiver, returned


def _session_factory_witness_rows(
    path, function, index, body, receiver, returned, tree, aliases
):
    hops = [
        _hop(path, function, "declared_session_factory", index),
        _hop(path, body[0], "canonical_session_construction", index),
    ]
    if len(body) == 3:
        if not _timeout_forwarder(
            body[1], receiver, aliases
        ) or _forwarder_provider_uncertain(tree, body[1], aliases):
            return None
        hops.append(_hop(path, body[1], "timeout_only_request_forwarding", index))
    hops.append(_hop(path, returned, "factory_return", index))
    return {
        "provider": "requests.Session",
        "profile": "DECLARED_FACTORY_MAY_FLOW",
        "preserved_slots": ["method", "url", "auth", "headers"],
        "runtime_provider_identity": "UNASSESSED",
        "runtime_factory_dispatch": "UNASSESSED",
        "hops": hops,
    }


def _endpoint_claim_profile_matches(finding, facts, digest):
    """Validate the original ordered claim profile and mutation-evident facts digest."""
    return (
        finding.get("code") == "SECURITY_HARDCODED_SECRET"
        and facts.get("schema") == "factory.public-protocol-endpoint.v1"
        and (facts.get("disposition") == "ENDPOINT_DECLARATION_ROLE_PROVEN")
        and (facts.get("flow_profile") == "DECLARED_CLASS_MAY_FLOW")
        and (facts.get("runtime_assurance") == "INCOMPLETE")
        and (facts.get("credential_safety") == "UNASSESSED")
        and (facts.get("known_auth_uses") == [])
        and (facts.get("linked_unknown_uses") == [])
        and (digest == _endpoint_evidence_digest(facts))
    )


def _endpoint_attestation_matches(
    finding, bindings, facts, digest, identity, required, publication, current, manifest
):
    """Validate the original endpoint attestation and bound source manifest."""
    return (
        _endpoint_claim_profile_matches(finding, facts, digest)
        and identity == _identity(finding)
        and (current is not None)
        and (publication == current)
        and (
            facts.get("workspace_sources_sha256")
            == _endpoint_evidence_digest(sorted(manifest))
        )
        and required
        and all(
            (
                bindings.get(path) == sha and dict(manifest).get(path) == sha
                for path, sha in required
            )
        )
        and (facts.get("source_path") == finding.get("path"))
        and ((facts.get("source_path"), facts.get("source_sha256")) in required)
    )


def _reviewed_capture_matches(capture, source):
    """Validate the original reviewed HTTPS capture fields in evaluation order."""
    return (
        _excerpt_https(source)
        and source == capture.get("final_url")
        and (capture.get("status") == 200)
        and _sha(capture.get("raw_sha256"))
        and isinstance(capture.get("observed_at"), str)
        and capture["observed_at"]
        and (capture.get("https_profile") == "urllib_default_certificate_verification")
        and (capture.get("redirect_policy") == "reject_before_follow")
    )


def _reviewed_publication_matches(review, origin, payload):
    """Validate the original publication review and payload binding."""
    return (
        review.get("decision") == "ADMITTED_PROTOCOL_ENDPOINT_ONLY"
        and review.get("publisher_origin") == origin
        and (review.get("fact_sha256") == digest(payload))
        and _sha(review.get("review_sha256"))
        and (review.get("publisher_and_endpoint_context_checked") is True)
        and (review.get("revoked") is False)
    )


# Source-bound session authority admission; candidate capture remains in the sensor.


def operative_signing_default_evidence(finding, context):
    """Join captured defaults to registered credential-verification boundaries."""
    if context is None or not context["index"].validate(Path(finding.get("path", ""))):
        return None
    from .semantic_credential_sensor import signing_configuration_evidence

    index, path = context["index"], Path(finding.get("path", ""))
    declarations = [
        node
        for node in ast.walk(index.snapshots[path])
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        if isinstance(node.value, ast.Constant)
        if isinstance(node.value.value, str)
        if (node.lineno, node.col_offset)
        == (finding.get("line"), finding.get("column", 0))
    ]
    match declarations:
        case [declaration]:
            pass
        case _:
            return None
    if _signing_unrendered_scaffold(declaration, index.snapshots[path]):
        return None
    observation = signing_configuration_evidence(finding, context)
    if (
        observation is not None
        and observation.get("consumer_role") == "django.SECRET_KEY"
    ):
        return _django_default_authority(finding, context, declaration, observation)
    return next(
        (
            witness
            for handler in _CredentialHandlerIndex(context).boundaries()
            if handler["application"]["framework"] == "fastapi"
            for origin in (
                _OperativeCredentialOrigin(context, finding, handler, declaration),
            )
            for witness in (origin.handler_authority(),)
            if witness is not None
        ),
        None,
    )


def _django_default_authority(finding, context, declaration, observation):
    from .mock_fixture_provenance import _django_assignment
    from .credential_role_constructor_provider import binding_occurrences
    from .review_audits import _resolved_ast_name
    from .semantic_credential_sensor import _signing_optional_configuration_defaults

    index, path = context["index"], Path(finding["path"])
    settings, default_guards = _signing_optional_configuration_defaults(
        context, path, observation
    )
    required = {
        "INSTALLED_APPS": {
            "django.contrib.auth",
            "django.contrib.sessions",
            "django.contrib.messages",
        },
        (
            "MIDDLEWARE"
            if binding_occurrences(settings.body, "MIDDLEWARE")
            else "MIDDLEWARE_CLASSES"
        ): {
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            "django.contrib.messages.middleware.MessageMiddleware",
        },
    }
    consumers = []
    for name, authorities in required.items():
        match _django_assignment(settings, name):
            case [(statement, ast.List(elts=values) | ast.Tuple(elts=values))] if all(
                isinstance(item, ast.Constant) for item in values
            ):
                pass
            case _:
                return None
        if not authorities.issubset(
            {item.value for item in values if isinstance(item.value, str)}
        ):
            return None
        if (
            name != "INSTALLED_APPS"
            and not _CredentialHandlerIndex.django_middleware_order(values)
        ):
            return None
        consumers.append(
            {
                "path": path.as_posix(),
                "sha256": index.inventory[path],
                "span": _span(statement),
            }
        )
    selected = _CredentialHandlerIndex(context, framework="django").django_feedback(
        path, settings
    )
    if selected is None:
        return None
    consumers.extend([selected["root"], *selected["evidence"]])
    selected_modules = {
        node.args[1].value
        for transfer in observation["transfers"]
        for node in ast.walk(index.snapshots[Path(transfer["path"])])
        if isinstance(node, ast.Call)
        and len(node.args) == 2
        and _span(node) == transfer["span"]
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "DJANGO_SETTINGS_MODULE"
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
    }
    if not _django_selected_consumers_closed(
        context,
        path,
        {
            *required,
            *_CredentialHandlerIndex._django_feedback_settings(),
            "ROOT_URLCONF",
            "SECRET_KEY",
            "SECRET_KEY_FALLBACKS",
            "MESSAGE_LEVEL",
            "AUTHENTICATION_BACKENDS",
        },
        selected_modules,
    ):
        return None
    return {
        "schema": "factory.security.selected-framework-consumer-authority.v1",
        "proof_scope": "source_bound_selected_framework_feedback_default",
        "framework": "django",
        "credential_key": "SECRET_KEY",
        "source_role": "published_literal_default",
        "consumer_role": "signed_feedback_integrity",
        "selected_consumer": selected,
        "transfers": [
            observation["declaration"],
            *consumers,
            *(
                {
                    "path": path.as_posix(),
                    "sha256": index.inventory[path],
                    "span": _span(node),
                }
                for node in default_guards
            ),
            *observation["transfers"],
        ],
        "runtime_execution": "not_performed",
        "deployment": "UNASSESSED",
        "distribution_runtime_selection": (
            "captured_settings_loader"
            if any(
                name.endswith(("pyproject.toml", "setup.cfg"))
                for name in context.get("captured", {})
            )
            or any(
                isinstance(node, ast.Call)
                and _resolved_ast_name(node.func, context["aliases"][owner])
                in {"setuptools.setup", "distutils.core.setup"}
                for owner, source in index.snapshots.items()
                for node in ast.walk(source)
            )
            else "no_captured_distribution_declaration"
        ),
    }


def _django_setting_import_closure(context, settings_path):
    """Derive closed setting-selected framework imports from current captured ASTs."""
    from .semantic_credential_sensor import (
        _signing_provider_reads,
        _provider_identity_uncertain,
    )
    from .semantic_credential_sensor import _signing_framework_external
    from .mock_fixture_provenance import _django_assignment, _django_name
    from .credential_role_constructor_provider import binding_occurrences

    index = context["index"]
    if (
        settings_path not in index.snapshots
        or not all(index.validate(p) for p in index.snapshots)
        or not _signing_framework_external(context, "django")
    ):
        return None
    tree = index.snapshots[settings_path]
    rows = _django_assignment(tree, "SESSION_ENGINE")
    if rows:
        if len(rows) != 1 or not isinstance(rows[0][1], ast.Constant):
            return None
        engine = rows[0][1].value
    else:
        if binding_occurrences(tree.body, "SESSION_ENGINE"):
            return None
        engine = "django.contrib.sessions.backends.db"
    if (
        not isinstance(engine, str)
        or engine
        not in _CredentialHandlerIndex._django_feedback_settings()["SESSION_ENGINE"]
    ):
        return None
    if sum(
        isinstance(n, ast.Name)
        and n.id == "SESSION_ENGINE"
        and isinstance(n.ctx, (ast.Store, ast.Del))
        for n in ast.walk(tree)
    ) != bool(rows):
        return None
    from .import_context import close_selected_import_sources

    sites = close_selected_import_sources(
        context,
        settings_path,
        _django_setting_import_sites(context, settings_path, engine, bool(rows)),
        {"django", "rest_framework"},
    )
    if sites is None:
        return None
    symbols = {
        _django_name({"source": index}, p) + "." + site["target"]
        for p, found in sites.items()
        for site in found
    }
    roots = (
        "importlib",
        "sys.modules",
        "sys.path",
        "sys.__dict__",
        "builtins",
        "django.conf.settings.SESSION_ENGINE",
        engine,
        *symbols,
    )
    proofs = []
    for path, source in index.snapshots.items():
        aliases = _django_setting_import_aliases(context, settings_path, path)
        aliases.update(
            {site["target"]: engine + ".SessionStore" for site in sites.get(path, ())}
        )
        nodes = list(ast.walk(source))
        approved = {
            identifier for site in sites.get(path, ()) for identifier in site["reads"]
        }
        reads = _signing_provider_reads(
            source, aliases, "django", roots, nodes, context=context, proofs=proofs
        )
        if _django_import_namespace_unknown(
            nodes, aliases, approved
        ) or _provider_identity_uncertain(
            source,
            aliases,
            roots=roots,
            nodes=[n for n in nodes if id(n) not in approved | reads],
            selected_paths=True,
        ):
            return None
    return {
        "reads": {
            id(index.snapshots[p]): {i for site in found for i in site["reads"]}
            for p, found in sites.items()
        },
        "finite_settings": proofs,
        "evidence": [
            {
                "module": engine,
                "member": "SessionStore",
                "configuration": {
                    "path": settings_path.as_posix(),
                    "sha256": index.inventory[settings_path],
                },
                "selection": "captured_literal"
                if rows
                else "registered_django_default",
                "source": site["source"],
            }
            for found in sites.values()
            for site in found
        ],
    }


def _django_setting_import_aliases(context, settings_path, path):
    from .semantic_credential_sensor import _signing_resolve_module

    aliases = dict(context["aliases"][path])
    for alias, canonical in tuple(aliases.items()):
        module, _, member = canonical.rpartition(".")
        if (
            _signing_resolve_module(context, ast.Constant(value=canonical), path)
            == settings_path
        ):
            aliases[alias] = "django.conf.settings"
        elif (
            member == "SESSION_ENGINE"
            and _signing_resolve_module(context, ast.Constant(value=module), path)
            == settings_path
        ):
            aliases[alias] = "django.conf.settings.SESSION_ENGINE"
    if path == settings_path:
        aliases["SESSION_ENGINE"] = "django.conf.settings.SESSION_ENGINE"
    return aliases


def _django_setting_import_sites(context, settings_path, engine, explicit):
    from .semantic_credential_sensor import _signing_resolve_module
    from .credential_role_constructor_provider import binding_occurrences
    from . import review_audits as audit

    index, sites = context["index"], {}
    if _signing_resolve_module(context, ast.Constant(value="importlib")) is not None:
        return None
    for path, tree in index.snapshots.items():
        aliases = _django_setting_import_aliases(context, settings_path, path)
        for statement in tree.body:
            match statement:
                case ast.Assign(
                    targets=[ast.Name(id=target)],
                    value=ast.Attribute(
                        value=ast.Call(args=[argument], keywords=[]) as call,
                        attr="SessionStore",
                    ),
                ):
                    pass
                case _:
                    continue
            if (
                audit._resolved_ast_name(call.func, aliases)
                != "importlib.import_module"
            ):
                continue
            if not _django_setting_import_operand(
                argument, aliases, context["aliases"][path], engine, explicit
            ):
                continue
            if not _django_importer_external(context, path, tree, call):
                return None
            if len(binding_occurrences(tree.body, target)) != 1:
                return None
            sites.setdefault(path, []).append(
                {
                    "target": target,
                    "reads": {
                        id(n) for node in (call.func, argument) for n in ast.walk(node)
                    },
                    "source": {
                        "path": path.as_posix(),
                        "sha256": index.inventory[path],
                        "span": _span(statement),
                    },
                }
            )
    return sites


def _django_importer_external(context, path, tree, call):
    from .import_context import import_source_choices, captured_import_inventory
    from .credential_role_constructor_provider import binding_occurrences
    from .semantic_credential_sensor import _signing_framework_external

    head = call.func
    while isinstance(head, ast.Attribute):
        head = head.value
    if not isinstance(head, ast.Name):
        return False
    rows = binding_occurrences(tree.body, head.id)
    if len(rows) != 1 or not isinstance(rows[0], (ast.Import, ast.ImportFrom)):
        return False
    index = context["index"]
    choices = import_source_choices(
        index.root,
        path,
        rows[0],
        "importlib",
        None,
        captured_inventory=captured_import_inventory(index),
    )
    return (
        _signing_framework_external(context, "importlib")
        and not any(candidate in index.snapshots for candidate, _ in choices)
        and not any(
            isinstance(n, ast.Name)
            and n.id == head.id
            and isinstance(n.ctx, (ast.Store, ast.Del))
            for n in ast.walk(tree)
        )
    )


def _django_setting_import_operand(argument, aliases, original, engine, explicit):
    from .review_audits import _resolved_ast_name

    literal = isinstance(argument, ast.Constant) and argument.value == engine
    selected = (
        _resolved_ast_name(argument, aliases) == "django.conf.settings.SESSION_ENGINE"
    )
    return (selected or literal) and (
        explicit
        or literal
        or _resolved_ast_name(argument, original)
        == "django.conf.settings.SESSION_ENGINE"
    )


def _django_import_namespace_unknown(nodes, aliases, approved):
    from .review_audits import _resolved_ast_name

    return any(
        isinstance(n, (ast.Name, ast.Attribute))
        and _resolved_ast_name(n, aliases).startswith(
            ("sys.modules", "sys.__dict__", "importlib.")
        )
        and id(n) not in approved
        or isinstance(n, ast.Attribute)
        and _resolved_ast_name(n.value, aliases) == "django.conf.settings"
        and n.attr.startswith("_")
        or isinstance(n, ast.Call)
        and _resolved_ast_name(n.func, aliases).startswith("sys.path.")
        or isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and _resolved_ast_name(n.func.value, aliases) == "django.conf.settings"
        for n in nodes
    )


def _django_selected_consumers_closed(context, path, required, selected_modules):
    from .semantic_credential_sensor import (
        _signing_provider_clear,
        _signing_resolve_module,
        _provider_path_conflicts,
    )
    from .finite_capture import _provider_paths, _provider_alias_bindings
    from . import review_audits as audit

    index = context["index"]
    roots = tuple("django.conf.settings." + name for name in required)
    configuration = {*required, "DEBUG", "STATIC_URL", "MEDIA_URL"}
    providers = (
        "django.urls",
        "django.conf.urls",
        "django.contrib.messages",
        "django.contrib.sessions.backends",
        "django.contrib.sessions.serializers",
        "django.contrib.auth.backends",
        "django.contrib.auth.decorators.login_required",
        "django.core.signing",
        "django.db.models.Model",
        "django.forms.ModelForm",
        "django.forms.models.ModelForm",
        "django.utils.decorators.method_decorator",
        "rest_framework.views.APIView",
        "rest_framework.generics",
    )
    for source_path, tree in index.snapshots.items():
        aliases = dict(context["aliases"][source_path])
        for alias, canonical in tuple(aliases.items()):
            module, _, member = canonical.rpartition(".")
            if (
                canonical == "django.conf.settings"
                or canonical in selected_modules
                or _signing_resolve_module(context, ast.Constant(value=canonical))
                == path
            ):
                aliases[alias] = "django.conf.settings"
            elif member in configuration and (
                module == "django.conf.settings"
                or module.lstrip(".") in selected_modules
                or _signing_resolve_module(
                    context, ast.Constant(value=module.lstrip("."))
                )
                == path
            ):
                aliases[alias] = "django.conf.settings." + member
        if source_path == path:
            aliases.update(
                {name: "django.conf.settings." + name for name in configuration}
            )
        nodes = list(ast.walk(tree))
        from .semantic_credential_sensor import _provider_identity_uncertain
        from .semantic_credential_sensor import _security_builtin_identity_closed

        reflection_closed = _security_builtin_identity_closed(
            tree, aliases, {"getattr", "hasattr"}
        )

        approved = {
            id(child)
            for node in nodes
            if isinstance(node, ast.Call)
            and len(node.args) == 2
            and audit._resolved_ast_name(node.func, aliases)
            in {"django.urls.path", "django.urls.re_path", "django.conf.urls.url"}
            and audit._resolved_ast_name(node.args[1], aliases)
            == "django.contrib.admin.site.urls"
            for child in ast.walk(node.args[1])
        }
        approved.update(
            id(child)
            for node in nodes
            if isinstance(node, ast.Call)
            and node.args
            and audit._resolved_ast_name(node.func, aliases)
            in {
                "django.urls.include",
                "django.conf.urls.include",
                "django.urls.conf.include",
            }
            and audit._resolved_ast_name(node.args[0], aliases)
            == "django.contrib.admin.site.urls"
            for child in ast.walk(node.args[0])
        )
        approved.update(
            id(node.args[0])
            for node in nodes
            if isinstance(node, ast.Call)
            and reflection_closed
            and (name := audit._resolved_ast_name(node.func, aliases))
            in {"getattr", "hasattr", "builtins.getattr", "builtins.hasattr"}
            and not node.keywords
            and len(node.args) in range(2, 4 if name.endswith("getattr") else 3)
            and audit._resolved_ast_name(node.args[0], aliases)
            == "django.conf.settings"
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
            and not node.args[1].value.startswith("_")
        )
        approved.update(
            id(child)
            for node in nodes
            if isinstance(node, ast.Call)
            and len(node.args) >= 2
            and audit._resolved_ast_name(node.func, aliases)
            in {"django.urls.path", "django.urls.re_path", "django.conf.urls.url"}
            and audit._resolved_ast_name(node.args[1], aliases)
            in {
                "django.contrib.auth.views." + name
                for name in (
                    "login",
                    "logout",
                    "password_reset",
                    "password_reset_done",
                    "password_reset_confirm",
                    "password_reset_complete",
                    "password_change",
                    "password_change_done",
                )
            }
            for child in ast.walk(node.args[1])
        )
        approved.update(
            id(child)
            for node in nodes
            if isinstance(node, ast.Call)
            and node.args
            and audit._resolved_ast_name(node.func, aliases)
            in {
                "django.conf.urls.static.static",
                "django.contrib.staticfiles.urls.static",
            }
            and audit._resolved_ast_name(node.args[0], aliases)
            in {"django.conf.settings.STATIC_URL", "django.conf.settings.MEDIA_URL"}
            for child in ast.walk(node.args[0])
        )
        approved.update(
            id(child)
            for node in nodes
            if isinstance(node, ast.Call)
            and len(node.args) == 1
            and audit._resolved_ast_name(node.func, aliases)
            == "django.utils.decorators.method_decorator"
            and audit._resolved_ast_name(node.args[0], aliases)
            in {
                "django.views.decorators.csrf.csrf_exempt",
                "django.views.decorators.http.require_POST",
            }
            for child in ast.walk(node.args[0])
        )
        guard_roots = (
            "django.contrib.admin",
            "django.views",
            "django.contrib.auth.views",
            "django.contrib.auth.urls",
            "django.conf.settings.DEBUG",
            "django.conf.settings.STATIC_URL",
            "django.conf.settings.MEDIA_URL",
        )
        from .semantic_credential_sensor import _signing_provider_reads

        approved.update(
            _signing_provider_reads(
                tree, aliases, "django", guard_roots, nodes, context=context
            )
        )
        if _provider_identity_uncertain(
            tree,
            aliases,
            roots=guard_roots,
            nodes=[node for node in nodes if id(node) not in approved],
            selected_paths=True,
        ):
            return False
        bindings = _provider_alias_bindings(nodes)
        if _signing_provider_clear(
            tree,
            aliases,
            "django",
            roots=(*roots, *providers),
            context=context,
            settings_path=path,
        ) is False or any(
            isinstance(node, ast.Call)
            and any(
                _provider_path_conflicts(provider, "*", root)
                for provider in _provider_paths(node.func, aliases, audit, bindings)[0]
                for root in roots
            )
            for node in nodes
        ):
            return False
    return True


def _signing_unrendered_scaffold(declaration, tree):
    from .semantic_credential_sensor import _AUTH_TEMPLATE

    if not _AUTH_TEMPLATE.search(declaration.value.value):
        return False
    return any(
        isinstance(node, ast.Assign)
        and any(
            isinstance(t, ast.Name) and t.id in {"ROOT_URLCONF", "WSGI_APPLICATION"}
            for t in node.targets
        )
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
        and _AUTH_TEMPLATE.search(node.value.value)
        for node in tree.body
    )


class _OperativeCredentialOrigin:
    """Conditional default origins and allocation-owned verification capabilities."""

    def __init__(self, context, finding, handler, declaration):
        from .credential_role_method_use_getter_audit import CapturedOriginProjection
        from .credential_role_identity_effects import _Value

        self.context, self.index, self.finding = context, context["index"], finding
        self.handler, self.declaration = handler, declaration
        self.path = Path(finding["path"])
        self.root = "default:" + _digest(
            [finding["path"], self.index.inventory[self.path], _span(declaration)]
        )
        self.value_type, self.allocations = _Value, {}
        self.projection = CapturedOriginProjection(self.index, self.leaf)
        self.execution_root = handler["application"]["path"].parent
        if self.projection.symbols is not None:
            self.projection.symbols = {
                **self.projection.symbols,
                "execution_root": self.execution_root,
            }
        self.consumer = None
        self.consumer_transfers = []
        self.key = _Value(
            roots=frozenset({self.root}),
            scalar_kind="text",
            trace=(
                (
                    "DEFAULT_MAY_REACH",
                    self.path.as_posix(),
                    self.index.inventory[self.path],
                    tuple(_span(declaration)),
                ),
            ),
        )

    def canonical(self, path, node, function=None):
        """Resolve a captured expression to its canonical imported provider identity."""
        from .mock_fixture_provenance import _app_expression_name

        selected = _app_expression_name(self.projection.symbols, path, node, function)
        return (
            selected
            if selected is not None
            else self.handler["graph"].canonical(path, node, function)
        )

    def provider(self, path, canonical, *, immutable=False):
        """Require an unmodified canonical provider at the captured expression site."""
        from . import review_audits as audit
        from .credential_role_constructor_provider import (
            _terminal_imported_module_receiver,
        )
        from .semantic_credential_sensor import (
            _provider_identity_uncertain,
            _signing_framework_external,
        )

        if not _signing_framework_external(self.context, canonical.split(".")[0]):
            return False
        provider_root = canonical.split(".")[0]
        if any(
            path == self.execution_root / (provider_root + ".py")
            or path.is_relative_to(self.execution_root / provider_root)
            for path in self.index.snapshots
        ):
            return False
        for owner, tree in self.index.snapshots.items():
            nodes = list(ast.walk(tree))
            if not self.provider_reflection_closed(
                nodes, self.context["aliases"][owner], canonical
            ):
                return False
            if _provider_identity_uncertain(
                tree,
                self.context["aliases"][owner],
                nodes=nodes,
                roots=(canonical,),
                selected_paths=True,
                argument_predicate=lambda item, aliases, parents: not (
                    _terminal_imported_module_receiver(item, parents, audit, canonical)
                    or immutable
                    and audit._resolved_ast_name(item, aliases) == canonical
                ),
            ):
                return False
        return self.projection._symbol_closed(
            [(canonical, None, None)],
            self.value_type(scalar_kind="integer") if immutable else self.value_type(),
        )

    def provider_reflection_closed(self, nodes, aliases, canonical):
        """Reject reflective writes and namespace escapes affecting the selected provider."""
        from . import review_audits as audit
        from .finite_capture import _provider_alias_bindings, _provider_paths
        from .semantic_credential_sensor import _provider_path_conflicts

        bindings = _provider_alias_bindings(nodes)
        for node in nodes:
            head = None
            if isinstance(node, ast.Call):
                name = audit._resolved_ast_name(node.func, aliases)
                if name in {
                    "exec",
                    "eval",
                    "__import__",
                    "builtins.exec",
                    "builtins.eval",
                    "builtins.__import__",
                    "importlib.import_module",
                }:
                    return False
                if (
                    name in {"vars", "getattr", "builtins.vars", "builtins.getattr"}
                    and node.args
                ):
                    head = node.args[0]
                if name in {
                    "globals",
                    "locals",
                    "builtins.globals",
                    "builtins.locals",
                } and any(
                    isinstance(value, str)
                    and _provider_path_conflicts(value, "*", canonical)
                    for value in aliases.values()
                ):
                    return False
            elif isinstance(node, ast.Attribute) and node.attr in {
                "__dict__",
                "__globals__",
                "__func__",
                "__code__",
            }:
                head = node.value
            if head is not None:
                paths, _ = _provider_paths(head, aliases, audit, bindings)
                if any(
                    _provider_path_conflicts(value, "*", canonical) for value in paths
                ):
                    return False
        return True

    def leaf(self, node, environment, path, function, projection):
        """Resolve the scalar origin and retained evidence for one captured expression."""
        if node is self.declaration.value and path == self.path:
            return True, self.key
        if isinstance(node, (ast.Name, ast.Attribute)) and self.literal_reference(
            path, node, function, projection
        ):
            return True, self.key
        if isinstance(node, ast.JoinedStr):
            from urllib.parse import urlsplit
            from .credential_role_identity_effects import _validated_exact_scalar

            if any(
                isinstance(part, ast.FormattedValue)
                and (part.conversion != -1 or part.format_spec is not None)
                for part in node.values
            ):
                return False, None
            operands = [
                projection.expression(
                    path,
                    part.value if isinstance(part, ast.FormattedValue) else part,
                    function,
                    environment,
                )
                for part in node.values
            ]
            if not all(known and not value.class_roots for known, value in operands):
                return False, None
            scalars = [(value, _validated_exact_scalar(value)) for _, value in operands]
            if not all(
                value.roots == self.key.roots
                and value.scalar_kind == "text"
                or not value.roots
                and bool(exact)
                and type(exact[0]) in {str, int}
                and "credential-origin" not in str(exact[0])
                for value, exact in scalars
            ):
                return False, None
            pieces = [
                "credential-origin" if value.roots else str(exact[0])
                for value, exact in scalars
            ]
            try:
                parsed = urlsplit("".join(pieces))
                password, hostname, _port = (
                    parsed.password,
                    parsed.hostname,
                    parsed.port,
                )
            except ValueError:
                return False, None
            if (
                parsed.scheme not in {"postgresql", "postgres", "mysql"}
                or password != "credential-origin"
                or not parsed.username
                or not hostname
                or not parsed.path.strip("/")
                or sum(piece == "credential-origin" for piece in pieces) != 1
            ):
                return False, None
            return True, self.value_type(
                roots=self.key.roots,
                scalar_kind="text",
                inert_kind="database_credential_url",
                trace=tuple(step for _, value in operands for step in value.trace),
            )
        projector = {
            ast.Subscript: self.field,
            ast.Attribute: self.field,
            ast.Compare: self.comparison,
            ast.Call: self.call,
        }.get(type(node))
        return (
            projector(node, environment, path, function, projection)
            if projector
            else (False, None)
        )

    def literal_reference(self, path, node, function, projection):
        """Bind an imported literal to its unchanged captured source declaration."""
        from .semantic_credential_sensor import (
            _signing_source_symbol,
            _flask_imported_key_written,
        )
        from .mock_fixture_provenance import _django_name

        selected = _signing_source_symbol(self.context, path, node, function)
        if selected != (self.path, self.declaration):
            return False
        name = self.finding["facts"]["name"]
        return not _flask_imported_key_written(
            self.path, self.context, name
        ) and projection._symbol_closed(
            [
                (
                    _django_name(projection.symbols, self.path) + "." + name,
                    self.path,
                    name,
                )
            ],
            self.key,
        )

    def field(self, node, environment, path, function, projection):
        """Read a captured credential field only when its receiver identity is closed."""
        known, request_value = self.request_field(
            node, environment, path, function, projection
        )
        if known:
            return known, request_value
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        ):
            known, value = projection.expression(
                path, node.value, function, environment
            )
            if known and value.roots == frozenset({"verified:" + self.root}):
                return True, self.value_type(
                    roots=value.roots, scalar_kind="json", trace=value.trace
                )
        if isinstance(node, ast.Attribute):
            known, owner = projection.expression(
                path, node.value, function, environment
            )
            if known and owner.container_id in self.allocations:
                fields = self.allocations[owner.container_id].get("fields", {})
                if node.attr in fields:
                    return True, fields[node.attr]
        return False, None

    def request_field(self, node, environment, path, function, projection):
        """Retain HTTP header and split-token provenance without treating it as sanitized."""
        if not isinstance(node, (ast.Attribute, ast.Subscript)):
            return False, None
        known, owner = projection.expression(path, node.value, function, environment)
        if not known:
            return False, None
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "headers"
            and owner.inert_kind == "http_request"
        ):
            return True, self.value_type(inert_kind="http_headers")
        if (
            isinstance(node, ast.Subscript)
            and owner.inert_kind == "request_token_parts"
        ):
            try:
                index = ast.literal_eval(node.slice)
            except (ValueError, TypeError):
                return False, None
            if type(index) is int:
                return True, self.value_type(
                    roots=owner.roots, scalar_kind="text", trace=owner.trace
                )
        return False, None

    def comparison(self, node, environment, path, function, projection):
        """Bind a credential comparison to its selected authority and input origin."""
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            operands = [
                projection.expression(path, item, function, environment)
                for item in (node.left, *node.comparators)
            ]
            if all(
                known
                and value.scalar_kind in {"json", "integer", "float", "boolean", "text"}
                and not value.class_roots
                for known, value in operands
            ):
                if isinstance(node.ops[0], ast.Eq) and {
                    value.roots for _, value in operands
                } == {self.key.roots, frozenset({"request-token"})}:
                    return True, self.value_type(
                        roots=frozenset({"verified:" + self.root}),
                        inert_kind="credential_equality",
                        scalar_kind="boolean",
                        trace=tuple(
                            step for _, value in operands for step in value.trace
                        ),
                    )
                return True, self.value_type(
                    inert_kind="scalar",
                    scalar_kind="boolean",
                    trace=tuple(step for _, value in operands for step in value.trace),
                )
        return False, None

    def call(self, node, environment, path, function, projection):
        """Interpret a supported captured provider call without executing target code."""
        known, request_value = self.request_call(
            node, environment, path, function, projection
        )
        if known:
            return known, request_value
        canonical = self.canonical(path, node.func, function)
        if (
            canonical
            in {
                "fastapi.HTTPException",
                "fastapi.exceptions.HTTPException",
                "fastapi.responses.JSONResponse",
                "starlette.responses.JSONResponse",
            }
            and not node.args
            and self.provider(path, canonical)
        ):
            status = next(
                (kw.value for kw in node.keywords if kw.arg == "status_code"), None
            )
            denied = (
                isinstance(status, ast.Constant)
                and status.value in {401, 403}
                or self.canonical(path, status, function)
                in {
                    "fastapi.status.HTTP_401_UNAUTHORIZED",
                    "fastapi.status.HTTP_403_FORBIDDEN",
                }
                and self.provider(
                    path, self.canonical(path, status, function), immutable=True
                )
            )
            if (
                denied
                and len({kw.arg for kw in node.keywords}) == len(node.keywords)
                and all(
                    kw.arg in {"status_code", "detail", "content"}
                    for kw in node.keywords
                )
            ):
                try:
                    for kw in node.keywords:
                        if kw.arg != "status_code":
                            ast.literal_eval(kw.value)
                except (ValueError, TypeError, SyntaxError):
                    return False, None
                return True, self.value_type(inert_kind="authentication_denial")
        if (
            canonical == "time.time"
            and not node.args
            and not node.keywords
            and self.provider(path, canonical)
        ):
            return True, self.value_type(inert_kind="scalar", scalar_kind="float")
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "encode"
            and not node.args
            and not node.keywords
        ):
            known, value = projection.expression(
                path, node.func.value, function, environment
            )
            if (
                known
                and value.scalar_kind == "text"
                and value.roots == frozenset({"request-token"})
            ):
                return True, self.value_type(
                    roots=value.roots, scalar_kind="bytes", trace=value.trace
                )
        known, value = self.construct(
            node, environment, path, function, projection, canonical
        )
        return (
            (known, value)
            if known
            else self.verify(node, environment, path, function, projection, canonical)
        )

    def request_call(self, node, environment, path, function, projection):
        """Model only fixed authorization-header reads and inert string splitting."""
        if (
            not isinstance(node.func, ast.Attribute)
            or node.keywords
            or len(node.args) != 1
        ):
            return False, None
        known, owner = projection.expression(
            path, node.func.value, function, environment
        )
        if (
            not known
            or not isinstance(node.args[0], ast.Constant)
            or not isinstance(node.args[0].value, str)
        ):
            return False, None
        if (
            node.func.attr == "get"
            and owner.inert_kind == "http_headers"
            and node.args[0].value.lower() == "authorization"
        ):
            return True, self.value_type(
                roots=frozenset({"request-token"}), scalar_kind="text"
            )
        if (
            node.func.attr == "split"
            and owner.roots == frozenset({"request-token"})
            and node.args[0].value == " "
        ):
            return True, self.value_type(
                roots=owner.roots, inert_kind="request_token_parts", trace=owner.trace
            )
        return False, None

    def construct(
        self, node, environment, path, function, projection, canonical, *, following=()
    ):
        """Resolve supported credential construction and retain the complete origin chain."""
        from .mock_fixture_provenance import _app_source_symbol

        if isinstance(node, ast.Try):
            if not (
                not node.orelse
                and not node.finalbody
                and node.body
                and node.handlers
                and isinstance(node.body[0], ast.Assign)
                and len(node.body[0].targets) == 1
                and isinstance(node.body[0].targets[0], ast.Name)
                and not any(
                    isinstance(item, (ast.Raise, ast.Return)) for item in node.body[1:]
                )
                and any(isinstance(item, ast.Return) for item in following)
                and all(
                    len(handler.body) == 1 and isinstance(handler.body[0], ast.Raise)
                    for handler in node.handlers
                )
            ):
                return False, None
            known, value = projection.expression(
                path, node.body[0].value, function, environment
            )
            if not known or value.roots != frozenset({"verified:" + self.root}):
                return False, None
            denials = [
                projection.expression(path, handler.body[0].exc, function, environment)
                for handler in node.handlers
            ]
            if not (
                all(
                    known and denial.inert_kind == "authentication_denial"
                    for known, denial in denials
                )
                and all(
                    isinstance(handler.body[0].exc, ast.Call)
                    and self.canonical(path, handler.body[0].exc.func, function)
                    in {"fastapi.HTTPException", "fastapi.exceptions.HTTPException"}
                    for handler in node.handlers
                )
            ):
                return False, None
            return True, value
        if not isinstance(node, ast.Call):
            return False, None
        selected = _app_source_symbol(projection.symbols, path, node.func, function)
        if selected and isinstance(selected[1], ast.ClassDef):
            owner_path, owner = selected
            base = (
                self.canonical(owner_path, owner.bases[0], None)
                if len(owner.bases) == 1
                else None
            )
            if (
                base == "pydantic_settings.BaseSettings"
                and self.provider(owner_path, base)
                and not owner.decorator_list
                and not owner.keywords
                and not node.args
                and not node.keywords
                and self.index.parents[self.path].get(id(self.declaration)) is owner
                and self.settings_fields_closed(owner_path, owner, projection)
            ):
                return self.allocate(
                    node,
                    path,
                    projection,
                    fields={self.finding["facts"]["name"]: self.key},
                )
        return False, None

    def verify(
        self, node, environment, path, function, projection, canonical, *, following=()
    ):
        """Require a source-bound verifier and its exact credential input binding."""
        if isinstance(node, ast.If):
            if not (
                not node.orelse
                and len(node.body) == 1
                and isinstance(node.body[0], ast.Return)
                and len(following) == 1
                and isinstance(following[0], (ast.Return, ast.Raise))
            ):
                return False, None
            try:
                ast.literal_eval(node.body[0].value)
            except (ValueError, TypeError, SyntaxError):
                return False, None
            known, value = projection.expression(path, node.test, function, environment)
            rejected = (
                following[0].value
                if isinstance(following[0], ast.Return)
                else following[0].exc
            )
            denial_known, denial = projection.expression(
                path, rejected, function, environment
            )
            expected = (
                {"fastapi.HTTPException", "fastapi.exceptions.HTTPException"}
                if isinstance(following[0], ast.Raise)
                else {
                    "fastapi.responses.JSONResponse",
                    "starlette.responses.JSONResponse",
                }
            )
            if not (
                known
                and value.inert_kind == "credential_equality"
                and denial_known
                and denial.inert_kind == "authentication_denial"
                and isinstance(rejected, ast.Call)
                and self.canonical(path, rejected.func, function) in expected
            ):
                return False, None
            self.consumer = ("fastapi", "direct_token_rejection")
            return True, value
        if canonical == "jwt.decode" and self.provider(path, canonical):
            if (
                len(node.args) != 2
                or len(node.keywords) != 1
                or {kw.arg for kw in node.keywords} != {"algorithms"}
            ):
                return False, None
            if not self.jwt_algorithms(
                node.keywords[0].value, environment, path, function, projection
            ):
                return False, None
            known, key = projection.expression(
                path, node.args[1], function, environment
            )
            token_known, token = projection.expression(
                path, node.args[0], function, environment
            )
            if (
                known
                and token_known
                and key.roots == self.key.roots
                and token.roots == frozenset({"request-token"})
            ):
                return True, self.value_type(
                    roots=frozenset({"verified:" + self.root}),
                    trace=key.trace + token.trace,
                )
        return False, None

    def jwt_algorithms(self, node, environment, path, function, projection):
        """Accept nonempty literal JWT algorithm lists limited to supported HMAC algorithms."""
        from .credential_role_identity_effects import _validated_exact_scalar

        if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
            return False
        for item in node.elts:
            known, value = projection.expression(path, item, function, environment)
            exact = _validated_exact_scalar(value) if known else ()
            if not exact or exact[0] not in {"HS256", "HS384", "HS512"}:
                return False
        return True

    def settings_fields_closed(self, path, owner, projection):
        """Reject conflicting configuration writes before using captured credential settings."""
        from .credential_role_constructor_provider import binding_occurrences

        declaration = self.declaration
        if not (
            isinstance(declaration, ast.AnnAssign)
            and isinstance(declaration.annotation, ast.Name)
            and declaration.annotation.id == "str"
            and not binding_occurrences(self.index.snapshots[path].body, "str")
            and len(binding_occurrences(owner.body, self.finding["facts"]["name"])) == 1
        ):
            return False
        for node in ast.walk(owner):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                return False
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                if any(
                    isinstance(target, ast.Name) and target.id == "model_config"
                    for target in targets
                ):
                    return False
        return projection._symbol_closed(
            [(owner.name, path, owner.name)], self.value_type()
        )

    def allocate(self, node, path, projection, **capability):
        """Allocate a bounded captured identity while retaining its source evidence."""
        if capability.pop("database_effect", False):
            from .mock_fixture_provenance import _app_source_symbol
            from .semantic_credential_sensor import _signing_source_span

            if not (
                self.provider(path, "fastapi.FastAPI")
                and isinstance(node, ast.Call)
                and not node.args
                and len(node.keywords) == 1
                and node.keywords[0].arg == "bind"
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "create_all"
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "metadata"
            ):
                return False, None
            base_chain, engine_chain = [], []
            base = _app_source_symbol(
                projection.symbols,
                path,
                node.func.value.value,
                provider_chain=base_chain,
            )
            engine = _app_source_symbol(
                projection.symbols,
                path,
                node.keywords[0].value,
                provider_chain=engine_chain,
            )
            if not base or not engine:
                return False, None
            base_path, base_declaration = base
            engine_path, engine_declaration = engine
            if not all(
                isinstance(item, ast.Assign)
                and len(item.targets) == 1
                and isinstance(item.targets[0], ast.Name)
                and isinstance(item.value, ast.Call)
                for item in (base_declaration, engine_declaration)
            ):
                return False, None
            constructor, connection = base_declaration.value, engine_declaration.value
            base_provider = self.canonical(base_path, constructor.func)
            if not (
                base_provider
                in {
                    "sqlalchemy.ext.declarative.declarative_base",
                    "sqlalchemy.orm.declarative_base",
                }
                and not constructor.args
                and not constructor.keywords
                and self.provider(base_path, base_provider)
                and self.canonical(engine_path, connection.func)
                == "sqlalchemy.create_engine"
                and self.provider(engine_path, "sqlalchemy.create_engine")
                and len(connection.args) == 1
                and not connection.keywords
            ):
                return False, None
            known, value = projection.expression(engine_path, connection.args[0])
            if not known or value.inert_kind != "database_credential_url":
                return False, None
            readonly_arguments = {id(node.keywords[0].value)} | {
                id(kw.value)
                for owner_path, tree in self.index.snapshots.items()
                for use in ast.walk(tree)
                if isinstance(use, ast.Call)
                and self.canonical(owner_path, use.func)
                == "sqlalchemy.orm.sessionmaker"
                and not use.args
                and all(
                    kw.arg in {"bind", "autocommit", "autoflush", "expire_on_commit"}
                    for kw in use.keywords
                )
                and self.provider(owner_path, "sqlalchemy.orm.sessionmaker")
                for kw in use.keywords
                if kw.arg == "bind"
                and _app_source_symbol(projection.symbols, owner_path, kw.value)
                == engine
            }
            if not (
                projection._symbol_closed(
                    engine_chain,
                    self.value_type(),
                    readonly_argument=lambda item: id(item) in readonly_arguments,
                )
                and projection._symbol_closed(
                    base_chain,
                    self.value_type(),
                    readonly_call=lambda item: item is node,
                )
            ):
                return False, None
            self.consumer = ("sqlalchemy", "database_authentication")
            self.consumer_transfers = [
                _signing_source_span(self.index, base_path, base_declaration),
                _signing_source_span(self.index, engine_path, engine_declaration),
            ]
            return True, value
        allocation = _digest(
            [projection.generation, projection.context, path.as_posix(), _span(node)]
        )
        self.allocations[allocation] = capability
        return True, self.value_type(
            roots=self.key.roots, container_id=allocation, trace=self.key.trace
        )

    def token_inputs(self, *, structural_only=False):
        """Enumerate registered bearer inputs, optionally checking only necessary syntax."""
        from .mock_fixture_provenance import _app_source_symbol

        function, path = (self.handler["function"], self.handler["path"])
        args = [*function.args.posonlyargs, *function.args.args]
        count = len(function.args.defaults)
        defaults = zip(args[-count:], function.args.defaults) if count else ()
        inputs = self.request_inputs(path, function, args)
        for arg, value in defaults:
            if (
                isinstance(value, ast.Call)
                and len(value.args) == 1
                and isinstance(value.args[0], ast.Constant)
                and value.args[0].value is Ellipsis
                and not value.keywords
                and self.canonical(path, value.func, function) == "fastapi.Query"
            ):
                from .credential_role_constructor_provider import binding_occurrences

                if not (
                    isinstance(arg.annotation, ast.Name)
                    and arg.annotation.id == "str"
                    and not binding_occurrences(self.index.snapshots[path].body, "str")
                    and self.provider(path, "builtins.str", immutable=True)
                ):
                    continue
                if structural_only or self.provider(path, "fastapi.Query"):
                    inputs[arg.arg] = self.value_type(
                        roots=frozenset({"request-token"}), scalar_kind="text"
                    )
                continue
            if not (
                isinstance(value, ast.Call)
                and len(value.args) == 1
                and (not value.keywords)
                and (self.canonical(path, value.func, function) == "fastapi.Depends")
            ):
                continue
            selected = _app_source_symbol(self.projection.symbols, path, value.args[0])
            if selected and isinstance(selected[1], ast.Assign):
                factory = selected[1].value
                if (
                    len(selected[1].targets) == 1
                    and isinstance(selected[1].targets[0], ast.Name)
                    and isinstance(factory, ast.Call)
                    and (not factory.args)
                    and (len(factory.keywords) == 1)
                    and all(
                        (
                            k.arg == "tokenUrl"
                            and isinstance(k.value, ast.Constant)
                            and isinstance(k.value.value, str)
                            for k in factory.keywords
                        )
                    )
                    and (
                        self.canonical(selected[0], factory.func, None)
                        == "fastapi.security.OAuth2PasswordBearer"
                    )
                ):
                    if structural_only:
                        return True
                    if (
                        self.provider(path, "fastapi.Depends")
                        and self.provider(
                            selected[0], "fastapi.security.OAuth2PasswordBearer"
                        )
                        and self.projection._symbol_closed(
                            [
                                (
                                    selected[1].targets[0].id,
                                    selected[0],
                                    selected[1].targets[0].id,
                                )
                            ],
                            self.value_type(),
                            readonly_argument=lambda item: id(item)
                            in self.dependency_arguments,
                        )
                    ):
                        inputs[arg.arg] = self.value_type(
                            roots=frozenset({"request-token"}), scalar_kind="text"
                        )
        return bool(inputs) if structural_only else inputs

    def handler_authority(self):
        """Prove credential authority only after input and complete provider closure."""
        function, path = self.handler["function"], self.handler["path"]
        self.consumer, self.consumer_transfers = None, []
        if not self.token_inputs(structural_only=True):
            application_path = self.handler["application"]["path"]
            effect = next(
                (
                    (statement.value, result[1])
                    for statement in self.index.snapshots[application_path].body
                    if isinstance(statement, ast.Expr)
                    and (
                        result := self.allocate(
                            statement.value,
                            application_path,
                            self.projection,
                            database_effect=True,
                        )
                    )[0]
                ),
                None,
            )
            return self.witness(*effect) if effect else None
        if not self.boundary_closed():
            return None
        environment = self.token_inputs()
        if not environment:
            return None
        statements = [
            item
            for item in function.body
            if not (
                isinstance(item, ast.Expr)
                and isinstance(item.value, ast.Constant)
                and isinstance(item.value.value, str)
            )
        ]
        for offset, statement in enumerate(statements):
            if (
                isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
            ):
                known, value = self.projection.expression(
                    path, statement.value, function, environment
                )
                if not known:
                    return None
                environment[statement.targets[0].id] = value
                continue
            interpreter = (
                self.construct if isinstance(statement, ast.Try) else self.verify
            )
            known, value = interpreter(
                statement,
                environment,
                path,
                function,
                self.projection,
                None,
                following=statements[offset + 1 :],
            )
            if known:
                return self.witness(statement, value)
            rejected = self.rejection_value(statement, environment, path, function)
            if rejected is None:
                return None
            if rejected.roots == frozenset({"request-token"}):
                continue
            return self.witness(statement, rejected)
        return None

    def request_inputs(self, path, function, arguments):
        """Model canonical FastAPI Request parameters as inert HTTP request inputs."""
        return {
            arg.arg: self.value_type(inert_kind="http_request")
            for arg in arguments
            if self.canonical(path, arg.annotation, function) == "fastapi.Request"
            and self.provider(path, "fastapi.Request")
        }

    def rejection_value(self, statement, environment, path, function):
        """Return a denied value for a simple inverted guard that raises."""
        if not (
            isinstance(statement, ast.If)
            and not statement.orelse
            and len(statement.body) == 1
            and isinstance(statement.body[0], ast.Raise)
            and isinstance(statement.test, ast.UnaryOp)
            and isinstance(statement.test.op, ast.Not)
            and isinstance(statement.test.operand, ast.Name)
        ):
            return None
        value = environment.get(statement.test.operand.id)
        known, denial = self.projection.expression(
            path, statement.body[0].exc, function, environment
        )
        if not (
            value is not None
            and value.roots
            in {frozenset({"request-token"}), frozenset({"verified:" + self.root})}
            and known
            and denial.inert_kind == "authentication_denial"
            and isinstance(statement.body[0].exc, ast.Call)
            and self.canonical(path, statement.body[0].exc.func, function)
            in {"fastapi.HTTPException", "fastapi.exceptions.HTTPException"}
        ):
            return None
        return value

    def boundary_closed(self):
        """Validate provider identity and callback closure for the selected handler."""
        from . import review_audits as audit
        from .credential_role_constructor_provider import (
            _captured_terminal_provider_mutation,
        )
        from .mock_fixture_provenance import _django_name
        from .mock_fixture_provenance import _app_source_symbol
        from .credential_role_identity_effects import _enclosing_function

        handler, index = self.handler, self.index
        if not self.provider(handler["path"], "fastapi.Depends"):
            return False
        readonly = {
            id(call.args[0]) for _, _, _, call in handler["graph"].edges if call.args
        }
        argument_calls = [
            (
                path,
                node,
                self.canonical(
                    path, node.func, _enclosing_function(node, index.parents[path])
                ),
            )
            for path, tree in index.snapshots.items()
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and len(node.args) == 1 and not node.keywords
        ]
        # A captured application initializer may pass the app only to the
        # canonical Tortoise FastAPI registration API. Prove the complete helper
        # before treating its argument as a registration rather than an escape.
        for owner, call, _ in argument_calls:
            parent = index.parents[owner].get(id(call))
            if (
                not isinstance(parent, ast.Expr)
                or index.parents[owner].get(id(parent)) is not index.snapshots[owner]
            ):
                continue
            selected = _app_source_symbol(self.projection.symbols, owner, call.func)
            if not (
                selected
                and isinstance(selected[1], ast.FunctionDef)
                and not selected[1].decorator_list
                and len(selected[1].args.args) == 1
                and not selected[1].args.defaults
                and not selected[1].args.kwonlyargs
                and not selected[1].args.vararg
                and not selected[1].args.kwarg
                and len(selected[1].body) == 1
                and isinstance(selected[1].body[0], ast.Expr)
            ):
                continue
            helper_path, helper = selected
            registration = helper.body[0].value
            if not (
                isinstance(registration, ast.Call)
                and self.canonical(helper_path, registration.func, helper)
                == "tortoise.contrib.fastapi.register_tortoise"
                and self.provider(
                    helper_path, "tortoise.contrib.fastapi.register_tortoise"
                )
                and len(registration.args) == 1
                and isinstance(registration.args[0], ast.Name)
                and registration.args[0].id == helper.args.args[0].arg
                and all(
                    kw.arg
                    in {
                        "db_url",
                        "modules",
                        "generate_schemas",
                        "add_exception_handlers",
                    }
                    for kw in registration.keywords
                )
            ):
                continue
            try:
                for kw in registration.keywords:
                    ast.literal_eval(kw.value)
            except (ValueError, TypeError, SyntaxError):
                continue
            if self.projection._symbol_closed(
                [(helper.name, helper_path, helper.name)],
                self.value_type(),
                readonly_call=lambda node: node is call,
            ):
                readonly.add(id(call.args[0]))
        registrations = {id(call) for _, _, _, call in handler["graph"].edges}
        registrations.update(
            id(route["decorator"]) for route in handler["graph"].handlers
        )
        self.dependency_arguments = {
            id(node.args[0])
            for _, node, canonical in argument_calls
            if canonical == "fastapi.Depends"
        }
        readonly.update(self.dependency_arguments)
        readonly.update(
            id(node.args[0])
            for path, node, canonical in argument_calls
            if canonical
            in {
                "fastapi.testclient.TestClient",
                "starlette.testclient.TestClient",
            }
            and self.provider(path, canonical)
        )
        bindings = [(handler["path"], handler["function"].name)]
        bindings.extend(
            (owner, name) for _, owner, name in handler.get("dependency_providers", ())
        )
        if not all(
            self.provider(
                allocation["path"],
                (
                    "fastapi.FastAPI"
                    if allocation["kind"] == "application"
                    else "fastapi.APIRouter"
                ),
            )
            and self.projection._symbol_closed(
                [(allocation["name"], allocation["path"], allocation["name"])],
                self.value_type(),
                readonly_argument=lambda node: id(node) in readonly,
                readonly_call=lambda node: id(node) in registrations,
                inventory_projector=lambda tree,
                aliases,
                nodes,
                canonical: self.boundary_inventory(tree, aliases, nodes, canonical),
            )
            for allocation in (handler["application"], handler["receiver"])
        ):
            return False
        return not any(
            _captured_terminal_provider_mutation(
                index,
                audit,
                _django_name(self.projection.symbols, owner) + "." + name,
                local_binding=(owner, name),
                readonly_argument=lambda node, _aliases, _parents: id(node) in readonly,
            )
            for owner, name in set(bindings)
        )

    def boundary_inventory(self, tree, aliases, nodes, canonical):
        """Keep unrelated exact dependency slots distinct from credential overrides."""
        from .mock_fixture_provenance import _app_source_symbol
        from .credential_role_identity_effects import _enclosing_function
        from .review_audits import _resolved_ast_name

        owner = next(
            (
                path
                for path, captured in self.index.snapshots.items()
                if captured is tree
            ),
            None,
        )
        if owner is None:
            return nodes
        protected = {(self.handler["path"], self.handler["function"].name)}
        protected.update(
            (path, name)
            for _, path, name in self.handler.get("dependency_providers", ())
        )
        ignored = set()
        for node in nodes:
            if not (
                isinstance(node, ast.Subscript)
                and isinstance(node.ctx, ast.Store)
                and _resolved_ast_name(node.value, aliases)
                == canonical + ".dependency_overrides"
            ):
                continue
            selected = _app_source_symbol(
                self.projection.symbols,
                owner,
                node.slice,
                _enclosing_function(node, self.index.parents[owner]),
            )
            if (
                selected
                and isinstance(selected[1], (ast.FunctionDef, ast.AsyncFunctionDef))
                and (selected[0], selected[1].name) not in protected
            ):
                ignored.update(id(child) for child in ast.walk(node))
        return [node for node in nodes if id(node) not in ignored]

    def witness(self, statement, value):
        """Build a source-bound credential witness from validated origins and consumers."""
        from .semantic_credential_sensor import _signing_source_span

        handler = self.handler
        app, route_path = (
            handler["application"],
            handler.get("route_path", handler["path"]),
        )
        spans = [_signing_source_span(self.index, self.path, self.declaration)]
        spans.extend(self.consumer_transfers)
        spans.extend(
            {"path": step[1], "sha256": step[2], "span": list(step[3])}
            for step in value.trace
            if len(step) == 4 and step[0] == "CAPTURED_ORIGIN"
        )
        spans.extend(
            _signing_source_span(self.index, owner, node)
            for owner, node in [
                (app["path"], app["creation"]),
                *handler["registrations"],
                (route_path, handler["decorator"]),
                *handler.get("dependencies", ()),
                (handler["path"], statement),
            ]
        )
        framework, consumer_role = self.consumer or (
            "pyjwt",
            "verified_bearer_rejection",
        )
        return {
            "schema": (
                "factory.security.credential-default-authority.v1"
                if self.consumer
                else "factory.security.signing-default-authority.v1"
            ),
            "framework": framework,
            "source_role": (
                "published_literal_default"
                if self.consumer
                else "conditional_published_default"
            ),
            "credential_key": self.finding["facts"]["name"],
            "proof_scope": (
                "source_bound_operative_credential_default"
                if self.consumer
                else "source_bound_operative_signing_default"
            ),
            "consumer_role": consumer_role,
            "transfers": spans,
            "configuration_overrides": "POSSIBLE; DEFAULT_MAY_REACH",
            "deployment": "UNASSESSED",
            "runtime_execution": "not_performed",
        }


class _CredentialHandlerIndex:
    """Bind route and router declarations to captured application allocations."""

    _providers = {
        "flask.Flask": ("flask", "application"),
        "flask.Blueprint": ("flask", "router"),
        "fastapi.FastAPI": ("fastapi", "application"),
        "fastapi.APIRouter": ("fastapi", "router"),
    }
    _routes = frozenset(
        {"route", "get", "post", "put", "patch", "delete", "options", "head"}
    )

    @staticmethod
    def _django_feedback_settings():
        return {
            "MESSAGE_STORAGE": {
                "django.contrib.messages.storage.fallback.FallbackStorage",
                "django.contrib.messages.storage.cookie.CookieStorage",
            },
            "SIGNING_BACKEND": {"django.core.signing.TimestampSigner"},
            "SESSION_ENGINE": {
                "django.contrib.sessions.backends." + name
                for name in ("db", "cache", "cached_db", "file", "signed_cookies")
            },
            "SESSION_SERIALIZER": {
                "django.contrib.sessions.serializers.JSONSerializer"
            },
            "MESSAGE_LEVEL": {10, 20},
            "SECRET_KEY_FALLBACKS": {()},
        }

    def __init__(self, context, *, framework=None):
        from .semantic_credential_sensor import (
            _provider_identity_uncertain,
            _signing_framework_external,
            _signing_source_symbols,
        )

        self.context, self.index, self.framework = context, context["index"], framework
        self.symbols = _signing_source_symbols(context)
        self.allocations, self.edges, self.handlers = {}, [], []
        if self.symbols is None:
            return
        if framework == "django":
            self.symbols = (
                self.symbols
                if all(self.index.validate(p) for p in self.index.snapshots)
                else None
            )
            return
        for path, tree in self.index.snapshots.items():
            if not self.index.validate(path):
                self.allocations.clear()
                return
            scopes = [
                tree,
                *(
                    n
                    for n in tree.body
                    if isinstance(n, ast.FunctionDef) and not n.decorator_list
                ),
            ]
            for scope in scopes:
                for statement in scope.body:
                    if not (
                        isinstance(statement, ast.Assign)
                        and len(statement.targets) == 1
                        and isinstance(statement.targets[0], ast.Name)
                        and isinstance(statement.value, ast.Call)
                    ):
                        continue
                    provider = self.canonical(
                        path, statement.value.func, None if scope is tree else scope
                    )
                    role = self._providers.get(provider)
                    if (
                        role is None
                        or not _signing_framework_external(context, role[0])
                        or _provider_identity_uncertain(
                            tree,
                            context["aliases"][path],
                            roots=(provider,),
                            selected_paths=True,
                        )
                    ):
                        continue
                    name = statement.targets[0].id
                    from .semantic_credential_sensor import _signing_binding_occurrences

                    if (
                        len(_signing_binding_occurrences(context, path, scope, name))
                        != 1
                    ):
                        continue
                    self.allocations[(path, id(statement))] = {
                        "path": path,
                        "scope": scope,
                        "statement": statement,
                        "creation": statement.value,
                        "name": name,
                        "framework": role[0],
                        "kind": role[1],
                    }
        self._connect()

    def canonical(self, path, expression, function=None):
        """Resolve a captured expression to its canonical imported provider identity."""
        from .mock_fixture_provenance import _app_expression_name

        from .mock_fixture_provenance import _django_expr

        return (
            _app_expression_name(self.symbols, path, expression, function)
            or _django_expr(self.symbols, path, expression, function)
            or (
                self._django_reimport_identity(path, expression)
                if self.framework == "django" and function is None
                else None
            )
        )

    def _django_reimport_identity(self, path, expression):
        from .mock_fixture_provenance import _django_import_rows, _django_name
        from .credential_role_constructor_provider import binding_occurrences
        from .review_audits import _resolved_ast_name

        canonical = _resolved_ast_name(expression, self.context["aliases"][path])
        head = expression
        while isinstance(head, ast.Attribute):
            head = head.value
        if not isinstance(head, ast.Name):
            return None
        provider = self.context["aliases"][path].get(head.id)
        rows = binding_occurrences(self.index.snapshots[path].body, head.id)
        package = _django_name(self.symbols, path).rpartition(".")[0]
        return (
            canonical
            if provider
            and rows
            and all(
                (head.id, provider) in (_django_import_rows(row, package) or [])
                for row in rows
            )
            else None
        )

    def django_feedback(self, path, settings):
        """Evaluate the selected URL sequence, retaining only closed feedback effects."""
        from .mock_fixture_provenance import _django_assignment
        from .semantic_credential_sensor import _signing_resolve_module

        self.django_settings, self.django_settings_path = settings, path
        configuration = self._django_feedback_configuration(path, settings)
        if configuration is None:
            return None
        match _django_assignment(settings, "ROOT_URLCONF"):
            case [(root, ast.Constant(value=str()) as value)]:
                target = _signing_resolve_module(self.context, value, path)
            case _:
                return None
        routes = self._django_routes(target, (), "")
        if routes is None:
            return None
        imports = _django_setting_import_closure(self.context, path) or {
            "evidence": [],
            "finite_settings": [],
        }
        provider_refs = [row["source"] for row in imports["evidence"]]
        provider_refs.extend(
            {"path": row["path"], "sha256": row["sha256"], "span": row[field]}
            for row in imports["finite_settings"]
            for field in ("span", "declaration_span")
        )
        earlier = []
        for route, model, references, prefix in routes:
            shadowed = any(
                route == old or broad and route.startswith(old)
                for old, broad in earlier
            )
            if model and not shadowed:
                return {
                    "model": model,
                    "route": route,
                    "root": self._django_reference(path, root),
                    "configuration_imports": imports["evidence"],
                    "configuration_import_closure": self.context.get(
                        "selected_import_closures", {}
                    ).get(self.django_settings_path.as_posix(), {}),
                    "finite_configuration_fields": imports["finite_settings"],
                    "evidence": [
                        *configuration,
                        *provider_refs,
                        *(ref for _, _, refs, _ in routes for ref in refs),
                    ],
                }
            earlier.append((route.split("<", 1)[0], prefix or "<" in route))
        return None

    @staticmethod
    def django_middleware_order(values):
        positions = {item.value: n for n, item in enumerate(values)}
        if any(
            sum(item.value == name for item in values) != 1
            for name in (
                "django.contrib.sessions.middleware.SessionMiddleware",
                "django.contrib.auth.middleware.AuthenticationMiddleware",
                "django.contrib.messages.middleware.MessageMiddleware",
            )
        ):
            return False
        session = positions["django.contrib.sessions.middleware.SessionMiddleware"]
        return (
            session
            < positions["django.contrib.auth.middleware.AuthenticationMiddleware"]
            and session
            < positions["django.contrib.messages.middleware.MessageMiddleware"]
        )

    def _django_feedback_configuration(self, path, settings):
        from .mock_fixture_provenance import _django_assignment
        from .credential_role_constructor_provider import binding_occurrences

        if self.symbols is None:
            return None
        references = []
        for name, allowed in self._django_feedback_settings().items():
            rows = _django_assignment(settings, name)
            if not rows:
                if binding_occurrences(settings.body, name):
                    return None
                continue
            if len(rows) != 1:
                return None
            try:
                value = ast.literal_eval(rows[0][1])
                value = tuple(value) if isinstance(value, list) else value
                valid = value in allowed
            except (ValueError, TypeError):
                valid = False
            if not valid:
                return None
            references.append(self._django_reference(path, rows[0][0]))
        return references

    def _django_reference(self, path, node):
        return {
            "path": path.as_posix(),
            "sha256": self.index.inventory[path],
            "span": _span(node),
        }

    def _django_sequence(self, path):
        """Interpret ordered container state; every selected-container use is closed."""
        from .semantic_credential_sensor import _signing_provider_clear
        from .mock_fixture_provenance import _django_name

        tree, values, accepted = self.index.snapshots[path], {}, set()
        if not self._django_sequence_statements(path, tree.body, values, accepted):
            return None
        names = {name for name, value in values.items() if value is not None} | {
            "urlpatterns"
        }
        if any(
            isinstance(n, ast.Name) and n.id in names and id(n) not in accepted
            for n in ast.walk(tree)
        ):
            return None
        root = _django_name(self.symbols, path) + ".urlpatterns"
        if not all(
            _signing_provider_clear(
                owner,
                self.context["aliases"][p],
                "django",
                roots=(root,),
                context=self.context,
                settings_path=self.django_settings_path,
            )
            for p, owner in self.index.snapshots.items()
            if p != path
        ):
            return None
        return values.get("urlpatterns")

    def _django_sequence_statements(self, path, statements, values, accepted):
        for statement in statements:
            match statement:
                case ast.Assign(targets=[ast.Name() as target], value=value):
                    fragment = (
                        None
                        if isinstance(value, ast.Name)
                        else self._django_sequence_value(path, value, values, accepted)
                    )
                    values[target.id] = fragment
                    if fragment is not None:
                        accepted.add(id(target))
                case ast.AugAssign(
                    target=ast.Name() as target, op=ast.Add(), value=value
                ):
                    fragment = self._django_sequence_value(
                        path, value, values, accepted
                    )
                    if values.get(target.id) is None or fragment is None:
                        return False
                    values[target.id] = [*values[target.id], *fragment]
                    accepted.add(id(target))
                case ast.Expr(
                    value=ast.Call(
                        func=ast.Attribute(
                            value=ast.Name(id="urlpatterns") as target, attr="clear"
                        ),
                        args=[],
                        keywords=[],
                    )
                ):
                    values[target.id] = []
                    accepted.add(id(target))
                case ast.If():
                    if not self._django_sequence_branch(
                        path, statement, values, accepted
                    ):
                        return False
        return True

    def _django_sequence_branch(self, path, statement, values, accepted):
        if isinstance(statement.test, ast.Constant) and isinstance(
            statement.test.value, bool
        ):
            selected = statement.test.value
        elif self.canonical(path, statement.test) == "django.conf.settings.DEBUG":
            selected = self._django_setting("DEBUG", False)
        else:
            return not any(
                isinstance(n, ast.Name) and n.id == "urlpatterns"
                for n in ast.walk(statement)
            )
        if not isinstance(selected, bool):
            return False
        active, inactive = (
            (statement.body, statement.orelse)
            if selected
            else (statement.orelse, statement.body)
        )
        accepted.update(
            id(n)
            for item in inactive
            for n in ast.walk(item)
            if isinstance(n, ast.Name)
        )
        return self._django_sequence_statements(path, active, values, accepted)

    def _django_sequence_value(self, path, value, values, accepted):
        if isinstance(value, (ast.List, ast.Tuple)):
            return [(node, "") for node in value.elts]
        if isinstance(value, ast.Name) and value.id != "urlpatterns":
            accepted.add(id(value))
            return values.get(value.id)
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
            left = self._django_sequence_value(path, value.left, values, accepted)
            right = self._django_sequence_value(path, value.right, values, accepted)
            return [*left, *right] if left is not None and right is not None else None
        if not isinstance(value, ast.Call):
            return None
        provider = self.canonical(path, value.func)
        if (
            provider == "django.conf.urls.patterns"
            and value.args
            and not value.keywords
        ):
            first = value.args[0]
            return (
                [(node, first.value) for node in value.args[1:]]
                if isinstance(first, ast.Constant) and isinstance(first.value, str)
                else None
            )
        return self._django_static_routes(path, value, provider)

    def _django_setting(self, name, default=None):
        from .mock_fixture_provenance import _django_assignment
        from .credential_role_constructor_provider import binding_occurrences

        rows = _django_assignment(self.django_settings, name)
        if not rows:
            return (
                None
                if binding_occurrences(self.django_settings.body, name)
                else default
            )
        if not all(isinstance(value, ast.Constant) for _, value in rows):
            return None
        return rows[-1][1].value

    def _django_static_routes(self, path, call, provider):
        providers = {
            "django.conf.urls.static.static",
            "django.contrib.staticfiles.urls.static",
            "django.contrib.staticfiles.urls.staticfiles_urlpatterns",
        }
        if provider not in providers or not isinstance(
            self._django_setting("DEBUG", False), bool
        ):
            return None
        if not self._django_setting("DEBUG", False):
            return []
        if provider.endswith(".staticfiles_urlpatterns"):
            name = "STATIC_URL" if not call.args and not call.keywords else None
        else:
            name = self._django_static_argument(path, call)
        prefix = self._django_setting(name) if name else None
        if not isinstance(prefix, str) or not prefix:
            return None
        if urlsplit(prefix).netloc:
            return []
        reference = self._django_reference(path, call)
        return [({"prefix": prefix.lstrip("/"), "evidence": [reference]}, "")]

    def _django_static_argument(self, path, call):
        if len(call.args) != 1 or any(
            k.arg != "document_root"
            or not isinstance(k.value, (ast.Attribute, ast.Constant))
            for k in call.keywords
        ):
            return None
        canonical = self.canonical(path, call.args[0])
        return (
            canonical.rpartition(".")[2]
            if canonical
            in {"django.conf.settings.STATIC_URL", "django.conf.settings.MEDIA_URL"}
            else None
        )

    def _django_routes(self, path, stack, prefix):
        if path is None or path in stack or not self.index.validate(path):
            return None
        sequence = self._django_sequence(path)
        if sequence is None:
            return None
        result = []
        for node, callback_prefix in sequence:
            if isinstance(node, dict):
                rows = [(prefix + node["prefix"], None, node["evidence"], True)]
            else:
                rows = self._django_route(
                    path, node, (*stack, path), prefix, callback_prefix
                )
            if rows is None:
                return None
            result.extend(rows)
        return result

    def _django_route(self, path, node, stack, prefix, callback_prefix=""):
        if (
            not isinstance(node, ast.Call)
            or len(node.args) not in {2, 3}
            or any(k.arg not in {"name"} for k in node.keywords)
        ):
            return None
        provider = self.canonical(path, node.func)
        if provider not in {
            "django.urls.path",
            "django.urls.re_path",
            "django.conf.urls.url",
        }:
            return None
        if not isinstance(node.args[0], ast.Constant) or not isinstance(
            node.args[0].value, str
        ):
            return None
        pattern = (
            self._django_pattern(provider, node.args[0].value)
            if len(node.args) == 2 or self._django_static_keywords(node.args[2])
            else None
        )
        if pattern is None:
            return None
        route, prefix_match, exact = pattern
        route = prefix + route
        target, reference = node.args[1], self._django_reference(path, node)
        if isinstance(target, ast.Call) and self.canonical(path, target.func) in {
            "django.urls.include",
            "django.conf.urls.include",
            "django.urls.conf.include",
        }:
            return self._django_include(path, node, stack, route, reference, exact)
        if self.canonical(path, target) == "django.contrib.admin.site.urls":
            if node.args[0].value.endswith("$") or not exact:
                return None
            return [(route, "django.admin.feedback.v1", [reference], True)]
        if (
            callback_prefix
            and isinstance(target, ast.Constant)
            and isinstance(target.value, str)
        ):
            target = ast.Constant(value=callback_prefix + "." + target.value)
        if self._django_target(path, target) is None:
            return None
        effect = self._django_operation_feedback(path, target) if exact else None
        return [
            (
                route,
                "django.authenticated-operation.feedback.v1" if effect else None,
                [reference, *(effect or [])],
                prefix_match,
            )
        ]

    def _django_include(self, path, node, stack, route, reference, exact=True):
        from .semantic_credential_sensor import _signing_resolve_module

        target = node.args[1]
        if (
            not target.args
            or len(target.args) > 2
            or target.keywords
            or node.args[0].value.endswith("$")
        ):
            return None
        literal = target.args[0]
        if self.canonical(path, literal) == "django.contrib.admin.site.urls":
            return (
                [(route, "django.admin.feedback.v1", [reference], True)]
                if exact
                else None
            )
        if (
            isinstance(literal, ast.Constant)
            and literal.value == "django.contrib.auth.urls"
        ):
            return [(route, None, [reference], True)]
        if not isinstance(literal, ast.Constant):
            literal = ast.Constant(value=self.canonical(path, literal))
        child = _signing_resolve_module(self.context, literal, path)
        rows = self._django_routes(child, stack, route)
        return (
            [
                (r, m if exact else None, [reference, *refs], broad)
                for r, m, refs, broad in rows
            ]
            if rows is not None
            else None
        )

    def _django_pattern(self, provider, source):
        if provider == "django.urls.path":
            return source, False, "<" not in source
        try:
            re.compile(source)
        except re.error:
            return None
        literal = source.removeprefix("^").removesuffix("$")
        if literal and not source.startswith("^"):
            return "", True, False
        exact = re.fullmatch(r"[\w/:-]*", literal) is not None
        if exact:
            return literal, not source.endswith("$"), True
        # Only our fixed linear matcher reads the pattern text. The captured
        # regex is never executed, and an opaque prefix cannot produce an effect.
        head = re.match(r"\^([\w/:-]*)", source)
        prefix = head.group(1) if head and "|" not in source else ""
        if head and source[head.end() : head.end() + 1] in {"?", "*", "{"}:
            prefix = prefix[:-1]
        return prefix, True, False

    @staticmethod
    def _django_static_keywords(node):
        return isinstance(node, ast.Dict) and all(
            isinstance(key, ast.Constant)
            and isinstance(key.value, str)
            and isinstance(value, ast.Constant)
            for key, value in zip(node.keys, node.values)
        )

    def _django_feedback_handler(self, path, target):
        from .credential_role_constructor_provider import binding_occurrences

        selected = self._django_target(path, target)
        if selected is None or not isinstance(selected[1], ast.FunctionDef):
            return None
        owner, function = selected
        if len(function.decorator_list) != 1 or not function.args.args:
            return None
        decorator = function.decorator_list[0]
        guard = decorator.func if isinstance(decorator, ast.Call) else decorator
        if (
            self.canonical(owner, guard)
            != "django.contrib.auth.decorators.login_required"
        ):
            return None
        if isinstance(decorator, ast.Call) and (
            decorator.args
            or any(
                k.arg != "login_url" or not isinstance(k.value, ast.Constant)
                for k in decorator.keywords
            )
        ):
            return None
        request = function.args.args[0].arg
        if binding_occurrences(function.body, request):
            return None
        return owner, function, decorator, request

    def _django_target(self, path, target):
        """Resolve callback identity; never execute an unknown handler factory."""
        from .semantic_credential_sensor import (
            _signing_source_symbol,
            _signing_resolve_module,
        )
        from .credential_role_constructor_provider import binding_occurrences

        if isinstance(target, ast.Lambda):
            return path, target
        if isinstance(target, ast.Call):
            return self._django_cbv(path, target)
        if self.canonical(path, target) in {
            "django.contrib.auth.views." + name
            for name in (
                "login",
                "logout",
                "password_reset",
                "password_reset_done",
                "password_reset_confirm",
                "password_reset_complete",
                "password_change",
                "password_change_done",
            )
        }:
            return path, target
        if not (isinstance(target, ast.Constant) and isinstance(target.value, str)):
            selected = _signing_source_symbol(self.context, path, target)
            if selected is None:
                from .mock_fixture_provenance import _django_source_function

                selected = _django_source_function(
                    self.symbols, path, target
                ) or self._django_declared_target(path, target)
            return (
                selected
                if selected
                and isinstance(selected[1], (ast.FunctionDef, ast.AsyncFunctionDef))
                else None
            )
        module, _, name = target.value.rpartition(".")
        if target.value in {
            "django.contrib.auth.views." + value for value in ("login", "logout")
        }:
            return path, target
        owner = _signing_resolve_module(self.context, ast.Constant(value=module), path)
        if owner is None:
            return None
        rows = binding_occurrences(self.index.snapshots[owner].body, name)
        if len(rows) == 1 and isinstance(rows[0], ast.FunctionDef):
            return owner, rows[0]
        return None

    def _django_cbv(self, path, call):
        from .semantic_credential_sensor import _signing_source_symbol

        if (
            not isinstance(call.func, ast.Attribute)
            or call.func.attr != "as_view"
            or call.args
        ):
            return None
        if any(
            k.arg not in {"template_name", "next_page", "success_url", "login_url"}
            or not isinstance(k.value, ast.Constant)
            or not isinstance(k.value.value, str)
            for k in call.keywords
        ):
            return None
        provider = call.func.value
        canonical = self.canonical(path, provider)
        if self._django_view_provider(canonical):
            return path, provider
        selected = _signing_source_symbol(
            self.context, path, provider
        ) or self._django_declared_target(path, provider)
        return selected if selected and self._django_view_class(*selected, ()) else None

    def _django_view_provider(self, canonical):
        from .semantic_credential_sensor import _signing_framework_external

        if not isinstance(canonical, str):
            return False
        generic = {
            "View",
            "TemplateView",
            "RedirectView",
            "ListView",
            "DetailView",
            "FormView",
            "CreateView",
            "UpdateView",
            "DeleteView",
        }
        providers = {
            "django.views": {"View"},
            "django.views.generic": generic,
            "django.views.generic.base": {"View", "TemplateView", "RedirectView"},
            "django.views.generic.list": {"ListView"},
            "django.views.generic.detail": {"DetailView"},
            "django.views.generic.edit": {
                "FormView",
                "CreateView",
                "UpdateView",
                "DeleteView",
            },
            "django.contrib.auth.views": {
                "LoginView",
                "LogoutView",
                "PasswordResetView",
                "PasswordResetDoneView",
                "PasswordResetConfirmView",
                "PasswordResetCompleteView",
                "PasswordChangeView",
                "PasswordChangeDoneView",
            },
            "rest_framework.views": {"APIView"},
            "rest_framework.generics": {
                "GenericAPIView",
                "CreateAPIView",
                "ListAPIView",
                "RetrieveAPIView",
                "DestroyAPIView",
                "UpdateAPIView",
                "ListCreateAPIView",
                "RetrieveUpdateAPIView",
                "RetrieveDestroyAPIView",
                "RetrieveUpdateDestroyAPIView",
            },
        }
        module, _, name = canonical.rpartition(".")
        return name in providers.get(module, ()) and _signing_framework_external(
            self.context, canonical.split(".")[0]
        )

    def _django_view_class(self, path, cls, seen):
        from .semantic_credential_sensor import (
            _signing_source_symbol,
            _signing_provider_clear,
        )
        from .credential_role_constructor_provider import binding_occurrences
        from .mock_fixture_provenance import _django_name

        if (
            not isinstance(cls, ast.ClassDef)
            or (path, cls.name) in seen
            or cls.keywords
        ):
            return False
        if not all(
            self._django_view_decorator(path, decorator)
            for decorator in cls.decorator_list
        ):
            return False
        if any(
            binding_occurrences(cls.body, name)
            for name in (
                "as_view",
                "__new__",
                "__init_subclass__",
                "__getattribute__",
                "__getattr__",
            )
        ):
            return False
        canonical = _django_name(self.symbols, path) + "." + cls.name
        if not all(
            _signing_provider_clear(
                tree,
                self.context["aliases"][p],
                "django",
                roots=(canonical,),
                context=self.context,
                settings_path=self.django_settings_path,
            )
            for p, tree in self.index.snapshots.items()
        ):
            return False
        from .review_integrity import _security_apply_import_bindings
        from . import review_audits as audit

        imports = _security_apply_import_bindings(
            self.index.snapshots[path].body, {}, cls, audit
        )
        bases = [
            audit._resolved_ast_name(base, imports) or self.canonical(path, base)
            for base in cls.bases
        ]
        candidates = [base for base in bases if self._django_view_provider(base)]
        local = [
            _signing_source_symbol(self.context, path, base)
            for base, name in zip(cls.bases, bases)
            if not self._django_view_provider(name)
            and not (name or "").startswith("django.contrib.auth.mixins.")
        ]
        inherited = [
            self._django_view_class(*selected, (*seen, (path, cls.name)))
            if selected
            else False
            for selected in local
        ]
        return bool(candidates or any(inherited)) and all(inherited)

    def _django_declared_target(self, path, target):
        from .semantic_credential_sensor import _signing_resolve_module
        from .credential_role_constructor_provider import binding_occurrences

        canonical = self.canonical(path, target)
        module, _, name = (canonical or "").rpartition(".")
        owner = _signing_resolve_module(self.context, ast.Constant(value=module), path)
        if owner is None:
            return None
        tree = self.index.snapshots[owner]
        rows = binding_occurrences(tree.body, name)
        selected = max(rows, key=lambda node: node.lineno) if rows else None
        return (
            (owner, selected)
            if selected in tree.body
            and isinstance(
                selected, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            )
            and self._django_callable_closed(owner, selected)
            else None
        )

    def _django_callable_closed(self, owner, declaration):
        from .semantic_credential_sensor import _provider_identity_uncertain
        from .mock_fixture_provenance import _django_name
        from . import review_audits as audit

        canonical = _django_name(self.symbols, owner) + "." + declaration.name
        for path, tree in self.index.snapshots.items():
            aliases = dict(self.context["aliases"][path])
            excluded = set()
            if path == owner:
                aliases[declaration.name] = canonical
                excluded.update(
                    id(n)
                    for base in getattr(declaration, "bases", ())
                    for n in ast.walk(base)
                )
            nodes = list(ast.walk(tree))
            excluded.update(
                id(child)
                for node in nodes
                if isinstance(node, ast.Call)
                and len(node.args) >= 2
                and audit._resolved_ast_name(node.func, aliases)
                in {"django.urls.path", "django.urls.re_path", "django.conf.urls.url"}
                and audit._resolved_ast_name(node.args[1], aliases) == canonical
                for child in ast.walk(node.args[1])
            )
            if _provider_identity_uncertain(
                tree,
                aliases,
                roots=(canonical,),
                nodes=[node for node in nodes if id(node) not in excluded],
                selected_paths=True,
            ):
                return False
        return True

    def _django_view_decorator(self, path, decorator):
        if not isinstance(decorator, ast.Call) or len(decorator.args) != 1:
            return False
        if (
            self.canonical(path, decorator.func)
            != "django.utils.decorators.method_decorator"
        ):
            return False
        return (
            self.canonical(path, decorator.args[0])
            in {
                "django.views.decorators.csrf.csrf_exempt",
                "django.views.decorators.http.require_POST",
            }
            and len(decorator.keywords) == 1
            and decorator.keywords[0].arg == "name"
            and isinstance(decorator.keywords[0].value, ast.Constant)
            and decorator.keywords[0].value.value == "dispatch"
        )

    def _django_operation_feedback(self, path, target):
        selected = self._django_feedback_handler(path, target)
        if selected is None:
            return None
        owner, function, decorator, request = selected
        for statement in ast.walk(function):
            from .credential_role_identity_effects import _enclosing_function

            if (
                _enclosing_function(statement, self.index.parents[owner])
                is not function
            ):
                continue
            if not isinstance(statement, ast.Expr) or not isinstance(
                statement.value, ast.Call
            ):
                continue
            call = statement.value
            if not self._django_feedback_call(owner, function, call, request):
                continue
            parent = self.index.parents[owner].get(id(statement))
            body = getattr(parent, "body", [])
            preceding = body[: body.index(statement)] if statement in body else []
            for item in preceding:
                operation = self._django_operation(owner, function, item)
                if operation:
                    return [
                        self._django_reference(owner, decorator),
                        self._django_reference(owner, function),
                        self._django_reference(owner, call),
                        *operation,
                    ]
        return None

    def _django_feedback_call(self, path, function, call, request):
        from .semantic_credential_sensor import (
            _security_control_branch_possible,
            _security_no_prior_terminator,
        )

        provider = self.canonical(path, call.func, function)
        if provider not in {
            "django.contrib.messages." + name
            for name in ("success", "info", "warning", "error")
        }:
            return False
        if (
            len(call.args) != 2
            or call.keywords
            or not isinstance(call.args[0], ast.Name)
            or call.args[0].id != request
        ):
            return False
        if (
            not isinstance(call.args[1], ast.Constant)
            or not isinstance(call.args[1].value, str)
            or not call.args[1].value
        ):
            return False
        child = call
        while (parent := self.index.parents[path].get(id(child))) is not None:
            if not _security_control_branch_possible(
                parent, child
            ) or not _security_no_prior_terminator(parent, child):
                return False
            child = parent
        return True

    def _django_operation(self, path, function, statement):
        """Recognize framework Model/ModelForm save/delete, not arbitrary method names."""
        from .semantic_credential_sensor import _signing_source_symbol
        from .credential_role_constructor_provider import binding_occurrences
        from .semantic_credential_sensor import _signing_provider_clear
        from .mock_fixture_provenance import _django_name

        if not isinstance(statement, ast.Expr) or not isinstance(
            statement.value, ast.Call
        ):
            return False
        call = statement.value
        if (
            not isinstance(call.func, ast.Attribute)
            or call.func.attr not in {"save", "delete"}
            or not isinstance(call.func.value, ast.Name)
        ):
            return False
        bindings = [
            self.index.parents[path].get(id(node))
            if isinstance(node, ast.Name)
            else node
            for node in binding_occurrences(function.body, call.func.value.id)
        ]
        if not bindings or any(
            not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call)
            for node in bindings
        ):
            return False
        constructors = [node.value for node in bindings]
        from .credential_role_constructor_provider import binding_dominates

        if not any(
            binding_dominates(node, call, self.index.parents[path], function)
            for node in bindings
        ):
            return False
        references = []
        for constructor in constructors:
            provider = constructor.func
            if (
                isinstance(provider, ast.Attribute)
                and provider.attr == "get"
                and isinstance(provider.value, ast.Attribute)
                and provider.value.attr == "objects"
            ):
                provider = provider.value.value
            selected = _signing_source_symbol(self.context, path, provider, function)
            if selected is None or not isinstance(selected[1], ast.ClassDef):
                return False
            owner, cls = selected
            bases = {self.canonical(owner, base) for base in cls.bases}
            canonical = _django_name(self.symbols, owner) + "." + cls.name
            if not (
                bases
                & {
                    "django.db.models.Model",
                    "django.forms.ModelForm",
                    "django.forms.models.ModelForm",
                }
            ) or binding_occurrences(cls.body, call.func.attr):
                return False
            if not all(
                _signing_provider_clear(
                    tree,
                    self.context["aliases"][p],
                    "django",
                    roots=(canonical,),
                    context=self.context,
                    settings_path=self.django_settings_path,
                )
                for p, tree in self.index.snapshots.items()
            ):
                return False
            references.extend(
                [
                    self._django_reference(owner, cls),
                    self._django_reference(path, constructor),
                ]
            )
        return [self._django_reference(path, call), *references]

    def binding(self, path, expression, function=None):
        """Resolve the captured declaration that dominates a selected credential use."""
        from .mock_fixture_provenance import _app_local_assignment
        from .credential_role_constructor_provider import binding_dominates

        if function is not None and isinstance(expression, ast.Name):
            local = _app_local_assignment(function, expression.id)
            if local is not None:
                if not binding_dominates(
                    local, expression, self.index.parents[path], function
                ):
                    return None
                return self.allocations.get((path, id(local)))
        from .semantic_credential_sensor import _signing_source_symbol

        selected = _signing_source_symbol(self.context, path, expression, function)
        if (
            selected is None
            and isinstance(expression, ast.Attribute)
            and isinstance(expression.value, ast.Name)
        ):
            from .credential_role_constructor_provider import binding_occurrences
            from .import_context import (
                captured_import_inventory,
                resolve_import_source,
                import_source_choices,
            )

            imports = binding_occurrences(
                self.index.snapshots[path].body, expression.value.id
            )
            if (
                len(imports) == 1
                and isinstance(imports[0], ast.ImportFrom)
                and not imports[0].level
            ):
                imported = next(
                    (
                        item.name
                        for item in imports[0].names
                        if (item.asname or item.name) == expression.value.id
                    ),
                    None,
                )
                target = resolve_import_source(
                    self.index.root,
                    path,
                    imports[0],
                    imports[0].module,
                    captured_import_inventory(self.index),
                    imported=imported,
                    captured=True,
                )
                if target is None:
                    choices = import_source_choices(
                        self.index.root,
                        path,
                        imports[0],
                        imports[0].module,
                        imported,
                        captured_inventory=captured_import_inventory(self.index),
                    )
                    children = {
                        candidate
                        for candidate, kind in choices
                        if kind == "child" and candidate in self.index.snapshots
                    }
                    packages = {
                        candidate
                        for candidate, kind in choices
                        if kind == "package" and candidate in self.index.snapshots
                    }
                    if len(children) == len(packages) == 1 and all(
                        isinstance(item, ast.Pass)
                        or isinstance(item, ast.Expr)
                        and isinstance(item.value, ast.Constant)
                        and isinstance(item.value.value, str)
                        for item in self.index.snapshots[next(iter(packages))].body
                    ):
                        target = next(iter(children))
                tree = self.index.snapshots.get(target)
                rows = (
                    binding_occurrences(tree.body, expression.attr)
                    if tree is not None
                    else []
                )
                if len(rows) == 1:
                    declaration = rows[0]
                    if isinstance(declaration, ast.Name):
                        declaration = self.index.parents[target].get(id(declaration))
                    selected = target, declaration
        return (
            self.allocations.get((selected[0], id(selected[1]))) if selected else None
        )

    def boundaries(self):
        """Follow exact dependency registrations, sharing one bounded route graph."""
        from .semantic_credential_sensor import _signing_source_symbol

        pending, seen = list(self.handlers), set()
        while pending and len(seen) < 512:
            handler = pending.pop()
            path, function = handler["path"], handler["function"]
            marker = (path, id(function), id(handler["decorator"]))
            if marker in seen:
                continue
            seen.add(marker)
            yield handler
            for value in (*function.args.defaults, *function.args.kw_defaults):
                if not (
                    isinstance(value, ast.Call)
                    and len(value.args) == 1
                    and not value.keywords
                    and self.canonical(path, value.func, function) == "fastapi.Depends"
                ):
                    continue
                chain = []
                selected = _signing_source_symbol(
                    self.context, path, value.args[0], function, provider_chain=chain
                )
                if selected is None and isinstance(value.args[0], ast.Name):
                    from .credential_role_constructor_provider import (
                        binding_occurrences,
                    )
                    from .import_context import (
                        captured_import_inventory,
                        import_source_choices,
                    )

                    bindings = binding_occurrences(
                        self.index.snapshots[path].body, value.args[0].id
                    )
                    if (
                        len(bindings) == 1
                        and isinstance(bindings[0], ast.ImportFrom)
                        and not bindings[0].level
                    ):
                        imported = next(
                            (
                                item.name
                                for item in bindings[0].names
                                if (item.asname or item.name) == value.args[0].id
                            ),
                            None,
                        )
                        module = bindings[0].module or ""
                        root = handler["application"]["path"].parent
                        parts = module.split(".")
                        if imported and all(part.isidentifier() for part in parts):
                            choices = {
                                candidate
                                for candidate in (
                                    root.joinpath(*parts).with_suffix(".py"),
                                    root.joinpath(*parts) / "__init__.py",
                                )
                                if candidate in self.index.snapshots
                            }
                            alternatives = {
                                candidate
                                for candidate, _ in import_source_choices(
                                    self.index.root,
                                    path,
                                    bindings[0],
                                    module,
                                    None,
                                    captured_inventory=captured_import_inventory(
                                        self.index
                                    ),
                                )
                                if candidate in self.index.snapshots
                            }
                            if (
                                len(choices) == 1
                                and alternatives == choices
                                and all(
                                    root.joinpath(*parts[:end]) / "__init__.py"
                                    in self.index.snapshots
                                    and root.joinpath(*parts[:end]).with_suffix(".py")
                                    not in self.index.snapshots
                                    for end in range(1, len(parts))
                                )
                                and len(
                                    rows := binding_occurrences(
                                        self.index.snapshots[next(iter(choices))].body,
                                        imported,
                                    )
                                )
                                == 1
                                and isinstance(
                                    rows[0], (ast.FunctionDef, ast.AsyncFunctionDef)
                                )
                            ):
                                target = next(iter(choices))
                                selected = target, rows[0]
                                chain.append(
                                    (module + "." + imported, target, imported)
                                )
                if (
                    selected
                    and isinstance(selected[1], (ast.FunctionDef, ast.AsyncFunctionDef))
                    and not selected[1].decorator_list
                ):
                    pending.append(
                        {
                            **handler,
                            "path": selected[0],
                            "function": selected[1],
                            "route_path": handler.get("route_path", path),
                            "dependency_providers": (
                                *handler.get("dependency_providers", ()),
                                *chain,
                            ),
                            "dependencies": (
                                *handler.get("dependencies", ()),
                                (path, value),
                            ),
                        }
                    )

    def _connect(self):
        from .credential_role_identity_effects import _enclosing_function
        from .semantic_credential_sensor import _flask_path_conditions_clear

        for path, tree in self.index.snapshots.items():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(
                    node.func, ast.Attribute
                ):
                    continue
                function = _enclosing_function(node, self.index.parents[path])
                receiver = self.binding(path, node.func.value, function)
                if receiver is None:
                    continue
                expected = (
                    "register_blueprint"
                    if receiver["framework"] == "flask"
                    else "include_router"
                )
                if (
                    node.func.attr == expected
                    and node.args
                    and not any(isinstance(a, ast.Starred) for a in node.args)
                ):
                    child = self.binding(path, node.args[0], function)
                    if (
                        child
                        and child["kind"] == "router"
                        and child["framework"] == receiver["framework"]
                        and _flask_path_conditions_clear(function or tree, node)
                    ):
                        self.edges.append((receiver, child, path, node))
        self._connect_routes()

    def _connect_routes(self):
        from .semantic_credential_sensor import _flask_path_conditions_clear

        for path, tree in self.index.snapshots.items():
            for function in ast.walk(tree):
                if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                routes = [
                    decorator
                    for decorator in function.decorator_list
                    if isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr in self._routes
                ]
                if len(routes) != 1:
                    continue
                decorator = routes[0]
                receiver = self.binding(path, decorator.func.value)
                if (
                    receiver is None
                    or receiver["framework"] == "fastapi"
                    and (
                        decorator.func.attr == "route"
                        or len(function.decorator_list) != 1
                    )
                    or not _flask_path_conditions_clear(tree, function)
                ):
                    # FastAPI.route registers a Starlette Route, which does not
                    # execute Depends; Flask.route remains an HTTP boundary.
                    continue
                for root, registrations in self._roots(receiver):
                    self.handlers.append(
                        {
                            "path": path,
                            "function": function,
                            "decorator": decorator,
                            "receiver": receiver,
                            "application": root,
                            "registrations": registrations,
                            "graph": self,
                        }
                    )

    def _roots(self, receiver, seen=()):
        marker = (receiver["path"], id(receiver["statement"]))
        if marker in seen or len(seen) >= 12:
            return
        if receiver["kind"] == "application":
            yield receiver, []
        for parent, child, path, call in self.edges:
            if child is receiver:
                for root, registrations in self._roots(parent, (*seen, marker)):
                    yield root, [*registrations, (path, call)]


def _flask_route_bound_to_app(function, receiver):
    return any(
        isinstance(value, ast.Attribute)
        and value.attr == "route"
        and isinstance(value.value, ast.Name)
        and value.value.id == receiver
        for decorator in function.decorator_list
        for value in [decorator.func if isinstance(decorator, ast.Call) else decorator]
    )


def _flask_session_authority_witness(path, tree, context, app, credential_key):
    from .semantic_credential_sensor import (
        _flask_authority_provider_clear,
        _flask_config_mutated,
        _flask_configuration_reloaded,
        _flask_login_wrapper,
        _flask_protected_route,
        _flask_route_bound_to_app,
    )
    from .review_integrity import _security_scope_request_aliases
    from .credential_role_constructor_provider import (
        _captured_terminal_provider_mutation,
    )
    from .runtime_audit_integrity import _conditional_module_name
    from . import review_audits as audit

    graph = _CredentialHandlerIndex(context)
    configuration = context["index"].snapshots[app.get("configuration_path", path)]
    application_closed = not _captured_terminal_provider_mutation(
        context["index"],
        audit,
        _conditional_module_name(context["index"].relative(path))
        + "."
        + app["receiver"],
        local_binding=(path, app["receiver"]),
    )
    candidates = {(path, app["receiver"]): tree}
    for handler in graph.handlers:
        allocation = handler["application"]
        decorator = handler["decorator"]
        if (
            allocation["path"] == path
            and allocation["creation"] is app["creation"]
            and handler["receiver"] is allocation
            and isinstance(decorator.func.value, ast.Name)
        ):
            owner = handler["path"]
            candidates[(owner, decorator.func.value.id)] = context["index"].snapshots[
                owner
            ]
    for (owner, receiver), source in candidates.items():
        if (
            owner != path
            and not application_closed
            or not context["index"].validate(owner)
            or not _flask_authority_provider_clear(owner, source, context)
            or owner != path
            and (
                _flask_config_mutated(source, receiver, {credential_key, "SECRET_KEY"})
                or _flask_configuration_reloaded(
                    source,
                    receiver,
                    app["configuration_path"],
                    context,
                    {credential_key, "SECRET_KEY"},
                    owner,
                )
            )
        ):
            continue
        aliases = context["aliases"][owner]
        login_wrapper = _flask_login_wrapper(source, aliases)
        protected = _flask_protected_route(source, receiver, aliases)
        if (
            login_wrapper is None
            or protected is None
            or owner != path
            and len(protected.decorator_list) != 2
        ):
            continue
        for route in source.body:
            if (
                not isinstance(route, (ast.FunctionDef, ast.AsyncFunctionDef))
                or not _flask_route_bound_to_app(route, receiver)
                or owner != path
                and len(route.decorator_list) != 1
            ):
                continue
            witness = _flask_route_authority(
                route,
                source,
                receiver,
                credential_key,
                aliases,
                _security_scope_request_aliases,
                configuration,
            )
            if witness is not None:
                return {
                    **witness,
                    "nodes": [
                        (path, app["creation"]),
                        (path, app["load"]),
                        (owner, witness["comparison"]),
                        (owner, witness["grant"]),
                        (owner, login_wrapper["guard"]),
                        (owner, protected),
                    ],
                    "login_wrapper": login_wrapper["guard"],
                    "protected_route": protected,
                }
    return None


def _flask_route_authority(
    route, tree, receiver, credential_key, aliases, alias_reader, configuration=None
):
    from .semantic_credential_sensor import _flask_path_conditions_clear

    if not isinstance(route, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    for guard in ast.walk(route):
        if not isinstance(guard, ast.If) or not _flask_path_conditions_clear(
            tree, guard
        ):
            continue
        witness = _flask_guard_authority(
            guard,
            route,
            tree,
            receiver,
            credential_key,
            aliases,
            alias_reader,
            configuration,
        )
        if witness is not None:
            return witness
    return None


def _flask_guard_authority(
    guard,
    route,
    tree,
    receiver,
    credential_key,
    aliases,
    alias_reader,
    configuration=None,
):
    from .semantic_credential_sensor import (
        _flask_password_config_comparison,
        _flask_config_key_declaration_in_tree,
        _flask_session_grant,
    )

    comparison = _flask_password_config_comparison(
        guard.test, receiver, aliases, route, guard, alias_reader
    )
    if comparison is None:
        return None
    password_key, equality = comparison
    if (
        _flask_config_key_declaration_in_tree(
            tree if configuration is None else configuration, password_key
        )
        is None
    ):
        return None
    grant = _flask_session_grant(guard.body, aliases, route, alias_reader)
    if grant is None or credential_key not in {password_key, "SECRET_KEY"}:
        return None
    return {"password_key": password_key, "comparison": equality, "grant": grant}


def _flask_credential_authority_for_key(
    finding, context, index, path, declaration, session_secret, key
):
    from .semantic_credential_sensor import (
        _flask_configured_apps,
        _flask_session_authority_witness,
        _flask_config_key_declaration,
        _literal_credential,
    )

    for app in _flask_configured_apps(
        path, context, {key, "SECRET_KEY"}, declaration=session_secret
    ):
        app_path, tree = app["path"], app["tree"]
        authority = _flask_session_authority_witness(app_path, tree, context, app, key)
        if key == "SECRET_KEY":
            login_authority = _flask_login_session_authority_witness(
                app_path, tree, context, app
            )
            if login_authority is not None:
                return _flask_credential_authority_witness(
                    index,
                    path,
                    declaration,
                    session_secret,
                    None,
                    app,
                    login_authority,
                    key,
                )
        if authority is None:
            continue
        password_key = authority["password_key"]
        password_declaration = _flask_config_key_declaration(index, path, password_key)
        if password_declaration is None or not _literal_credential(
            password_declaration.value
        ):
            continue
        if key not in {"SECRET_KEY", password_key}:
            continue
        return _flask_credential_authority_witness(
            index,
            path,
            declaration,
            session_secret,
            password_declaration,
            app,
            authority,
            key,
        )
    return None


def _flask_login_session_authority_witness(path, tree, context, app):
    """Bind a configured Flask app to Flask-Login session creation and protection."""
    from .semantic_credential_sensor import (
        _signing_framework_external,
        _flask_module_aliases,
        _provider_identity_uncertain,
        _flask_path_conditions_clear,
        _flask_route_bound_to_app,
        _flask_authority_provider_clear,
        _flask_config_mutated,
        _flask_configuration_reloaded,
    )

    if not _signing_framework_external(context, "flask_login"):
        return None
    aliases = _flask_module_aliases(path, tree, context)
    from .review_integrity import security_call_name
    from .review_audits import _resolved_ast_name

    scope = app["scope"]
    statements = scope.body
    executable = [
        node
        for statement in statements
        if not isinstance(
            statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        )
        for node in ast.walk(statement)
    ]
    managers = [
        node
        for node in executable
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.Call)
        and security_call_name(node.value, aliases) == "flask_login.LoginManager"
        and not node.value.args
        and not node.value.keywords
    ]
    manager = managers[0].targets[0].id if len(managers) == 1 else None
    initialized = [
        node
        for node in executable
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "init_app"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == manager
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == app["receiver"]
    ]
    if (
        manager is None
        or sum(
            isinstance(node, ast.Name)
            and node.id == manager
            and isinstance(node.ctx, (ast.Store, ast.Del))
            for node in ast.walk(scope)
        )
        != 1
        or _provider_identity_uncertain(
            scope,
            {**aliases, manager: "flask_login.LoginManagerInstance"},
            roots=("flask_login.LoginManagerInstance",),
        )
        or len(initialized) != 1
    ):
        return None
    login_users = []
    protected = []
    graph = _CredentialHandlerIndex(context)
    candidates = [
        (path, tree, function, app["receiver"])
        for function in scope.body
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    from .credential_role_constructor_provider import (
        _captured_terminal_provider_mutation,
    )
    from .runtime_audit_integrity import _conditional_module_name
    from . import review_audits as audit

    manager_closed = not _captured_terminal_provider_mutation(
        context["index"],
        audit,
        _conditional_module_name(context["index"].relative(path)) + "." + manager,
        local_binding=(path, manager),
    )
    manager_closed = manager_closed and not _captured_terminal_provider_mutation(
        context["index"],
        audit,
        _conditional_module_name(context["index"].relative(path))
        + "."
        + app["receiver"],
        local_binding=(path, app["receiver"]),
        readonly_argument=lambda node, _aliases, parents: (
            parents.get(id(node)) is initialized[0] and node is initialized[0].args[0]
        ),
    )
    for handler in graph.handlers if manager_closed else ():
        owner, allocation = handler["path"], handler["application"]
        decorator = handler["decorator"]
        if (
            owner == path
            or allocation["path"] != path
            or allocation["creation"] is not app["creation"]
            or handler["receiver"] is not allocation
            or not isinstance(decorator.func.value, ast.Name)
        ):
            continue
        source = context["index"].snapshots[owner]
        receiver = decorator.func.value.id
        if (
            _flask_authority_provider_clear(owner, source, context)
            and not _flask_config_mutated(source, receiver, {"SECRET_KEY"})
            and not _flask_configuration_reloaded(
                source,
                receiver,
                app["configuration_path"],
                context,
                {"SECRET_KEY"},
                owner,
            )
        ):
            candidates.append((owner, source, handler["function"], receiver))
    for owner, source, function, receiver in candidates:
        aliases = _flask_module_aliases(owner, source, context)
        if any(
            not (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr == "route"
                and isinstance(decorator.func.value, ast.Name)
                and decorator.func.value.id == receiver
            )
            and _resolved_ast_name(decorator, aliases) != "flask_login.login_required"
            for decorator in function.decorator_list
        ) or not _flask_route_bound_to_app(function, receiver):
            continue
        login_users.extend(
            (owner, function, node)
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and security_call_name(node, aliases) == "flask_login.login_user"
            and _flask_path_conditions_clear(function, node)
        )
        decorators = [
            _resolved_ast_name(
                decorator.func if isinstance(decorator, ast.Call) else decorator,
                aliases,
            )
            for decorator in function.decorator_list
        ]
        if "flask_login.login_required" not in decorators or not any(
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr == "route"
            and isinstance(decorator.func.value, ast.Name)
            and decorator.func.value.id == receiver
            for decorator in function.decorator_list[
                : decorators.index("flask_login.login_required")
            ]
        ):
            continue
        protected.append(
            (
                owner,
                function,
                function.decorator_list[decorators.index("flask_login.login_required")],
            )
        )
    if len(login_users) != 1 or not protected:
        return None
    login_path, login_function, login_call = login_users[0]
    return {
        "consumer_kind": "flask_login_session",
        "nodes": [
            (path, app["creation"]),
            (path, app["load"]),
            (path, initialized[0]),
            (login_path, login_function),
            (login_path, login_call),
            *(
                (owner, node)
                for owner, function, decorator in protected
                for node in (function, decorator)
            ),
        ],
    }


def _flask_credential_authority_witness(
    index, path, declaration, session_secret, password_declaration, app, authority, key
):
    from .semantic_credential_sensor import _signing_source_span

    nodes = [(path, declaration)]
    if session_secret is not declaration:
        nodes.append((path, session_secret))
    if "nodes" in authority:
        if password_declaration is not None:
            nodes.append((path, password_declaration))
        nodes.extend(authority["nodes"])
        role = (
            {"password_key": authority["password_key"]}
            if "password_key" in authority
            else {"consumer_role": authority["consumer_kind"]}
        )
    else:
        nodes.extend(
            (path, node)
            for node in (
                app["creation"],
                app["load"],
                password_declaration,
                authority["comparison"],
                authority["grant"],
                authority["login_wrapper"],
                authority["protected_route"],
            )
        )
        role = {"password_key": authority["password_key"]}
    return {
        "framework": "flask",
        "credential_key": key,
        **role,
        "transfers": [
            _signing_source_span(index, owner, node) for owner, node in nodes
        ],
        "proof_scope": "source_bound_flask_session_authority",
        "runtime_execution": "not_performed",
        "deployment": "UNASSESSED",
        "claim": "Captured source binds a literal configuration default to same-app session authority.",
    }
