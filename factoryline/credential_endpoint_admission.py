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
            if callable(value)
        )
        + _callable_values(
            (
                "operative_signing_default_evidence",
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
    from .semantic_credential_sensor import (
        signing_configuration_evidence,
        _signing_resolve_module,
    )
    from .mock_fixture_provenance import _django_assignment
    from .review_audits import _resolved_ast_name

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
    observation = signing_configuration_evidence(finding, context)
    match observation:
        case {"consumer_role": "django.SECRET_KEY"}:
            # A captured distribution can select another runtime or use a demo app;
            # its deployment selection remains unresolved rather than being called safe.
            distributions = [
                call
                for source_path, tree in index.snapshots.items()
                for call in ast.walk(tree)
                if isinstance(call, ast.Call)
                if _resolved_ast_name(call.func, context["aliases"][source_path])
                in {"setuptools.setup", "distutils.core.setup"}
            ]
            match (bool(distributions), tuple(context.get("captured", {}))):
                case (True, _):
                    return None
                case (_, names) if any(
                    name.endswith(("pyproject.toml", "setup.cfg")) for name in names
                ):
                    return None
            material = declaration.value.value.strip()
            if re.fullmatch(
                r"(?i)(?:your|replace|change|example|placeholder)(?:[ _-]+[a-z]+)*",
                material,
            ):
                return None
            settings = index.snapshots[path]
            required = {
                "INSTALLED_APPS": {"django.contrib.auth", "django.contrib.sessions"},
                "MIDDLEWARE": {
                    "django.contrib.sessions.middleware.SessionMiddleware",
                    "django.contrib.auth.middleware.AuthenticationMiddleware",
                },
            }
            consumers = []
            for name, authorities in required.items():
                match _django_assignment(settings, name):
                    case [
                        (statement, ast.List(elts=values) | ast.Tuple(elts=values))
                    ] if all(isinstance(item, ast.Constant) for item in values):
                        pass
                    case _:
                        return None
                if not authorities.issubset(
                    {item.value for item in values if isinstance(item.value, str)}
                ) or any(
                    isinstance(node, ast.Name)
                    and node.id == name
                    and isinstance(node.ctx, ast.Load)
                    for node in ast.walk(settings)
                ):
                    return None
                consumers.append(
                    {
                        "path": path.as_posix(),
                        "sha256": index.inventory[path],
                        "span": _span(statement),
                    }
                )
            foreign_access = (
                node
                for source_path, tree in index.snapshots.items()
                for node in ast.walk(tree)
                if isinstance(node, (ast.Name, ast.Attribute))
                for module, _, member in (
                    _resolved_ast_name(
                        node, context["aliases"][source_path]
                    ).rpartition("."),
                )
                if member in required
                if _signing_resolve_module(
                    context,
                    ast.Constant(value=module),
                )
                == path
            )
            return (
                None
                if next(foreign_access, None) is not None
                else {
                    "schema": "factory.security.framework-session-authority.v1",
                    "proof_scope": "source_bound_standalone_framework_session_default",
                    "framework": "django",
                    "credential_key": "SECRET_KEY",
                    "source_role": "published_literal_default",
                    "consumer_role": "configured_authentication_session_signing",
                    "transfers": [
                        observation["declaration"],
                        *consumers,
                        *observation["transfers"],
                    ],
                    "runtime_execution": "not_performed",
                    "deployment": "UNASSESSED",
                    "distribution_runtime_selection": "no_captured_distribution_declaration",
                }
            )
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

    def canonical(self, path, node, function):
        """Resolve a captured expression to its canonical imported provider identity."""
        from .mock_fixture_provenance import _app_expression_name

        return _app_expression_name(self.projection.symbols, path, node, function)

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

    def field(self, node, environment, path, function, projection):
        """Read a captured credential field only when its receiver identity is closed."""
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
                return True, self.value_type(
                    inert_kind="scalar",
                    scalar_kind="boolean",
                    trace=tuple(step for _, value in operands for step in value.trace),
                )
        return False, None

    def call(self, node, environment, path, function, projection):
        """Interpret a supported captured provider call without executing target code."""
        canonical = self.canonical(path, node.func, function)
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

    def construct(self, node, environment, path, function, projection, canonical):
        """Resolve supported credential construction and retain the complete origin chain."""
        from .mock_fixture_provenance import _app_source_symbol

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

    def verify(self, node, environment, path, function, projection, canonical):
        """Require a source-bound verifier and its exact credential input binding."""
        if canonical == "jwt.decode" and self.provider(path, canonical):
            if (
                len(node.args) != 2
                or len(node.keywords) != 1
                or {kw.arg for kw in node.keywords} != {"algorithms"}
            ):
                return False, None
            algorithms = node.keywords[0].value
            if not (
                isinstance(algorithms, (ast.List, ast.Tuple))
                and algorithms.elts
                and all(
                    isinstance(a, ast.Constant)
                    and a.value in {"HS256", "HS384", "HS512"}
                    for a in algorithms.elts
                )
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
        inputs = {}
        for arg, value in defaults:
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
        return inputs

    def handler_authority(self):
        """Prove credential authority only after input and complete provider closure."""
        function, path = self.handler["function"], self.handler["path"]
        if not self.token_inputs(structural_only=True) or not self.boundary_closed():
            return None
        environment = self.token_inputs()
        if not environment:
            return None
        for statement in function.body:
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
            if value is None or value.roots != frozenset({"verified:" + self.root}):
                return None
            exception = statement.body[0].exc
            if not (
                isinstance(exception, ast.Call)
                and not exception.args
                and self.canonical(path, exception.func, function)
                in {"fastapi.HTTPException", "fastapi.exceptions.HTTPException"}
                and self.provider(path, self.canonical(path, exception.func, function))
            ):
                return None
            status = next(
                (kw.value for kw in exception.keywords if kw.arg == "status_code"), None
            )
            if not (
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
            ):
                return None
            return self.witness(statement, value)
        return None

    def boundary_closed(self):
        """Validate provider identity and callback closure for the selected handler."""
        from . import review_audits as audit
        from .credential_role_constructor_provider import (
            _captured_terminal_provider_mutation,
        )
        from .mock_fixture_provenance import _django_name
        from .credential_role_identity_effects import _enclosing_function

        handler, index = self.handler, self.index
        if not self.provider(handler["path"], "fastapi.Depends"):
            return False
        readonly = {
            id(call.args[0]) for _, _, _, call in handler["graph"].edges if call.args
        }
        registrations = {id(call) for _, _, _, call in handler["graph"].edges}
        registrations.update(
            id(route["decorator"]) for route in handler["graph"].handlers
        )
        self.dependency_arguments = set()
        for path, tree in index.snapshots.items():
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and len(node.args) == 1
                    and not node.keywords
                    and self.canonical(
                        path, node.func, _enclosing_function(node, index.parents[path])
                    )
                    == "fastapi.Depends"
                ):
                    readonly.add(id(node.args[0]))
                    self.dependency_arguments.add(id(node.args[0]))
                if (
                    isinstance(node, ast.Call)
                    and len(node.args) == 1
                    and not node.keywords
                    and self.canonical(
                        path, node.func, _enclosing_function(node, index.parents[path])
                    )
                    in {
                        "fastapi.testclient.TestClient",
                        "starlette.testclient.TestClient",
                    }
                    and self.provider(
                        path,
                        self.canonical(
                            path,
                            node.func,
                            _enclosing_function(node, index.parents[path]),
                        ),
                    )
                ):
                    readonly.add(id(node.args[0]))
        bindings = [(handler["path"], handler["function"].name)]
        bindings.extend(
            (owner, name) for _, owner, name in handler.get("dependency_providers", ())
        )
        for allocation in (handler["application"], handler["receiver"]):
            provider = (
                "fastapi.FastAPI"
                if allocation["kind"] == "application"
                else "fastapi.APIRouter"
            )
            if not self.provider(allocation["path"], provider):
                return False
            if not self.projection._symbol_closed(
                [(allocation["name"], allocation["path"], allocation["name"])],
                self.value_type(),
                readonly_argument=lambda node: id(node) in readonly,
                readonly_call=lambda node: id(node) in registrations,
                inventory_projector=lambda tree,
                aliases,
                nodes,
                canonical: self.boundary_inventory(tree, aliases, nodes, canonical),
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
        return {
            "schema": "factory.security.signing-default-authority.v1",
            "framework": "pyjwt",
            "source_role": "conditional_published_default",
            "credential_key": self.finding["facts"]["name"],
            "proof_scope": "source_bound_operative_signing_default",
            "consumer_role": "verified_bearer_rejection",
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

    def __init__(self, context):
        from .credential_role_identity_effects import source_symbol_index
        from .semantic_credential_sensor import (
            _provider_identity_uncertain,
            _signing_framework_external,
        )

        self.context, self.index = context, context["index"]
        self.symbols = source_symbol_index(self.index)
        self.allocations, self.edges, self.handlers = {}, [], []
        if self.symbols is None:
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
                    from .credential_role_constructor_provider import (
                        binding_occurrences,
                    )

                    if len(binding_occurrences(scope.body, name)) != 1:
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

        return _app_expression_name(self.symbols, path, expression, function)

    def binding(self, path, expression, function=None):
        """Resolve the captured declaration that dominates a selected credential use."""
        from .mock_fixture_provenance import _app_local_assignment, _app_source_symbol
        from .credential_role_constructor_provider import binding_dominates

        if function is not None and isinstance(expression, ast.Name):
            local = _app_local_assignment(function, expression.id)
            if local is not None:
                if not binding_dominates(
                    local, expression, self.index.parents[path], function
                ):
                    return None
                return self.allocations.get((path, id(local)))
        selected = _app_source_symbol(self.symbols, path, expression, function)
        return (
            self.allocations.get((selected[0], id(selected[1]))) if selected else None
        )

    def boundaries(self):
        """Follow exact dependency registrations, sharing one bounded route graph."""
        from .mock_fixture_provenance import _app_source_symbol

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
                selected = _app_source_symbol(
                    self.symbols, path, value.args[0], function, provider_chain=chain
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
                if (
                    not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
                    or len(function.decorator_list) != 1
                ):
                    continue
                decorator = function.decorator_list[0]
                if not (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr in self._routes
                ):
                    continue
                receiver = self.binding(path, decorator.func.value)
                if (
                    receiver is None
                    or receiver["framework"] == "fastapi"
                    and decorator.func.attr == "route"
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


def _flask_credential_authority_for_key(
    finding, context, index, path, declaration, session_secret, key
):
    from .semantic_credential_sensor import (
        _flask_configured_apps,
        _flask_session_authority_witness,
        _flask_config_key_declaration,
        _literal_credential,
    )

    for app in _flask_configured_apps(path, context, {key, "SECRET_KEY"}):
        app_path, tree = app["path"], app["tree"]
        authority = _flask_session_authority_witness(app_path, tree, context, app, key)
        if app_path != path:
            authority = None
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
    if len(managers) != 1:
        return None
    manager = managers[0].targets[0].id
    if sum(
        isinstance(node, ast.Name)
        and node.id == manager
        and isinstance(node.ctx, (ast.Store, ast.Del))
        for node in ast.walk(scope)
    ) != 1 or _provider_identity_uncertain(
        scope,
        {**aliases, manager: "flask_login.LoginManagerInstance"},
        roots=("flask_login.LoginManagerInstance",),
    ):
        return None
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
    if len(initialized) != 1:
        return None
    login_users = []
    protected = []
    for function in (
        item
        for item in scope.body
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
    ):
        if _flask_route_bound_to_app(function, app["receiver"]):
            login_users.extend(
                (function, node)
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
        if (
            _flask_route_bound_to_app(function, app["receiver"])
            and "flask_login.login_required" in decorators
        ):
            guard_position = decorators.index("flask_login.login_required")
            if not any(
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr == "route"
                and isinstance(decorator.func.value, ast.Name)
                and decorator.func.value.id == app["receiver"]
                for decorator in function.decorator_list[:guard_position]
            ):
                continue
            protected.append(
                (
                    function,
                    function.decorator_list[
                        decorators.index("flask_login.login_required")
                    ],
                )
            )
    if len(login_users) != 1 or not protected:
        return None
    login_function, login_call = login_users[0]
    return {
        "consumer_kind": "flask_login_session",
        "nodes": [
            (path, app["creation"]),
            (path, app["load"]),
            (path, initialized[0]),
            (path, login_function),
            (path, login_call),
            *(
                (path, node)
                for function, decorator in protected
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
        nodes.extend(authority["nodes"])
        role = {"consumer_role": authority["consumer_kind"]}
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
