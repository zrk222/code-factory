import hashlib
from importlib import resources
import json
import pytest
from factoryline import credential_publication_catalog as catalog
import ast
from types import SimpleNamespace
from factoryline.credential_role_bindings import class_chain
from factoryline.credential_role_chain_memo import ClassChainMemo
from factoryline.credential_role_scope_bindings import effective_method
from factoryline.credential_role_sources import SourceSnapshotIndex
from factoryline.review_audits import security_scan
from factoryline.credential_role_method_flow import method_url_hops
from factoryline.credential_role_sources import declaration_fact
from factoryline.review_integrity import bind_source_call


def _raw():
    return (
        resources.files("factoryline")
        .joinpath("data/protocol_publications.json")
        .read_bytes()
    )


@pytest.mark.parametrize(
    "value",
    [
        "https://cloud.digitalocean.com/v1/oauth/token",
        "https://appleid.apple.com/auth/token",
        "https://id.twitch.tv/oauth2/token",
        "https://api.login.yahoo.com/oauth2/get_token",
        "https://api.hubapi.com/oauth/v1/token",
        "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
        "https://oauth.yandex.com/token",
        "https://open.feishu.cn/open-apis/authen/v1/access_token",
        "https://auth.dataporten.no/oauth/token",
    ],
)
def test_exact_publications_are_offline_facts_not_safety(value, monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("catalog lookup must not connect")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    fact = catalog.endpoint_publication(value)
    assert fact["value"] == value
    assert fact["catalog_sha256"] == hashlib.sha256(_raw()).hexdigest()
    assert fact["credential_safety"] == "UNASSESSED"
    assert fact["runtime_assurance"] == "INCOMPLETE"
    assert "disposition" not in fact


@pytest.mark.parametrize(
    "value",
    [
        "https://appleid.apple.com/auth/token/",
        "https://appleid.apple.com/auth/token?secret=credential",
        "https://appleid.apple.com/auth/token/credential",
        "https://name:credential@appleid.apple.com/auth/token",
        "https://api.telegram.org/botliteral-credential/getMe",
        "https://appleid.apple.com/auth/{token}",
        "https://appleid.apple.com/auth/",
        "HTTPS://appleid.apple.com/auth/token",
        "https://appleid.apple.com/auth/token#fragment",
        "https://oauth.yandex.com/token/",
        "https://open.feishu.cn/open-apis/authen/v1/access_token/",
        "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal/",
        "https://auth.dataporten.no/oauth/token/",
        "https://auth.dataporten.no/oauth/token?secret=credential",
        None,
    ],
)
def test_no_prefix_template_normalization_or_url_credential_exemptions(value):
    assert catalog.endpoint_publication(value) is None


def test_corruption_or_missing_resource_is_not_a_publication(monkeypatch):
    assert catalog._read(_raw() + b" ") == ()
    assert catalog._read(b"x" * 1048577) == ()
    assert catalog._read(None) == ()

    class Missing:
        def joinpath(self, *args):
            return self

        def open(self, *args):
            raise FileNotFoundError("missing data")

    monkeypatch.setattr(catalog.resources, "files", lambda *args: Missing())
    assert catalog.endpoint_publication("https://appleid.apple.com/auth/token") is None


def test_raw_metadata_and_capture_are_revalidated():
    row = json.loads(_raw())["entries"][0]
    row["document_utf8"] += " "
    assert catalog._entry(row) is None
    row = json.loads(_raw())["entries"][0]
    row["capture"]["redirect_policy"] = "follow"
    assert catalog._entry(row) is None
    row = json.loads(_raw())["entries"][0]
    row["capture"]["final_url"] += "/other"
    assert catalog._entry(row) is None


def test_catalog_contains_publication_data_only():
    raw = _raw()
    document = json.loads(raw)
    assert (
        document["admission"]["decision"] == "ADMITTED_PUBLIC_PROTOCOL_PUBLICATION_ONLY"
    )
    assert len(document["entries"]) == 27
    assert not any(
        term in raw
        for term in (
            b"case_id",
            b"raw_ids",
            b"packet_id",
            b"repository",
            b"adjudication_label",
        )
    )


def test_batch_snapshot_has_immutable_facts():
    snapshot = catalog.endpoint_publications()
    assert isinstance(snapshot, tuple) and len(snapshot) == 27
    with pytest.raises(TypeError):
        snapshot[0]["value"] = "changed"
    assert catalog.endpoint_publication(snapshot[0]["value"]) == dict(snapshot[0])


def test_catalog_data_changes_invalidate_native_context_cache_key(
    tmp_path, monkeypatch
):
    import io
    from factoryline.review_audits import _oracle_context_cache_key

    before = _oracle_context_cache_key(tmp_path, [], {})
    raw = _raw()

    class Changed:
        def joinpath(self, *args):
            return self

        def open(self, *args):
            return io.BytesIO(raw + b" ")

    monkeypatch.setattr(catalog.resources, "files", lambda *args: Changed())
    after = _oracle_context_cache_key(tmp_path, [], {})
    assert before != after
    assert catalog.endpoint_publications() == ()


@pytest.mark.parametrize(
    "name",
    [
        "_unique_object",
        "_public_https",
        "endpoint_metadata",
        "matches_endpoint_declaration",
    ],
)
def test_moved_parser_callables_invalidate_native_context_cache_key(
    tmp_path, monkeypatch, name
):
    from factoryline.review_audits import _oracle_context_cache_key

    before = _oracle_context_cache_key(tmp_path, [], {})
    original = getattr(catalog, name)

    def replacement(*args, **kwargs):
        return original(*args, **kwargs)

    monkeypatch.setattr(catalog, name, replacement)
    after = _oracle_context_cache_key(tmp_path, [], {})
    assert before != after


ISSUER = "https://issuer.example/tenant"
SOURCE = "https://issuer.example/.well-known/oauth-authorization-server/tenant"
ENDPOINT = "https://issuer.example/tenant/oauth/token"


def _metadata_raw(**changes):
    return json.dumps(
        {"issuer": ISSUER, "token_endpoint": ENDPOINT, **changes}
    ).encode()


def _parse(raw=None, source=SOURCE, issuer=ISSUER):
    return catalog.endpoint_metadata(
        _metadata_raw() if raw is None else raw,
        source_url=source,
        expected_issuer=issuer,
    )


def test_metadata_binds_exact_values_and_retains_unverified_origin_boundary():
    raw = _metadata_raw()
    declaration = _parse(raw)
    assert declaration["origin_authenticity"] == "NOT_ESTABLISHED_BY_PARSER"
    assert declaration["credential_safety"] == "NOT_ESTABLISHED_BY_PARSER"
    assert catalog.matches_endpoint_declaration(ENDPOINT, declaration, raw)
    for value in (ENDPOINT + "/", ENDPOINT + "/secret", ENDPOINT.upper()):
        assert not catalog.matches_endpoint_declaration(value, declaration, raw)


def test_oidc_path_and_rfc8414_path_are_distinct():
    assert _parse(source=ISSUER + "/.well-known/openid-configuration")
    assert _parse(source=ISSUER + "/.well-known/oauth-authorization-server") is None


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"[]",
        b"null",
        b"not json",
        b"\xff",
        _metadata_raw(issuer=ISSUER + "/"),
        _metadata_raw(token_endpoint=ENDPOINT + "?client_secret=fixture"),
        _metadata_raw(token_endpoint="https://user:fixture@issuer.example/token"),
        _metadata_raw(token_endpoint="http://issuer.example/token"),
        _metadata_raw(token_endpoint=ENDPOINT + "#fragment"),
        _metadata_raw(token_endpoint=42),
        _metadata_raw(token_endpoint="https://issuer.example:bad/token"),
        _metadata_raw(token_endpoint="https://issuer.example/\\token"),
        _metadata_raw(token_endpoint="https://issuer.example/\ud800"),
        b'{"issuer":"https://issuer.example/tenant","token_endpoint":"a",'
        b'"token_endpoint":"https://issuer.example/token"}',
        b" " * 262145,
    ],
    ids=lambda raw: f"bytes-{len(raw)}",
)
def test_malformed_ambiguous_or_credential_bearing_metadata_fails_closed(raw):
    assert _parse(raw) is None


def test_wrong_origin_or_forged_record_does_not_match():
    assert (
        _parse(source="https://other.example/.well-known/openid-configuration") is None
    )
    record = _parse()
    record["value"] = ENDPOINT + "/secret"
    assert not catalog.matches_endpoint_declaration(
        record["value"], record, _metadata_raw()
    )
    assert not catalog.matches_endpoint_declaration(
        ENDPOINT, _parse(), _metadata_raw(extra="changed")
    )


def test_publication_can_contain_a_path_token_without_becoming_a_safety_verdict():
    raw = _metadata_raw(
        token_endpoint="https://issuer.example/bot/fixture-credential/getMe"
    )
    record = _parse(raw)
    assert record is not None
    assert record["credential_safety"] == "NOT_ESTABLISHED_BY_PARSER"


"""C3 resolution is source-bound, ordered, and fail-closed."""


def _index(tmp_path, sources, imports=None, *, memo=True):
    snapshots, source_bytes, inventory, classes = {}, {}, {}, {}
    for relative, source in sources.items():
        path = tmp_path / relative
        raw = source.encode()
        tree = ast.parse(raw)
        digest = hashlib.sha256(raw).hexdigest()
        tree._oracle_source_sha256 = digest
        snapshots[path], source_bytes[path], inventory[path] = tree, raw, digest
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                classes[(path, node.name)] = node
    index = SourceSnapshotIndex(tmp_path, snapshots, source_bytes, inventory)
    import_map = {path: {} for path in snapshots}
    for relative, aliases in (imports or {}).items():
        import_map[tmp_path / relative] = {
            alias: (tmp_path / target, symbol)
            for alias, (target, symbol) in aliases.items()
        }
    audit = SimpleNamespace(_name=ast.unparse)
    if memo:
        index.class_chain_memo = ClassChainMemo(index, import_map, classes, audit)
    return index, import_map, classes, audit


def _names(chain):
    return [name for _, name, _ in chain]


def test_imported_multiple_inheritance_uses_c3_order_for_getter(tmp_path):
    index, imports, classes, audit = _index(
        tmp_path,
        {
            "bases.py": """
class Root: pass
class Left(Root):
    def endpoint(self): return self.ACCESS_TOKEN_URL
class Right(Root):
    def endpoint(self): return 'other'
""",
            "client.py": """
from bases import Left as First, Right as Second
class Client(First, Second): pass
""",
        },
        {"client.py": {"First": ("bases.py", "Left"), "Second": ("bases.py", "Right")}},
    )
    chain = class_chain(
        index, tmp_path / "client.py", "Client", imports, classes, audit
    )
    assert _names(chain) == ["Client", "Left", "Right", "Root"]
    getter = effective_method(chain, "endpoint")
    assert getter[0] == tmp_path / "bases.py"
    assert getter[1].lineno == 4
    assert index.class_chain_memo.valid()


@pytest.mark.parametrize(
    "sources,imports,name",
    [
        ({"app.py": "class A: pass\nclass Child(A, A): pass\n"}, {}, "Child"),
        (
            {"app.py": "class A(B): pass\nclass B(A): pass\n"},
            {},
            "A",
        ),
        (
            {
                "app.py": """
class X: pass
class Y: pass
class A(X, Y): pass
class B(Y, X): pass
class Child(A, B): pass
"""
            },
            {},
            "Child",
        ),
        ({"app.py": "class Child(External): pass\n"}, {}, "Child"),
        (
            {"app.py": "@opaque\nclass Base: pass\nclass Child(Base): pass\n"},
            {},
            "Child",
        ),
    ],
)
def test_invalid_or_unresolved_mro_stays_unknown(tmp_path, sources, imports, name):
    index, import_map, classes, audit = _index(tmp_path, sources, imports)
    path = tmp_path / next(iter(sources))
    assert class_chain(index, path, name, import_map, classes, audit) is None


def test_import_alias_rebinding_is_rejected(tmp_path):
    index, imports, classes, audit = _index(
        tmp_path,
        {
            "bases.py": "class Base: pass\n",
            "client.py": "from bases import Base as Alias\nAlias = object\nclass Child(Alias): pass\n",
        },
        {"client.py": {"Alias": ("bases.py", "Base")}},
    )
    assert (
        class_chain(index, tmp_path / "client.py", "Child", imports, classes, audit)
        is None
    )


def test_c3_chain_is_memoized_and_source_mutation_invalidates_credit(tmp_path):
    index, imports, classes, audit = _index(
        tmp_path,
        {"app.py": "class A: pass\nclass B: pass\nclass Child(A, B): pass\n"},
    )
    path = tmp_path / "app.py"
    first = class_chain(index, path, "Child", imports, classes, audit)
    assert first is class_chain(index, path, "Child", imports, classes, audit)
    assert _names(first) == ["Child", "A", "B"]
    assert index.class_chain_memo.valid()
    index.source_bytes[path] += b"# source changed\n"
    assert not index.class_chain_memo.valid()


def test_mro_over_sixteen_unique_classes_is_rejected(tmp_path):
    source = "class C0: pass\n" + "".join(
        f"class C{number}(C{number - 1}): pass\n" for number in range(1, 17)
    )
    index, imports, classes, audit = _index(tmp_path, {"app.py": source})
    assert (
        class_chain(index, tmp_path / "app.py", "C16", imports, classes, audit) is None
    )


def _scan_inherited_getter(tmp_path, source):
    path = tmp_path / "client.py"
    path.write_text(source, encoding="utf-8")
    return security_scan(tmp_path, cache_enabled=False)


def test_scanner_retains_auth_override_before_candidate_getter(tmp_path):
    result = _scan_inherited_getter(
        tmp_path,
        "import requests\n"
        "class FieldMixin:\n"
        "    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'\n"
        "class GetterMixin:\n"
        "    def endpoint(self): return self.ACCESS_TOKEN_URL\n"
        "class AuthMixin:\n"
        "    def endpoint(self):\n"
        "        return requests.request('POST', 'https://example.test/token', "
        "auth=('client', self.ACCESS_TOKEN_URL))\n"
        "class Client(AuthMixin, FieldMixin, GetterMixin):\n"
        "    def send(self): return requests.request('POST', self.endpoint())\n",
    )
    alerts = [
        item
        for item in result["findings"]
        if item["code"] == "SECURITY_HARDCODED_SECRET"
    ]
    assert alerts
    assert all(item["severity"] == "CRITICAL" for item in alerts)


class _Audit:
    @staticmethod
    def _name(node):
        return ast.unparse(node)

    @staticmethod
    def _module_security_aliases(tree):
        aliases = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for item in node.names:
                    aliases[item.asname or item.name.split(".")[0]] = item.name
            elif isinstance(node, ast.ImportFrom):
                for item in node.names:
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"
        return aliases


def _case(tmp_path, source, replacement=None):
    path = tmp_path / "client.py"
    raw = source.encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    snapshots, source_bytes, inventory = {path: tree}, {path: raw}, {path: digest}
    index = SourceSnapshotIndex(tmp_path, snapshots, source_bytes, inventory)
    classes = {
        (path, node.name): node for node in tree.body if isinstance(node, ast.ClassDef)
    }
    imports = {path: {}}
    aliases = {path: _Audit._module_security_aliases(tree)}
    fact_node = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and isinstance(getattr(node, "value", None), ast.Constant)
        and isinstance(node.value.value, str)
        and isinstance(
            node.targets[0] if isinstance(node, ast.Assign) else node.target, ast.Name
        )
        and (node.targets[0] if isinstance(node, ast.Assign) else node.target).id
        == "ENDPOINT"
    )
    fact = declaration_fact(index, path, fact_node)
    call = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "request"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "requests"
    )
    expression = replacement(call) if replacement else call.args[1]
    audit, integrity = _Audit(), SimpleNamespace(bind_source_call=bind_source_call)
    hops = method_url_hops(
        fact,
        path,
        call,
        expression,
        index,
        imports,
        classes,
        aliases,
        audit,
        integrity,
    )
    return hops, index, path, call, fact, imports, classes, aliases, audit, integrity


_GOOD = """
import requests
class Base:
    def endpoint(self):
        return self.ENDPOINT
    def dispatch(self, url):
        return requests.request("GET", url)
    def send(self):
        return self.dispatch(self.endpoint())
class Child(Base):
    ENDPOINT = "https://provider.example/token"
"""


def test_inherited_return_and_wrapper_parameter_reach_canonical_url(tmp_path):
    hops, *_ = _case(tmp_path, _GOOD)
    assert [row["role"] for row in hops] == [
        "declared_literal",
        "declared_member_read",
        "declared_method_return",
        "method_call",
        "method_argument_binding",
        "bound_method_parameter",
        "canonical_http_url_sink",
    ]
    assert all(len(row["source_sha256"]) == 64 for row in hops)
    assert "provider.example" not in repr(hops)


@pytest.mark.parametrize(
    "source",
    [
        _GOOD.replace(
            "self.dispatch(self.endpoint())", "self.dispatch(opaque(self.ENDPOINT))"
        ),
        _GOOD.replace(
            "def endpoint(self):\n        return self.ENDPOINT",
            "@dynamic\n    def endpoint(self):\n        return self.ENDPOINT",
        ),
        _GOOD.replace(
            "return self.ENDPOINT", 'return self.setting("URL", self.ENDPOINT)'
        ),
        _GOOD.replace(
            "self.dispatch(self.endpoint())",
            "self.dispatch(self.endpoint(), **options)",
        ),
    ],
)
def test_opaque_decorated_and_expanded_method_flows_are_unresolved(tmp_path, source):
    hops, *_ = _case(tmp_path, source)
    assert hops is None


def test_auth_slot_is_not_mistaken_for_canonical_url_argument(tmp_path):
    source = _GOOD.replace(
        'return requests.request("GET", url)',
        'return requests.request("GET", "/fixed", auth=("user", self.ENDPOINT))',
    )
    hops, *_ = _case(tmp_path, source, lambda call: call.keywords[0].value.elts[1])
    assert hops is None


def test_replaced_method_and_shadowed_parameter_do_not_flow(tmp_path):
    replaced = _GOOD.replace(
        "class Child(Base):\n    ENDPOINT",
        "class Child(Base):\n    endpoint = replacement\n    ENDPOINT",
    )
    assert _case(tmp_path / "replaced", replaced)[0] is None
    shadowed = _GOOD.replace(
        'return requests.request("GET", url)',
        'url = replacement\n        return requests.request("GET", url)',
    )
    assert _case(tmp_path / "shadowed", shadowed)[0] is None


def test_recursive_method_cycle_does_not_create_a_witness(tmp_path):
    source = _GOOD.replace(
        "return self.ENDPOINT",
        "return self.other()\n    def other(self):\n        return self.endpoint()",
    )
    assert _case(tmp_path, source)[0] is None


def test_returned_parameter_uses_the_exact_callsite_arguments(tmp_path):
    source = _GOOD.replace(
        "    def endpoint(self):\n        return self.ENDPOINT",
        "    def identity(self, value):\n        return value\n"
        "    def endpoint(self):\n        return self.ENDPOINT",
    ).replace(
        "self.dispatch(self.endpoint())",
        'self.dispatch(self.identity("https://different.example/token"))\n'
        "    def irrelevant(self):\n        return self.identity(self.ENDPOINT)",
    )
    assert _case(tmp_path, source)[0] is None


def test_cross_file_method_call_hop_keeps_callsite_source_path(tmp_path):
    root = tmp_path.resolve()
    texts = {
        "base.py": 'import requests\nclass Base:\n    def endpoint(self):\n        return self.ENDPOINT\n    def dispatch(self, url):\n        return requests.request("GET", url)\n',
        "child.py": 'from base import Base\nclass Child(Base):\n    ENDPOINT = "/token"\n    def send(self):\n        return self.dispatch(self.endpoint())\n',
    }
    snapshots, raw, inventory, paths = {}, {}, {}, {}
    for name, source in texts.items():
        path, data = root / name, source.encode()
        tree = ast.parse(data)
        digest = hashlib.sha256(data).hexdigest()
        tree._oracle_source_sha256 = digest
        snapshots[path], raw[path], inventory[path], paths[name] = (
            tree,
            data,
            digest,
            path,
        )
    index = SourceSnapshotIndex(root, snapshots, raw, inventory)
    audit = _Audit()
    classes = {
        (path, node.name): node
        for path, tree in snapshots.items()
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    imports = {
        paths["base.py"]: {},
        paths["child.py"]: {"Base": (paths["base.py"], "Base")},
    }
    aliases = {
        path: audit._module_security_aliases(tree) for path, tree in snapshots.items()
    }
    fact_node = snapshots[paths["child.py"]].body[1].body[0]
    fact = declaration_fact(index, paths["child.py"], fact_node)
    sink = next(
        n
        for n in ast.walk(snapshots[paths["base.py"]])
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "request"
    )
    hops = method_url_hops(
        fact,
        paths["base.py"],
        sink,
        sink.args[1],
        index,
        imports,
        classes,
        aliases,
        audit,
        SimpleNamespace(bind_source_call=bind_source_call),
    )
    method_call = next(row for row in hops if row["role"] == "method_call")
    assert method_call["path"] == "child.py"


def test_stale_source_bytes_fail_closed(tmp_path):
    state = _case(tmp_path, _GOOD)
    assert state[0]
    state[1].source_bytes[state[2]] += b"# changed after capture\n"
    assert (
        method_url_hops(
            state[4], state[2], state[3], state[3].args[1], state[1], *state[5:]
        )
        is None
    )
