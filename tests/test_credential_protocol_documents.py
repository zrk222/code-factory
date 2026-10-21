import json
import pytest
from factoryline.credential_endpoint_admission import (
    matches_openapi_endpoint,
    openapi_endpoint_declarations,
)
import ast
import hashlib
from factoryline import review_audits, review_integrity
from factoryline.credential_role_bindings import matches_fact
from factoryline.credential_role_scope_bindings import class_attribute, effective_method
from factoryline.credential_role_sources import SourceSnapshotIndex, declaration_fact
from factoryline.credential_role_setting_boundary import setting_boundary_nodes
from factoryline.credential_role_method_use_getter_audit import _stable_self

SOURCE = "https://publisher.example/openapi.json"
ENDPOINT = "https://auth.example/oauth/token"


def document(endpoint=ENDPOINT):
    return {
        "openapi": "3.0.3",
        "components": {
            "securitySchemes": {
                "OAuth": {
                    "type": "oauth2",
                    "flows": {
                        "authorizationCode": {
                            "tokenUrl": endpoint,
                            "authorizationUrl": "https://auth.example/authorize",
                            "scopes": {},
                        }
                    },
                }
            }
        },
    }


def encode(value):
    return json.dumps(value).encode()


def test_whole_document_extracts_exact_standard_role_without_granting_trust():
    raw = encode(document())
    rows = openapi_endpoint_declarations(raw, source_url=SOURCE)
    assert len(rows) == 1
    assert rows[0]["value"] == ENDPOINT
    assert rows[0]["credential_safety"] == "NOT_ESTABLISHED_BY_PARSER"
    assert rows[0]["origin_authenticity"] == "NOT_ESTABLISHED_BY_PARSER"
    assert matches_openapi_endpoint(ENDPOINT, rows[0], raw)
    assert not matches_openapi_endpoint(ENDPOINT + "/", rows[0], raw)


@pytest.mark.parametrize(
    "endpoint",
    [
        "/oauth/token",
        "http://auth.example/token",
        "https://u:p@auth.example/token",
        "https://auth.example/token?secret=x",
        "https://auth.example/token#secret",
        "https://auth.example:bad/token",
        "https://auth.example/\\token",
        None,
    ],
)
def test_unsafe_or_unsupported_url_is_not_a_publication_fact(endpoint):
    assert (
        openapi_endpoint_declarations(encode(document(endpoint)), source_url=SOURCE)
        is None
    )


def test_opaque_capability_path_is_only_a_declaration_never_safety_evidence():
    raw = encode(document("https://auth.example/private/capability-abc123"))
    rows = openapi_endpoint_declarations(raw, source_url=SOURCE)
    assert rows[0]["credential_safety"] == "NOT_ESTABLISHED_BY_PARSER"
    assert "disposition" not in rows[0]


@pytest.mark.parametrize(
    "mutation", ["reference", "duplicate", "wrong_type", "version", "flow", "scopes"]
)
def test_ambiguous_documents_fail_closed(mutation):
    doc = document()
    scheme = doc["components"]["securitySchemes"]["OAuth"]
    if mutation == "reference":
        scheme["$ref"] = "https://elsewhere.example/schema"
    elif mutation == "duplicate":
        raw = encode(doc).replace(
            b'"tokenUrl":', b'"tokenUrl":"https://evil.example", "tokenUrl":'
        )
        assert openapi_endpoint_declarations(raw, source_url=SOURCE) is None
        return
    elif mutation == "wrong_type":
        doc["components"]["securitySchemes"] = []
    elif mutation == "version":
        doc["openapi"] = "2.0"
    elif mutation == "flow":
        scheme["flows"] = {"unknown": {"tokenUrl": ENDPOINT, "scopes": {}}}
    else:
        scheme["flows"]["authorizationCode"]["scopes"] = []
    assert openapi_endpoint_declarations(encode(doc), source_url=SOURCE) is None


def test_forged_fact_and_changed_document_do_not_match():
    raw = encode(document())
    row = openapi_endpoint_declarations(raw, source_url=SOURCE)[0]
    assert not matches_openapi_endpoint(
        ENDPOINT, {**row, "credential_safety": "SAFE"}, raw
    )
    assert not matches_openapi_endpoint(
        ENDPOINT, row, encode(document("https://other.example/token"))
    )


def test_size_and_node_budgets_fail_closed(monkeypatch):
    import factoryline.credential_endpoint_admission as parser

    raw = encode(document())
    monkeypatch.setattr(parser, "MAX_DOCUMENT_BYTES", len(raw) - 1)
    assert openapi_endpoint_declarations(raw, source_url=SOURCE) is None
    monkeypatch.setattr(parser, "MAX_DOCUMENT_BYTES", len(raw) + 1)
    monkeypatch.setattr(parser, "MAX_DOCUMENT_NODES", 2)
    assert openapi_endpoint_declarations(raw, source_url=SOURCE) is None


def test_multiple_flows_and_schemes_preserve_exact_provenance():
    doc = document()
    schemes = doc["components"]["securitySchemes"]
    schemes["OAuth"]["flows"]["clientCredentials"] = {
        "tokenUrl": ENDPOINT,
        "scopes": {},
    }
    schemes["Basic"] = {"type": "http", "scheme": "basic"}
    rows = openapi_endpoint_declarations(encode(doc), source_url=SOURCE)
    assert len(rows) == 2
    assert {r["flow"] for r in rows} == {"authorizationCode", "clientCredentials"}


@pytest.mark.parametrize(
    "mutation",
    [
        "empty_query",
        "empty_fragment",
        "nan",
        "surrogate",
        "missing_authorize",
        "bad_scopes",
        "deep",
        "ref_sibling",
        "implicit",
    ],
)
def test_reviewer_document_boundary_controls(mutation):
    doc = document()
    flow = doc["components"]["securitySchemes"]["OAuth"]["flows"]["authorizationCode"]
    if mutation == "empty_query":
        flow["tokenUrl"] += "?"
    elif mutation == "empty_fragment":
        flow["tokenUrl"] += "#"
    elif mutation == "nan":
        doc["extra"] = float("nan")
    elif mutation == "surrogate":
        doc["extra"] = "\ud800"
    elif mutation == "missing_authorize":
        flow.pop("authorizationUrl")
    elif mutation == "bad_scopes":
        flow["scopes"] = {"read": 123}
    elif mutation == "deep":
        for _ in range(60):
            doc = {"nested": doc}
    elif mutation == "ref_sibling":
        flow["$ref"] = "https://other.example/doc"
    else:
        doc["components"]["securitySchemes"]["OAuth"]["flows"] = {"implicit": flow}
    assert openapi_endpoint_declarations(encode(doc), source_url=SOURCE) is None


"""Source identity controls for the semantic credential role helpers."""


def _index(tmp_path, texts):
    trees, sources, inventory = {}, {}, {}
    for relative, source in texts.items():
        path = tmp_path / relative
        raw = source.encode()
        tree = ast.parse(raw)
        digest = hashlib.sha256(raw).hexdigest()
        tree._oracle_source_sha256 = digest
        review_integrity.bind_security_call_scopes(tree)
        trees[path] = tree
        sources[path] = raw
        inventory[path] = digest
    return SourceSnapshotIndex(tmp_path, trees, sources, inventory), trees


def _find_fact(index, path, tree, member):
    node = next(
        row
        for row in ast.walk(tree)
        if isinstance(row, (ast.Assign, ast.AnnAssign))
        and getattr(row, "value", None) is not None
        and isinstance(row.value, ast.Constant)
        and isinstance(row.value.value, str)
        and any(
            isinstance(target, ast.Name) and target.id == member
            for target in (row.targets if isinstance(row, ast.Assign) else [row.target])
        )
    )
    return declaration_fact(index, path, node)


def test_parameter_and_local_import_shadows_do_not_match_module_value(tmp_path):
    source = (
        "TOKEN = 'public'\n"
        "def parameter(TOKEN):\n    return requests.get(TOKEN)\n"
        "def imported():\n    from other import TOKEN\n    return requests.get(TOKEN)\n"
    )
    index, trees = _index(tmp_path, {"mod.py": source})
    path, tree = next(iter(trees.items()))
    fact = _find_fact(index, path, tree, "TOKEN")
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    argument = calls[0].args[0]
    assert not matches_fact(fact, path, argument, index, {path: {}}, {}, review_audits)
    argument = calls[1].args[0]
    assert not matches_fact(
        fact,
        path,
        argument,
        index,
        {path: {"TOKEN": (tmp_path / "other.py", "TOKEN")}},
        {},
        review_audits,
    )


def test_local_constant_has_local_role_and_cannot_claim_module_source(tmp_path):
    index, trees = _index(
        tmp_path,
        {
            "mod.py": "def make():\n    TOKEN = 'local'\n    return requests.get(TOKEN)\n"
        },
    )
    path, tree = next(iter(trees.items()))
    fact = _find_fact(index, path, tree, "TOKEN")
    use = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == "TOKEN"
        and isinstance(node.ctx, ast.Load)
    )
    assert fact.owner == "<local:make>"
    assert fact.source_role == "local_literal"
    assert not matches_fact(fact, path, use, index, {path: {}}, {}, review_audits)


def test_nested_function_self_parameter_is_not_outer_instance(tmp_path):
    source = (
        "class API:\n    URL = 'https://example.test'\n"
        "    def send(self):\n"
        "        def nested(self):\n            return requests.get(self.URL)\n"
    )
    index, trees = _index(tmp_path, {"api.py": source})
    path, tree = next(iter(trees.items()))
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef))
    fact = _find_fact(index, path, tree, "URL")
    use = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "URL"
    )
    aliases = {path: review_audits._module_security_aliases(tree)}
    assert not matches_fact(
        fact, path, use, index, aliases, {(path, "API"): owner}, review_audits
    )


def test_conditional_and_decorated_method_bindings_are_unknown(tmp_path):
    tree = ast.parse(
        "class Base:\n    def read(self): pass\n"
        "class Conditional(Base):\n    if enabled:\n        def read(self): pass\n"
        "class Decorated:\n    @wrapper\n    def read(self): pass\n"
        "class Reassigned:\n    read = replacement\n"
    )
    base, conditional, decorated, reassigned = tree.body
    assert (
        effective_method(
            [(None, "Conditional", conditional), (None, "Base", base)], "read"
        )
        is None
    )
    assert effective_method([(None, "Decorated", decorated)], "read") is None
    assert effective_method([(None, "Reassigned", reassigned)], "read") is None
    assert class_attribute([(None, "Conditional", conditional)], "read") is None


def _setting_snapshots(
    tmp_path,
    *,
    hook="return getattr(_app_settings, name)",
    setting_call="return get_setting(self.prefix + name, dflt)",
):
    texts = {
        "allauth/socialaccount/app_settings.py": (
            "from allauth.utils import get_setting\n"
            "class AppSettings:\n"
            "    def _setting(self, name, dflt):\n"
            "        from allauth.utils import get_setting\n"
            f"        {setting_call}\n"
            "    @property\n"
            "    def ADAPTER(self):\n"
            "        return self._setting('ADAPTER', 'allauth.socialaccount.adapter.DefaultAdapter')\n"
            "_app_settings = AppSettings('SOCIALACCOUNT_')\n"
            "def __getattr__(name):\n    " + hook + "\n"
        ),
        "allauth/utils.py": (
            "from django.conf import settings\n"
            "from django.utils.module_loading import import_string\n"
            "def import_callable(path_or_callable):\n"
            "    if not callable(path_or_callable):\n"
            "        ret = import_string(path_or_callable)\n"
            "    else:\n        ret = path_or_callable\n"
            "    return ret\n"
            "def get_setting(name, dflt):\n"
            "    getter = getattr(settings, 'ALLAUTH_SETTING_GETTER', lambda name, dflt: getattr(settings, name, dflt))\n"
            "    getter = import_callable(getter)\n"
            "    return getter(name, dflt)\n"
        ),
    }
    return _index(tmp_path, texts)


def test_declared_adapter_setting_requires_getattr_bridge_and_source_transfer(tmp_path):
    index, snapshots = _setting_snapshots(tmp_path)
    settings_path = tmp_path / "allauth/socialaccount/app_settings.py"
    owner = next(
        node for node in snapshots[settings_path].body if isinstance(node, ast.ClassDef)
    )
    aliases = {
        path: review_audits._module_security_aliases(tree)
        for path, tree in snapshots.items()
    }
    rows = setting_boundary_nodes(
        index, snapshots, settings_path, owner, aliases[settings_path]
    )
    assert rows is not None
    assert set(rows) == {
        "module_getattr",
        "settings_instance",
        "setting_method",
        "setting_transfer",
        "get_setting",
    }


def test_changed_module_hook_or_setting_target_cannot_complete_chain(tmp_path):
    index, snapshots = _setting_snapshots(tmp_path, hook="return globals()[name]")
    settings_path = tmp_path / "allauth/socialaccount/app_settings.py"
    owner = snapshots[settings_path].body[1]
    aliases = review_audits._module_security_aliases(snapshots[settings_path])
    assert (
        setting_boundary_nodes(index, snapshots, settings_path, owner, aliases) is None
    )

    index, snapshots = _setting_snapshots(
        tmp_path, setting_call="return self.other(name, dflt)"
    )
    settings_path = tmp_path / "allauth/socialaccount/app_settings.py"
    owner = next(
        node for node in snapshots[settings_path].body if isinstance(node, ast.ClassDef)
    )
    aliases = review_audits._module_security_aliases(snapshots[settings_path])
    assert (
        setting_boundary_nodes(index, snapshots, settings_path, owner, aliases) is None
    )


class _Audit:
    @staticmethod
    def _name(node):
        return ast.unparse(node)


_DECORATOR = """
from functools import wraps
def handle_http_errors(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyError:
            raise
    return wrapper
"""

_MUTATING_DECORATOR = """
import functools
def replacement(*args, **kwargs):
    return None
functools.wraps = replacement
def handle_http_errors(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyError:
            raise
    return wrapper
"""

_CONSUMER = """
from decorators import handle_http_errors
class Child:
    @handle_http_errors
    def auth_complete(self):
        return self.access_token_url()
"""


def _case(tmp_path, decorator_source, consumer_source=_CONSUMER):
    root = tmp_path.resolve()
    paths = {name: root / name for name in ("client.py", "decorators.py")}
    sources = {"client.py": consumer_source, "decorators.py": decorator_source}
    trees, raw, inventory = {}, {}, {}
    for name, source in sources.items():
        data = source.encode()
        digest = hashlib.sha256(data).hexdigest()
        tree = ast.parse(data)
        tree._oracle_source_sha256 = digest
        path = paths[name]
        trees[path], raw[path], inventory[path] = tree, data, digest
    index = SourceSnapshotIndex(root, trees, raw, inventory)
    function = next(
        node
        for node in ast.walk(trees[paths["client.py"]])
        if isinstance(node, ast.FunctionDef) and node.name == "auth_complete"
    )
    receiver = next(
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Name) and node.id == "self"
    )
    owner = next(
        node
        for node in trees[paths["client.py"]].body
        if isinstance(node, ast.ClassDef)
    )
    imported = {"handle_http_errors": (paths["decorators.py"], "handle_http_errors")}
    imports = {paths["client.py"]: imported, paths["decorators.py"]: {}}
    classes = {(paths["client.py"], "Child"): owner}
    context = imports, classes, _Audit()
    return _stable_self(receiver, index, paths["client.py"], context)


def test_transparent_imported_decorator_allows_verified_receiver(tmp_path):
    assert _case(tmp_path, _DECORATOR) is True


def test_mutated_decorator_provider_keeps_receiver_unknown(tmp_path):
    assert _case(tmp_path, _MUTATING_DECORATOR) is False


def test_unresolved_base_keeps_decorated_receiver_unknown(tmp_path):
    source = _CONSUMER.replace("class Child:", "class Child(ExternalBase):")
    assert _case(tmp_path, _DECORATOR, source) is False
