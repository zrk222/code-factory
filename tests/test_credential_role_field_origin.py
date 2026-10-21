import ast
import hashlib
from factoryline.credential_role_method_use_getter_audit import (
    resolve_declared_field_origin,
)
from factoryline.credential_role_constructor_provider import SourceSnapshotIndex
from types import SimpleNamespace
from factoryline.credential_role_paths import forwarding_definition
from factoryline.credential_role_paths import method_url_hops
from factoryline.credential_role_constructor_provider import declaration_fact
from factoryline.credential_role_paths import fallback_method
from factoryline.review_integrity import bind_source_call
import pytest
from factoryline import review_audits as audit, review_integrity as integrity
from factoryline.credential_role_paths import endpoint_role_evidence


def _index(tmp_path, files):
    root = tmp_path.resolve()
    snapshots, raw, inventory, paths = {}, {}, {}, {}
    for name, source in files.items():
        path = root / name
        data = source.encode()
        digest = hashlib.sha256(data).hexdigest()
        tree = ast.parse(data)
        tree._oracle_source_sha256 = digest
        snapshots[path], raw[path], inventory[path], paths[name] = (
            tree,
            data,
            digest,
            path,
        )
    return SourceSnapshotIndex(root, snapshots, raw, inventory), paths


def _chain(index, path, names):
    tree = index.snapshots[path]
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    return [(path, name, classes[name]) for name in names]


def _origin(tmp_path, child, base, member="ENDPOINT"):
    index, paths = _index(tmp_path, {"classes.py": child + base})
    path = paths["classes.py"]
    return resolve_declared_field_origin(
        _chain(index, path, ["Child", "Base"]), member, index
    )


def test_inherited_field_returns_only_bound_declaration_identity(tmp_path):
    result = _origin(
        tmp_path,
        "class Child(Base):\n    pass\n",
        'class Base:\n    ENDPOINT = "hidden"\n',
    )
    assert result["state"] == "EXACT"
    assert result["origin"]["path"] == "classes.py"
    assert result["origin"]["span"][0] == 4
    assert len(result["origin"]["source_sha256"]) == 64
    assert "hidden" not in repr(result)


def test_child_override_has_distinct_origin(tmp_path):
    child = 'class Child(Base):\n    ENDPOINT = "child-value"\n'
    base = 'class Base:\n    ENDPOINT = "base-value"\n'
    result = _origin(tmp_path, child, base)
    assert result["state"] == "EXACT"
    assert result["origin"]["span"][0] == 2
    assert "value" not in repr(result)


def test_none_literal_has_source_identity_without_exposing_value(tmp_path):
    index, paths = _index(
        tmp_path,
        {"classes.py": "class Child:\n    ENDPOINT = None\n"},
    )
    path = paths["classes.py"]
    result = resolve_declared_field_origin(
        _chain(index, path, ["Child"]), "ENDPOINT", index
    )
    assert result["state"] == "EXACT"
    assert result["origin"]["span"][0] == 2
    assert set(result["origin"]) == {"path", "span", "source_sha256"}


def test_duplicate_conditional_or_dynamic_binding_is_unknown(tmp_path):
    cases = (
        'class Child(Base):\n    ENDPOINT = "one"\n    ENDPOINT = "two"\n',
        'class Child(Base):\n    if flag:\n        ENDPOINT = "one"\n',
        "class Child(Base):\n    ENDPOINT = make_endpoint()\n",
    )
    for child in cases:
        result = _origin(tmp_path, child, 'class Base:\n    ENDPOINT = "base"\n')
        assert result["state"] == "UNKNOWN"


def test_instance_mutation_and_reflection_block_inherited_origin(tmp_path):
    cases = (
        'class Child(Base):\n    def update(self):\n        self.ENDPOINT = "new"\n',
        'class Child(Base):\n    def update(self):\n        setattr(self, "ENDPOINT", "new")\n',
        "class Child(Base):\n    def __getattribute__(self, name):\n        return super().__getattribute__(name)\n",
    )
    for child in cases:
        result = _origin(tmp_path, child, 'class Base:\n    ENDPOINT = "base"\n')
        assert result["state"] == "UNKNOWN"


def test_stale_source_cannot_return_origin(tmp_path):
    source = 'class Child(Base):\n    pass\nclass Base:\n    ENDPOINT = "base"\n'
    index, paths = _index(tmp_path, {"classes.py": source})
    path = paths["classes.py"]
    index.source_bytes[path] += b"\n"
    result = resolve_declared_field_origin(
        _chain(index, path, ["Child", "Base"]), "ENDPOINT", index
    )
    assert result["state"] == "UNKNOWN"
    assert result["reason"] == "class_source_unbound"


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


def _snapshot(tmp_path, source):
    path = (tmp_path / "client.py").resolve()
    raw = source.encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(
        tmp_path.resolve(), {path: tree}, {path: raw}, {path: digest}
    )
    aliases = {path: _Audit._module_security_aliases(tree)}
    return index, tree, path, aliases


def test_member_return_requires_verified_self_receiver(tmp_path):
    source = """import requests
class Client:
    ENDPOINT = "https://service.example/token"
    def endpoint(self):
        return self.ENDPOINT
    def send(self, other):
        self = other
        return requests.request("GET", self.endpoint())
"""
    index, tree, path, aliases = _snapshot(tmp_path, source)
    declaration = tree.body[1].body[0]
    fact = declaration_fact(index, path, declaration)
    sink = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "request"
    )
    classes = {(path, n.name): n for n in tree.body if isinstance(n, ast.ClassDef)}
    hops = method_url_hops(
        fact,
        path,
        sink,
        sink.args[1],
        index,
        {path: {}},
        classes,
        aliases,
        _Audit(),
        SimpleNamespace(bind_source_call=bind_source_call),
    )
    assert hops is None


def test_mutated_typing_provider_does_not_support_cast_flow(tmp_path):
    source = """import requests
import typing
def replacement(*args):
    return "unrelated"
typing.cast = replacement
class Client:
    ENDPOINT = "https://service.example/token"
    def endpoint(self):
        return typing.cast(str, self.ENDPOINT)
    def dispatch(self, url):
        return requests.request("GET", url)
    def send(self):
        return self.dispatch(self.endpoint())
"""
    index, tree, path, aliases = _snapshot(tmp_path, source)
    fact = declaration_fact(index, path, tree.body[-1].body[0])
    sink = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "request"
    )
    classes = {(path, n.name): n for n in tree.body if isinstance(n, ast.ClassDef)}
    assert (
        method_url_hops(
            fact,
            path,
            sink,
            sink.args[1],
            index,
            {path: {}},
            classes,
            aliases,
            _Audit(),
            SimpleNamespace(bind_source_call=bind_source_call),
        )
        is None
    )


def test_forwarder_rejects_finally_and_normal_handler_replacement(tmp_path):
    for replacement in (
        "        finally:\n            return None\n",
        "        except ValueError:\n            if condition:\n                raise\n            return None\n",
    ):
        source = """import functools
def transparent(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValueError:
            raise
    return wrapper
""".replace("        except ValueError:\n            raise\n", replacement)
        index, tree, path, _ = _snapshot(tmp_path, source)
        decorator = ast.Name("transparent", ast.Load())
        assert (
            forwarding_definition(
                path, decorator, index, {path: {"transparent": (path, "transparent")}}
            )
            is None
        )


def test_strategy_fallback_rejects_rebinding_and_control_flow(tmp_path):
    base = """def setting(self, name, default=None, backend=None):
    names = [name, name]
    if backend:
        names.insert(0, name)
    for value in names:
        try:
            return self.get_setting(value)
        except (AttributeError, KeyError):
            pass
    return default
"""
    variants = (
        base.replace(
            "    return default\n", "    default = None\n    return default\n"
        ),
        base.replace("names = [name, name]", "names = [opaque(default), name]"),
        base.replace(
            "    if backend:\n        names.insert(0, name)\n",
            "    if backend:\n        names.insert(0, opaque(default))\n",
        ),
        base.replace(
            "    if backend:\n        names.insert(0, name)\n",
            '    if backend:\n        names.insert(0, name)\n    else:\n        names[0] = "other"\n',
        ),
        base.replace(
            "        except (AttributeError, KeyError):\n            pass\n",
            '        except (AttributeError, KeyError):\n            pass\n        finally:\n            return "other"\n',
        ),
    )
    for source in variants:
        function = ast.parse(source).body[0]
        assert fallback_method(function) is None


def test_cast_and_format_alias_returns_keep_the_exact_endpoint_callsite(tmp_path):
    for label, imports, returned in (
        ("cast", "import typing", "typing.cast(str, alias)"),
        ("format", "", "alias.format(**{})"),
    ):
        root = tmp_path / label
        root.mkdir()
        source = f"""{imports}
import requests
class Client:
    ENDPOINT = "https://service.example/token"
    def identity(self, value):
        alias = value
        return {returned}
    def send(self):
        return requests.request("GET", self.identity(self.ENDPOINT))
"""
        index, tree, path, aliases = _snapshot(root, source)
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef))
        fact = declaration_fact(index, path, owner.body[0])
        sink = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "request"
        )
        classes = {(path, owner.name): owner}
        hops = method_url_hops(
            fact,
            path,
            sink,
            sink.args[1],
            index,
            {path: {}},
            classes,
            aliases,
            _Audit(),
            SimpleNamespace(bind_source_call=bind_source_call),
        )
        assert hops and any(row["role"] == "declared_member_read" for row in hops)


"""Real AST role derivation with clean, mixed-auth and unresolved-use controls."""


ENDPOINT = "https://appleid.apple.com/auth/token"


def _roles(tmp_path, extra=""):
    path = tmp_path / "client.py"
    raw = (
        "import requests\n"
        "class Client:\n"
        f"    ACCESS_TOKEN_URL = {ENDPOINT!r}\n"
        "    def send(self):\n"
        "        return requests.get(self.ACCESS_TOKEN_URL)\n" + extra
    ).encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    integrity.bind_security_call_scopes(tree)
    rows = endpoint_role_evidence(
        tmp_path,
        {path: tree},
        {path: {}},
        {path: raw},
        {path: digest},
        audit,
        integrity,
    )
    return rows["client.py", 3, "ACCESS_TOKEN_URL"]


def test_direct_endpoint_role_has_complete_declared_value_audit(tmp_path):
    row = _roles(tmp_path)
    assert row["url_witnesses"]
    assert row["value_use_audit"]["state"] == "COMPLETE"
    assert not row["linked_unknown_uses"]


def test_known_password_use_is_retained_separately(tmp_path):
    row = _roles(
        tmp_path,
        "    def login(self):\n"
        "        return requests.get('https://example.test', "
        "auth=('user', self.ACCESS_TOKEN_URL))\n",
    )
    assert row["known_auth_uses"]


@pytest.mark.parametrize(
    "statement",
    [
        "consume(self.ACCESS_TOKEN_URL)",
        "self.ACCESS_TOKEN_URL = replacement",
        "getattr(self, field_name)",
        "getattr(self, 'ACCESS_TOKEN_URL')",
        "self.__dict__['ACCESS_TOKEN_URL'] = replacement",
        "requests.get(self.ACCESS_TOKEN_URL, auth=opaque(self.ACCESS_TOKEN_URL))",
        "alias = self.ACCESS_TOKEN_URL\n        consume(alias)",
    ],
)
def test_unresolved_or_mutated_member_cannot_pass_use_audit(tmp_path, statement):
    row = _roles(tmp_path, f"    def other(self):\n        {statement}\n")
    assert row["linked_unknown_uses"]
    assert row["value_use_audit"]["state"] == "INCOMPLETE"


@pytest.mark.parametrize(
    "statement",
    [
        "getattr(Client, 'ACCESS_TOKEN_URL')",
        "vars(Client)['ACCESS_TOKEN_URL']",
        "Client.__dict__['ACCESS_TOKEN_URL']",
    ],
)
def test_external_reflection_retains_unknown_value_use(tmp_path, statement):
    row = _roles(tmp_path, f"\nconsume({statement})\n")
    assert row["linked_unknown_uses"]
    assert row["value_use_audit"]["state"] == "INCOMPLETE"


def test_descendant_credential_use_cannot_be_omitted(tmp_path):
    row = _roles(
        tmp_path,
        "class Child(Client):\n    pass\n"
        "requests.get('https://example.test', auth=('user', Child.ACCESS_TOKEN_URL))\n",
    )
    assert row["known_auth_uses"]


def test_alias_used_as_url_and_elsewhere_is_incomplete(tmp_path):
    row = _roles(
        tmp_path,
        "    def other(self):\n"
        "        url = self.ACCESS_TOKEN_URL\n"
        "        requests.request('GET', url)\n"
        "        consume(url)\n",
    )
    assert row["linked_unknown_uses"]
    assert row["value_use_audit"]["state"] == "INCOMPLETE"
