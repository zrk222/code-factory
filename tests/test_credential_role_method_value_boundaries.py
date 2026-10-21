import ast
import hashlib
from types import SimpleNamespace

from factoryline.credential_role_paths import method_url_hops
from factoryline.credential_role_constructor_provider import (
    SourceSnapshotIndex,
    declaration_fact,
)
from factoryline.review_integrity import bind_source_call


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


def test_local_typing_alias_mutation_vetoes_cast(tmp_path):
    source = """import requests
import typing as t
def replacement(*args): return "unrelated"
t.cast = replacement
class Client:
    ENDPOINT = "https://service.example/token"
    def endpoint(self): return t.cast(str, self.ENDPOINT)
    def dispatch(self, url): return requests.request("GET", url)
    def send(self): return self.dispatch(self.endpoint())
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


def test_returned_parameter_alias_uses_the_current_callsite(tmp_path):
    source = """import requests
class Client:
    ENDPOINT = "https://service.example/token"
    def identity(self, value):
        alias = value
        return alias
    def send(self):
        return requests.request("GET", self.identity("https://other.example/"))
    def unused(self):
        return self.identity(self.ENDPOINT)
"""
    index, tree, path, aliases = _snapshot(tmp_path, source)
    fact = declaration_fact(index, path, tree.body[1].body[0])
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


def test_formatted_literal_with_substitution_is_not_exact_endpoint_value(tmp_path):
    source = """import requests
class Client:
    ENDPOINT = "https://service.example/{tenant}/token"
    def endpoint(self): return self.ENDPOINT.format(tenant="alpha")
    def dispatch(self, url): return requests.request("GET", url)
    def send(self): return self.dispatch(self.endpoint())
"""
    index, tree, path, aliases = _snapshot(tmp_path, source)
    fact = declaration_fact(index, path, tree.body[1].body[0])
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


def test_cast_transform_keeps_current_callsite_environment(tmp_path):
    source = """import requests
import typing
class Client:
    ENDPOINT = "https://service.example/token"
    def identity(self, value):
        alias = value
        return typing.cast(str, alias)
    def send(self): return requests.request("GET", self.identity("https://other.example/"))
    def unrelated(self): return self.identity(self.ENDPOINT)
"""
    _assert_sink_does_not_match_fact(tmp_path, source)


def test_format_transform_keeps_current_callsite_environment(tmp_path):
    source = """import requests
class Client:
    ENDPOINT = "https://service.example/token"
    def identity(self, value):
        alias = value
        return alias.format(**{})
    def send(self): return requests.request("GET", self.identity("https://other.example/"))
    def unrelated(self): return self.identity(self.ENDPOINT)
"""
    _assert_sink_does_not_match_fact(tmp_path, source)


def _assert_sink_does_not_match_fact(tmp_path, source):
    index, tree, path, aliases = _snapshot(tmp_path, source)
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
