import ast
import hashlib
from types import SimpleNamespace

from factoryline.credential_role_forwarding_decorator import forwarding_definition
from factoryline.credential_role_method_flow import method_url_hops
from factoryline.credential_role_sources import SourceSnapshotIndex, declaration_fact
from factoryline.credential_role_strategy_fallback import fallback_method
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
