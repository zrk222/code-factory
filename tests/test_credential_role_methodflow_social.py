import ast
import hashlib
from types import SimpleNamespace

from factoryline.credential_role_method_paths import method_url_hop_paths
from factoryline.credential_role_sources import SourceSnapshotIndex, declaration_fact
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


def _snapshot(root, sources):
    trees, raw, inventory, paths = {}, {}, {}, {}
    for name, source in sources.items():
        path = (root / name).resolve()
        data = source.encode()
        tree = ast.parse(data)
        digest = hashlib.sha256(data).hexdigest()
        tree._oracle_source_sha256 = digest
        trees[path], raw[path], inventory[path], paths[name] = tree, data, digest, path
    return SourceSnapshotIndex(root.resolve(), trees, raw, inventory), trees, paths


def test_social_style_setting_cast_format_decorator_reaches_http_url(tmp_path):
    sources = {
        "decorators.py": """import functools
def transparent(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValueError:
            raise
    return wrapper
""",
        "strategy.py": """class BaseStrategy:
    def setting(self, name, default=None, backend=None):
        names = [name, name]
        if backend:
            names.insert(0, name)
        for value in names:
            try:
                return self.get_setting(value)
            except (AttributeError, KeyError):
                pass
        return default
""",
        "base.py": """import requests
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from strategy import BaseStrategy
class BaseAuth:
    def __init__(self, strategy: BaseStrategy | None = None):
        self.strategy: BaseStrategy = strategy if strategy is not None else object()
    def setting(self, name, default=None):
        return self.strategy.setting(name, default=default, backend=self)
    def request(self, url):
        return requests.request('GET', url)
    def get_json(self, url):
        return self.request(url)
""",
        "oauth.py": """from base import BaseAuth
from decorators import transparent
from typing import cast
class OAuthAuth(BaseAuth):
    ENDPOINT = '/token'
    def access_token_url(self):
        url = cast('str', self.setting('ENDPOINT', self.ENDPOINT))
        if params := self.get_format():
            return url.format(**params)
        return url
    def get_format(self):
        return {}
    def request_access_token(self, url):
        return self.get_json(url)
    @transparent
    def auth_complete(self):
        return self.request_access_token(self.access_token_url())
""",
    }
    index, trees, paths = _snapshot(tmp_path, sources)
    classes = {
        (path, node.name): node
        for path, tree in trees.items()
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    imports = {
        paths["oauth.py"]: {
            "BaseAuth": (paths["base.py"], "BaseAuth"),
            "transparent": (paths["decorators.py"], "transparent"),
        },
        paths["base.py"]: {},
    }
    audit = _Audit()
    aliases = {
        path: audit._module_security_aliases(tree) for path, tree in trees.items()
    }
    candidate = classes[(paths["oauth.py"], "OAuthAuth")].body[0]
    fact = declaration_fact(index, paths["oauth.py"], candidate)
    sink = next(
        node
        for node in ast.walk(trees[paths["base.py"]])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "request"
    )
    result = method_url_hop_paths(
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
    roles = {row["role"] for hops in result["paths"] for row in hops}
    assert "declared_string_format_input" in roles
    assert "strategy_lookup_fallback" in roles
    assert "verified_return_preserving_decorator" in roles
    assert "bound_method_parameter" in roles
    assert "method_argument_binding" in roles
