import ast
import hashlib

from factoryline.credential_role_method_contracts import alias_value, cast_value
from factoryline.credential_role_sources import SourceSnapshotIndex
from factoryline.credential_role_strategy_default import setting_default
from factoryline.credential_role_forwarding_decorator import forwarding_definition


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


def _index(tmp_path, sources):
    trees, raw, inventory, paths = {}, {}, {}, {}
    for name, source in sources.items():
        path = (tmp_path / name).resolve()
        data = source.encode()
        tree = ast.parse(data)
        digest = hashlib.sha256(data).hexdigest()
        tree._oracle_source_sha256 = digest
        trees[path], raw[path], inventory[path], paths[name] = tree, data, digest, path
    return SourceSnapshotIndex(tmp_path.resolve(), trees, raw, inventory), trees, paths


def test_alias_and_typing_cast_require_unique_source_bindings():
    function = ast.parse(
        "def f():\n value = cast(str, ENDPOINT)\n return value\n"
    ).body[0]
    use = function.body[-1].value
    rhs, assignment = alias_value(use, function)
    assert isinstance(rhs, ast.Call) and assignment.lineno == 2
    assert (
        alias_value(
            use,
            ast.parse(
                "def f():\n value = ENDPOINT\n value = OTHER\n return value\n"
            ).body[0],
        )
        is None
    )
    aliases = {"module": {"cast": "typing.cast"}}
    assert ast.unparse(cast_value(rhs, "module", aliases)) == "ENDPOINT"
    shadowed = ast.parse("cast = local\nvalue = cast(str, ENDPOINT)").body[1].value
    assert cast_value(shadowed, "module", {"module": {"cast": "local"}}) is None


def test_nominal_strategy_default_contract_is_source_bound(tmp_path):
    sources = {
        "backend.py": """from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from strategy import BaseStrategy
class BaseAuth:
    def __init__(self, strategy: BaseStrategy | None = None):
        self.strategy: BaseStrategy = strategy if strategy is not None else object()
    def setting(self, name, default=None):
        return self.strategy.setting(name, default=default, backend=self)
class OAuthAuth(BaseAuth):
    ENDPOINT = '/token'
    def lookup(self):
        return self.setting('ENDPOINT', self.ENDPOINT)
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
    }
    index, trees, paths = _index(tmp_path, sources)
    backend = paths["backend.py"]
    classes = {
        (path, node.name): node
        for path, tree in trees.items()
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    chain = [
        (backend, "OAuthAuth", classes[(backend, "OAuthAuth")]),
        (backend, "BaseAuth", classes[(backend, "BaseAuth")]),
    ]
    call = next(
        node
        for node in ast.walk(classes[(backend, "OAuthAuth")])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "setting"
    )
    result = setting_default(call, chain, index, classes)
    assert result and ast.unparse(result[0]) == "self.ENDPOINT"
    changed = sources["strategy.py"].replace("return default", "return None")
    bad_index, bad_trees, _ = _index(
        tmp_path / "changed", {**sources, "strategy.py": changed}
    )
    bad_classes = {
        (path, node.name): node
        for path, tree in bad_trees.items()
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    bad_backend = (tmp_path / "changed/backend.py").resolve()
    bad_chain = [
        (bad_backend, "OAuthAuth", bad_classes[(bad_backend, "OAuthAuth")]),
        (bad_backend, "BaseAuth", bad_classes[(bad_backend, "BaseAuth")]),
    ]
    bad_call = next(
        node
        for node in ast.walk(bad_classes[(bad_backend, "OAuthAuth")])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "setting"
    )
    assert setting_default(bad_call, bad_chain, bad_index, bad_classes) is None


def test_only_verified_return_preserving_decorator_is_transparent(tmp_path):
    index, trees, paths = _index(
        tmp_path,
        {
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
            "client.py": "from decorators import transparent\n@transparent\ndef target(self):\n    return self.url\n",
        },
    )
    decorator = trees[paths["client.py"]].body[1].decorator_list[0]
    imports = {
        paths["client.py"]: {"transparent": (paths["decorators.py"], "transparent")}
    }
    proof = forwarding_definition(paths["client.py"], decorator, index, imports)
    assert proof and proof[0] == paths["decorators.py"]
    bad_index, bad_trees, bad_paths = _index(
        tmp_path / "bad",
        {
            "decorators.py": """import functools
def transparent(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func('replacement')
    return wrapper
""",
            "client.py": "from decorators import transparent\n@transparent\ndef target(self):\n    return self.url\n",
        },
    )
    bad_decorator = bad_trees[bad_paths["client.py"]].body[1].decorator_list[0]
    assert (
        forwarding_definition(
            bad_paths["client.py"],
            bad_decorator,
            bad_index,
            {
                bad_paths["client.py"]: {
                    "transparent": (bad_paths["decorators.py"], "transparent")
                }
            },
        )
        is None
    )
