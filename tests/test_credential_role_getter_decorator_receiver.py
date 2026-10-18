import ast
import hashlib

from factoryline.credential_role_method_use_getters import _stable_self
from factoryline.credential_role_sources import SourceSnapshotIndex


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
