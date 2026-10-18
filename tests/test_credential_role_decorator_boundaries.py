import ast
import hashlib

from factoryline.credential_role_forwarding_decorator import method_rows
from factoryline.credential_role_sources import SourceSnapshotIndex


def _index(tmp_path, client, decorators):
    trees, raw, hashes, paths = {}, {}, {}, {}
    for name, source in {"client.py": client, "decorators.py": decorators}.items():
        path = (tmp_path / name).resolve()
        data = source.encode()
        tree = ast.parse(data)
        digest = hashlib.sha256(data).hexdigest()
        tree._oracle_source_sha256 = digest
        trees[path], raw[path], hashes[path], paths[name] = tree, data, digest, path
    index = SourceSnapshotIndex(tmp_path.resolve(), trees, raw, hashes)
    imports = {
        paths["client.py"]: {"transparent": (paths["decorators.py"], "transparent")}
    }
    return index, trees, paths, imports


def _decorator_source(extra=""):
    return (
        """import functools
"""
        + extra
        + """def transparent(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValueError:
            raise
    return wrapper
"""
    )


def test_rebound_consumer_import_is_not_a_verified_method_decorator(tmp_path):
    client = """from decorators import transparent
transparent = replacement
class Client:
    @transparent
    def send(self): return self.endpoint()
"""
    index, trees, paths, imports = _index(tmp_path, client, _decorator_source())
    owner = next(
        node
        for node in trees[paths["client.py"]].body
        if isinstance(node, ast.ClassDef)
    )
    rows, _ = method_rows([(paths["client.py"], "Client", owner)], index, imports)
    assert "send" not in rows


def test_mutated_functools_wraps_is_not_a_transparent_decorator(tmp_path):
    decorators = _decorator_source(
        "def replacement(func): return func\nfunctools.wraps = replacement\n"
    )
    client = """from decorators import transparent
class Client:
    @transparent
    def send(self): return self.endpoint()
"""
    index, trees, paths, imports = _index(tmp_path, client, decorators)
    owner = next(
        node
        for node in trees[paths["client.py"]].body
        if isinstance(node, ast.ClassDef)
    )
    rows, _ = method_rows([(paths["client.py"], "Client", owner)], index, imports)
    assert "send" not in rows


def test_wrapper_formal_cannot_shadow_captured_function(tmp_path):
    decorators = _decorator_source().replace(
        "def wrapper(*args, **kwargs):",
        "def wrapper(*args, func=replacement, **kwargs):",
    )
    _assert_decorator_rejected(tmp_path, decorators)


def test_exception_target_cannot_shadow_captured_function(tmp_path):
    decorators = _decorator_source().replace(
        "except ValueError:", "except ValueError as func:"
    )
    _assert_decorator_rejected(tmp_path, decorators)


def _assert_decorator_rejected(tmp_path, decorators):
    client = """from decorators import transparent
class Client:
    @transparent
    def send(self): return self.endpoint()
"""
    index, trees, paths, imports = _index(tmp_path, client, decorators)
    owner = next(
        node
        for node in trees[paths["client.py"]].body
        if isinstance(node, ast.ClassDef)
    )
    rows, _ = method_rows([(paths["client.py"], "Client", owner)], index, imports)
    assert "send" not in rows
