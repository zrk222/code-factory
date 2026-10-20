import ast
import hashlib
from factoryline.credential_role_forwarding_decorator import method_rows
from factoryline.credential_role_sources import SourceSnapshotIndex
from types import SimpleNamespace
import pytest
from factoryline.credential_role_bindings import class_chain
from factoryline.credential_role_chain_memo import ClassChainMemo
from factoryline.credential_role_adapter_selection import _property_default
from factoryline.credential_role_setting_boundary import _setting_getter_shape
from factoryline.review_audits import security_scan
import textwrap
from factoryline.credential_role_method_return import method_returns


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


# --- Merged from test_credential_role_chain_memo.py; test definitions and fixtures retained ---
"""Cached resolution must lose all credit if its frozen resolver changes."""


def setup(tmp_path, source="class Base: pass\nclass Child(Base): pass\n"):
    path = tmp_path / "app.py"
    raw = source.encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    classes = {(path, n.name): n for n in tree.body if isinstance(n, ast.ClassDef)}
    imports = {path: {}}
    audit = SimpleNamespace(_name=ast.unparse)
    index.class_chain_memo = ClassChainMemo(index, imports, classes, audit)
    return path, index, imports, classes, audit


def test_cached_chain_is_immutable_local_and_matches_uncached(tmp_path):
    path, index, imports, classes, audit = setup(tmp_path)
    first = class_chain(index, path, "Child", imports, classes, audit)
    assert isinstance(first, tuple)
    assert len(first) == 2
    assert class_chain(index, path, "Child", imports, classes, audit) is first
    assert index.class_chain_memo.valid()
    with pytest.raises(TypeError):
        first[0] = None
    _, other, _, _, _ = setup(tmp_path)
    assert other.class_chain_memo.entries == {}


@pytest.mark.parametrize(
    "mutation",
    [
        "bytes",
        "inventory",
        "ast",
        "alias",
        "class",
        "duplicate",
        "base",
        "decorator",
        "helper",
        "membership",
    ],
)
def test_mutation_after_hit_invalidates_all_credit(tmp_path, mutation):
    path, index, imports, classes, audit = setup(tmp_path)
    assert class_chain(index, path, "Child", imports, classes, audit)
    tree = index.snapshots[path]
    if mutation == "bytes":
        index.source_bytes[path] += b"# changed"
    elif mutation == "inventory":
        index.inventory[path] = "0" * 64
    elif mutation == "ast":
        tree.body.append(ast.Pass())
    elif mutation == "alias":
        imports[path]["Other"] = (path, "Base")
    elif mutation == "class":
        classes[(path, "Child")] = ast.ClassDef(
            name="Child", bases=[], keywords=[], body=[], decorator_list=[]
        )
    elif mutation == "duplicate":
        tree.body.append(ast.parse("class Child: pass").body[0])
    elif mutation == "base":
        tree.body[1].bases = []
    elif mutation == "decorator":
        tree.body[1].decorator_list.append(ast.Name(id="opaque", ctx=ast.Load()))
    elif mutation == "helper":
        audit._name = lambda node: "Other"
    else:
        index.snapshots.pop(path)
    assert index.class_chain_memo.valid() is False


def test_different_resolver_mapping_gets_no_cached_credit(tmp_path):
    path, index, imports, classes, audit = setup(tmp_path)
    assert class_chain(index, path, "Child", imports, classes, audit)
    assert class_chain(index, path, "Child", dict(imports), classes, audit) is None
    assert class_chain(index, path, "Child", imports, dict(classes), audit) is None


@pytest.mark.parametrize(
    "source,name",
    [
        ("class A(B): pass\nclass B(A): pass\n", "A"),
        ("class A: pass\nclass A: pass\n", "A"),
        ("@opaque\nclass A: pass\n", "A"),
        ("class A(Unknown): pass\n", "A"),
    ],
)
def test_failed_resolution_stays_failed_on_repeated_queries(tmp_path, source, name):
    path, index, imports, classes, audit = setup(tmp_path, source)
    for _ in range(2):
        assert class_chain(index, path, name, imports, classes, audit) is None


def test_uncached_and_cached_resolution_agree(tmp_path):
    path, index, imports, classes, audit = setup(tmp_path)
    cached = class_chain(index, path, "Child", imports, classes, audit)
    del index.class_chain_memo
    assert tuple(class_chain(index, path, "Child", imports, classes, audit)) == cached


@pytest.mark.parametrize(
    "extra",
    [
        "",
        "    def leak(self):\n        opaque(self.ACCESS_TOKEN_URL)\n",
        "    def leak(self):\n        requests.get('https://other.example', auth=('u', self.ACCESS_TOKEN_URL))\n",
    ],
)
def test_cached_and_uncached_actual_scanner_findings_match(
    tmp_path, monkeypatch, extra
):
    from factoryline.review_audits import security_scan
    import factoryline.credential_role_chain_memo as module
    import factoryline.credential_endpoint_admission as admission

    (tmp_path / "app.py").write_text(
        "import requests\nclass Client:\n"
        "    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'\n"
        "    def send(self):\n        return requests.get(self.ACCESS_TOKEN_URL)\n"
        + extra,
        encoding="utf-8",
    )
    cached = security_scan(tmp_path, cache_enabled=False)

    class Uncached(ClassChainMemo):
        def resolve(self, path, name, resolver):
            return resolver()

    monkeypatch.setattr(module, "ClassChainMemo", Uncached)
    admission._WORKSPACES.clear()
    uncached = security_scan(tmp_path, cache_enabled=False)

    def projection(report):
        return [
            (
                key,
                f["code"],
                f["path"],
                f["line"],
                f["severity"],
                f.get("facts", {}).get("disposition"),
            )
            for key in ("findings", "primitive_observations")
            for f in report.get(key, [])
        ]

    assert projection(cached) == projection(uncached)


# --- Merged from test_credential_role_default_guards.py; test definitions and fixtures retained ---
"""Reject invented default adapter transfers in the finite source model."""


@pytest.mark.parametrize(
    "fallback",
    [
        "lambda name, dflt: supplied",
        "lambda name, dflt: getattr(settings, name, 'other')",
        "lambda name, dflt: getattr(settings, 'OTHER', dflt)",
    ],
)
def test_setting_fallback_must_preserve_default(tmp_path, fallback):
    tree = ast.parse(
        "def get_setting(name, dflt):\n"
        f"    getter = getattr(settings, 'ALLAUTH_SETTING_GETTER', {fallback})\n"
        "    getter = import_callable(getter)\n"
        "    return getter(name, dflt)\n"
    )
    assert _setting_getter_shape({tmp_path / "utils.py": tree}) is None


def test_decorated_getter_cannot_prove_default(tmp_path):
    tree = ast.parse(
        "@replacement\n"
        "def get_setting(name, dflt):\n"
        "    getter = getattr(settings, 'ALLAUTH_SETTING_GETTER', "
        "lambda name, dflt: getattr(settings, name, dflt))\n"
        "    getter = import_callable(getter)\n"
        "    return getter(name, dflt)\n"
    )
    assert _setting_getter_shape({tmp_path / "utils.py": tree}) is None


@pytest.mark.parametrize(
    "prefix",
    [
        "self = supplied",
        "self._setting = supplied",
        "mutate(self)",
    ],
)
def test_property_cannot_mutate_its_receiver_before_default(prefix):
    owner = ast.parse(
        "class Settings:\n"
        "    @property\n"
        "    def ADAPTER(self):\n"
        f"        {prefix}\n"
        "        return self._setting('ADAPTER', 'module.Adapter')\n"
    ).body[0]
    assert _property_default(owner) is None


# --- Merged from test_credential_role_discarded_getter.py; test definitions and fixtures retained ---
"""Discarded return values do not waive callee or authentication obligations."""


BASE = """import requests
class Client:
    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'
    def endpoint(self):
{getter}
    def send(self, url): return requests.request('POST', url)
    def run(self): return self.send(self.endpoint())
{child}
{inspect}
"""


@pytest.mark.parametrize(
    "getter,child,inspect,active",
    [
        (
            "        return self.ACCESS_TOKEN_URL",
            "",
            "def inspect(client):\n    client.endpoint()",
            False,
        ),
        (
            "        requests.get('https://other.test', auth=('u', self.ACCESS_TOKEN_URL))\n        return self.ACCESS_TOKEN_URL",
            "",
            "def inspect(client):\n    client.endpoint()",
            True,
        ),
        (
            "        value = self.ACCESS_TOKEN_URL\n        requests.get('https://other.test', auth=('u', value))\n        return value",
            "",
            "def inspect(client):\n    client.endpoint()",
            True,
        ),
        (
            "        return self.ACCESS_TOKEN_URL",
            "class Child(Client):\n    def endpoint(self):\n        requests.get('https://other.test', auth=('u', super().endpoint()))",
            "def inspect(client):\n    client.endpoint()",
            True,
        ),
        (
            "        return self.ACCESS_TOKEN_URL",
            "",
            "def inspect(client):\n    result = client.endpoint()",
            True,
        ),
        (
            "        return self.ACCESS_TOKEN_URL",
            "",
            "async def inspect(client):\n    await client.endpoint()",
            True,
        ),
        (
            "        return self.ACCESS_TOKEN_URL",
            "",
            "def inspect(client):\n    opaque(client.endpoint())",
            True,
        ),
        (
            "        return self.ACCESS_TOKEN_URL",
            "",
            "def inspect(client):\n    client.endpoint(unknown())",
            True,
        ),
    ],
)
def test_discarded_getter_only_closes_the_exact_unused_result(
    tmp_path, getter, child, inspect, active
):
    (tmp_path / "client.py").write_text(
        BASE.format(getter=getter, child=child, inspect=inspect), encoding="utf-8"
    )
    result = security_scan(tmp_path, cache_enabled=False)
    findings = [
        row
        for row in result["findings"]
        if row["code"] == "SECURITY_HARDCODED_SECRET" and row["line"] == 3
    ]
    assert bool(findings) is active
    if active:
        assert findings[0]["severity"] == "CRITICAL"
    else:
        primitive = [
            row
            for row in result["primitive_observations"]
            if row["code"] == "SECURITY_HARDCODED_SECRET" and row["line"] == 3
        ]
        assert len(primitive) == 1 and primitive[0]["severity"] == "CRITICAL"
        assert (
            primitive[0]["facts"]["disposition"] == "ENDPOINT_DECLARATION_ROLE_PROVEN"
        )


# --- Merged from test_credential_role_try_returns.py; test definitions and fixtures retained ---


def _method_index(tmp_path, function_source):
    source = textwrap.dedent(function_source).strip() + "\n"
    path = (tmp_path / "oauth.py").resolve()
    raw = source.encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(
        tmp_path.resolve(), {path: tree}, {path: raw}, {path: digest}
    )
    index.validate(path)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
    return method_returns(function, index, path)


def test_try_return_with_reraising_handler_is_source_preserving(tmp_path):
    returns = _method_index(
        tmp_path,
        """def refresh_token_url(self):
    try:
        return self.REFRESH_URL or self.access_token_url()
    except AuthError as error:
        error.stage = 'refresh'
        raise""",
    )
    assert len(returns) == 1
    assert isinstance(returns[0].value, ast.BoolOp)


@pytest.mark.parametrize(
    "source",
    [
        """def f(self):
    try:
        return self.endpoint()
    except Error:
        raise
    finally:
        return None""",
        """def f(self):
    try:
        return self.endpoint()
    except Error:
        return self.other()""",
        """def f(self):
    try:
        return self.endpoint()
    except Error:
        error.stage = 'refresh'
        pass""",
        """def f(self):
    try:
        return self.endpoint()
    except Error:
        raise
    else:
        return self.other()""",
    ],
)
def test_try_return_rejects_overrides_and_normal_handler_paths(tmp_path, source):
    assert _method_index(tmp_path, source) == []
