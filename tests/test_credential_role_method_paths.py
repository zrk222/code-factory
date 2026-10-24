from pathlib import Path
from factoryline import credential_role_paths as paths
from factoryline import review_audits as audit
from factoryline import review_integrity as integrity
import ast
import hashlib
from types import SimpleNamespace
from factoryline.credential_role_paths import method_url_hop_paths
from factoryline.credential_role_constructor_provider import (
    SourceSnapshotIndex,
    declaration_fact,
)
from factoryline.review_integrity import bind_source_call
import pytest
from factoryline.credential_role_constructor_provider import ClassChainMemo
from factoryline.credential_role_method_use_getter_audit import absolute_path


class _Audit:
    @staticmethod
    def _name(node):
        return ast.unparse(node)

    @staticmethod
    def _module_security_aliases(tree):
        return {
            item.asname or item.name.split(".")[0]: item.name
            for statement in tree.body
            if isinstance(statement, ast.Import)
            for item in statement.names
        }


def test_all_matching_callers_remain_separate_exact_paths(tmp_path, monkeypatch):
    source = """import requests
class Client:
    ENDPOINT = "https://service.example/token"
    def identity(self, value):
        alias = value
        return alias
    def dispatch(self, url):
        return requests.request("GET", url)
    def send(self):
        self.dispatch(self.identity(self.ENDPOINT))
        self.dispatch(self.ENDPOINT)
"""
    path = (tmp_path / "client.py").resolve()
    raw = source.encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(
        tmp_path.resolve(), {path: tree}, {path: raw}, {path: digest}
    )
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef))
    classes = {(path, owner.name): owner}
    imports = {path: {}}
    audit = _Audit()
    from factoryline import credential_role_paths as path_module
    from factoryline import credential_role_paths as forwarding
    from factoryline.credential_role_constructor_provider import ClassChainMemo

    index.class_chain_memo = ClassChainMemo(index, imports, classes, audit)
    calls = []
    original = forwarding.method_rows

    def count_method_rows(*args):
        calls.append(1)
        return original(*args)

    monkeypatch.setattr(path_module, "method_rows", count_method_rows)
    fact = declaration_fact(index, path, owner.body[0])
    sink = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "request"
    )
    aliases = {path: audit._module_security_aliases(tree)}
    result = method_url_hop_paths(
        fact,
        path,
        sink,
        sink.args[1],
        index,
        imports,
        classes,
        aliases,
        audit,
        SimpleNamespace(bind_source_call=bind_source_call),
    )
    assert result["state"] == "BRANCH_ENUMERATION_COMPLETE"
    assert len(result["paths"]) == 2
    assert all(
        {row["role"] for row in route}.issuperset(
            {"method_argument_binding", "bound_method_parameter"}
        )
        for route in result["paths"]
    )
    spans = {
        (row["line"], row["column"])
        for route in result["paths"]
        for row in route
        if row["role"] == "method_argument_binding"
    }
    assert len(spans) >= 2
    assert len(calls) == 1
    values = iter((True, False))
    monkeypatch.setattr(index.class_chain_memo, "valid", lambda: next(values))
    stale = method_url_hop_paths(
        fact,
        path,
        sink,
        sink.args[1],
        index,
        imports,
        classes,
        aliases,
        audit,
        SimpleNamespace(bind_source_call=bind_source_call),
    )
    assert stale == {
        "state": "INCOMPLETE",
        "paths": [],
        "reason": "snapshot_revalidation_failed",
    }


"""Reverse lookup preserves ambiguity and final source validation."""


def _index(root, count=3):
    raw = b"pass\n"
    digest = hashlib.sha256(raw).hexdigest()
    trees = {}
    for number in range(count):
        tree = ast.parse(raw)
        tree._oracle_source_sha256 = digest
        trees[root / f"file{number}.py"] = tree
    index = SourceSnapshotIndex(
        root, trees, dict.fromkeys(trees, raw), dict.fromkeys(trees, digest)
    )
    memo = ClassChainMemo(index, {}, {}, SimpleNamespace(_name=ast.unparse))
    index.class_chain_memo = memo
    return index, memo


def test_path_table_is_built_once_per_batch(tmp_path, monkeypatch):
    index, memo = _index(tmp_path)
    original, calls = index.relative, []

    def relative(path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(index, "relative", relative)
    with memo.analysis_batch() as batch:
        for _ in range(100):
            assert absolute_path(index, "file1.py") == tmp_path / "file1.py"
            assert absolute_path(index, "absent") is None
    assert batch.accepted and len(calls) == 3
    assert absolute_path(index, "file1.py") == tmp_path / "file1.py"
    assert len(calls) == 6


def test_duplicate_relative_paths_stay_ambiguous(tmp_path, monkeypatch):
    index, memo = _index(tmp_path)
    monkeypatch.setattr(index, "relative", lambda path: "same")
    with memo.analysis_batch() as batch:
        assert absolute_path(index, "same") is None
        assert absolute_path(index, "absent") is None
    assert batch.accepted


def test_native_bound_method_identity_is_stable(tmp_path):
    index, memo = _index(tmp_path)
    with memo.analysis_batch() as batch:
        for _ in range(100):
            assert absolute_path(index, "file1.py") == tmp_path / "file1.py"
    assert batch.accepted


def test_changed_relative_helper_rejects_batch(tmp_path, monkeypatch):
    index, memo = _index(tmp_path)
    with memo.analysis_batch() as batch:
        assert absolute_path(index, "file1.py")
        monkeypatch.setattr(index, "relative", lambda path: "changed")
        assert absolute_path(index, "file1.py") is None
    assert not batch.accepted


def test_late_source_mutation_rejects_batch(tmp_path):
    index, memo = _index(tmp_path)
    with memo.analysis_batch() as batch:
        path = absolute_path(index, "file1.py")
        index.snapshots[path].body.append(ast.Pass())
    assert not batch.accepted


@pytest.mark.parametrize("change", ["root", "keys", "inventory", "bytes"])
def test_path_cache_cannot_accept_changed_source_context(tmp_path, change):
    index, memo = _index(tmp_path)
    with memo.analysis_batch() as batch:
        path = absolute_path(index, "file1.py")
        if change == "root":
            index.root = tmp_path / "other"
        elif change == "keys":
            index.snapshots.pop(path)
        elif change == "inventory":
            index.inventory[path] = "invalid"
        else:
            index.source_bytes[path] = b"different\n"
    assert not batch.accepted


def test_none_projection_matches_old_lookup(tmp_path, monkeypatch):
    index, memo = _index(tmp_path, 1)
    monkeypatch.setattr(index, "relative", lambda path: None)
    with memo.analysis_batch() as batch:
        assert absolute_path(index, None) == tmp_path / "file0.py"
        assert absolute_path(index, "file0.py") is None
    assert batch.accepted


def test_invalid_epoch_falls_back_without_acceptance(tmp_path):
    _, memo = _index(tmp_path)
    with memo.analysis_batch() as batch:
        assert memo.source_model("bad", lambda: True, helper_epoch=lambda: None)
    assert not batch.accepted


def test_bound_epoch_replacement_cannot_reuse_cached_acceptance(tmp_path, monkeypatch):
    index, memo = _index(tmp_path)
    with memo.analysis_batch() as batch:
        assert memo.source_model(
            "bound", lambda: True, helper_epoch=lambda: (index.relative,)
        )
        monkeypatch.setattr(index, "relative", lambda path: "changed")
        assert not memo.source_model(
            "bound", lambda: False, helper_epoch=lambda: (index.relative,)
        )
    assert not batch.accepted


def _paths_contract_index(root, sources):
    root = Path(root).resolve()
    snapshots, source_bytes, inventory = {}, {}, {}
    for relative, source in sources.items():
        path = (root / relative).resolve()
        raw = source.encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        tree = ast.parse(raw)
        tree._oracle_source_sha256 = digest
        snapshots[path] = tree
        source_bytes[path] = raw
        inventory[path] = digest
    index = SourceSnapshotIndex(root, snapshots, source_bytes, inventory)
    for path in snapshots:
        assert index.validate(path)
    return index, snapshots


def _parents(tree):
    return {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }


def _named(tree, kind, name):
    return next(
        node for node in ast.walk(tree) if isinstance(node, kind) and node.name == name
    )


def _flow(index, path, trace):
    def prepend(role, source_path, node, found):
        if found is None:
            return None
        return [(role, source_path, node), *found]

    return SimpleNamespace(
        aliases={path: audit._module_security_aliases(index.snapshots[path])},
        index=index,
        chain=(),
        classes={},
        methods={},
        blocked_choices=set(),
        decorator_proofs={},
        integrity=SimpleNamespace(bind_source_call=integrity.bind_source_call),
        fact=SimpleNamespace(_literal="https://service.example/token"),
        branch_choices=[],
        trace=trace,
        _prepend=prepend,
    )


def test_credential_paths_useful_body_keeps_executable_statements():
    function = _named(
        ast.parse(
            'def read():\n    """explanation"""\n    value = 7\n    return value\n'
        ),
        ast.FunctionDef,
        "read",
    )
    body = paths.useful_body(function)
    assert [type(node) for node in body] == [ast.Assign, ast.Return]
    assert paths.useful_body(ast.parse('def empty():\n    """only"""\n').body[0]) == []


def test_credential_paths_single_return_rejects_extra_work():
    accepted = _named(
        ast.parse('def read():\n    """doc"""\n    return 7\n'), ast.FunctionDef, "read"
    )
    rejected = _named(
        ast.parse("def read():\n    value = 7\n    return value\n"),
        ast.FunctionDef,
        "read",
    )
    assert paths.single_return(accepted) is True
    assert paths.single_return(rejected) is False


def test_credential_paths_default_getter_requires_exact_fallback():
    accepted = ast.parse(
        "getattr(settings, 'ALLAUTH_SETTING_GETTER', "
        "lambda name, dflt: getattr(settings, name, dflt))",
        mode="eval",
    ).body
    wrong_setting = ast.parse(
        "getattr(settings, 'OTHER_GETTER', "
        "lambda name, dflt: getattr(settings, name, dflt))",
        mode="eval",
    ).body
    wrong_parameters = ast.parse(
        "getattr(settings, 'ALLAUTH_SETTING_GETTER', "
        "lambda name: getattr(settings, name, None))",
        mode="eval",
    ).body
    assert paths.default_getter(accepted) is True
    assert paths.default_getter(wrong_setting) is False
    assert paths.default_getter(wrong_parameters) is False


def test_credential_paths_getter_environment_rejects_shadowed_imports():
    valid_source = (
        "from django.conf import settings\n"
        "from django.utils.module_loading import import_string\n"
        "def import_callable(path_or_callable):\n"
        "    if not callable(path_or_callable):\n"
        "        ret = import_string(path_or_callable)\n"
        "    else:\n"
        "        ret = path_or_callable\n"
        "    return ret\n"
        "def get_setting(name, dflt):\n"
        "    return dflt\n"
    )
    tree = ast.parse(valid_source)
    getter = _named(tree, ast.FunctionDef, "get_setting")
    assert paths.getter_environment(tree, getter) is True

    shadowed = ast.parse(valid_source + "settings = object()\n")
    shadowed_getter = _named(shadowed, ast.FunctionDef, "get_setting")
    assert paths.getter_environment(shadowed, shadowed_getter) is False

    decorated = ast.parse(
        valid_source.replace("def get_setting", "@route\ndef get_setting")
    )
    decorated_getter = _named(decorated, ast.FunctionDef, "get_setting")
    assert paths.getter_environment(decorated, decorated_getter) is False


def test_credential_paths_property_default_returns_exact_setting_nodes():
    tree = ast.parse(
        "class AdapterSettings:\n"
        "    @property\n"
        "    def ADAPTER(self):\n"
        "        return self._setting('ADAPTER', 'demo.adapter.Client')\n"
    )
    owner = _named(tree, ast.ClassDef, "AdapterSettings")
    result = paths.property_default(owner)
    assert result is not None
    function, returned, value, literal = result
    assert function.name == "ADAPTER"
    assert returned.value.func.attr == "_setting"
    assert value.value == "demo.adapter.Client"
    assert literal == "demo.adapter.Client"

    malformed = ast.parse(
        "class AdapterSettings:\n"
        "    @property\n"
        "    def ADAPTER(self):\n"
        "        return self._setting('ADAPTER', 'local')\n"
    )
    assert (
        paths.property_default(_named(malformed, ast.ClassDef, "AdapterSettings"))
        is None
    )


def test_credential_paths_enclosing_function_uses_nearest_scope(tmp_path):
    index, snapshots = _paths_contract_index(
        tmp_path,
        {"nested.py": "def outer():\n    def inner():\n        return 1\n"},
    )
    path = tmp_path.resolve() / "nested.py"
    tree = snapshots[path]
    inner_return = next(node for node in ast.walk(tree) if isinstance(node, ast.Return))
    index.parents[path] = _parents(tree)
    assert paths.enclosing_function(inner_return, index, path).name == "inner"
    module_assignment = ast.parse("value = 1").body[0]
    index.parents[path][id(module_assignment)] = tree
    assert paths.enclosing_function(module_assignment, index, path) is None


def test_credential_paths_is_parameter_rejects_a_local_rebind():
    clean = _named(
        ast.parse("def send(endpoint):\n    return endpoint\n"), ast.FunctionDef, "send"
    )
    rebound = _named(
        ast.parse(
            "def send(endpoint):\n    endpoint = 'replacement'\n    return endpoint\n"
        ),
        ast.FunctionDef,
        "send",
    )
    assert paths.is_parameter(clean, "endpoint") is True
    assert paths.is_parameter(clean, "absent") is False
    assert paths.is_parameter(rebound, "endpoint") is False


def test_credential_paths_returned_parameter_resolves_only_unique_aliases():
    function = _named(
        ast.parse(
            "def send(endpoint):\n"
            "    first = endpoint\n"
            "    second = first\n"
            "    return second\n"
        ),
        ast.FunctionDef,
        "send",
    )
    result = paths.returned_parameter(function, function.body[-1].value)
    assert result[0] == "endpoint"
    assert [row.targets[0].id for row in result[1]] == ["second", "first"]

    rebound = _named(
        ast.parse(
            "def send(endpoint):\n"
            "    alias = endpoint\n"
            "    alias = 'changed'\n"
            "    return alias\n"
        ),
        ast.FunctionDef,
        "send",
    )
    assert paths.returned_parameter(rebound, rebound.body[-1].value) == (None, [])


def test_credential_paths_format_receiver_accepts_only_keyword_expansion():
    accepted = ast.parse("self.endpoint.format(**fields)", mode="eval").body
    positional = ast.parse("self.endpoint.format(fields)", mode="eval").body
    named = ast.parse("self.endpoint.format(values=fields)", mode="eval").body
    assert ast.unparse(paths.format_receiver(accepted)) == "self.endpoint"
    assert paths.format_receiver(positional) is None
    assert paths.format_receiver(named) is None


def test_credential_paths_verified_instance_receiver_rejects_static_methods(tmp_path):
    index, snapshots = _paths_contract_index(
        tmp_path,
        {
            "direct.py": (
                "class Client:\n"
                "    def send(self):\n"
                "        return self.session.request()\n"
                "class StaticClient:\n"
                "    @staticmethod\n"
                "    def send(self):\n"
                "        return self.session.request()\n"
            )
        },
    )
    path = tmp_path.resolve() / "direct.py"
    tree = snapshots[path]
    index.parents[path] = _parents(tree)
    direct_owner = _named(tree, ast.ClassDef, "Client")
    direct_method = _named(direct_owner, ast.FunctionDef, "send")
    direct_call = next(
        node for node in ast.walk(direct_method) if isinstance(node, ast.Call)
    )
    static_owner = _named(tree, ast.ClassDef, "StaticClient")
    static_method = _named(static_owner, ast.FunctionDef, "send")
    static_call = next(
        node for node in ast.walk(static_method) if isinstance(node, ast.Call)
    )
    assert (
        paths.verified_instance_receiver(
            direct_call, direct_method, direct_owner, index, path, False
        )
        is True
    )
    assert (
        paths.verified_instance_receiver(
            static_call, static_method, static_owner, index, path, False
        )
        is False
    )


def test_credential_paths_source_span_reports_hash_and_relative_path(tmp_path):
    index, snapshots = _paths_contract_index(tmp_path, {"sample.py": "value = 1\n"})
    path = tmp_path.resolve() / "sample.py"
    node = snapshots[path].body[0]
    record = paths.source_span(index, path, node, "assignment")
    assert record == {
        "path": "sample.py",
        "line": 1,
        "column": 0,
        "end_line": 1,
        "end_column": 9,
        "source_sha256": hashlib.sha256(b"value = 1\n").hexdigest(),
        "role": "assignment",
    }

    outside = tmp_path.resolve().parent / "outside.py"
    outside_raw = b"value = 2\n"
    outside_tree = ast.parse(outside_raw)
    outside_tree._oracle_source_sha256 = hashlib.sha256(outside_raw).hexdigest()
    outside_index = SourceSnapshotIndex(
        tmp_path.resolve(),
        {outside: outside_tree},
        {outside: outside_raw},
        {outside: hashlib.sha256(outside_raw).hexdigest()},
    )
    assert (
        paths.source_span(outside_index, outside, outside_tree.body[0], "external")[
            "path"
        ]
        is None
    )


def test_credential_paths_settings_module_bridge_rejects_duplicate_instance():
    source = (
        "class AppSettings:\n"
        "    pass\n"
        "def __getattr__(name):\n"
        "    return getattr(_app_settings, name)\n"
        "_app_settings = AppSettings('demo.settings')\n"
    )
    tree = ast.parse(source)
    owner = _named(tree, ast.ClassDef, "AppSettings")
    bridge = paths.settings_module_bridge(
        {"settings.py": tree}, "settings.py", owner, paths.module_binding
    )
    assert bridge is not None
    assert bridge[0].name == "__getattr__"
    assert bridge[1].targets[0].id == "_app_settings"

    duplicate = ast.parse(source + "_app_settings = AppSettings('shadow.settings')\n")
    duplicate_owner = _named(duplicate, ast.ClassDef, "AppSettings")
    assert (
        paths.settings_module_bridge(
            {"settings.py": duplicate},
            "settings.py",
            duplicate_owner,
            paths.module_binding,
        )
        is None
    )


def test_credential_paths_module_binding_requires_one_binding_of_requested_kind():
    tree = ast.parse("class Adapter:\n    pass\ndef resolve():\n    return Adapter\n")
    assert isinstance(paths.module_binding(tree, "Adapter", ast.ClassDef), ast.ClassDef)
    assert paths.module_binding(tree, "resolve", ast.ClassDef) is None
    assert paths.module_binding(tree, "missing", ast.FunctionDef) is None
    duplicate = ast.parse(
        "def resolve():\n    return 1\ndef resolve():\n    return 2\n"
    )
    assert paths.module_binding(duplicate, "resolve", ast.FunctionDef) is None


def test_credential_paths_trace_call_records_only_verified_cast_hops(tmp_path):
    index, snapshots = _paths_contract_index(
        tmp_path,
        {"cast.py": "import typing\nvalue = typing.cast(str, secret)\n"},
    )
    path = tmp_path.resolve() / "cast.py"
    call = next(
        node for node in ast.walk(snapshots[path]) if isinstance(node, ast.Call)
    )
    flow = _flow(index, path, lambda value, *_args: [("value", value)])
    traced = paths.trace_call(flow, call, None, path, set(), 0)
    assert [row[0] for row in traced] == ["typing_cast_value", "value"]
    assert traced[0][2] is call

    mutated_index, mutated_snapshots = _paths_contract_index(
        tmp_path / "mutated",
        {
            "cast.py": (
                "import typing\n"
                "typing.cast = opaque\n"
                "value = typing.cast(str, secret)\n"
            )
        },
    )
    mutated_path = (tmp_path / "mutated").resolve() / "cast.py"
    mutated_call = next(
        node
        for node in ast.walk(mutated_snapshots[mutated_path])
        if isinstance(node, ast.Call)
    )
    fallback = _flow(
        mutated_index,
        mutated_path,
        lambda *_args: pytest.fail("shadowed cast was traced"),
    )
    fallback._return_call = lambda *_args: "return-call-fallback"
    assert (
        paths.trace_call(fallback, mutated_call, None, mutated_path, set(), 0)
        == "return-call-fallback"
    )


def test_credential_paths_trace_return_binds_argument_and_aliases(tmp_path):
    source = (
        "class Client:\n"
        "    def normalize(self, endpoint):\n"
        "        alias = endpoint\n"
        "        return alias\n"
        "    def send(self):\n"
        "        return self.normalize('https://service.example/token')\n"
    )
    index, snapshots = _paths_contract_index(tmp_path, {"client.py": source})
    path = tmp_path.resolve() / "client.py"
    tree = snapshots[path]
    callee = _named(tree, ast.FunctionDef, "normalize")
    caller = _named(tree, ast.FunctionDef, "send")
    row = callee.body[-1]
    expression = next(node for node in ast.walk(caller) if isinstance(node, ast.Call))
    flow = _flow(index, path, lambda value, *_args: [("observed_value", value)])
    traced = paths.trace_return(
        flow, row, expression, path, callee, caller, path, set(), 0
    )
    roles = [item[0] for item in traced]
    assert roles[:3] == [
        "unique_local_alias",
        "bound_method_parameter",
        "method_argument_binding",
    ]
    assert "observed_value" in roles

    missing_source = source.replace(
        "self.normalize('https://service.example/token')", "self.normalize()"
    )
    missing_index, missing_snapshots = _paths_contract_index(
        tmp_path / "missing", {"client.py": missing_source}
    )
    missing_path = (tmp_path / "missing").resolve() / "client.py"
    missing_tree = missing_snapshots[missing_path]
    missing_callee = _named(missing_tree, ast.FunctionDef, "normalize")
    missing_caller = _named(missing_tree, ast.FunctionDef, "send")
    missing_row = missing_callee.body[-1]
    missing_call = next(
        node for node in ast.walk(missing_caller) if isinstance(node, ast.Call)
    )
    missing_flow = _flow(
        missing_index, missing_path, lambda *_args: [("unexpected", None)]
    )
    assert (
        paths.trace_return(
            missing_flow,
            missing_row,
            missing_call,
            missing_path,
            missing_callee,
            missing_caller,
            missing_path,
            set(),
            0,
        )
        is None
    )


def test_credential_paths_call_argument_reports_direct_self_call(tmp_path):
    index, snapshots = _paths_contract_index(
        tmp_path,
        {
            "client.py": (
                "class Client:\n"
                "    def dispatch(self, endpoint):\n"
                "        return endpoint\n"
                "    def send(self):\n"
                "        return self.dispatch('https://service.example/token')\n"
            )
        },
    )
    path = tmp_path.resolve() / "client.py"
    tree = snapshots[path]
    owner = _named(tree, ast.ClassDef, "Client")
    callee = _named(owner, ast.FunctionDef, "dispatch")
    caller = _named(owner, ast.FunctionDef, "send")
    flow = _flow(index, path, lambda value, *_args: [("observed_value", value)])
    flow.methods = {"send": (path, caller, owner)}
    traced = paths.call_argument(flow, "endpoint", callee, set(), 0)
    roles = [item[0] for item in traced]
    assert roles[:2] == ["bound_method_parameter", "method_argument_binding"]
    assert "observed_value" in roles
    assert len(flow.branch_choices) == 1

    flow.methods = {}
    assert paths.call_argument(flow, "endpoint", callee, set(), 0) is None


def test_credential_paths_source_hop_rejects_stale_bytes(tmp_path):
    index, snapshots = _paths_contract_index(tmp_path, {"source.py": "value = 3\n"})
    path = tmp_path.resolve() / "source.py"
    node = snapshots[path].body[0]
    hop = paths.source_hop(index, path, node, "declared_value")
    assert hop["path"] == "source.py"
    assert hop["role"] == "declared_value"
    assert hop["source_sha256"] == hashlib.sha256(b"value = 3\n").hexdigest()
    assert paths.source_hop(index, path, None, "missing") is None

    stale, stale_snapshots = _paths_contract_index(
        tmp_path / "stale", {"source.py": "value = 4\n"}
    )
    stale_path = (tmp_path / "stale").resolve() / "source.py"
    stale.source_bytes[stale_path] = b"value = 5\n"
    stale.validated.pop(stale_path)
    assert (
        paths.source_hop(
            stale, stale_path, stale_snapshots[stale_path].body[0], "stale"
        )
        is None
    )


def test_credential_paths_default_session_evidence_fails_closed_on_unresolved_adapter(
    tmp_path,
):
    sources = {
        "demo/getter.py": (
            "from django.conf import settings\n"
            "from django.utils.module_loading import import_string\n"
            "def import_callable(path_or_callable):\n"
            "    if not callable(path_or_callable):\n"
            "        ret = import_string(path_or_callable)\n"
            "    else:\n"
            "        ret = path_or_callable\n"
            "    return ret\n"
            "def get_setting(name, dflt):\n"
            "    getter = getattr(settings, 'ALLAUTH_SETTING_GETTER', "
            "lambda name, dflt: getattr(settings, name, dflt))\n"
            "    getter = import_callable(getter)\n"
            "    return getter(name, dflt)\n"
        ),
        "demo/settings.py": (
            "from demo.getter import get_setting\n"
            "class AppSettings:\n"
            "    def __init__(self, prefix):\n"
            "        self.prefix = prefix\n"
            "    @property\n"
            "    def ADAPTER(self):\n"
            "        return self._setting('ADAPTER', 'demo.adapter.Adapter')\n"
            "    def _setting(self, name, dflt):\n"
            "        from demo.getter import get_setting\n"
            "        return get_setting(self.prefix + name, dflt)\n"
            "def __getattr__(name):\n"
            "    return getattr(_app_settings, name)\n"
            "_app_settings = AppSettings('demo.settings')\n"
        ),
        "demo/adapter.py": (
            "import requests\n"
            "from django.utils.module_loading import import_string\n"
            "from demo.settings import AppSettings\n"
            "def get_adapter(registry):\n"
            "    return import_string(AppSettings.ADAPTER)(registry)\n"
            "class Adapter:\n"
            "    def get_requests_session(self):\n"
            "        session = requests.Session()\n"
            "        return session\n"
        ),
    }
    index, snapshots = _paths_contract_index(tmp_path, sources)
    settings_path = next(
        path for path in snapshots if path.as_posix().endswith("demo/settings.py")
    )
    adapter_path = next(
        path for path in snapshots if path.as_posix().endswith("demo/adapter.py")
    )
    aliases = {
        path: audit._module_security_aliases(tree) for path, tree in snapshots.items()
    }
    classes = {
        (path, node.name): node
        for path, tree in snapshots.items()
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    imports = {path: {} for path in snapshots}
    imports[adapter_path]["AppSettings"] = (settings_path, "AppSettings")

    selected = paths._declared_default(index, snapshots)
    assert selected is not None
    boundary = paths.setting_boundary_nodes(
        index, snapshots, settings_path, selected[-1], aliases[settings_path]
    )
    assert boundary is not None
    selected_adapter = paths._selected_adapter(
        index, snapshots, imports, classes, aliases, audit, selected
    )
    assert selected_adapter is not None
    evidence = paths.default_session_evidence(
        index, snapshots, imports, classes, aliases, audit
    )
    assert evidence["provider"] == "requests.Session"
    assert evidence["profile"] == "DECLARED_DEFAULT_MAY_FLOW"
    assert evidence["get_adapter_canonical"] == "demo.adapter.get_adapter"
    assert evidence["runtime_setting_getter"] == "UNASSESSED"
    assert evidence["runtime_adapter_override"] == "UNASSESSED"
    assert {hop.get("role") for hop in evidence["hops"]}.issuperset(
        {
            "declared_default_adapter",
            "settings_module_getattr",
            "default_adapter_import",
        }
    )

    imports[adapter_path].clear()
    assert (
        paths.default_session_evidence(
            index, snapshots, imports, classes, aliases, audit
        )
        is None
    )


def test_credential_paths_record_use_binds_matching_source_and_sink_hashes(tmp_path):
    raw = (
        "import requests\n"
        "class Client:\n"
        "    ENDPOINT = 'https://service.example/token'\n"
        "    def send(self):\n"
        "        return requests.get(self.ENDPOINT)\n"
    )
    index, snapshots = _paths_contract_index(tmp_path, {"client.py": raw})
    path = tmp_path.resolve() / "client.py"
    tree = snapshots[path]
    owner = _named(tree, ast.ClassDef, "Client")
    assignment = owner.body[0]
    fact = declaration_fact(index, path, assignment)
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    expression = call.args[0]
    classes = {(path, owner.name): owner}
    imports = {path: {}}
    aliases = {path: audit._module_security_aliases(tree)}

    records = paths.record_use(
        fact,
        path,
        call,
        "endpoint_locator",
        expression,
        index,
        imports,
        classes,
        audit,
        integrity,
        aliases,
    )
    assert len(records) == 1
    record = records[0]
    assert record["path"] == "client.py"
    assert record["slot"] == "endpoint_locator"
    assert record["source_sha256"] == fact.source_sha256
    assert record["sink_sha256"] == hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert record["source_span"] == [3, 4, 3, 46]
    assert record["method_value_flow"] is False

    unrelated = ast.parse("requests.get('https://other.example/')").body[0].value
    unrelated_call = unrelated
    assert (
        paths.record_use(
            fact,
            path,
            unrelated_call,
            "password",
            unrelated_call.args[0],
            index,
            imports,
            classes,
            audit,
            integrity,
            aliases,
        )
        is None
    )
