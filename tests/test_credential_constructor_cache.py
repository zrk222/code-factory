"""Constructor-provider reuse stays inside a freshness-checked analysis batch."""

import pytest
from test_credential_role_decorator_boundaries import setup
from factoryline import credential_role_constructor_provider as provider
from factoryline import credential_role_constructor_provider as type_effects
from factoryline import finite_capture
from factoryline.credential_role_constructor_provider import class_chain
from factoryline.credential_role_constructor_provider import constructor_bindings_inert
from factoryline import credential_endpoint_admission as httpx
from factoryline import credential_endpoint_admission as assertions
from factoryline import credential_role_constructor_provider as roles
from factoryline import credential_endpoint_admission as routers
from factoryline import review_audits as audit
import ast
from types import SimpleNamespace
from factoryline import credential_role_paths as selection
import hashlib
from factoryline.credential_role_constructor_provider import auth_constructor_password
from factoryline.credential_role_paths import session_request_context
from factoryline.credential_role_constructor_provider import (
    SourceSnapshotIndex,
    source_session_factories,
)
from factoryline.credential_role_constructor_provider import ClassChainMemo
from factoryline.credential_role_constructor_provider import constructor_url_hops
from factoryline.credential_role_constructor_provider import declaration_fact
from factoryline.review_integrity import bind_source_call

SOURCE = "class Client: pass\nclass Adapter:\n    client_class = Client\n"


@pytest.mark.parametrize(
    "source",
    [
        "client = object()",
        "del client",
        "def client(): pass",
        "class client: pass",
        "client: object",
        "for client in items: pass",
    ],
)
def test_terminal_namespace_rejects_non_import_binding_shapes(source):
    statement = ast.parse(source).body[0]
    bindings = [
        node
        for node in ast.walk(statement)
        if isinstance(node, ast.Name) and node.id == "client"
    ] or [statement]
    for binding in bindings:
        assert (
            provider._terminal_namespace_import_prefix(
                [binding], "client", "library.client.Base"
            )
            is None
        )


@pytest.mark.parametrize(
    "helper_name", ["_walk", "_index_source_nodes", "_references", "_provider_uses"]
)
@pytest.mark.parametrize("mutation", ["binding", "code"])
def test_shared_consumer_index_changes_invalidate_native_context(
    tmp_path, monkeypatch, helper_name, mutation
):
    from factoryline.runtime_audit_integrity import _LiteralConsumers

    original = getattr(_LiteralConsumers, helper_name)
    before = audit._oracle_context_cache_key(tmp_path, [], {})

    def changed(*args, **kwargs):
        return None

    with monkeypatch.context() as patch:
        if mutation == "binding":
            patch.setattr(_LiteralConsumers, helper_name, changed)
        else:
            patch.setattr(original, "__code__", changed.__code__)
        assert audit._oracle_context_cache_key(tmp_path, [], {}) != before
    assert audit._oracle_context_cache_key(tmp_path, [], {}) == before


def test_provider_helper_code_change_revokes_batch(tmp_path, monkeypatch):
    _, index, imports, chain, _ = _context(tmp_path, monkeypatch)

    def changed(*args):
        return False

    with index.class_chain_memo.analysis_batch() as batch:
        assert constructor_bindings_inert(chain, index, imports)
        monkeypatch.setattr(
            provider._captured_mutations_inert, "__code__", changed.__code__
        )
        assert not constructor_bindings_inert(chain, index, imports)
    assert not batch.accepted


def _context(tmp_path, monkeypatch):
    path, index, imports, classes, audit = setup(tmp_path, SOURCE)
    chain = class_chain(index, path, "Client", imports, classes, audit)
    calls = []
    original = provider.constructor_provider_bindings_inert

    def observed(*args):
        calls.append(args)
        return original(*args)

    monkeypatch.setattr(provider, "constructor_provider_bindings_inert", observed)
    return path, index, imports, chain, calls


def test_same_constructor_reuses_one_guard_in_validated_batch(tmp_path, monkeypatch):
    _, index, imports, chain, calls = _context(tmp_path, monkeypatch)
    with index.class_chain_memo.analysis_batch() as batch:
        assert constructor_bindings_inert(chain, index, imports)
        assert constructor_bindings_inert(chain, index, imports)
        assert len(calls) == 1
    assert batch.accepted


def test_outside_batch_recomputes_provider_guard(tmp_path, monkeypatch):
    _, index, imports, chain, calls = _context(tmp_path, monkeypatch)
    assert constructor_bindings_inert(chain, index, imports)
    assert constructor_bindings_inert(chain, index, imports)
    assert len(calls) == 2


def test_different_import_mapping_gets_no_cached_guard(tmp_path, monkeypatch):
    _, index, imports, chain, calls = _context(tmp_path, monkeypatch)
    with index.class_chain_memo.analysis_batch() as batch:
        assert constructor_bindings_inert(chain, index, imports)
        assert constructor_bindings_inert(chain, index, dict(imports))
        assert len(calls) == 2
    assert batch.accepted


def test_changed_provider_helper_revokes_batch_acceptance(tmp_path, monkeypatch):
    _, index, imports, chain, _ = _context(tmp_path, monkeypatch)
    with index.class_chain_memo.analysis_batch() as batch:
        assert constructor_bindings_inert(chain, index, imports)
        monkeypatch.setattr(provider, "_captured_mutations_inert", lambda *args: False)
        assert not constructor_bindings_inert(chain, index, imports)
    assert not batch.accepted


def test_changed_source_after_cache_hit_revokes_batch_acceptance(tmp_path, monkeypatch):
    path, index, imports, chain, calls = _context(tmp_path, monkeypatch)
    with index.class_chain_memo.analysis_batch() as batch:
        assert constructor_bindings_inert(chain, index, imports)
        index.source_bytes[path] += b"\n# changed capture\n"
        assert constructor_bindings_inert(chain, index, imports)
        assert len(calls) == 1
    assert not batch.accepted


@pytest.mark.parametrize("mutation", ["binding", "code"])
def test_transitive_mutation_helper_change_revokes_batch(
    tmp_path, monkeypatch, mutation
):
    _, index, imports, chain, _ = _context(tmp_path, monkeypatch)

    def changed(call, aliases, audit, bindings, facts):
        facts.update((value, "*") for value in aliases.values())

    with index.class_chain_memo.analysis_batch() as batch:
        assert constructor_bindings_inert(chain, index, imports)
        if mutation == "binding":
            monkeypatch.setattr(finite_capture, "_reflective_provider_write", changed)
        else:
            monkeypatch.setattr(
                finite_capture._reflective_provider_write,
                "__code__",
                changed.__code__,
            )
        constructor_bindings_inert(chain, index, imports)
    assert not batch.accepted


@pytest.mark.parametrize("mutation", ["binding", "code"])
def test_type_effect_helper_change_revokes_batch(tmp_path, monkeypatch, mutation):
    _, index, imports, chain, calls = _context(tmp_path, monkeypatch)

    def changed(*args):
        return False

    with index.class_chain_memo.analysis_batch() as batch:
        assert constructor_bindings_inert(chain, index, imports)
        assert constructor_bindings_inert(chain, index, imports)
        assert len(calls) == 1
        if mutation == "binding":
            monkeypatch.setattr(type_effects, "_ordinary_class", changed)
        else:
            monkeypatch.setattr(
                type_effects._ordinary_class, "__code__", changed.__code__
            )
        constructor_bindings_inert(chain, index, imports)
        assert len(calls) == 2
    assert not batch.accepted


# --- Merged from test_credential_cache_identity.py; test definitions and fixtures retained ---
"""Every external native credential validator participates in cache identity."""


@pytest.mark.parametrize(
    "module,name",
    [
        (httpx, "request_client_origin"),
        (assertions, "public_json_assertion"),
        (roles, "binding_dominates"),
        (routers, "router_factory_call_published"),
    ],
)
def test_validator_replacement_invalidates_native_context(
    tmp_path, monkeypatch, module, name
):
    before = audit._oracle_context_cache_key(tmp_path, [], {})
    original = getattr(module, name)

    def replacement(*args, **kwargs):
        return original(*args, **kwargs)

    monkeypatch.setattr(module, name, replacement)
    after = audit._oracle_context_cache_key(tmp_path, [], {})
    assert before != after


@pytest.mark.parametrize(
    "helper_name",
    [
        "request_client_origin",
        "public_json_assertion",
        "_json_assertion_operands",
        "_json_detail_name",
        "_json_cast_response",
        "_json_response_name",
        "_json_response_request",
        "router_factory_call_published",
        "endpoint_binding",
        "endpoint_publication",
        "reviewed_excerpt_fact",
        "openapi_endpoint_declarations",
        "session_factory_witness",
    ],
)
def test_moved_validator_code_mutation_invalidates_native_context(
    tmp_path, monkeypatch, helper_name
):
    helper = getattr(httpx, helper_name)
    before = audit._oracle_context_cache_key(tmp_path, [], {})

    def changed(*args, **kwargs):
        return False

    monkeypatch.setattr(helper, "__code__", changed.__code__)
    after = audit._oracle_context_cache_key(tmp_path, [], {})
    assert before != after


@pytest.mark.parametrize(
    "helper_name",
    [
        "request_client_origin",
        "public_json_assertion",
        "_json_assertion_operands",
        "_json_detail_name",
        "_json_cast_response",
        "_json_response_name",
        "_json_response_request",
        "router_factory_call_published",
        "endpoint_binding",
        "endpoint_publication",
        "reviewed_excerpt_fact",
        "openapi_endpoint_declarations",
        "session_factory_witness",
    ],
)
def test_moved_helper_binding_replacement_invalidates_native_context(
    tmp_path, monkeypatch, helper_name
):
    before = audit._oracle_context_cache_key(tmp_path, [], {})

    def replacement(*args, **kwargs):
        return None

    monkeypatch.setattr(httpx, helper_name, replacement)
    after = audit._oracle_context_cache_key(tmp_path, [], {})
    assert before != after


# --- Merged from test_credential_role_adapter_selection.py; test definitions and fixtures retained ---
"""Unrelated configuration defaults must not hide a declared HTTP adapter."""


def _source(default):
    return ast.parse(
        "class Settings:\n"
        "    @property\n"
        "    def ADAPTER(self):\n"
        f"        return self._setting('ADAPTER', '{default}')\n"
    )


def _snapshots(tmp_path, second_http=False):
    snapshots = {
        tmp_path / "account_settings.py": _source("account.AccountAdapter"),
        tmp_path / "social_settings.py": _source("social.SocialAdapter"),
        tmp_path / "account.py": ast.parse(
            "class AccountAdapter:\n    def login(self):\n        pass\n"
        ),
        tmp_path / "social.py": ast.parse(
            "class SocialAdapter:\n    def get_requests_session(self):\n        pass\n"
        ),
    }
    if second_http:
        snapshots[tmp_path / "account.py"] = ast.parse(
            "class AccountAdapter:\n    def get_requests_session(self):\n        pass\n"
        )
    index = SimpleNamespace(
        root=tmp_path,
        snapshots=snapshots,
        relative=lambda path: path.relative_to(tmp_path).as_posix(),
    )
    return index, snapshots


def test_unrelated_adapter_defaults_do_not_block_http_candidate(tmp_path, monkeypatch):
    index, snapshots = _snapshots(tmp_path)
    monkeypatch.setattr(
        selection, "_setting_getter_shape", lambda _: (tmp_path / "utils.py", object())
    )
    selected = selection._declared_default(index, snapshots)
    assert selected is not None
    assert selected[0] == tmp_path / "social_settings.py"
    assert selected[7] == tmp_path / "social.py"


def test_two_http_adapter_defaults_remain_ambiguous(tmp_path, monkeypatch):
    index, snapshots = _snapshots(tmp_path, second_http=True)
    monkeypatch.setattr(
        selection, "_setting_getter_shape", lambda _: (tmp_path / "utils.py", object())
    )
    assert selection._declared_default(index, snapshots) is None


# --- Merged from test_credential_role_api_boundaries.py; test definitions and fixtures retained ---
"""Exercise native resolver contracts and lazy source validation."""


def test_auth_constructor_uses_canonical_call_contract(tmp_path):
    path = tmp_path / "client.py"
    call = ast.parse("requests.auth.HTTPBasicAuth('user', secret)").body[0].value
    aliases = {path: {"requests": "requests"}}
    assert auth_constructor_password(call, path, aliases) is call.args[1]


def test_source_factory_uses_canonical_call_contract():
    tree = ast.parse(
        "def factory():\n    session = requests.Session()\n    return session\n"
    )
    assert source_session_factories(tree, {"requests": "requests"}) == {"factory"}


def test_session_context_validates_lazy_source_before_parent_lookup(tmp_path):
    path = tmp_path / "client.py"
    raw = (
        b"def send():\n"
        b"    with get_adapter().get_requests_session() as session:\n"
        b"        session.request('GET', endpoint)\n"
    )
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    call = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "request"
    )
    assert not index.parents
    aliases = {"get_adapter": "provider.get_adapter"}
    assert session_request_context(call, index, path, aliases) == "provider.get_adapter"
    assert path in index.parents


def test_session_context_rejects_stale_source(tmp_path):
    path = tmp_path / "client.py"
    raw = b"session.request('GET', endpoint)"
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = "0" * 64
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: "0" * 64})
    assert session_request_context(tree.body[0].value, index, path, {}) is False


@pytest.mark.parametrize(
    "prefix",
    [
        "session = supplied",
        "session.request = supplied",
        "del session.request",
        "mutate(session)",
        "setattr(session, 'request', supplied)",
    ],
)
def test_session_receiver_mutation_is_unresolved(tmp_path, prefix):
    path = tmp_path / "client.py"
    raw = (
        "def send():\n"
        "    with get_adapter().get_requests_session() as session:\n"
        f"        {prefix}\n"
        "        session.request('GET', endpoint)\n"
    ).encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    call = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "request"
    )
    assert session_request_context(call, index, path, {}) is False


@pytest.mark.parametrize("arguments", ["supplied", "**options", "auth=secret"])
def test_session_factory_arguments_are_unresolved(tmp_path, arguments):
    path = tmp_path / "client.py"
    raw = (
        "def send():\n"
        f"    with get_adapter().get_requests_session({arguments}) as session:\n"
        "        session.request('GET', endpoint)\n"
    ).encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    call = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "request"
    )
    assert session_request_context(call, index, path, {}) is False


@pytest.mark.parametrize(
    "body, expected_slots, expected_checks",
    [
        ("consume(1)\nconsume(2)\nconsume(3)", [], 0),
        ("requests.get(endpoint)", ["endpoint_locator"], 1),
        ("requests.auth.HTTPBasicAuth('user', secret)", ["password"], 1),
        ("consume(requests)\nrequests.get(endpoint)", [], 1),
        ("requests.get = replacement\nrequests.get(endpoint)", [], 1),
    ],
)
def test_sink_planning_checks_provider_only_for_candidate_slots(
    tmp_path, monkeypatch, body, expected_slots, expected_checks
):
    from factoryline import credential_role_paths as paths
    from factoryline import review_audits as audit
    from factoryline.review_integrity import bind_security_call_scopes

    path = tmp_path / "client.py"
    raw = ("import requests\n" + body + "\n").encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    bind_security_call_scopes(tree)
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    aliases = {path: audit._module_security_aliases(tree)}
    original = paths._provider_identity_uncertain
    checks = []

    def observed(*args, **kwargs):
        checks.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(paths, "_provider_identity_uncertain", observed)
    rows = paths._sink_rows({path: tree}, aliases, index, None)
    assert [row[3] for row in rows] == expected_slots
    assert len(checks) == expected_checks


@pytest.mark.parametrize(
    "mutation", ["", "requests.get = supplied", "consume(requests)"]
)
def test_provider_profiles_share_one_module_index_without_changing_vetoes(
    tmp_path, monkeypatch, mutation
):
    from factoryline import credential_role_paths as paths
    from factoryline import review_audits as audit
    from factoryline.review_integrity import bind_security_call_scopes

    path = tmp_path / "client.py"
    raw = (
        "import requests\n" + mutation + "\n"
        "def first():\n    import requests as primary\n    primary.get(endpoint)\n"
        "def second():\n    import requests as secondary\n    secondary.post(endpoint)\n"
    ).encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    bind_security_call_scopes(tree)
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    aliases = {path: audit._module_security_aliases(tree)}
    original = paths._provider_identity_uncertain
    supplied = []

    def observed(tree, lexical, **kwargs):
        supplied.append((kwargs["nodes"], kwargs["parents"]))
        reused = original(tree, lexical, **kwargs)
        assert reused == original(tree, lexical)
        return reused

    monkeypatch.setattr(paths, "_provider_identity_uncertain", observed)
    paths._sink_rows({path: tree}, aliases, index, None)
    assert len(supplied) >= 2
    assert len({id(nodes) for nodes, _ in supplied}) == 1
    assert len({id(parents) for _, parents in supplied}) == 1
    nodes, parents = supplied[0]
    assert parents == {
        id(child): node for node in nodes for child in ast.iter_child_nodes(node)
    }


# --- Merged from test_credential_role_batch_validation.py; test definitions and fixtures retained ---
"""A producer batch must discard every derived role after source mutation."""


def _memo(tmp_path):
    path = tmp_path / "client.py"
    raw = b"class Client: pass\n"
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = hashlib.sha256(raw).hexdigest()
    index = SourceSnapshotIndex(
        tmp_path, {path: tree}, {path: raw}, {path: tree._oracle_source_sha256}
    )
    assert index.validate(path)
    imports, classes = {path: {}}, {(path, "Client"): tree.body[0]}
    audit = SimpleNamespace(_name=ast.unparse)
    return path, ClassChainMemo(index, imports, classes, audit)


def test_source_models_reuse_only_inside_validated_batch(tmp_path):
    _, memo = _memo(tmp_path)
    calls = []

    def derive():
        calls.append(True)
        return len(calls)

    assert memo.source_model(("fixture", derive), derive) == 1
    assert memo.source_model(("fixture", derive), derive) == 2
    with memo.analysis_batch() as batch:
        assert batch.started
        assert memo.source_model(("fixture", derive), derive) == 3
        assert memo.source_model(("fixture", derive), derive) == 3
    assert batch.accepted
    assert memo.source_model(("fixture", derive), derive) == 4


def test_source_model_cache_cannot_admit_late_mutation(tmp_path):
    path, memo = _memo(tmp_path)
    with memo.analysis_batch() as batch:
        assert batch.started
        assert memo.source_model("fixture", lambda: True)
        memo.index.snapshots[path].body[0].body.append(ast.Pass())
        assert memo.source_model("fixture", lambda: False)
    assert not batch.accepted


def test_receiver_identity_summary_reused_only_inside_batch(tmp_path, monkeypatch):
    from factoryline import credential_role_identity_effects as lifetime

    path, memo = _memo(tmp_path)
    memo.index.class_chain_memo = memo
    receiver = ast.Name("client", ast.Load())
    chain = [(path, "Client", memo.classes[(path, "Client")])]
    calls = []

    def derive(*args):
        calls.append(True)
        return False

    monkeypatch.setattr(lifetime, "_local_receiver_stable", derive)
    with memo.analysis_batch() as batch:
        for _ in range(20):
            assert not lifetime.local_receiver_stable(
                path, receiver, "endpoint", chain, memo.index
            )
    assert batch.accepted and len(calls) == 1
    assert not lifetime.local_receiver_stable(
        path, receiver, "endpoint", chain, memo.index
    )
    assert len(calls) == 2


def test_helper_epoch_replacement_rejects_batch_after_fresh_negative(
    tmp_path, monkeypatch
):
    from factoryline import credential_role_identity_effects as lifetime

    path, memo = _memo(tmp_path)
    memo.index.class_chain_memo = memo
    receiver = ast.Name("client", ast.Load())
    chain = [(path, "Client", memo.classes[(path, "Client")])]
    monkeypatch.setattr(
        lifetime,
        "_local_receiver_stable",
        lambda *args: lifetime._field_writes_safe(None, ()),
    )
    monkeypatch.setattr(lifetime, "_field_writes_safe", lambda *args: True)
    with memo.analysis_batch() as batch:
        assert lifetime.local_receiver_stable(
            path, receiver, "endpoint", chain, memo.index
        )
        monkeypatch.setattr(lifetime, "_field_writes_safe", lambda *args: False)
        assert not lifetime.local_receiver_stable(
            path, receiver, "endpoint", chain, memo.index
        )
    assert not batch.accepted


@pytest.mark.parametrize("mutation", ["bytes", "ast", "inventory", "imports", "helper"])
def test_batch_exit_freshly_rejects_mutation(tmp_path, mutation):
    path, memo = _memo(tmp_path)
    with memo.analysis_batch() as batch:
        assert batch.started and not batch.accepted
        assert memo.defers_validation(
            memo.index, memo.imports, memo.classes, memo.audit
        )
        if mutation == "bytes":
            memo.index.source_bytes[path] += b"# changed\n"
        elif mutation == "ast":
            memo.index.snapshots[path].body.append(ast.Pass())
        elif mutation == "inventory":
            memo.index.inventory[path] = "0" * 64
        elif mutation == "imports":
            memo.imports[path]["Alias"] = (path, "Other")
        else:
            memo.audit._name = lambda node: "Other"
    assert not batch.accepted
    assert not memo.defers_validation(
        memo.index, memo.imports, memo.classes, memo.audit
    )


def test_batch_runs_two_fresh_checks_and_does_not_escape(tmp_path, monkeypatch):
    _, memo = _memo(tmp_path)
    calls, original = [], memo.valid

    def observed():
        calls.append(True)
        return original()

    monkeypatch.setattr(memo, "valid", observed)
    with memo.analysis_batch() as batch:
        for _ in range(20):
            assert memo.defers_validation(
                memo.index, memo.imports, memo.classes, memo.audit
            )
        with pytest.raises(ValueError, match="nested"):
            with memo.analysis_batch():
                pass
    assert batch.accepted and len(calls) == 2
    assert not memo.defers_validation(
        memo.index, memo.imports, memo.classes, memo.audit
    )


def test_relative_path_cache_is_inventory_bounded_and_tracks_root(tmp_path):
    path, memo = _memo(tmp_path)
    index = memo.index
    for _ in range(20):
        assert index.relative(path) == "client.py"
        assert index.relative(tmp_path / "uncaptured.py") == "uncaptured.py"
    assert len(index._relative_paths) == 1
    index.root = tmp_path / "different"
    assert index.relative(path) is None
    assert index._relative_paths == {}
    index.root = tmp_path
    assert index.relative(path) == "client.py"


def test_failed_batch_never_reports_acceptance(tmp_path):
    _, memo = _memo(tmp_path)
    with pytest.raises(RuntimeError, match="failed"):
        with memo.analysis_batch() as state:
            raise RuntimeError("failed")
    assert not state.accepted and memo._analysis_batch is None


def test_candidate_independent_consumer_check_is_reused(tmp_path):
    path, memo = _memo(tmp_path)
    memo.audit._module_security_aliases = lambda tree: {}
    node, calls = memo.index.snapshots[path].body[0], []

    def derive(*args):
        calls.append(args)
        return None

    for _ in range(20):
        assert memo.getter_role(node, path, memo.audit, derive) is False
    assert len(calls) == 1
    memo.audit._module_security_aliases = lambda tree: {}
    assert memo.getter_role(node, path, memo.audit, derive) is False
    assert len(calls) == 2
    memo.index.snapshots[path].body.append(ast.Pass())
    assert memo.valid() is False


def test_actual_scanner_discards_mutated_batch(tmp_path, monkeypatch):
    from factoryline import credential_endpoint_admission as admission
    from factoryline import credential_role_paths as paths
    from factoryline.review_audits import security_scan

    (tmp_path / "client.py").write_text(
        "import requests\nclass Client:\n"
        "    ACCESS_TOKEN_URL = 'https://appleid.apple.com/auth/token'\n"
        "    def send(self):\n        return requests.get(self.ACCESS_TOKEN_URL)\n"
    )
    baseline = security_scan(tmp_path, cache_enabled=False)
    assert any(
        f["code"] == "SECURITY_HARDCODED_SECRET"
        for f in baseline["primitive_observations"]
    )
    original = paths._analyze_fact

    def mutate(fact, evidence, sinks, context, publications, aliases):
        original(fact, evidence, sinks, context, publications, aliases)
        index = context[0]
        index.snapshots[index.root / fact.path].body.append(ast.Pass())

    monkeypatch.setattr(paths, "_analyze_fact", mutate)
    admission._WORKSPACES.clear()
    result = security_scan(tmp_path, cache_enabled=False)
    assert any(
        f["code"] == "SECURITY_HARDCODED_SECRET" and f["severity"] == "CRITICAL"
        for f in result["findings"]
    )


@pytest.mark.parametrize("mutation", ["helper_code", "helper_binding", "provider_code"])
def test_python_helper_code_epoch_recomputes_and_rejects_batch(tmp_path, mutation):
    _, memo = _memo(tmp_path)

    def helper():
        return True

    def replacement():
        return False

    selected = [helper]

    def epoch():
        return (selected[0],)

    def changed_epoch():
        return tuple(selected)

    with memo.analysis_batch() as batch:
        assert memo.source_model("code", lambda: selected[0](), helper_epoch=epoch)
        if mutation == "helper_code":
            helper.__code__ = replacement.__code__
        elif mutation == "helper_binding":
            selected[0] = replacement
        else:
            epoch.__code__ = changed_epoch.__code__
        assert not memo.source_model("code", lambda: False, helper_epoch=epoch)
    assert not batch.accepted


@pytest.mark.parametrize("mutation", ["self", "function", "code"])
def test_bound_helper_code_epoch_is_identity_exact(tmp_path, mutation):
    _, memo = _memo(tmp_path)

    class Helper:
        def check(self):
            return True

        def negative(self):
            return False

    first, second = Helper(), Helper()
    selected, calls = [first], []

    def epoch():
        return (selected[0].check,)

    def derive():
        calls.append(True)
        return len(calls)

    with memo.analysis_batch() as batch:
        assert memo.source_model("bound-code", derive, helper_epoch=epoch) == 1
        assert memo.source_model("bound-code", derive, helper_epoch=epoch) == 1
        if mutation == "self":
            selected[0] = second
        elif mutation == "function":
            Helper.check = Helper.negative
        else:
            Helper.check.__code__ = Helper.negative.__code__
        assert memo.source_model("bound-code", derive, helper_epoch=epoch) == 2
    assert not batch.accepted


def test_fresh_local_epoch_wrappers_reuse_code_and_explicit_dependencies(tmp_path):
    _, memo = _memo(tmp_path)
    dependency, calls = object(), []

    def epoch_factory(value):
        def epoch():
            return (value,)

        return epoch

    def derive():
        calls.append(True)
        return len(calls)

    with memo.analysis_batch() as batch:
        for _ in range(20):
            assert (
                memo.source_model(
                    "local-wrapper", derive, helper_epoch=epoch_factory(dependency)
                )
                == 1
            )
    assert batch.accepted and len(calls) == 1


def test_local_epoch_wrapper_changed_dependency_rejects_batch(tmp_path):
    _, memo = _memo(tmp_path)

    def epoch_factory(value):
        def epoch():
            return (value,)

        return epoch

    with memo.analysis_batch() as batch:
        assert memo.source_model(
            "local-change", lambda: True, helper_epoch=epoch_factory(object())
        )
        assert not memo.source_model(
            "local-change", lambda: False, helper_epoch=epoch_factory(object())
        )
    assert not batch.accepted


@pytest.mark.parametrize("mutation", ["bound_self", "globals"])
def test_provider_implementation_namespace_is_bound(tmp_path, mutation):
    from types import FunctionType

    _, memo = _memo(tmp_path)

    class Provider:
        def epoch(self):
            return ()

    first, second = Provider(), Provider()

    def epoch():
        return ()

    provider = first.epoch if mutation == "bound_self" else epoch
    with memo.analysis_batch() as batch:
        assert memo.source_model("provider", lambda: True, helper_epoch=provider)
        changed = (
            second.epoch
            if mutation == "bound_self"
            else FunctionType(epoch.__code__, {})
        )
        assert not memo.source_model("provider", lambda: False, helper_epoch=changed)
    assert not batch.accepted


def test_opaque_epoch_values_use_identity_without_equality(tmp_path):
    _, memo = _memo(tmp_path)

    class Opaque:
        def __eq__(self, other):
            raise AssertionError("epoch must not call opaque equality")

    opaque = Opaque()
    value = (opaque, "data")

    def epoch():
        return (opaque, value)

    with memo.analysis_batch() as batch:
        assert memo.source_model("opaque", lambda: True, helper_epoch=epoch)
        assert memo.source_model("opaque", lambda: False, helper_epoch=epoch)
    assert batch.accepted


@pytest.mark.parametrize("invalid", ["raises", "non_tuple"])
def test_invalid_provider_epoch_never_accepts_batch(tmp_path, invalid):
    _, memo = _memo(tmp_path)

    def epoch():
        if invalid == "raises":
            raise ValueError("bad epoch")
        return []

    with memo.analysis_batch() as batch:
        assert memo.source_model("invalid-code", lambda: True, helper_epoch=epoch)
    assert not batch.accepted


# --- Merged from test_credential_role_constructor_flow.py; test definitions and fixtures retained ---


class _Audit:
    @staticmethod
    def _name(node):
        return ast.unparse(node)

    @staticmethod
    def _bound_names(node):
        return audit._bound_names(node)


def _snapshot(tmp_path, sources):
    snapshots, source_bytes, inventory, paths = {}, {}, {}, {}
    for name, source in sources.items():
        path = tmp_path / name
        raw = source.encode()
        tree = ast.parse(raw)
        digest = hashlib.sha256(raw).hexdigest()
        tree._oracle_source_sha256 = digest
        snapshots[path] = tree
        source_bytes[path] = raw
        inventory[path] = digest
        paths[name] = path
    return SourceSnapshotIndex(tmp_path, snapshots, source_bytes, inventory), paths


def _case(tmp_path, client_call, constructor):
    index, paths = _snapshot(
        tmp_path,
        {
            "adapter.py": """
from client import Client
class BaseAdapter:
    client_class = Client
    def get_client(self):
        return self.client_class(self.access_token_url)
class AppleAdapter(BaseAdapter):
    access_token_url = 'https://apple.example/token'
""",
            "client.py": f"""
class Client:
    def __init__(self, endpoint):
        {constructor}
    def send(self):
        url = self.endpoint
        with get_adapter().get_requests_session() as sess:
            {client_call}
""",
        },
    )
    adapter, client = paths["adapter.py"], paths["client.py"]
    classes = {
        (path, node.name): node
        for path, tree in index.snapshots.items()
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    imports = {adapter: {"Client": (client, "Client")}, client: {}}
    fact_node = next(
        node
        for node in ast.walk(index.snapshots[adapter])
        if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "access_token_url"
    )
    fact = declaration_fact(index, adapter, fact_node)
    call = next(
        node
        for node in ast.walk(index.snapshots[client])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "request"
    )
    expression = call.args[1]
    hops = constructor_url_hops(
        fact,
        client,
        call,
        expression,
        index,
        imports,
        classes,
        _Audit(),
        SimpleNamespace(bind_source_call=bind_source_call),
    )
    return hops


def test_inherited_provider_literal_flows_through_constructor_and_client_field(
    tmp_path,
):
    hops = _case(
        tmp_path,
        'sess.request("POST", url)',
        "self.endpoint = endpoint",
    )
    assert [hop["role"] for hop in hops] == [
        "declared_literal",
        "client_class_selection",
        "constructor_argument",
        "constructor_parameter",
        "constructor_field_binding",
        "canonical_http_url_consumer",
    ]
    assert all(len(hop["source_sha256"]) == 64 for hop in hops)
    assert all("https://" not in str(hop) for hop in hops)


def test_unsupported_constructor_assignment_does_not_create_flow(tmp_path):
    assert (
        _case(
            tmp_path,
            'sess.request("POST", url)',
            "self.endpoint = transform(endpoint)",
        )
        is None
    )


def test_duplicate_constructor_field_write_is_unresolved(tmp_path):
    assert (
        _case(
            tmp_path,
            'sess.request("POST", url)',
            "self.endpoint = endpoint\n        self.endpoint = other",
        )
        is None
    )


@pytest.mark.parametrize(
    "constructor",
    [
        "endpoint = replacement\n        self.endpoint = endpoint",
        "if condition:\n            self.endpoint = endpoint",
        "self.endpoint = endpoint\n        self.endpoint: str = replacement",
        "self.endpoint = endpoint\n        del self.endpoint",
    ],
)
def test_mutated_or_conditional_constructor_transfer_is_unresolved(
    tmp_path, constructor
):
    assert _case(tmp_path, 'sess.request("POST", url)', constructor) is None


@pytest.mark.parametrize(
    "capture",
    [None, "value = 1\n", 17, bytearray(b"value = 1\n")],
    ids=["missing", "text", "integer", "mutable_bytes"],
)
@pytest.mark.parametrize("mixed", [False, True])
def test_nonbyte_source_capture_rejects_the_whole_snapshot(tmp_path, capture, mixed):
    raw = b"value = 1\n"
    digest = hashlib.sha256(raw).hexdigest()
    path = tmp_path / "missing.py"
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = digest
    snapshots, captured, inventory = {path: tree}, {path: capture}, {path: digest}
    if mixed:
        valid = tmp_path / "valid.py"
        snapshots[valid], captured[valid], inventory[valid] = tree, raw, digest
    index = SourceSnapshotIndex(tmp_path, snapshots, captured, inventory)
    assert index.bounded is False
    assert all(index.validate(member) is False for member in snapshots)
    assert index.parents == {}


def test_immutable_source_capture_keeps_hash_bound_snapshot_valid(tmp_path):
    path, raw = tmp_path / "valid.py", b"value = 1\n"
    digest = hashlib.sha256(raw).hexdigest()
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    assert index.bounded is True
    assert index.validate(path) is True


@pytest.mark.parametrize("mutation", ["binding", "code", "ast_helper"])
def test_constructor_epoch_tracks_extracted_snapshot_validation(monkeypatch, mutation):
    from factoryline import credential_role_constructor_provider as provider

    before = provider._constructor_provider_epoch()
    method = provider.SourceSnapshotIndex._matches_snapshot
    if mutation == "binding":
        monkeypatch.setattr(
            provider.SourceSnapshotIndex, "_matches_snapshot", lambda *args: False
        )
    elif mutation == "code":
        monkeypatch.setattr(
            method, "__code__", (lambda self, path, tree, raw, digest: False).__code__
        )
    else:
        monkeypatch.setattr(provider, "_ast_matches_source", lambda raw, tree: False)
    assert provider._constructor_provider_epoch() != before
    monkeypatch.undo()
    assert provider._constructor_provider_epoch() == before


@pytest.mark.parametrize(
    "source,aliases,expected",
    [
        (
            "import requests as rq\ndef build():\n s = rq.Session()\n return s\n",
            {"rq": "requests"},
            {"build"},
        ),
        (
            "import requests as rq\ndef build():\n s = rq.Session()\n return other\n",
            {"rq": "requests"},
            set(),
        ),
        (
            "import requests as rq\ndef build():\n s = rq.Session()\n return s\n",
            {"rq": "unmodeled"},
            set(),
        ),
    ],
)
def test_source_session_factory_returns_only_the_created_canonical_session(
    source, aliases, expected
):
    assert source_session_factories(ast.parse(source), aliases) == expected


@pytest.mark.parametrize(
    "expression,aliases,expected",
    [
        (
            "requests.auth.HTTPBasicAuth('user', secret)",
            {"requests": "requests"},
            "secret",
        ),
        (
            "httpx.BasicAuth(username='user', password=secret)",
            {"httpx": "httpx"},
            "secret",
        ),
        (
            "requests.auth.HTTPBasicAuth('user', secret, mode)",
            {"requests": "requests"},
            None,
        ),
        (
            "foreign.HTTPBasicAuth('user', secret)",
            {"requests": "requests"},
            None,
        ),
    ],
)
def test_auth_constructor_password_slot_is_exact(expression, aliases, expected):
    from pathlib import Path

    path = Path("auth.py")
    call = ast.parse(expression).body[0].value
    result = auth_constructor_password(call, path, {path: aliases})
    assert (ast.unparse(result) if result is not None else None) == expected


@pytest.mark.parametrize(
    "sources,imports,expected",
    [
        (
            {
                "base.py": "class Root: pass\nclass Middle(Root): pass\n",
                "leaf.py": "from base import Middle\nclass Leaf(Middle): pass\n",
            },
            "imported",
            [("leaf.py", "Leaf"), ("base.py", "Middle"), ("base.py", "Root")],
        ),
        (
            {"leaf.py": "class Leaf(MissingBase): pass\n"},
            "unresolved",
            None,
        ),
    ],
)
def test_class_chain_resolves_captured_c3_and_rejects_unknown_base(
    tmp_path, sources, imports, expected
):
    index, paths = _snapshot(tmp_path, sources)
    classes = {
        (path, node.name): node
        for path, tree in index.snapshots.items()
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    import_map = {path: {} for path in index.snapshots}
    if imports == "imported":
        import_map[paths["leaf.py"]]["Middle"] = (paths["base.py"], "Middle")
    chain = class_chain(index, paths["leaf.py"], "Leaf", import_map, classes, _Audit())
    if expected is None:
        assert chain is None
        return
    assert [
        (path.relative_to(tmp_path).as_posix(), name) for path, name, _ in chain
    ] == expected


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "class Client:\n def send(self):\n  return self.request(url)\n",
            True,
        ),
        (
            "class Client:\n @staticmethod\n def send(self):\n  return self.request(url)\n",
            False,
        ),
        (
            "class Client:\n def send(this):\n  return this.request(url)\n",
            False,
        ),
    ],
)
def test_instance_receiver_contract_requires_direct_instance_method(
    tmp_path, source, expected
):
    path = tmp_path / "receiver.py"
    raw = source.encode()
    digest = hashlib.sha256(raw).hexdigest()
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    assert index.validate(path)
    owner = tree.body[0]
    function = (
        owner.body[-1]
        if source.startswith("class Client:\n @staticmethod")
        else owner.body[0]
    )
    call = next(node for node in ast.walk(function) if isinstance(node, ast.Call))
    from factoryline.credential_role_constructor_provider import instance_receiver

    assert instance_receiver(call, function, owner, index, path) is expected


@pytest.mark.parametrize(
    "source,name,expected_lines",
    [
        ("endpoint = first\nendpoint = second\n", "endpoint", [1, 2]),
        ("def nested():\n    endpoint = hidden\n", "endpoint", []),
        ("if ready:\n    endpoint = value\n", "endpoint", [2]),
    ],
)
def test_binding_occurrences_contract_respects_real_scope_and_statement_rows(
    source, name, expected_lines
):
    from factoryline.credential_role_constructor_provider import binding_occurrences

    tree = ast.parse(source)
    rows = binding_occurrences(tree.body, name)
    assert sorted(row.lineno for row in rows) == expected_lines


@pytest.mark.parametrize(
    "constructor,client_call,expected_roles",
    [
        (
            "self.endpoint = endpoint",
            'sess.request("POST", url)',
            [
                "declared_literal",
                "client_class_selection",
                "constructor_argument",
                "constructor_parameter",
                "constructor_field_binding",
                "canonical_http_url_consumer",
            ],
        ),
        ("self.endpoint = transform(endpoint)", 'sess.request("POST", url)', None),
        ("self.endpoint = endpoint", 'sess.request("POST", other_url)', None),
    ],
)
def test_constructor_url_hops_contract_preserves_only_exact_transfer(
    tmp_path, constructor, client_call, expected_roles
):
    hops = _case(tmp_path, client_call, constructor)
    if expected_roles is None:
        assert hops is None
        return
    assert [hop["role"] for hop in hops] == expected_roles
    assert all(len(hop["source_sha256"]) == 64 for hop in hops)
    assert all({"path", "line", "column"} <= hop.keys() for hop in hops)


def test_captured_name_and_scope_helpers_resolve_exact_source_rows(tmp_path):
    from factoryline.credential_role_constructor_provider import (
        binding_statements,
        class_binding,
        function_bindings,
        import_is_stable,
        match_name,
        module_literal_binding,
        resolve_class,
        resolve_class_chain,
        scope_class,
    )

    index, paths = _snapshot(
        tmp_path,
        {
            "base.py": "class Base: pass\n",
            "use.py": (
                "from base import Base as Parent\n"
                "TOKEN = 'https://example.invalid/token'\n"
                "class Client(Parent):\n"
                "    endpoint = TOKEN\n"
                "    def send(self, value):\n"
                "        local = value\n"
                "        return self.endpoint, local\n"
            ),
        },
    )
    base, use = paths["base.py"], paths["use.py"]
    classes = {
        (path, node.name): node
        for path, tree in index.snapshots.items()
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    imports = {base: {}, use: {"Parent": (base, "Base")}}
    tree = index.snapshots[use]
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef))
    method = next(node for node in owner.body if isinstance(node, ast.FunctionDef))
    local = next(
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Name)
        and node.id == "local"
        and isinstance(node.ctx, ast.Store)
    )
    token = tree.body[1]
    token_name = (
        next(
            node
            for node in ast.walk(method)
            if isinstance(node, ast.Name)
            and node.id == "TOKEN"
            and isinstance(node.ctx, ast.Load)
        )
        if any(
            isinstance(node, ast.Name) and node.id == "TOKEN"
            for node in ast.walk(method)
        )
        else next(
            node
            for node in ast.walk(owner)
            if isinstance(node, ast.Name) and node.id == "TOKEN"
        )
    )

    assert resolve_class(use, ast.Name("Parent"), imports, classes) == (base, "Base")
    chain = resolve_class_chain(index, use, "Client", imports, classes, _Audit())
    assert [(path, name) for path, name, _ in chain] == [
        (use, "Client"),
        (base, "Base"),
    ]
    assert scope_class(method, index, use) is owner
    assert class_binding(owner, "endpoint", index.parents[use]) is not None
    assert binding_statements(method.body, "local") == [method.body[0]]
    assert function_bindings(method, "value", _Audit()) is None
    assert function_bindings(method, "local", _Audit()) == [method.body[0]]
    assert import_is_stable(use, "Parent", index, _Audit())
    fact = declaration_fact(index, use, token)
    assert fact is not None
    module_token = next(
        node
        for node in ast.walk(token)
        if isinstance(node, ast.Name) and node.id == "TOKEN"
    )
    assert module_literal_binding(fact, use, index, module_token, _Audit())
    assert match_name(
        fact, use, module_token, None, index, imports, classes, _Audit(), ()
    )
    assert local is not None and token_name is not None


def test_provider_selector_and_field_alias_helpers_apply_source_edges(tmp_path):
    from factoryline.credential_role_constructor_provider import (
        capture_holder_instances,
        class_index,
        field_alias_path,
        init_override,
        instance_selector_edges,
    )

    index, paths = _snapshot(
        tmp_path,
        {
            "adapter.py": "class Adapter: pass\nclass Client: pass\nadapter = Client()\n",
            "base.py": "class Base:\n    def __init__(self, endpoint):\n        self.endpoint = endpoint\n",
        },
    )
    assert all(index.validate(path) for path in index.snapshots)
    adapter = paths["adapter.py"]
    tree = index.snapshots[adapter]
    aliases = {}
    owners = {"captured_Client"}
    roots = set()
    filtered = {}
    fields = {}

    def resolve(node, known):
        name = ast.unparse(node)
        return {"Client": "captured_Client", "adapter": "captured_Adapter"}.get(
            name, known.get(name, name)
        )

    assert capture_holder_instances(
        tree,
        index.parents[adapter],
        aliases,
        owners,
        roots,
        adapter,
        filtered,
        fields,
        resolve,
    )
    assert aliases["adapter"] == "captured_Client"
    assert "captured_Client.client_class" in roots
    holder_tree = ast.parse("holder.client_class = selected.client_class\n")
    selector_roots = {"captured_Client.client_class"}
    selector_owners = set()
    selector_filtered = {}

    # Use a directly parsed mapping callback to exercise the selector edge contract.
    def selector_resolve(node, _aliases):
        return {
            "holder": "captured_Adapter",
            "selected.client_class": "captured_Client.client_class",
        }.get(ast.unparse(node))

    assert instance_selector_edges(
        holder_tree,
        {},
        selector_owners,
        selector_roots,
        paths["base.py"],
        selector_filtered,
        selector_resolve,
    )
    assert selector_owners == {"captured_Adapter"}
    assert "captured_Adapter.client_class" in selector_roots
    assert (
        field_alias_path(
            "captured_Adapter.client_class",
            {"captured_Adapter.client_class": "captured_Client.client_class"},
        )
        == "captured_Client.client_class"
    )
    base_tree = index.snapshots[paths["base.py"]]
    base_owner = next(node for node in base_tree.body if isinstance(node, ast.ClassDef))
    assert init_override(base_owner, index.parents[paths["base.py"]]) is True
    class_aliases = {
        path: {
            node.name: "captured_" + node.name
            for node in module.body
            if isinstance(node, ast.ClassDef)
        }
        for path, module in index.snapshots.items()
    }
    assert class_index(index, class_aliases)["captured_Adapter"][0] == adapter
    assert class_index(index, {path: {} for path in index.snapshots}) == {}


def test_constructor_provider_epochs_and_candidate_selection_are_live(tmp_path):
    from factoryline.credential_role_constructor_provider import (
        _helper_snapshot,
        candidate_facts,
        constructor_provider_helper_epoch,
        constructor_provider_model,
        constructor_provider_model_helper_epoch,
        constructor_provider_provenance_epoch,
        helper_epochs_valid,
        url_use,
    )

    index, paths = _snapshot(
        tmp_path,
        {"source.py": "TOKEN = 'https://user:password@example.invalid/token'\n"},
    )
    path = paths["source.py"]
    tree = index.snapshots[path]
    fact = declaration_fact(index, path, tree.body[0])
    sink_expression = ast.parse("TOKEN").body[0].value
    candidates = candidate_facts(
        index, index.snapshots, [(None, None, None, None, sink_expression)], set()
    )
    assert candidates == [fact]
    evidence = {"known_auth_uses": [], "url_witnesses": [], "linked_unknown_uses": []}
    url_use(fact, {"source": "consumer"}, evidence, set())
    assert evidence["known_auth_uses"] == [
        {"source": "consumer", "slot": "http_url_userinfo"}
    ]
    selected_model = constructor_provider_model(
        set(),
        index,
        {path: {}},
        lambda _path, _tree, _imports, _index: {},
        lambda *_args: False,
    )
    assert selected_model is not None and selected_model[0] == set()
    for epoch in (
        constructor_provider_provenance_epoch,
        constructor_provider_model_helper_epoch,
        constructor_provider_helper_epoch,
    ):
        values = epoch()
        assert isinstance(values, tuple) and values
        assert helper_epochs_valid({id(epoch): (epoch, _helper_snapshot(epoch))})


def test_factory_and_parameter_helpers_require_exact_direct_transfer(tmp_path):
    from factoryline.credential_role_constructor_provider import (
        build_hops,
        direct_factory_call,
        exact_parameter_field,
    )

    index, paths = _snapshot(
        tmp_path,
        {
            "adapter.py": "TOKEN = 'https://example.invalid/token'\n",
            "client.py": (
                "class Client:\n"
                "    def __init__(self, endpoint):\n"
                "        self.endpoint = endpoint\n"
                "    def build(self):\n"
                "        return Client(self.TOKEN)\n"
                "    def send(self, session):\n"
                "        return session.request('POST', self.endpoint)\n"
            ),
        },
    )
    assert all(index.validate(path) for path in index.snapshots)
    client_path = paths["client.py"]
    client = index.snapshots[client_path].body[0]
    ctor, factory, send = client.body
    assignment = ctor.body[0]
    return_call = factory.body[0].value
    assert direct_factory_call(return_call, factory, index, client_path)
    assert exact_parameter_field(ctor, assignment, "endpoint", index, client_path)
    assert not exact_parameter_field(ctor, assignment, "missing", index, client_path)
    fact = declaration_fact(
        index, paths["adapter.py"], index.snapshots[paths["adapter.py"]].body[0]
    )
    sink = send.body[0].value
    hops = build_hops(
        fact,
        index,
        client_path,
        return_call.func,
        (client_path, return_call.func),
        return_call,
        factory,
        ctor,
        assignment,
        sink,
        "endpoint",
        client_path,
        client_path,
        client_path,
    )
    assert [hop["role"] for hop in hops] == [
        "declared_literal",
        "client_class_selection",
        "constructor_argument",
        "constructor_parameter",
        "constructor_field_binding",
        "canonical_http_url_consumer",
    ]
    assert hops[0]["path"] == "adapter.py"
    assert all(hop["path"] == "client.py" for hop in hops[1:])
    assert hops[-1]["line"] == sink.lineno
    assert all(len(hop["source_sha256"]) == 64 for hop in hops)


@pytest.mark.parametrize(
    "expression,tail,reason",
    [
        ("Client.endpoint", ("endpoint",), None),
        ("Client.endpoint = foreign", ("endpoint",), "member_write_or_unknown_access"),
        (
            "Client.endpoint.lower()",
            ("endpoint", "lower"),
            "member_transform_or_unknown_tail",
        ),
        ("opaque(Client)", (), "class_escape_or_reflection"),
    ],
)
def test_direct_class_reads_retains_exact_member_and_rejects_ambiguous_edges(
    expression, tail, reason
):
    tree = ast.parse("class Client: pass\n" + expression + "\n")
    owner = tree.body[0]
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    if tail:
        node = next(
            n
            for n in ast.walk(tree.body[1])
            if isinstance(n, ast.Attribute) and n.attr == tail[-1]
        )
    else:
        node = tree.body[1].value.args[0]
    graph = SimpleNamespace(
        refs={("class", "source.py", "Client"): [("source.py", node, tail)]},
        parents=parents,
    )
    reads, actual = provider.direct_class_reads(
        graph, [("source.py", "Client", owner)], "endpoint"
    )
    assert actual == reason
    assert reads == (
        [] if reason else [("source.py", node, "source.py", "Client", None)]
    )


@pytest.mark.parametrize(
    "method_source,reason",
    [
        ("def endpoint(self):\n    return self.endpoint", None),
        ("def endpoint(self):\n    return opaque(self)", "receiver_escape_or_alias"),
        (
            "@property\ndef endpoint(self):\n    return self.endpoint",
            "decorated_method_access",
        ),
    ],
)
def test_method_reads_preserves_direct_receiver_and_rejects_escape(
    method_source, reason
):
    tree = ast.parse(method_source)
    method = tree.body[0]
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    graph = SimpleNamespace(parents=parents, _walk=ast.walk)
    reads, actual = provider.method_reads(
        graph, {"endpoint": ("source.py", "Client", method)}, "endpoint"
    )
    assert actual == reason
    if reason:
        assert reads == []
    else:
        assert reads == [
            ("source.py", method.body[0].value, "source.py", "Client", "endpoint")
        ]


@pytest.mark.parametrize(
    "contracts,accepted",
    [
        ({"external.Base": "caller-reviewed terminal"}, True),
        ({}, False),
        ({"external.Base": ""}, False),
        ({"Base": "unqualified"}, False),
    ],
)
def test_external_terminal_resolution_requires_exact_explicit_contract(
    tmp_path, contracts, accepted
):
    index, paths = _snapshot(
        tmp_path, {"source.py": "from external import Base\nclass Client(Base): pass\n"}
    )
    path = paths["source.py"]
    owner = index.snapshots[path].body[1]
    result = provider.resolve_class_chain_with_terminals(
        index,
        path,
        "Client",
        {path: {}},
        {(path, "Client"): owner},
        audit,
        contracts,
    )
    if accepted:
        assert result == {
            "chain": [(path, "Client", owner)],
            "terminal_assumptions": [
                {"canonical": "external.Base", "contract": "caller-reviewed terminal"}
            ],
        }
    else:
        assert result is None


@pytest.mark.parametrize(
    "declaration,base",
    [
        ("from external import Other, Base", "Base"),
        ("from external import Base, Other", "Base"),
        ("from external import Other, Base as Parent", "Parent"),
        ("from external import Other as Base, Base as Parent", "Parent"),
    ],
)
def test_terminal366_combined_import_preserves_selected_base_contract(
    tmp_path, declaration, base
):
    index, paths = _snapshot(
        tmp_path, {"source.py": f"{declaration}\nclass Child({base}): pass\n"}
    )
    path = paths["source.py"]
    owner = index.snapshots[path].body[1]
    result = provider.resolve_class_chain_with_terminals(
        index,
        path,
        "Child",
        {path: {}},
        {(path, "Child"): owner},
        audit,
        {"external.Base": "reviewed.external-base.v1"},
    )
    assert result == {
        "chain": [(path, "Child", owner)],
        "terminal_assumptions": [
            {"canonical": "external.Base", "contract": "reviewed.external-base.v1"}
        ],
    }


@pytest.mark.parametrize(
    "change",
    [
        "duplicate-alias",
        "rebound",
        "captured-shadow",
        "provider-write",
        "unregistered-base",
    ],
)
def test_terminal366_combined_import_rejects_ambiguous_or_mutated_base(
    tmp_path, change
):
    declaration = "from external import Other, Base as Parent"
    if change == "duplicate-alias":
        declaration = "from external import Base as Parent, Other as Parent"
    source = declaration + "\nclass Child(Parent): pass\n"
    if change == "rebound":
        source += "Parent = replacement\n"
    sources = {"source.py": source}
    if change == "captured-shadow":
        sources["external.py"] = "class Base: pass\nclass Other: pass\n"
    if change == "provider-write":
        sources["mutator.py"] = "import external\nexternal.Base = replacement\n"
    index, paths = _snapshot(tmp_path, sources)
    path = paths["source.py"]
    owner = index.snapshots[path].body[1]
    contract = "external.Other" if change == "unregistered-base" else "external.Base"
    assert (
        provider.resolve_class_chain_with_terminals(
            index,
            path,
            "Child",
            {path: {}},
            {(path, "Child"): owner},
            audit,
            {contract: "reviewed.external-base.v1"},
        )
        is None
    )


@pytest.mark.parametrize(
    "operand",
    [
        "django.utils.timezone.now",
        "[django.utils.timezone.now]",
        "{'callback': django.utils.timezone.now}",
    ],
)
def test_terminal367_namespace_receivers_do_not_escape_the_whole_package(
    tmp_path, operand
):
    index, paths = _snapshot(
        tmp_path,
        {
            "source.py": "from django.test import TestCase, Client\nclass Case(TestCase): pass\n",
            "migration.py": f"import django.utils.timezone\nfield(default={operand})\n",
        },
    )
    path = paths["source.py"]
    owner = index.snapshots[path].body[1]
    result = provider.resolve_class_chain_with_terminals(
        index,
        path,
        "Case",
        {path: {}},
        {(path, "Case"): owner},
        audit,
        {"django.test.TestCase": "reviewed.testcase.v1"},
    )
    assert result is not None
    assert result["terminal_assumptions"] == [
        {"canonical": "django.test.TestCase", "contract": "reviewed.testcase.v1"}
    ]


@pytest.mark.parametrize(
    "effect",
    [
        "consume(django)",
        "consume(django.test)",
        "consume(django.test.TestCase)",
        "consume(django.test.TestCase.setUp)",
        "consume(django.__dict__)",
        "django.test.TestCase = supplied",
        "setattr(django.test, 'TestCase', supplied)",
        "def callback(django): consume(django.utils.timezone.now)",
        "def callback():\n    import other as django\n    consume(django.utils.timezone.now)",
        "def callback():\n    def django(): pass\n    consume(django.utils.timezone.now)",
    ],
)
def test_terminal367_real_namespace_escape_or_provider_write_stays_rejected(
    tmp_path, effect
):
    index, paths = _snapshot(
        tmp_path,
        {
            "source.py": "from django.test import TestCase, Client\nclass Case(TestCase): pass\n",
            "migration.py": "import django.utils.timezone\n" + effect + "\n",
        },
    )
    path = paths["source.py"]
    owner = index.snapshots[path].body[1]
    assert (
        provider.resolve_class_chain_with_terminals(
            index,
            path,
            "Case",
            {path: {}},
            {(path, "Case"): owner},
            audit,
            {"django.test.TestCase": "reviewed.testcase.v1"},
        )
        is None
    )


def test_terminal367_leaf_capability_escape_is_not_cleared_by_module_prefix(tmp_path):
    index, paths = _snapshot(
        tmp_path,
        {
            "source.py": "from library.provider import Base\nclass Case(Base): pass\n",
            "peer.py": "import library.provider\nconsume(library.provider.Base.endpoint)\n",
        },
    )
    path = paths["source.py"]
    owner = index.snapshots[path].body[1]
    assert (
        provider.resolve_class_chain_with_terminals(
            index,
            path,
            "Case",
            {path: {}},
            {(path, "Case"): owner},
            audit,
            {"library.provider.Base": "reviewed.base.v1"},
        )
        is None
    )


@pytest.mark.parametrize(
    "helper",
    ["_terminal_imported_module_receiver", "_terminal_namespace_import_prefix"],
)
def test_terminal367_import_operand_helper_replacement_invalidates_native_context(
    tmp_path, monkeypatch, helper
):
    original = audit._oracle_context_cache_key(tmp_path, [], {})
    monkeypatch.setattr(provider, helper, lambda *_: False)
    assert audit._oracle_context_cache_key(tmp_path, [], {}) != original


@pytest.mark.parametrize(
    "declaration,operand",
    [
        ("from django.db import models", "models.CASCADE"),
        ("from django.db import models as db", "db.CASCADE"),
    ],
)
def test_terminal367_contracted_class_module_prefix_is_a_namespace(
    tmp_path, declaration, operand
):
    index, paths = _snapshot(
        tmp_path,
        {
            "source.py": "from django.db.models import Model\nclass Record(Model): pass\n",
            "migration.py": declaration + f"\nfield(on_delete={operand})\n",
        },
    )
    path = paths["source.py"]
    owner = index.snapshots[path].body[1]
    assert (
        provider.resolve_class_chain_with_terminals(
            index,
            path,
            "Record",
            {path: {}},
            {(path, "Record"): owner},
            audit,
            {"django.db.models.Model": "reviewed.model.v1"},
        )
        is not None
    )


def test_terminal367_imported_class_receiver_does_not_receive_namespace_exemption(
    tmp_path,
):
    index, paths = _snapshot(
        tmp_path,
        {
            "source.py": "from framework import Provider\nclass Record(Provider): pass\n",
            "peer.py": "from framework import Provider\nconsume(Provider.member)\n",
        },
    )
    path = paths["source.py"]
    owner = index.snapshots[path].body[1]
    assert (
        provider.resolve_class_chain_with_terminals(
            index,
            path,
            "Record",
            {path: {}},
            {(path, "Record"): owner},
            audit,
            {"framework.Provider": "reviewed.class.v1"},
        )
        is None
    )


@pytest.mark.parametrize(
    "change",
    [
        "",
        "password-projection-hook",
        "manager-return-replacement",
        "model-id-descriptor",
        "signal-connect",
        "aliased-signal-connect",
        "dynamic-signal-import",
        "provider-escape",
        "registry-user-alias",
        "get-user-model-alias",
        "reflective-registry-alias",
    ],
)
def test_terminal367_user_identifier_contract_rejects_password_dependent_identifiers(
    tmp_path, change
):
    source = "from django.contrib.auth.models import User\n"
    additions = {
        "": "pass\n",
        "password-projection-hook": (
            "from django.db.models.signals import post_save\n"
            "from django.dispatch import receiver\n"
            "@receiver(post_save, sender=User)\n"
            "def rewrite(sender, instance, **kwargs):\n"
            "    instance.pk = int.from_bytes(instance.password.encode()[:8], 'big')\n"
        ),
        "manager-return-replacement": "User.objects.create_superuser = replacement\n",
        "model-id-descriptor": "User.id = property(lambda obj: obj.password)\n",
        "signal-connect": (
            "from django.db.models.signals import post_init\n"
            "post_init.connect(rewrite, sender=User)\n"
        ),
        "aliased-signal-connect": (
            "import django.db.models.signals as hooks\n"
            "connect = hooks.post_save.connect\nconnect(rewrite)\n"
        ),
        "dynamic-signal-import": (
            "from importlib import import_module\n"
            "hooks = import_module('django.db.models.signals')\n"
        ),
        "provider-escape": "unknown(User)\n",
        "registry-user-alias": (
            "from django.apps import apps\nTarget = apps.get_model('auth', 'User')\n"
            "Target.pk = property(lambda obj: obj.password)\n"
        ),
        "get-user-model-alias": (
            "from django.contrib.auth import get_user_model\nTarget = get_user_model()\n"
            "Target.pk = property(lambda obj: obj.password)\n"
        ),
        "reflective-registry-alias": (
            "from django.apps import apps\nTarget = apps.get_model('auth', 'User')\n"
            "setattr(Target, 'pk', property(lambda obj: obj.password))\n"
        ),
    }
    index, _ = _snapshot(tmp_path, {"source.py": source + additions[change]})
    result = provider.django_user_identifier_contract({"source": index})
    assert (result is not None) is (change == "")
    if result is not None:
        assert result["projections"] == ("pk", "id")
        assert result["role"] == "NON_SECRET_PROJECTION"
        assert result["downstream_authorization"] == "UNASSESSED"


@pytest.mark.parametrize(
    "helper", ["django_user_identifier_contract", "_django_user_projection_hooks_clear"]
)
def test_terminal367_identifier_contract_helpers_participate_in_native_cache_epoch(
    tmp_path, monkeypatch, helper
):
    before = audit._oracle_context_cache_key(tmp_path, [], {})
    monkeypatch.setattr(provider, helper, lambda *_: None)
    assert audit._oracle_context_cache_key(tmp_path, [], {}) != before


@pytest.mark.parametrize(
    "change",
    [
        "",
        "unbound-method",
        "unbound-init",
        "reflective-init",
        "self-rebind",
        "custom-new",
        "shadowed-object",
    ],
)
def test_terminal367_unrelated_constructor_write_requires_owned_receiver_closure(
    tmp_path, change
):
    source = (
        "from django.apps import apps\n"
        "class Metadata(object):\n"
        "    def __init__(self, key, value):\n"
        "        setattr(self, key, value)\n"
        "Metadata('title', 'ordinary data')\n"
    )
    if change == "unbound-method":
        source = source.replace("__init__", "rewrite").replace(
            "Metadata('title', 'ordinary data')", ""
        )
        source += "Target = apps.get_model('auth', 'User')\nMetadata.rewrite(Target, 'pk', descriptor)\n"
    if change == "unbound-init":
        source += "Target = apps.get_model('auth', 'User')\nMetadata.__init__(Target, 'pk', descriptor)\n"
    if change == "reflective-init":
        source += "Target = apps.get_model('auth', 'User')\ngetattr(Metadata, '__init__')(Target, 'pk', descriptor)\n"
    if change == "self-rebind":
        source = source.replace(
            "        setattr",
            "        self = apps.get_model('auth', 'User')\n        setattr",
        )
    if change == "custom-new":
        source = source.replace(
            "    def __init__",
            "    def __new__(cls, *args): return apps.get_model('auth', 'User')\n    def __init__",
        )
    if change == "shadowed-object":
        source = source.replace(
            "class Metadata", "object = apps.get_model('auth', 'User')\nclass Metadata"
        )
    index, _ = _snapshot(tmp_path, {"source.py": source})
    assert (
        provider.django_user_identifier_contract({"source": index}) is not None
    ) is (change == "")


@pytest.mark.parametrize(
    "change",
    [
        "",
        "self-alias",
        "self-escape",
        "password-escape",
        "account-escape",
        "client-escape",
        "helper-export",
        "outside-call",
        "unbound-call",
        "identity-mismatch",
        "account-rebind",
        "conditional-client-override",
    ],
)
def test_adapter367_registered_helper_requires_complete_credential_and_receiver_uses(
    tmp_path, change
):
    from factoryline import mock_fixture_provenance as fixture

    text = (
        "from django.contrib.auth.models import User\n"
        "from django.test import TestCase, Client\n"
        "class Scenario(TestCase):\n"
        "    def setUp(self): self.assertTrue(self.prepare())\n"
        "    def prepare(self):\n"
        "        username = 'account'\n"
        "        email = 'account@example.invalid'\n"
        "        password = 'admin'\n"
        "        self.transport = Client()\n"
        "        self.actor = User.objects.create_superuser(username, email, password)\n"
        "        return self.transport.login(username=username, password=password)\n"
        "    def test_exercise(self):\n"
        "        consume(self.actor.pk)\n"
        "        self.transport.get('/')\n"
    )
    additions = {
        "self-alias": "        alias = self\n        leak(alias.actor.password)\n",
        "self-escape": "        leak(self)\n",
        "account-escape": "        leak(self.actor)\n",
        "client-escape": "        leak(self.transport)\n",
        "helper-export": "        callback = self.prepare\n        leak(callback)\n",
        "account-rebind": "        self.actor = other\n",
    }
    text += additions.get(change, "")
    if change == "password-escape":
        text = text.replace(
            "        self.transport = Client()",
            "        leak(password)\n        self.transport = Client()",
        )
    if change == "outside-call":
        text += "case = Scenario()\ncase.prepare()\n"
    if change == "unbound-call":
        text += "Scenario.prepare(holder)\n"
    if change == "identity-mismatch":
        text = text.replace("login(username=username", "login(username='different'")
    if change == "conditional-client-override":
        text = text.replace(
            "class Scenario(TestCase):",
            "class Scenario(TestCase):\n    if True: client_class = RemoteClient",
        )
    raw = text.encode()
    path = tmp_path / "renamed.py"
    digest = hashlib.sha256(raw).hexdigest()
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = digest
    index = fixture.application_test_index(
        tmp_path, {path: tree}, {path: raw}, {path: digest}
    )
    declaration = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Constant)
        and node.value.value == "admin"
    )
    result = fixture.application_test_secret_evidence(
        index, path, declaration.lineno, "admin"
    )
    assert result["eligible"] is (change == ""), result


@pytest.mark.parametrize(
    "declaration,suffix,accepted",
    [
        ("class Client: pass", "isinstance(value, Client)", True),
        ("class Client(metaclass=opaque): pass", "isinstance(value, Client)", False),
        (
            "class Client: pass",
            "Client.__bases__ = supplied\nisinstance(value, Client)",
            False,
        ),
        (
            "class Client: pass",
            "def probe(Client):\n    return isinstance(value, Client)",
            False,
        ),
    ],
)
def test_ordinary_type_operand_requires_captured_stable_class(
    tmp_path, declaration, suffix, accepted
):
    index, paths = _snapshot(
        tmp_path, {"source.py": declaration + "\n" + suffix + "\n"}
    )
    path = paths["source.py"]
    assert index.validate(path)
    tree = index.snapshots[path]
    aliases = {"Client": "source.Client"}
    classes = {"source.Client": (path, tree.body[0], aliases, tree)}
    operand = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "isinstance"
    ).args[1]
    assert (
        provider.ordinary_type_operand(
            operand,
            tree,
            index.parents[path],
            index,
            classes,
            aliases,
            {"source.Client"},
            {path: aliases},
        )
        is accepted
    )
    assert not provider.ordinary_type_operand(
        ast.Constant(1),
        tree,
        index.parents[path],
        index,
        classes,
        aliases,
        {"source.Client"},
        {path: aliases},
    )


@pytest.mark.parametrize(
    "body,stable,accepted",
    [
        ("return None", True, True),
        ("return opaque(value)", True, False),
        ("return None", False, False),
    ],
)
def test_source_owner_consumer_requires_closed_classmethod_effects(
    tmp_path, body, stable, accepted
):
    source = (
        "class Value: pass\nclass Consumer:\n    @classmethod\n    def inspect(cls, value):\n        "
        + body
        + "\nConsumer.inspect(Value)\n"
    )
    index, paths = _snapshot(tmp_path, {"source.py": source})
    path = paths["source.py"]
    assert index.validate(path)
    tree = index.snapshots[path]
    aliases = {"Value": "source.Value", "Consumer": "source.Consumer"}
    classes = {
        "source." + node.name: (path, node, aliases, tree)
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }
    node = tree.body[-1].value.args[0]
    result = provider.source_owner_consumer(
        node,
        path,
        tree,
        index.parents[path],
        index,
        aliases,
        classes,
        {"source.Value"},
        stable,
        {path: aliases},
    )
    assert result == ("source.Consumer.inspect" if accepted else None)


@pytest.mark.parametrize(
    "change,eligible",
    [
        ("", True),
        ("unknown-mode", False),
        ("overwrite", False),
        ("formal-rebind", False),
        ("escape", False),
        ("mutating-method", False),
        ("early-return", False),
        ("effectful-guard", False),
        ("wrong-branch", False),
        ("namespace-mutation", False),
        ("detached-caller", False),
    ],
)
def test_literal273_selected_field_branch_is_source_bound(tmp_path, change, eligible):
    import ast
    import hashlib
    from factoryline.mock_fixture_provenance import application_test_index
    from factoryline.review_integrity import bind_source_call
    from factoryline.credential_role_identity_effects import (
        _app_literal_branch_field_transfer,
    )

    text = (
        "class Request:\n"
        "    def __init__(self, *, body, mode='http'):\n"
        "        if mode == 'http':\n"
        "            self.raw_body = body if body is not None else ''\n"
        "        else:\n"
        "            self.raw_body = ''\n"
        "def test_request():\n"
        "    raw = 'payload'\n"
        "    request = Request(body=raw)\n"
    )
    if change == "unknown-mode":
        text = text.replace("Request(body=raw)", "Request(body=raw, mode=unknown())")
    if change == "overwrite":
        text = text.replace(
            "def test_request", "        self.raw_body = other\ndef test_request"
        )
    if change in {"formal-rebind", "escape", "mutating-method", "early-return"}:
        statement = {
            "formal-rebind": "body = other",
            "escape": "publish(self)",
            "mutating-method": "self.change()",
            "early-return": "return",
        }[change]
        text = text.replace(
            "        if mode", "        " + statement + "\n        if mode"
        )
    if change == "effectful-guard":
        text = text.replace("mode == 'http'", "publish(body) is None")
    if change == "wrong-branch":
        text = text.replace("Request(body=raw)", "Request(body=raw, mode='other')")
    if change == "namespace-mutation":
        text = text.replace(
            "def test_request", "        rewrite(self.__dict__)\ndef test_request"
        )
    path = tmp_path / "sample.py"
    raw = text.encode()
    digest = hashlib.sha256(raw).hexdigest()
    tree = ast.parse(raw)
    tree._oracle_source_sha256 = digest
    index = application_test_index(tmp_path, {path: tree}, {path: raw}, {path: digest})
    assert index is not None
    assert index["source"].validate(path)
    constructor = tree.body[0].body[0]
    caller = tree.body[1]
    call = caller.body[-1].value
    bound = bind_source_call(call, constructor, ast.Name(id="target", ctx=ast.Load()))
    if change == "detached-caller":
        caller = ast.parse(text.replace("raw = 'payload'", "raw = 'forged'")).body[1]
    result = _app_literal_branch_field_transfer(
        index, path, constructor, bound, path, caller, "raw_body"
    )
    assert (result is not None) is eligible
    if result is not None:
        assert result["formal"] == "body"
        assert result["actual"] is call.keywords[0].value
        assert result["statement"] is constructor.body[0].body[0]


@pytest.mark.parametrize(
    "arguments,change,accepted",
    [
        ("headers=value", "", True),
        ("headers=value, **options", "", False),
        ("*items, headers=value", "", False),
        ("**value", "", False),
        ("headers=value", "detached-keyword", False),
        ("headers=value", "foreign-scope", False),
        ("headers=value", "unverified-consumer", False),
    ],
)
def test_literal273_keyword_value_requires_exact_closed_consumer(
    arguments, change, accepted
):
    from factoryline.finite_capture import captured_value_use_closure

    function = ast.parse("def test_request():\n    Request(" + arguments + ")\n").body[
        0
    ]
    call = function.body[0].value
    keyword = call.keywords[0]
    value = keyword.value
    parents = {
        id(child): node
        for node in ast.walk(function)
        for child in ast.iter_child_nodes(node)
    }
    if change == "detached-keyword":
        parents[id(value)] = ast.keyword(arg="headers", value=value)
        parents[id(parents[id(value)])] = call
    result = captured_value_use_closure(
        function,
        value,
        parents,
        lambda node: None if change == "foreign-scope" else function,
        lambda scope: None,
        lambda scope, node: call
        if node is call and change != "unverified-consumer"
        else None,
    )
    assert (result is not None) is accepted
    if result is not None:
        assert result["sinks"] == (call,)
