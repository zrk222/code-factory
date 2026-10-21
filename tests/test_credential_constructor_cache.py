"""Constructor-provider reuse stays inside a freshness-checked analysis batch."""

import pytest
from test_credential_role_decorator_boundaries import setup
from factoryline import credential_role_constructor_provider as provider
from factoryline import credential_role_constructor_provider_provenance as type_effects
from factoryline import provider_mutations
from factoryline.credential_role_bindings import class_chain
from factoryline.credential_role_constructor_flow import constructor_bindings_inert
from factoryline import credential_httpx_origins as httpx
from factoryline import credential_json_assertions as assertions
from factoryline import credential_role_scope_bindings as roles
from factoryline import credential_router_publication as routers
from factoryline import review_audits as audit
import ast
from types import SimpleNamespace
from factoryline import credential_role_adapter_selection as selection
import hashlib
from factoryline.credential_role_bindings import auth_constructor_password
from factoryline.credential_role_paths import session_request_context
from factoryline.credential_role_sources import (
    SourceSnapshotIndex,
    source_session_factories,
)
from factoryline.credential_role_chain_memo import ClassChainMemo
from factoryline.credential_role_constructor_flow import constructor_url_hops
from factoryline.credential_role_sources import declaration_fact
from factoryline.review_integrity import bind_source_call

SOURCE = "class Client: pass\nclass Adapter:\n    client_class = Client\n"


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
            monkeypatch.setattr(
                provider_mutations, "_reflective_provider_write", changed
            )
        else:
            monkeypatch.setattr(
                provider_mutations._reflective_provider_write,
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
