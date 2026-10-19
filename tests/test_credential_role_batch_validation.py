"""A producer batch must discard every derived role after source mutation."""

import ast
import hashlib
from types import SimpleNamespace

import pytest

from factoryline.credential_role_chain_memo import ClassChainMemo
from factoryline.credential_role_sources import SourceSnapshotIndex


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
    from factoryline import credential_role_receiver_lifetime as lifetime

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
    from factoryline import credential_role_receiver_lifetime as lifetime

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
