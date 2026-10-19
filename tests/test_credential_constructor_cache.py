"""Constructor-provider reuse stays inside a freshness-checked analysis batch."""

import pytest

from test_credential_role_chain_memo import setup

from factoryline import credential_role_constructor_provider as provider
from factoryline import credential_role_constructor_provider_provenance as type_effects
from factoryline import provider_mutations
from factoryline.credential_role_bindings import class_chain
from factoryline.credential_role_transfer_guards import constructor_bindings_inert


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
