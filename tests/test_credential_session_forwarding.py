import ast
import hashlib

import pytest

from factoryline import review_audits as audit
from factoryline.credential_role_sources import SourceSnapshotIndex
from factoryline.credential_session_forwarding import session_factory_witness


SOURCE = (
    "import functools\n"
    "class Adapter:\n"
    "    def factory(self):\n"
    "        import requests\n"
    "        session = requests.Session()\n"
    "        session.request = functools.partial(session.request, timeout=30)\n"
    "        return session\n"
)


def _input(tmp_path, source=SOURCE):
    path = tmp_path / "adapter.py"
    raw = source.encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(tmp_path, {path: tree}, {path: raw}, {path: digest})
    function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
    return path, function, index, audit._module_security_aliases(tree)


def test_timeout_only_forwarder_preserves_slots_and_binds_every_hop(tmp_path):
    args = _input(tmp_path)
    witness = session_factory_witness(*args)
    assert witness["preserved_slots"] == ["method", "url", "auth", "headers"]
    assert witness["runtime_provider_identity"] == "UNASSESSED"
    assert witness["runtime_factory_dispatch"] == "UNASSESSED"
    assert len(witness["hops"]) == 4
    assert all(
        hop["source_sha256"] == args[2].inventory[args[0]]
        and hop["path"] == "adapter.py"
        for hop in witness["hops"]
    )


def test_unmodified_session_factory_has_three_hops(tmp_path):
    source = SOURCE.replace(
        "        session.request = functools.partial(session.request, timeout=30)\n", ""
    )
    assert len(session_factory_witness(*_input(tmp_path, source))["hops"]) == 3


@pytest.mark.parametrize(
    "replacement",
    [
        "functools.partial(session.request, url='other')",
        "functools.partial(session.request, auth=('u', 'secret'))",
        "functools.partial(session.request, 'POST', timeout=30)",
        "functools.partial(session.request, timeout=30, headers={})",
        "functools.partial(session.request, **options)",
        "functools.partial(*arguments, timeout=30)",
        "functools.partial(other.request, timeout=30)",
        "other.request",
        "opaque(session.request)",
    ],
)
def test_changed_slot_binding_or_unknown_forwarder_is_unresolved(tmp_path, replacement):
    source = SOURCE.replace(
        "functools.partial(session.request, timeout=30)", replacement
    )
    assert session_factory_witness(*_input(tmp_path, source)) is None


@pytest.mark.parametrize(
    "source",
    [
        SOURCE.replace("requests.Session()", "unknown.Session()"),
        SOURCE.replace("requests.Session()", "requests.Session(config)"),
        SOURCE.replace("return session", "return other"),
        SOURCE.replace("    def factory", "    @unknown\n    def factory"),
        SOURCE.replace("class Adapter:", "@unknown\nclass Adapter:"),
        SOURCE.replace("class Adapter:", "class Adapter(metaclass=Unknown):"),
        SOURCE + "    factory = replacement\n",
        SOURCE + "requests.Session = replacement\n",
        SOURCE + "functools.partial = replacement\n",
        SOURCE + "setattr(functools, 'partial', replacement)\n",
        SOURCE + "    if True:\n        def factory(self): return replacement\n",
        SOURCE + "    if True:\n        class factory: pass\n",
    ],
)
def test_unknown_factory_identity_or_mutation_cannot_be_canonical(tmp_path, source):
    assert session_factory_witness(*_input(tmp_path, source)) is None


def test_stale_or_forged_source_tree_cannot_supply_hops(tmp_path):
    path, function, index, aliases = _input(tmp_path)
    index.source_bytes[path] += b"# changed\n"
    assert session_factory_witness(path, function, index, aliases) is None
    path, function, index, aliases = _input(tmp_path)
    forged = next(
        n for n in ast.walk(ast.parse(SOURCE)) if isinstance(n, ast.FunctionDef)
    )
    assert session_factory_witness(path, forged, index, aliases) is None
