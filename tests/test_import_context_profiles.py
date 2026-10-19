"""Native import-context tier boundaries, identity and immutability controls."""

import pytest

from factoryline import import_context as capture


@pytest.mark.parametrize(
    "size,tier",
    [
        (0, "standard-static-v1"),
        (460, "standard-static-v1"),
        (461, "expanded-static-v1"),
        (2000, "expanded-static-v1"),
        (2001, "unsupported"),
        (True, "unsupported"),
        (-1, "unsupported"),
    ],
)
def test_import_profile_has_bounded_deterministic_selection(size, tier):
    assert capture.native_import_profile(size)["id"] == tier


@pytest.mark.parametrize("size", [1, 461])
@pytest.mark.parametrize("limit", ["bindings", "characters"])
def test_each_tier_accepts_the_limit_then_rejects_entire_view(tmp_path, size, limit):
    source = tmp_path / "source.py"
    views = capture.new_import_views(size)
    imported = {"Alias": (source, "Name")}
    cost = len("Alias") + len(str(source)) + len("Name")
    maximum = views["profile"][limit]
    views[limit] = maximum - (1 if limit == "bindings" else cost)
    capture.capture_project_imports(views, source, imported, {})
    assert source in views["resolved"]
    assert views[limit] == maximum
    capture.capture_project_imports(views, source, imported, {})
    assert views == {}
    capture.capture_project_imports(views, source, {}, {})
    assert views == {}


def test_exact_inventory_and_tier_are_required_and_views_are_immutable(tmp_path):
    source = tmp_path / "source.py"
    snapshots = {source: object()}
    eligible = {source.resolve(): source}
    imported = {"Alias": (source, "Name")}
    views = capture.new_import_views(1)
    capture.capture_project_imports(views, source, imported, eligible)
    imported.clear()
    selected = capture.project_import_views(views, snapshots)
    assert selected[source]["Alias"] == (source, "Name")
    with pytest.raises(TypeError):
        selected[source]["Alias"] = (source, "Other")
    with pytest.raises(TypeError):
        selected[source] = {}
    assert capture.project_import_views(views, {}) is None
    views["profile"] = capture.native_import_profile(461)
    assert capture.project_import_views(views, snapshots) is None
    views["profile"] = capture.native_import_profile(1)
    views["resolved"].clear()
    assert capture.project_import_views(views, snapshots) is None


def test_foreign_or_unsupported_limits_cannot_create_a_partial_view(tmp_path):
    source = tmp_path / "source.py"
    for profile in (
        {"id": "custom", "bindings": 999999, "characters": 9999999},
        capture.native_import_profile(2001),
    ):
        views = capture.new_import_views(1)
        views["profile"] = profile
        capture.capture_project_imports(views, source, {}, {})
        assert views == {}


def test_tier_is_declared_in_cache_configuration_and_scan_metadata():
    standard = capture.import_configuration({}, None, 460)
    expanded = capture.import_configuration({}, None, 461)
    assert standard != expanded
    assert expanded["native_import_context"] == {
        "id": "expanded-static-v1",
        "bindings": 8192,
        "characters": 2097152,
    }
    metadata = capture.import_context_metadata([None] * 461, [], [])
    assert metadata["import_context_profile"] == expanded["native_import_context"]
    assert metadata["resolved_edges"] == []
    assert metadata["edge_count"] == 0


def test_profile_helper_implementation_is_part_of_context_cache_identity(
    tmp_path, monkeypatch
):
    from factoryline import review_audits as audit

    original = audit.contracts.native_import_profile
    identity = capture.import_configuration({}, None, 1)
    before = audit._oracle_context_cache_key(tmp_path, [], identity)

    def replaced(size):
        return original(size)

    monkeypatch.setattr(audit.contracts, "native_import_profile", replaced)
    after = audit._oracle_context_cache_key(tmp_path, [], identity)
    assert before != after


def test_native_context_cold_warm_keeps_the_same_profile_and_evidence(tmp_path):
    from factoryline import review_audits as audit
    from factoryline.review_integrity import encode_structural_context

    (tmp_path / "base.py").write_text(
        "class Adapter:\n    def run(self): raise NotImplementedError\n"
    )
    (tmp_path / "impl.py").write_text(
        "from base import Adapter\nclass Impl(Adapter):\n    def run(self): return 1\n"
    )
    files = sorted(tmp_path.glob("*.py"))
    audit._oracle_context_cache_clear()
    cold = audit._project_oracle_context(tmp_path, files)
    warm = audit._project_oracle_context(tmp_path, files)
    assert encode_structural_context(cold[0]) == encode_structural_context(warm[0])
    assert cold[1:] == warm[1:]
    assert audit._oracle_context_cache_info()["hits"] >= 1


@pytest.mark.parametrize("inventory_kind", ["mapping", "set"])
def test_provider_initializer_resolution_retains_exact_eligible_paths(
    tmp_path, inventory_kind
):
    from factoryline.context_efficiency import _provider_package_initializers

    source = tmp_path / "package" / "nested" / "module.py"
    initializers = [tmp_path / "__init__.py", source.parent / "__init__.py"]
    initializers.append(source.parent.parent / "__init__.py")
    for path in [source, *initializers]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    eligible = {path.resolve(): path for path in [source, *initializers]}
    if inventory_kind == "set":
        eligible = set(eligible.values())

    assert _provider_package_initializers(
        tmp_path, [source, source], eligible
    ) == sorted(initializers)
    excluded = source.parent / "__init__.py"
    if isinstance(eligible, dict):
        eligible.pop(excluded.resolve())
    else:
        eligible.remove(excluded)
    assert _provider_package_initializers(tmp_path, [source], eligible) == sorted(
        path for path in initializers if path != excluded
    )


def test_provider_initializer_resolution_does_not_scan_above_root(tmp_path):
    from factoryline.context_efficiency import _provider_package_initializers

    root = tmp_path / "project"
    source = root / "package" / "module.py"
    outside = tmp_path / "__init__.py"
    inside = root / "__init__.py"
    eligible = {path.resolve(): path for path in [outside, inside]}
    assert _provider_package_initializers(root, [source], eligible) == [inside]


def test_provider_initializer_resolves_root_and_each_initializer_once(
    tmp_path, monkeypatch
):
    from pathlib import Path

    from factoryline.context_efficiency import _provider_package_initializers

    source = tmp_path / "package" / "nested" / "module.py"
    initializer = source.parent / "__init__.py"
    eligible = {initializer.resolve(): initializer}
    original = Path.resolve
    calls = []

    def counted(path, *args, **kwargs):
        calls.append(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", counted)
    assert _provider_package_initializers(tmp_path, [source], eligible) == [initializer]
    assert calls.count(tmp_path) == 1
    assert calls.count(initializer) == 1
    assert len(calls) == 5


def test_provider_initializer_resolution_preserves_symlink_canonicalization(tmp_path):
    from factoryline.context_efficiency import _provider_package_initializers

    actual = tmp_path / "actual"
    actual.mkdir()
    source = actual / "module.py"
    source.write_text("", encoding="utf-8")
    initializer = actual / "__init__.py"
    initializer.write_text("", encoding="utf-8")
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(actual, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    eligible = {initializer.resolve(): linked / "__init__.py"}
    assert _provider_package_initializers(linked, [linked / "module.py"], eligible) == [
        linked / "__init__.py"
    ]
