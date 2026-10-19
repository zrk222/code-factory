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


@pytest.mark.parametrize("mutation", ["inventory", "tree"])
def test_initializer_lookup_rejects_changed_generation(tmp_path, mutation):
    import ast

    from factoryline.context_efficiency import captured_import_resolver

    source = tmp_path / "module.py"
    snapshots = {source: ast.parse("pass")}
    eligible = {source.resolve(): source}
    _, initializers, _validate = captured_import_resolver(
        tmp_path, snapshots, eligible, lambda *args: {}, with_initializers=True
    )
    initializers([source])
    if mutation == "inventory":
        eligible.clear()
    else:
        snapshots[source] = ast.parse("pass")
    with pytest.raises(ValueError, match="outside its captured generation"):
        initializers([source])


@pytest.mark.parametrize("mutation", ["binding", "code"])
def test_initializer_lookup_rejects_changed_helper(tmp_path, monkeypatch, mutation):
    from factoryline import context_efficiency as context

    _, initializers, _validate = context.captured_import_resolver(
        tmp_path, {}, {}, lambda *args: {}, with_initializers=True
    )
    initializers([])

    def replacement(root, sources, eligible):
        return []

    if mutation == "binding":
        monkeypatch.setattr(context, "_provider_package_initializers", replacement)
    else:
        monkeypatch.setattr(
            context._provider_package_initializers, "__code__", replacement.__code__
        )
    with pytest.raises(ValueError, match="Initializer helper changed"):
        initializers([])


def test_initializer_lookup_memoizes_exact_groups_and_returns_copies(
    tmp_path, monkeypatch
):
    from factoryline import context_efficiency as context

    first = tmp_path / "first.py"
    second = tmp_path / "second.py"
    calls = []

    def arbitrary_helper(root, sources, eligible):
        calls.append(tuple(sources))
        return [root / f"arity_{len(sources)}.py"]

    monkeypatch.setattr(context, "_provider_package_initializers", arbitrary_helper)
    _, lookup, validate = context.captured_import_resolver(
        tmp_path,
        {first: object(), second: object()},
        {first: first, second: second},
        lambda *args: {},
        with_initializers=True,
    )
    groups = [[], [first], [first, second], [second, first]]
    for group in groups:
        expected = arbitrary_helper(tmp_path, group, {})
        observed = lookup(group)
        assert observed == expected
        observed.clear()
        assert lookup(group) == expected
    assert calls == [item for group in groups for item in [tuple(group), tuple(group)]]
    context.captured_import_resolver(
        tmp_path, {}, {}, lambda *args: {}, with_initializers=True
    )[1]([])
    assert calls[-1] == ()
    assert len(calls) == 9


@pytest.mark.parametrize("module_count,complete", [(62, True), (63, True), (64, False)])
def test_initializer_lookup_preserves_exact_closure_cycle_and_bound(
    tmp_path, module_count, complete
):
    import ast

    from factoryline.context_efficiency import (
        captured_import_resolver,
        captured_local_import_closure,
    )

    modules = [tmp_path / f"module_{index}.py" for index in range(module_count)]
    initializer = tmp_path / "__init__.py"
    snapshots = {path: ast.parse("pass") for path in [*modules, initializer]}
    for tree in snapshots.values():
        tree._oracle_source_sha256 = "b" * 64
    eligible = {path.resolve(): path for path in snapshots}
    imports = {
        source: {"Next": (modules[(index + 1) % module_count], "Name")}
        for index, source in enumerate(modules)
    }
    imports[initializer] = {}
    resolve, lookup, validate = captured_import_resolver(
        tmp_path,
        snapshots,
        eligible,
        lambda root, source, tree, inventory: imports[source],
        with_initializers=True,
    )
    arguments = (
        tmp_path,
        {"Start": (modules[0], "Name")},
        snapshots,
        eligible,
        resolve,
    )
    expected = captured_local_import_closure(*arguments, extra_sources=[modules[0]])
    observed = captured_local_import_closure(
        *arguments, extra_sources=[modules[0]], initializer_lookup=lookup
    )
    assert observed == expected
    rows, actual_complete = observed
    assert actual_complete is complete
    if complete:
        assert len(rows) == module_count + 1
    else:
        assert rows == []


@pytest.mark.parametrize("foreign", ["inventory", "source"])
def test_initializer_lookup_uses_fresh_results_outside_canonical_inventory(
    tmp_path, monkeypatch, foreign
):
    from factoryline import context_efficiency as context

    source = tmp_path / "source.py"
    seen = []

    def counted(root, sources, eligible):
        seen.append(tuple(sources))
        return []

    monkeypatch.setattr(context, "_provider_package_initializers", counted)
    eligible = {source: source}
    query = [source]
    if foreign == "inventory":
        eligible = {source: tmp_path / "alias.py"}
    else:
        query = [tmp_path / "foreign.py"]
    _, lookup, validate = context.captured_import_resolver(
        tmp_path,
        {source: object()},
        eligible,
        lambda *args: {},
        with_initializers=True,
    )
    assert lookup(query) == lookup(query) == []
    assert len(seen) == 2
    validate()


def test_initializer_validation_rejects_a_new_previously_absent_alias(tmp_path):
    import ast

    from factoryline import context_efficiency as context

    source = tmp_path / "package" / "module.py"
    source.parent.mkdir()
    source.write_text("value = 1", encoding="utf-8")
    poison = tmp_path / "poison.py"
    poison.write_text("value = 1", encoding="utf-8")
    snapshots = {path: ast.parse(path.read_text()) for path in [source, poison]}
    eligible = {path: path for path in snapshots}
    _, lookup, validate = context.captured_import_resolver(
        tmp_path, snapshots, eligible, lambda *args: {}, with_initializers=True
    )
    assert lookup([source]) == []
    validate()
    initializer = source.parent / "__init__.py"
    try:
        initializer.symlink_to(poison)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert lookup([source]) == []
    assert context._provider_package_initializers(tmp_path, [source], eligible) == [
        poison
    ]
    with pytest.raises(ValueError, match="Initializer paths changed"):
        validate()


def test_native_context_builder_requires_initializer_validation_before_cache(
    tmp_path, monkeypatch
):
    from factoryline import context_efficiency as context
    from factoryline import review_audits as audit

    (tmp_path / "source.py").write_text("value = 1", encoding="utf-8")
    original = context.captured_import_resolver
    observed = []
    cache_writes = []

    def captured(*args, **kwargs):
        resolve, lookup, validate = original(*args, **kwargs)

        def rejected():
            observed.append("validated")
            validate()
            raise ValueError("initializer-validation-sentinel")

        return resolve, lookup, rejected

    monkeypatch.setattr(context, "captured_import_resolver", captured)
    monkeypatch.setattr(
        audit, "_oracle_context_cache_write", lambda *args: cache_writes.append(args)
    )
    with pytest.raises(ValueError, match="initializer-validation-sentinel"):
        audit.security_scan(tmp_path, cache_enabled=True)
    assert observed == ["validated"]
    assert cache_writes == []


def test_initializer_factory_implementation_participates_in_cache_epoch(
    tmp_path, monkeypatch
):
    from factoryline import context_efficiency as context
    from factoryline import review_audits as audit

    original = context.captured_initializer_lookup
    assert original in context.provider_context_cache_helpers(audit.contracts)
    before = audit._oracle_context_cache_key(tmp_path, [], {})

    def replacement(*args, **kwargs):
        return original(*args, **kwargs)

    monkeypatch.setattr(context, "captured_initializer_lookup", replacement)
    after = audit._oracle_context_cache_key(tmp_path, [], {})
    assert before != after
