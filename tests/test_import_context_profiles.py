"""Native import-context tier boundaries, identity and immutability controls."""

import pytest
from factoryline import import_context as capture
from factoryline.proof_reuse import evaluate_proofs, record_proof
from factoryline.incremental_scheduler import (
    SchedulerError,
    SCHEMA,
    compare_shadow,
    paths_intersect,
    plan_incremental,
    validate_schedule_manifest,
)
import ast
from test_runtime_audit_integrity import _JSON_TEST, _json_enum_graph
from pathlib import Path
from factoryline import intent_quality
from factoryline import review_audits as audit


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


def _manifest(**overrides):
    value = {
        "schema": SCHEMA,
        "plan_id": "plan-1",
        "assurance_level": "isolated_worker",
        "changed_paths": ["src/app.py"],
        "dependency_closure": {"lint": ["src/app.py"], "tests": ["src/app.py"]},
        "gates": [
            {"id": "lint", "depends_on": [], "side_effects": False, "proof": None},
            {
                "id": "tests",
                "depends_on": ["lint"],
                "side_effects": False,
                "proof": None,
            },
        ],
    }
    value.update(overrides)
    return value


def test_unknown_closure_fails_closed_to_run_and_preserves_topological_order():
    result = plan_incremental(
        __import__("pathlib").Path.cwd(),
        _manifest(dependency_closure={"lint": ["src/app.py"]}),
    )
    assert result["order"] == ["lint", "tests"]
    assert result["findings"]["tests"]["disposition"] == "RUN"
    assert result["findings"]["tests"]["reason"] == "PROOF_RELEVANCE_FAIL_CLOSED"
    assert result["authority"] == "none"


def test_changed_dependency_closure_forces_run_even_with_reusable_proof():
    manifest = _manifest(
        gates=[
            {
                "id": "lint",
                "depends_on": [],
                "side_effects": False,
                "proof": {"assurance_level": "isolated_worker"},
            }
        ],
        dependency_closure={"lint": ["src/app.py"]},
    )
    result = plan_incremental(__import__("pathlib").Path.cwd(), manifest)
    assert result["findings"]["lint"]["disposition"] == "RUN"
    assert result["findings"]["lint"]["reason"] == "DEPENDENCY_CLOSURE_CHANGED"


def test_side_effect_block_propagates_to_dependents():
    manifest = _manifest(
        gates=[
            {"id": "lint", "depends_on": [], "side_effects": True, "proof": None},
            {
                "id": "tests",
                "depends_on": ["lint"],
                "side_effects": False,
                "proof": None,
            },
        ]
    )
    result = plan_incremental(__import__("pathlib").Path.cwd(), manifest)
    assert result["findings"]["lint"]["disposition"] == "BLOCK"
    assert result["findings"]["lint"]["reason"] == "PROOF_SIDE_EFFECT_REUSE_REFUSED"
    assert result["findings"]["tests"]["disposition"] == "BLOCK"
    assert result["findings"]["tests"]["reason"] == "SCHEDULER_DEPENDENCY_BLOCKED"


def test_cycle_and_unsafe_path_are_rejected():
    cyclic = _manifest(
        gates=[
            {"id": "a", "depends_on": ["b"], "side_effects": False, "proof": None},
            {"id": "b", "depends_on": ["a"], "side_effects": False, "proof": None},
        ],
        dependency_closure={"a": ["src/app.py"], "b": ["src/app.py"]},
    )
    with pytest.raises(SchedulerError, match="E_SCHEDULE_CYCLE"):
        plan_incremental(__import__("pathlib").Path.cwd(), cyclic)
    with pytest.raises(SchedulerError, match="unsafe path"):
        validate_schedule_manifest(_manifest(changed_paths=["../secrets.txt"]))
    with pytest.raises(SchedulerError, match="unsafe path"):
        validate_schedule_manifest(_manifest(changed_paths=[".."]))
    with pytest.raises(SchedulerError, match="unsafe path"):
        validate_schedule_manifest(_manifest(changed_paths=["C:\\secrets.txt"]))


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("src/app.py", "src", True),
        ("src/app.py", "src/app.py", True),
        ("src/app.py", "src/apply.py", False),
        ("Src\\App.py", "src", True),
        (".factory/receipts/run.json", ".factory/receipts", True),
        ("./.factory/run.json", "factory/run.json", False),
        ("", "src", False),
    ],
)
def test_paths_intersect_is_conservative_and_segment_aware(
    left: str, right: str, expected: bool
):
    assert paths_intersect(left, right) is expected


def test_shadow_comparison_exposes_differences_without_authority():
    incremental = {
        "assurance_level": "isolated_worker",
        "obligations": ["lint"],
        "findings": {"lint": {"disposition": "RUN"}},
    }
    full = {
        "assurance_level": "isolated_worker",
        "obligations": ["lint"],
        "findings": {"lint": {"disposition": "RUN"}},
    }
    assert compare_shadow(incremental, full)["shadow_equivalent"] is True
    full["findings"]["lint"]["disposition"] = "BLOCK"
    result = compare_shadow(incremental, full)
    assert result["shadow_equivalent"] is False
    assert "lint" in result["differences"]["findings_changed"]
    assert result["release_approval"] is False


def test_incremental_plan_batches_duplicate_proof_names_without_persistence(
    tmp_path, monkeypatch
):
    import factoryline.incremental_scheduler as scheduler
    import factoryline.proof_reuse as proof_reuse

    source = tmp_path / "src" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_text("print('ok')\n", encoding="utf-8")
    outputs = []
    proofs = []
    for index in range(2):
        output = tmp_path / "dist" / f"result-{index}.json"
        output.parent.mkdir(exist_ok=True)
        output.write_text('{"passed":true}\n', encoding="utf-8")
        outputs.append(output)
        proof = {
            "name": "same-proof-name",
            "command": ["python", "-m", f"check{index}"],
            "inputs": ["src/app.py"],
            "outputs": [output.relative_to(tmp_path).as_posix()],
            "relevant_paths": ["src"],
            "safe_to_skip": False,
            "read_only": True,
            "toolchain": {"python": "3.11.9"},
            "environment": {"os": "windows"},
        }
        record_proof(tmp_path, proof, elapsed_ms=1000)
        proofs.append(proof)

    manifest = _manifest(
        changed_paths=["docs/readme.md"],
        gates=[
            {
                "id": f"gate-{index}",
                "depends_on": [],
                "side_effects": False,
                "proof": proof,
            }
            for index, proof in enumerate(proofs)
        ],
        dependency_closure={f"gate-{index}": ["src/app.py"] for index in range(2)},
    )
    original_evaluate = scheduler.evaluate_proofs
    calls = []

    def count_batch(*args, **kwargs):
        calls.append(len(args[1]["gates"]))
        return original_evaluate(*args, **kwargs)

    writes = 0
    original_atomic = proof_reuse._atomic_json

    def count_atomic(*args, **kwargs):
        nonlocal writes
        writes += 1
        return original_atomic(*args, **kwargs)

    monkeypatch.setattr(scheduler, "evaluate_proofs", count_batch)
    monkeypatch.setattr(proof_reuse, "_atomic_json", count_atomic)
    monkeypatch.setattr(
        "tempfile.TemporaryDirectory",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("temp directory")),
    )
    destination = tmp_path / "incremental-plan.json"
    result = plan_incremental(tmp_path, manifest, out=destination)

    assert calls == [2]
    assert writes == 0
    assert destination.is_file()
    assert not (tmp_path / ".factory" / "proof-plans").exists()
    assert [row["disposition"] for row in result["items"]] == ["REUSE", "REUSE"]
    for row, proof in zip(result["items"], proofs, strict=True):
        single = evaluate_proofs(
            tmp_path,
            {"schema": "factory.proof-request.v1", "gates": [proof]},
            changed_paths=["docs/readme.md"],
        )["items"][0]
        assert row["proof"] == {
            "proof_key": single["proof_key"],
            "receipt_sha256": single["receipt_sha256"],
        }
        assert row["reason"] == single["reason"]


"""Immutable native scope indexes reuse traversal without accepting rebinding."""


def test_scope_write_index_is_shared_across_names(tmp_path, monkeypatch):
    graph = _json_enum_graph(tmp_path)
    scope = graph.functions[tmp_path.resolve() / "test_api.py", "test_invalid_password"]
    graph.assignment_cache.clear()
    calls = []
    original = graph._walk

    def observed(node):
        if node is scope:
            calls.append(node)
        yield from original(node)

    monkeypatch.setattr(graph, "_walk", observed)
    response = graph._unique_name_assignment(scope, "response")
    data = graph._unique_name_assignment(scope, "data")
    assert isinstance(response, ast.Assign)
    assert isinstance(data, ast.Assign)
    assert graph._unique_name_assignment(scope, "response") is response
    assert graph._unique_name_assignment(scope, "missing") is None
    assert len(calls) == 1


def test_scope_index_retains_later_rebinding_veto(tmp_path):
    graph = _json_enum_graph(
        tmp_path, test_source=_JSON_TEST + "    response = supplied\n"
    )
    scope = graph.functions[tmp_path.resolve() / "test_api.py", "test_invalid_password"]
    assert graph._unique_name_assignment(scope, "response") is None
    assert not graph.witnesses()


TARGETS = {
    "factoryline/codex_metadata.py": {"audit_metadata"},
    "factoryline/oracle_firewall.py": {
        "seal_oracle_contract",
        "compile_oracle_challenge",
        "validate_oracle_challenge_plan",
        "verify_oracle_challenge_result",
        "record_oracle_incident",
    },
}
BRANCHES = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.IfExp,
    ast.comprehension,
    ast.ExceptHandler,
    ast.Match,
)


def test_public_oracle_coordinators_stay_within_ten_branches() -> None:
    found = set()
    for filename, names in TARGETS.items():
        tree = ast.parse(Path(filename).read_text(encoding="utf-8"), filename=filename)
        for node in tree.body:
            if (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name in names
            ):
                found.add(node.name)
                assert (
                    sum(isinstance(item, BRANCHES) for item in ast.walk(node)) <= 10
                ), node.name
    assert found == set().union(*TARGETS.values())


def test_a2a_validators_stay_within_forgeline_complexity_limit() -> None:
    """Preserve the measured refactor, including its extracted validators."""
    tree = ast.parse(Path("factoryline/agentic_control.py").read_text(encoding="utf-8"))
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and (node.name.startswith("_a2a_") or node.name == "audit_a2a_agent_card")
    ]
    assert len(functions) == 14
    for node in functions:
        complexity = 1
        for child in ast.walk(node):
            if isinstance(
                child,
                (
                    ast.If,
                    ast.For,
                    ast.While,
                    ast.ExceptHandler,
                    ast.With,
                    ast.Assert,
                    ast.IfExp,
                ),
            ):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        assert complexity <= 10, (node.name, complexity)


"""Host overrides must remain visible to the real type-intent policy."""


@pytest.fixture
def isolated_host(tmp_path, monkeypatch):
    for name in ("HOME", "USERPROFILE", "APPDATA", "XDG_CONFIG_HOME", "ProgramFiles"):
        directory = tmp_path / name.lower()
        directory.mkdir()
        monkeypatch.setenv(name, str(directory))
    for name in (
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
        "TY_CONFIG_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


@pytest.mark.parametrize(
    "name",
    [
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
    ],
)
def test_git_environment_override_still_vetoes_type_credit(
    isolated_host, monkeypatch, name
):
    monkeypatch.setenv(name, "1")
    state, safe = intent_quality._ty_global_git_configuration(65536)
    assert safe is False
    assert state["state"] == "environment_override"


@pytest.mark.parametrize(
    "relative", ["userprofile/.gitconfig", "xdg_config_home/git/config"]
)
@pytest.mark.parametrize(
    "content", ["[include]\npath = external\n", "[core]\nexcludesFile = external\n"]
)
def test_host_git_file_still_vetoes_type_credit(isolated_host, relative, content):
    # Path.home uses USERPROFILE on Windows and HOME on POSIX.
    from pathlib import Path

    target = isolated_host / relative
    if relative == "userprofile/.gitconfig":
        target = Path.home() / ".gitconfig"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    state, safe = intent_quality._ty_global_git_configuration(65536)
    assert safe is False
    assert state["state"] in {"include", "global_ignore_configured"}


def test_host_ty_configuration_still_vetoes_type_credit(isolated_host):
    config = isolated_host / "appdata/ty/ty.toml"
    config.parent.mkdir()
    config.write_text("[src]\nexclude = ['tests']\n", encoding="utf-8")
    assert intent_quality._ty_external_config_state(isolated_host) == {
        "state": "unknown",
        "config_override": True,
    }


"""Unknown-oracle guidance remains advisory and does not change detection."""


def test_unknown_callback_includes_existing_native_probe_guidance(tmp_path):
    (tmp_path / "test_case.py").write_text(
        "def test_behavior(runner):\n"
        "    def check():\n"
        "        assert compute() == 42\n"
        "    runner.callback = check\n",
        encoding="utf-8",
    )
    report = audit.security_scan(tmp_path, cache_enabled=False)
    finding = next(
        f for f in report["findings"] if f["code"] == "QUALITY_UNKNOWN_TEST_ORACLE"
    )
    assert finding["severity"] == "INFO"
    assert finding["facts"]["state"] == "INCOMPLETE"
    probe = finding["facts"]["native_assertion_probe"]
    assert probe["assertion_lines"] == [3]
    assert probe["nodeid_hint"] == "test_case.py::test_behavior"
    assert probe["exact_collection_id_required"] is True
    assert probe["call_available"] is False
    assert "never started by a static scan" in probe["execution"]


def test_unknown_call_probe_does_not_execute_target_and_cache_preserves_guidance(
    tmp_path,
):
    (tmp_path / "test_case.py").write_text(
        "from pathlib import Path\n"
        "Path('scanner-ran-source').write_text('unexpected')\n"
        "def test_behavior():\n"
        "    callback()\n"
        "    pass\n"
        "def callback():\n"
        "    opaque_operation()\n",
        encoding="utf-8",
    )
    cold = audit.security_scan(tmp_path)
    warm = audit.security_scan(tmp_path)
    assert cold["findings"] == warm["findings"]
    finding = next(
        f for f in cold["findings"] if f["code"] == "QUALITY_UNKNOWN_TEST_ORACLE"
    )
    probe = finding["facts"]["native_assertion_probe"]
    assert probe["call_lines"] == [4]
    assert probe["call_available"] is True
    assert "<exact collected pytest node ID>" in probe["call_command"]
    assert not (tmp_path / "scanner-ran-source").exists()


@pytest.mark.parametrize(
    "source",
    [
        "def test_behavior():\n    def check():\n        assert compute() == 42\n    pass\n",
        "def callback():\n    pass\ndef test_behavior():\n    callback()\n",
    ],
)
def test_proven_inert_bodies_are_not_unknown_guidance_fixtures(tmp_path, source):
    (tmp_path / "test_case.py").write_text(source, encoding="utf-8")
    report = audit.security_scan(tmp_path, cache_enabled=False)
    assert report["finding_counts"] == {"QUALITY_HOLLOW_TEST": 1}
    assert report["findings"][0]["severity"] == "MEDIUM"


def _application_import_binding(signature, asynchronous, attribute):
    """Build a hash-bound source slice without importing the synthetic provider."""
    import hashlib
    from factoryline import mock_fixture_provenance as fixtures

    statement = (
        "import provider as client"
        if attribute
        else "from provider import api as client"
    )
    expression = "client.api" if attribute else "client"
    source = (
        f"{statement}\n{'async ' if asynchronous else ''}def exercise({signature}):\n"
        f"    return {expression}()\n"
    ).encode()
    path, tree = Path("repository/test_api.py"), ast.parse(source)
    digest = hashlib.sha256(source).hexdigest()
    tree._oracle_source_sha256 = digest
    index = fixtures.application_test_index(
        Path("repository"), {path: tree}, {path: source}, {path: digest}
    )
    function = tree.body[1]
    expression = function.body[0].value.func
    return fixtures._app_expression_name(index, path, expression, function)


@pytest.mark.parametrize(
    "signature", ["client", "client, /", "*, client", "*client", "**client"]
)
@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("attribute", [False, True])
def test_application_provider_import_is_not_a_shadowing_parameter(
    signature, asynchronous, attribute
):
    assert _application_import_binding(signature, asynchronous, attribute) is None


@pytest.mark.parametrize("signature", ["", "*other", "**other", "*, other=None"])
@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("attribute", [False, True])
def test_application_provider_import_survives_unrelated_parameters(
    signature, asynchronous, attribute
):
    assert (
        _application_import_binding(signature, asynchronous, attribute)
        == "provider.api"
    )


@pytest.mark.parametrize("mutation", ["binding", "code"])
def test_application_parameter_helper_mutation_invalidates_native_context(
    tmp_path, monkeypatch, mutation
):
    from factoryline import credential_role_identity_effects as effects

    before = audit._oracle_context_cache_key(tmp_path, [], {})

    def unsafe_names(function):
        return set()

    if mutation == "binding":
        monkeypatch.setattr(effects, "_argument_names", unsafe_names)
    else:
        monkeypatch.setattr(effects._argument_names, "__code__", unsafe_names.__code__)
    assert audit._oracle_context_cache_key(tmp_path, [], {}) != before
