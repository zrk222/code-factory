import pytest
from factoryline.runtime_audit import evaluate_runtime_audit
from factoryline.runtime_audit_integrity import index_executions, repair_guidance
from factoryline.runtime_audit_common import RuntimeAuditError
from test_runtime_audit import _plan, _command
import ast
from factoryline.runtime_audit_integrity import closed_declaration_input_witness
from factoryline.runtime_audit_integrity import finite_literal_eval_input_witness
from factoryline.runtime_audit_integrity import source_generated_eval_input_witness


@pytest.mark.parametrize(
    "mutation", ["duplicate", "unknown", "kind", "malformed", "overflow"]
)
def test_ambiguous_join_is_rejected(tmp_path, mutation):
    lane = _plan()["lanes"][0]

    entry = {
        "id": lane["id"],
        "kind": lane["kind"],
        "target": _command(lane["kind"]),
        "known_bad": _command(lane["kind"], True),
    }

    rows = [entry]

    if mutation == "duplicate":
        rows.append(dict(entry))

    elif mutation == "unknown":
        entry["id"] = "unapproved"

    elif mutation == "kind":
        entry["kind"] = "tenant_isolation"

    elif mutation == "malformed":
        rows.append(None)

    else:
        rows *= 7

    with pytest.raises(RuntimeAuditError) as error:
        evaluate_runtime_audit(_plan(), {"executions": rows}, tmp_path)

    assert error.value.code == "E_AUDIT_EXECUTION_SET"


def test_missing_evidence_stays_incomplete(tmp_path):
    result = evaluate_runtime_audit(_plan(), {"executions": []}, tmp_path)

    assert result["decision"] == "BLOCKED"

    assert all(
        lane["repair_guidance"]["repair_target"] == "audit_evidence"
        for lane in result["lanes"]
    )


@pytest.mark.parametrize("lane", _plan()["lanes"])
def test_all_six_lanes_get_exact_replay_and_no_authority(lane):
    result = repair_guidance({"state": "FAIL", "finding": "REAL_DEFECT"}, lane)

    assert result["repair_target"] == "application_behavior"

    assert result["negative_argv"] == lane["known_bad_argv"]

    assert result["expected_negative_code"] == lane["expected_negative_code"]

    assert result["authority"] == "none"

    assert (
        repair_guidance({"state": "FAIL", "finding": "HOLLOW_RUNTIME_AUDIT"}, lane)[
            "repair_target"
        ]
        == "audit_evidence"
    )


def test_duplicate_plan_lane_cannot_claim_six_lane_coverage():
    plan = _plan()

    plan["lanes"][-1] = plan["lanes"][0]

    with pytest.raises(RuntimeAuditError):
        index_executions(plan, {"executions": []})


def _witness(source, source_bytes=None):
    tree = ast.parse(source)
    source_bytes = source.encode("utf-8") if source_bytes is None else source_bytes
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "exec"
        and len(node.args) == 3
    ]
    assert len(calls) == 1
    return closed_declaration_input_witness(
        calls[0],
        "exec",
        source_bytes=source_bytes,
        source_path="case.py",
    )


def test_closed_declaration_input_witness_accepts_exact_alias_declaration():
    witness = _witness(
        "def run():\n    ctx = {}\n    exec('type Alias = int', ctx, None)\n"
    )

    assert witness["schema"] == "factory.closed-declaration-input.v1"
    assert witness["disposition"] == "PROVEN_CLOSED_DECLARATION_INPUT"


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int\\nmarker = 1', ctx, None)\n",
            id="extra-statement",
        ),
        pytest.param(
            "def run():\n    ctx = {}\n    exec('type Alias = int\\n', ctx, None)\n",
            id="newline-in-input",
        ),
        pytest.param(
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias[T] = list[T]', ctx, None)\n",
            id="type-parameters",
        ),
        pytest.param(
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = build_type()', ctx, None)\n",
            id="computed-rhs",
        ),
        pytest.param(
            "def run(custom_ctx):\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', custom_ctx, None)\n",
            id="custom-namespace",
        ),
        pytest.param(
            "def run():\n"
            "    ctx = {}\n"
            "    ctx['extra'] = 1\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="precall-context-mutation",
        ),
        pytest.param(
            "def run():\n"
            "    ctx = {}\n"
            "    retain(ctx)\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="context-escape",
        ),
        pytest.param(
            "def run():\n"
            "    exec = replacement\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="shadowed-exec",
        ),
        pytest.param(
            "__builtins__['exec'] = replacement\n"
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="builtins-exec-mutation",
        ),
        pytest.param(
            "import builtins\n"
            "builtins.__dict__['exec'] = replacement\n"
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="builtins-dict-exec-mutation",
        ),
        pytest.param(
            "import builtins\n"
            "mutate = setattr\n"
            "mutate(builtins, 'exec', replacement)\n"
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="builtins-exec-mutated-through-setter-alias",
        ),
        pytest.param(
            "import builtins\n"
            "builtins.__setattr__('exec', replacement)\n"
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="builtins-exec-mutated-through-module-setattr",
        ),
        pytest.param(
            "from builtins import setattr as mutate\n"
            "import builtins\n"
            "mutate(builtins, 'exec', replacement)\n"
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="imported-setattr-mutates-builtins-exec",
        ),
        pytest.param(
            "from builtins import __dict__ as namespace\n"
            "namespace['exec'] = replacement\n"
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="imported-builtins-dict-mutates-exec",
        ),
        pytest.param(
            "exec('exec = replacement')\n"
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="exec-rebinds-exec-before-candidate",
        ),
        pytest.param(
            "from builtins import exec as rewrite\n"
            "rewrite('exec = replacement')\n"
            "def run():\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="imported-exec-rebinds-exec-before-candidate",
        ),
        pytest.param(
            "def run(value):\n"
            "    match value:\n"
            "        case exec:\n"
            "            pass\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="match-capture-binds-exec",
        ),
        pytest.param(
            "def run(value):\n"
            "    match value:\n"
            "        case ctx:\n"
            "            pass\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="match-capture-binds-namespace",
        ),
        pytest.param(
            "def run():\n"
            "    import math as ctx\n"
            "    ctx = {}\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="import-binds-namespace",
        ),
        pytest.param(
            "def run():\n"
            "    ctx = {}\n"
            "    try:\n"
            "        raise ValueError\n"
            "    except Exception as ctx:\n"
            "        pass\n"
            "    exec('type Alias = int', ctx, None)\n",
            id="except-binds-namespace",
        ),
        pytest.param(
            "def run(source):\n    ctx = {}\n    exec(source, ctx, None)\n",
            id="nonliteral-input",
        ),
        pytest.param(
            "def run():\n    ctx = {}\n    exec('type __Alias = int', ctx, None)\n",
            id="dunder-identifier",
        ),
    ],
)
def test_closed_declaration_input_witness_rejects_unproven_variants(source):
    assert _witness(source) == {}


def test_closed_declaration_input_witness_rejects_stale_source_bytes():
    source = "def run():\n    ctx = {}\n    exec('type Alias = int', ctx, None)\n"
    changed = source.replace("type Alias = int", "type Alias = str")

    assert _witness(source, changed.encode("utf-8")) == {}


def test_security_scan_keeps_declaration_exec_as_hash_bound_incomplete_observation(
    tmp_path,
):
    import copy
    import hashlib

    from factoryline.review_integrity import partition_proven_primitive_observations
    from factoryline.review_audits import security_scan

    source = "def run():\n    ctx = {}\n    exec('type Alias = int', ctx, None)\n"
    source_path = tmp_path / "app.py"
    source_path.write_text(source, encoding="utf-8")

    report = security_scan(tmp_path, cache_enabled=False)
    finding = next(
        row
        for row in report["primitive_observations"]
        if row["code"] == "SECURITY_DYNAMIC_EXECUTION"
    )

    assert finding["severity"] == "INFO"
    assert finding["facts"]["schema"] == "factory.closed-declaration-input.v1"
    assert finding["facts"]["disposition"] == "PROVEN_CLOSED_DECLARATION_INPUT"
    assert finding["facts"]["runtime_assurance"] == "INCOMPLETE"
    assert (
        finding["facts"]["source_sha256"]
        == hashlib.sha256(source_path.read_bytes()).hexdigest()
    )

    for mutate in (
        lambda facts: facts.__setitem__("source_sha256", "0" * 64),
        lambda facts: facts.__setitem__(
            "literal_span",
            [
                facts["call_span"][2],
                facts["call_span"][3] + 1,
                facts["call_span"][2],
                facts["call_span"][3] + 2,
            ],
        ),
    ):
        tampered = copy.deepcopy(report)
        tampered_finding = tampered["primitive_observations"][0]
        mutate(tampered_finding["facts"])
        partition_proven_primitive_observations(tampered)

        assert tampered["primitive_observations"] == []
        rejected = tampered["findings"][0]
        assert rejected["severity"] == "HIGH"
        assert rejected["facts"]["disposition"] == "UNVERIFIED_FIXED_PROGRAM"
        assert rejected["facts"]["proof_rejection"] == "SOURCE_BINDING_MISMATCH"


SOURCE = 'types = [(eval(tp), expected) for tp, expected in [("list[Person]", True), ("tuple[Person, ...]", False)]]\n'


def witness(source, raw=None):
    tree = ast.parse(source)
    call = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "eval"
    )
    return finite_literal_eval_input_witness(
        call, "eval", source_bytes=raw or source.encode(), source_path="case.py"
    )


def test_finite_eval_literal_domain_records_input_only():
    facts = witness(SOURCE)
    assert facts["domain_size"] == 2
    assert facts["runtime_assurance"] == "INCOMPLETE"
    assert facts["target_execution"] == "not_performed"


@pytest.mark.parametrize(
    "source",
    [
        SOURCE.replace('"list[Person]"', "payload"),
        SOURCE.replace('"list[Person]"', '"factory()"'),
        SOURCE.replace('"list[Person]"', '"Person.attr"'),
        SOURCE.replace(
            "for tp, expected in", "for tp, expected in supplied for unused in"
        ),
        SOURCE.replace("eval(tp)", "eval(tp, supplied)"),
        SOURCE.replace("eval(tp)", "eval((tp := supplied))"),
        SOURCE.replace("eval(tp)", "eval(tp + supplied)"),
        SOURCE.replace("eval(tp)", "eval(tp) if expected else expose(tp)"),
        "eval = replacement\n" + SOURCE,
        'from builtins import exec as rewrite\nrewrite("eval = replacement")\n'
        + SOURCE,
        SOURCE.replace('"list[Person]"', '"[x for x in source]"'),
        SOURCE.replace('[("list[Person]", True), ("tuple[Person, ...]", False)]', "[]"),
    ],
)
def test_finite_eval_rejects_open_or_executable_inputs(source):
    assert witness(source) == {}


def test_finite_eval_rejects_stale_ast():
    assert witness(SOURCE, SOURCE.replace("eval(tp)", "eval(other)").encode()) == {}


def test_finite_eval_recomputes_changed_domain_from_current_bytes():
    old = witness(SOURCE)
    new = witness(SOURCE, SOURCE.replace("Person", "Other").encode())
    assert old["source_sha256"] != new["source_sha256"]
    assert old["program_sha256"] != new["program_sha256"]


def test_finite_eval_ignores_later_uninvoked_function_effects():
    assert (
        witness(SOURCE + '\ndef later():\n    delattr(NoParams, "__parameters__")\n')[
            "domain_size"
        ]
        == 2
    )


def test_finite_eval_rejects_prior_function_invocation():
    source = 'def rewrite():\n    globals()["eval"] = replacement\nrewrite()\n' + SOURCE
    assert witness(source) == {}


def test_finite_eval_native_scan_retains_primitive(tmp_path):
    from factoryline.review_audits import security_scan

    (tmp_path / "app.py").write_text(SOURCE)
    report = security_scan(tmp_path, cache_enabled=False)
    assert not report["findings"]
    assert (
        report["primitive_observations"][0]["facts"]["disposition"]
        == "PROVEN_FINITE_LITERAL_EVAL_INPUT"
    )


@pytest.mark.parametrize(
    "source",
    [
        'types = [(lambda tp: eval(tp)) for tp, expected in [("list[Person]", True)]]\n',
        "from arbitrary import eval\n" + SOURCE,
        "from arbitrary import replacement as eval\n" + SOURCE,
        SOURCE.replace('"list[Person]", True', '"list[Person]", rewrite()'),
    ],
)
def test_finite_eval_rejects_shadowed_or_effectful_table(source):
    assert witness(source) == {}


def test_finite_eval_partition_rejects_unrelated_domain_span(tmp_path):
    from factoryline.review_audits import security_scan
    from factoryline.review_integrity import partition_proven_primitive_observations

    (tmp_path / "app.py").write_text(SOURCE)
    report = security_scan(tmp_path, cache_enabled=False)
    report["primitive_observations"][0]["facts"]["domain_span"] = [999, 0, 999, 1]
    partition_proven_primitive_observations(report)
    assert not report["primitive_observations"]
    assert report["findings"][0]["severity"] == "HIGH"


_SOURCE_GENERATED_TEMPLATE = """from sqlalchemy import Index
from sqlalchemy import text

def build(config):
    return [
        (
            eval(f'lambda t: Index("idx", text({conn!r}), _table=t)'),
            eval(f'lambda t: Index("idx", text({meta!r}), _table=t)'),
            config.requirements.reflects_indexes_column_sorting,
        )
        for meta, conn in __DOMAIN__
    ]
"""
_SOURCE_GENERATED_ROWS = """(
    ("z nulls first", "z nulls first"),
    ("z nulls last", "z"),
)"""
_SOURCE_GENERATED = _SOURCE_GENERATED_TEMPLATE.replace(
    "__DOMAIN__", _SOURCE_GENERATED_ROWS
)


def _source_generated_facts(source=_SOURCE_GENERATED, *, identity=True):
    tree = ast.parse(source)
    calls = [
        item
        for item in ast.walk(tree)
        if isinstance(item, ast.Call)
        and isinstance(item.func, ast.Name)
        and item.func.id == "eval"
    ]
    return [
        source_generated_eval_input_witness(
            call,
            "eval",
            source_bytes=source.encode(),
            source_path="tests/test_autogen_indexes.py",
            builtin_identity_proven=identity,
        )
        for call in calls
    ]


def test_source_generated_eval_proves_bounded_literal_rows_only():
    facts = _source_generated_facts()
    assert len(facts) == 2
    assert all(item["domain_size"] == 2 for item in facts)
    assert all(
        item["scope_profile"] == "single-comprehension-source-template"
        and item["input_effect"] == "CLOSED_SOURCE_GENERATED_STRINGS"
        and item["runtime_assurance"] == "INCOMPLETE"
        and item["target_execution"] == "not_performed"
        for item in facts
    )
    assert len({item["program_sha256"] for item in facts}) == 2
    assert _source_generated_facts(identity=False) == [{}, {}]


def test_source_generated_eval_obeys_domain_and_rendered_byte_caps():
    domain_overflow = (
        "(" + ",".join(f'("meta-{index}", "conn-{index}")' for index in range(65)) + ")"
    )
    value = "x" * 1100
    rendered_byte_overflow = (
        "(" + ",".join(f"({value!r}, {value!r})" for _ in range(9)) + ")"
    )
    assert _source_generated_facts(
        _SOURCE_GENERATED_TEMPLATE.replace("__DOMAIN__", domain_overflow)
    ) == [{}, {}]
    assert _source_generated_facts(
        _SOURCE_GENERATED_TEMPLATE.replace("__DOMAIN__", rendered_byte_overflow)
    ) == [{}, {}]


@pytest.mark.parametrize(
    "source",
    [
        _SOURCE_GENERATED_TEMPLATE.replace("__DOMAIN__", "supplied_rows"),
        _SOURCE_GENERATED_TEMPLATE.replace(
            "__DOMAIN__", "(" + _SOURCE_GENERATED_ROWS + " if config.enabled else ())"
        ),
        _SOURCE_GENERATED_TEMPLATE.replace(
            "__DOMAIN__", '((provider(), "z"), ("meta", "conn"))'
        ),
        _SOURCE_GENERATED.replace("{conn!r}", "{config.value!r}"),
        _SOURCE_GENERATED.replace("{conn!r}", "{(conn := config.value)!r}"),
    ],
)
def test_source_generated_eval_rejects_alias_branch_provider_and_external_values(
    source,
):
    assert _source_generated_facts(source) == [{}, {}]


def test_source_generated_eval_native_scan_keeps_builtin_alias_high(tmp_path):
    from factoryline.review_audits import security_scan

    (tmp_path / "app.py").write_text("eval = replacement\n" + _SOURCE_GENERATED)
    report = security_scan(tmp_path, cache_enabled=False)
    assert report.get("primitive_observations", []) == []
    assert len(report["findings"]) == 2
    assert all(item["severity"] == "HIGH" for item in report["findings"])


def test_source_generated_eval_native_scan_partitions_both_closed_calls(tmp_path):
    from factoryline.review_audits import security_scan

    (tmp_path / "app.py").write_text(_SOURCE_GENERATED)
    report = security_scan(tmp_path, cache_enabled=False)
    assert not report["findings"]
    assert len(report["primitive_observations"]) == 2
    assert all(
        item["facts"]["disposition"] == "PROVEN_FINITE_LITERAL_EVAL_INPUT"
        and item["facts"]["input_effect"] == "CLOSED_SOURCE_GENERATED_STRINGS"
        for item in report["primitive_observations"]
    )


def test_source_generated_eval_partition_rejects_tampered_effect(tmp_path):
    from factoryline.review_audits import security_scan
    from factoryline.review_integrity import partition_proven_primitive_observations

    (tmp_path / "app.py").write_text(_SOURCE_GENERATED)
    report = security_scan(tmp_path, cache_enabled=False)
    for item in report["primitive_observations"]:
        item["facts"]["input_effect"] = "USER_CONTROLLED"
    partition_proven_primitive_observations(report)
    assert report["primitive_observations"] == []
    assert len(report["findings"]) == 2
    assert all(item["severity"] == "HIGH" for item in report["findings"])


_JSON_ENUM = """from enum import Enum
class ErrorCode(str, Enum):
    REGISTER_INVALID_PASSWORD = "REGISTER_INVALID_PASSWORD"
"""
_JSON_CLIENT = """import pytest
import httpx
from asgi_lifespan import LifespanManager
@pytest.fixture
def get_test_client():
    async def make_client(app):
        async with LifespanManager(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
                yield client
    return make_client
"""
_JSON_TEST = """from typing import Any, cast
import pytest_asyncio
from fastapi import FastAPI
from common import ErrorCode
@pytest_asyncio.fixture
async def app_client(get_test_client):
    app = FastAPI()
    async for client in get_test_client(app):
        yield client
async def test_invalid_password(app_client):
    response = await app_client.post("/register", json={})
    assert response.status_code == 400
    data = cast(dict[str, Any], response.json())
    assert data["detail"] == {"code": ErrorCode.REGISTER_INVALID_PASSWORD}
"""


def _json_enum_graph(
    tmp_path,
    *,
    test_source=_JSON_TEST,
    client_source=_JSON_CLIENT,
    enum_source=_JSON_ENUM,
    extra_sources=None,
    reverse_sources=False,
    stale=False,
):
    import hashlib
    from factoryline import review_audits, review_integrity
    from factoryline.runtime_audit_integrity import _LiteralConsumers

    root = tmp_path.resolve()
    root.mkdir(parents=True, exist_ok=True)
    sources = {
        "common.py": enum_source,
        "conftest.py": client_source,
        "test_api.py": test_source,
    }
    sources.update(extra_sources or {})
    if reverse_sources:
        sources = dict(reversed(tuple(sources.items())))
    raw = {root / name: source.encode() for name, source in sources.items()}
    for path, source in raw.items():
        path.write_bytes(source)
    trees = {path: ast.parse(source) for path, source in raw.items()}
    inventory = {
        path: hashlib.sha256(source).hexdigest() for path, source in raw.items()
    }
    for path, tree in trees.items():
        tree._oracle_source_sha256 = inventory[path]
    eligible = {path.resolve(): path for path in trees}
    imports = {
        path: review_audits._oracle_imports(root, path, tree, eligible)
        for path, tree in trees.items()
    }
    if stale:
        inventory[root / "common.py"] = "0" * 64
    return _LiteralConsumers(
        root,
        trees,
        imports,
        review_audits,
        review_integrity,
        source_bytes=raw,
        inventory=inventory,
    )


def test_public_enum_json_requires_actual_client_origin(tmp_path):
    graph = _json_enum_graph(tmp_path)
    result = graph.witnesses()
    assert graph.complete
    assert (tmp_path.resolve() / "common.py", 3, "REGISTER_INVALID_PASSWORD") in result


def test_provider_mutation_index_precedes_fixture_decisions(tmp_path):
    fixture = (
        "import pytest\n"
        "@pytest.fixture\ndef client(): pass\n"
        "def test_client(client): pass\n"
    )
    mutations = (
        "import pytest\npytest.fixture = supplied\n",
        "import pytest as pt\npt = supplied\n",
        "import pytest\npytest.fixture.__code__ = supplied\n",
        "import pytest\npytest.fixture.nested.attribute = supplied\n",
    )
    for reverse in (False, True):
        for index, mutation in enumerate(mutations):
            case = tmp_path / f"case_{reverse}_{index}"
            graph = _json_enum_graph(
                case,
                extra_sources={"a_fixture.py": fixture, "z_mutation.py": mutation},
                reverse_sources=reverse,
            )
            assert not graph._provider_is_unmodified("pytest", {"fixture"})
            assert not graph.witnesses()


def test_public_enum_witness_is_snapshot_order_independent(tmp_path):
    graph = _json_enum_graph(tmp_path, reverse_sources=True)
    assert graph.complete
    assert (
        tmp_path.resolve() / "common.py",
        3,
        "REGISTER_INVALID_PASSWORD",
    ) in graph.witnesses()


def test_public_enum_json_accepts_scalar_detail_comparison(tmp_path):
    source = _JSON_TEST.replace(
        '{"code": ErrorCode.REGISTER_INVALID_PASSWORD}',
        "ErrorCode.REGISTER_INVALID_PASSWORD",
    )
    graph = _json_enum_graph(tmp_path, test_source=source)
    assert graph.complete
    assert (
        tmp_path.resolve() / "common.py",
        3,
        "REGISTER_INVALID_PASSWORD",
    ) in graph.witnesses()


def test_public_enum_scalar_json_retains_signing_consumer(tmp_path):
    source = _JSON_TEST.replace(
        '{"code": ErrorCode.REGISTER_INVALID_PASSWORD}',
        "ErrorCode.REGISTER_INVALID_PASSWORD",
    )
    enum_source = (
        _JSON_ENUM + "\nsigned = signer(ErrorCode.REGISTER_INVALID_PASSWORD)\n"
    )
    graph = _json_enum_graph(tmp_path, test_source=source, enum_source=enum_source)
    assert graph.complete
    assert not graph.witnesses()


def test_public_enum_scalar_json_rejects_custom_equality(tmp_path):
    source = _JSON_TEST.replace(
        '{"code": ErrorCode.REGISTER_INVALID_PASSWORD}',
        "ErrorCode.REGISTER_INVALID_PASSWORD",
    )
    enum_source = _JSON_ENUM + "    def __eq__(self, other):\n        return True\n"
    graph = _json_enum_graph(tmp_path, test_source=source, enum_source=enum_source)
    assert graph.complete
    assert not graph.witnesses()


@pytest.mark.parametrize(
    "mutation",
    [
        "    __eq__ = replacement\n",
        "\nErrorCode.__eq__ = replacement\n",
    ],
)
def test_public_enum_scalar_json_rejects_equality_binding_mutation(tmp_path, mutation):
    source = _JSON_TEST.replace(
        '{"code": ErrorCode.REGISTER_INVALID_PASSWORD}',
        "ErrorCode.REGISTER_INVALID_PASSWORD",
    )
    graph = _json_enum_graph(
        tmp_path, test_source=source, enum_source=_JSON_ENUM + mutation
    )
    assert graph.complete
    assert not graph.witnesses()


def test_public_enum_scalar_json_native_observation_is_source_bound(tmp_path):
    from factoryline.review_audits import security_scan

    source = _JSON_TEST.replace(
        '{"code": ErrorCode.REGISTER_INVALID_PASSWORD}',
        "ErrorCode.REGISTER_INVALID_PASSWORD",
    )
    _json_enum_graph(tmp_path, test_source=source)
    report = security_scan(tmp_path, cache_enabled=False)
    assert report["audit_coverage"]["complete"]
    assert not any(
        row["code"] == "SECURITY_HARDCODED_SECRET" for row in report["findings"]
    )
    observations = report.get("primitive_observations", [])
    assert len(observations) == 1
    assert (
        observations[0]["facts"]["disposition"] == "PROVEN_PUBLIC_SYMBOLIC_IDENTIFIER"
    )
    assert observations[0]["facts"]["runtime_assurance"] == "INCOMPLETE"


@pytest.mark.parametrize("escape", [None, "test_app", "schema"])
def test_returned_app_tracks_keyword_only_fixture_consumers(tmp_path, escape):
    source = _JSON_TEST.replace(
        "async def app_client(get_test_client):\n    app = FastAPI()",
        "def test_app():\n    app = FastAPI()\n    return app\n"
        "@pytest_asyncio.fixture\nasync def app_client(test_app, get_test_client):",
    ).replace("get_test_client(app):", "get_test_client(test_app):")
    source += (
        "\n@pytest_asyncio.fixture\ndef schema(test_app):\n    return test_app.openapi()\n"
        "def test_schema(schema):\n    route = schema['paths']['/register']['post']\n"
        "    assert list(route['responses'].keys()) == ['400']\n"
    )
    if escape:
        source += f"\ndef test_opaque(*, {escape}):\n    opaque({escape})\n"
    graph = _json_enum_graph(tmp_path, test_source=source)
    path = tmp_path.resolve() / "test_api.py"
    fixture = next(
        node
        for node in graph.trees[path].body
        if getattr(node, "name", None) == "test_app"
    )
    assert graph._returned_app_fixture_closed(path, fixture, "app") is (escape is None)


def test_public_enum_native_cold_warm_and_source_invalidation(tmp_path):
    from factoryline.review_audits import security_scan

    _json_enum_graph(tmp_path)
    for cache in (False, True, True):
        report = security_scan(tmp_path, cache_enabled=cache)
        assert not any(
            row["code"] == "SECURITY_HARDCODED_SECRET" for row in report["findings"]
        )
        observations = report.get("primitive_observations", [])
        assert len(observations) == 1
        assert (
            observations[0]["facts"]["disposition"]
            == "PROVEN_PUBLIC_SYMBOLIC_IDENTIFIER"
        )
        assert observations[0]["facts"]["runtime_assurance"] == "INCOMPLETE"
    with (tmp_path / "common.py").open("a") as stream:
        stream.write("signed = signer(ErrorCode.REGISTER_INVALID_PASSWORD)\n")
    report = security_scan(tmp_path, cache_enabled=True)
    assert any(row["code"] == "SECURITY_HARDCODED_SECRET" for row in report["findings"])
    assert not report.get("primitive_observations")


def test_public_enum_native_incomplete_source_denies_admission(tmp_path):
    from factoryline.review_audits import security_scan

    _json_enum_graph(tmp_path)
    (tmp_path / "missing_flow.py").write_text("def broken(:\n")
    report = security_scan(tmp_path, cache_enabled=False)
    assert any(row["code"] == "SECURITY_HARDCODED_SECRET" for row in report["findings"])
    assert not report.get("primitive_observations")


@pytest.mark.parametrize(
    "field,value",
    [
        ("declaration_span", [3, 4, 999, 1]),
        ("name", "OTHER_PASSWORD"),
        ("source_profiles", [{"invocation": "invented"}]),
    ],
)
def test_public_enum_receipt_rejects_changed_facts(tmp_path, field, value):
    from factoryline.review_audits import security_scan
    from factoryline.review_integrity import partition_proven_primitive_observations

    _json_enum_graph(tmp_path)
    report = security_scan(tmp_path, cache_enabled=False)
    report["primitive_observations"][0]["facts"][field] = value
    partition_proven_primitive_observations(report)
    assert not report["primitive_observations"]
    assert any(row["code"] == "SECURITY_HARDCODED_SECRET" for row in report["findings"])


@pytest.mark.parametrize(
    "mutation",
    [
        "signing",
        "client_rebind",
        "data_rebind",
        "json_replacement",
        "client_hooks",
        "provider_rebind",
        "stale_source",
        "client_import",
        "client_except",
        "client_match",
        "client_method",
        "client_escape",
        "response_escape",
        "class_fixture_override",
        "helper_rebind",
        "yield_client_escape",
        "response_setattr",
        "module_fixture_alias",
        "provider_fixture_alias",
        "local_httpx_shadow",
        "local_manager_shadow",
    ],
)
def test_public_enum_json_retains_unproven_consumers(tmp_path, mutation):
    source, client, enum = _JSON_TEST, _JSON_CLIENT, _JSON_ENUM
    source_replacements = {
        "client_rebind": (
            "    response =",
            "    app_client = replacement\n    response =",
        ),
        "data_rebind": ("    assert data[", "    data = replacement\n    assert data["),
        "json_replacement": (
            "    data =",
            "    response.json = replacement\n    data =",
        ),
        "helper_rebind": ("    app =", "    get_test_client = replacement\n    app ="),
        "yield_client_escape": (
            "        yield client",
            "        opaque(client)\n        yield client",
        ),
        "response_setattr": (
            "    data =",
            "    response.__setattr__('json', replacement)\n    data =",
        ),
    }
    client_replacements = {
        "client_hooks": (
            'base_url="http://test"',
            'base_url="http://test", event_hooks={"response": [replacement]}',
        ),
        "local_httpx_shadow": (
            "        async with",
            "        httpx = replacement\n        async with",
        ),
        "local_manager_shadow": (
            "    async def make_client",
            "    LifespanManager = replacement\n    async def make_client",
        ),
    }
    client += {
        "provider_rebind": "httpx.AsyncClient = replacement\n",
        "provider_fixture_alias": "\n@pytest.fixture(name='get_test_client')\ndef override():\n    return replacement\n",
    }.get(mutation, "")
    source += {
        "module_fixture_alias": "\n@pytest_asyncio.fixture(name='app_client')\nasync def override():\n    yield replacement\n"
    }.get(mutation, "")
    enum += {"signing": "signed = signer(ErrorCode.REGISTER_INVALID_PASSWORD)\n"}.get(
        mutation, ""
    )
    if mutation in source_replacements:
        source = source.replace(*source_replacements[mutation])
    elif mutation in client_replacements:
        client = client.replace(*client_replacements[mutation], 1)
    elif mutation in {
        "client_import",
        "client_except",
        "client_match",
        "client_method",
        "client_escape",
        "response_escape",
    }:
        statements = {
            "client_import": "    import arbitrary as app_client\n",
            "client_except": "    try:\n        pass\n    except Exception as app_client:\n        pass\n",
            "client_match": '    match replacement:\n        case {"client": app_client}:\n            pass\n',
            "client_method": "    app_client.post = replacement\n",
            "client_escape": "    opaque(app_client)\n",
            "response_escape": "    opaque(response)\n",
        }
        anchor = "    data =" if mutation == "response_escape" else "    response ="
        source = source.replace(anchor, statements[mutation] + anchor)
    elif mutation == "class_fixture_override":
        prefix, body = source.split("async def test_invalid_password", 1)
        override = (
            "class TestOverride:\n    @pytest_asyncio.fixture\n"
            "    async def app_client(self):\n        yield replacement\n"
        )
        method = "async def test_invalid_password" + body
        method = method.replace(
            "test_invalid_password(app_client)",
            "test_invalid_password(self, app_client)",
        )
        source = (
            prefix + override + "\n".join("    " + line for line in method.splitlines())
        )
    graph = _json_enum_graph(
        tmp_path,
        test_source=source,
        client_source=client,
        enum_source=enum,
        stale=mutation == "stale_source",
    )
    assert not graph.witnesses()
    if mutation != "stale_source":
        from factoryline.review_audits import security_scan

        report = security_scan(tmp_path, cache_enabled=False)
        assert any(
            row["code"] == "SECURITY_HARDCODED_SECRET" for row in report["findings"]
        )
        assert not report.get("primitive_observations")


@pytest.mark.parametrize(
    "target,domain",
    [
        ("value", "((1,),)"),
        ("(value,)", "(b'x',)"),
        ("(value,)", "('x',)"),
        ("(value,)", "(1,)"),
        ("(value,value)", "((1,2),)"),
    ],
)
def test_source_generated_eval_rejects_mismatched_unpacking(target, domain):
    source = f"items = [(eval(f'lambda: {{value!r}}'),) for {target} in {domain}]\n"
    assert _source_generated_facts(source) == [{}]


def test_source_generated_eval_receipt_hash_matches_exact_rendered_strings():
    import hashlib
    import json

    source = "items = [(eval(f'lambda: {value!r}'),) for value in ('a', 'b')]\n"
    facts = _source_generated_facts(source)[0]
    programs = ["lambda: 'a'", "lambda: 'b'"]
    assert (
        facts["program_sha256"]
        == hashlib.sha256(
            json.dumps(programs, separators=(",", ":")).encode()
        ).hexdigest()
    )


@pytest.mark.parametrize("field", ["scope_profile", "input_effect"])
@pytest.mark.parametrize("value", [[], {}, 3, None])
def test_source_generated_eval_partition_rejects_unhashable_or_wrong_fact_types(
    tmp_path, field, value
):
    from factoryline.review_audits import security_scan
    from factoryline.review_integrity import partition_proven_primitive_observations

    (tmp_path / "app.py").write_text(_SOURCE_GENERATED, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert len(report["primitive_observations"]) == 2
    report["primitive_observations"][0]["facts"][field] = value
    partition_proven_primitive_observations(report)
    assert len(report["primitive_observations"]) == 1
    assert len(report["findings"]) == 1
    assert report["findings"][0]["severity"] == "HIGH"


@pytest.mark.parametrize(
    "prefix",
    [
        "import builtins\nbuiltins.eval = replacement\n",
        "exec('eval = replacement')\n",
        "saved = eval\n",
    ],
)
def test_source_generated_eval_rejects_provider_mutation_or_escape(tmp_path, prefix):
    from factoryline.review_audits import security_scan

    (tmp_path / "app.py").write_text(prefix + _SOURCE_GENERATED, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert not report.get("primitive_observations")
    assert (
        sum(
            item["code"] == "SECURITY_DYNAMIC_EXECUTION" and item["severity"] == "HIGH"
            for item in report["findings"]
        )
        >= 2
    )


def test_source_generated_helpers_are_included_in_verifier_source_identity():
    from factoryline import runtime_audit_integrity as runtime

    helpers = set(runtime.workspace_builtin_helpers())
    expected = {
        value
        for name, value in vars(runtime).items()
        if name.startswith("_source_eval_") and callable(value)
    }
    assert expected <= helpers
    assert runtime.finite_eval_binding in helpers
