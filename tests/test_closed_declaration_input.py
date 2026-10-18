import ast

import pytest

from factoryline.runtime_audit_integrity import closed_declaration_input_witness


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
