"""Shared receiver identity and immutable input provenance remain distinct."""

import ast
import hashlib
from pathlib import Path

import pytest

from factoryline.credential_role_constructor_provider import SourceSnapshotIndex
from factoryline.credential_role_identity_effects import (
    _Value,
    summarize_identity_effect,
)
from factoryline.review_integrity import bind_security_call_scopes
from factoryline import review_audits as audit


def context(source):
    raw = source.encode()
    path = Path("entry.py")
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    bind_security_call_scopes(tree)
    index = SourceSnapshotIndex(Path("."), {path: tree}, {path: raw}, {path: digest})
    assert index.validate(path)
    return path, tree, index


@pytest.mark.parametrize(
    "options,unknown",
    [({}, False), ({"strict_calls": True}, True), ({"role_view": True}, True)],
)
def test_rootless_ambient_alias_retains_strict_and_role_uncertainty(options, unknown):
    path, tree, index = context("def work(self):\n    value = ambient()\n")
    result = summarize_identity_effect(
        tree.body[0], path, index, {"self": "receiver"}, **options
    )
    assert bool(result.unknowns) is unknown
    assert not result.class_writes and not result.field_writes and not result.escapes


@pytest.mark.parametrize(
    "value",
    [
        _Value(roots=frozenset({"receiver"}), unknown=True),
        _Value(roots=frozenset({"mutable"}), content_unknown=True, unknown=True),
    ],
)
def test_unknown_tracked_receiver_or_mutable_value_does_not_become_rootless(value):
    path, tree, index = context(
        "def work(self, raw):\n    copied = raw\n    unknown(copied)\n"
    )
    result = summarize_identity_effect(
        tree.body[0], path, index, {"self": "receiver", "raw": value}
    )
    assert result.status == "UNKNOWN"
    assert "alias receives unresolved tracked expression" in result.unknowns


@pytest.mark.parametrize(
    "options,unknown",
    [({}, False), ({"strict_calls": True}, True), ({"role_view": True}, True)],
)
def test_rootless_unknown_argument_preserves_strict_and_role_modes(options, unknown):
    path, tree, index = context("def work(self):\n    consume(ambient())\n")
    result = summarize_identity_effect(
        tree.body[0], path, index, {"self": "receiver"}, **options
    )
    assert bool(result.unknowns) is unknown
    if options.get("role_view"):
        assert any(event.uncertain for event in result.role_events)


@pytest.mark.parametrize(
    "value",
    [
        _Value(roots=frozenset({"receiver"}), unknown=True),
        _Value(roots=frozenset({"mutable"}), content_unknown=True, unknown=True),
    ],
)
def test_unknown_identity_argument_stays_unknown(value):
    path, tree, index = context("def work(self, raw):\n    consume(raw)\n")
    result = summarize_identity_effect(
        tree.body[0], path, index, {"self": "receiver", "raw": value}
    )
    assert "call receives an unresolved tracked value" in result.unknowns


def test_unresolved_return_capture_does_not_become_known_value():
    from factoryline.credential_role_identity_effects import summarize_identity_call

    path, tree, index = context("def work():\n    return ambient()\n")
    call = tree.body[0].body[0].value
    result = summarize_identity_call(
        call, path, index, {}, resolve_call=lambda call, path: None
    )
    assert result.return_status == "UNKNOWN"
    assert result.return_values and result.return_values[0].value.unknown


SOURCE = """import subprocess
class Worker:
    def __init__(self, raw):
        self.command = raw
    def ready(self):
        unrelated = ambient()
    def go(self):
        subprocess.call("echo {}".format(self.command), shell=True)
def run():
    raw = input("command: ")
    r = Worker(raw)
    r.ready()
    r.go()
"""


def native(tmp_path, source):
    (tmp_path / "entry.py").write_text(source)
    result = audit.security_scan(tmp_path, cache_enabled=False, security_only=True)
    return [
        r
        for r in result["finding_tier_report"]["ledger"]
        if r["raw_finding"]["code"] == "SECURITY_SHELL_COMMAND"
    ]


def test_receiver_value_reaches_admission_with_source_proof(tmp_path):
    rows = native(tmp_path, SOURCE)
    assert len(rows) == 1 and rows[0]["tier"] == "SUPPORTED_DEFECT"
    flow = rows[0]["raw_finding"]["facts"]["security_precondition"]["input_value_flow"]
    operations = {s["operation"] for s in flow["steps"]}
    assert {
        "BUILTIN_INPUT",
        "EXACT_CONSTRUCTOR_ARGUMENT",
        "ORDINARY_FIELD_STORE",
        "POSSIBLE_ORDERED_RECEIVER_ACTIVATION",
        "ORDINARY_FIELD_READ",
    } <= operations


@pytest.mark.parametrize(
    "expression", ['"echo " + self.command', 'f"echo {self.command}"']
)
def test_composed_receiver_value_reaches_admission_with_source_proof(
    tmp_path, expression
):
    source = SOURCE.replace('"echo {}".format(self.command)', expression)
    rows = native(tmp_path, source)
    assert len(rows) == 1 and rows[0]["tier"] == "SUPPORTED_DEFECT"
    flow = rows[0]["raw_finding"]["facts"]["security_precondition"]["input_value_flow"]
    assert "ORDINARY_FIELD_READ" in {step["operation"] for step in flow["steps"]}


@pytest.mark.parametrize(
    "source",
    [
        SOURCE.replace("def run():", "def run(Worker):"),
        SOURCE.replace("def go(self):", "def go(self):\n        self = Safe()"),
        SOURCE.replace(
            "raw = input", "def clean():\n        r.command = 'safe'\n    raw = input"
        ).replace("r.ready()", "clean()"),
        SOURCE.replace("r.ready()", "unknown(r)"),
        SOURCE.replace("r.ready()", "alias = r\n    unknown(alias)"),
        SOURCE.replace("unrelated = ambient()", "self.command = 'fixed'"),
        SOURCE.replace("r.go()", "other = Worker('fixed')\n    other.go()"),
        SOURCE.replace(
            "def ready(self):",
            "def __setattr__(self, name, value):\n        pass\n    def ready(self):",
        ),
        SOURCE.replace("r.ready()", "Worker.go = replacement"),
        SOURCE.replace("raw = input", "input = replacement\n    raw = input"),
        SOURCE.replace('"echo {}".format(self.command)', "callback(self)").replace(
            "def go(self):", 'def go(self):\n        self.command = "safe"'
        ),
    ],
)
def test_receiver_counterexamples_do_not_admit(tmp_path, source):
    rows = native(tmp_path, source)
    assert len(rows) == 1 and rows[0]["tier"] != "SUPPORTED_DEFECT"


@pytest.mark.parametrize(
    "declaration",
    [
        "def standalone(self):\n    return self.command\n",
        "def outside():\n    def inner(self):\n        return self.command\n",
    ],
)
def test_standalone_and_nested_self_spelling_does_not_crash(tmp_path, declaration):
    native(tmp_path, SOURCE + declaration)


def test_receiver_argument_callback_is_not_ignored(tmp_path):
    source = SOURCE.replace('"echo {}".format(self.command)', "mutating(self)")
    rows = native(tmp_path, source)
    assert rows[0]["tier"] != "SUPPORTED_DEFECT"


def test_receiver_query_reuses_only_current_source_and_helper_epoch(monkeypatch):
    from factoryline.credential_role_method_use_getter_audit import (
        selected_receiver_field_value,
        _SelectedReceiverState,
    )

    path, tree, index = context(SOURCE)
    field = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Attribute)
        and n.attr == "command"
        and isinstance(n.ctx, ast.Load)
    )
    first = selected_receiver_field_value(field, index, path)
    assert first is not None
    assert selected_receiver_field_value(field, index, path) == first
    monkeypatch.setattr(_SelectedReceiverState, "input_origin", lambda self, node: None)
    assert selected_receiver_field_value(field, index, path) is None
    index.inventory[path] = "0" * 64
    assert selected_receiver_field_value(field, index, path) is None


@pytest.mark.parametrize(
    "source",
    [
        SOURCE.replace(
            "r = Worker(raw)",
            'if raw not in {"start", "stop"}:\n        return\n    r = Worker(raw)',
        ),
        SOURCE.replace(
            "r = Worker(raw)", 'if raw != "safe":\n        return\n    r = Worker(raw)'
        ),
        'import builtins\nbuiltins.input = lambda prompt: "fixed"\n'
        + SOURCE.replace("raw = input", "raw = builtins.input"),
        "import builtins\nbuiltins.str = replacement\n"
        + SOURCE.replace('raw = input("command: ")', 'raw = str(input("command: "))'),
    ],
)
def test_input_origin_retains_domain_and_provider_guards(tmp_path, source):
    rows = native(tmp_path, source)
    assert len(rows) == 1 and rows[0]["tier"] != "SUPPORTED_DEFECT"


def test_finite_exclusion_does_not_turn_unbounded_text_into_an_allowlist(tmp_path):
    source = SOURCE.replace(
        "r = Worker(raw)", 'if raw == "":\n        return\n    r = Worker(raw)'
    )
    rows = native(tmp_path, source)
    assert len(rows) == 1 and rows[0]["tier"] == "SUPPORTED_DEFECT"


@pytest.mark.parametrize(
    "expression,tracked",
    [
        ("opaque().format(self.command)", False),
        ("opaque().format(self)", True),
        ("opaque().format(mutating(self), self.command)", True),
        ("opaque(self.command, mutating(self))", True),
    ],
)
def test_opaque_expression_composes_proven_field_values_without_hiding_callbacks(
    expression, tracked
):
    from factoryline.credential_role_identity_effects import (
        identity_value,
        tracked_roots,
    )

    tree = ast.parse(expression, mode="eval")
    value = identity_value(
        tree.body,
        {
            "self": _Value(roots=frozenset({"receiver"})),
            ("receiver", "command"): _Value(inert_kind="scalar", scalar_kind="text"),
        },
        strict_calls=True,
        material_values=True,
    )
    assert value.unknown  # No invented type or call-safety proof.
    assert bool(tracked_roots(value)) is tracked


def test_repeated_field_reads_share_a_proof_but_keep_distinct_source_spans(monkeypatch):
    from factoryline.credential_role_method_use_getter_audit import (
        selected_receiver_field_value,
        _SelectedReceiverState,
    )

    source = SOURCE.replace(
        '"echo {}".format(self.command)',
        '"echo {} {}".format(self.command, self.command)',
    )
    path, tree, index = context(source)
    fields = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Attribute)
        and n.attr == "command"
        and isinstance(n.ctx, ast.Load)
    ]
    count = []
    original = _SelectedReceiverState.derive

    def counted(self):
        count.append(1)
        return original(self)

    monkeypatch.setattr(_SelectedReceiverState, "derive", counted)
    values = [selected_receiver_field_value(field, index, path) for field in fields]
    assert all(values) and len(count) == 1
    assert values[0].trace[-1][1] != values[1].trace[-1][1]


@pytest.mark.parametrize(
    "source,positive",
    [
        (
            SOURCE.replace(
                "def __init__(self, raw):",
                "def __init__(self, raw, label):\n        self.label = label",
            )
            .replace(
                'subprocess.call("echo {}".format(self.command)',
                'rendered = opaque().format(self.label)\n        subprocess.call("echo {}".format(self.command)',
            )
            .replace(
                "Worker(raw)",
                'Worker(raw, str(raw).rsplit("/")[len(str(raw).split("/")) - 1])',
            ),
            True,
        ),
        (
            SOURCE.replace(
                "def __init__(self, raw):",
                "def __init__(self, raw, label):\n        self.label = label",
            )
            .replace(
                'subprocess.call("echo {}".format(self.command)',
                'rendered = opaque().format(self.label)\n        subprocess.call("echo {}".format(self.command)',
            )
            .replace("Worker(raw)", 'Worker(raw, fake(raw).split("/")[0])'),
            False,
        ),
    ],
)
def test_constructor_text_element_type_is_source_owned(tmp_path, source, positive):
    rows = native(tmp_path, source)
    assert len(rows) == 1
    assert (rows[0]["tier"] == "SUPPORTED_DEFECT") is positive


@pytest.mark.parametrize(
    "expression,tracked",
    [
        ("opaque(key=self)", True),
        ("opaque([item for item in self])", True),
        ("opaque([item for item in values if check(self)])", True),
        ("opaque(key=self.command)", False),
        ("opaque([item for item in self.command])", False),
    ],
)
def test_opaque_expression_preserves_container_child_roots(expression, tracked):
    from factoryline.credential_role_identity_effects import (
        identity_value,
        tracked_roots,
    )

    value = identity_value(
        ast.parse(expression, mode="eval").body,
        {
            "self": _Value(roots=frozenset({"receiver"})),
            ("receiver", "command"): _Value(inert_kind="scalar", scalar_kind="text"),
        },
        strict_calls=True,
        material_values=True,
    )
    assert value.unknown
    assert bool(tracked_roots(value)) is tracked


@pytest.mark.parametrize(
    "source",
    [
        SOURCE.replace("unrelated = ambient()", "opaque((self.command for _ in (0,)))"),
        SOURCE.replace(
            "r = Worker(raw)", 'assert raw in ("safe",)\n    r = Worker(raw)'
        ),
        SOURCE.replace("r = Worker(raw)", "assert raw.isalnum()\n    r = Worker(raw)"),
    ],
)
def test_lazy_capture_and_asserted_input_domain_do_not_admit(tmp_path, source):
    rows = native(tmp_path, source)
    assert len(rows) == 1 and rows[0]["tier"] != "SUPPORTED_DEFECT"


@pytest.mark.parametrize("proven", [False, True])
def test_shared_receiver_projection_preserves_proof_or_unknown_roots(proven):
    from factoryline.finite_capture import _security_structural_receiver_value

    expression = ast.parse("self.command", mode="eval").body
    known = _Value(inert_kind="scalar", scalar_kind="text")
    aliases = {"self": _Value(roots=frozenset({"receiver"}))}
    from factoryline.credential_role_identity_effects import identity_value

    value = (
        known
        if proven
        else identity_value(
            expression, aliases, strict_calls=True, material_values=True
        )
    )
    result = _security_structural_receiver_value(expression, aliases, value)
    if proven:
        assert result is known
    else:
        assert result.unknown and result.roots == frozenset({"receiver"})
    assert aliases == {"self": _Value(roots=frozenset({"receiver"}))}
