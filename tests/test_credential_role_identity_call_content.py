"""Unknown call results stay separate from tracked receiver identity."""

import ast
import hashlib
from pathlib import Path

import pytest

from factoryline.credential_role_identity_effect_types import (
    ResolvedIdentityCall,
    _Value,
)
from factoryline.credential_role_identity_effects import summarize_identity_effect
from factoryline.credential_role_identity_value_model import (
    identity_value,
    tracked_roots,
)
from factoryline.credential_role_sources import SourceSnapshotIndex


def _analyze(
    tmp_path, strategy_body, backend_body, *, wrong_mapping=False, nonlocal_store=False
):
    source = (
        "class Strategy:\n"
        "    def request_data(self):\n"
        + "".join("        " + line + "\n" for line in strategy_body.splitlines())
        + "class Backend:\n"
        "    def initialize(self):\n"
        + "".join("        " + line + "\n" for line in backend_body.splitlines())
    )
    if nonlocal_store:
        source = "def enclosing():\n    leaked = None\n" + "".join(
            "    " + line + "\n" for line in source.splitlines()
        )
        compile(source, "fixture.py", "exec")  # Compile only; target code never runs.
    path = Path(tmp_path) / "fixture.py"
    raw = source.encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    index = SourceSnapshotIndex(
        Path(tmp_path), {path: tree}, {path: raw}, {path: digest}
    )
    scope = tree.body[0] if nonlocal_store else tree
    strategy, backend = [node for node in scope.body if isinstance(node, ast.ClassDef)]
    method = next(node for node in backend.body if isinstance(node, ast.FunctionDef))
    request_data = next(
        node for node in strategy.body if isinstance(node, ast.FunctionDef)
    )

    def resolve(call, call_path):
        if (
            call_path == path
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "request_data"
            and call.func.value is not None
        ):
            receiver = (
                ast.Name(id="different", ctx=ast.Load())
                if wrong_mapping
                else call.func.value
            )
            return ResolvedIdentityCall(request_data, path, {"self": receiver})
        return None

    return summarize_identity_effect(
        method,
        path,
        index,
        {"self": "backend"},
        resolve_call=resolve,
        field_roots={("backend", "strategy"): "strategy"},
        strict_calls=True,
    )


def test_exact_call_result_content_does_not_alias_backend(tmp_path):
    result = _analyze(tmp_path, "return {}", "self.data = self.strategy.request_data()")

    assert result.status == "NO_CLASS_EFFECT"
    assert not result.escapes
    assert not result.unknowns


@pytest.mark.parametrize(
    "strategy_body",
    [
        "return self",
        "self.__class__ = Changed\nreturn {}",
        "import inspect\nframe = inspect.currentframe().f_back\n"
        "frame.f_locals['self'].__class__ = Changed\nreturn {}",
    ],
)
def test_exact_callee_root_escape_or_mutation_stays_unresolved(tmp_path, strategy_body):
    result = _analyze(
        tmp_path, strategy_body, "self.data = self.strategy.request_data()"
    )

    assert result.status != "NO_CLASS_EFFECT"


def test_unknown_call_result_cannot_flow_to_an_opaque_call(tmp_path):
    result = _analyze(
        tmp_path,
        "return {}",
        "self.data = self.strategy.request_data()\nopaque(self.data)",
    )

    assert result.status == "UNKNOWN"


def test_unknown_call_result_cannot_hide_in_literal_container_before_escape(tmp_path):
    result = _analyze(
        tmp_path,
        "return {}",
        "self.data = self.strategy.request_data()\nsaved = [self.data]\nopaque(saved)",
    )

    assert result.status == "UNKNOWN"


@pytest.mark.parametrize("projection", ["self.data.callback", "self.data['x']"])
def test_content_unknown_attribute_or_subscript_extraction_stays_unknown(
    tmp_path, projection
):
    result = _analyze(
        tmp_path,
        "return {}",
        f"self.data = self.strategy.request_data()\nopaque({projection})",
    )

    assert result.status == "UNKNOWN"


def test_content_unknown_return_and_foreign_store_stay_unknown(tmp_path):
    returned = _analyze(
        tmp_path,
        "return {}",
        "self.data = self.strategy.request_data()\nreturn self.data",
    )
    stored = _analyze(
        tmp_path,
        "return {}",
        "self.data = self.strategy.request_data()\nexternal.value = self.data",
    )

    assert returned.status == "UNKNOWN"
    assert stored.status == "UNKNOWN"


@pytest.mark.parametrize(
    "container",
    ["[self.data]", "{'nested': [{'value': self.data}] }"],
)
def test_nested_content_unknown_cannot_escape_in_returned_container(
    tmp_path, container
):
    result = _analyze(
        tmp_path,
        "return {}",
        f"self.data = self.strategy.request_data()\nreturn {container}",
    )

    assert result.status == "UNKNOWN"


def test_formatting_content_unknown_stays_unknown(tmp_path):
    result = _analyze(
        tmp_path,
        "return {}",
        "self.data = self.strategy.request_data()\nmessage = f'{self.data}'",
    )

    assert result.status == "UNKNOWN"


@pytest.mark.parametrize(
    "consumer",
    [
        "for item in self.data:\n    pass",
        "with self.data:\n    pass",
        "items = [None for item in self.data]",
        "items = self.data + 1",
        "items = [*self.data]",
        "items = {**self.data}",
        "if self.data == None:\n    pass",
    ],
)
def test_unmodeled_content_consumers_stay_unknown(tmp_path, consumer):
    result = _analyze(
        tmp_path,
        "return {}",
        f"self.data = self.strategy.request_data()\n{consumer}",
    )

    assert result.status == "UNKNOWN"


def test_passive_content_alias_and_literal_container_storage_are_allowed(tmp_path):
    result = _analyze(
        tmp_path,
        "return {}",
        "self.data = self.strategy.request_data()\n"
        "saved = self.data\n"
        "container = [{'value': saved}]",
    )

    assert result.status == "NO_CLASS_EFFECT"
    assert not result.escapes
    assert not result.unknowns


def test_identity_test_of_content_can_control_branch_without_protocol_dispatch(
    tmp_path,
):
    result = _analyze(
        tmp_path,
        "return {}",
        "self.data = self.strategy.request_data()\n"
        "if self.data is None:\n"
        "    return {}",
    )

    assert result.status == "NO_CLASS_EFFECT"


def test_source_call_mapping_must_use_the_actual_receiver(tmp_path):
    result = _analyze(
        tmp_path,
        "return {}",
        "self.data = self.strategy.request_data()",
        wrong_mapping=True,
    )

    assert result.status == "UNKNOWN"


def test_nonstrict_calls_preserve_tracked_roots_in_unknown_expressions():
    node = ast.parse("strategy.request_data()", mode="eval").body
    aliases = {"strategy": _Value(roots=frozenset({"strategy"}))}
    value = identity_value(node, aliases)
    strict_value = identity_value(node, aliases, strict_calls=True)

    assert tracked_roots(value) == {"strategy"}
    assert strict_value.content_unknown


@pytest.mark.parametrize("value", ["self.data", "[self.data]", "{'x': [self.data]}"])
def test_global_content_storage_is_an_escape(tmp_path, value):
    result = _analyze(
        tmp_path,
        "return {}",
        f"global leaked\nself.data = self.strategy.request_data()\nleaked = {value}",
    )
    assert result.status == "UNKNOWN"
    assert (
        "global/nonlocal assignment contains unresolved tracked value"
        in result.unknowns
    )


@pytest.mark.parametrize(
    "body",
    [
        "saved = self.data\ndef inner():\n    return saved",
        "saved = [self.data]\ndef inner():\n    return saved",
        "def inner(value=self.data):\n    pass",
        "@opaque\ndef inner():\n    pass",
    ],
)
def test_nested_content_capture_and_definition_effects_stay_unknown(tmp_path, body):
    result = _analyze(
        tmp_path, "return {}", "self.data = self.strategy.request_data()\n" + body
    )
    assert result.status == "UNKNOWN"


@pytest.mark.parametrize("value", ["self.data", "{'x': [self.data]}"])
def test_nonlocal_content_storage_is_an_escape(tmp_path, value):
    result = _analyze(
        tmp_path,
        "return {}",
        f"nonlocal leaked\nself.data = self.strategy.request_data()\nleaked = {value}",
        nonlocal_store=True,
    )
    assert result.status == "UNKNOWN"
    assert (
        "global/nonlocal assignment contains unresolved tracked value"
        in result.unknowns
    )
