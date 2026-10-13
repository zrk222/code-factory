from __future__ import annotations

import json
import hashlib
import subprocess
from pathlib import Path

import pytest

from factoryline.analysis_evidence import (
    AnalysisEvidenceError,
    assess_review_reuse,
    build_execution_review_evidence,
    build_review_evidence,
    evaluate_spans,
    evaluate_spans_file,
    validate_evaluation_bindings,
    parse_analysis_sarif,
    trace_evaluation_status,
    validate_review_evidence,
)
from factoryline.audit_trace import build_audit_trace


def _implementation_findings(
    source: str, *, relative="src/service.py", test_source=False, aliases=None
):
    import ast

    from factoryline.review_integrity import implementation_completeness_findings

    return implementation_completeness_findings(
        relative, ast.parse(source), source, aliases=aliases, test_source=test_source
    )


def test_implementation_completeness_flags_exact_production_stubs_and_exempts_interfaces():
    source = """from abc import ABC, abstractmethod
from typing import Protocol, overload

def empty_pass():
    pass

def empty_ellipsis():
    ...

def empty_not_implemented():
    raise NotImplementedError("later")

def operator_fallback(other):
    return NotImplemented

def conditional_not_implemented(flag):
    if flag:
        raise NotImplementedError
    return 1

class Base(ABC):
    @abstractmethod
    def required(self):
        pass

class Port(Protocol):
    def execute(self):
        ...

@overload
def parse(value: str) -> str: ...
"""
    findings = _implementation_findings(source)

    assert [item["facts"]["symbol"] for item in findings] == [
        "empty_pass",
        "empty_ellipsis",
        "empty_not_implemented",
    ]
    assert all(item["severity"] == "MEDIUM" for item in findings)
    assert all(
        item["facts"]["intent"] == "UNKNOWN_REVIEW_REQUIRED" for item in findings
    )


def test_implementation_completeness_flags_only_exact_returned_placeholder_strings():
    source = """def demo():
    return "DEMO_ONLY"

def todo():
    return "TODO"

def ordinary_empty():
    return ""

def normal_none():
    return None

def phrase():
    return "The TODO is tracked in issue 19"

def outer():
    def nested():
        return "TODO"
    return nested()
"""
    findings = _implementation_findings(source)

    assert [item["facts"]["symbol"] for item in findings] == [
        "demo",
        "todo",
        "nested",
    ]
    assert all(item["code"] == "QUALITY_PLACEHOLDER_OUTPUT" for item in findings)


def test_implementation_completeness_tokenizes_omission_comments_not_strings_or_docstrings():
    source = '''"""TODO in documentation is not a source comment."""
MARKER = "FIXME"
# TODO: implement retry behavior
def run():
    # FIXME validate the response
    return "ordinary"
'''
    findings = _implementation_findings(source)

    assert [item["code"] for item in findings] == [
        "QUALITY_OMISSION_MARKER",
        "QUALITY_OMISSION_MARKER",
    ]
    assert [item["line"] for item in findings] == [3, 5]


def test_implementation_completeness_resolves_unittest_mock_aliases_and_patch_apis():
    source = """import unittest.mock as mocking
from unittest.mock import Mock as MakeMock
from unittest import mock as unittest_mock

def configure():
    one = mocking.Mock()
    two = MakeMock()
    with unittest_mock.patch.object(one, "send"):
        pass
"""
    findings = _implementation_findings(source)

    assert [item["facts"]["api"] for item in findings] == [
        "unittest.mock.Mock",
        "unittest.mock.Mock",
        "unittest.mock.patch.object",
    ]
    assert all(item["code"] == "QUALITY_PRODUCTION_MOCK" for item in findings)


def test_implementation_completeness_resolves_pytest_monkeypatch_constructor_aliases():
    source = """import pytest as pt
from pytest import MonkeyPatch as PatchFixture

def configure():
    first = pt.MonkeyPatch()
    second = PatchFixture()
"""
    findings = _implementation_findings(source)

    assert [item["facts"]["api"] for item in findings] == [
        "pytest.MonkeyPatch",
        "pytest.MonkeyPatch",
    ]


def test_implementation_completeness_respects_test_source_and_local_shadowing():
    source = """import pytest
from unittest.mock import Mock as MakeMock

def production_parameter_shadow(MakeMock):
    return MakeMock()

def production_assignment_shadow():
    MakeMock = FakeMock
    return MakeMock()

@pytest.fixture
def fixture_helper():
    pass

def test_fixture():
    # TODO: implement a test assertion
    pass
"""

    assert _implementation_findings(source) == []
    assert _implementation_findings(source, test_source=True) == []
    assert _implementation_findings(source, relative="tests/test_service.py") == []


def test_implementation_completeness_does_not_match_mock_names_or_unresolved_aliases():
    source = """def make(mock_request):
    return mock_request

def smoke():
    return FakeMock()
"""

    assert _implementation_findings(source) == []
    assert (
        _implementation_findings(
            "def configure():\n    MakeMock()\n",
            aliases={"MakeMock": "unknown.MakeMock"},
        )
        == []
    )


def test_implementation_completeness_decodes_declared_source_encoding():
    import ast

    from factoryline.review_integrity import implementation_completeness_findings

    source = (
        b"# -*- coding: latin-1 -*-\n# TODO: implement r\xe9try\ndef run():\n    pass\n"
    )
    findings = implementation_completeness_findings(
        "src/service.py", ast.parse(source), source
    )

    assert [item["code"] for item in findings] == [
        "QUALITY_OMISSION_MARKER",
        "QUALITY_EMPTY_IMPLEMENTATION",
    ]


def test_implementation_completeness_rejects_invalid_source_encoding():
    import ast

    from factoryline.review_integrity import implementation_completeness_findings

    source = b"# coding: no-such-codec\ndef run(): pass\n"
    with pytest.raises(ValueError, match="invalid Python encoding"):
        implementation_completeness_findings(
            "src/service.py", ast.parse("def run(): pass"), source
        )


def test_implementation_completeness_respects_source_ordered_aliases_and_fixtures():
    source = """import pytest as pt
from unittest.mock import Mock as Build

def setup():
    from unrelated import Build
    return Build()

@pt.fixture
def plugin_fixture():
    return Build()
"""

    findings = _implementation_findings(source)

    assert findings == []


def test_implementation_completeness_exempts_generic_protocol_and_not_relative_imports():
    source = """from typing import Protocol, TypeVar
from .unittest.mock import Mock
from .abc import abstractmethod

T = TypeVar("T")
class Port(Protocol[T]):
    def execute(self): ...

def local_factory():
    return Mock()

class ConcreteLooking:
    @abstractmethod
    def execute(self):
        pass
"""

    findings = _implementation_findings(source)

    assert [(item["code"], item["facts"].get("symbol")) for item in findings] == [
        ("QUALITY_EMPTY_IMPLEMENTATION", "execute")
    ]


def test_implementation_completeness_does_not_resolve_relative_mock_import_as_stdlib():
    source = """from .unittest import mock

def local_factory():
    return mock.Mock()
"""

    assert _implementation_findings(source) == []


def test_implementation_completeness_respects_except_and_pattern_capture_shadows():
    source = """from unittest.mock import Mock as Build

def caught():
    try:
        raise RuntimeError()
    except RuntimeError as Build:
        Build()

def matched(value):
    match value:
        case Build:
            Build()
        case {**Build}:
            Build()
"""

    assert _implementation_findings(source) == []


def test_implementation_completeness_respects_lambda_parameter_shadowing():
    source = """from unittest.mock import Mock
maker = lambda Mock: Mock()
"""

    assert _implementation_findings(source) == []


def _span_fixture(root: Path) -> tuple[dict, list[dict]]:
    (root / "src").mkdir()
    source = root / "src" / "sample.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    for args in (
        ["init", "--quiet"],
        ["config", "user.name", "Trace Test"],
        ["config", "user.email", "trace@example.invalid"],
        ["add", "src/sample.py"],
        ["commit", "--quiet", "-m", "fixture"],
    ):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    trace = build_audit_trace(
        root,
        changed_paths=["src/sample.py"],
        lane_states={"tests": "PASS"},
        steps=[
            {
                "step_id": "bound-source",
                "input": "sha256:" + hashlib.sha256(b"input").hexdigest(),
                "guard": "SOURCE_BOUND",
                "decision": "RECORD",
                "state": "PASS",
                "source_paths": ["src/sample.py"],
            }
        ],
    )
    trace_path = root / "trace.json"
    trace_path.write_text(json.dumps(trace), encoding="utf-8")
    candidate_path = root / "candidate.json"
    candidate_path.write_text(json.dumps(trace["candidate"]), encoding="utf-8")
    artifacts = {
        "tool": {
            "version": "1",
            "tools": {
                "search": {
                    "result_required": True,
                    "state_required": True,
                    "allow_empty": False,
                }
            },
            "results": {
                "s1": {
                    "status": "SUCCESS",
                    "result_present": True,
                    "output_bytes": 2,
                    "observed_state": "ok",
                }
            },
        },
        "model": {"id": "review-model", "version": "1"},
        "prompt": {"version": "1", "template": "review"},
        "rubric": {"required_context_ids": ["goal", "tool"], "version": "1"},
        "dataset": {
            "version": "1",
            "context_evidence": {
                "goal": {
                    "path": "src/sample.py",
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                },
                "tool": {
                    "path": "src/sample.py",
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                },
            },
            "numeric_facts": {
                "s1": {
                    "value": 0.5,
                    "unit": "ratio",
                    "numerator": 1,
                    "denominator": 2,
                    "precision": 3,
                }
            },
        },
        "policy": {"version": "1"},
    }
    paths = {}
    for role, body in artifacts.items():
        path = root / f"{role}.json"
        path.write_text(json.dumps(body), encoding="utf-8")
        raw = path.read_bytes()
        paths[role] = {"path": path.name, "sha256": hashlib.sha256(raw).hexdigest()}
    source_raw = source.read_bytes()
    binding = {
        "schema": "factory.span-evaluation.binding-request.v1",
        "trace": {
            "path": "trace.json",
            "sha256": hashlib.sha256(trace_path.read_bytes()).hexdigest(),
        },
        "candidate": {
            "path": "candidate.json",
            "sha256": hashlib.sha256(candidate_path.read_bytes()).hexdigest(),
        },
        "sources": [
            {"path": "src/sample.py", "sha256": hashlib.sha256(source_raw).hexdigest()}
        ],
        "artifacts": paths,
        "applicability": {"model": "applicable"},
    }
    candidate_sha = hashlib.sha256(
        json.dumps(trace["candidate"], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    spans = [
        {
            "span_id": "s1",
            "numeric": {
                "value": 0.5,
                "unit": "ratio",
                "numerator": 1,
                "denominator": 2,
                "precision": 3,
            },
            "context_refs": ["goal", "tool"],
            "contradicted_context_ids": [],
            "tool": {"name": "search"},
            "call": {
                "tool": "search",
                "args_sha256": "a" * 64,
                "state_sha256": "b" * 64,
                "candidate_sha256": candidate_sha,
                "freshness_sha256": "d" * 64,
            },
        }
    ]
    return {
        "schema": "factory.span-evaluation.request.v1",
        "binding_request": binding,
        "spans": spans,
    }, artifacts


def _attach_span_policy(root: Path, request: dict, criteria: dict) -> None:
    policy = {"schema": "factory.span-applicability.v1", "rules": criteria}
    path = root / "span-policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    request["binding_request"]["artifacts"]["span_policy"] = {
        "path": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _applicability_rule(span_id: str, overrides: dict | None = None) -> dict:
    criteria = {
        name: {
            "applicable": True,
            "reason": f"{name} applies to this span",
            "references": [{"path": "src/sample.py", "sha256": ""}],
        }
        for name in ("numeric", "context", "tool", "redundancy")
    }
    if overrides:
        for name, entry in overrides.items():
            criteria[name].update(entry)
    return {"span_id": span_id, "criteria": criteria}


def _bind_policy_source_hash(request: dict, rules: list[dict]) -> list[dict]:
    source_hash = request["binding_request"]["sources"][0]["sha256"]
    for rule in rules:
        for entry in rule["criteria"].values():
            entry["references"][0]["sha256"] = source_hash
    return rules


def test_span_evaluation_binds_artifacts_and_returns_four_closed_criteria(
    tmp_path: Path,
) -> None:
    request, _ = _span_fixture(tmp_path)
    bound = validate_evaluation_bindings(tmp_path, request["binding_request"])
    assert bound["state"] == "BOUND_LOCAL_EVIDENCE"
    result = evaluate_spans(tmp_path, request)
    assert result["schema"] == "factory.span-evaluation.v1"
    assert (
        result["request_sha256"]
        == hashlib.sha256(
            json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    )
    assert result["provenance"] == "BOUND_LOCAL_EVIDENCE"
    assert result["semantic_correctness"] == "UNKNOWN_PENDING_JEV"
    assert [
        result["spans"][0][key]["state"]
        for key in ("numeric", "context", "tool", "redundancy")
    ] == ["PASS"] * 4
    assert result["authority"] == "none"


@pytest.mark.parametrize(
    "mutation,code",
    [
        ("numeric", "NUMERIC_UNGROUNDED"),
        ("context", "CONTEXT_INCOMPLETE"),
        ("silent", "TOOL_SILENT_FAILURE"),
        ("redundant", "TOOL_REDUNDANT"),
    ],
)
def test_span_evaluation_detects_grounding_context_silence_and_redundancy(
    tmp_path: Path, mutation: str, code: str
) -> None:
    request, _ = _span_fixture(tmp_path)
    span = request["spans"][0]
    if mutation == "numeric":
        span["numeric"]["denominator"] = 0
    elif mutation == "context":
        span["context_refs"].remove("tool")
    elif mutation == "silent":
        tool = json.loads((tmp_path / "tool.json").read_text(encoding="utf-8"))
        tool["results"]["s1"]["result_present"] = False
        (tmp_path / "tool.json").write_text(json.dumps(tool), encoding="utf-8")
        request["binding_request"]["artifacts"]["tool"]["sha256"] = hashlib.sha256(
            (tmp_path / "tool.json").read_bytes()
        ).hexdigest()
    else:
        request["spans"].append({**span, "span_id": "s2"})
        tools = json.loads((tmp_path / "tool.json").read_text(encoding="utf-8"))
        tools["results"]["s2"] = dict(tools["results"]["s1"])
        (tmp_path / "tool.json").write_text(json.dumps(tools), encoding="utf-8")
        request["binding_request"]["artifacts"]["tool"]["sha256"] = hashlib.sha256(
            (tmp_path / "tool.json").read_bytes()
        ).hexdigest()
    result = evaluate_spans(tmp_path, request)
    keys = {
        "numeric": "numeric",
        "context": "context",
        "silent": "tool",
        "redundant": "redundancy",
    }
    rows = [row[keys[mutation]]["code"] for row in result["spans"]]
    assert code in rows


def test_span_evaluation_file_hash_and_stale_binding_fail_closed(
    tmp_path: Path,
) -> None:
    request, _ = _span_fixture(tmp_path)
    path = tmp_path / "request.json"
    path.write_text(json.dumps(request), encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert (
        evaluate_spans_file(tmp_path, path, digest)["schema"]
        == "factory.span-evaluation.v1"
    )
    assert evaluate_spans_file(tmp_path, path, "0" * 64)["state"] == "INCOMPLETE"


def test_evaluate_trace_file_replays_exact_request_and_dispatches_kind(
    tmp_path: Path,
) -> None:
    from factoryline.analysis_evidence import evaluate_trace_file

    request, _ = _span_fixture(tmp_path)
    raw = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
    path = tmp_path / "span-request.json"
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()

    result = evaluate_trace_file(tmp_path, path, digest, kind="spans")

    assert result["state"] == "PASS"
    assert result["request_sha256"] == digest
    assert (
        evaluate_trace_file(tmp_path, path, "0" * 64, kind="spans")["state"]
        == "INCOMPLETE"
    )
    assert (
        evaluate_trace_file(tmp_path, path, digest, kind="unknown")["state"]
        == "INCOMPLETE"
    )


def test_span_applicability_accepts_bound_partial_exemption(tmp_path: Path) -> None:
    request, _ = _span_fixture(tmp_path)
    request["spans"][0]["context_refs"] = []
    rule = _applicability_rule(
        "s1",
        {
            "context": {
                "applicable": False,
                "reason": "No contextual claim exists on this span.",
            }
        },
    )
    _attach_span_policy(tmp_path, request, _bind_policy_source_hash(request, [rule]))

    result = evaluate_spans(tmp_path, request)

    assert result["state"] == "PASS"
    assert result["spans"][0]["context"] == {
        "state": "NOT_APPLICABLE",
        "code": "CRITERION_NOT_APPLICABLE",
        "reason": "No contextual claim exists on this span.",
        "references": [request["binding_request"]["sources"][0]],
    }
    assert result["criteria_coverage"] == {
        "evaluated": 3,
        "not_applicable": 1,
        "incomplete": 0,
        "failed": 0,
        "total": 4,
    }


@pytest.mark.parametrize("mutation", ["reason", "reference", "coverage"])
def test_span_applicability_rejects_forged_or_incomplete_policy(
    tmp_path: Path, mutation: str
) -> None:
    request, _ = _span_fixture(tmp_path)
    rule = _applicability_rule("s1")
    rules = _bind_policy_source_hash(request, [rule])
    if mutation == "reason":
        rules[0]["criteria"]["tool"]["reason"] = "  "
    elif mutation == "reference":
        rules[0]["criteria"]["tool"]["references"][0]["sha256"] = "0" * 64
    else:
        del rules[0]["criteria"]["tool"]
    _attach_span_policy(tmp_path, request, rules)

    result = evaluate_spans(tmp_path, request)

    assert result["state"] == "INCOMPLETE"
    assert result["errors"][0]["code"] == "TRACE_UNBOUND"


@pytest.mark.parametrize("hidden", ["numeric", "tool"])
def test_span_applicability_cannot_hide_present_facts(
    tmp_path: Path, hidden: str
) -> None:
    request, _ = _span_fixture(tmp_path)
    rule = _applicability_rule(
        "s1",
        {
            hidden: {
                "applicable": False,
                "reason": f"{hidden} is not relevant",
            }
        },
    )
    _attach_span_policy(tmp_path, request, _bind_policy_source_hash(request, [rule]))

    result = evaluate_spans(tmp_path, request)

    assert result["state"] == "INCOMPLETE"
    assert result["errors"][0]["code"] == "TRACE_UNBOUND"


def test_span_applicability_all_not_applicable_is_incomplete(tmp_path: Path) -> None:
    request, _ = _span_fixture(tmp_path)
    span = request["spans"][0]
    span.update(
        numeric=None,
        context_refs=[],
        contradicted_context_ids=[],
        tool=None,
        call=None,
    )
    overrides = {
        name: {"applicable": False, "reason": f"{name} is absent."}
        for name in ("numeric", "context", "tool", "redundancy")
    }
    rule = _applicability_rule("s1", overrides)
    _attach_span_policy(tmp_path, request, _bind_policy_source_hash(request, [rule]))

    result = evaluate_spans(tmp_path, request)

    assert result["state"] == "INCOMPLETE"
    assert all(
        result["spans"][0][name]["state"] == "NOT_APPLICABLE"
        for name in ("numeric", "context", "tool", "redundancy")
    )
    assert result["criteria_coverage"] == {
        "evaluated": 0,
        "not_applicable": 4,
        "incomplete": 0,
        "failed": 0,
        "total": 4,
    }


@pytest.mark.parametrize("field", ["result_required", "state_required"])
def test_span_tool_contract_requires_boolean_requirement_flags(
    tmp_path: Path, field: str
) -> None:
    request, _ = _span_fixture(tmp_path)
    tool = json.loads((tmp_path / "tool.json").read_text(encoding="utf-8"))
    tool["tools"]["search"][field] = 1
    tool_path = tmp_path / "tool.json"
    tool_path.write_text(json.dumps(tool), encoding="utf-8")
    request["binding_request"]["artifacts"]["tool"]["sha256"] = hashlib.sha256(
        tool_path.read_bytes()
    ).hexdigest()

    result = evaluate_spans(tmp_path, request)

    assert result["spans"][0]["tool"]["state"] == "INCOMPLETE"
    assert result["spans"][0]["tool"]["code"] == "TOOL_SILENT_FAILURE"


def test_trace_status_rejects_fabricated_selfhashed_saved_evaluation(
    tmp_path: Path,
) -> None:
    from factoryline.runtime_audit_common import canonical_bytes

    request, _ = _span_fixture(tmp_path)
    request_raw = canonical_bytes(request)
    (tmp_path / "request.json").write_bytes(request_raw)
    receipt = evaluate_spans(tmp_path, request)
    forged = dict(receipt)
    forged["state"] = "PASS" if receipt["state"] != "PASS" else "FAIL"
    core = {key: value for key, value in forged.items() if key != "evaluation_sha256"}
    forged["evaluation_sha256"] = hashlib.sha256(canonical_bytes(core)).hexdigest()
    receipt_raw = canonical_bytes(forged)
    (tmp_path / "receipt.json").write_bytes(receipt_raw)
    directory = tmp_path / ".factory" / "trace-evaluation"
    directory.mkdir(parents=True)
    manifest = {
        "schema": "factory.trace-evaluation-manifest.v1",
        "kind": "spans",
        "request": {
            "path": "request.json",
            "sha256": hashlib.sha256(request_raw).hexdigest(),
        },
        "receipt": {
            "path": "receipt.json",
            "sha256": hashlib.sha256(receipt_raw).hexdigest(),
        },
    }
    (directory / "latest.json").write_bytes(canonical_bytes(manifest))

    assert trace_evaluation_status(tmp_path)["state"] == "INCOMPLETE"


def _sarif(root: Path, tool: str, *, result: dict[str, object] | None = None) -> Path:
    path = root / f"{tool.casefold()}.sarif.json"
    path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": tool}},
                        "invocations": [{"executionSuccessful": True}],
                        "results": [result] if result else [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(
    ("tool", "provider"),
    [("JetBrains Qodana", "qodana"), ("SonarQube for IDE", "sonarqube")],
)
def test_adapter_auto_detects_supported_analyzers_and_binds_exact_bytes(
    tmp_path: Path, tool: str, provider: str
) -> None:
    path = _sarif(
        tmp_path,
        tool,
        result={
            "ruleId": "quality:one",
            "level": "warning",
            "baselineState": "new",
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}}}
            ],
        },
    )
    result = parse_analysis_sarif(tmp_path, path)
    assert result["provider"] == provider
    assert result["execution_successful"] is True
    assert result["counts"]["new"] == 1
    assert result["findings"][0]["paths"] == ["src/app.py"]
    assert len(result["file_sha256"]) == len(result["evidence_sha256"]) == 64
    assert all(value is False for value in result["authority"].values())


def test_adapter_rejects_unknown_ambiguous_and_mismatched_providers(
    tmp_path: Path,
) -> None:
    unknown = _sarif(tmp_path, "Unknown Analyzer")
    with pytest.raises(AnalysisEvidenceError, match="auto detection") as auto_error:
        parse_analysis_sarif(tmp_path, unknown)
    assert auto_error.value.code == "ANALYSIS_PROVIDER_UNVERIFIED"

    qodana = _sarif(tmp_path, "JetBrains Qodana")
    with pytest.raises(AnalysisEvidenceError, match="requested sonarqube") as mismatch:
        parse_analysis_sarif(tmp_path, qodana, provider="sonarqube")
    assert mismatch.value.code == "ANALYSIS_PROVIDER_MISMATCH"

    ambiguous = _sarif(tmp_path, "Qodana SonarQube Bridge")
    with pytest.raises(AnalysisEvidenceError, match="more than one") as ambiguous_error:
        parse_analysis_sarif(tmp_path, ambiguous)
    assert ambiguous_error.value.code == "ANALYSIS_PROVIDER_AMBIGUOUS"


def test_adapter_drops_unsafe_location_uris_but_keeps_the_finding(
    tmp_path: Path,
) -> None:
    path = _sarif(
        tmp_path,
        "SonarQube",
        result={
            "ruleId": "security:path",
            "level": "error",
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "../secret.txt"}}},
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "file:///tmp/secret.txt"}
                    }
                },
            ],
        },
    )
    result = parse_analysis_sarif(tmp_path, path)
    assert result["findings"][0]["paths"] == []
    assert result["counts"]["unbaselined"] == 1


def test_review_evidence_packet_keeps_unknowns_and_validates_hashes() -> None:
    from hashlib import sha256
    import json

    def seal(value: dict[str, object]) -> str:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return sha256(raw).hexdigest()

    receipt: dict[str, object] = {
        "candidate_sha256": "a" * 64,
        "findings": [
            {
                "finding_id": "finding-1",
                "analyzer_id": "codeql",
                "rule_id": "security:path",
                "locations": [{"path": "src/app.py"}],
            }
        ],
        "report_hashes": {"codeql": "b" * 64},
    }
    receipt["receipt_sha256"] = seal(receipt)
    packet = build_review_evidence(receipt)
    assert validate_review_evidence(packet) == packet
    assert packet["claims"][0]["supporting_evidence_ids"]
    assert packet["claims"][0]["contradicting_evidence_ids"] == []
    assert any(
        "candidate source hashes" in item["verification_action"]
        for item in packet["unknowns"]
    )
    assert any(
        "runtime evidence" in item["verification_action"] for item in packet["unknowns"]
    )
    evidence_id = packet["evidence"][0]["id"]
    assert (
        assess_review_reuse(
            packet,
            candidate_sha256="a" * 64,
            receipt_sha256=receipt["receipt_sha256"],
            required_evidence_ids=[evidence_id],
        )["decision"]
        == "REUSE"
    )
    assert (
        assess_review_reuse(
            packet,
            candidate_sha256="c" * 64,
            receipt_sha256=receipt["receipt_sha256"],
            required_evidence_ids=[evidence_id],
        )["decision"]
        == "RERUN"
    )
    assert (
        assess_review_reuse(
            packet,
            candidate_sha256="a" * 64,
            receipt_sha256=receipt["receipt_sha256"],
            required_evidence_ids=["missing"],
        )["decision"]
        == "RERUN"
    )

    tampered = dict(packet)
    tampered["candidate_sha256"] = "c" * 64
    with pytest.raises(AnalysisEvidenceError, match="packet hash"):
        validate_review_evidence(tampered)


def test_review_evidence_rejects_source_receipt_hash_mismatch() -> None:
    from hashlib import sha256

    receipt = {
        "candidate_sha256": "a" * 64,
        "findings": [],
        "report_hashes": {"codeql": "invalid"},
    }
    receipt["receipt_sha256"] = sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    with pytest.raises(AnalysisEvidenceError, match="report hash"):
        build_review_evidence(receipt)


def test_review_evidence_rejects_report_body_mismatch() -> None:
    from hashlib import sha256

    receipt = {
        "candidate_sha256": "a" * 64,
        "findings": [],
        "report_hashes": {"codeql": "b" * 64},
    }
    receipt["receipt_sha256"] = sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    report = {
        "analyzer": {"id": "codeql"},
        "execution_successful": True,
        "normalized_sha256": "b" * 64,
    }
    with pytest.raises(AnalysisEvidenceError, match="normalized report"):
        build_review_evidence(receipt, reports=[report])


def test_execution_packet_binds_persisted_six_lane_evidence(tmp_path: Path) -> None:
    import hashlib

    candidate = "a" * 64
    lanes = []
    plan_lanes = []
    for index in range(6):
        lane_id = f"lane-{index}"
        engine = f"engine-{index}"
        plan_lanes.append({"id": lane_id, "engine": engine})
        lanes.append(
            {
                "lane_id": lane_id,
                "engine": engine,
                "family": "runtime" if index == 0 else "static",
                "state": "OBSERVED",
                "gaps": [],
                "report_sha256": str(index) * 64,
                "coverage_sha256": str(index + 1) * 64,
                "findings": (
                    [
                        {
                            "rule_id": "R1",
                            "kind": "fail",
                            "level": "warning",
                            "locations": [
                                {"path": "src/app.py", "source_sha256": "f" * 64}
                            ],
                            "flows": [],
                        }
                    ]
                    if index == 0
                    else []
                ),
            }
        )
    state = {
        "candidate_sha256": candidate,
        "run_id": "run-1",
        "lanes": lanes,
        "findings": [],
    }
    canonical = json.dumps(
        state,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    state_file = tmp_path / "evidence.json"
    state_file.write_bytes(
        json.dumps(
            {**state, "sha256": hashlib.sha256(canonical).hexdigest()},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    )
    packet = build_execution_review_evidence(state, {"lanes": plan_lanes}, state_file)
    assert validate_review_evidence(packet) == packet
    assert (
        len([item for item in packet["evidence"] if item["kind"] == "lane_observation"])
        == 6
    )
    assert len(packet["claims"]) == 1
    assert "not a confirmed defect" in packet["claims"][0]["statement"]
    assert any(
        item["id"].startswith("runtime_evidence:") for item in packet["unknowns"]
    )
    state_file.write_text("{}", encoding="utf-8")
    with pytest.raises(AnalysisEvidenceError, match="does not match returned state"):
        build_execution_review_evidence(state, {"lanes": plan_lanes}, state_file)
