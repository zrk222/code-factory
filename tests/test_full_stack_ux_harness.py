from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from hashlib import sha256
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import shutil
import tempfile
import threading
from urllib.parse import urlsplit
import sys
from pathlib import Path

import pytest

from factoryline import full_stack_ux_harness as comparison
from factoryline.cli import main
from factoryline.journey_proof import compile_reality_graph
from factoryline.full_stack_ux_harness import (
    CORE_CHECKS,
    JUDGMENTS,
    UI_CHECKS,
    FullStackUXHarnessError,
    quality_harness_template,
    render_journey_comparison,
    run_visual_behavior_gate,
    verify_visual_behavior_receipt,
    verify_quality_harness,
)
from factoryline.optimizer import optimize_pr


def _write_manifest(root: Path, *, ui: bool = True) -> Path:
    evidence = root / "native-checks.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    manifest = quality_harness_template(ui_in_scope=ui)
    for check in manifest["checks"]:
        check.update(
            state="passed", provenance="trusted_source", evidence=[evidence.name]
        )
    manifest["reviewer"] = {"name": "Release Owner", "type": "human"}
    for judgment in manifest["judgments"]:
        judgment.update(
            approved=True,
            rationale=f"Reviewed {judgment['id']} against the stated user task and evidence.",
        )
    path = root / "quality.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def test_template_has_closed_core_ui_and_judgment_sets():
    ui = quality_harness_template(ui_in_scope=True)
    non_ui = quality_harness_template(ui_in_scope=False)
    assert [item["id"] for item in ui["checks"]] == [*CORE_CHECKS, *UI_CHECKS]
    assert [item["id"] for item in non_ui["checks"]] == list(CORE_CHECKS)
    assert [item["id"] for item in ui["judgments"]] == list(JUDGMENTS)
    assert all(
        item["state"] == "unknown" and item["provenance"] == "agent_proposed"
        for item in ui["checks"]
    )


def test_complete_manifest_is_hash_bound_but_retains_zero_authority(tmp_path: Path):
    result = verify_quality_harness(tmp_path, _write_manifest(tmp_path))
    assert result["decision"] == "READY_FOR_HUMAN_RELEASE_REVIEW"
    assert result["findings"] == []
    assert len(result["checks"]) == 19
    assert set(result["evidence_classes"]) == {"deterministic", "heuristic"}
    assert all(value is False for value in result["authority"].values())
    assert result["review_identity"]["authenticated"] is False
    stored = json.loads(Path(result["path"]).read_text(encoding="utf-8"))
    core = {
        key: value
        for key, value in stored.items()
        if key not in {"receipt_sha256", "generated_at"}
    }
    digest = hashlib.sha256(
        json.dumps(
            core,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    ).hexdigest()
    assert stored["receipt_sha256"] == digest
    assert "not authenticated identity" in stored["claim_boundary"]


def test_agent_cannot_approve_human_judgments(tmp_path: Path):
    path = _write_manifest(tmp_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["reviewer"] = {"name": "coding-agent", "type": "agent"}
    path.write_text(json.dumps(manifest), encoding="utf-8")
    result = verify_quality_harness(tmp_path, path)
    assert result["decision"] == "BLOCKED"
    assert any(
        item["code"] == "E_UX_HUMAN_REVIEW_REQUIRED" for item in result["findings"]
    )


def test_ui_check_cannot_be_omitted_or_reclassified_as_non_ui(tmp_path: Path):
    path = _write_manifest(tmp_path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["checks"] = [
        item for item in manifest["checks"] if item["id"] != "ui.keyboard_navigation"
    ]
    path.write_text(json.dumps(manifest), encoding="utf-8")
    result = verify_quality_harness(tmp_path, path)
    assert result["decision"] == "BLOCKED"
    assert result["findings"] == [
        {
            "code": "E_UX_CHECK_SET_MISMATCH",
            "detail": "expected exactly 19 closed check identifiers",
        }
    ]


def test_agent_proposed_check_remains_blocked_even_when_marked_passed(tmp_path: Path):
    path = _write_manifest(tmp_path, ui=False)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["checks"][0]["provenance"] = "agent_proposed"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    result = verify_quality_harness(tmp_path, path)
    assert result["decision"] == "BLOCKED"
    assert any(item["code"] == "E_UX_CHECK_PROVENANCE" for item in result["findings"])


def test_short_or_rejected_human_rationale_blocks(tmp_path: Path):
    path = _write_manifest(tmp_path, ui=False)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["judgments"][0].update(approved=False, rationale="too short")
    path.write_text(json.dumps(manifest), encoding="utf-8")
    result = verify_quality_harness(tmp_path, path)
    assert result["decision"] == "BLOCKED"
    assert {item["code"] for item in result["findings"]} == {
        "E_UX_HUMAN_REVIEW_REQUIRED"
    }


def test_evidence_path_escape_is_rejected(tmp_path: Path):
    path = _write_manifest(tmp_path, ui=False)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["checks"][0]["evidence"] = ["../outside.json"]
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(FullStackUXHarnessError) as caught:
        verify_quality_harness(tmp_path, path)
    assert caught.value.code == "E_UX_EVIDENCE_PATH"


def test_receipt_cannot_replace_manifest_even_with_equivalent_relative_path(
    tmp_path: Path,
):
    path = _write_manifest(tmp_path, ui=False)
    with pytest.raises(FullStackUXHarnessError) as caught:
        verify_quality_harness(tmp_path, path, out=Path(".") / path.name)
    assert caught.value.code == "E_UX_RECEIPT_PATH"
    assert (
        json.loads(path.read_text(encoding="utf-8"))["schema"]
        == "factory.full-stack-ux-harness.manifest.v1"
    )


def test_unknown_manifest_fields_are_rejected_instead_of_ignored(tmp_path: Path):
    path = _write_manifest(tmp_path, ui=False)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["release_override"] = True
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(FullStackUXHarnessError) as caught:
        verify_quality_harness(tmp_path, path)
    assert caught.value.code == "E_UX_MANIFEST_SCHEMA"


def test_duplicate_evidence_is_blocked(tmp_path: Path):
    path = _write_manifest(tmp_path, ui=False)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["checks"][0]["evidence"] = ["native-checks.json", "native-checks.json"]
    path.write_text(json.dumps(manifest), encoding="utf-8")
    result = verify_quality_harness(tmp_path, path)
    assert result["decision"] == "BLOCKED"
    assert any(
        item["code"] == "E_UX_CHECK_EVIDENCE_DUPLICATE" for item in result["findings"]
    )


def test_cli_writes_template_and_returns_nonzero_until_review_is_complete(
    tmp_path: Path, capsys
):
    assert (
        main(
            [
                "quality-harness",
                "template",
                "--root",
                str(tmp_path),
                "--ui",
                "--out",
                "quality.json",
                "--json",
            ]
        )
        == 0
    )
    template = json.loads(capsys.readouterr().out)
    assert Path(template["path"]).is_file()
    assert (
        main(
            [
                "quality-harness",
                "verify",
                "quality.json",
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 1
    )
    result = json.loads(capsys.readouterr().out)
    assert result["decision"] == "BLOCKED"


def test_frontend_diff_routes_to_quality_harness_and_prestige(tmp_path: Path):
    result = optimize_pr(tmp_path, changed=["src/App.tsx"], feature="ui")
    assert "quality-harness:verify" in result["recommended_stages"]
    assert "prestige:audit" in result["recommended_stages"]


def test_intent_envelope_binds_the_approved_quality_harness_spec():
    root = Path(__file__).parents[1]
    spec = (
        (root / "specs" / "full-stack-ux-harness-v1.md")
        .read_text(encoding="utf-8")
        .replace("\r\n", "\n")
    )
    envelope = json.loads(
        (root / "envelopes" / "full-stack-ux-harness-v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert envelope["source"] == "specs/full-stack-ux-harness-v1.md"
    assert envelope["sealed_hash"] == hashlib.sha256(spec.encode("utf-8")).hexdigest()
    assert envelope["coherence_score"] == 100
    assert envelope["assumptions"]


def _visual_binding(root: Path, path: Path, kind="source"):
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "kind": kind,
    }


def _visual_contract(root: Path, target="http://127.0.0.1:8765/"):
    source = root / "app.html"
    source.write_text(
        '<button id="save">Save</button><p id="state">Ready</p>', encoding="utf-8"
    )
    return {
        "schema": "factory.visual-behavior.contract.v1",
        "fixture_only": True,
        "project_id": "generic-web",
        "journey_id": "save",
        "candidate": [_visual_binding(root, source)],
        "reviewer": {"name": "Test Owner", "type": "human"},
        "target": target,
        "browser": {
            "executable": sys.executable,
            "version": "test-unexecuted",
            "platform": sys.platform,
            "width": 640,
            "height": 480,
        },
        "design": None,
        "cases": [
            {
                "id": "ready",
                "baseline": None,
                "action": None,
                "element": {
                    "selector": "#save",
                    "role": "button",
                    "name": "Save",
                    "enabled": True,
                },
                "state": {"selector": "#state", "text": "Ready"},
                "response": None,
                "tokens": [],
                "timeout_ms": 500,
                "max_changed_ratio": 0.0,
            }
        ],
    }


def _visual_write(root: Path, contract):
    path = root / "visual-contract.json"
    path.write_text(json.dumps(contract, allow_nan=False), encoding="utf-8")
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_visual_journey_step_trace_respects_order_and_explicit_failure():
    from factoryline.full_stack_ux_harness import _visual_step_findings

    expected = {"steps": [{"id": "dismiss"}, {"id": "return to form"}]}
    findings = []

    def add(*finding):
        findings.append(finding)

    _visual_step_findings(expected, {"steps": [{"id": "dismiss", "ok": False}]}, add)
    assert findings.pop()[0] == "E_VISUAL_STEP"

    for invalid in (
        [],
        [{"id": "dismiss", "ok": True}],
        [{"id": "return to form", "ok": False}],
        [{"id": "dismiss", "ok": 0}],
        [{"id": "dismiss", "ok": False}, {"id": "return to form", "ok": True}],
    ):
        _visual_step_findings(expected, {"steps": invalid}, add)
        assert findings.pop()[0] == "E_VISUAL_STEP_EVIDENCE"


@pytest.mark.parametrize(
    "step",
    [
        {"id": "step", "kind": "press", "selector": "button", "value": "Control+Alt+x"},
        {"id": "step", "kind": "count", "selector": "main", "value": True},
        {"id": "step", "kind": "click", "selector": "button", "value": "anything"},
    ],
)
def test_visual_journey_rejects_unsupported_steps(step):
    from factoryline.full_stack_ux_harness import (
        FullStackUXHarnessError,
        _visual_steps_contract,
    )

    with pytest.raises(FullStackUXHarnessError, match="unsupported|bounds"):
        _visual_steps_contract([step])


def test_visual_noexecute_never_discovers_tools_or_launches(tmp_path, monkeypatch):
    import factoryline.full_stack_ux_harness as harness

    def forbidden(*args, **kwargs):
        raise AssertionError("noexecute must not discover or launch native tools")

    monkeypatch.setattr(harness, "_visual_tool_identity", forbidden)
    path, pin = _visual_write(tmp_path, _visual_contract(tmp_path))
    result = harness.run_visual_behavior_gate(tmp_path, path, pin)
    assert result["decision"] == "NOT_RUN"
    assert (tmp_path / "app.html").read_text().startswith("<button")


@pytest.mark.parametrize(
    "mutation",
    [
        "pin",
        "forged",
        "remote",
        "agent",
        "empty",
        "duplicate",
        "threshold",
        "deadline",
        "response",
        "escape",
        "source_hash",
        "empty_cases",
        "duplicate_cases",
        "width",
        "css_property",
        "fixture_false",
        "fixture_absent",
    ],
)
def test_visual_admission_rejects_untrusted_contract_before_execution(
    tmp_path, monkeypatch, mutation
):
    import factoryline.full_stack_ux_harness as harness

    def forbidden(*args, **kwargs):
        raise AssertionError("invalid contract reached tool discovery")

    monkeypatch.setattr(harness, "_visual_tool_identity", forbidden)
    contract = _visual_contract(tmp_path)
    case = contract["cases"][0]
    mutations = {
        "pin": lambda: None,
        "forged": lambda: case.update(passed=True),
        "remote": lambda: contract.update(target="https://example.com/"),
        "agent": lambda: contract["reviewer"].update(type="agent"),
        "empty": lambda: contract.update(candidate=[]),
        "duplicate": lambda: contract.update(candidate=contract["candidate"] * 2),
        "threshold": lambda: case.update(max_changed_ratio=0.02),
        "deadline": lambda: case.update(timeout_ms=True),
        "escape": lambda: contract["candidate"][0].update(path="../outside.html"),
        "source_hash": lambda: contract["candidate"][0].update(sha256="0" * 64),
        "empty_cases": lambda: contract.update(cases=[]),
        "duplicate_cases": lambda: contract.update(cases=contract["cases"] * 2),
        "width": lambda: contract["browser"].update(width=319),
        "css_property": lambda: case.update(
            tokens=[{"selector": "body", "property": "behavior", "value": "evil"}]
        ),
        "fixture_false": lambda: contract.update(fixture_only=False),
        "fixture_absent": lambda: contract.pop("fixture_only"),
        "response": lambda: case.update(
            response={
                "method": "POST",
                "path": "/save",
                "status": 200,
                "field": "saved",
                "value": True,
                "correlation": {"header": "x-cf-action", "value": "ready"},
            }
        ),
    }
    mutations[mutation]()
    path, pin = _visual_write(tmp_path, contract)
    with pytest.raises((FullStackUXHarnessError, ValueError)):
        harness.run_visual_behavior_gate(
            tmp_path, path, "0" * 64 if mutation == "pin" else pin, execute=True
        )


def test_visual_missing_optional_tool_is_incomplete_not_passed(tmp_path, monkeypatch):
    import factoryline.full_stack_ux_harness as harness

    def unavailable(*args, **kwargs):
        raise ImportError("owned missing optional capture tool control")

    monkeypatch.setattr(harness, "_visual_tool_identity", unavailable)
    path, pin = _visual_write(tmp_path, _visual_contract(tmp_path))
    result = harness.run_visual_behavior_gate(tmp_path, path, pin, execute=True)
    assert result["decision"] == "INCOMPLETE"
    assert result["findings"]


@pytest.mark.parametrize("failure", ["crash", "timeout", "cleanup"])
def test_visual_failed_child_execution_never_passes(tmp_path, monkeypatch, failure):
    import factoryline.full_stack_ux_harness as harness
    import factoryline.assembly_process as process

    def failed_child(*args, **kwargs):
        return {
            "exit_code": 1 if failure == "crash" else 0,
            "ok": False,
            "cleanup_confirmed": failure != "cleanup",
            "reason": "timeout" if failure == "timeout" else "process_exit",
            "streams_closed": True,
            "stdout": b"",
            "stderr": b"",
        }

    monkeypatch.setattr(harness, "_visual_tool_identity", lambda: {})
    monkeypatch.setattr(process, "run_cli_detailed", failed_child)
    path, pin = _visual_write(tmp_path, _visual_contract(tmp_path))
    result = harness.run_visual_behavior_gate(tmp_path, path, pin, execute=True)
    assert result["decision"] == "INCOMPLETE"
    assert result["execution"]["cleanup_confirmed"] is (failure != "cleanup")
    assert any(item["code"] == "E_VISUAL_EXECUTION" for item in result["findings"])


@pytest.mark.parametrize("missing", ["ok", "reason"])
def test_visual_process_requires_explicit_success_facts(missing):
    import factoryline.full_stack_ux_harness as harness

    facts = {
        "ok": True,
        "exit_code": 0,
        "cleanup_confirmed": True,
        "streams_closed": True,
        "reason": None,
        "deadline_seconds": 60,
        "duration_ms": 1,
    }
    del facts[missing]
    assert harness._visual_process_findings(facts)


@pytest.mark.parametrize("reader", ["json", "artifact"])
def test_visual_file_budget_is_bounded_before_reading_all_bytes(
    tmp_path, monkeypatch, reader
):
    import io
    import factoryline.full_stack_ux_harness as harness

    path = tmp_path / "oversized.json"
    path.write_bytes(b"x")
    requests = []

    class LargeStream(io.BytesIO):
        def read(self, size=-1):
            requests.append(size)
            assert 0 < size <= harness.MAX_EVIDENCE_BYTES + 1
            return b"x" * size

    original = Path.open

    def bounded_open(current, mode="r", *args, **kwargs):
        if current == path and mode == "rb":
            return LargeStream()
        return original(current, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", bounded_open)
    with pytest.raises((FullStackUXHarnessError, ValueError)):
        if reader == "json":
            harness._visual_read(path)
        else:
            harness._visual_artifact(tmp_path, path, "observation")
    assert requests


def _visual_replay_tamper_controls(tmp_path, approved, harness):
    original_receipt = json.loads(Path(approved["path"]).read_text())

    def reject_resealed(value, name):
        value["receipt_sha256"] = harness._sha(
            {key: item for key, item in value.items() if key != "receipt_sha256"}
        )
        target = tmp_path / f"tamper-{name}.json"
        target.write_text(json.dumps(value))
        try:
            replay = harness.verify_visual_behavior_receipt(tmp_path, target)
        except (FullStackUXHarnessError, ValueError, OSError):
            return
        assert replay["decision"] != "PASS", name

    for omission in ("all", "screenshot", "accessibility", "observations"):
        changed = json.loads(json.dumps(original_receipt))
        changed["artifacts"] = (
            []
            if omission == "all"
            else [item for item in changed["artifacts"] if item["kind"] != omission]
        )
        reject_resealed(changed, omission)
    for field, replacement in (("sha256", "0" * 64), ("path", "reviewed.png")):
        changed = json.loads(json.dumps(original_receipt))
        changed["cases"][0]["screenshot"][field] = replacement
        reject_resealed(changed, field)
    changed = json.loads(json.dumps(original_receipt))
    changed["cases"][0]["accessible_snapshot"] = '- button "Invented"'
    reject_resealed(changed, "inline-aria")
    aria = next(
        item
        for item in original_receipt["artifacts"]
        if item["kind"] == "accessibility"
    )
    aria_path = tmp_path / aria["path"]
    aria_bytes = aria_path.read_bytes()
    aria_path.unlink()
    reject_resealed(json.loads(json.dumps(original_receipt)), "missing-aria")
    aria_path.write_bytes(aria_bytes)
    capture_path = tmp_path / original_receipt["cases"][0]["screenshot"]["path"]
    capture_bytes = capture_path.read_bytes()
    capture_path.write_bytes(capture_bytes + b"changed")
    reject_resealed(json.loads(json.dumps(original_receipt)), "changed-png")
    capture_path.write_bytes(capture_bytes)


def _visual_runtime_negative_controls(
    tmp_path, capsys, contract, behavior, run, baseline, baseline_bytes, quality
):
    for mode in ("pixel", "hidden", "unnamed"):
        behavior["mode"] = mode
        observed = run()
        assert observed["decision"] == "FAIL", (mode, observed)
        if mode == "pixel":
            assert any(
                item["code"] == "E_VISUAL_TOKEN" for item in observed["findings"]
            )
        assert baseline.read_bytes() == baseline_bytes

    behavior["mode"] = "dishonest"
    case = contract["cases"][0]
    case.update(
        action={"selector": ".control"},
        state={"selector": "#state", "text": "Saved"},
        response={
            "method": "GET",
            "path": "/api/save",
            "status": 200,
            "field": "saved",
            "value": True,
            "correlation": {"header": "x-cf-action", "value": "ready"},
        },
    )
    dishonest = run()
    assert dishonest["decision"] == "FAIL"
    assert dishonest["cases"][0]["state_text"] == "Saved"
    assert (
        main(
            [
                "quality-harness",
                "verify",
                str(quality),
                "--visual-receipt",
                dishonest["path"],
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["decision"] == "BLOCKED"
    assert any(item["code"] == "E_VISUAL_RUNTIME" for item in dishonest["findings"])
    assert "PRIVATE_RESPONSE_SENTINEL_8237" not in json.dumps(dishonest)
    for artifact in dishonest["artifacts"]:
        if artifact["path"].endswith(".json"):
            assert (
                "PRIVATE_RESPONSE_SENTINEL_8237"
                not in (tmp_path / artifact["path"]).read_text()
            )
    behavior["mode"] = "stuck"
    assert run()["decision"] == "INCOMPLETE"
    behavior["mode"] = "ready"
    case["response"]["correlation"]["value"] = "wrong-owned-action"
    wrong_action = run()
    assert wrong_action["decision"] == "FAIL"
    assert any(item["code"] == "E_VISUAL_RUNTIME" for item in wrong_action["findings"])
    case["response"]["correlation"]["value"] = "ready"
    for mode in ("missing-length", "oversize-length", "encoded", "chunked"):
        behavior["mode"] = mode
        assert run()["decision"] == "INCOMPLETE", mode
    behavior["mode"] = "multiple"
    assert run()["decision"] == "INCOMPLETE"
    case["response"]["path"] = "/never-observed"
    assert run()["decision"] == "INCOMPLETE"


class _VisualApp(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _api_response(self, mode):
        body = b'{"saved":true,"private":"PRIVATE_RESPONSE_SENTINEL_8237"}'
        self.send_response(500 if mode == "dishonest" else 200)
        self.send_header("Content-Type", "application/json")
        if mode not in {"missing-length", "chunked"}:
            self.send_header(
                "Content-Length",
                str(10_000_001 if mode == "oversize-length" else len(body)),
            )
        if mode == "encoded":
            self.send_header("Content-Encoding", "identity")
        if mode == "chunked":
            self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        self.wfile.write(
            (f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
            if mode == "chunked"
            else body
        )

    def do_GET(self):
        mode = self.server.visual_behavior["mode"]
        if self.path == "/api/save":
            self._api_response(mode)
            return
        html = (self.server.visual_root / "app.html").read_text(encoding="utf-8")
        if mode == "source-drift":
            (self.server.visual_root / "app.html").write_text(
                html + "<!-- concurrent drift -->", encoding="utf-8"
            )
        if mode == "pixel":
            html = html.replace("#ffffff", "#000000")
        if mode == "hidden":
            html = html.replace('id="save"', 'id="save" hidden')
        if mode == "unnamed":
            html = html.replace(">Save</button>", "></button>")
        if mode == "multiple":
            html = html.replace(
                "fetch('/api/save',",
                "fetch('/api/save',{headers:{'x-cf-action':'ready'}});fetch('/api/save',",
            )
        if mode == "stuck":
            html = html.replace("textContent='Saved'", "textContent='Working'")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())


def test_visual_route_does_not_follow_redirects(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    import factoryline.full_stack_ux_harness as harness

    pytest.importorskip("playwright.sync_api")
    monkeypatch.setattr("time.monotonic", lambda: 1.0)
    target = "http://127.0.0.1:4000/"
    route = Mock(request=SimpleNamespace(url=target))
    route.fetch.return_value.status = 302
    route.fetch.return_value.headers = {"location": "/fixture-next"}
    harness._visual_route(route, target, 2.0)
    route.fetch.assert_called_once_with(max_redirects=0, timeout=1000)
    route.abort.assert_called_once_with("blockedbyclient")
    route.fulfill.assert_not_called()


def test_visual_replay_reports_unavailable_optional_dependencies(monkeypatch, tmp_path):
    import factoryline.full_stack_ux_harness as harness

    def unavailable(*args):
        raise ImportError("optional tool unavailable")

    monkeypatch.setattr(harness, "_visual_tool_identity", unavailable)
    monkeypatch.setattr(harness, "_visual_prestige", unavailable)
    assert (
        harness._visual_profile_findings({"browser": {}}, {})[0]["code"]
        == "E_VISUAL_PROFILE"
    )
    assert (
        harness._visual_prestige_replay(tmp_path, {}, {})[0]["code"]
        == "E_VISUAL_PRESTIGE"
    )


def test_visual_real_browser_pixels_semantics_runtime_and_prestige(tmp_path, capsys):
    """Exposed local detector acceptance, never a production accuracy claim."""
    from http.server import ThreadingHTTPServer
    import threading
    import shutil
    import factoryline.full_stack_ux_harness as harness

    # Required native CI never skips; optional jobs only skip absent packages.
    if any(
        __import__("os").environ.get(flag) == "1"
        for flag in ("FACTORY_REQUIRE_NATIVE_VISUAL", "FACTORY_VISUAL_ACCEPTANCE")
    ):
        from playwright.sync_api import sync_playwright
        import prestige_design

        assert prestige_design.__version__
    else:
        sync_playwright = pytest.importorskip("playwright.sync_api").sync_playwright
        pytest.importorskip("prestige_design")
    with sync_playwright() as playwright:
        executable = playwright.chromium.executable_path
        browser = playwright.chromium.launch(headless=True)
        version = browser.version
        browser.close()

    behavior = {"mode": "ready"}

    server = ThreadingHTTPServer(("127.0.0.1", 0), _VisualApp)
    server.visual_root = tmp_path
    server.visual_behavior = behavior
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        contract = _visual_contract(tmp_path, f"http://127.0.0.1:{server.server_port}/")
        source = tmp_path / "app.html"
        source.write_text(
            "<style>body {background:#ffffff;margin:8px}</style>"
            "<button id=\"save\" class=\"control\" onclick=\"fetch('/api/save',{headers:{'x-cf-action':'ready'}}).then(()=>document.querySelector('#state').textContent='Saved')\">Save</button>"
            '<button class="control">Cancel</button>'
            '<p id="state">Ready</p>',
            encoding="utf-8",
        )
        contract["candidate"] = [_visual_binding(tmp_path, source)]
        contract["browser"].update(executable=executable, version=version)
        contract["cases"][0]["timeout_ms"] = 5000
        contract["cases"][0]["tokens"] = [
            {
                "selector": "body",
                "property": "background-color",
                "value": "rgb(255, 255, 255)",
            }
        ]
        design = tmp_path / "DESIGN.md"
        design.write_text(
            '```design-tokens\n{"spacing":["8px"],"font_size":[],"font_weight":[],"radius":[],"color":["#ffffff"]}\n```',
            encoding="utf-8",
        )
        contract["design"] = {
            "contract": _visual_binding(tmp_path, design),
            "html": _visual_binding(tmp_path, source),
            "css": [],
        }

        def run():
            path, pin = _visual_write(tmp_path, contract)
            code = main(
                [
                    "quality-harness",
                    "visual",
                    str(path),
                    "--contract-sha256",
                    pin,
                    "--execute",
                    "--root",
                    str(tmp_path),
                    "--json",
                ]
            )
            result = json.loads(capsys.readouterr().out)
            assert code == (0 if result["decision"] == "PASS" else 1)
            return result

        path, pin = _visual_write(tmp_path, contract)
        assert (
            main(
                [
                    "quality-harness",
                    "visual",
                    str(path),
                    "--contract-sha256",
                    pin,
                    "--root",
                    str(tmp_path),
                    "--json",
                ]
            )
            == 1
        )
        assert json.loads(capsys.readouterr().out)["decision"] == "NOT_RUN"

        proposed = run()
        assert proposed["decision"] == "INCOMPLETE", proposed
        screenshots = [
            item for item in proposed["artifacts"] if item["path"].endswith(".png")
        ]
        assert len(screenshots) == 1
        baseline = tmp_path / "reviewed.png"
        shutil.copyfile(tmp_path / screenshots[0]["path"], baseline)
        baseline_bytes = baseline.read_bytes()
        contract["cases"][0]["baseline"] = _visual_binding(
            tmp_path, baseline, "baseline"
        )
        approved = run()
        assert approved["decision"] == "PASS", approved
        approved_contract_bytes = (tmp_path / "visual-contract.json").read_bytes()
        _visual_replay_tamper_controls(tmp_path, approved, harness)
        quality = _write_manifest(tmp_path)
        visual_source = Path(approved["path"])
        visual_before = visual_source.read_bytes()
        with pytest.raises(
            harness.FullStackUXHarnessError, match="differ from its inputs"
        ):
            harness.verify_quality_harness(
                tmp_path,
                quality,
                visual_receipt=visual_source,
                out=visual_source.relative_to(tmp_path),
            )
        assert visual_source.read_bytes() == visual_before
        assert (
            main(
                [
                    "quality-harness",
                    "verify",
                    str(quality),
                    "--visual-receipt",
                    approved["path"],
                    "--root",
                    str(tmp_path),
                    "--json",
                ]
            )
            == 0
        )
        included = json.loads(capsys.readouterr().out)
        assert included["decision"] == "READY_FOR_HUMAN_RELEASE_REVIEW"
        assert (
            harness.verify_visual_behavior_receipt(tmp_path, Path(approved["path"]))[
                "decision"
            ]
            == "PASS"
        )
        tampered = json.loads(Path(approved["path"]).read_text())
        del tampered["identity"]["executable_sha256"]
        tampered["receipt_sha256"] = harness._sha(
            {key: value for key, value in tampered.items() if key != "receipt_sha256"}
        )
        tampered_path = tmp_path / "missing-identity.json"
        tampered_path.write_text(json.dumps(tampered))
        assert (
            harness.verify_visual_behavior_receipt(tmp_path, tampered_path)["decision"]
            == "INCOMPLETE"
        )
        _visual_runtime_negative_controls(
            tmp_path, capsys, contract, behavior, run, baseline, baseline_bytes, quality
        )
        contract = json.loads(approved_contract_bytes)
        behavior["mode"] = "source-drift"
        clean_source = source.read_bytes()
        assert run()["decision"] == "INCOMPLETE"
        source.write_bytes(clean_source)
        behavior["mode"] = "ready"
        design_bytes = design.read_bytes()
        design.write_text(design.read_text().replace('["8px"]', "[]"), encoding="utf-8")
        contract["design"]["contract"] = _visual_binding(tmp_path, design)
        assert run()["decision"] == "FAIL"
        design.write_bytes(design_bytes)

        # Reviewed source and baseline drift must invalidate an earlier PASS.
        (tmp_path / "visual-contract.json").write_bytes(approved_contract_bytes)
        source.write_text(source.read_text() + "<!-- drift -->", encoding="utf-8")
        with pytest.raises((FullStackUXHarnessError, ValueError)):
            harness.verify_visual_behavior_receipt(tmp_path, Path(approved["path"]))
        source.write_text(
            source.read_text().replace("<!-- drift -->", ""), encoding="utf-8"
        )
        baseline.write_bytes(baseline_bytes + b"tampered")
        with pytest.raises((FullStackUXHarnessError, ValueError)):
            harness.verify_visual_behavior_receipt(tmp_path, Path(approved["path"]))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


# Journey receipt comparison and HTML report


def _record(root, *, source=None, target="http://127.0.0.1:8765/", mutate=None):
    root.mkdir(exist_ok=True)
    contract = _visual_contract(root, target)
    if source is not None:
        path = root / "app.html"
        path.write_bytes(source)
        contract["candidate"] = [_visual_binding(root, path)]
    if mutate is not None:
        mutate(contract)
    path, pin = _visual_write(root, contract)
    return comparison.run_visual_behavior_gate(root, path, pin)["path"]


@pytest.fixture
def replayed_captures(monkeypatch):
    """Exercise comparison with controlled outcomes after receipt replay."""
    original = comparison._verify_visual_behavior
    observations = {}

    def verify(root, receipt):
        verified, contract, independent = original(root, receipt)
        if receipt in observations:
            status, profile, findings, *cases = observations[receipt]
            verified.update(decision=status, identity=profile, findings=findings)
            independent = cases[1] if len(cases) > 1 else findings
            if cases:
                verified.update(cases=cases[0])
        return verified, contract, independent

    monkeypatch.setattr(comparison, "_verify_visual_behavior", verify)
    return observations


def test_comparison_read_only_and_stable(tmp_path, replayed_captures):
    before, after = tmp_path / "before", tmp_path / "after"
    original = b"<p>Error</p>\n"
    repaired = b"<p>Saved</p>\n"
    first = _record(before, source=original)
    second = _record(after, source=repaired, target="http://127.0.0.1:8766/")
    detail = comparison._visual_finding(
        "E_VISUAL_RUNTIME", "same-action API/UI mismatch", case_id="ready"
    )
    profile = {"browser": "same", "viewport": {"width": 640, "height": 480}}
    replayed_captures.update(
        {first: ("FAIL", profile, [detail, detail]), second: ("PASS", profile, [])}
    )
    files = set(tmp_path.rglob("*"))
    result = comparison.compare_journey_evidence(before, first, after, second)
    assert result == comparison.compare_journey_evidence(before, first, after, second)
    assert result["status"] == "PASS"
    assert result["before"]["findings"] == [detail]
    assert (
        result["before"]["receipt_sha256"]
        == json.loads(Path(first).read_text(encoding="utf-8"))["receipt_sha256"]
    )
    assert result["cases"] == [
        {"id": "ready", "before_status": "FAIL", "after_status": "PASS"}
    ]
    assert result["source_diff"] == {
        "status": "AVAILABLE",
        "text": "--- a/app.html\n+++ b/app.html\n@@ -1 +1 @@\n-<p>Error</p>\n+<p>Saved</p>\n",
        "truncated": False,
    }
    assert result["component_hints"][0]["after_sha256"] == comparison._sha(repaired)
    assert result["next_action"] is None
    assert not any(result["authority"].values())
    assert set(tmp_path.rglob("*")) == files
    assert (before / "app.html").read_bytes() == original
    assert (after / "app.html").read_bytes() == repaired


def test_current_noexecute_stale_and_malformed_fail_closed(tmp_path):
    receipt = _record(tmp_path)
    skipped = comparison.compare_journey_evidence(tmp_path, receipt, tmp_path, receipt)
    assert skipped["status"] == "INCOMPLETE"
    assert skipped["before"]["status"] == "NOT_RUN"
    assert skipped["source_diff"]["status"] == "UNAVAILABLE"
    (tmp_path / "app.html").write_text("stale", encoding="utf-8")
    stale = comparison.compare_journey_evidence(tmp_path, receipt, tmp_path, receipt)
    assert stale["status"] == "INCOMPLETE"
    assert stale["before"]["receipt_sha256"] is None
    assert stale["findings"][0]["code"] == "E_VISUAL_SOURCE_DRIFT"
    broken = tmp_path / "malformed.json"
    broken.write_text('{"same": 1, "same": 2}', encoding="utf-8")
    result = comparison.compare_journey_evidence(tmp_path, broken, tmp_path, receipt)
    assert result["status"] == "INCOMPLETE"
    assert result["before"]["findings"][0]["code"] == "E_VISUAL_SCHEMA"
    assert not result["component_hints"]


@pytest.mark.parametrize(
    "difference", ["case", "profile", "browser", "target", "component"]
)
def test_nonequivalent_comparison_has_no_preview(
    tmp_path, replayed_captures, difference
):
    before, after = tmp_path / "before", tmp_path / "after"
    first = _record(before)

    def mutate(contract):
        if difference == "case":
            contract["cases"][0]["state"]["text"] = "Other expected state"
        if difference == "browser":
            contract["browser"]["width"] = 800
        if difference == "component":
            contract["candidate"][0]["kind"] = "other"

    target = "http://127.0.0.1:8766/" + ("other" if difference == "target" else "")
    second = _record(after, source=b"<p>Changed</p>", target=target, mutate=mutate)
    replayed_captures[first] = ("PASS", {"browser": "same"}, [])
    replayed_captures[second] = (
        "PASS",
        {"browser": "different" if difference == "profile" else "same"},
        [],
    )
    result = comparison.compare_journey_evidence(before, first, after, second)
    assert result["status"] == "INCOMPLETE"
    assert result["cases"] == result["component_hints"] == []
    assert result["source_diff"]["status"] == "UNAVAILABLE"
    expected = "E_JOURNEY_PROFILE" if difference == "profile" else "E_JOURNEY_SCOPE"
    assert result["findings"][0]["code"] == expected


@pytest.mark.parametrize(
    ("source", "status", "truncated"),
    [
        (b"old\n", "UNCHANGED", False),
        (b"0000000000000000000000\n" * 500, "AVAILABLE", True),
        ((b"a" * 1_000 + b"\n") * 24, "AVAILABLE", True),
        (b"\x1b[31m", "UNAVAILABLE", False),
        (b"x" * (comparison.MAX_SOURCE_BYTES + 1), "UNAVAILABLE", False),
    ],
    ids=[
        "unchanged",
        "line-bound",
        "preview-byte-bound",
        "control-character",
        "source-byte-bound",
    ],
)
def test_diff_limits_and_observed_failure(
    tmp_path, replayed_captures, source, status, truncated
):
    before, after = tmp_path / "before", tmp_path / "after"
    first = _record(before, source=b"old\n")
    second = _record(after, source=source)
    replayed_captures[first] = ("PASS", {}, [])
    replayed_captures[second] = (
        "FAIL",
        {},
        [comparison._visual_finding("E_VISUAL_STATE", "wrong state", case_id="ready")],
    )
    result = comparison.compare_journey_evidence(before, first, after, second)
    preview = result["source_diff"]
    assert preview["status"] == status
    assert preview["truncated"] is truncated
    assert len(preview["text"].encode("utf-8")) <= comparison.MAX_DIFF_BYTES
    assert len(preview["text"].splitlines()) <= comparison.MAX_DIFF_LINES
    assert result["status"] == "FAIL"
    assert "terminal UI state" in result["next_action"]


def test_steps_bind_the_observed_failure_and_unreached_steps(
    tmp_path, replayed_captures
):
    before, after = tmp_path / "before", tmp_path / "after"

    def add_steps(contract):
        contract["cases"][0]["steps"] = [
            {"id": name, "kind": "visible", "selector": "#save", "value": True}
            for name in ["open", "save", "confirm"]
        ]

    first = _record(before, mutate=add_steps)
    second = _record(after, mutate=add_steps)
    replayed_captures[first] = (
        "PASS",
        {},
        [],
        [
            {
                "id": "ready",
                "steps": [
                    {"id": name, "ok": True} for name in ["open", "save", "confirm"]
                ],
            }
        ],
    )
    replayed_captures[second] = (
        "FAIL",
        {},
        [
            comparison._visual_finding(
                "E_VISUAL_STEP", "journey step failed: save", case_id="ready"
            )
        ],
        [
            {
                "id": "ready",
                "steps": [{"id": "open", "ok": True}, {"id": "save", "ok": False}],
            }
        ],
    )
    result = comparison.compare_journey_evidence(before, first, after, second)
    assert result["cases"][0]["steps"] == [
        {"id": "open", "before_status": "PASS", "after_status": "PASS"},
        {"id": "save", "before_status": "PASS", "after_status": "FAIL"},
        {"id": "confirm", "before_status": "PASS", "after_status": "INCOMPLETE"},
    ]
    assert result["findings"][0]["step_id"] == "save"


def test_unreproduced_recorded_failure_is_incomplete(tmp_path, replayed_captures):
    receipt = _record(tmp_path)
    replayed_captures[receipt] = (
        "FAIL",
        {},
        [comparison._visual_finding("E_VISUAL_STATE", "forged")],
        [],
        [],
    )

    result = comparison.compare_journey_evidence(tmp_path, receipt, tmp_path, receipt)

    assert result["status"] == "INCOMPLETE"
    assert result["before"]["status"] == "INCOMPLETE"
    assert result["before"]["findings"][0]["code"] == "E_JOURNEY_FAILURE_UNVERIFIED"
    assert result["source_diff"]["status"] == "UNAVAILABLE"


def test_source_drift_during_preview_suppresses_comparison(
    tmp_path, replayed_captures, monkeypatch
):
    before, after = tmp_path / "before", tmp_path / "after"
    first = _record(before, source=b"old\n")
    second = _record(after, source=b"new\n")
    replayed_captures[first] = replayed_captures[second] = ("PASS", {}, [])
    original = comparison._source_lines

    def drift(root, binding):
        if root == after:
            (root / binding["path"]).write_bytes(b"concurrent edit\n")
        return original(root, binding)

    monkeypatch.setattr(comparison, "_source_lines", drift)
    result = comparison.compare_journey_evidence(before, first, after, second)

    assert result["status"] == "INCOMPLETE"
    assert result["findings"][0]["code"] == "E_VISUAL_SOURCE_DRIFT"
    assert result["source_diff"]["text"] == ""


class _Document(HTMLParser):
    def __init__(self, document):
        super().__init__()
        self.elements = []
        self.feed(document)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


def _comparison():
    proof = {
        "status": "PASS",
        "receipt_sha256": "a" * 64,
        "contract_sha256": "b" * 64,
        "components": [],
        "evidence": [],
        "profile": None,
        "findings": [],
    }
    return {
        "status": "FAIL",
        "fixture_only": True,
        "project_id": "expense",
        "journey_id": "submit",
        "before": proof,
        "after": {**proof, "status": "FAIL", "receipt_sha256": "c" * 64},
        "cases": [
            {"id": "confirmation", "before_status": "PASS", "after_status": "FAIL"}
        ],
        "findings": [
            {
                "code": "E_JOURNEY_RECEIPT",
                "detail": "Confirmation missing",
                "case_id": "confirmation",
            }
        ],
        "component_hints": [],
        "source_diff": {
            "status": "AVAILABLE",
            "text": "- before\n+ after",
            "truncated": True,
        },
        "next_action": "Open the recorded confirmation evidence.",
        "comparison_sha256": "d" * 64,
    }


def test_comparison_exposes_failed_case_proofs_and_optional_follow_on():
    html = render_journey_comparison(_comparison())
    document = _Document(html)
    assert "Local fixture evidence" in html
    assert "First affected case · confirmation" in html
    assert "Open the recorded confirmation evidence." in html
    assert "Comparison verdict" in html
    assert "Case progress" in html
    assert "a" * 64 in html and "c" * 64 in html
    assert "Diff truncated" in html
    assert ("a", {"class": "button", "href": "#done"}) in document.elements
    assert ("a", {"class": "return", "href": "#review"}) in document.elements
    assert ("details", {}) in document.elements
    assert "Review ended" in html
    assert "#done:target + #review { display: none; }" in html


def test_incomplete_comparison_preserves_evidence_gaps():
    comparison = _comparison()
    comparison.update(
        status="INCOMPLETE", cases=[], next_action="Capture comparable evidence."
    )
    comparison["source_diff"] = {
        "status": "UNAVAILABLE",
        "text": "",
        "truncated": False,
    }
    html = render_journey_comparison(comparison)
    assert ">Incomplete<" in html
    assert "No paired cases recorded." in html
    assert "Source diff unavailable." in html
    assert "Capture comparable evidence." in html


def test_comparison_identifies_first_failing_step_with_before_and_after_statuses():
    comparison = _comparison()
    comparison["cases"][0]["steps"] = [
        {"id": "open", "before_status": "PASS", "after_status": "PASS"},
        {"id": "submit", "before_status": "PASS", "after_status": "FAIL"},
        {"id": "close", "before_status": "PASS", "after_status": "INCOMPLETE"},
    ]
    html = render_journey_comparison(comparison)
    assert "First failing step · confirmation / submit" in html
    assert "Last verified After step · confirmation / open" in html
    assert 'aria-label="Steps"' in html
    assert ">Incomplete<" in html


def test_comparison_identifies_first_incomplete_step_across_ordered_cases():
    comparison = _comparison()
    comparison["status"] = "INCOMPLETE"
    comparison["cases"] = [
        {"id": "confirm", "steps": [{"id": "open", "after_status": "PASS"}]},
        {
            "id": "finish",
            "steps": [
                {"id": "save", "after_status": "PASS"},
                {"id": "close", "after_status": "NOT_RUN"},
                {"id": "return", "after_status": "INCOMPLETE"},
            ],
        },
    ]
    html = render_journey_comparison(comparison)
    assert "First incomplete step · finish / close" in html
    assert "Last verified After step · finish / save" in html


def test_comparison_escapes_evidence_and_has_no_external_resources():
    comparison = _comparison()
    payload = '<img src="https://example.invalid" onerror="alert(1)">'
    comparison["project_id"] = payload
    comparison["next_action"] = payload
    comparison["findings"][0]["detail"] = payload
    comparison["source_diff"]["text"] = payload
    comparison["before"]["evidence"] = [
        {"path": payload, "sha256": "e" * 64, "bytes": 8, "kind": "trace"}
    ]
    comparison["before"]["profile"] = {"browser": payload}
    html = render_journey_comparison(comparison)
    elements = _Document(html).elements
    assert payload not in html
    assert html.count("&lt;img") == 6
    assert "default-src 'none'" in html
    assert all(
        tag not in {"form", "iframe", "img", "link", "script"} for tag, _ in elements
    )
    assert all(
        attrs["href"].startswith("#") for _, attrs in elements if "href" in attrs
    )
    assert all("src" not in attrs for _, attrs in elements)


# Chromium acceptance for the synthetic expense journey

FIXTURES = Path(__file__).parent / "fixtures" / "prestige_expense_journey"
SAMPLE = {"merchant": "North Station", "amount": "18.75"}
DETAIL = "$18.75 · North Station"
STATUS = f"Expense saved. {DETAIL}"


def _write(path, value):
    path.write_text(
        json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    return path


def _digest(path):
    return sha256(path.read_bytes()).hexdigest()


def _binding(root, path, kind):
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": _digest(path),
        "kind": kind,
    }


def _stage(root, variant):
    root.mkdir(parents=True, exist_ok=True)
    html = (FIXTURES / "after.html").read_text(encoding="utf-8")
    if variant == "before":
        for source, replacement in (
            ('data-variant="after"', 'data-variant="before"'),
            (' role="status" aria-live="polite"', ""),
            ("      <p>Your expense is in Recent expenses.</p>\n", ""),
            (
                ".actions > button { width: 100%; }",
                ".actions > button { width: 100%; }\n"
                "      #confirmation button { min-height: 32px; padding-block: 0; }",
            ),
        ):
            assert html.count(source) == 1
            html = html.replace(source, replacement)
    (root / "index.html").write_text(html, encoding="utf-8", newline="\n")
    shutil.copyfile(FIXTURES / "expense.js", root / "expense.js")


@contextmanager
def _serve(root, *, fail_once=False):
    requests = []
    records = []

    class ExpenseApp(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, mime, data):
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            paths = {
                "/": ("index.html", "text/html"),
                "/expense.js": ("expense.js", "text/javascript"),
            }
            target = paths.get(urlsplit(self.path).path)
            if target is None:
                self.send_error(404)
                return
            filename, mime = target
            self.reply(200, mime, (root / filename).read_bytes())

        def do_POST(self):
            if self.path != "/api/expenses":
                self.send_error(404)
                return
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(payload)
            if fail_once and len(requests) == 1:
                self.reply(503, "application/json", b"{}")
                return
            assert payload == SAMPLE
            records.append(payload)
            self.reply(201, "application/json", json.dumps(payload).encode())

    with ThreadingHTTPServer(("127.0.0.1", 0), ExpenseApp) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}/", requests, records
        finally:
            server.shutdown()
            thread.join()


@pytest.fixture(scope="module")
def chromium():
    if os.environ.get("FACTORY_REQUIRE_NATIVE_VISUAL") == "1":
        from playwright import sync_api
    else:
        sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as playwright:
        executable = playwright.chromium.executable_path
        browser = playwright.chromium.launch(headless=True)
        try:
            yield browser, executable, sync_api.expect
        finally:
            browser.close()


@pytest.fixture(scope="module")
def evidence(tmp_path_factory):
    configured = os.environ.get("FACTORY_PRESTIGE_EXPENSE_EVIDENCE")
    root = (
        Path(configured).resolve()
        if configured
        else tmp_path_factory.mktemp("expense-proof")
    )
    root.mkdir(parents=True, exist_ok=True)
    return root


def _open_and_fill(page, expect, *, mobile):
    opener = page.get_by_role("button", name="New expense")
    if mobile:
        opener.tap()
    else:
        page.keyboard.press("Tab")
        expect(opener).to_be_focused()
        page.keyboard.press("Enter")
    merchant = page.get_by_label("Merchant")
    expect(merchant).to_be_focused()
    page.keyboard.type(SAMPLE["merchant"])
    page.keyboard.press("Tab")
    amount = page.get_by_label("Amount (USD)")
    expect(amount).to_be_focused()
    page.keyboard.type(SAMPLE["amount"])
    page.keyboard.press("Tab")
    expect(page.get_by_role("button", name="Save expense")).to_be_focused()


def _save(page, expect, *, mobile):
    if mobile:
        page.get_by_role("button", name="Save expense").tap()
    else:
        page.keyboard.press("Enter")
    saved = page.get_by_role("heading", name="Expense saved")
    expect(saved).to_be_visible()
    expect(page.locator("#records li")).to_have_count(1)
    expect(page.locator("#records li")).to_have_text(DETAIL)
    return saved


REQUIREMENTS = {
    "form": "REACH_FORM",
    "saved": "ONE_SAVE_ONE_RECORD",
    "announced": "STATUS_LIVE_REGION",
    "returned": "DONE_RETURNS_FOCUS",
    "next": "EXPLICIT_ADD_ANOTHER",
}
TRANSITIONS = (
    ("open-editor", "list", "form"),
    ("submit-once", "form", "saved"),
    ("expose-live-status", "saved", "announced"),
    ("done-closes-editor", "saved", "returned"),
    ("add-another-opens-editor", "saved", "next"),
)
PROJECT = {"project_id": "fieldbook-fixture", "journey_id": "save-expense"}


def _reality(evidence, replay, facts, artifacts):
    expected_states = {"list", *REQUIREMENTS}
    present_states = {
        "list",
        *(state for state, key in REQUIREMENTS.items() if facts[key]),
    }
    if not facts["DONE_RETURNS_FOCUS"]:
        present_states.add("unexpected-editor")
    expected_outcomes = ["returned", "next"]
    expected = {
        "schema": "factory.journey-declaration.v1",
        **PROJECT,
        "states": [
            {
                "id": state,
                "requirements": [REQUIREMENTS[state]] if state in REQUIREMENTS else [],
                "outcome": state in expected_outcomes,
            }
            for state in sorted(expected_states)
        ],
        "transitions": [
            {"id": key, "from": start, "to": end, "requirements": [REQUIREMENTS[end]]}
            for key, start, end in TRANSITIONS
        ],
        "requirements": sorted(REQUIREMENTS.values()),
        "outcomes": expected_outcomes,
    }
    observed = {
        "schema": "factory.journey-observation.v1",
        **PROJECT,
        "run_id": replay["profile"],
        "code_version": replay["candidate_sha256"],
        "environment": {
            "label": "local synthetic loopback",
            "fingerprint": replay["browser"],
        },
        "states": [{"id": state} for state in sorted(present_states)],
        "transitions": [
            {"id": key, "from": start, "to": end, "artifacts": artifacts}
            for key, start, end in TRANSITIONS
            if end in present_states
        ],
        "requirements": sorted(key for key, passed in facts.items() if passed),
        "outcomes": [state for state in expected_outcomes if state in present_states],
        "observed_at": replay["observed_at"],
    }
    declaration = _write(evidence / "declaration.json", expected)
    observation = _write(evidence / f"{replay['profile']}-observation.json", observed)
    return compile_reality_graph(evidence, declaration.name, observation.name)


@pytest.mark.parametrize(
    "variant,mobile",
    [("before", False), ("before", True), ("after", False), ("after", True)],
    ids=["before-desktop", "before-mobile", "after-desktop", "after-mobile"],
)
def test_expense_browser_journey(variant, mobile, chromium, evidence):
    browser, _, expect = chromium
    profile = f"{variant}-{'mobile' if mobile else 'desktop'}"
    stage = evidence / f"replay-{profile}"
    _stage(stage, variant)
    viewport = (
        {"width": 320, "height": 640} if mobile else {"width": 960, "height": 720}
    )
    screenshot = evidence / f"{profile}.png"
    confirmation_height = {}
    context = browser.new_context(viewport=viewport, is_mobile=mobile, has_touch=mobile)
    try:
        with _serve(stage) as (target, requests, records):
            page = context.new_page()
            page.goto(target)
            _open_and_fill(page, expect, mobile=mobile)
            saved = _save(page, expect, mobile=mobile)
            done = page.get_by_role("button", name="Done")
            expect(done).to_be_focused()
            expect(page.locator("#expense-detail")).to_have_text(DETAIL)
            page.screenshot(path=str(screenshot), animations="disabled")
            live_region = page.get_by_role("status")
            status_text = (
                live_region.text_content() if live_region.count() == 1 else None
            )
            aria = page.locator("body").aria_snapshot()
            no_horizontal_overflow = page.evaluate(
                "document.documentElement.scrollWidth === window.innerWidth"
            )
            expect(done).to_be_in_viewport()
            assert no_horizontal_overflow
            if mobile:
                for control in (done, page.get_by_role("button", name="Add another")):
                    bounds = control.bounding_box()
                    assert bounds["width"] >= 44
                    confirmation_height[control.inner_text()] = bounds["height"]
                    assert (bounds["height"] >= 44) == (variant == "after")
                done.tap()
            else:
                page.keyboard.press("Enter")
            expect(saved).to_be_hidden()
            editor = page.locator("#editor")
            opener = page.get_by_role("button", name="New expense")
            done_focus = page.evaluate("document.activeElement.id")
            done_closed = editor.is_hidden()
            assert requests == records == [SAMPLE]
            if variant == "before":
                assert not done_closed and done_focus == "merchant"
                assert status_text is None
            else:
                expect(editor).to_be_hidden()
                expect(opener).to_be_focused()
                assert done_focus == "open-expense" and status_text == STATUS
                assert "status" in aria and "Expense saved" in aria

        # Separate visit: choosing Add another must open a fresh editor without saving.
        with _serve(stage) as (target, requests, records):
            page.goto(target)
            _open_and_fill(page, expect, mobile=mobile)
            _save(page, expect, mobile=mobile)
            add_another = page.get_by_role("button", name="Add another")
            if mobile:
                add_another.tap()
            else:
                page.keyboard.press("Tab")
                expect(add_another).to_be_focused()
                page.keyboard.press("Enter")
            expect(page.get_by_label("Merchant")).to_be_focused()
            expect(page.get_by_label("Merchant")).to_have_value("")
            expect(page.get_by_label("Amount (USD)")).to_have_value("")
            expect(page.get_by_role("heading", name="Expense saved")).to_be_hidden()
            assert requests == records == [SAMPLE]
    finally:
        context.close()

    facts = {
        "REACH_FORM": True,
        "ONE_SAVE_ONE_RECORD": True,
        "STATUS_LIVE_REGION": status_text == STATUS,
        "DONE_RETURNS_FOCUS": done_closed and done_focus == "open-expense",
        "EXPLICIT_ADD_ANOTHER": True,
    }
    replay = {
        "profile": profile,
        "browser": f"Playwright Chromium {browser.version}",
        "viewport": viewport,
        "input": (
            "emulated touch with hardware key entry"
            if mobile
            else "hardware keyboard only"
        ),
        "candidate_sha256": _digest(stage / "index.html"),
        "script_sha256": _digest(stage / "expense.js"),
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "requests": requests,
        "records": records,
        "done_focus": done_focus,
        "done_closed_editor": done_closed,
        "status_text": status_text,
        "confirmation_accessibility_snapshot": aria,
        "no_horizontal_overflow": no_horizontal_overflow,
        "confirmation_control_height_px": confirmation_height,
        "facts": facts,
        "scope": "Synthetic service and browser accessibility tree. Physical hardware, native soft keyboard, screen reader speech and production storage were outside this run.",
    }
    report = _write(evidence / f"{profile}.json", replay)
    receipt = _reality(
        evidence,
        replay,
        facts,
        [
            _binding(evidence, report, "runtime"),
            _binding(evidence, screenshot, "screenshot"),
        ],
    )
    if variant == "before":
        assert receipt["marker"] == "JOURNEY_REALITY_REVIEW_REQUIRED"
        assert set(receipt["deltas"]["requirements"]["missing"]) == {
            "done_returns_focus",
            "status_live_region",
        }
    else:
        assert receipt["marker"] == "JOURNEY_REALITY_MATCHED", receipt


def test_expense_validation_and_retry(chromium, evidence):
    browser, _, expect = chromium
    stage = evidence / "replay-after-desktop"
    _stage(stage, "after")
    page = browser.new_page()
    try:
        with _serve(stage, fail_once=True) as (target, requests, records):
            page.goto(target)
            page.get_by_role("button", name="New expense").click()
            save = page.get_by_role("button", name="Save expense")
            save.click()
            assert requests == records == []
            assert not page.get_by_label("Merchant").evaluate(
                "(field) => field.validity.valid"
            )
            page.get_by_label("Merchant").fill(SAMPLE["merchant"])
            page.get_by_label("Amount (USD)").fill("0")
            save.click()
            assert requests == records == []
            assert page.get_by_label("Amount (USD)").evaluate(
                "(field) => field.validity.rangeUnderflow"
            )
            page.get_by_label("Amount (USD)").fill(SAMPLE["amount"])
            save.click()
            expect(page.get_by_role("alert")).to_have_text(
                "Expense could not be saved. Try again."
            )
            expect(save).to_be_focused()
            assert requests == [SAMPLE] and records == []
            save.press("Enter")
            expect(page.get_by_role("heading", name="Expense saved")).to_be_visible()
            assert requests == [SAMPLE, SAMPLE] and records == [SAMPLE]
            _write(
                evidence / "validation-retry.json",
                {
                    "browser": f"Playwright Chromium {browser.version}",
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "invalid_input_requests": 0,
                    "failed_save_records": 0,
                    "retry_requests_total": len(requests),
                    "retry_records_total": len(records),
                },
            )
    finally:
        page.close()


def _step(step_id, kind, selector, value=None):
    return dict(id=step_id, kind=kind, selector=selector, value=value)


VISUAL_STEPS = {
    "finish": [
        _step("one-record-after-save", "count", "#records li", 1),
        _step("activate-done", "press", "#done", "Enter"),
        _step("return-focus-to-opener", "focus", "#open-expense"),
        _step("editor-stays-closed", "visible", "#editor", False),
        _step("confirmation-dismissed", "visible", "#confirmation", False),
        _step("one-record-after-done", "count", "#records li", 1),
    ],
    "add-another": [
        _step("tab-to-add-another", "press", "#done", "Tab"),
        _step("activate-add-another", "press", "#add-another", "Enter"),
        _step("focus-fresh-merchant", "focus", "#merchant"),
        _step("show-fresh-editor", "visible", "#editor", True),
        _step("confirmation-dismissed", "visible", "#confirmation", False),
        _step("one-record-before-second-save", "count", "#records li", 1),
    ],
    "announce": [
        _step(
            "live-success-with-detail",
            "count",
            '#save-status[role="status"][aria-live="polite"]:text-is("Expense saved. $18.75 · North Station")',
            1,
        ),
    ],
}


def _visual_cases(stage, *, with_baseline):
    cases = []
    for case_id, steps in VISUAL_STEPS.items():
        baseline = stage / f"{case_id}.png"
        cases.append(
            {
                "id": case_id,
                "baseline": (
                    _binding(stage, baseline, "baseline") if with_baseline else None
                ),
                "action": {"selector": "#save-expense"},
                "element": {
                    "selector": "#save-expense",
                    "role": "button",
                    "name": "Save expense",
                    "enabled": True,
                },
                "state": {"selector": "#confirmation-title", "text": "Expense saved"},
                "response": {
                    "method": "POST",
                    "path": "/api/expenses",
                    "status": 201,
                    "field": "merchant",
                    "value": SAMPLE["merchant"],
                    "correlation": {
                        "header": "X-Fixture-Journey",
                        "value": "expense-save",
                    },
                },
                "tokens": [],
                "timeout_ms": 7000,
                "max_changed_ratio": 0,
                "steps": steps,
            }
        )
    return cases


def _expense_visual_contract(stage, target, browser, executable, *, with_baseline):
    return {
        "schema": "factory.visual-behavior.contract.v1",
        "fixture_only": True,
        **PROJECT,
        "candidate": [
            _binding(stage, stage / name, "source")
            for name in ("index.html", "expense.js")
        ],
        "reviewer": {"name": "Local fixture baseline", "type": "human"},
        "target": target + "?fixture=save",
        "browser": {
            "executable": executable,
            "version": browser.version,
            "platform": sys.platform,
            "width": 320,
            "height": 640,
        },
        "design": None,
        "cases": _visual_cases(stage, with_baseline=with_baseline),
    }


def test_native_expense_visual_pair(chromium, evidence):
    browser, executable, _ = chromium
    run_root = Path(tempfile.mkdtemp(prefix="native-", dir=evidence))
    stages = {variant: run_root / variant for variant in ("after", "before")}
    locations = {}
    for variant, stage in stages.items():
        _stage(stage, variant)
    for variant, stage in stages.items():
        with _serve(stage) as (target, requests, records):

            def run(*, with_baseline):
                contract = _expense_visual_contract(
                    stage, target, browser, executable, with_baseline=with_baseline
                )
                filename = (
                    "visual-contract.json"
                    if with_baseline
                    else "proposed-contract.json"
                )
                path = _write(stage / filename, contract)
                return run_visual_behavior_gate(
                    stage,
                    path,
                    _digest(path),
                    execute=True,
                )

            if variant == "after":
                proposed = run(with_baseline=False)
                assert proposed["decision"] == "INCOMPLETE", proposed["findings"]
                assert len(proposed["cases"]) == len(VISUAL_STEPS)
                for case in proposed["cases"]:
                    assert len(case["steps"]) == len(VISUAL_STEPS[case["id"]])
                    assert all(step["ok"] for step in case["steps"]), case
                    origin = stage / case["screenshot"]["path"]
                    for sibling in stages.values():
                        shutil.copyfile(origin, sibling / f"{case['id']}.png")
                requests.clear()
                records.clear()

            receipt = run(with_baseline=True)
            assert requests == records == [SAMPLE] * len(VISUAL_STEPS)
            verified = verify_visual_behavior_receipt(stage, Path(receipt["path"]))
            expected = "PASS" if variant == "after" else "FAIL"
            assert verified["decision"] == receipt["decision"] == expected, receipt[
                "findings"
            ]
            if variant == "before":
                failed = {
                    case["id"]: [step["id"] for step in case["steps"] if not step["ok"]]
                    for case in receipt["cases"]
                }
                assert failed == {
                    "finish": ["return-focus-to-opener"],
                    "add-another": [],
                    "announce": ["live-success-with-detail"],
                }
            locations[variant] = {
                "root": stage.relative_to(evidence).as_posix(),
                "receipt": Path(receipt["path"]).relative_to(stage).as_posix(),
                "decision": receipt["decision"],
            }
    _write(evidence / "native-pair.json", locations)
    result = comparison.compare_journey_evidence(
        stages["before"],
        locations["before"]["receipt"],
        stages["after"],
        locations["after"]["receipt"],
    )
    assert result["status"] == "PASS", result["findings"]
    assert result["before"]["status"] == "FAIL"
    assert result["source_diff"]["status"] == "AVAILABLE"
    assert "Last verified After step" in render_journey_comparison(result)
