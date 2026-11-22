from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.full_stack_ux_harness import (
    CORE_CHECKS,
    JUDGMENTS,
    UI_CHECKS,
    FullStackUXHarnessError,
    quality_harness_template,
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
    if mutation == "forged":
        case["passed"] = True
    elif mutation == "remote":
        contract["target"] = "https://example.com/"
    elif mutation == "agent":
        contract["reviewer"]["type"] = "agent"
    elif mutation == "empty":
        contract["candidate"] = []
    elif mutation == "duplicate":
        contract["candidate"] *= 2
    elif mutation == "threshold":
        case["max_changed_ratio"] = 0.02
    elif mutation == "deadline":
        case["timeout_ms"] = True
    elif mutation == "escape":
        contract["candidate"][0]["path"] = "../outside.html"
    elif mutation == "source_hash":
        contract["candidate"][0]["sha256"] = "0" * 64
    elif mutation == "empty_cases":
        contract["cases"] = []
    elif mutation == "duplicate_cases":
        contract["cases"] *= 2
    elif mutation == "width":
        contract["browser"]["width"] = 319
    elif mutation == "css_property":
        case["tokens"] = [{"selector": "body", "property": "behavior", "value": "evil"}]
    elif mutation == "fixture_false":
        contract["fixture_only"] = False
    elif mutation == "fixture_absent":
        del contract["fixture_only"]
    elif mutation == "response":
        case["response"] = {
            "method": "POST",
            "path": "/save",
            "status": 200,
            "field": "saved",
            "value": True,
            "correlation": {"header": "x-cf-action", "value": "ready"},
        }
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


def test_visual_real_browser_pixels_semantics_runtime_and_prestige(tmp_path, capsys):
    """Exposed local detector acceptance, never a production accuracy claim."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    import shutil
    import factoryline.full_stack_ux_harness as harness

    # Windows acceptance must actually run; dependency absence must fail here.
    if sys.platform == "win32":
        from playwright.sync_api import sync_playwright
    else:
        sync_playwright = pytest.importorskip("playwright.sync_api").sync_playwright
    with sync_playwright() as playwright:
        executable = playwright.chromium.executable_path
        browser = playwright.chromium.launch(headless=True)
        version = browser.version
        browser.close()

    behavior = {"mode": "ready"}

    class App(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            mode = behavior["mode"]
            if self.path == "/api/save":
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
                return
            html = (tmp_path / "app.html").read_text(encoding="utf-8")
            if mode == "source-drift":
                (tmp_path / "app.html").write_text(
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

    server = ThreadingHTTPServer(("127.0.0.1", 0), App)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        contract = _visual_contract(tmp_path, f"http://127.0.0.1:{server.server_port}/")
        source = tmp_path / "app.html"
        source.write_text(
            "<style>body {background:#ffffff;margin:8px}</style>"
            "<button id=\"save\" onclick=\"fetch('/api/save',{headers:{'x-cf-action':'ready'}}).then(()=>document.querySelector('#state').textContent='Saved')\">Save</button>"
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
        quality = _write_manifest(tmp_path)
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
            action={"selector": "#save"},
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
        assert any(
            item["code"] == "E_VISUAL_RUNTIME" for item in wrong_action["findings"]
        )
        case["response"]["correlation"]["value"] = "ready"
        for mode in ("missing-length", "oversize-length", "encoded", "chunked"):
            behavior["mode"] = mode
            assert run()["decision"] == "INCOMPLETE", mode
        behavior["mode"] = "multiple"
        assert run()["decision"] == "INCOMPLETE"
        case["response"]["path"] = "/never-observed"
        assert run()["decision"] == "INCOMPLETE"

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
