"""Behavior assertions for previously unattributed local workflow functions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import runpy
import subprocess

import pytest

from factoryline.cdte import SCAN_SCHEMA, load_scans
from factoryline.habituation import load_resamples
from factoryline.cli_foundations import cli_command, emit_version
from factoryline.codex_metadata import write_metadata_audit
from factoryline.combine import combine_projection
from factoryline.control_api import ControlPlaneAPI, create_app
from factoryline.full_stack_ux_harness import (
    FullStackUXHarnessError,
    quality_harness_template,
    write_quality_harness_template,
)
from factoryline.mcp_mrt import evaluate_release_gate
from factoryline.migration import RepositoryHistoryError, git_lines
from factoryline.output_map import OUTPUT_MAP_MARKER, write_output_map
from factoryline.proof import execute_replay, load_trace
from factoryline.signed_receipts import SignedReceiptError, ci_receipt_main
from factoryline.deep_audit import cancel_deep_run, deep_run_status, scan_deep_audit
from factoryline.runtime_audit_common import RuntimeAuditError
from factoryline.studio import (
    StudioRequestError,
    authorize_graph_ops_from_studio,
    run_graph_ops_reality_check_from_studio,
)


def test_load_scans_keeps_only_valid_schema_receipts(tmp_path: Path) -> None:
    directory = tmp_path / ".factory" / "cdte"
    directory.mkdir(parents=True)
    valid = {"schema": SCAN_SCHEMA, "scan_id": "scan-1", "conflicts": []}
    (directory / "00-valid.json").write_text(json.dumps(valid), encoding="utf-8")
    (directory / "01-foreign.json").write_text(
        json.dumps({"schema": "other.v1"}), encoding="utf-8"
    )
    (directory / "02-broken.json").write_text("{", encoding="utf-8")

    assert load_scans(tmp_path) == [valid]


def test_load_resamples_skips_corrupt_and_foreign_records(tmp_path: Path) -> None:
    directory = tmp_path / ".factory" / "habituation"
    directory.mkdir(parents=True)
    valid = {"schema": "factory.habituation.resample.v1", "review_id": "r-1"}
    (directory / "resample.01.json").write_text(json.dumps(valid), encoding="utf-8")
    (directory / "resample.02.json").write_text(
        json.dumps({"schema": "other.v1"}), encoding="utf-8"
    )
    (directory / "resample.03.json").write_text("not-json", encoding="utf-8")

    assert load_resamples(tmp_path) == [valid]


def test_emit_version_formats_json_and_human_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from factoryline import provenance as provenance_module

    payload = {"version": "0.47.0", "source_commit": "abc123"}
    monkeypatch.setattr(provenance_module, "provenance", lambda: payload)

    assert emit_version(as_json=True) == 0
    assert json.loads(capsys.readouterr().out) == payload
    assert emit_version(as_json=False) == 0
    assert capsys.readouterr().out.strip() == "factory 0.47.0"


def test_cli_command_prefers_launcher_directory(tmp_path: Path, monkeypatch) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    launcher = scripts / "factory-launcher.py"
    launcher.write_text("", encoding="utf-8")
    executable = scripts / "factory.exe"
    executable.write_text("", encoding="utf-8")
    monkeypatch.setattr("factoryline.cli_foundations.sys.argv", [str(launcher)])

    assert cli_command("factory") == str(executable)


def test_write_metadata_audit_persists_marked_receipt(tmp_path: Path) -> None:
    source = tmp_path / "candidate.json"
    source.write_text(json.dumps({"status": "draft"}), encoding="utf-8")

    result = write_metadata_audit(tmp_path, [source], Path("audit.json"))

    persisted = json.loads((tmp_path / "audit.json").read_text(encoding="utf-8"))
    assert result["marker"] == "CODEX_METADATA_CLI_WRITTEN"
    assert result["markers"][-1] == "CODEX_METADATA_CLI_WRITTEN"
    assert persisted == result
    assert not (tmp_path / "audit.json.tmp").exists()


def test_combine_projection_reports_empty_read_only_state(tmp_path: Path) -> None:
    result = combine_projection(tmp_path)

    assert result["marker"] == "COMBINE_STATUS_READ_ONLY"
    assert result["available"] is False
    assert result["scoreboards"] == []
    assert all(value is False for value in result["authority"].values())


def test_create_app_exposes_health_and_requires_verified_identity(tmp_path: Path) -> None:
    app = create_app(tmp_path / "control.sqlite3")
    assert isinstance(app, ControlPlaneAPI)

    def call(path: str) -> tuple[str, dict]:
        captured: dict[str, str] = {}

        def start_response(status: str, headers: list[tuple[str, str]]) -> None:
            captured["status"] = status

        body = b"".join(
            app(
                {
                    "REQUEST_METHOD": "GET",
                    "PATH_INFO": path,
                    "CONTENT_LENGTH": "0",
                    "wsgi.input": __import__("io").BytesIO(b""),
                },
                start_response,
            )
        )
        return captured["status"], json.loads(body)

    status, health = call("/healthz")
    assert status == "200 OK" and health["ok"] is True
    status, error = call("/v1/evidence")
    assert status == "400 Bad Request"
    assert error["error"]["code"] == "E_IDENTITY_REQUIRED"


def test_write_quality_harness_template_containment_and_no_overwrite(
    tmp_path: Path,
) -> None:
    result = write_quality_harness_template(
        tmp_path, Path("quality.json"), ui_in_scope=False
    )
    saved = json.loads((tmp_path / "quality.json").read_text(encoding="utf-8"))
    assert saved["checks"] == quality_harness_template(ui_in_scope=False)["checks"]
    assert result["path"] == str((tmp_path / "quality.json").resolve())

    with pytest.raises(FullStackUXHarnessError) as exists_error:
        write_quality_harness_template(
            tmp_path, Path("quality.json"), ui_in_scope=False
        )
    assert exists_error.value.code == "E_UX_MANIFEST_EXISTS"
    with pytest.raises(FullStackUXHarnessError) as path_error:
        write_quality_harness_template(
            tmp_path, Path("../outside.json"), ui_in_scope=False
        )
    assert path_error.value.code == "E_UX_MANIFEST_PATH"


def test_evaluate_release_gate_requests_input_without_approving() -> None:
    card = {
        "feature": "payments",
        "state": "BLOCKED",
        "blockers": [{"code": "MISSING_EVIDENCE"}],
    }

    first = evaluate_release_gate(card)
    second = evaluate_release_gate(card)

    assert first["type"] == "input_required"
    assert first["toolCallId"] == second["toolCallId"]
    assert first["context"]["proofDebt"] == ["MISSING_EVIDENCE"]
    assert all(value is False for value in first["authority"].values())


def test_git_lines_is_read_only_allowlisted_and_returns_root(tmp_path: Path) -> None:
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)

    observed_root = git_lines(tmp_path, "rev-parse", "--show-toplevel")
    assert len(observed_root) == 1
    assert Path(observed_root[0]).resolve() == tmp_path.resolve()
    with pytest.raises(RepositoryHistoryError, match="read-only allowlist"):
        git_lines(tmp_path, "status", "--short")


def test_write_output_map_binds_digest_and_lists_expected_paths(tmp_path: Path) -> None:
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text("value = 1\n", encoding="utf-8")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()

    result = write_output_map(
        tmp_path,
        name="sample",
        source_sha256=source_hash,
        status="blocked",
        expected_paths=["src/app.py"],
    )
    rendered = (tmp_path / result["path"]).read_text(encoding="utf-8")

    assert result["marker"] == OUTPUT_MAP_MARKER
    assert result["sha256"] == hashlib.sha256(
        (tmp_path / result["path"]).read_bytes()
    ).hexdigest()
    assert result["file_count"] >= 2
    assert "src/app.py" in rendered
    assert "output inventory, not a completion certificate" in rendered


def test_load_trace_reads_exact_json_object_and_rejects_malformed_json(
    tmp_path: Path,
) -> None:
    trace = {"feature": "payments", "nodes": [{"stage": "tests"}]}
    path = tmp_path / "trace.json"
    path.write_text(json.dumps(trace), encoding="utf-8")
    assert load_trace(path) == trace

    path.write_text("{", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        load_trace(path)


def test_execute_replay_stops_after_failed_command(tmp_path: Path) -> None:
    (tmp_path / "input.json").write_text('{"ok": true}', encoding="utf-8")
    result = execute_replay(
        {
            "feature": "json-replay",
            "trace_sha256": "a" * 64,
            "commands": [
                {"command": "python -m json.tool input.json"},
                {"command": "python -m json.tool missing.json"},
                {"command": "python -m json.tool input.json"},
            ],
        },
        root=tmp_path,
    )

    assert result["executed"] is True
    assert result["ok"] is False
    assert [row["status"] for row in result["results"]] == ["ok", "failed"]
    assert "\"ok\": true" in result["results"][0]["log_tail"]


def test_ci_receipt_main_rejects_missing_or_unknown_route() -> None:
    with pytest.raises(SignedReceiptError) as exc:
        ci_receipt_main([])
    assert exc.value.code == "E_CI_RECEIPT"


def test_authorize_graph_ops_from_studio_rejects_incomplete_payload(
    tmp_path: Path,
) -> None:
    with pytest.raises(StudioRequestError) as exc:
        authorize_graph_ops_from_studio(tmp_path, {})
    assert exc.value.code == "GRAPH_AUTHORIZATION_INVALID"
    assert exc.value.status == 400


def test_run_graph_ops_reality_check_from_studio_rejects_extra_fields(
    tmp_path: Path,
) -> None:
    with pytest.raises(StudioRequestError) as exc:
        run_graph_ops_reality_check_from_studio(
            tmp_path, {"authorization": "missing.json", "unexpected": True}
        )
    assert exc.value.code == "GRAPH_AUTHORIZATION_INVALID"
    assert exc.value.status == 400


def test_prooflab_run_module_executes_and_surfaces_module_failure(
    tmp_path: Path,
) -> None:
    source = Path(__file__).parents[1] / "scripts" / "prooflab_e2e.py"
    run_module = runpy.run_path(str(source))["run_module"]
    (tmp_path / "input.json").write_text('{"ok": true}', encoding="utf-8")

    assert run_module("json.tool", ["input.json"], tmp_path) is None
    with pytest.raises(RuntimeError, match="failed"):
        run_module("json.tool", ["missing.json"], tmp_path)


def test_release_train_write_complete_emits_every_declared_stage(
    tmp_path: Path,
) -> None:
    source = Path(__file__).parents[1] / "scripts" / "release_train_e2e.py"
    module = runpy.run_path(str(source))

    module["write_complete"](tmp_path, {"source_sha256": "a" * 64})

    receipts = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (tmp_path / "receipts").glob("*.json")
    ]
    observed_stages = {(row["module"], row["stage"]) for row in receipts}
    expected_stages = {
        tuple(item.split(":", maxsplit=1)) for item in module["STAGES"]
    }
    assert observed_stages == expected_stages
    assert all(row["feature"] == "release-train" and row["ok"] for row in receipts)


def test_cancel_deep_run_does_not_rewrite_a_terminal_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_deep_audit_contract import execution_fixture

    root, manifest, pin, authorization, trust, plan, _, _ = execution_fixture(tmp_path)

    def unavailable() -> None:
        raise RuntimeAuditError("E_DOCKER_UNAVAILABLE", "fixture unavailable")

    monkeypatch.setattr("factoryline.deep_audit._docker_base", unavailable)
    run = scan_deep_audit(
        root,
        manifest,
        pin,
        authorization=authorization,
        trust_root=trust,
        trust_root_sha256=plan["trust_root_sha256"],
        emit=lambda _event: None,
    )
    run_id = run["run_id"]

    cancellation = cancel_deep_run(root, run_id)

    assert run["state"] == "INCOMPLETE"
    assert deep_run_status(root, run_id)["observed_state"] == "INCOMPLETE"
    assert cancellation == {
        "run_id": run_id,
        "state": "ALREADY_STOPPED",
        "authority": "none",
    }
