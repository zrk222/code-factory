import io
import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.context_efficiency import (
    MAX_SOURCE_BYTES,
    REQUEST_SCHEMA,
    SELECTION_SCHEMA,
    ContextEfficiencyError,
    build_context_packet,
    build_selected_context_packet,
    context_efficiency_status,
    verify_context_packet,
)
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.mission_control_status import mission_control_status


def _request(paths=("README.md",), **overrides):
    value = {
        "schema": REQUEST_SCHEMA,
        "mission_id": "speed-slice",
        "contract_digest": "a" * 64,
        "changed_paths": list(paths),
        "sources": [
            {"path": path, "role": "intent", "priority": 100 - index}
            for index, path in enumerate(paths)
        ],
        "max_tokens": 256,
        "per_file_tokens": 64,
    }
    value.update(overrides)
    return value


def test_packet_is_bounded_and_verifiable(tmp_path):
    (tmp_path / "README.md").write_text(
        "intent\n" + ("detail " * 1000), encoding="utf-8"
    )
    packet = build_context_packet(tmp_path, _request())
    assert packet["budget"]["decision"] == "TRUNCATED"
    assert (
        packet["budget"]["token_quality"]
        == "estimated_from_utf8_bytes_not_provider_usage"
    )
    assert packet["budget"]["selected_bytes"] <= packet["budget"]["max_bytes"]
    result = verify_context_packet(tmp_path, tmp_path / packet["cache"]["path"])
    assert result["valid"] is True


def test_resealed_forged_excerpt_is_blocked_and_not_reused(tmp_path):
    from factoryline.context_efficiency import _packet_digest

    (tmp_path / "README.md").write_text("approved source", encoding="utf-8")
    first = build_context_packet(tmp_path, _request())
    path = tmp_path / first["cache"]["path"]
    forged = json.loads(path.read_text(encoding="utf-8"))
    forged["sources"][0]["excerpt"] = "forged but rehashed"
    forged["packet_sha256"] = _packet_digest(forged)
    path.write_text(json.dumps(forged), encoding="utf-8")

    verified = verify_context_packet(tmp_path, path)
    assert verified["state"] == "BLOCKED"
    assert verified["code"] == "E_EXCERPT_MISMATCH"
    rebuilt = build_context_packet(tmp_path, _request())
    assert rebuilt["cache"]["hit"] is False
    assert rebuilt["sources"][0]["excerpt"] == "approved source"


def test_python_ast_input_limit_is_explicit(tmp_path):
    from factoryline.context_efficiency import MAX_AST_SOURCE_BYTES

    (tmp_path / "large.py").write_text(
        "# bounded source\n" + ("# data\n" * (MAX_AST_SOURCE_BYTES // 7)),
        encoding="utf-8",
    )
    packet = build_selected_context_packet(
        tmp_path,
        _selection_manifest(
            candidates=[{"path": "large.py", "role": "implementation"}],
            changed_paths=["large.py"],
            required_paths=[],
            max_sources=1,
            required_evidence_roles=[],
        ),
    )
    assert packet["selection"]["candidates"][0]["structure"]["status"] == "PARSE_LIMIT"


def test_secret_file_is_digest_only(tmp_path):
    (tmp_path / "api-token.txt").write_text("not for context", encoding="utf-8")
    packet = build_context_packet(tmp_path, _request(paths=("api-token.txt",)))
    assert packet["sources"][0]["inclusion"] == "digest_only"
    assert "excerpt" not in packet["sources"][0]


@pytest.mark.parametrize(
    ("name", "content"),
    [
        (".env.local", b"ordinary-looking config"),
        ("id_ed25519", b"synthetic private material"),
        ("config.txt", b"GOOGLE_API_KEY=AIza" + b"A" * 32),
    ],
)
def test_common_credential_paths_and_shapes_are_digest_only(name, content):
    from factoryline.context_efficiency import _SECRET_BYTES, _SECRET_NAME, _selection

    sensitive = bool(_SECRET_NAME.search(name)) or any(
        pattern.search(content) for pattern in _SECRET_BYTES
    )
    excerpt, inclusion, _, _ = _selection(content, 64, 1024, sensitive_name=sensitive)
    assert inclusion == "digest_only"
    assert excerpt is None


def test_secret_material_in_request_is_rejected(tmp_path):
    (tmp_path / "README.md").write_text("safe", encoding="utf-8")
    with pytest.raises(ContextEfficiencyError, match="E_SECRET_MATERIAL"):
        build_context_packet(tmp_path, _request(token="do-not-accept"))


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_tokens", 255),
        ("max_tokens", 12001),
        ("per_file_tokens", 31),
        ("per_file_tokens", 2001),
    ],
)
def test_budget_bounds_are_fail_closed(tmp_path, field, value):
    (tmp_path / "README.md").write_text("safe", encoding="utf-8")
    with pytest.raises(ContextEfficiencyError, match="E_FIELD"):
        build_context_packet(tmp_path, _request(**{field: value}))


def test_traversal_and_symlink_are_rejected(tmp_path):
    (tmp_path / "README.md").write_text("safe", encoding="utf-8")
    with pytest.raises(ContextEfficiencyError, match="E_PATH_BOUNDARY"):
        build_context_packet(tmp_path, _request(paths=("../README.md",)))
    link = tmp_path / "link.md"
    try:
        link.symlink_to(tmp_path / "README.md")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(ContextEfficiencyError, match="E_PATH_LINK"):
        build_context_packet(tmp_path, _request(paths=("link.md",)))


def test_second_build_reuses_exact_cache(tmp_path):
    (tmp_path / "README.md").write_text("stable", encoding="utf-8")
    first = build_context_packet(tmp_path, _request())
    second = build_context_packet(tmp_path, _request())
    assert first["cache"]["key"] == second["cache"]["key"]
    assert first["packet_sha256"] != second["packet_sha256"]
    assert second["cache"]["hit"] is True
    assert context_efficiency_status(tmp_path)["cache_hits"] == 1


def test_source_drift_blocks_verification(tmp_path):
    (tmp_path / "README.md").write_text("before", encoding="utf-8")
    packet = build_context_packet(tmp_path, _request())
    (tmp_path / "README.md").write_text("after", encoding="utf-8")
    result = verify_context_packet(tmp_path, tmp_path / packet["cache"]["path"])
    assert result["state"] == "BLOCKED"
    assert result["code"] == "E_SOURCE_DRIFT"


def test_status_missing_ready_and_invalid(tmp_path):
    assert context_efficiency_status(tmp_path)["state"] == "MISSING"
    (tmp_path / "README.md").write_text("safe", encoding="utf-8")
    build_context_packet(tmp_path, _request())
    assert context_efficiency_status(tmp_path)["state"] == "READY"
    broken = tmp_path / ".factory" / "context-efficiency" / "broken.json"
    broken.write_text("{}", encoding="utf-8")
    status = context_efficiency_status(tmp_path)
    assert status["state"] == "BLOCKED"
    assert status["invalid_count"] == 1


def test_cli_pack_verify_and_status_are_read_only(tmp_path, capsys):
    (tmp_path / "README.md").write_text("safe", encoding="utf-8")
    manifest = tmp_path / "request.json"
    manifest.write_text(json.dumps(_request()), encoding="utf-8")
    assert (
        main(
            [
                "efficiency",
                "pack",
                "--manifest",
                str(manifest),
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    packet = json.loads(capsys.readouterr().out)
    packet_path = tmp_path / packet["cache"]["path"]
    assert (
        main(
            [
                "efficiency",
                "verify",
                str(packet_path),
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert main(["efficiency", "status", "--root", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "READY"


def test_mission_and_graph_surface_invalid_cache_as_review_only(tmp_path):
    directory = tmp_path / ".factory" / "context-efficiency"
    directory.mkdir(parents=True)
    (directory / "broken.json").write_text("{}", encoding="utf-8")
    mission = mission_control_status(tmp_path)
    assert mission["blockers"]["context_efficiency_blocked"] == 1
    assert (
        mission["human_control_plane"]["next_action"]
        == "repair_context_efficiency_packet"
    )
    assert all(value is False for value in mission["authority"].values())
    snapshot = graph_ops_snapshot(tmp_path)
    assert snapshot["facts"]["context_efficiency_blocked"] == 1
    assert snapshot["recommendation"]["action"] == "repair_context_efficiency_packet"
    assert "GRAPH_OPS_CONTEXT_EFFICIENCY_REVIEW_REQUIRED" in snapshot["markers"]


def _selection_manifest(**overrides):
    value = {
        "schema": SELECTION_SCHEMA,
        "task": "repair cli parser",
        "mission_id": "task-selection",
        "contract_digest": "b" * 64,
        "changed_paths": ["tests/test_cli.py"],
        "candidates": [
            {"path": "README.md", "role": "guide"},
            {"path": "factoryline/cli.py", "role": "cli"},
            {"path": "tests/test_cli.py", "role": "test"},
        ],
        "required_paths": ["factoryline/cli.py"],
        "required_evidence_roles": ["cli", "test"],
        "max_sources": 2,
        "max_tokens": 256,
        "per_file_tokens": 64,
    }
    value.update(overrides)
    return value


def test_selection_is_explicit_ranked_progressive_and_reusable(tmp_path):
    (tmp_path / "README.md").write_text("guide", encoding="utf-8")
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "factoryline" / "cli.py").write_text(
        "def cli_handler():\n    return 'cli'\n", encoding="utf-8"
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_cli.py").write_text(
        "def test_cli_handler():\n    assert True\n", encoding="utf-8"
    )
    manifest = _selection_manifest()
    first = build_selected_context_packet(tmp_path, manifest)
    second = build_selected_context_packet(tmp_path, manifest)
    assert {row["path"] for row in first["selection"]["selected"]} == {
        "factoryline/cli.py",
        "tests/test_cli.py",
    }
    assert first["selection"]["omitted"][0]["path"] == "README.md"
    assert first["selection"]["omitted"][0]["reason"] == "lower_task_relevance"
    assert first["budget"]["progression"][0]["selected_sources"] == 2
    assert all(
        row["structure"]["status"] == "SYNTACTIC_ONLY"
        for row in first["selection"]["candidates"]
        if row["path"].endswith(".py")
    )
    assert all(
        set(row["related_paths"]).issubset(
            {candidate["path"] for candidate in first["selection"]["candidates"]}
        )
        for row in first["selection"]["candidates"]
    )
    assert second["cache"]["hit"] is True
    assert (
        verify_context_packet(tmp_path, tmp_path / first["cache"]["path"])["valid"]
        is True
    )
    status = context_efficiency_status(tmp_path)
    assert status["source_selection_status"] == "CACHED_METADATA_UNVERIFIED"
    assert status["source_evidence_status"] == "UNVERIFIED"
    assert status["reusable_packet_count"] is None
    assert status["structural_evidence_status"] == "CACHED_METADATA_ONLY"
    assert status["deep_evidence_file_count"] == 2
    assert status["observed_latency_reduction"] is None
    assert "excerpt" not in status


def test_selection_rejects_missing_or_truncated_required_evidence(tmp_path):
    (tmp_path / "README.md").write_text("guide", encoding="utf-8")
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "factoryline" / "cli.py").write_text("x" * 512, encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_cli.py").write_text("test", encoding="utf-8")
    missing = _selection_manifest(required_paths=["not-listed.py"])
    with pytest.raises(ContextEfficiencyError, match="E_REQUIRED_EVIDENCE"):
        build_selected_context_packet(tmp_path, missing)
    required = _selection_manifest(
        candidates=[{"path": "factoryline/cli.py", "role": "cli"}],
        changed_paths=["factoryline/cli.py"],
        required_paths=["factoryline/cli.py"],
        required_evidence_roles=["cli"],
        max_sources=1,
        per_file_tokens=32,
    )
    with pytest.raises(ContextEfficiencyError, match="E_REQUIRED_EVIDENCE"):
        build_selected_context_packet(tmp_path, required)


def test_changed_omitted_candidate_invalidates_selection_packet(tmp_path):
    (tmp_path / "README.md").write_text("guide", encoding="utf-8")
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "factoryline" / "cli.py").write_text("cli evidence", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_cli.py").write_text("test evidence", encoding="utf-8")
    packet = build_selected_context_packet(tmp_path, _selection_manifest())
    (tmp_path / "README.md").write_text("changed omitted evidence", encoding="utf-8")
    verified = verify_context_packet(tmp_path, tmp_path / packet["cache"]["path"])
    assert verified["state"] == "BLOCKED"
    assert verified["code"] == "E_SELECTION_DRIFT"


def test_selected_build_reads_each_candidate_once(tmp_path, monkeypatch):
    from factoryline import context_efficiency as engine

    (tmp_path / "README.md").write_text("guide", encoding="utf-8")
    (tmp_path / "factoryline").mkdir()
    (tmp_path / "factoryline" / "cli.py").write_text(
        "def run_cli():\n    pass\n", encoding="utf-8"
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_cli.py").write_text(
        "def test_cli():\n    pass\n", encoding="utf-8"
    )
    calls = []
    original = engine._stable_file

    def counted(path):
        calls.append(Path(path).resolve())
        return original(path)

    monkeypatch.setattr(engine, "_stable_file", counted)
    packet = engine.build_selected_context_packet(tmp_path, _selection_manifest())
    assert packet["selection"]["candidate_count"] == 3
    assert len(calls) == 3
    assert len(set(calls)) == 3


def test_malformed_experiment_store_is_projected_as_blocked(tmp_path):
    path = tmp_path / ".factory" / "context-efficiency" / "experiment.json"
    path.parent.mkdir(parents=True)
    path.write_text("{", encoding="utf-8")
    status = context_efficiency_status(tmp_path)
    assert status["state"] == "BLOCKED"
    assert status["experiment_status"] == "BLOCKED"
    assert status["observed_latency_reduction"] is None


def test_live_source_growth_is_bounded_while_reading(tmp_path, monkeypatch):
    from pathlib import Path

    from factoryline.context_efficiency import _stable_file

    source = tmp_path / "small.txt"
    source.write_bytes(b"x")
    original_open = Path.open

    def growing_open(path, *args, **kwargs):
        if path == source:
            return io.BytesIO(b"x" * (MAX_SOURCE_BYTES + 1))
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", growing_open)
    with pytest.raises(ContextEfficiencyError, match="E_SOURCE_BOUNDARY"):
        _stable_file(source)
