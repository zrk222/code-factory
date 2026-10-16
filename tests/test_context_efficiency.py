import io
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.context_efficiency import (
    MAX_SOURCE_BYTES,
    REQUEST_SCHEMA,
    SELECTION_SCHEMA,
    ContextEfficiencyError,
    build_context_packet,
    build_context_shard_candidate,
    build_selected_context_packet,
    context_efficiency_status,
    review_context_shard_candidate,
    validate_context_shard_candidate,
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


def _shard_fixture(tmp_path, source="stable rule: keep API local\n"):
    source_path = tmp_path / "README.md"
    source_path.write_text(source, encoding="utf-8")
    packet = build_context_packet(tmp_path, _request())
    packet_path = tmp_path / packet["cache"]["path"]
    start = source.index("stable")
    end = len(source.rstrip("\n"))
    locator = {"path": "README.md", "start_byte": start, "end_byte": end}
    candidate = build_context_shard_candidate(
        tmp_path,
        packet_path,
        "rule",
        [{"key": "network", "value": "local", "locators": [locator]}],
        {
            "correction": [locator],
            "failure": [locator],
            "approval": [locator],
            "unresolved_action": [locator],
        },
        "2026-10-20T00:00:00Z",
        now=datetime(2026, 10, 13, tzinfo=timezone.utc),
    )
    return source_path, packet_path, locator, candidate


def test_context_shard_preserves_provenance_and_requires_explicit_review(tmp_path):
    _, _, _, candidate = _shard_fixture(tmp_path)
    candidate_file = tmp_path / candidate["artifact_path"]
    persisted_candidate = candidate_file.read_bytes()
    verified = validate_context_shard_candidate(
        tmp_path, candidate, now=datetime(2026, 10, 13, tzinfo=timezone.utc)
    )
    assert verified["valid"] is True
    assert candidate["state"] == "CANDIDATE"
    assert candidate["review_status"] == "UNREVIEWED"
    assert candidate["retention_inventory_status"] == "CALLER_DECLARED"
    assert set(candidate["retained_records"]) == {
        "correction",
        "failure",
        "approval",
        "unresolved_action",
    }
    assert all(
        len(candidate["retained_records"][name]) == 1
        for name in candidate["retained_records"]
    )
    assert candidate["claims"][0]["locators"][0]["raw_source_sha256"]
    assert candidate["claims"][0]["locators"][0]["span_sha256"]

    review = review_context_shard_candidate(
        tmp_path,
        candidate,
        "accept",
        "reviewer-handle",
        "explicit caller review basis",
        now=datetime(2026, 10, 13, tzinfo=timezone.utc),
    )
    assert review["state"] == "CALLER_REVIEWED_ACCEPTED"
    assert review["reviewer_identity_authenticated"] is False
    assert review["activation"] == "NONE"
    assert candidate_file.read_bytes() == persisted_candidate
    assert (
        validate_context_shard_candidate(
            tmp_path,
            candidate,
            accepted_shards=[{"candidate": candidate, "review": review}],
            now=datetime(2026, 10, 13, tzinfo=timezone.utc),
        )["valid"]
        is True
    )


def test_context_shard_becomes_stale_after_source_changes(tmp_path):
    source_path, _, _, candidate = _shard_fixture(tmp_path)
    source_path.write_text("stable rule: changed\n", encoding="utf-8")
    result = validate_context_shard_candidate(
        tmp_path, candidate, now=datetime(2026, 10, 13, tzinfo=timezone.utc)
    )
    assert result["state"] == "STALE"
    assert result["valid"] is False


def test_context_shard_expiry_is_reported_without_acceptance(tmp_path):
    _, _, _, candidate = _shard_fixture(tmp_path)
    result = validate_context_shard_candidate(
        tmp_path, candidate, now=datetime(2026, 10, 20, tzinfo=timezone.utc)
    )
    assert result["state"] == "EXPIRED"
    with pytest.raises(ContextEfficiencyError, match="E_SHARD_NOT_REVIEWABLE"):
        review_context_shard_candidate(
            tmp_path,
            candidate,
            "accept",
            "reviewer",
            "basis",
            now=datetime(2026, 10, 20, tzinfo=timezone.utc),
        )


def test_context_shard_refuses_truncated_and_unlocatable_sources(tmp_path):
    (tmp_path / "README.md").write_text("stable " + ("long " * 1000), encoding="utf-8")
    packet = build_context_packet(tmp_path, _request())
    assert packet["sources"][0]["inclusion"] != "full"
    with pytest.raises(ContextEfficiencyError, match="E_SHARD_LOCATOR"):
        build_context_shard_candidate(
            tmp_path,
            tmp_path / packet["cache"]["path"],
            "fact",
            [
                {
                    "key": "k",
                    "value": "v",
                    "locators": [{"path": "README.md", "start_byte": 0, "end_byte": 6}],
                }
            ],
            {
                name: []
                for name in ("correction", "failure", "approval", "unresolved_action")
            },
            "2026-10-20T00:00:00Z",
            now=datetime(2026, 10, 13, tzinfo=timezone.utc),
        )


def test_context_shard_reports_only_deterministic_accepted_conflicts(tmp_path):
    _, packet_path, locator, candidate = _shard_fixture(tmp_path)
    empty_inventory = {
        name: [] for name in ("correction", "failure", "approval", "unresolved_action")
    }
    other = build_context_shard_candidate(
        tmp_path,
        packet_path,
        "rule",
        [{"key": "network", "value": "remote", "locators": [locator]}],
        empty_inventory,
        "2026-10-20T00:00:00Z",
        now=datetime(2026, 10, 13, tzinfo=timezone.utc),
    )
    review = review_context_shard_candidate(
        tmp_path,
        other,
        "accept",
        "reviewer",
        "explicit review",
        now=datetime(2026, 10, 13, tzinfo=timezone.utc),
    )
    result = validate_context_shard_candidate(
        tmp_path,
        candidate,
        accepted_shards=[{"candidate": other, "review": review}],
        now=datetime(2026, 10, 13, tzinfo=timezone.utc),
    )
    assert result["state"] == "CONTRADICTED"
    assert result["contradiction"]["basis"].startswith("same type and normalized key")


def test_context_shard_blocks_incomplete_accepted_set_over_limit(tmp_path):
    _, _, _, candidate = _shard_fixture(tmp_path)
    result = validate_context_shard_candidate(
        tmp_path,
        candidate,
        accepted_shards=[{}] * 257,
        now=datetime(2026, 10, 13, tzinfo=timezone.utc),
    )
    assert result["state"] == "BLOCKED"
    assert result["valid"] is False


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
    cached_path = tmp_path / first["cache"]["path"]
    assert json.loads(cached_path.read_text(encoding="utf-8")) == first
    assert second["cache"]["hit"] is True
    assert second["packet_sha256"] != first["packet_sha256"]
    assert second["packet_sha256"] == __import__(
        "factoryline.context_efficiency", fromlist=["_packet_digest"]
    )._packet_digest(second)
    assert (
        verify_context_packet(tmp_path, tmp_path / first["cache"]["path"])["valid"]
        is True
    )
    assert context_efficiency_status(tmp_path)["cache_hits"] == 1


def test_hit_output_is_valid_and_cache_file_stays_immutable(tmp_path):
    (tmp_path / "README.md").write_text("stable", encoding="utf-8")
    first = build_context_packet(tmp_path, _request())
    cache_path = tmp_path / first["cache"]["path"]
    original = cache_path.read_bytes()
    out = tmp_path / "hit.json"
    hit = build_context_packet(tmp_path, _request(), out=out)
    assert cache_path.read_bytes() == original
    assert json.loads(out.read_text(encoding="utf-8")) == hit
    assert hit["packet_sha256"] == __import__(
        "factoryline.context_efficiency", fromlist=["_packet_digest"]
    )._packet_digest(hit)
    assert verify_context_packet(tmp_path, out)["valid"] is True


def test_public_root_reparse_path_fails_before_resolution(tmp_path, monkeypatch):
    from factoryline.context_efficiency import ContextEfficiencyError
    from types import SimpleNamespace
    import stat

    (tmp_path / "README.md").write_text("stable", encoding="utf-8")
    linked_root = tmp_path.parent / (tmp_path.name + "-root-link")
    try:
        linked_root.symlink_to(tmp_path, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks unavailable")
    with pytest.raises(ContextEfficiencyError, match="E_PATH_LINK"):
        build_context_packet(linked_root, _request())
    with pytest.raises(ContextEfficiencyError, match="E_PATH_LINK"):
        context_efficiency_status(linked_root)

    plain_root = tmp_path / "plain-root"
    plain_root.mkdir()
    real_lstat = Path.lstat

    def fake_reparse_lstat(path):
        if path == plain_root:
            return SimpleNamespace(
                st_mode=stat.S_IFDIR,
                st_file_attributes=0x400,
            )
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_reparse_lstat)
    with pytest.raises(ContextEfficiencyError, match="E_PATH_LINK"):
        build_context_packet(plain_root, _request())
    with pytest.raises(ContextEfficiencyError, match="E_PATH_LINK"):
        context_efficiency_status(plain_root)


def test_failed_cache_counter_write_reports_unknown(tmp_path, monkeypatch):
    import factoryline.context_efficiency as module

    (tmp_path / "README.md").write_text("stable", encoding="utf-8")
    first = build_context_packet(tmp_path, _request())
    monkeypatch.setattr(module, "_record_cache_hit", lambda *_: False)
    out = tmp_path / "unrecorded-hit.json"
    hit = build_context_packet(tmp_path, _request(), out=out)
    assert hit["cache"]["usage_count"] is None
    assert verify_context_packet(tmp_path, out)["valid"] is True
    assert context_efficiency_status(tmp_path)["cache_hits"] is None
    assert (tmp_path / first["cache"]["path"]).is_file()


def test_failed_counter_and_marker_keep_status_as_lower_bound(tmp_path, monkeypatch):
    import factoryline.context_efficiency as module

    (tmp_path / "README.md").write_text("stable", encoding="utf-8")
    build_context_packet(tmp_path, _request())
    assert build_context_packet(tmp_path, _request())["cache"]["usage_count"] == 1
    monkeypatch.setattr(module, "_record_cache_hit", lambda *_: False)
    monkeypatch.setattr(module, "_mark_cache_usage_unknown", lambda *_: None)
    hit = build_context_packet(tmp_path, _request())
    assert hit["cache"]["usage_count"] is None
    status = context_efficiency_status(tmp_path)
    assert status["cache_hits"] == 1
    assert status["cache_hits_semantics"] == "recorded_lower_bound"
    assert status["cache_usage_completeness"] == "UNKNOWN"


def test_cache_usage_row_cap_reports_unknown(tmp_path, monkeypatch):
    import factoryline.context_efficiency as module

    (tmp_path / "README.md").write_text("stable", encoding="utf-8")
    build_context_packet(tmp_path, _request())
    monkeypatch.setattr(module, "MAX_USAGE_ROWS", 0)
    hit = build_context_packet(tmp_path, _request())
    assert hit["cache"]["usage_count"] is None
    assert context_efficiency_status(tmp_path)["cache_hits"] is None


def test_cache_hit_counter_is_separate_and_bounded(tmp_path):
    from factoryline.context_efficiency import (
        MAX_USAGE_ROWS,
        _cache_hit_count,
        _record_cache_hit,
    )

    (tmp_path / "README.md").write_text("stable", encoding="utf-8")
    packet = build_context_packet(tmp_path, _request())
    cache_key = packet["cache"]["key"]
    _record_cache_hit(tmp_path, cache_key)
    _record_cache_hit(tmp_path, cache_key)
    assert _cache_hit_count(tmp_path, cache_key) == 2
    assert context_efficiency_status(tmp_path)["cache_hits"] == 2
    for index in range(MAX_USAGE_ROWS + 1):
        _record_cache_hit(tmp_path, f"{index:064x}")
    import sqlite3

    with sqlite3.connect(tmp_path / ".factory/context-efficiency/usage.sqlite3") as db:
        count = db.execute("SELECT COUNT(*) FROM cache_usage").fetchone()[0]
    assert count == MAX_USAGE_ROWS


def test_cache_usage_symlink_is_ignored(tmp_path):
    from factoryline.context_efficiency import _cache_hit_count, _record_cache_hit

    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir()
    cache_dir = tmp_path / ".factory/context-efficiency"
    cache_dir.parent.mkdir(parents=True)
    try:
        cache_dir.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks unavailable")
    _record_cache_hit(tmp_path, "a" * 64)
    assert _cache_hit_count(tmp_path, "a" * 64) is None
    assert list(outside.iterdir()) == []


def test_cache_usage_rejects_reparse_ancestor_and_invalid_counter(
    tmp_path, monkeypatch
):
    from types import SimpleNamespace
    import stat
    import sqlite3

    from factoryline.context_efficiency import (
        _cache_hit_count,
        _has_reparse_ancestor,
    )

    candidate = tmp_path / "workspace"
    candidate.mkdir()
    real_lstat = Path.lstat

    def fake_lstat(path):
        if path == candidate:
            return SimpleNamespace(
                st_mode=stat.S_IFDIR,
                st_file_attributes=0x400,
            )
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    assert _has_reparse_ancestor(candidate) is True
    monkeypatch.setattr(Path, "lstat", real_lstat)

    cache_dir = candidate / ".factory/context-efficiency"
    cache_dir.mkdir(parents=True)
    database_path = cache_dir / "usage.sqlite3"
    with sqlite3.connect(database_path) as database:
        database.execute("CREATE TABLE cache_usage (cache_key TEXT, hits INTEGER)")
        database.execute("INSERT INTO cache_usage VALUES (?, ?)", ("a" * 64, -1))
    assert _cache_hit_count(candidate, "a" * 64) is None


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


def test_cli_context_shard_build_validate_review_is_bounded_and_nonactivating(
    tmp_path, capsys
):
    (tmp_path / "README.md").write_text(
        "stable rule: keep API local\n", encoding="utf-8"
    )
    packet = build_context_packet(tmp_path, _request())
    packet_path = packet["cache"]["path"]
    locator = {"path": "README.md", "start_byte": 0, "end_byte": 27}
    manifest = tmp_path / "shard-request.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "factory.context-shard-request.v1",
                "packet_path": packet_path,
                "shard_type": "rule",
                "claims": [{"key": "network", "value": "local", "locators": [locator]}],
                "retained_records": {
                    name: [locator]
                    for name in (
                        "correction",
                        "failure",
                        "approval",
                        "unresolved_action",
                    )
                },
                "expires_at": "2026-10-20T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "input-directory").mkdir()
    assert (
        main(
            [
                "efficiency",
                "shard-build",
                "--manifest",
                "input-directory",
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 2
    )
    rejected_directory = json.loads(capsys.readouterr().out)
    assert rejected_directory["code"] == "E_PATH_INPUT"
    assert str(tmp_path) not in rejected_directory["message"]
    assert (
        main(
            [
                "efficiency",
                "shard-build",
                "--manifest",
                str(manifest),
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 2
    )
    rejected_manifest = json.loads(capsys.readouterr().out)
    assert rejected_manifest["code"] == "E_PATH_BOUNDARY"
    assert str(tmp_path) not in rejected_manifest["message"]
    assert (
        main(
            [
                "efficiency",
                "shard-build",
                "--manifest",
                "shard-request.json",
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    candidate = json.loads(capsys.readouterr().out)
    assert candidate["state"] == "CANDIDATE"
    assert candidate["review_status"] == "UNREVIEWED"
    candidate_path = candidate["artifact_path"]
    accepted = tmp_path / "accepted.json"
    accepted.write_text("[]", encoding="utf-8")

    assert (
        main(
            [
                "efficiency",
                "shard-validate",
                candidate_path,
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert (
        main(
            [
                "efficiency",
                "shard-validate",
                candidate_path,
                "--accepted",
                "accepted.json",
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert (
        main(
            [
                "efficiency",
                "shard-validate",
                candidate_path,
                "--accepted",
                str(accepted),
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 2
    )
    rejected_accepted = json.loads(capsys.readouterr().out)
    assert rejected_accepted["code"] == "E_PATH_BOUNDARY"
    assert str(tmp_path) not in rejected_accepted["message"]
    assert (
        main(
            [
                "efficiency",
                "shard-review",
                candidate_path,
                "--decision",
                "accept",
                "--reviewer-id",
                "operator",
                "--review-basis",
                "explicit local review",
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    review = json.loads(capsys.readouterr().out)
    assert review["reviewer_identity_authenticated"] is False
    assert review["activation"] == "NONE"

    assert (
        main(
            [
                "efficiency",
                "shard-validate",
                str(tmp_path / candidate_path),
                "--root",
                str(tmp_path),
                "--json",
            ]
        )
        == 2
    )
    error = json.loads(capsys.readouterr().out)
    assert error["code"] == "E_PATH_BOUNDARY"


def test_cli_context_shard_rejects_linked_workspace_root(tmp_path, capsys):
    linked_root = tmp_path.parent / f"{tmp_path.name}-linked"
    try:
        linked_root.symlink_to(tmp_path, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")

    assert (
        main(
            [
                "efficiency",
                "shard-validate",
                "candidate.json",
                "--root",
                str(linked_root),
                "--json",
            ]
        )
        == 2
    )
    error = json.loads(capsys.readouterr().out)
    assert error["code"] == "E_PATH_LINK"
    assert str(linked_root) not in error["message"]


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


@pytest.mark.parametrize("change", ["unchanged", "added", "deleted", "configuration"])
def test_verify_database_context_checks_current_inventory(tmp_path, change):
    from factoryline.context_efficiency import verify_database_context

    schema = tmp_path / "schema.sql"
    schema.write_text("CREATE TABLE users (id INT);", encoding="utf-8")
    context = {
        "discovery": {
            "paths": ["schema.sql"],
            "configuration_present": False,
            "inventory_complete": True,
        }
    }
    if change == "added":
        (tmp_path / "added.sql").write_text(
            "CREATE TABLE roles (id INT);", encoding="utf-8"
        )
    elif change == "deleted":
        schema.unlink()
    elif change == "configuration":
        (tmp_path / "factory.database.json").write_text("{}", encoding="utf-8")
    if change == "unchanged":
        assert verify_database_context(tmp_path, context, ValueError) is None
    else:
        with pytest.raises(ValueError, match="inventory changed"):
            verify_database_context(tmp_path, context, ValueError)


def test_database_context_entities_flow_through_existing_selected_packet(tmp_path):
    schema = tmp_path / "schema.sql"
    schema.write_text("CREATE TABLE accounts (id INTEGER PRIMARY KEY);\n")
    (tmp_path / "models.py").write_text(
        "from sqlalchemy import Column, Integer\n"
        "from sqlalchemy.orm import declarative_base\n"
        "Base = declarative_base()\n"
        "class Account(Base):\n"
        "    __tablename__ = 'accounts'\n"
        "    id = Column(Integer, primary_key=True)\n"
    )
    manifest = _selection_manifest(
        task="review accounts schema and model",
        changed_paths=["schema.sql"],
        candidates=[
            {"path": "schema.sql", "role": "schema"},
            {"path": "models.py", "role": "model"},
        ],
        required_paths=["schema.sql"],
        required_evidence_roles=["schema", "model"],
    )
    packet = build_selected_context_packet(tmp_path, manifest)
    metadata = {item["path"]: item for item in packet["selection"]["candidates"]}
    assert metadata["schema.sql"]["structure"]["status"] == "DATABASE_STATIC_ONLY"
    assert "accounts" in metadata["models.py"]["structure"]["identifiers"]
    assert "models.py" in metadata["schema.sql"]["related_paths"]
    packet_path = tmp_path / packet["cache"]["path"]
    assert verify_context_packet(tmp_path, packet_path)["valid"] is True
    schema.write_text(schema.read_text() + "ALTER TABLE accounts ADD email TEXT;\n")
    assert verify_context_packet(tmp_path, packet_path)["valid"] is False


@pytest.mark.parametrize("snapshot", [{}, {"models.py": object()}])
def test_database_oracle_missing_or_corrupt_snapshot_falls_back_to_source(
    tmp_path, monkeypatch, snapshot
):
    import ast

    from factoryline import intent_quality, review_audits
    from factoryline.context_efficiency import _database_workspace_context_from_oracle

    source = (
        b"from sqlalchemy import Column, Integer\n"
        b"from sqlalchemy.orm import declarative_base\n"
        b"Base = declarative_base()\n"
        b"class Account(Base):\n"
        b"    __tablename__ = 'accounts'\n"
        b"    id = Column(Integer, primary_key=True)\n"
    )
    path = tmp_path / "models.py"
    path.write_bytes(source)
    calls = []
    original_parse = ast.parse

    def counted_parse(text, *args, **kwargs):
        if kwargs.get("filename") == "models.py":
            calls.append(text)
        return original_parse(text, *args, **kwargs)

    monkeypatch.setattr(ast, "parse", counted_parse)
    monkeypatch.setattr(intent_quality, "_DB_CACHE", {})
    monkeypatch.setattr(intent_quality, "_DB_CACHE_BYTES", 0)
    result = _database_workspace_context_from_oracle(
        tmp_path,
        {path: source},
        review_audits._security_source_bytes,
        [{"path": "models.py", "state": "retained", "retained": True}],
        snapshot,
    )
    assert calls == [source.decode("utf-8")]
    assert [table["name"] for table in result["tables"]] == ["accounts"]


def test_oracle_source_input_facade_matches_bound_helper(tmp_path):
    from factoryline import intent_quality, review_audits

    path = tmp_path / "module.py"
    path.write_bytes(b"value = 1\n")
    expected = intent_quality._oracle_source_inputs(
        tmp_path,
        [path],
        review_audits._security_source_bytes,
        review_audits.local_file,
        review_audits._measure_hash,
        review_audits.sha256,
        review_audits.RuntimeAuditError,
        review_audits.MAX_BYTES,
        16 * 1024 * 1024,
    )
    assert review_audits._oracle_source_inputs(tmp_path, [path]) == expected


def test_oracle_database_projection_reuses_only_fresh_owned_tree(tmp_path, monkeypatch):
    import ast

    from factoryline import intent_quality, review_audits
    from factoryline.context_efficiency import database_workspace_context

    source = (
        b"from sqlalchemy import Column, Integer\n"
        b"from sqlalchemy.orm import declarative_base\n"
        b"Base = declarative_base()\n"
        b"class Account(Base):\n"
        b"    __tablename__ = 'accounts'\n"
        b"    id = Column(Integer, primary_key=True)\n"
    )
    path = tmp_path / "models.py"
    path.write_bytes(source)
    files = [path]
    calls = []
    original_parse = ast.parse

    def counted_parse(text, *args, **kwargs):
        if kwargs.get("filename") == "models.py":
            calls.append(text)
        return original_parse(text, *args, **kwargs)

    monkeypatch.setattr(ast, "parse", counted_parse)
    monkeypatch.setattr(intent_quality, "_DB_CACHE", {})
    monkeypatch.setattr(intent_quality, "_DB_CACHE_BYTES", 0)
    review_audits._oracle_context_cache_clear()
    inventory = []
    projection = {}
    cold = review_audits._project_oracle_context(
        tmp_path,
        files,
        python_inventory_out=inventory,
        database_context_out=projection,
    )
    assert calls == [source]
    assert [table["name"] for table in projection["tables"]] == ["accounts"]

    warm_projection = {"stale": True}
    warm_inventory = []
    warm = review_audits._project_oracle_context(
        tmp_path,
        files,
        python_inventory_out=warm_inventory,
        database_context_out=warm_projection,
    )
    assert not warm_projection
    assert len(calls) == 1
    monkeypatch.setattr(intent_quality, "_DB_CACHE", {})
    monkeypatch.setattr(intent_quality, "_DB_CACHE_BYTES", 0)
    fallback = database_workspace_context(
        tmp_path, warm[3], review_audits._security_source_bytes, warm_inventory
    )
    assert calls == [source, source.decode("utf-8")]
    assert fallback == projection
    assert cold[3] == warm[3]

    changed = source.replace(b"accounts", b"customers")
    path.write_bytes(changed)
    changed_projection = {}
    review_audits._project_oracle_context(
        tmp_path, files, database_context_out=changed_projection
    )
    assert calls[-1] == changed
    assert [table["name"] for table in changed_projection["tables"]] == ["customers"]

    forged = original_parse(
        "class Forged:\n    __tablename__ = 'forged'\n", filename="models.py"
    )
    monkeypatch.setattr(intent_quality, "_DB_CACHE", {})
    monkeypatch.setattr(intent_quality, "_DB_CACHE_BYTES", 0)
    public = intent_quality.database_structure(
        {"models.py": changed}, snapshots={"models.py": forged}
    )
    assert calls[-1] == changed.decode("utf-8")
    assert [table["name"] for table in public["tables"]] == ["customers"]


def test_security_scan_reuses_oracle_tree_for_database_projection(
    tmp_path, monkeypatch
):
    import ast

    from factoryline import context_efficiency, intent_quality, review_audits

    source = (
        b"from sqlalchemy import Column, Integer\n"
        b"from sqlalchemy.orm import declarative_base\n"
        b"Base = declarative_base()\n"
        b"class Account(Base):\n"
        b"    __tablename__ = 'accounts'\n"
        b"    id = Column(Integer, primary_key=True)\n"
    )
    path = tmp_path / "models.py"
    path.write_bytes(source)
    calls = []
    original_parse = ast.parse

    def counted_parse(text, *args, **kwargs):
        if kwargs.get("filename") == "models.py":
            calls.append(text)
        return original_parse(text, *args, **kwargs)

    monkeypatch.setattr(ast, "parse", counted_parse)
    monkeypatch.setattr(intent_quality, "_DB_CACHE", {})
    monkeypatch.setattr(intent_quality, "_DB_CACHE_BYTES", 0)
    review_audits._oracle_context_cache_clear()
    private_calls = []
    public_calls = []
    private_projection = context_efficiency._database_workspace_context_from_oracle
    public_projection = context_efficiency.database_workspace_context

    def counted_private(*args, **kwargs):
        private_calls.append(True)
        return private_projection(*args, **kwargs)

    def counted_public(*args, **kwargs):
        public_calls.append(True)
        return public_projection(*args, **kwargs)

    monkeypatch.setattr(
        context_efficiency, "_database_workspace_context_from_oracle", counted_private
    )
    monkeypatch.setattr(
        context_efficiency, "database_workspace_context", counted_public
    )
    database = {}
    review_audits._scan_security_sources(
        tmp_path, [path], (), {}, test_file_patterns=set(), database_context=database
    )
    assert calls == [source, source]
    assert len(private_calls) == 1
    assert not public_calls
    assert [table["name"] for table in database["tables"]] == ["accounts"]

    warm_database = {}
    review_audits._scan_security_sources(
        tmp_path,
        [path],
        (),
        {},
        test_file_patterns=set(),
        database_context=warm_database,
    )
    assert calls == [source, source, source]
    assert len(private_calls) == 1
    assert len(public_calls) == 1
    assert warm_database == database


def test_database_context_structural_metadata_respects_secret_boundaries():
    from factoryline.context_efficiency import _structural_evidence

    source = b"CREATE TABLE private_accounts (id INTEGER);"
    result = _structural_evidence("credentials.sql", source)
    assert result["status"] == "NOT_PARSED"
    assert not result["identifiers"]


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


@pytest.mark.parametrize("boundary", ["per_file", "aggregate", "inventory"])
def test_database_context_resource_limits_prevent_partial_complete_graph(
    tmp_path, monkeypatch, boundary
):
    from factoryline import context_efficiency as engine
    from factoryline import intent_quality

    count = 257 if boundary == "inventory" else 17 if boundary == "aggregate" else 1
    for index in range(count):
        (tmp_path / f"{index:03}.sql").write_bytes(b"placeholder")

    def reject_partial_parse(*args, **kwargs):
        pytest.fail("Resource-limited inputs must not reach graph extraction")

    monkeypatch.setattr(intent_quality, "database_structure", reject_partial_parse)
    size = 1_000_001 if boundary == "per_file" else 1_000_000
    graph = engine.database_workspace_context(
        tmp_path, {}, lambda root, relative: b"x" * size
    )
    assert graph["status"] == "INCOMPLETE"
    assert not graph["discovery"]["inventory_complete"]
    assert any("limit" in gap for gap in graph["gaps"])
    assert graph["tables"] == []
    assert graph["queries"] == []


def test_database_context_incomplete_advice_explains_missing_evidence():
    from factoryline.audit_action_refs import _security_scan_action_summary

    advice = _security_scan_action_summary("INCOMPLETE")
    assert "coverage gaps" in advice
    assert "could not be verified" in advice
    assert "Resolve each listed finding" not in advice


def test_database_context_cache_enforces_entry_byte_and_replacement_bounds(monkeypatch):
    from factoryline import intent_quality as reader

    monkeypatch.setattr(reader, "_DB_CACHE", {})
    monkeypatch.setattr(reader, "_DB_CACHE_BYTES", 0)
    for index in range(20):
        reader._db_cache_write(str(index), b"{}")
    assert len(reader._DB_CACHE) == 16
    assert reader._DB_CACHE_BYTES == 32
    reader._db_cache_write("0", b'{"updated":true}')
    assert len(reader._DB_CACHE) == 16
    assert reader._DB_CACHE_BYTES == sum(map(len, reader._DB_CACHE.values()))

    reader._db_cache_write("large", b"x" * 3_999_999)
    assert reader._DB_CACHE_BYTES <= 4_000_000
    assert reader._DB_CACHE_BYTES == sum(map(len, reader._DB_CACHE.values()))
    before = dict(reader._DB_CACHE)
    reader._db_cache_write("oversized", b"x" * 4_000_001)
    assert reader._DB_CACHE == before
    assert reader._DB_CACHE_BYTES == sum(map(len, reader._DB_CACHE.values()))


def test_select_context_request_returns_only_explicit_bound_sources(tmp_path):
    from factoryline.context_efficiency import select_context_request

    (tmp_path / "README.md").write_text("approved guide", encoding="utf-8")
    (tmp_path / "unlisted.py").write_text("never selected", encoding="utf-8")
    manifest = _selection_manifest(
        candidates=[{"path": "README.md", "role": "guide"}],
        changed_paths=["README.md"],
        required_paths=["README.md"],
        required_evidence_roles=["guide"],
        max_sources=1,
    )
    request, selection = select_context_request(tmp_path, manifest)
    assert [item["path"] for item in request["sources"]] == ["README.md"]
    assert selection["candidate_count"] == 1
    assert not (tmp_path / ".factory").exists()
