import ast
import io
import json
from datetime import datetime, timedelta, timezone
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
    _module_has_dynamic_capability_access,
    review_context_shard_candidate,
    validate_context_shard_candidate,
    verify_context_packet,
)
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.mission_control_status import mission_control_status
from factoryline.review_audits import security_scan


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


@pytest.mark.parametrize(
    "source, expected",
    [
        ("from sys import modules as loaded\nloaded['unittest.mock']", True),
        ("from sys import *", True),
        ("from importlib import import_module as load\nload('unittest.mock')", True),
        ("from builtins import __import__ as load\nload('unittest.mock')", True),
        ("from sys import version as release", False),
    ],
    ids=[
        "sys-modules-alias",
        "sys-star-import",
        "importlib-import-module-alias",
        "builtins-import-alias",
        "unrelated-sys-import",
    ],
)
def test_dynamic_capability_guard_covers_module_reacquisition_aliases(source, expected):
    nodes = tuple(ast.walk(ast.parse(source)))
    assert _module_has_dynamic_capability_access(nodes) is expected


@pytest.mark.parametrize(
    "source",
    [
        "from sys import modules as loaded\n"
        "async def compute():\n    return 3\n"
        "def fail():\n    raise RuntimeError()\n"
        "loaded[__name__].compute = fail\n"
        "def test_behavior():\n    compute()\n",
        "from sys import modules as loaded\n"
        "def perform():\n    pass\n"
        "def fail():\n    raise RuntimeError()\n"
        "loaded[__name__].perform = fail\n"
        "def test_behavior():\n    perform()\n",
    ],
    ids=["registry-mutated-coroutine", "registry-mutated-pass-stub"],
)
def test_registry_mutated_completion_helpers_remain_unknown(tmp_path, source):
    (tmp_path / "test_registry_completion.py").write_text(source, encoding="utf-8")
    report = security_scan(tmp_path, cache_enabled=False)
    assert "QUALITY_HOLLOW_TEST" not in report["finding_counts"]
    assert report["finding_counts"].get("QUALITY_UNKNOWN_TEST_ORACLE") == 1


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
                "expires_at": (
                    datetime.now(timezone.utc) + timedelta(days=1)
                ).isoformat(),
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
    from factoryline.context_efficiency import _database_workspace_context

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
    result = _database_workspace_context(
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
    private_projection = context_efficiency._database_workspace_context
    public_projection = context_efficiency.database_workspace_context

    def counted_private(*args, **kwargs):
        if len(args) > 4 or "oracle_snapshots" in kwargs:
            private_calls.append(True)
        return private_projection(*args, **kwargs)

    def counted_public(*args, **kwargs):
        public_calls.append(True)
        return public_projection(*args, **kwargs)

    monkeypatch.setattr(
        context_efficiency, "_database_workspace_context", counted_private
    )
    monkeypatch.setattr(
        context_efficiency, "database_workspace_context", counted_public
    )
    database = {}
    review_audits._scan_security_sources(
        tmp_path, [path], (), {}, test_file_patterns=set(), database_context=database
    )
    assert calls == [source]
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
    assert calls == [source, source]
    assert len(private_calls) == 1
    assert len(public_calls) == 1
    assert warm_database == database


def test_security_scan_reuses_only_fresh_oracle_trees_on_cold_path(
    tmp_path, monkeypatch
):
    import ast
    import json

    from factoryline import intent_quality, review_audits

    sources = {
        "models.py": (
            "from sqlalchemy import Column, Integer\n"
            "from sqlalchemy.orm import declarative_base\n"
            "Base = declarative_base()\n"
            "class Account(Base):\n"
            "    __tablename__ = 'accounts'\n"
            "    id = Column(Integer, primary_key=True)\n"
            "def unfinished():\n"
            "    pass\n"
        ),
        "helper.py": "def invoke(callback):\n    callback()\n",
        "app.py": "from helper import invoke\ndef run(callback):\n    invoke(callback)\n",
    }
    for name, source in sources.items():
        (tmp_path / name).write_text(source, encoding="utf-8")
    model_bytes = (tmp_path / "models.py").read_bytes()
    calls = []
    parse = ast.parse

    def counted_parse(source, *args, **kwargs):
        if kwargs.get("filename") == "models.py":
            calls.append(source)
        return parse(source, *args, **kwargs)

    monkeypatch.setattr(ast, "parse", counted_parse)
    monkeypatch.setattr(intent_quality, "_DB_CACHE", {})
    monkeypatch.setattr(intent_quality, "_DB_CACHE_BYTES", 0)
    review_audits._oracle_context_cache_clear()
    scan_snapshot = review_audits._security_scan_file_snapshot
    structural_inputs = []

    def with_stale_sidecars(*args, **kwargs):
        tree = args[7]
        before = ast.dump(tree, include_attributes=True)
        tree._security_stale_test_marker = "must be cleared"
        structural_inputs.append(before)
        result = scan_snapshot(*args, **kwargs)
        assert not hasattr(tree, "_security_stale_test_marker")
        assert ast.dump(tree, include_attributes=True) == before
        return result

    monkeypatch.setattr(
        review_audits, "_security_scan_file_snapshot", with_stale_sidecars
    )
    cold = review_audits.security_scan(tmp_path, cache_enabled=True)
    assert calls == [model_bytes]
    assert structural_inputs
    assert [table["name"] for table in cold["database_context"]["tables"]] == [
        "accounts"
    ]
    assert "QUALITY_EMPTY_IMPLEMENTATION" in cold["finding_counts"]

    # A warm oracle-cache hit has no producer-owned AST, so scanning reparses.
    warm = review_audits.security_scan(tmp_path, cache_enabled=True)
    assert calls == [model_bytes, model_bytes]
    assert warm["audit_sha256"] == cold["audit_sha256"]
    assert warm["database_context"] == cold["database_context"]
    assert json.loads(json.dumps(warm, sort_keys=True)) == warm


def test_security_scan_reparses_a_tree_changed_by_an_intermediate_consumer(
    tmp_path, monkeypatch
):
    import ast

    from factoryline import context_efficiency, intent_quality, review_audits

    source = (
        "from sqlalchemy import Column, Integer\n"
        "from sqlalchemy.orm import declarative_base\n"
        "Base = declarative_base()\n"
        "class Account(Base):\n"
        "    __tablename__ = 'accounts'\n"
        "    id = Column(Integer, primary_key=True)\n"
    )
    path = tmp_path / "models.py"
    path.write_text(source, encoding="utf-8")
    source_bytes = path.read_bytes()
    parse = ast.parse
    calls = []

    def counted_parse(text, *args, **kwargs):
        if kwargs.get("filename") == "models.py":
            calls.append(text)
        return parse(text, *args, **kwargs)

    monkeypatch.setattr(ast, "parse", counted_parse)
    monkeypatch.setattr(intent_quality, "_DB_CACHE", {})
    monkeypatch.setattr(intent_quality, "_DB_CACHE_BYTES", 0)
    review_audits._oracle_context_cache_clear()
    expected = review_audits.security_scan(tmp_path, cache_enabled=False)
    assert calls == [source_bytes]

    parse_calls = len(calls)
    review_audits._oracle_context_cache_clear()
    project = context_efficiency._database_workspace_context
    mutated_trees = []

    def mutate_after_database_projection(root, sources, reader, inventory, snapshots):
        result = project(root, sources, reader, inventory, snapshots)
        tree = snapshots[path]
        tree.body.append(ast.Pass())
        mutated_trees.append(tree)
        return result

    monkeypatch.setattr(
        context_efficiency,
        "_database_workspace_context",
        mutate_after_database_projection,
    )
    actual = review_audits.security_scan(tmp_path, cache_enabled=False)
    assert calls[parse_calls:] == [source_bytes, source_bytes]
    assert actual["audit_sha256"] == expected["audit_sha256"]
    assert actual["database_context"] == expected["database_context"]
    assert len(mutated_trees) == 1
    assert json.loads(json.dumps(actual, sort_keys=True)) == actual


def test_security_scan_falls_back_when_producer_snapshot_is_missing(
    tmp_path, monkeypatch
):
    import ast

    from factoryline import review_audits

    source = b"def unfinished():\n    pass\n"
    path = tmp_path / "models.py"
    path.write_bytes(source)
    original_parse = ast.parse
    parsed = []

    def counted_parse(text, *args, **kwargs):
        if kwargs.get("filename") == "models.py":
            parsed.append(text)
        return original_parse(text, *args, **kwargs)

    monkeypatch.setattr(ast, "parse", counted_parse)
    review_audits._oracle_context_cache_clear()
    bound = review_audits.contracts.bound_snapshots

    def drop_snapshot(root, files, source_bytes, source_bindings):
        snapshots = bound(root, files, source_bytes, source_bindings)
        snapshots.pop(path, None)
        return snapshots

    monkeypatch.setattr(review_audits.contracts, "bound_snapshots", drop_snapshot)
    result = review_audits.security_scan(tmp_path, cache_enabled=False)

    assert parsed == [source, source]
    assert "QUALITY_EMPTY_IMPLEMENTATION" in result["finding_counts"]
    assert json.loads(json.dumps(result, sort_keys=True)) == result


@pytest.mark.parametrize("corruption", ["non_module", "source_sha"])
def test_security_scan_rebuilds_corrupt_producer_snapshot(
    tmp_path, monkeypatch, corruption
):
    import ast

    from factoryline import intent_quality, review_audits

    source = b"def run(value):\n    return value\n"
    path = tmp_path / "app.py"
    path.write_bytes(source)
    review_audits._oracle_context_cache_clear()
    monkeypatch.setattr(intent_quality, "_DB_CACHE", {})
    monkeypatch.setattr(intent_quality, "_DB_CACHE_BYTES", 0)
    expected = review_audits.security_scan(tmp_path, cache_enabled=False)
    review_audits._oracle_context_cache_clear()
    bound = review_audits.contracts.bound_snapshots
    original_parse = ast.parse
    parsed = []

    def counted_parse(text, *args, **kwargs):
        if kwargs.get("filename") == "app.py":
            parsed.append(text)
        return original_parse(text, *args, **kwargs)

    def corrupt_snapshot(root, files, source_bytes, source_bindings):
        snapshots = bound(root, files, source_bytes, source_bindings)
        if corruption == "non_module":
            snapshots[path] = object()
        else:
            snapshots[path]._oracle_source_sha256 = "0" * 64
        return snapshots

    monkeypatch.setattr(ast, "parse", counted_parse)
    monkeypatch.setattr(review_audits.contracts, "bound_snapshots", corrupt_snapshot)
    actual = review_audits.security_scan(tmp_path, cache_enabled=False)

    assert parsed == [source, source]
    assert actual["audit_sha256"] == expected["audit_sha256"]
    assert json.loads(json.dumps(actual, sort_keys=True)) == actual


def test_security_scan_rechecks_configuration_after_snapshot_consumption(
    tmp_path, monkeypatch
):
    import pytest

    from factoryline import review_audits
    from factoryline.review_audits import ReviewAuditError

    config = tmp_path / "pyproject.toml"
    config.write_text('[tool.mypy]\nfiles = ["typing_probe.py"]\n', encoding="utf-8")
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\npython_files = typing_probe.py\n", encoding="utf-8"
    )
    (tmp_path / "typing_probe.py").write_text(
        "from typing_extensions import assert_type\ndef test_type():\n"
        "    assert_type(compute(), int)\n",
        encoding="utf-8",
    )
    original = review_audits._security_scan_file_snapshot

    def mutate_after_snapshot(*args, **kwargs):
        result = original(*args, **kwargs)
        config.write_text("[tool.mypy]\nfiles = []\n", encoding="utf-8")
        return result

    monkeypatch.setattr(
        review_audits, "_security_scan_file_snapshot", mutate_after_snapshot
    )
    with pytest.raises(ReviewAuditError, match="Evidence changed.*pyproject.toml"):
        review_audits.security_scan(tmp_path, cache_enabled=False)


@pytest.mark.parametrize("cache_enabled", [False, True])
def test_security_scan_rechecks_sources_after_cold_and_warm_consumption(
    tmp_path, monkeypatch, cache_enabled
):
    import pytest

    from factoryline import review_audits
    from factoryline.review_audits import ReviewAuditError

    source = tmp_path / "app.py"
    source.write_text("def run(value):\n    return value\n", encoding="utf-8")
    review_audits._oracle_context_cache_clear()
    if cache_enabled:
        review_audits.security_scan(tmp_path, cache_enabled=True)
        scanner = review_audits._security_scan_file
        scanner_name = "_security_scan_file"
    else:
        scanner = review_audits._security_scan_file_snapshot
        scanner_name = "_security_scan_file_snapshot"

    def mutate_after_scan(*args, **kwargs):
        result = scanner(*args, **kwargs)
        source.write_text("def run(value):\n    eval(value)\n", encoding="utf-8")
        return result

    monkeypatch.setattr(review_audits, scanner_name, mutate_after_scan)
    with pytest.raises(ReviewAuditError, match="Evidence changed.*app.py"):
        review_audits.security_scan(tmp_path, cache_enabled=cache_enabled)


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


def _fixture_snapshot(path, source, digest="a" * 64):
    import ast

    tree = ast.parse(source, filename=str(path))
    tree._oracle_source_sha256 = digest
    return tree


def _async_runner_sources():
    return (
        "import asyncio\n"
        "import pytest\n"
        "import trio\n"
        "def _asyncio_run(async_fn, *args):\n"
        "    return asyncio.run(async_fn(*args))\n"
        "@pytest.fixture(params=[_asyncio_run, trio.run], ids=['asyncio', 'trio'])\n"
        "def run_async_fn(request):\n"
        "    return request.param\n"
    )


def _fixture_capability(api, binding):
    return {
        "status": "CLOSED",
        "api": api,
        "binding": binding,
        "source": "conftest.py",
        "sha256": "a" * 64,
        "origin": {"line": 1, "column": 0},
        "uses": [{"line": 2, "column": 4}],
    }


def test_async_runner_context_resolves_every_inherited_runner_alternative(tmp_path):
    import ast

    from factoryline.context_efficiency import async_runner_fixture_context

    conftest = tmp_path / "conftest.py"
    test_file = tmp_path / "tests" / "test_async.py"
    test_file.parent.mkdir()
    snapshots = {
        conftest: _fixture_snapshot(conftest, _async_runner_sources()),
        test_file: _fixture_snapshot(
            test_file, "def test_async(run_async_fn):\n    pass\n", "b" * 64
        ),
    }

    result = async_runner_fixture_context(tmp_path, list(snapshots), snapshots)
    summary = result["tests/test_async.py"]
    fixture = summary["fixtures"]["run_async_fn"]

    assert summary["schema"] == "factory.async-runner-fixture-context.v3"
    assert summary["module_sha256"] == "b" * 64
    assert fixture["trusted"] is True
    assert fixture["source"] == "conftest.py"
    assert fixture["sha256"] == "a" * 64
    assert {item["api"] for item in fixture["alternatives"]} == {
        "asyncio.run",
        "trio.run",
    }
    assert all(
        item["capability"]["status"] == "CLOSED"
        and item["capability"]["source"] == "conftest.py"
        and item["capability"]["sha256"] == "a" * 64
        and item["capability"]["origin"]
        and item["capability"]["uses"]
        for item in fixture["alternatives"]
    )
    assert ast.parse(_async_runner_sources())


def test_async_runner_context_nearest_conftest_replaces_parent_runner(tmp_path):
    from factoryline.context_efficiency import async_runner_fixture_context

    root_fixture = tmp_path / "conftest.py"
    suite = tmp_path / "suite"
    suite.mkdir()
    nearest_fixture = suite / "conftest.py"
    test_file = suite / "test_async.py"
    snapshots = {
        root_fixture: _fixture_snapshot(root_fixture, _async_runner_sources()),
        nearest_fixture: _fixture_snapshot(
            nearest_fixture, _async_runner_sources(), "c" * 64
        ),
        test_file: _fixture_snapshot(
            test_file, "def test_async(run_async_fn):\n    pass\n", "b" * 64
        ),
    }

    result = async_runner_fixture_context(tmp_path, list(snapshots), snapshots)

    fixture = result["suite/test_async.py"]["fixtures"]["run_async_fn"]
    assert fixture["trusted"] is True
    assert fixture["source"] == "suite/conftest.py"
    assert fixture["sha256"] == "c" * 64


@pytest.mark.parametrize(
    "override",
    [
        "@pytest.fixture(params=[_asyncio_run, anyio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n\ndef _asyncio_run(async_fn, *args):\n    return asyncio.run(async_fn(*args))\n",
        "trio.run = replacement\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "import trio as other\nother.run = replacement\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "import trio as other\nsaved_runner = other.run\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "import trio as other\nconsume(other.run)\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "from trio import run as other_run\nsaved_runner = other_run\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "import trio as other\ndel other.run\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "import trio as other\nother.__setattr__('run', noop)\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "import sys\nsys.modules['trio'].run = noop\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "import importlib\nimportlib.import_module('trio').run = noop\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "__import__('trio').run = noop\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "import trio as other\nrunner_module = other\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "asyncio.run = replacement\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "trio.__setattr__('run', noop)\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "from builtins import setattr as change\nchange(trio, 'run', noop)\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "from builtins import *\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "setattr(trio, 'run', noop)\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "getattr(trio, 'run')\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "runner_alias = trio.run\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "exec('trio.run = noop')\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "asyncio.__setattr__('run', noop)\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "asyncio.run.__code__ = replacement\n@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "@pytest.fixture(name='run_async_fn', params=[_asyncio_run, trio.run])\ndef other(request):\n    return request.param\n",
        "@pytest.fixture(name=fixture_name, params=[_asyncio_run, trio.run])\ndef other(request):\n    return request.param\n",
        "@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    if request.param:\n        return request.param\n    return None\n",
        "@pytest.fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param(*args)\n",
        "@pytest.fixture(params=[_asyncio_run, trio.run])\nasync def run_async_fn(request):\n    return request.param\n",
        "@fixture(params=[_asyncio_run, trio.run])\ndef run_async_fn(request):\n    return request.param\n",
        "from pytest import fixture as fx\n@fx\ndef run_async_fn(request):\n    return request.param\n",
        "from pytest import fixture as fx\nfx = fake_fixture\n"
        "@fx(params=[_asyncio_run, trio.run])\n"
        "def run_async_fn(request):\n    return request.param\n",
    ],
)
def test_async_runner_context_rejects_incomplete_or_unresolved_alternatives(
    tmp_path, override
):
    from factoryline.context_efficiency import async_runner_fixture_context

    conftest = tmp_path / "conftest.py"
    suite = tmp_path / "suite"
    test_file = suite / "test_async.py"
    suite.mkdir()
    snapshots = {
        conftest: _fixture_snapshot(conftest, _async_runner_sources()),
        suite / "conftest.py": _fixture_snapshot(
            suite / "conftest.py",
            "import asyncio\nimport pytest\nimport trio\n"
            "def _asyncio_run(async_fn, *args):\n"
            "    return asyncio.run(async_fn(*args))\n" + override,
            "c" * 64,
        ),
        test_file: _fixture_snapshot(
            test_file, "def test_async(run_async_fn):\n    pass\n", "b" * 64
        ),
    }

    result = async_runner_fixture_context(tmp_path, list(snapshots), snapshots)

    assert result["suite/test_async.py"]["fixtures"]["run_async_fn"]["trusted"] is False


@pytest.mark.parametrize(
    "fixture_source",
    [
        "import asyncio as event_loop\n"
        "import pytest\n"
        "from trio import run as trio_run\n"
        "def _asyncio_run(async_fn, *args):\n"
        "    return event_loop.run(async_fn(*args))\n"
        "@pytest.fixture(params=[_asyncio_run, trio_run])\n"
        "def run_async_fn(request):\n"
        "    return request.param\n",
        "import asyncio as loop\n"
        "import pytest\n"
        "import trio as task_group\n"
        "def _asyncio_run(async_fn, *args):\n"
        "    return loop.run(async_fn(*args))\n"
        "@pytest.fixture(params=[_asyncio_run, task_group.run])\n"
        "def run_async_fn(request):\n"
        "    return request.param\n",
        "import asyncio as event_loop\n"
        "import pytest\n"
        "import trio as provider\n"
        "import trio as second_provider\n"
        "@pytest.fixture(params=[_asyncio_run, provider.run])\n"
        "def run_async_fn(request):\n"
        "    return request.param\n"
        "def _asyncio_run(async_fn, *args):\n"
        "    return event_loop.run(async_fn(*args))\n",
    ],
    ids=[
        "direct-run-import",
        "renamed-imports",
        "fixture-before-wrapper-with-equivalent-module-alias",
    ],
)
def test_async_runner_capability_proof_accepts_alias_and_placement_variants(
    tmp_path, fixture_source
):
    from factoryline.context_efficiency import async_runner_fixture_context

    conftest = tmp_path / "conftest.py"
    test_file = tmp_path / "test_async.py"
    snapshots = {
        conftest: _fixture_snapshot(conftest, fixture_source),
        test_file: _fixture_snapshot(
            test_file, "def test_async(run_async_fn):\n    pass\n", "b" * 64
        ),
    }

    result = async_runner_fixture_context(tmp_path, list(snapshots), snapshots)

    fixture = result["test_async.py"]["fixtures"]["run_async_fn"]
    assert fixture["trusted"] is True
    assert {item["api"] for item in fixture["alternatives"]} == {
        "asyncio.run",
        "trio.run",
    }
    assert all(
        item["capability"]["status"] == "CLOSED" for item in fixture["alternatives"]
    )


def test_nested_async_callback_uses_source_bound_fixture_context():
    import ast

    from factoryline.context_efficiency import _nested_async_runner_invocations

    module = ast.parse(
        "def test_async(run_async_fn):\n"
        "    async def callback():\n"
        "        assert 1 == 1\n"
        "    run_async_fn(callback)\n"
    )
    module._oracle_source_sha256 = "b" * 64
    test = module.body[0]
    test._oracle_module = module
    module._oracle_async_runner_fixtures = {
        "schema": "factory.async-runner-fixture-context.v3",
        "module_sha256": "b" * 64,
        "fixtures": {
            "run_async_fn": {
                "trusted": True,
                "source": "conftest.py",
                "sha256": "a" * 64,
                "alternatives": [
                    {
                        "api": "asyncio.run",
                        "binding": "_asyncio_run",
                        "capability": _fixture_capability("asyncio.run", "asyncio"),
                    },
                    {
                        "api": "trio.run",
                        "binding": "trio",
                        "capability": _fixture_capability("trio.run", "trio"),
                    },
                ],
            }
        },
    }
    callback = test.body[0]

    accepted = _nested_async_runner_invocations(
        test, {callback.name: callback}, {callback.name}, {}
    )

    assert callback.name in accepted
    assert "run_async_fn" in accepted

    module._oracle_async_runner_fixtures["fixtures"]["run_async_fn"]["alternatives"][0][
        "capability"
    ]["sha256"] = "c" * 64
    stale_witness = _nested_async_runner_invocations(
        test, {callback.name: callback}, {callback.name}, {}
    )
    assert callback.name not in stale_witness


def test_async_runner_wrapper_rejects_parameter_shadowing_asyncio():
    import ast

    from factoryline import review_audits
    from factoryline.context_efficiency import _async_runner_wrapper_receiver

    baseline = ast.parse(
        "import asyncio as loop\n"
        "def runner(async_fn, *args):\n"
        "    return loop.run(async_fn(*args))\n"
    )
    aliases = review_audits._scope_security_aliases(
        review_audits._module_security_aliases(baseline), baseline
    )
    assert (
        _async_runner_wrapper_receiver(
            baseline.body[1], baseline, aliases, review_audits
        )
        is not None
    )

    shadowed = ast.parse(
        "import asyncio\n"
        "def runner(asyncio, *args):\n"
        "    return asyncio.run(asyncio(*args))\n"
    )
    aliases = review_audits._scope_security_aliases(
        review_audits._module_security_aliases(shadowed), shadowed
    )
    assert (
        _async_runner_wrapper_receiver(
            shadowed.body[1], shadowed, aliases, review_audits
        )
        is None
    )


@pytest.mark.parametrize(
    "body, trusted, module_sha, expected",
    [
        ("    run_async_fn(callback)\n", True, "b" * 64, True),
        ("    if enabled:\n        run_async_fn(callback)\n", True, "b" * 64, False),
        (
            "    try:\n        run_async_fn(callback)\n    except Exception:\n        pass\n",
            True,
            "b" * 64,
            False,
        ),
        (
            "    run_async_fn = fake\n    run_async_fn(callback)\n",
            True,
            "b" * 64,
            False,
        ),
        (
            "    run_async_fn.__code__ = (lambda *args: None).__code__\n"
            "    run_async_fn(callback)\n",
            True,
            "b" * 64,
            False,
        ),
        (
            "    setattr(run_async_fn, '__code__', (lambda *args: None).__code__)\n"
            "    run_async_fn(callback)\n",
            True,
            "b" * 64,
            False,
        ),
        (
            "    delegate(run_async_fn)\n    run_async_fn(callback)\n",
            True,
            "b" * 64,
            False,
        ),
        (
            "    runner_alias = run_async_fn\n    run_async_fn(callback)\n",
            True,
            "b" * 64,
            False,
        ),
        ("    run_async_fn(callback)\n", False, "b" * 64, False),
        ("    run_async_fn(callback)\n", True, "c" * 64, False),
    ],
)
def test_nested_async_fixture_call_fails_closed_on_control_or_shadow(
    body, trusted, module_sha, expected
):
    import ast

    from factoryline.context_efficiency import _nested_async_runner_invocations

    module = ast.parse(
        "def test_async(run_async_fn):\n"
        "    async def callback():\n"
        "        assert 1 == 1\n" + body
    )
    module._oracle_source_sha256 = "b" * 64
    test = module.body[0]
    test._oracle_module = module
    module._oracle_async_runner_fixtures = {
        "schema": "factory.async-runner-fixture-context.v3",
        "module_sha256": module_sha,
        "fixtures": {
            "run_async_fn": {
                "trusted": trusted,
                "source": "conftest.py",
                "sha256": "a" * 64,
                "alternatives": [
                    {
                        "api": "trio.run",
                        "binding": "trio",
                        "capability": _fixture_capability("trio.run", "trio"),
                    }
                ],
            }
        },
    }
    callback = test.body[0]
    actual = _nested_async_runner_invocations(
        test, {callback.name: callback}, {callback.name}, {}
    )

    assert (callback.name in actual) is expected


def test_async_runner_fixture_source_digest_is_required(tmp_path):
    from factoryline.context_efficiency import async_runner_fixture_context

    conftest = tmp_path / "conftest.py"
    test_file = tmp_path / "test_async.py"
    snapshots = {
        conftest: _fixture_snapshot(conftest, _async_runner_sources(), "invalid"),
        test_file: _fixture_snapshot(
            test_file, "def test_async(run_async_fn):\n    pass\n", "b" * 64
        ),
    }

    assert async_runner_fixture_context(tmp_path, list(snapshots), snapshots) == {}


def _large_async_runner_test_source(name):
    return f"def {name}():\n" + "    assert left == right\n" * 5500


def test_async_runner_context_node_limit_is_per_module(tmp_path):
    from factoryline.context_efficiency import async_runner_fixture_context

    fixture_path = tmp_path / "conftest.py"
    target_path = tmp_path / "tests" / "test_async.py"
    unrelated_path = tmp_path / "tests" / "test_unrelated.py"
    target_path.parent.mkdir()
    snapshots = {
        fixture_path: _fixture_snapshot(fixture_path, _async_runner_sources()),
        target_path: _fixture_snapshot(
            target_path,
            "def test_async(run_async_fn):\n    pass\n",
            "b" * 64,
        ),
        unrelated_path: _fixture_snapshot(
            unrelated_path, _large_async_runner_test_source("test_noise"), "c" * 64
        ),
    }

    result = async_runner_fixture_context(tmp_path, list(snapshots), snapshots)

    assert result["tests/test_async.py"]["fixtures"]["run_async_fn"]["trusted"]
    assert result["tests/test_unrelated.py"]["gaps"] == ["TEST_MODULE_NODE_LIMIT"]


@pytest.mark.parametrize("oversized_scope", ["test", "conftest"])
def test_async_runner_context_oversized_scope_is_uncredited_with_gap(
    tmp_path, oversized_scope
):
    from factoryline.context_efficiency import async_runner_fixture_context

    fixture_path = tmp_path / "conftest.py"
    test_path = tmp_path / "tests" / "test_async.py"
    test_path.parent.mkdir()
    fixture_source = _async_runner_sources()
    test_source = "def test_async(run_async_fn):\n    pass\n"
    if oversized_scope == "conftest":
        fixture_source += _large_async_runner_test_source("large_helper")
    else:
        test_source = (
            "def test_async(run_async_fn):\n"
            "    async def callback():\n"
            "        assert await fetch_value() == expected_value\n"
            "    run_async_fn(callback)\n" + "    assert left == right\n" * 5500
        )
    snapshots = {
        fixture_path: _fixture_snapshot(fixture_path, fixture_source),
        test_path: _fixture_snapshot(test_path, test_source, "b" * 64),
    }

    summary = async_runner_fixture_context(tmp_path, list(snapshots), snapshots)[
        "tests/test_async.py"
    ]

    expected_gap = (
        "TEST_MODULE_NODE_LIMIT"
        if oversized_scope == "test"
        else "ANCESTOR_FIXTURE_SOURCE_NODE_LIMIT"
    )
    assert expected_gap in summary["gaps"]
    assert not summary["fixtures"].get("run_async_fn", {}).get("trusted", False)


def _async_test_oracle_rows(report):
    codes = {
        "QUALITY_HOLLOW_TEST",
        "QUALITY_UNKNOWN_TEST_ORACLE",
        "QUALITY_WEAK_TEST_ORACLE",
    }
    return [
        row
        for row in report["findings"]
        if row.get("code") in codes
        and row.get("path") == "tests/test_async.py"
        and row.get("facts", {}).get("symbol") == "test_async"
    ]


def _assert_async_oracle_unresolved(report):
    rows = _async_test_oracle_rows(report)
    assert len(rows) == 1
    assert rows[0]["code"] == "QUALITY_UNKNOWN_TEST_ORACLE"
    assert rows[0]["severity"] == "INFO"
    assert rows[0]["facts"]["state"] == "INCOMPLETE"
    assert report["state"] == "INCOMPLETE"
    return rows


def test_security_scan_uses_async_runner_fixture_cold_warm_and_stale_context(
    tmp_path,
):
    from factoryline import review_audits

    conftest = tmp_path / "conftest.py"
    tests = tmp_path / "tests"
    tests.mkdir()
    test_file = tests / "test_async.py"
    conftest.write_text(_async_runner_sources(), encoding="utf-8")
    test_file.write_text(
        "def test_async(run_async_fn):\n"
        "    async def callback():\n"
        "        assert await fetch_value() == expected_value\n"
        "    run_async_fn(callback)\n",
        encoding="utf-8",
    )
    review_audits._oracle_context_cache_clear()

    cold = review_audits.security_scan(tmp_path, cache_enabled=True)
    cold_hits = review_audits._oracle_context_cache_info()["hits"]
    cold_target = _async_test_oracle_rows(cold)
    assert not cold_target

    warm = review_audits.security_scan(tmp_path, cache_enabled=True)
    warm_info = review_audits._oracle_context_cache_info()
    assert warm_info["hits"] == cold_hits + 1
    assert warm["audit_sha256"] == cold["audit_sha256"]
    assert _async_test_oracle_rows(warm) == cold_target

    conftest.write_text(
        "import asyncio\nimport pytest\nimport trio\n"
        "@pytest.fixture(params=[asyncio.run, trio.run], ids=['asyncio', 'trio'])\n"
        "def run_async_fn(request):\n"
        "    return request.param if request.config.option.asyncio else None\n",
        encoding="utf-8",
    )
    before_stale = review_audits._oracle_context_cache_info()
    stale = review_audits.security_scan(tmp_path, cache_enabled=True)
    after_stale = review_audits._oracle_context_cache_info()
    stale_target = _assert_async_oracle_unresolved(stale)
    assert len(stale_target) == 1
    assert after_stale["hits"] == before_stale["hits"]
    assert after_stale["misses"] == before_stale["misses"] + 1


@pytest.mark.parametrize(
    "runner_call, bad_backend",
    [
        ("", False),
        ("    return\n    run_async_fn(callback)\n", False),
        ("    run_async_fn(callback)\n", True),
    ],
    ids=["uninvoked-fixture", "unreachable-runner", "one-unrecognized-backend"],
)
def test_security_scan_does_not_credit_unproven_async_runner_calls(
    tmp_path, runner_call, bad_backend
):
    from factoryline import review_audits

    conftest = tmp_path / "conftest.py"
    tests = tmp_path / "tests"
    tests.mkdir()
    test_file = tests / "test_async.py"
    fixture_source = _async_runner_sources()
    if bad_backend:
        fixture_source = fixture_source.replace("trio.run", "anyio.run")
    conftest.write_text(fixture_source, encoding="utf-8")
    test_file.write_text(
        "def test_async(run_async_fn):\n"
        "    async def callback():\n"
        "        assert await fetch_value() == expected_value\n" + runner_call,
        encoding="utf-8",
    )

    result = review_audits.security_scan(tmp_path, cache_enabled=False)

    target = _assert_async_oracle_unresolved(result)
    assert len(target) == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "run_async_fn.__code__ = (lambda *args: None).__code__\n",
        "setattr(run_async_fn, '__code__', (lambda *args: None).__code__)\n",
        "delegate(run_async_fn)\n",
        "runner_alias = run_async_fn\n",
    ],
)
def test_security_scan_keeps_mutated_async_runner_unresolved(tmp_path, mutation):
    from factoryline import review_audits

    conftest = tmp_path / "conftest.py"
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_async.py").write_text(
        "def test_async(run_async_fn):\n"
        "    async def callback():\n"
        "        assert await fetch_value() == expected_value\n"
        f"    {mutation}"
        "    run_async_fn(callback)\n",
        encoding="utf-8",
    )
    conftest.write_text(_async_runner_sources(), encoding="utf-8")

    result = review_audits.security_scan(tmp_path, cache_enabled=False)

    target = _assert_async_oracle_unresolved(result)
    assert len(target) == 1


@pytest.mark.parametrize(
    "parameters, body",
    [
        ("[disable(other.run)]", "return request.param"),
        ("choose([other.run])", "return request.param"),
        (
            "[other.run]",
            "request.param.__code__ = replacement\n    return request.param",
        ),
        ("[other.run]", "consume(request.param)\n    return request.param"),
        ("[other.run, disable()]", "return request.param"),
    ],
    ids=[
        "nested-call",
        "dynamic-params",
        "consumer-mutation",
        "consumer-escape",
        "effectful-alternative",
    ],
)
def test_async_runner_context_rejects_impure_secondary_fixture_consumer(
    tmp_path, parameters, body
):
    from factoryline.context_efficiency import async_runner_fixture_context

    conftest = tmp_path / "conftest.py"
    source = (
        _async_runner_sources() + "import trio as other\n"
        f"@pytest.fixture(params={parameters})\ndef secondary(request):\n    {body}\n"
    )
    tree = _fixture_snapshot(conftest, source)
    test_file = tmp_path / "test_async.py"
    snapshots = {
        conftest: tree,
        test_file: _fixture_snapshot(
            test_file, "def test_async(run_async_fn):\n    pass\n"
        ),
    }
    context = async_runner_fixture_context(tmp_path, list(snapshots), snapshots)
    assert context["test_async.py"]["fixtures"]["run_async_fn"]["trusted"] is False


def test_async_runner_context_accepts_pure_secondary_fixture_consumer(tmp_path):
    from factoryline.context_efficiency import async_runner_fixture_context

    conftest = tmp_path / "conftest.py"
    source = (
        _async_runner_sources() + "import trio as other\n"
        "@pytest.fixture(params=(other.run,))\ndef secondary(request):\n"
        "    return request.param\n"
    )
    tree = _fixture_snapshot(conftest, source)
    test_file = tmp_path / "test_async.py"
    snapshots = {
        conftest: tree,
        test_file: _fixture_snapshot(
            test_file, "def test_async(run_async_fn):\n    pass\n"
        ),
    }
    context = async_runner_fixture_context(tmp_path, list(snapshots), snapshots)
    assert context["test_async.py"]["fixtures"]["run_async_fn"]["trusted"] is True
    assert context["test_async.py"]["fixtures"]["secondary"]["trusted"] is True


def _protocol_source_case(
    tmp_path, test_source, product=None, *, additional=None, materialize=True, **options
):
    import ast
    import hashlib

    from factoryline.context_efficiency import protocol_call_context

    sources = {
        "pkg/__init__.py": product
        or (
            "from abc import ABC\n"
            "class Base(ABC):\n"
            "    def __init__(self):\n        self.value = 3\n"
            "    def __repr__(self):\n        return f'<value={self.value}>'\n"
        ),
        "test_protocol.py": test_source,
        **(additional or {}),
    }
    snapshots = {}
    for relative, source in sources.items():
        path = tmp_path / relative
        if materialize:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(source.encode("utf-8"))
        tree = ast.parse(source, filename=str(path))
        tree._oracle_source_sha256 = hashlib.sha256(source.encode()).hexdigest()
        snapshots[path] = tree
    # These fixtures test the declared model, not the host interpreter profile.
    options.setdefault(
        "python_profile", {"implementation": "cpython", "version": "3.11.9"}
    )
    context = protocol_call_context(tmp_path, list(snapshots), snapshots, **options)
    return context.get("test_protocol.py", {"summaries": [], "gaps": []})


def test_protocol_context_requires_materialized_import_source(tmp_path):
    result = _protocol_source_case(
        tmp_path,
        "from pkg import Base\ndef test_protocol():\n    repr(Base())\n",
        materialize=False,
    )
    assert result["summaries"][0]["status"] == "UNKNOWN"
    assert result["summaries"][0]["unknown_reasons"] == ["IMPORT_SOURCE_UNAVAILABLE"]


@pytest.mark.parametrize(
    "body, expected",
    [
        (
            "    repr(Base())\n    repr(Base())\n",
            [
                ("WEAK_PROTOCOL", (), 3),
                ("UNKNOWN", ("PRECEDING_CONTROL_OR_EFFECT_UNKNOWN",), 4),
            ],
        ),
        (
            "    yield None\n    repr(Base())\n",
            [("UNKNOWN", ("DEFERRED_EXECUTION",), 4)],
        ),
        (
            "    import builtins\n    repr(Base())\n",
            [("UNKNOWN", ("REFLECTIVE_TEST_EFFECTS",), 4)],
        ),
    ],
)
def test_protocol_context_reuses_one_ordered_test_walk(
    tmp_path, monkeypatch, body, expected
):
    import ast
    import hashlib

    from factoryline import context_efficiency as efficiency

    sources = {
        "pkg/__init__.py": (
            "from abc import ABC\n"
            "class Base(ABC):\n"
            "    def __init__(self):\n        self.value = 3\n"
            "    def __repr__(self):\n        return f'<value={self.value}>'\n"
        ),
        "test_protocol.py": "from pkg import Base\ndef test_protocol():\n" + body,
    }
    snapshots = {}
    for relative, source in sources.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(source.encode("utf-8"))
        tree = ast.parse(source, filename=str(path))
        tree._oracle_source_sha256 = hashlib.sha256(source.encode()).hexdigest()
        snapshots[path] = tree

    test_path = tmp_path / "test_protocol.py"
    test_node = snapshots[test_path].body[1]
    original_walk = ast.walk
    test_walks = 0

    def counted_walk(node):
        nonlocal test_walks
        if node is test_node:
            test_walks += 1
        return original_walk(node)

    monkeypatch.setattr(ast, "walk", counted_walk)
    result = efficiency.protocol_call_context(
        tmp_path,
        list(snapshots),
        snapshots,
        python_profile={"implementation": "cpython", "version": "3.11.9"},
    )
    summaries = result["test_protocol.py"]["summaries"]
    observed = [
        (row["status"], tuple(row["unknown_reasons"]), row["line"]) for row in summaries
    ]
    assert observed == expected
    assert test_walks == 1


def test_protocol_context_source_resolves_three_repr_dispatch_shapes(tmp_path):
    source = (
        "import pkg as library\n"
        "from pkg import asyncio as async_backend, tornado as tornado_backend\n"
        "def test_sync():\n"
        "    class Concrete(library.Base):\n"
        "        def __call__(self):\n            pass\n"
        "    repr(Concrete())\n"
        "def test_async_backend():\n    repr(async_backend.Async())\n"
        "def test_tornado_backend():\n    repr(tornado_backend.Tornado())\n"
    )
    result = _protocol_source_case(
        tmp_path,
        source,
        additional={
            "pkg/asyncio/__init__.py": "from pkg import Base\nclass Async(Base):\n    def __init__(self):\n        super().__init__()\n",
            "pkg/tornado.py": "from pkg import Base\nclass Tornado(Base):\n    def __init__(self):\n        super().__init__()\n",
        },
    )
    assert len(result["summaries"]) == 3
    for summary in result["summaries"]:
        assert summary["status"] == "WEAK_PROTOCOL"
        assert summary["output_checked"] is False
        assert summary["runtime_observed"] is False
        assert summary["conditional_on_successful_construction"] is True
        assert (
            summary["assumptions"][0]["contract"]
            == "stdlib.abc-transparent-method-lookup.cpython-3.11.9.v1"
        )
        assert {item["role"] for item in summary["dependencies"]} >= {
            "test",
            "receiver_class",
            "protocol_method",
        }
        assert all(
            len(item["sha256"]) == len(item["ast_sha256"]) == 64
            for item in summary["dependencies"]
        )


@pytest.mark.parametrize(
    "imports, receiver",
    [
        ("from pkg import Base as ChangedName", "ChangedName"),
        ("import pkg as renamed", "renamed.Base"),
        ("from pkg import Base\nclass Middle(Base):\n    pass", "Middle"),
    ],
)
def test_protocol_context_resolves_renamed_and_inherited_receivers(
    tmp_path, imports, receiver
):
    result = _protocol_source_case(
        tmp_path, imports + f"\ndef test_protocol():\n    repr({receiver}())\n"
    )
    assert result["summaries"][0]["status"] == "WEAK_PROTOCOL"


@pytest.mark.parametrize(
    "source",
    [
        "from pkg import Base\ndef test_protocol():\n    Base.__repr__ = replacement\n    repr(Base())\n",
        "import pkg as p\nimport pkg as other\nother.Base.__repr__ = replacement\ndef test_protocol():\n    repr(p.Base())\n",
        "from pkg import Base\nfrom pkg import Base as other\nother.__repr__ = replacement\ndef test_protocol():\n    repr(Base())\n",
        "import pkg as p\nimport pkg as other\nconsume(other.Base)\ndef test_protocol():\n    repr(p.Base())\n",
        "from pkg import Base\ndef test_protocol():\n    saved = Base\n    repr(Base())\n",
        "from pkg import Base\ndef test_protocol():\n    Base = fake\n    repr(Base())\n",
        "from pkg import Base\ndef test_protocol(repr):\n    repr(Base())\n",
        "from pkg import Base\nrepr = fake\ndef test_protocol():\n    repr(Base())\n",
        "from pkg import Base\nimport builtins\nbuiltins.repr = fake\ndef test_protocol():\n    repr(Base())\n",
        "from pkg import Base\ndef test_protocol():\n    if False:\n        repr(Base())\n",
        "from pkg import Base\ndef test_protocol():\n    def unused():\n        repr(Base())\n",
        "from pkg import Base\ndef test_protocol():\n    try:\n        repr(Base())\n    except Exception:\n        pass\n",
        "from pkg import Base\ndef test_protocol():\n    with suppress(Exception):\n        repr(Base())\n",
        "from pkg import Base\nasync def test_protocol():\n    repr(Base())\n",
        "from pkg import Base\ndef test_protocol():\n    repr(Base())\n    yield 1\n",
        "from pkg import Base\n@xfail\ndef test_protocol():\n    repr(Base())\n",
        "from pkg import Base\ndef test_protocol():\n    return\n    repr(Base())\n",
        "from pkg import Base\ndef test_protocol():\n    class Child(Base):\n        Base.__repr__ = replacement\n    repr(Child())\n",
        "from pkg import Base\ndef test_protocol():\n    class Child(Base, metaclass=Meta):\n        pass\n    repr(Child())\n",
    ],
)
def test_protocol_context_rejects_mutation_escape_shadow_or_nonexecution(
    tmp_path, source
):
    summary = _protocol_source_case(tmp_path, source)["summaries"][0]
    assert summary["status"] == "UNKNOWN"
    assert summary["unknown_reasons"]
    assert summary["output_checked"] is False


@pytest.mark.parametrize(
    "product",
    [
        "class Base:\n    pass\n",
        "class Base:\n    def __repr__(self):\n        return 'constant'\n",
        "class Base(external.Unknown):\n    def __repr__(self):\n        return f'{self.value}'\n",
        "class Base(factory()):\n    def __repr__(self):\n        return f'{self.value}'\n",
        "class Base:\n    def __new__(cls):\n        return other\n    def __repr__(self):\n        return f'{self.value}'\n",
        "class Base:\n    def __init__(self):\n        self.__class__ = Other\n    def __repr__(self):\n        return f'{self.value}'\n",
        "class Base:\n    def __init__(self):\n        consume(self)\n    def __repr__(self):\n        return f'{self.value}'\n",
    ],
)
def test_protocol_context_rejects_unresolved_or_constant_protocols(tmp_path, product):
    summary = _protocol_source_case(
        tmp_path,
        "from pkg import Base\ndef test_protocol():\n    repr(Base())\n",
        product,
    )["summaries"][0]
    assert summary["status"] == "UNKNOWN"
    assert summary["unknown_reasons"]


def test_protocol_context_keeps_constant_compute_without_protocol_credit(tmp_path):
    result = _protocol_source_case(
        tmp_path,
        "def compute():\n    return 3\ndef test_never_asserts_anything():\n    compute()\n",
    )
    assert result["summaries"] == []


def test_protocol_context_rejects_source_drift_budget_and_unknown_abc_profile(tmp_path):
    source = "from pkg import Base\ndef test_protocol():\n    repr(Base())\n"
    result = _protocol_source_case(tmp_path, source, source_hashes={})
    assert result["gaps"] == ["SOURCE_IDENTITY_DRIFT"]
    result = _protocol_source_case(tmp_path, source, max_nodes=3)
    assert result["gaps"] == ["AST_NODE_LIMIT"]
    result = _protocol_source_case(
        tmp_path,
        source,
        python_profile={"implementation": "cpython", "version": "3.14.0"},
    )
    assert result["summaries"][0]["unknown_reasons"] == ["ABC_PROFILE_UNSUPPORTED"]


@pytest.mark.parametrize(
    "product",
    [
        "from abc import ABC\nimport abc as other\nother.ABCMeta.__call__ = replacement\nclass Base(ABC):\n    def __repr__(self):\n        return f'{self.value}'\n",
        "class Base:\n    def __init__(self):\n        consume(Base)\n        self.value = 3\n    def __repr__(self):\n        return f'{self.value}'\n",
        "class Base:\n    def __init__(self):\n        from pkg import Base as alias\n        consume(alias)\n    def __repr__(self):\n        return f'{self.value}'\n",
        "super = replacement\nclass Parent:\n    pass\nclass Base(Parent):\n    def __init__(self):\n        super().__init__()\n    def __repr__(self):\n        return f'{self.value}'\n",
        "class Base:\n    def __repr__(self):\n        return 'constant' if True else self.value\n",
        "class Base:\n    def __repr__(self):\n        return f'{True or self.value}'\n",
    ],
)
def test_protocol_context_transfer_rejects_abc_constructor_and_dead_dependency_controls(
    tmp_path, product
):
    source = "from pkg import Base\ndef test_protocol():\n    repr(Base())\n"
    summary = _protocol_source_case(tmp_path, source, product)["summaries"][0]
    assert summary["status"] == "UNKNOWN"
    assert summary["unknown_reasons"]


def test_protocol_context_transfer_records_decorated_method_as_partial_unknown(
    tmp_path,
):
    product = "class Base:\n    @metadata_decorator\n    def __repr__(self):\n        return f'{self.value}'\n"
    source = "from pkg import Base\ndef test_protocol():\n    repr(Base())\n"
    summary = _protocol_source_case(tmp_path, source, product)["summaries"][0]
    assert summary["status"] == "UNKNOWN"
    assert summary["unknown_reasons"] == ["PROFILE_BINDING_AMBIGUOUS"]
    assert summary["receiver"]["class"] == "Base"
    assert summary["method_decorators"] == ["metadata_decorator"]
    assert any(row["role"] == "protocol_method" for row in summary["dependencies"])


def test_protocol_context_transfer_rejects_local_constructor_before_declaration(
    tmp_path,
):
    source = "from pkg import Base\ndef test_protocol():\n    repr(Local())\n    class Local(Base):\n        pass\n"
    summary = _protocol_source_case(tmp_path, source)["summaries"][0]
    assert summary["unknown_reasons"] == ["LOCAL_CLASS_NOT_YET_DECLARED"]


def test_protocol_context_transfer_unrelated_oversized_source_cannot_poison_valid_summary(
    tmp_path,
):
    source = "from pkg import Base\ndef test_protocol():\n    repr(Base())\n"
    result = _protocol_source_case(
        tmp_path,
        source,
        additional={"unrelated.py": "unrelated = 3\n" * 500},
        max_nodes=300,
    )
    assert result["summaries"][0]["status"] == "WEAK_PROTOCOL"


def test_protocol_context_transfer_has_no_assertion_or_finding_suppression_side_effect(
    tmp_path,
):
    from factoryline.review_audits import _hollow_test_finding
    import ast

    source = "from pkg import Base\ndef test_protocol():\n    repr(Base())\n"
    context = _protocol_source_case(tmp_path, source)
    test = ast.parse(source).body[1]
    finding = _hollow_test_finding(
        "test_protocol.py",
        test,
        {"Base": "pkg.Base"},
        oracle_context={"protocol_call_context": context},
    )
    baseline = _hollow_test_finding("test_protocol.py", test, {"Base": "pkg.Base"})
    assert context["summaries"][0]["status"] == "WEAK_PROTOCOL"
    assert finding == baseline
    assert finding["code"] == "QUALITY_UNKNOWN_TEST_ORACLE"
    assert finding["facts"]["state"] == "INCOMPLETE"


@pytest.mark.parametrize(
    "mutation",
    [
        "other.Base = replacement",
        "del other.Base",
        "other.Base.__bases__ = (replacement,)",
    ],
)
def test_protocol_context_constructor_replacement_through_equivalent_alias_is_unknown(
    tmp_path, mutation
):
    source = (
        "import pkg as selected\nimport pkg as other\n"
        + mutation
        + "\ndef test_protocol():\n    repr(selected.Base())\n"
    )
    summary = _protocol_source_case(tmp_path, source)["summaries"][0]
    assert summary["status"] == "UNKNOWN"
    assert summary["unknown_reasons"]


def test_protocol_context_dependency_source_drift_invalidates_selected_receiver(
    tmp_path,
):
    import hashlib

    source = "from pkg import Base\ndef test_protocol():\n    repr(Base())\n"
    hashes = {
        "test_protocol.py": hashlib.sha256(source.encode()).hexdigest(),
        "pkg/__init__.py": "b" * 64,
    }
    summary = _protocol_source_case(tmp_path, source, source_hashes=hashes)[
        "summaries"
    ][0]
    assert summary["unknown_reasons"] == ["SOURCE_IDENTITY_DRIFT"]


def test_protocol_context_dependency_hashes_change_and_helpers_are_exported(tmp_path):
    from factoryline.context_efficiency import (
        protocol_call_context,
        protocol_call_helpers,
    )

    source = "from pkg import Base\ndef test_protocol():\n    repr(Base())\n"
    first = _protocol_source_case(tmp_path, source)["summaries"][0]
    product = "class Base:\n    def __init__(self):\n        self.other = 3\n    def __repr__(self):\n        return f'{self.other}'\n"
    second = _protocol_source_case(tmp_path, source, product)["summaries"][0]
    original = next(
        row for row in first["dependencies"] if row["role"] == "protocol_method"
    )
    changed = next(
        row for row in second["dependencies"] if row["role"] == "protocol_method"
    )
    assert first["status"] == second["status"] == "WEAK_PROTOCOL"
    assert original["sha256"] != changed["sha256"]
    assert original["ast_sha256"] != changed["ast_sha256"]
    assert protocol_call_context in protocol_call_helpers()


@pytest.mark.parametrize(
    "name, flag", [("renamed", "__override__"), ("keep_identity", "__final__")]
)
def test_protocol_context_metadata_identity_transfer_is_source_bound_and_renamable(
    tmp_path, name, flag
):
    product = f"from .metadata import {name} as annotation\nclass Base:\n    @annotation\n    def __repr__(self):\n        return f'{{self.value}}'\n"
    decorator = (
        f"def {name}(function):\n    function.{flag} = True\n    return function\n"
    )
    source = "from pkg import Base\ndef test_protocol():\n    repr(Base())\n"
    summary = _protocol_source_case(
        tmp_path, source, product, additional={"pkg/metadata.py": decorator}
    )["summaries"][0]
    assert summary["status"] == "WEAK_PROTOCOL"
    assert summary["output_checked"] is False
    assert any(
        row["role"] == "identity_decorator" and row["source"] == "pkg/metadata.py"
        for row in summary["dependencies"]
    )


def _protocol_profile_metadata_source():
    return (
        "import typing as types\nimport sys as runtime\nimport contextlib as contexts\n"
        "if types.TYPE_CHECKING:\n    from missing import identity\n"
        "elif runtime.version_info >= (3, 12):\n    from typing import override as identity\n"
        "else:\n    def identity(function):\n"
        "        with contexts.suppress(AttributeError, TypeError):\n"
        "            function.__override__ = True\n        return function\n"
    )


def test_protocol_context_metadata_identity_selects_the_declared_runtime_branch(
    tmp_path,
):
    product = "from .metadata import identity\nclass Base:\n    @identity\n    def __repr__(self):\n        return f'{self.value}'\n"
    source = "from pkg import Base\ndef test_protocol():\n    repr(Base())\n"
    summary = _protocol_source_case(
        tmp_path,
        source,
        product,
        additional={"pkg/metadata.py": _protocol_profile_metadata_source()},
    )["summaries"][0]
    assert summary["status"] == "WEAK_PROTOCOL"
    assert any(row["role"] == "identity_decorator" for row in summary["dependencies"])

    assert summary["python_profile"] == {
        "implementation": "cpython",
        "version": "3.11.9",
    }
    assert any(
        item["contract"] == "source.metadata-identity-transfer.v1"
        for item in summary["assumptions"]
    )


@pytest.mark.parametrize(
    "decorator",
    [
        "def identity(function):\n    function.__code__ = True\n    return function\n",
        "def identity(function):\n    function.__globals__ = True\n    return function\n",
        "def identity(function):\n    function.__class__ = True\n    return function\n",
        "def identity(function):\n    return wrapper\n",
        "def identity(function):\n    consume(function)\n    return function\n",
        "if unknown_flag:\n    def identity(function):\n        return function\n",
        "import sys as runtime\nimport sys as other\nother.version_info = (3, 12)\nif runtime.version_info >= (3, 12):\n    def identity(function):\n        return function\nelse:\n    def identity(function):\n        return function\n",
    ],
)
def test_protocol_context_metadata_identity_rejects_execution_replacement_and_unknown_branches(
    tmp_path, decorator
):
    product = "from .metadata import identity\nclass Base:\n    @identity\n    def __repr__(self):\n        return f'{self.value}'\n"
    source = "from pkg import Base\ndef test_protocol():\n    repr(Base())\n"
    summary = _protocol_source_case(
        tmp_path, source, product, additional={"pkg/metadata.py": decorator}
    )["summaries"][0]
    assert summary["status"] == "UNKNOWN"
    assert summary["unknown_reasons"]


def test_protocol_context_metadata_identity_rejects_mutation_through_other_import_alias(
    tmp_path,
):
    product = "from .metadata import identity\nfrom .metadata import identity as other\nother.__code__ = replacement\nclass Base:\n    @identity\n    def __repr__(self):\n        return f'{self.value}'\n"
    source = "from pkg import Base\ndef test_protocol():\n    repr(Base())\n"
    summary = _protocol_source_case(
        tmp_path,
        source,
        product,
        additional={
            "pkg/metadata.py": "def identity(function):\n    return function\n"
        },
    )["summaries"][0]
    assert summary["status"] == "UNKNOWN"
    assert summary["unknown_reasons"]


@pytest.mark.parametrize(
    "operation", ["saved = helper.__annotations__", "saved = helper.__dict__"]
)
def test_protocol_context_metadata_annotation_reflection_cannot_escape_class_identity(
    tmp_path, operation
):
    source = (
        "from pkg import Base\ndef helper(argument: Base):\n    pass\ndef test_protocol():\n    "
        + operation
        + "\n    repr(Base())\n"
    )
    summary = _protocol_source_case(tmp_path, source)["summaries"][0]
    assert summary["status"] == "UNKNOWN"


def test_protocol_context_metadata_allows_direct_type_metadata_and_async_identity_decorators(
    tmp_path,
):
    product = "from .metadata import identity\nclass Base:\n    @identity\n    def __repr__(self):\n        return f'{self.value}'\n    @identity\n    async def unrelated(self):\n        pass\n"
    source = "from pkg import Base\ndef helper(argument: Base) -> Base:\n    pass\nclass Holder:\n    annotation: Base\ndef test_protocol():\n    repr(Base())\n"
    summary = _protocol_source_case(
        tmp_path,
        source,
        product,
        additional={
            "pkg/metadata.py": "def identity(function):\n    function.__override__ = True\n    return function\n"
        },
    )["summaries"][0]
    assert summary["status"] == "WEAK_PROTOCOL"


def test_protocol_context_metadata_callable_object_is_not_a_proven_base_class(tmp_path):
    product = "def factory():\n    return object\nclass Base(factory):\n    def __repr__(self):\n        return f'{self.value}'\n"
    source = "from pkg import Base\ndef test_protocol():\n    repr(Base())\n"
    summary = _protocol_source_case(tmp_path, source, product)["summaries"][0]
    assert summary["status"] == "UNKNOWN"


@pytest.mark.parametrize(
    "product",
    [
        "def alter():\n    Base.__repr__ = lambda self: 'constant'\nclass Base:\n    def __init__(self):\n        alter()\n    def __repr__(self):\n        return self.value\n",
        "def alter():\n    Base.__repr__ = lambda self: 'constant'\ndef intermediate():\n    alter()\nclass Base:\n    def __init__(self):\n        intermediate()\n    def __repr__(self):\n        return self.value\n",
        "def alter():\n    Base.__repr__ = lambda self: 'constant'\nalias = alter\nclass Base:\n    def __init__(self):\n        alias()\n    def __repr__(self):\n        return self.value\n",
        "def initialize(self):\n    Base.__repr__ = lambda self: 'constant'\nclass Base:\n    __init__ = initialize\n    def __repr__(self):\n        return self.value\n",
        "class Base:\n    def __init__(self):\n        self.value = 3\n    def __setattr__(self, name, value):\n        Base.__repr__ = lambda self: 'constant'\n    def __repr__(self):\n        return self.value\n",
    ],
)
def test_protocol_context_constructor_effect_closure_rejects_dispatch_changes(
    tmp_path, product
):
    source = "from pkg import Base\ndef test_protocol():\n    repr(Base())\n"
    summary = _protocol_source_case(tmp_path, source, product)["summaries"][0]
    assert summary["status"] == "UNKNOWN"
    assert summary["unknown_reasons"]


def test_protocol_context_constructor_effect_closure_retains_nonmutating_source_helper(
    tmp_path,
):
    product = "def harmless():\n    return 3\nclass Base:\n    def __init__(self):\n        harmless()\n        self.value = 3\n    def __repr__(self):\n        return self.value\n"
    source = "from pkg import Base\ndef test_protocol():\n    repr(Base())\n"
    summary = _protocol_source_case(tmp_path, source, product)["summaries"][0]
    assert summary["status"] == "WEAK_PROTOCOL"
    assert summary["conditional_on_unchanged_dispatch"] is True
    assert "conditional" in summary["dispatch"]
    assert any(
        d["role"] == "constructor_effect" and d["symbol"] == "harmless"
        for d in summary["dependencies"]
    )


def test_protocol_context_constructor_unavailable_import_is_conditional_not_dispatch_proof(
    tmp_path,
):
    product = "from opaque_external import operation\nclass Base:\n    def __init__(self):\n        operation()\n        self.value = 3\n    def __repr__(self):\n        return self.value\n"
    source = "from pkg import Base\ndef test_protocol():\n    repr(Base())\n"
    summary = _protocol_source_case(tmp_path, source, product)["summaries"][0]
    assert summary["status"] == "WEAK_PROTOCOL"
    assert summary["conditional_on_unchanged_dispatch"] is True
    assert summary["runtime_observed"] is False
    assert (
        "CONSTRUCTOR_SUCCESS_AND_EFFECTS_NOT_VERIFIED" in summary["unresolved_effects"]
    )


@pytest.mark.parametrize(
    "document",
    [
        None,
        {},
        {"summaries": None},
        {"summaries": 7},
        {"summaries": "bad"},
        {"summaries": [None, 0, "bad", {}]},
        {"summaries": [{"test": "test_protocol", "dependencies": None}]},
        {"summaries": [{"test": "test_protocol", "dependencies": 7}]},
        {
            "summaries": [
                {
                    "test": "test_protocol",
                    "dependencies": [{"role": "test", "line": True}],
                }
            ]
        },
    ],
)
def test_protocol_context_annotation_consumer_rejects_malformed_documents(
    tmp_path, document
):
    import ast
    from copy import deepcopy
    from factoryline.context_efficiency import _protocol_annotate_finding

    node = ast.parse("def test_protocol():\n    pass\n").body[0]
    finding = {
        "code": "QUALITY_HOLLOW_TEST",
        "severity": "MEDIUM",
        "facts": {"original": True},
    }
    before = deepcopy(finding)
    assert (
        _protocol_annotate_finding(finding, node, {"protocol_observations": document})
        == before
    )


def test_protocol_context_annotation_consumer_matches_exact_test_identity_and_preserves_status(
    tmp_path,
):
    import ast
    from copy import deepcopy
    from factoryline.context_efficiency import (
        _protocol_annotate_finding,
        protocol_call_helpers,
    )

    node = ast.parse("def test_protocol():\n    pass\n").body[0]
    selected = {
        "test": node.name,
        "status": "UNKNOWN",
        "dependencies": [{"role": "test", "line": node.lineno}],
    }
    second = {**selected, "line": 8}
    wrong_name = {**selected, "test": "other"}
    wrong_line = {**selected, "dependencies": [{"role": "test", "line": 99}]}
    context = {
        "protocol_observations": {
            "summaries": [selected, wrong_name, second, wrong_line]
        }
    }
    before = deepcopy(context)
    finding = {"code": "QUALITY_HOLLOW_TEST", "severity": "MEDIUM"}
    result = _protocol_annotate_finding(finding, node, context)
    assert result["code"] == "QUALITY_HOLLOW_TEST" and result["severity"] == "MEDIUM"
    assert result["facts"]["protocol_observations"]["summaries"] == [selected, second]
    result["facts"]["protocol_observations"]["summaries"][0]["status"] = "changed"
    assert context == before
    assert _protocol_annotate_finding in protocol_call_helpers()
    assert protocol_call_helpers in protocol_call_helpers()


def test_protocol_context_constructor_effect_dependency_drift_is_not_treated_as_opaque_import(
    tmp_path,
):
    import hashlib

    product = "from .effects import operation\nclass Base:\n    def __init__(self):\n        operation()\n        self.value = 3\n    def __repr__(self):\n        return self.value\n"
    source = "from pkg import Base\ndef test_protocol():\n    repr(Base())\n"
    hashes = {
        "test_protocol.py": hashlib.sha256(source.encode()).hexdigest(),
        "pkg/__init__.py": hashlib.sha256(product.encode()).hexdigest(),
        "pkg/effects.py": "b" * 64,
    }
    summary = _protocol_source_case(
        tmp_path,
        source,
        product,
        additional={"pkg/effects.py": "def operation():\n    return 3\n"},
        source_hashes=hashes,
    )["summaries"][0]
    assert summary["status"] == "UNKNOWN"
    assert summary["unknown_reasons"] == ["SOURCE_IDENTITY_DRIFT"]


def test_protocol_context_constructor_effect_records_consulted_helper_classes(tmp_path):
    product = "class Helper:\n    pass\nclass Base:\n    def __init__(self):\n        Helper()\n        self.value = 3\n    def __repr__(self):\n        return self.value\n"
    source = "from pkg import Base\ndef test_protocol():\n    repr(Base())\n"
    summary = _protocol_source_case(tmp_path, source, product)["summaries"][0]
    assert summary["status"] == "WEAK_PROTOCOL"
    assert any(
        d["role"] == "constructor_effect_class" and d["symbol"] == "Helper"
        for d in summary["dependencies"]
    )


_DEMAND_PRODUCT = """class Pipeline:
    def __init__(self):
        self.enabled = False
    def enable(self):
        self.enabled = True
    def run(self, text):
        for item in text:
            yield item
def stream(text):
    stack = Pipeline()
    stack.enable()
    return stack.run(text)
def parse(text):
    return tuple(stream(text))
def format(text):
    stack = Pipeline()
    return ''.join(stack.run(text))
"""


@pytest.mark.parametrize("consumer", ["tuple", "list", "''.join"])
def test_protocol_context_demand_consumed_unconsumed_twin(tmp_path, consumer):
    source = (
        "import pkg\n"
        f"def test_consumed():\n    {consumer}(pkg.stream('data'))\n"
        "def test_created():\n    pkg.stream('data')\n"
    )
    rows = _protocol_source_case(tmp_path, source, _DEMAND_PRODUCT)["summaries"]
    by_test = {row["test"]: row for row in rows}
    consumed, created = by_test["test_consumed"], by_test["test_created"]
    assert consumed["status"] == "WEAK_PROTOCOL", consumed
    assert created["status"] == "CREATED_ONLY", created
    assert any(s["phase"] == "body_entered" for s in consumed["demand_chain"])
    assert not any(s["phase"] == "body_entered" for s in created["demand_chain"])
    assert consumed["output_checked"] is consumed["runtime_observed"] is False
    assert consumed["item_produced"] is consumed["exhausted"] is None
    assert consumed["conditional_on_path"] is True


@pytest.mark.parametrize("operation", ["parse", "format"])
def test_protocol_context_demand_source_return_and_local_receiver(tmp_path, operation):
    source = f"import pkg as renamed\ndef test_operation():\n    renamed.{operation}('data')\n"
    row = _protocol_source_case(tmp_path, source, _DEMAND_PRODUCT)["summaries"][0]
    assert row["status"] == "WEAK_PROTOCOL", row
    assert any(s["phase"] == "forces" for s in row["demand_chain"])
    assert any(
        s["phase"] == "body_entered" and s["symbol"] == "run"
        for s in row["demand_chain"]
    )
    assert any(
        d["role"] == "demand_allocation" and d["symbol"] == "Pipeline"
        for d in row["dependencies"]
    )


@pytest.mark.parametrize(
    "body", ["yield 3", "yield from ()", "if False:\n        yield None"]
)
def test_protocol_context_demand_constant_empty_keep_body_entry_separate(
    tmp_path, body
):
    product = "def stream(text):\n    " + body + "\n"
    source = "import pkg\ndef test_operation():\n    tuple(pkg.stream('data'))\n"
    row = _protocol_source_case(tmp_path, source, product)["summaries"][0]
    assert row["status"] == "UNKNOWN"
    assert "CONSTANT_OR_EMPTY_GENERATOR" in row["unknown_reasons"]
    assert any(s["phase"] == "body_entered" for s in row["demand_chain"])
    assert row["item_produced"] is row["exhausted"] is None


@pytest.mark.parametrize(
    "prefix", ["tuple = lambda x: x\n", "from pkg import parse as tuple\n"]
)
def test_protocol_context_demand_shadowed_consumer_not_credited(tmp_path, prefix):
    source = (
        "import pkg\n"
        + prefix
        + "def test_operation():\n    tuple(pkg.stream('data'))\n"
    )
    rows = _protocol_source_case(tmp_path, source, _DEMAND_PRODUCT)["summaries"]
    assert not any(r["status"] == "WEAK_PROTOCOL" for r in rows)


@pytest.mark.parametrize(
    "statement", ["next(pkg.stream('data'))", "pkg.stream('data')"]
)
def test_protocol_context_demand_partial_or_unconsumed_not_exhaustion(
    tmp_path, statement
):
    source = f"import pkg\ndef test_operation():\n    {statement}\n"
    rows = _protocol_source_case(tmp_path, source, _DEMAND_PRODUCT)["summaries"]
    assert not any(r["status"] == "WEAK_PROTOCOL" for r in rows)


@pytest.mark.parametrize(
    "body",
    [
        "try:\n        yield text\n    except Exception:\n        pass",
        "try:\n        yield text\n    finally:\n        return",
    ],
)
def test_protocol_context_demand_swallowed_generator_failure_unknown(tmp_path, body):
    product = "def stream(text):\n    " + body + "\n"
    source = "import pkg\ndef test_operation():\n    tuple(pkg.stream('data'))\n"
    row = _protocol_source_case(tmp_path, source, product)["summaries"][0]
    assert row["status"] == "UNKNOWN"
    assert "GENERATOR_FAILURE_MAY_BE_SWALLOWED" in row["unknown_reasons"]


@pytest.mark.parametrize(
    "mutation",
    [
        "pkg.Pipeline.run = lambda self, text: iter(())",
        "alias = pkg.Pipeline\n    alias.run = lambda self, text: iter(())",
    ],
)
def test_protocol_context_demand_mutated_dispatch_unknown(tmp_path, mutation):
    source = (
        "import pkg\ndef test_operation():\n    "
        + mutation
        + "\n    pkg.parse('data')\n"
    )
    rows = _protocol_source_case(tmp_path, source, _DEMAND_PRODUCT)["summaries"]
    assert not any(r["status"] == "WEAK_PROTOCOL" for r in rows)


def test_protocol_context_demand_constant_compute_has_no_body_entry(tmp_path):
    source = "import pkg\ndef test_operation():\n    pkg.compute()\n"
    rows = _protocol_source_case(tmp_path, source, "def compute():\n    return 3\n")[
        "summaries"
    ]
    assert not any(r["status"] == "WEAK_PROTOCOL" for r in rows)
    assert not any(
        s["phase"] == "body_entered" for r in rows for s in r["demand_chain"]
    )


@pytest.mark.parametrize("prefix", ["return\n    ", "if True:\n        return\n    "])
def test_protocol_context_demand_unreachable_test_call_has_no_credit(tmp_path, prefix):
    source = (
        "import pkg\ndef test_operation():\n    "
        + prefix
        + "tuple(pkg.stream('data'))\n"
    )
    rows = _protocol_source_case(tmp_path, source, _DEMAND_PRODUCT)["summaries"]
    assert not any(r["status"] == "WEAK_PROTOCOL" for r in rows)


def test_protocol_context_demand_skipped_test_has_no_credit(tmp_path):
    source = "import pytest\nimport pkg\n@pytest.mark.skip\ndef test_operation():\n    tuple(pkg.stream('data'))\n"
    rows = _protocol_source_case(tmp_path, source, _DEMAND_PRODUCT)["summaries"]
    assert not any(r["status"] == "WEAK_PROTOCOL" for r in rows)


def test_protocol_context_demand_earlier_wrapper_return_unknown(tmp_path):
    product = _DEMAND_PRODUCT.replace(
        "def parse(text):\n", "def parse(text):\n    if True:\n        return ()\n"
    )
    rows = _protocol_source_case(
        tmp_path, "import pkg\ndef test_operation():\n    pkg.parse('data')\n", product
    )["summaries"]
    assert not any(r["status"] == "WEAK_PROTOCOL" for r in rows)
    assert not any(
        s["phase"] == "body_entered" for r in rows for s in r["demand_chain"]
    )


def test_protocol_context_demand_later_receiver_allocation_not_resolved(tmp_path):
    product = _DEMAND_PRODUCT.replace(
        "    stack = Pipeline()\n    stack.enable()\n    return stack.run(text)",
        "    return stack.run(text)\n    stack = Pipeline()",
    )
    rows = _protocol_source_case(
        tmp_path, "import pkg\ndef test_operation():\n    pkg.parse('data')\n", product
    )["summaries"]
    assert not any(r["status"] == "WEAK_PROTOCOL" for r in rows)


def test_protocol_context_demand_generator_context_suppression_unknown(tmp_path):
    product = "import contextlib\ndef stream(text):\n    with contextlib.suppress(Exception):\n        yield text\n"
    row = _protocol_source_case(
        tmp_path,
        "import pkg\ndef test_operation():\n    tuple(pkg.stream('data'))\n",
        product,
    )["summaries"][0]
    assert row["status"] == "UNKNOWN"
    assert row["unknown_reasons"] == ["GENERATOR_CONTEXT_MANAGER_UNKNOWN"]


@pytest.mark.parametrize(
    "effect",
    [
        "stack.run = lambda *_: iter(())",
        "mutate(stack)",
        "alias = stack\n    alias.run = replacement",
    ],
)
def test_protocol_context_demand_identity_builder_effects_unknown(tmp_path, effect):
    product = _DEMAND_PRODUCT.replace(
        "    return ''.join(stack.run(text))",
        "    stack = builder(stack, text)\n    return ''.join(stack.run(text))",
    )
    product += "\ndef builder(stack, options):\n    " + effect + "\n    return stack\n"
    rows = _protocol_source_case(
        tmp_path, "import pkg\ndef test_operation():\n    pkg.format('data')\n", product
    )["summaries"]
    assert not any(r["status"] == "WEAK_PROTOCOL" for r in rows)


def test_protocol_context_demand_ordered_identity_builder_preserves_input(tmp_path):
    product = _DEMAND_PRODUCT.replace(
        "    return ''.join(stack.run(text))",
        "    stack = renamed(stack, text)\n    return ''.join(stack.run(text))",
    )
    product += "\ndef renamed(receiver, options):\n    return receiver\n"
    row = _protocol_source_case(
        tmp_path, "import pkg\ndef test_operation():\n    pkg.format('data')\n", product
    )["summaries"][0]
    assert row["status"] == "WEAK_PROTOCOL", row
    assert any(s["phase"] == "body_entered" for s in row["demand_chain"])


@pytest.mark.parametrize("star", [False, True])
def test_protocol_context_demand_parametrize_binding_closure_is_execution_scoped(
    tmp_path, star
):
    source = (
        "import pytest\nimport pkg\n"
        + ("from pytest import *\n" if star else "")
        + "def unrelated(value, name):\n    return getattr(value, name)\n"
        + "@pytest.mark.parametrize('text', ['data'])\ndef test_operation(text):\n    tuple(pkg.stream(text))\n"
    )
    rows = _protocol_source_case(tmp_path, source, _DEMAND_PRODUCT)["summaries"]
    assert any(r["status"] == "WEAK_PROTOCOL" for r in rows) is not star


def test_protocol_context_demand_builder_preserves_checked_data_receiver(tmp_path):
    product = _DEMAND_PRODUCT.replace(
        "        self.enabled = False",
        "        self.enabled = False\n        self.items = []",
    )
    product = product.replace(
        "    return ''.join(stack.run(text))",
        "    stack = builder(stack, text)\n    return ''.join(stack.run(text))",
    )
    product += "\ndef builder(stack, options):\n    stack.enable()\n    stack.items.append(3)\n    return stack\n"
    row = _protocol_source_case(
        tmp_path, "import pkg\ndef test_operation():\n    pkg.format('data')\n", product
    )["summaries"][0]
    assert row["status"] == "WEAK_PROTOCOL", row
    assert any(
        d["role"] == "receiver_effect" and d["symbol"] == "enable"
        for d in row["dependencies"]
    )


@pytest.mark.parametrize("effect", ["self.run = 'constant'", "self.__class__ = 3"])
def test_protocol_context_demand_builder_receiver_method_cannot_change_dispatch(
    tmp_path, effect
):
    product = _DEMAND_PRODUCT.replace(
        "        self.enabled = True", "        " + effect
    )
    product = product.replace(
        "    return ''.join(stack.run(text))",
        "    stack = builder(stack, text)\n    return ''.join(stack.run(text))",
    )
    product += "\ndef builder(stack, options):\n    stack.enable()\n    return stack\n"
    rows = _protocol_source_case(
        tmp_path, "import pkg\ndef test_operation():\n    pkg.format('data')\n", product
    )["summaries"]
    assert not any(r["status"] == "WEAK_PROTOCOL" for r in rows)


def test_protocol_context_demand_builder_early_return_cannot_prove_identity(tmp_path):
    product = _DEMAND_PRODUCT.replace(
        "    return ''.join(stack.run(text))",
        "    stack = builder(stack, text)\n    return ''.join(stack.run(text))",
    )
    product += "\ndef builder(stack, options):\n    if options:\n        return object()\n    return stack\n"
    rows = _protocol_source_case(
        tmp_path, "import pkg\ndef test_operation():\n    pkg.format('data')\n", product
    )["summaries"]
    assert not any(r["status"] == "WEAK_PROTOCOL" for r in rows)


def test_protocol_context_demand_builder_append_argument_cannot_escape_receiver(
    tmp_path,
):
    product = _DEMAND_PRODUCT.replace(
        "        self.enabled = False",
        "        self.enabled = False\n        self.items = []",
    )
    product = product.replace(
        "    return ''.join(stack.run(text))",
        "    stack = builder(stack, text)\n    return ''.join(stack.run(text))",
    )
    product += "\ndef builder(stack, options):\n    stack.items.append(mutate(stack))\n    return stack\n"
    rows = _protocol_source_case(
        tmp_path, "import pkg\ndef test_operation():\n    pkg.format('data')\n", product
    )["summaries"]
    assert not any(r["status"] == "WEAK_PROTOCOL" for r in rows)


def test_protocol_context_demand_builder_duplicate_receiver_argument_unknown(tmp_path):
    product = _DEMAND_PRODUCT.replace(
        "    return ''.join(stack.run(text))",
        "    stack = builder(stack, stack)\n    return ''.join(stack.run(text))",
    )
    product += "\ndef builder(primary, other):\n    other.run = replacement\n    return primary\n"
    rows = _protocol_source_case(
        tmp_path, "import pkg\ndef test_operation():\n    pkg.format('data')\n", product
    )["summaries"]
    assert not any(r["status"] == "WEAK_PROTOCOL" for r in rows), rows


def test_protocol_context_demand_unconditional_raise_prevents_return_demand(tmp_path):
    product = _DEMAND_PRODUCT.replace(
        "def parse(text):\n", "def parse(text):\n    raise RuntimeError('stop')\n"
    )
    rows = _protocol_source_case(
        tmp_path, "import pkg\ndef test_operation():\n    pkg.parse('data')\n", product
    )["summaries"]
    assert not any(r["status"] == "WEAK_PROTOCOL" for r in rows), rows


def test_protocol_context_demand_wrapper_receiver_cannot_replace_selected_method(
    tmp_path,
):
    product = _DEMAND_PRODUCT.replace(
        "        self.enabled = True", "        self.run = lambda *_: iter(())"
    )
    rows = _protocol_source_case(
        tmp_path, "import pkg\ndef test_operation():\n    pkg.parse('data')\n", product
    )["summaries"]
    assert not any(r["status"] == "WEAK_PROTOCOL" for r in rows), rows


@pytest.mark.parametrize(
    "call",
    [
        "pkg.stream()",
        "pkg.stream('data', text='other')",
        "pkg.stream(*values)",
        "pkg.stream(**values)",
    ],
)
def test_protocol_context_demand_invalid_source_binding_never_enters_body(
    tmp_path, call
):
    source = "import pkg\ndef test_operation():\n    tuple(" + call + ")\n"
    rows = _protocol_source_case(
        tmp_path, source, "def stream(text):\n    yield text\n"
    )["summaries"]
    assert not any(r["status"] == "WEAK_PROTOCOL" for r in rows), rows
    assert not any(
        s["phase"] == "body_entered" for r in rows for s in r["demand_chain"]
    ), rows


@pytest.mark.parametrize(
    "product,call",
    [
        ("def stream(text='data'):\n    yield text\n", "pkg.stream()"),
        ("def stream(*, text):\n    yield text\n", "pkg.stream(text='data')"),
        ("def stream(text, /):\n    yield text\n", "pkg.stream('data')"),
    ],
)
def test_protocol_context_demand_valid_source_binding_preserves_entry(
    tmp_path, product, call
):
    source = "import pkg\ndef test_operation():\n    tuple(" + call + ")\n"
    row = _protocol_source_case(tmp_path, source, product)["summaries"][0]
    assert row["status"] == "WEAK_PROTOCOL", row
    assert any(s["phase"] == "body_entered" for s in row["demand_chain"])


@pytest.mark.parametrize("rebind", [False, True])
def test_protocol_context_source_kwargs_identity_propagates_until_rebound(
    tmp_path, monkeypatch, rebind
):
    from factoryline import review_integrity

    actual = review_integrity.bind_source_call
    seen = []

    def capture(call, function, *args, **kwargs):
        bound = actual(call, function, *args, **kwargs)
        if function.name == "stream":
            seen.append(bound["options"])
        return bound

    monkeypatch.setattr(review_integrity, "bind_source_call", capture)
    product = (
        "def stream(options):\n    yield options\ndef format(**options):\n    "
        + ("options = replacement\n    " if rebind else "")
        + "return tuple(stream(options))\n"
    )
    rows = _protocol_source_case(
        tmp_path,
        "import pkg\ndef test_operation():\n    pkg.format(enabled=True)\n",
        product,
    )["summaries"]
    assert rows and seen
    assert (type(seen[0]) is dict) is not rebind
    if not rebind:
        assert seen[0]["enabled"].value is True


@pytest.mark.parametrize(
    "signature,returned,arguments,expected",
    [
        ("prefix, /, result", "result", "stack, None", False),
        ("primary, /, secondary", "primary", "stack, None", True),
        ("primary, /", "primary", "stack", True),
    ],
)
def test_protocol_context_identity_return_tracks_actual_positional_parameter(
    tmp_path, signature, returned, arguments, expected
):
    product = _DEMAND_PRODUCT.replace(
        "    return ''.join(stack.run(text))",
        "    stack = builder(" + arguments + ")\n    return ''.join(stack.run(text))",
    )
    product += "\ndef builder(" + signature + "):\n    return " + returned + "\n"
    rows = _protocol_source_case(
        tmp_path, "import pkg\ndef test_operation():\n    pkg.format('data')\n", product
    )["summaries"]
    assert any(row["status"] == "WEAK_PROTOCOL" for row in rows) is expected, rows


@pytest.mark.parametrize(
    ("body", "severity"),
    [
        (
            "def test_pickle(self):\n"
            "    objects = select(s for s in Student if s.scholarship > 0).order_by(\n"
            "        desc(Student.id)\n"
            "    )\n"
            "    data = pickle.dumps(objects)\n"
            "    rollback()\n"
            "    objects = pickle.loads(data)\n"
            "    self.assertTrue(objects)\n",
            "INFO",
        ),
        (
            "def test_pickle():\n"
            "    packet = {'value': 4}\n"
            "    serialized = pickle.dumps(packet)\n"
            "    packet = pickle.loads(serialized)\n"
            "    assert packet\n",
            "INFO",
        ),
        (
            "def test_pickle():\n"
            "    protocol = 4\n"
            "    packet = {'value': 4}\n"
            "    serialized = pickle.dumps(packet, protocol=protocol)\n"
            "    restored = pickle.loads(serialized)\n"
            "    assert restored == packet\n",
            "INFO",
        ),
        (
            "def test_pickle():\n"
            "    objects = []\n"
            "    data = pickle.dumps(objects)\n"
            "    objects.append('later generation')\n"
            "    restored = pickle.loads(data)\n"
            "    assert restored == []\n",
            "INFO",
        ),
        (
            "def test_pickle():\n"
            "    objects = []\n"
            "    publish(objects)\n"
            "    data = pickle.dumps(objects)\n"
            "    restored = pickle.loads(data)\n"
            "    assert restored\n",
            "HIGH",
        ),
        (
            "def test_pickle():\n"
            "    objects = []\n"
            "    alias = objects\n"
            "    data = pickle.dumps(objects)\n"
            "    restored = pickle.loads(data)\n"
            "    assert restored\n",
            "HIGH",
        ),
        (
            "def test_pickle():\n"
            "    objects = []\n"
            "    objects.clear()\n"
            "    data = pickle.dumps(objects)\n"
            "    restored = pickle.loads(data)\n"
            "    assert restored\n",
            "HIGH",
        ),
        (
            "def test_pickle():\n"
            "    objects = []\n"
            "    def later():\n"
            "        return objects\n"
            "    data = pickle.dumps(objects)\n"
            "    restored = pickle.loads(data)\n"
            "    assert restored\n",
            "HIGH",
        ),
        (
            "def test_pickle():\n"
            "    objects = []\n"
            "    def later(value=objects):\n"
            "        return value\n"
            "    data = pickle.dumps(objects)\n"
            "    restored = pickle.loads(data)\n"
            "    assert restored\n",
            "HIGH",
        ),
        (
            "def test_pickle():\n"
            "    objects = []\n"
            "    callback = lambda: objects\n"
            "    data = pickle.dumps(objects)\n"
            "    restored = pickle.loads(data)\n"
            "    assert restored\n",
            "HIGH",
        ),
        (
            "def test_pickle():\n"
            "    objects = []\n"
            "    def unrelated():\n"
            "        objects = ['local to nested function']\n"
            "        return objects\n"
            "    data = pickle.dumps(objects)\n"
            "    restored = pickle.loads(data)\n"
            "    assert restored == []\n",
            "INFO",
        ),
        (
            "def test_pickle():\n"
            "    objects = []\n"
            "    objects = make_objects()\n"
            "    data = pickle.dumps(objects)\n"
            "    restored = pickle.loads(data)\n"
            "    assert restored\n",
            "HIGH",
        ),
        (
            "def test_pickle():\n"
            "    objects = []\n"
            "    data = pickle.dumps(objects, protocol=choose_protocol())\n"
            "    restored = pickle.loads(data)\n"
            "    assert restored == objects\n",
            "HIGH",
        ),
    ],
    ids=[
        "post-dump-rebinding",
        "name-independent-generation",
        "known-protocol-option",
        "post-dump-object-mutation",
        "opaque-escape-before-dump",
        "alias-before-dump",
        "mutation-before-dump",
        "closure-capture-before-dump",
        "definition-header-capture-before-dump",
        "lambda-capture-before-dump",
        "nested-function-local-write",
        "rebound-before-dump",
        "side-effecting-protocol-option",
    ],
)
def test_security_scan_tracks_pickle_value_generation_at_dump(tmp_path, body, severity):
    from factoryline.review_audits import security_scan

    (tmp_path / "test_pickle.py").write_text("import pickle\n" + body, encoding="utf-8")
    findings = [
        finding
        for finding in security_scan(tmp_path, cache_enabled=False)["findings"]
        if finding["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    assert len(findings) == 1
    assert findings[0]["severity"] == severity
    if severity == "INFO":
        assert findings[0]["facts"]["input_provenance"] == "direct_local_serialization"


@pytest.mark.parametrize(
    "prefix,setup,option,severity",
    [
        ("def test_roundtrip(protocol):\n", "", "protocol", "HIGH"),
        ("def test_roundtrip():\n", "    protocol = 4\n", "protocol", "INFO"),
        ("def test_roundtrip():\n", "    protocol = -1\n", "protocol", "INFO"),
        ("def test_roundtrip():\n", "    protocol = True\n", "protocol", "HIGH"),
        ("def test_roundtrip():\n", "    protocol = 'invalid'\n", "protocol", "HIGH"),
        ("def test_roundtrip():\n", "    protocol = Protocol()\n", "protocol", "HIGH"),
        (
            "def test_roundtrip():\n",
            "    protocol = 4\n    protocol = supplied\n",
            "protocol",
            "HIGH",
        ),
        (
            "def test_roundtrip():\n",
            "    global protocol\n    protocol = 4\n",
            "protocol",
            "HIGH",
        ),
        ("def test_roundtrip():\n", "", "4", "INFO"),
        ("def test_roundtrip():\n", "", "choose_protocol()", "HIGH"),
        (
            "@pytest.mark.parametrize('protocol', [3, 4])\ndef test_roundtrip(protocol):\n",
            "",
            "protocol",
            "INFO",
        ),
        (
            "@pytest.mark.parametrize('protocol', [3, supplied])\ndef test_roundtrip(protocol):\n",
            "",
            "protocol",
            "HIGH",
        ),
        (
            "@pytest.mark.parametrize('protocol', [3, 4], indirect=True)\ndef test_roundtrip(protocol):\n",
            "",
            "protocol",
            "HIGH",
        ),
        (
            "pytest.mark.parametrize = replacement\n@pytest.mark.parametrize('protocol', [3, 4])\ndef test_roundtrip(protocol):\n",
            "",
            "protocol",
            "HIGH",
        ),
    ],
)
def test_pickle_protocol_requires_closed_integer_domain(
    tmp_path, prefix, setup, option, severity
):
    from factoryline.review_audits import security_scan

    source = (
        "import pickle\nimport pytest\n"
        + prefix
        + setup
        + "    local = {'value': 1}\n"
        + f"    data = pickle.dumps(local, protocol={option})\n"
        + "    restored = pickle.loads(data)\n    assert restored == local\n"
    )
    (tmp_path / "test_protocol.py").write_text(source, encoding="utf-8")
    findings = security_scan(tmp_path, cache_enabled=False)["findings"]
    unsafe = [
        item for item in findings if item["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    assert len(unsafe) == 1
    assert unsafe[0]["severity"] == severity


@pytest.mark.parametrize(
    "reuse",
    [
        "def test_reentry():\n    test_roundtrip(Protocol())\n",
        "alias = test_roundtrip\ndef test_reentry():\n    alias(Protocol())\n",
        "registered = [test_roundtrip]\n",
        "def test_reentry():\n    globals()['test_roundtrip'](Protocol())\n",
        "def test_roundtrip(protocol):\n    pass\n",
        "def test_reentry():\n    module.test_roundtrip(Protocol())\n",
        "def test_reentry():\n    name = 'test_' + 'roundtrip'\n    globals()[name](Protocol())\n",
        "def test_reentry():\n    for name, fn in list(globals().items()):\n        if name.startswith('test_round'):\n            fn(Protocol())\n",
        "namespace = globals\ndef test_reentry():\n    namespace()['test_' + 'roundtrip'](Protocol())\n",
    ],
)
def test_pickle_protocol_parametrize_does_not_close_reused_function(tmp_path, reuse):
    from factoryline.review_audits import security_scan

    source = (
        "import pickle\nimport pytest\n"
        "class Protocol:\n    def __index__(self):\n        return get_protocol()\n"
        "@pytest.mark.parametrize('protocol', [3, 4])\n"
        "def test_roundtrip(protocol):\n"
        "    local = {'value': 1}\n"
        "    data = pickle.dumps(local, protocol=protocol)\n"
        "    restored = pickle.loads(data)\n    assert restored == local\n" + reuse
    )
    (tmp_path / "test_protocol.py").write_text(source, encoding="utf-8")
    findings = security_scan(tmp_path, cache_enabled=False)["findings"]
    unsafe = [
        item for item in findings if item["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    assert len(unsafe) == 1
    assert unsafe[0]["severity"] == "HIGH"
    assert "input_provenance" not in unsafe[0]["facts"]


def test_pickle_protocol_function_name_as_data_is_not_a_callable_escape(tmp_path):
    from factoryline.review_audits import security_scan

    source = (
        "import pickle\nimport pytest\n"
        "@pytest.mark.parametrize('protocol', [3, 4])\n"
        "def test_roundtrip(protocol):\n"
        "    local = {'label': 'test_roundtrip'}\n"
        "    data = pickle.dumps(local, protocol=protocol)\n"
        "    restored = pickle.loads(data)\n    assert restored == local\n"
    )
    (tmp_path / "test_protocol.py").write_text(source, encoding="utf-8")
    findings = security_scan(tmp_path, cache_enabled=False)["findings"]
    unsafe = [
        item for item in findings if item["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    assert len(unsafe) == 1
    assert unsafe[0]["severity"] == "INFO"
    assert unsafe[0]["facts"]["input_provenance"] == "direct_local_serialization"


def test_pickle_colocation_uses_current_exact_byte_occurrence_guard(
    tmp_path, monkeypatch
):
    from factoryline import context_efficiency as context
    from factoryline.review_audits import security_scan

    (tmp_path / "test_roundtrip.py").write_text(
        "import pickle\ndef test_roundtrip():\n    value = []\n"
        "    data = pickle.dumps(value)\n    restored = pickle.loads(data)\n"
        "    assert restored == []\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(context, "_capability_uses_match", lambda *_args: False)
    findings = security_scan(tmp_path, cache_enabled=False)["findings"]
    assert any(
        item["code"] == "SECURITY_UNSAFE_DESERIALIZATION" and item["severity"] == "HIGH"
        for item in findings
    )


def test_provider_colocation_uses_current_captured_import_closure(
    monkeypatch, tmp_path
):
    from factoryline import context_efficiency as context
    from factoryline import type_intent_provider_provenance as provider

    context_packet = {}
    calls = []

    def unresolved(*args):
        calls.append(args)
        return [], False

    monkeypatch.setattr(context, "captured_local_import_closure", unresolved)
    context.bind_provider_context(
        context_packet, tmp_path, tmp_path / "test_sample.py", {}, {}, {}, None
    )
    assert len(calls) == 1
    assert context_packet["provider_source_closure_complete"] is False
    assert context.bind_provider_context is provider.bind_provider_context
    assert provider.bind_provider_context in provider.CACHE_HELPERS


def test_pickle_colocation_helpers_participate_in_runtime_proof_identity():
    from factoryline import context_efficiency as context
    from factoryline import runtime_audit_integrity as runtime

    helpers = set(runtime.workspace_builtin_helpers())
    expected = {
        value
        for name, value in vars(runtime).items()
        if (
            name.startswith("_pickle_")
            or name.startswith("_local_pickle")
            or name
            in {
                "_test_serialization_roundtrip",
                "_plain_scope_statement_index",
                "_simple_scope_assignment",
                "_prior_pickle_dump",
                "_single_local_pickle_bytes_flow",
            }
        )
        and callable(value)
    }
    assert expected <= helpers
    assert (
        context._test_serialization_roundtrip is runtime._test_serialization_roundtrip
    )


@pytest.mark.parametrize("provider", ["builtins", "contextlib"])
def test_absent_oracle_provider_does_not_walk_descendants(monkeypatch, provider):
    import ast
    from factoryline import test_oracle_misuse as misuse

    module = ast.parse(
        "import json\ndef test_value():\n    value = 1\n    assert value == value\n"
    )
    test = module.body[1]

    def forbidden_walk(_):
        raise AssertionError("absent provider must not walk module descendants")

    monkeypatch.setattr(misuse, "_stored_names", forbidden_walk)
    assert misuse._module_provider_aliases(module, test, provider, {"ValueError"}) == {}
    assert (
        misuse._imported_provider_names_closed(module, test, provider, {"ValueError"})
        is True
    )


@pytest.mark.parametrize(
    "provider,symbol", [("builtins", "ValueError"), ("contextlib", "suppress")]
)
@pytest.mark.parametrize("form", ["module", "from"])
def test_present_oracle_provider_still_checks_all_references(provider, symbol, form):
    import ast
    from factoryline import test_oracle_misuse as misuse

    declaration = (
        f"import {provider} as p"
        if form == "module"
        else f"from {provider} import {symbol} as operation"
    )
    call = f"p.{symbol}()" if form == "module" else "operation()"
    clean = ast.parse(f"{declaration}\ndef test_value():\n    {call}\n")
    escaped = ast.parse(
        f"{declaration}\nleaked = {('p' if form == 'module' else 'operation')}\ndef test_value():\n    {call}\n"
    )
    if form == "module":
        assert misuse._module_provider_aliases(
            clean, clean.body[-1], provider, {symbol}
        ) == {"p": provider}
        assert (
            misuse._module_provider_aliases(
                escaped, escaped.body[-1], provider, {symbol}
            )
            is None
        )
    else:
        assert (
            misuse._imported_provider_names_closed(
                clean, clean.body[-1], provider, {symbol}
            )
            is True
        )
        assert (
            misuse._imported_provider_names_closed(
                escaped, escaped.body[-1], provider, {symbol}
            )
            is False
        )


@pytest.mark.parametrize("provider", ["builtins", "contextlib"])
def test_dotted_oracle_provider_does_not_take_absent_fast_path(provider):
    import ast
    from factoryline import test_oracle_misuse as misuse

    module = ast.parse(f"import {provider}.extension\ndef test_value():\n    pass\n")
    assert (
        misuse._module_provider_aliases(module, module.body[-1], provider, set())
        is None
    )


@pytest.mark.parametrize("provider", ["builtins", "contextlib"])
def test_wildcard_oracle_provider_does_not_take_absent_fast_path(provider):
    import ast
    from factoryline import test_oracle_misuse as misuse

    module = ast.parse(f"from {provider} import *\ndef test_value():\n    pass\n")
    assert (
        misuse._imported_provider_names_closed(module, module.body[-1], provider, set())
        is False
    )


def test_absent_inert_module_helper_does_not_build_reference_maps(monkeypatch):
    import ast
    from factoryline import test_oracle_misuse as misuse

    module = ast.parse(
        "def helper():\n    return opaque()\ndef test_value():\n    helper()\n"
    )

    def forbidden_bindings(_):
        raise AssertionError("no stub candidate needs module reference maps")

    monkeypatch.setattr(misuse, "_module_bindings", forbidden_bindings)
    assert misuse._module_pass_helpers(module, set(), module.body[-1]) == {}


@pytest.mark.parametrize(
    "body", ["pass", "...", "return", "return None", '"docstring"']
)
def test_present_inert_module_helper_retains_reference_validation(body):
    import ast
    from factoryline import test_oracle_misuse as misuse

    clean = ast.parse(f"def helper():\n    {body}\ndef test_value():\n    helper()\n")
    leaked = ast.parse(
        f"def helper():\n    {body}\nleaked = helper\ndef test_value():\n    helper()\n"
    )
    assert misuse._module_pass_helpers(clean, set(), clean.body[-1]) == {
        "helper": clean.body[0]
    }
    assert misuse._module_pass_helpers(leaked, {"leaked"}, leaked.body[-1]) == {}


def test_protocol_context_uses_invocation_resolver_with_standalone_fallback(
    tmp_path, monkeypatch
):
    import ast
    import hashlib
    from factoryline import review_audits as scanner
    from factoryline.context_efficiency import (
        captured_import_resolver,
        protocol_call_context,
    )

    source = tmp_path / "test_case.py"
    source.write_text("def test_case():\n    pass\n")
    tree = ast.parse(source.read_text())
    tree._oracle_source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    snapshots = {source: tree}
    eligible = {source.resolve(): source}
    calls = []
    original = scanner._oracle_imports

    def observed(*args):
        calls.append(args[1])
        return original(*args)

    monkeypatch.setattr(scanner, "_oracle_imports", observed)
    resolver = captured_import_resolver(tmp_path, snapshots, eligible, observed)
    assert calls == [source]
    captured = protocol_call_context(
        tmp_path, [source], snapshots, import_resolver=resolver, eligible=eligible
    )
    assert calls == [source]
    assert protocol_call_context(tmp_path, [source], snapshots) == captured
    assert calls == [source, source]
    with pytest.raises(ValueError, match="outside its captured generation"):
        resolver(tmp_path, source, ast.parse(source.read_text()), eligible)
