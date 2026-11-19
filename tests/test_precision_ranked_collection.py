"""Exercise registered native dispatch, ordered receipts, and source budget ownership."""

from contextlib import closing, contextmanager
from hashlib import sha256
import json
from pathlib import Path
from threading import Event, get_ident
from time import monotonic
from types import SimpleNamespace

import pytest

from scripts import precision_ranked_collection as ranked
from scripts.precision_native_capture import main as capture_main


@pytest.mark.parametrize("scope", ["native", "python", "empty"])
def test_normal_projection_keeps_explicit_no_source_producers_without_fake_pass(
    tmp_path, scope
):
    from scripts.precision_native_capture import project_normal_observation

    root, sources, report = _normal_projection_fixture(tmp_path)
    static = report["static_security"]
    keep_python, keep_native = scope == "python", scope == "native"
    static["findings"] = (
        [row for row in static["findings"] if bool(row.get("code")) == keep_python]
        if scope != "empty"
        else []
    )
    if not keep_python:
        (root / "app.py").unlink()
        static["python_ast_security"] = {
            "state": "NO_SOURCES",
            "findings": [],
            "audit_coverage": {"measurement_state": "not_applicable"},
        }
        static.pop("finding_tier_report")
        static["python_finding_conservation"] = {}
    if not keep_native:
        (root / "app.tsx").unlink()
        report["deep_audit"]["lanes"] = []
    sources = [row for row in sources if (root / row["path"]).exists()]
    static["sources"] = sources
    count = int(keep_python) + int(keep_native)
    static["finding_conservation"].update(
        expected_raw_rows=count,
        physical_raw_rows=count,
        python_rows=int(keep_python),
        native_raw_rows=int(keep_native),
    )
    static.pop("finding_counts")
    static.pop("source_binding_count")
    _seal_normal_fixture(report)
    raw = json.dumps(report).encode()
    projected = project_normal_observation(
        raw, sources, root=root, report_sha256=sha256(raw).hexdigest()
    )
    assert projected["raw_count"] == count
    assert projected["admitted_count"] is None


@pytest.mark.parametrize("malformed", [b"NaN", b"[]", b'{"static_security":null}'])
def test_detached_projection_malformed_json_fails_without_traceback_or_output(
    tmp_path, capsys, malformed
):
    normal, manifest, out = (
        tmp_path / "normal.json",
        tmp_path / "inventory.json",
        tmp_path / "out.json",
    )
    root = tmp_path / "capture"
    root.mkdir()
    normal.write_bytes(malformed)
    manifest.write_text('{"sources":[]}')
    assert (
        capture_main(
            [
                "--root",
                str(root),
                "--normal-report",
                str(normal),
                "--normal-report-sha256",
                _sha(normal),
                "--observation-manifest",
                str(manifest),
                "--out",
                str(out),
            ]
        )
        == 2
    )
    assert not out.exists()
    assert json.loads(capsys.readouterr().err)["state"] == "INVALID"


def _read(path):
    return json.loads(path.read_bytes())


def _sha(path):
    return sha256(path.read_bytes()).hexdigest()


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _normal_projection_fixture(tmp_path):
    root = tmp_path / "capture"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n")
    (root / "app.tsx").write_text("export const value = 1;\n")
    sources = [
        {
            "path": p.name,
            "sha256": _sha(p),
            "kind": "python" if p.suffix == ".py" else "typescript",
        }
        for p in root.iterdir()
    ]
    source_hashes = {row["path"]: row["sha256"] for row in sources}
    python = {
        "code": "SECURITY_CONTROL",
        "path": "app.py",
        "line": 1,
        "column": 0,
        "end_line": 1,
        "end_column": 5,
    }
    native = {
        "finding_id": "native-id",
        "rule_id": "rule.control",
        "lane_id": "native-static",
        "path": "app.tsx",
        "line": 1,
        "source_sha256": source_hashes["app.tsx"],
        "locations": [{"path": "app.tsx", "line": 1}],
        "flows": [{"source": 1, "sink": 1}],
    }
    lane = {
        "lane_id": "native-static",
        "engine": "semgrep",
        "state": "OBSERVED",
        "gaps": [],
        "findings": [native],
        "bundle_sha256": "a" * 64,
        "report_sha256": "b" * 64,
        "coverage_sha256": "c" * 64,
        "challenge_sha256": "d" * 64,
    }
    static = {
        "schema": "factory.mixed-security-audit.v1",
        "policy_scope": "python_ast_security",
        "sources": sources,
        "findings": [python, native],
        "finding_tier_report": {
            "ledger": [
                {
                    "raw_finding": python,
                    "tier": "NEEDS_CONTEXT",
                    "source_identity": {
                        "path": "app.py",
                        "source_sha256": source_hashes["app.py"],
                    },
                }
            ]
        },
        "python_finding_conservation": {"state": "PASS"},
        "finding_conservation": {
            "state": "UNASSESSED",
            "scope": "mixed_diagnostic_identity_multiplicity",
            "expected_raw_rows": 2,
            "physical_raw_rows": 2,
            "python_rows": 1,
            "native_raw_rows": 1,
            "native_policy_state": "UNASSESSED",
        },
    }
    report = {
        "schema": "factory.scan-report.v1",
        "state": "INCOMPLETE",
        "static_security": static,
        "deep_audit": {
            "lanes": [
                {
                    "measurement_id": "native_worker_execution",
                    "result": {"lanes": [lane]},
                }
            ]
        },
    }
    static["python_ast_security"] = {
        "schema": "factory.security-audit.v1",
        "state": "BLOCKED",
        "findings": [python],
        "sources": [row for row in sources if row["kind"] == "python"],
        "oracle_context": {},
        "database_context": {},
        "finding_tier_report": json.loads(json.dumps(static["finding_tier_report"])),
        "finding_conservation": {"state": "PASS"},
    }
    report = json.loads(json.dumps(report))
    _seal_normal_fixture(report)
    return root, sources, report


def _seal_normal_fixture(report):
    from factoryline.adoption import _digest

    static = report["static_security"]
    child = static["python_ast_security"]
    if child.get("state") != "NO_SOURCES":
        from scripts.precision_native_capture import _normal_digest

        child["source_manifest_sha256"] = _normal_digest(
            {
                key: child[key]
                for key in ("sources", "oracle_context", "database_context")
            }
        )
        child["audit_sha256"] = _normal_digest(
            {key: value for key, value in child.items() if key != "audit_sha256"}
        )
    static.setdefault("source_binding_count", len(static["sources"]))
    from collections import Counter

    static.setdefault(
        "finding_counts",
        dict(
            Counter(
                row.get("code") or row.get("rule_id") or row.get("id") or "UNCLASSIFIED"
                for row in static["findings"]
            )
        ),
    )
    static["source_manifest_sha256"] = _digest(static["sources"])
    static["audit_sha256"] = _digest(
        {key: value for key, value in static.items() if key != "audit_sha256"}
    )


@pytest.mark.parametrize("damage", [None, "source", "seal", "missing_row", "count"])
def test_normal_projection_accepts_original_python_producer_and_rejects_drift(
    tmp_path, damage
):
    from scripts.precision_native_capture import (
        NativeObservationError,
        _normal_digest,
        project_normal_observation,
    )

    root, sources, report = _normal_projection_fixture(tmp_path)
    sources = [row for row in sources if row["kind"] == "python"]
    python = report["static_security"]["python_ast_security"]
    python["finding_counts"] = {"SECURITY_CONTROL": 1}
    python["finding_conservation"].update(
        scope="diagnostic_identity_multiplicity",
        expected_raw_rows=1,
        physical_raw_rows=1,
        ledger_raw_rows=1,
    )
    if damage == "missing_row":
        python["finding_tier_report"]["ledger"] = []
    if damage == "count":
        python["finding_counts"] = {"SECURITY_CONTROL": 2}
    python["audit_sha256"] = _normal_digest(
        {key: value for key, value in python.items() if key != "audit_sha256"}
    )
    if damage == "seal":
        python["audit_sha256"] = "0" * 64
    if damage == "source":
        (root / "app.py").write_text("changed = True\n")
    report["static_security"] = python
    report["deep_audit"]["lanes"] = [
        {
            "measurement_id": "native_worker_execution",
            "state": "NOT_RUN",
            "result": None,
        }
    ]
    raw = json.dumps(report).encode()
    if damage is not None:
        with pytest.raises(NativeObservationError):
            project_normal_observation(
                raw, sources, root=root, report_sha256=sha256(raw).hexdigest()
            )
        return
    projected = project_normal_observation(
        raw, sources, root=root, report_sha256=sha256(raw).hexdigest()
    )
    assert projected["raw_count"] == 1
    assert projected["raw"][0]["raw_finding"] == python["findings"][0]
    assert projected["raw"][0]["tier"] == "NEEDS_CONTEXT"
    assert projected["authority"] == "none" and projected["execution_verified"] is False
    assert projected["measurement_complete"] is False
    assert projected["score_eligible"] is False and projected["admitted_count"] is None
    assert "python_ast_security" not in python and "source_binding_count" not in python
    assert json.dumps(report).encode() == raw


def test_normal_projection_preserves_mixed_rows_without_claiming_policy_or_execution(
    tmp_path,
):
    from scripts.precision_native_capture import project_normal_observation

    root, sources, report = _normal_projection_fixture(tmp_path)
    raw = json.dumps(report).encode()
    result = project_normal_observation(
        raw, sources, root=root, report_sha256=sha256(raw).hexdigest()
    )
    assert result["schema"] == "factory.precision.normal-observation.v1"
    assert result["raw_count"] == 2
    assert result["execution_verified"] is False
    assert result["admitted_count"] is None
    native = result["raw"][1]
    assert native["tier"] == "UNASSESSED" and native["admitted"] is None
    assert native["raw_finding"] == report["static_security"]["findings"][1]
    assert native["native_bindings"]["bundle_sha256"] == "a" * 64


@pytest.mark.parametrize(
    "scenario",
    [
        "failed",
        "clean",
        "missing_actions",
        "missing_coverage",
        "incomplete_actions",
        "missing_binding",
    ],
)
def test_detached_normal_projection_preserves_zero_row_lane_measurement(
    tmp_path, scenario
):
    """Producer completeness metadata cannot authenticate detached execution or scoring."""
    from scripts.precision_native_capture import project_normal_observation

    root, sources, report = _normal_projection_fixture(tmp_path)
    static = report["static_security"]
    worker = report["deep_audit"]["lanes"][0]["result"]
    lane = worker["lanes"][0]
    lane["findings"] = []
    failed = scenario == "failed"
    lane.update(
        state="INCOMPLETE" if failed else "OBSERVED",
        gaps=["NATIVE_SCAN_FAILED"] if failed else [],
    )
    worker.update(
        state="INCOMPLETE" if failed else "COMPLETE",
        analysis_complete=not failed,
        gaps=[{"code": "NATIVE_SCAN_FAILED"}] if failed else [],
        action_coverage={
            "state": "VERIFIED",
            "expected_count": 1,
            "started_count": 1,
            "terminal_count": 1,
            "missing_starts": [],
            "missing_terminals": [],
            "duplicates": [],
            "unexpected": [],
            "mismatches": [],
        },
    )
    static["findings"] = static["python_ast_security"]["findings"]
    static["audit_coverage"] = {"complete": not failed}
    static["python_ast_security"]["audit_coverage"] = {"complete": True}
    static["finding_conservation"].update(
        expected_raw_rows=1, physical_raw_rows=1, native_raw_rows=0
    )
    static.pop("finding_counts")
    if scenario == "missing_actions":
        worker.pop("action_coverage")
    if scenario == "missing_coverage":
        static.pop("audit_coverage")
    if scenario == "incomplete_actions":
        worker["action_coverage"]["missing_terminals"] = ["declared-unfinished-action"]
    if scenario == "missing_binding":
        lane.pop("challenge_sha256")
    _seal_normal_fixture(report)
    raw = json.dumps(report).encode()
    result = project_normal_observation(
        raw, sources, root=root, report_sha256=sha256(raw).hexdigest()
    )
    assert result["raw_count"] == 1
    assert result["measurement_complete"] is (scenario == "clean")
    assert result["score_eligible"] is False
    assert result["execution_verified"] is False
    assert result["admitted_count"] is None
    diagnostic = result["native_diagnostics"]["workers"][0]
    assert diagnostic["state"] == worker["state"]
    assert diagnostic["analysis_complete"] == worker["analysis_complete"]
    assert diagnostic["gaps"] == worker["gaps"]
    assert diagnostic["action_coverage"] == worker.get("action_coverage")
    assert diagnostic["lanes"][0]["raw_count"] == 0
    assert diagnostic["lanes"][0]["state"] == lane["state"]
    assert diagnostic["lanes"][0]["gaps"] == lane["gaps"]
    assert diagnostic["lanes"][0]["evidence_bindings_present"] is (
        scenario != "missing_binding"
    )


@pytest.mark.parametrize(
    "damage",
    [
        "wrong_hash",
        "stale_source",
        "unbound_source",
        "missing_native",
        "duplicate",
        "global_pass",
        "unverified_lane",
        "missing_binding",
        "child_divergence",
        "false_counts",
        "native_location",
    ],
)
def test_normal_projection_rejects_stale_unbound_or_unconserved_inputs(
    tmp_path, damage
):
    from scripts.precision_native_capture import (
        project_normal_observation,
        NativeObservationError,
    )

    root, sources, report = _normal_projection_fixture(tmp_path)
    static = report["static_security"]
    lane = report["deep_audit"]["lanes"][0]["result"]["lanes"][0]
    mutations = {
        "stale_source": lambda: (root / "app.tsx").write_text("changed"),
        "unbound_source": lambda: static["findings"][1].update(source_sha256="0" * 64),
        "missing_native": lambda: static["findings"].pop(),
        "duplicate": lambda: (
            lane["findings"].append(lane["findings"][0]),
            static["findings"].append(static["findings"][-1]),
        ),
        "global_pass": lambda: static["finding_conservation"].update(state="PASS"),
        "unverified_lane": lambda: lane.update(state="INCOMPLETE"),
        "missing_binding": lambda: lane.pop("bundle_sha256"),
        "child_divergence": lambda: static["finding_tier_report"]["ledger"][0].update(
            tier="SUPPORTED_DEFECT"
        ),
        "false_counts": lambda: static.update(finding_counts={"SECURITY_CONTROL": 100}),
        "native_location": lambda: static["findings"][1]["locations"][0].update(
            path="other.tsx"
        ),
    }
    mutations.get(damage, lambda: None)()
    _seal_normal_fixture(report)
    raw = json.dumps(report).encode()
    expected = "0" * 64 if damage == "wrong_hash" else sha256(raw).hexdigest()
    with pytest.raises(NativeObservationError):
        project_normal_observation(raw, sources, root=root, report_sha256=expected)


def test_detached_normal_report_cli_never_scans_and_keeps_capture_readonly(
    tmp_path, monkeypatch
):
    from scripts import precision_native_capture as capture

    root, sources, report = _normal_projection_fixture(tmp_path)
    normal = tmp_path / "normal.json"
    normal.write_text(json.dumps(report))
    manifest = tmp_path / "registered.json"
    manifest.write_text(json.dumps({"sources": sources}))
    out = tmp_path / "observation.json"
    monkeypatch.setattr(
        capture,
        "scan_capture",
        lambda *_: pytest.fail("detached projection must never execute a scan"),
    )
    args = [
        "--root",
        str(root),
        "--normal-report",
        str(normal),
        "--normal-report-sha256",
        _sha(normal),
        "--observation-manifest",
        str(manifest),
        "--out",
        str(out),
    ]
    assert capture.main(args) == 0
    assert _read(out)["raw_count"] == 2
    assert not (root / ".factory").exists()
    assert capture.main([*args[:-1], str(root / "inside.json")]) == 2
    assert (
        capture.main(
            [
                "--root",
                str(root),
                "--normal-report",
                str(normal),
                "--out",
                str(tmp_path / "bad.json"),
            ]
        )
        == 2
    )


def test_native_observation_keeps_blocked_raw_without_admission(
    tmp_path, monkeypatch, capsys
):
    from scripts import precision_native_capture

    projected = []
    original = precision_native_capture.project_paired_observation

    def project_checked(report, inventory):
        with pytest.raises(precision_native_capture.NativeObservationError) as error:
            original(report, [*inventory, inventory[0]])
        assert error.value.checks == ["source_identity"]
        invalid = {
            **report,
            "audit_coverage": {**report["audit_coverage"], "complete": False},
            "finding_conservation": {"state": "FAIL"},
        }
        with pytest.raises(precision_native_capture.NativeObservationError) as error:
            original(invalid, inventory)
        assert error.value.checks == ["coverage", "finding_conservation"]
        result = original(report, inventory)
        projected.append(result)
        return result

    monkeypatch.setattr(
        precision_native_capture, "project_paired_observation", project_checked
    )
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text(
        "def read():\n    return eval(input())\n", encoding="utf-8"
    )
    (source / "conftest.py").write_text(
        "pytest_plugins = ['external_plugin']\n", encoding="utf-8"
    )
    inventory = [
        dict(path=p.name, sha256=_sha(p), kind="python") for p in source.iterdir()
    ]
    manifest = tmp_path / "capture.json"
    manifest.write_text(json.dumps({"sources": inventory}), encoding="utf-8")
    out = tmp_path / "observation.json"
    args = ["--root", str(source), "--observation-manifest", str(manifest), "--out"]
    assert capture_main([*args, str(out)]) == 2
    result = _read(out)
    assert projected == [result]
    assert result["admission_available"] is False
    (finding,) = result["raw"]
    assert finding["identity"][:3] == ["SECURITY_DYNAMIC_EXECUTION", "app.py", 2]
    assert finding["admitted"] is None
    assert finding["source_sha256"] == _sha(source / "app.py")
    assert not (source / ".factory").exists()
    monkeypatch.setattr(
        precision_native_capture, "project_paired_observation", original
    )
    (source / "app.py").write_text("changed = 1\n", encoding="utf-8")
    rejected = tmp_path / "rejected.json"
    assert capture_main([*args, str(rejected)]) == 2
    assert not rejected.exists()
    assert json.loads(capsys.readouterr().err)["failed_checks"] == ["source_identity"]


def _fixture(tmp_path, *, limit=2):
    owner = get_ident()
    registration = tmp_path / "registration.json"
    root = Path.cwd()
    profile = {
        "schema": ranked.PROFILE,
        "files": {path: _sha(root / path) for path in ranked.TRANSPORT_FILES},
    }
    reg = {"native_transport": profile}
    registration.write_text(json.dumps(reg), encoding="utf-8")
    program = tmp_path / "worker.py"
    program.write_text(
        """import gzip, hashlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
from scripts.precision_native_capture import scan_capture
assert sys.argv[1] == 'worker'
flags = dict(zip(sys.argv[2::2], sys.argv[3::2]))
digest = lambda raw: hashlib.sha256(raw).hexdigest()
assert digest(Path(flags['--registration']).read_bytes()) == flags['--registration-sha256']
path = Path(flags['--job'])
assert digest(path.read_bytes()) == flags['--job-sha256']
job = json.loads(path.read_bytes())
profile = json.loads(Path(flags['--registration']).read_bytes())['native_transport']
assert job['native_transport_sha256'] == digest(json.dumps(profile,sort_keys=True).encode())
code, report = scan_capture(job['source_root'])
assert code in (0, 1, 2) and report['finding_conservation']['state'] == 'PASS'
report_path = path.parents[2] / 'reports' / 'v2' / (str(job['repository_id'])+'.json.gz')
report_path.parent.mkdir(parents=True, exist_ok=True)
report_path.write_bytes(gzip.compress(json.dumps(report).encode(), mtime=0))
receipt = {k: job[k] for k in ('repository_id','selection_rank','analysis_input_sha256')}
receipt.update(state='COMPLETE', job_sha256=digest(json.dumps(job,sort_keys=True).encode()),
               report_sha256=digest(report_path.read_bytes()), eligible=True)
path.with_name('native.json').write_text(json.dumps(receipt), encoding='utf-8')
""",
        encoding="utf-8",
    )
    controller = SimpleNamespace(
        __file__=program,
        read=_read,
        sha=_sha,
        digest=_digest,
        checkpoint_reusable=lambda row, job, report: row["report_sha256"]
        == _sha(report),
    )
    study = SimpleNamespace(
        root=Path.cwd(),
        out=tmp_path,
        metadata=tmp_path / "metadata",
        registration_path=registration,
        registration_sha=_sha(registration),
        reg=reg,
        deadline=monotonic() + 100,
        attempted=0,
        execution={
            "case_timeout_seconds": 30,
            "native_kill_grace_seconds": 5,
            "max_cases_per_invocation": limit,
        },
    )

    def save(path, value, *, immutable=False):
        assert get_ident() == owner
        if immutable and path.exists():
            assert _read(path) == value
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value), encoding="utf-8")

    def admit():
        assert get_ident() == owner
        assert study.attempted < limit
        study.attempted += 1

    study.save, study.admit_case = save, admit
    work = []
    for rank in (1, 2, 3):
        source = tmp_path / f"source-{rank}"
        source.mkdir()
        (source / "app.py").write_text("value = 1\n", encoding="utf-8")
        job = dict(
            repository_id=rank,
            selection_rank=rank,
            analysis_input_sha256=str(rank),
            source_root=str(source),
            native_transport_sha256=_digest(profile),
        )
        work.append((rank, ranked.RankInput(job=job)))
    return study, controller, work


def _collect(study, controller, work, extras=None):
    return ranked.ranked_native_receipts(
        study,
        controller,
        work,
        check_history=lambda: None,
        save_lookahead=lambda *row: extras.append(row) if extras is not None else None,
        last_rank=len(work),
    )


def test_registered_technical_retry_preserves_first_attempt_and_rank(
    tmp_path, monkeypatch
):
    study, controller, work = _fixture(tmp_path)
    calls = []

    def fail(command, **kwargs):
        calls.append(command)
        return 1

    monkeypatch.setattr(ranked, "run_native_command", fail)
    study.reg["technical_retry"] = {
        "schema": "factory.precision.technical-retry.v1",
        "max_retries": 1,
        "reasons": [ranked.WORKER_ERROR],
    }
    study.registration_path.write_text(json.dumps(study.reg))
    study.registration_sha = _sha(study.registration_path)
    first = list(_collect(study, controller, work[:1]))
    assert first[0][1]["reason"] == ranked.WORKER_ERROR
    assert len(calls) == 1
    study.attempted = 0
    second = list(_collect(study, controller, work[:1]))
    assert second[0][0] == 1
    assert len(calls) == 2
    archive = study.metadata / "1" / "native.attempt-1.json"
    assert _read(archive) == first[0][1]
    study.attempted = 0
    list(_collect(study, controller, work[:1]))
    assert len(calls) == 2
    assert _read(archive) == first[0][1]


def test_registered_worker_resume_reuses_success_and_charges_only_new_launch(tmp_path):
    study, controller, work = _fixture(tmp_path, limit=1)
    first = list(_collect(study, controller, work[:2]))
    assert [row["state"] for _, row in first] == ["COMPLETE", "INCOMPLETE"]
    assert first[1][1]["reason"] == ranked.DEFERRED
    assert study.attempted == 1
    study.attempted = 0
    second = list(_collect(study, controller, work[:2]))
    assert second[0] == first[0]
    assert second[1][1]["state"] == "COMPLETE"
    assert study.attempted == 1
    assert not list(tmp_path.glob("source-*/.factory"))


def test_dispatched_lookahead_is_recorded_outside_prefix(tmp_path, monkeypatch):
    study, controller, work = _fixture(tmp_path)
    second_started, stop = Event(), Event()

    def native(command, **kwargs):
        case = Path(command[-3]).parent.name
        if case == "1":
            assert second_started.wait(5)
        else:
            assert case == "2"
            second_started.set()
            assert stop.wait(5)
        return 1

    monkeypatch.setattr(ranked, "run_native_command", native)
    extras = []
    with closing(_collect(study, controller, work, extras)) as results:
        rank, first = next(results)
        assert rank == 1 and first["reason"] == ranked.WORKER_ERROR
        stop.set()
    assert [(rank, row["reason"]) for rank, row, _ in extras] == [
        (2, ranked.WORKER_ERROR)
    ]
    assert not (study.metadata / "3/job.json").exists()
    assert study.attempted == 2


def test_shared_source_commit_holds_report_budget_lock():
    events = []

    @contextmanager
    def lock():
        events.append("lock")
        yield
        events.append("unlock")

    def write(path, raw):
        assert events == ["lock"]
        events.append((path, raw))

    ranked.shared_source_commit(SimpleNamespace(io_lock=lock), write, "x", b"a")
    assert events == ["lock", ("x", b"a"), "unlock"]


def test_preserves_attempt_if_command_defers_before_spawn(tmp_path, monkeypatch):
    study, controller, work = _fixture(tmp_path)

    def defer(*_args, **_kwargs):
        raise TimeoutError(ranked.DEFERRED)

    monkeypatch.setattr(ranked, "run_native_command", defer)
    [(_, receipt)] = list(_collect(study, controller, work[:1]))
    assert receipt["reason"] == ranked.DEFERRED
    assert study.attempted == 0


def test_worker_timeout_records_the_failed_check(tmp_path, monkeypatch):
    study, controller, work = _fixture(tmp_path)

    def timeout(command, **_options):
        raise ranked.subprocess.TimeoutExpired(command, 1)

    monkeypatch.setattr(ranked, "run_native_command", timeout)
    [(_, receipt)] = list(_collect(study, controller, work[:1]))
    assert receipt["reason"] == ranked.WORKER_ERROR
    assert receipt["failed_checks"] == ["timeout"]
    assert study.attempted == 1


def test_unconfirmed_lookahead_termination_prevents_seal(tmp_path, monkeypatch):
    study, controller, work = _fixture(tmp_path)
    second_started, stop = Event(), Event()

    def native(command, **kwargs):
        if Path(command[-3]).parent.name == "1":
            assert second_started.wait(5)
            return 1
        second_started.set()
        assert stop.wait(5)
        raise RuntimeError("NATIVE_REAP_FAILED")

    monkeypatch.setattr(ranked, "run_native_command", native)
    with pytest.raises(RuntimeError, match="NATIVE_REAP_FAILED"):
        with closing(_collect(study, controller, work)) as results:
            assert next(results)[0] == 1
            stop.set()


@pytest.mark.parametrize("mutation", ["registration", "job"])
def test_wrong_transport_hash_never_charges_a_launch(tmp_path, mutation):
    study, controller, work = _fixture(tmp_path)
    if mutation == "registration":
        profile = study.reg["native_transport"]
        profile["files"]["scripts/precision_native_capture.py"] = "0" * 64
    else:
        work[0][1].job["native_transport_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="NATIVE_.*TRANSPORT_.*CHANGED"):
        list(_collect(study, controller, work[:1]))
    assert study.attempted == 0


def test_verify_registered_transport_rejects_stale_worker_hash():
    root = Path(ranked.__file__).resolve().parents[1]
    files = {path: _sha(root / path) for path in ranked.TRANSPORT_FILES}
    profile = {"schema": ranked.PROFILE, "files": files}
    ranked.verify_registered_transport(root, profile, _sha)

    files["scripts/precision_native_capture.py"] = "0" * 64
    with pytest.raises(ValueError, match="NATIVE_TRANSPORT_SOURCE_CHANGED"):
        ranked.verify_registered_transport(root, profile, _sha)
