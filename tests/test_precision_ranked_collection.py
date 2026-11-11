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


def _read(path):
    return json.loads(path.read_bytes())


def _sha(path):
    return sha256(path.read_bytes()).hexdigest()


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


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
