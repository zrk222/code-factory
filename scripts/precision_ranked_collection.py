"""Owner-side receipt and quota handoff for registered ranked native workers."""

from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys
from threading import Lock
from time import monotonic

from scripts.precision_ranked_execution import (
    ordered_native_results,
    run_native_command,
)

DEFERRED = "INVOCATION_LIMIT_NO_NATIVE_LAUNCH"
WORKER_ERROR = "NATIVE_TIMEOUT_OR_WORKER_ERROR"
PROFILE = "factory.precision.ranked-read-only.v1"
TRANSPORT_FILES = frozenset(
    {
        "scripts/precision_ranked_collection.py",
        "scripts/precision_ranked_execution.py",
        "scripts/precision_native_capture.py",
    }
)


@dataclass(frozen=True)
class RankInput:
    job: dict | None = None
    receipt: dict | None = None


@dataclass(frozen=True)
class Launch:
    rank: int
    job: dict
    result_path: Path
    report_path: Path
    command: tuple[str, ...]


def shared_source_commit(study, write_source, path, raw):
    """Share the existing disk-reserve lock with report and metadata writers."""
    with study.io_lock():
        return write_source(path, raw)


def verify_registered_transport(root, profile, sha):
    """Bind scheduler, dispatch, and read-only worker bytes before scheduling."""
    if not isinstance(profile, dict) or profile.get("schema") != PROFILE:
        raise ValueError("NATIVE_TRANSPORT_NOT_REGISTERED")
    files = profile.get("files")
    if not isinstance(files, dict) or set(files) != TRANSPORT_FILES:
        raise ValueError("NATIVE_TRANSPORT_FILES_CHANGED")
    root = Path(root).resolve()
    if (
        Path(__file__).resolve() != root / "scripts/precision_ranked_collection.py"
        or Path(sys.modules[ordered_native_results.__module__].__file__).resolve()
        != root / "scripts/precision_ranked_execution.py"
    ):
        raise ValueError("NATIVE_TRANSPORT_IMPORT_CHANGED")
    for relative, expected in files.items():
        path = root / relative
        if path.resolve() != path or sha(path) != expected:
            raise ValueError("NATIVE_TRANSPORT_SOURCE_CHANGED")


def _incomplete(controller, job, reason):
    return {
        "job_sha256": controller.digest(job),
        "analysis_input_sha256": job["analysis_input_sha256"],
        "repository_id": job["repository_id"],
        "selection_rank": job["selection_rank"],
        "state": "INCOMPLETE",
        "eligible": False,
        "admitted": [],
        "raw_findings": None,
        "reason": reason,
    }


def _validate_receipt(controller, job, row, report_path):
    if not isinstance(row, dict):
        raise ValueError("NATIVE_RECEIPT_INVALID")
    expected = _incomplete(controller, job, WORKER_ERROR)
    for key in (
        "job_sha256",
        "analysis_input_sha256",
        "repository_id",
        "selection_rank",
    ):
        if row.get(key) != expected[key]:
            raise ValueError("NATIVE_RECEIPT_BINDING_CHANGED")
    if row.get("state") == "COMPLETE":
        if not controller.checkpoint_reusable(row, job, report_path):
            raise ValueError("NATIVE_REPORT_BINDING_CHANGED")
    elif not (
        row.get("state") == "INCOMPLETE"
        and row.get("eligible") is False
        and row.get("raw_findings", ()) is None
        and row.get("admitted") == []
    ):
        raise ValueError("NATIVE_INCOMPLETE_RECEIPT_INVALID")
    return row


class _RegisteredDispatch:
    def __init__(self, study, controller, check_history):
        self.study = study
        self.controller = controller
        self.check_history = check_history
        profile = study.reg.get("native_transport")
        verify_registered_transport(study.root, profile, controller.sha)
        self.transport_sha = controller.digest(profile)
        self.finished = {}
        self.failed_reaps = set()
        self.lock = Lock()

    def reserve(self, rank, item):
        if item.job is None:
            if item.receipt is None or item.receipt.get("selection_rank") != rank:
                raise ValueError("NATIVE_RECEIPT_RANK_CHANGED")
            return item.receipt
        job = item.job
        if item.receipt is not None or job.get("selection_rank") != rank:
            raise ValueError("NATIVE_JOB_RANK_CHANGED")
        if job.get("native_transport_sha256") != self.transport_sha:
            raise ValueError("NATIVE_JOB_TRANSPORT_CHANGED")
        study, controller = self.study, self.controller
        self.check_history()
        case = str(job["repository_id"])
        path = study.metadata / case / "job.json"
        result = path.with_name("native.json")
        report = study.out / "reports" / "v2" / (case + ".json.gz")
        study.save(path, job, immutable=True)
        if result.is_file():
            prior = _validate_receipt(controller, job, controller.read(result), report)
            if prior.get("reason") != DEFERRED and not self._retry_technical(
                job, prior, result
            ):
                return prior
        if (
            monotonic() + study.execution["case_timeout_seconds"] > study.deadline
            or study.attempted >= study.execution["max_cases_per_invocation"]
        ):
            deferred = _incomplete(controller, job, DEFERRED)
            study.save(result, deferred)
            return deferred
        command = (
            sys.executable,
            "-B",
            str(Path(controller.__file__).resolve()),
            "worker",
            "--registration",
            str(study.registration_path),
            "--registration-sha256",
            study.registration_sha,
            "--job",
            str(path),
            "--job-sha256",
            controller.sha(path),
        )
        study.admit_case()
        return Launch(rank, job, result, report, command)

    def _retry_technical(self, job, prior, result):
        """Only a sealed opt-in policy may retry a transport failure once."""
        policy = self.study.reg.get("technical_retry")
        expected = {
            "schema": "factory.precision.technical-retry.v1",
            "max_retries": 1,
            "reasons": [WORKER_ERROR],
        }
        if policy is None:
            return False
        if policy != expected:
            raise ValueError("NATIVE_RETRY_POLICY_INVALID")
        if (
            self.controller.sha(self.study.registration_path)
            != self.study.registration_sha
        ):
            raise ValueError("NATIVE_RETRY_REGISTRATION_CHANGED")
        registered = self.controller.read(self.study.registration_path)
        if registered.get("technical_retry") != policy:
            raise ValueError("NATIVE_RETRY_REGISTRATION_CHANGED")
        if prior.get("reason") != WORKER_ERROR or prior.get("state") != "INCOMPLETE":
            return False
        if (
            monotonic() + self.study.execution["case_timeout_seconds"]
            > self.study.deadline
        ):
            return False
        if self.study.attempted >= self.study.execution["max_cases_per_invocation"]:
            return False
        attempt = result.with_name("native.attempt-1.json")
        if attempt.exists():
            _validate_receipt(
                self.controller, job, self.controller.read(attempt), result
            )
            return False
        self.study.save(attempt, prior, immutable=True)
        return True

    def invoke(self, work):
        if not isinstance(work, Launch):
            return work
        study = self.study
        try:
            code = run_native_command(
                work.command,
                cwd=study.root,
                deadline=study.deadline,
                timeout=study.execution["case_timeout_seconds"],
                kill_grace=study.execution["native_kill_grace_seconds"],
            )
            outcome = None if code == 0 and work.result_path.is_file() else WORKER_ERROR
        except TimeoutError:
            outcome = DEFERRED
        except (OSError, subprocess.TimeoutExpired):
            outcome = WORKER_ERROR
        except RuntimeError:
            with self.lock:
                self.failed_reaps.add(work.rank)
            raise
        with self.lock:
            self.finished[work.rank] = (work, outcome)
        return work

    def settle(self, work):
        if not isinstance(work, Launch):
            return work
        with self.lock:
            _, outcome = self.finished.pop(work.rank)
        controller, study = self.controller, self.study
        if outcome is not None:
            if outcome == DEFERRED:
                study.attempted -= 1
            row = _incomplete(controller, work.job, outcome)
            study.save(work.result_path, row)
            return row
        row = controller.read(work.result_path)
        if row.get("reason") == DEFERRED:
            raise ValueError("NATIVE_WORKER_RETURNED_PRELAUNCH_RECEIPT")
        return _validate_receipt(controller, work.job, row, work.report_path)


def ranked_native_receipts(
    study, controller, prepared, *, check_history, save_lookahead, last_rank=None
):
    """Yield only the contiguous prefix; persist any drained launches separately."""
    owner = _RegisteredDispatch(study, controller, check_history)
    try:
        with closing(
            ordered_native_results(
                prepared,
                owner.invoke,
                last_rank=last_rank,
                before_dispatch=owner.reserve,
            )
        ) as results:
            for rank, work in results:
                yield rank, owner.settle(work)
    finally:
        if owner.failed_reaps:
            raise RuntimeError("NATIVE_REAP_FAILED")
        for rank, (work, _) in sorted(owner.finished.items()):
            row = owner.settle(work)
            save_lookahead(rank, row, controller.sha(work.result_path))
        check_history()
        verify_registered_transport(
            study.root, study.reg["native_transport"], controller.sha
        )
