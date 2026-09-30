"""Sigstore identity signatures for existing factory receipt files."""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
import json
import hashlib
import os
import platform
import re
import time
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Sequence


RESULT_SCHEMA = "factory.sigstore.result.v1"
DEFAULT_TIMEOUT_SECONDS = 300
CI_RECEIPT_SCHEMA = "factory.receipt.ci.v1"
CI_CHECK_SCHEMA = "factory.receipt.ci.check.v1"
CI_COMMANDS = (
    ("tests", ("python", "-m", "pytest", "-n", "2", "-q", "--junitxml=ci-tests.xml")),
    (
        "architecture",
        (
            "python",
            "-m",
            "factoryline.cli",
            "architecture",
            "health",
            "--root",
            ".",
            "--json",
        ),
    ),
    ("quality", ("forge", "qa", "--repo-wide", "--root", ".", "--strict")),
    (
        "scanner_controls",
        ("python", "-m", "factoryline.cli", "audit", "evals", "--json"),
    ),
)


def _ci_identity(root: Path) -> dict:
    env = os.environ
    if (
        env.get("GITHUB_ACTIONS") != "true"
        or env.get("GITHUB_REF") != "refs/heads/main"
    ):
        raise SignedReceiptError(
            "E_CI_IDENTITY", "release receipts require protected-main GitHub Actions"
        )
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    if not re.fullmatch(r"[a-f0-9]{40}", head) or env.get("GITHUB_SHA") != head:
        raise SignedReceiptError(
            "E_CI_IDENTITY", "checkout and Actions commit must match"
        )
    required = ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "RUNNER_OS")
    if any(not env.get(key) for key in required):
        raise SignedReceiptError("E_CI_IDENTITY", "runner identity is incomplete")
    return {
        "commit": head,
        "repository": env["GITHUB_REPOSITORY"],
        "run_id": env["GITHUB_RUN_ID"],
        "run_attempt": env["GITHUB_RUN_ATTEMPT"],
        "ref": env["GITHUB_REF"],
        "runner_os": env["RUNNER_OS"],
    }


def _ci_pristine(root: Path) -> None:
    tree = subprocess.check_output(
        ["git", "ls-tree", "-rz", "HEAD"],
        cwd=root,
        timeout=15,
    )
    if any(
        not _ci_tree_entry_matches(root, entry) for entry in tree.split(b"\0") if entry
    ):
        raise SignedReceiptError(
            "E_CI_SOURCE_CHANGED", "checkout bytes differ from committed tree"
        )


def _ci_tree_entry_matches(root: Path, entry: bytes) -> bool:
    metadata, relative = entry.split(b"\t", 1)
    mode, kind, oid = metadata.split()
    path = root / os.fsdecode(relative)
    try:
        if kind != b"blob":
            return False
        content = (
            os.fsencode(os.readlink(path)) if mode == b"120000" else path.read_bytes()
        )
        algorithm = "sha1" if len(oid) == 40 else "sha256"
        digest = hashlib.new(algorithm, usedforsecurity=False)
        digest.update(b"blob " + str(len(content)).encode("ascii") + b"\0" + content)
        return digest.hexdigest().encode("ascii") == oid
    except OSError:
        return False


def _ci_run(root: Path, name: str, argv: tuple[str, ...]) -> dict:
    _ci_pristine(root)
    started = time.monotonic()
    process = subprocess.run(
        list(argv), cwd=root, capture_output=True, text=True, timeout=1200, check=False
    )
    _ci_pristine(root)
    log = (process.stdout + "\n" + process.stderr).encode("utf-8")
    (root / f"ci-{name}.log").write_bytes(log)
    return {
        "name": name,
        "argv": list(argv),
        "exit_code": process.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "log_sha256": hashlib.sha256(log).hexdigest(),
    }


def produce_ci_receipt(root: Path, output: Path, check_name: str | None = None) -> dict:
    """Run one fixed check per isolated Actions job; require CI attestation."""
    root = Path(root).resolve()
    identity = _ci_identity(root)
    checks = dict(CI_COMMANDS)
    if check_name not in checks:
        raise SignedReceiptError(
            "E_CI_CHECK", "exactly one named check is required per runner"
        )
    _ci_pristine(root)
    commands = [_ci_run(root, check_name, checks[check_name])]
    passed = all(item["exit_code"] == 0 for item in commands)
    payload = {
        "schema": CI_CHECK_SCHEMA,
        "ok": passed,
        "identity": identity,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "environment": {"python": sys.version, "platform": platform.platform()},
        "commands": commands,
        "authority": "none",
        "signature_status": "requires_verified_ci_attestation",
    }
    packages = subprocess.check_output(
        [sys.executable, "-m", "pip", "freeze"], text=True
    )
    payload["dependencies"] = packages.splitlines()
    junit = root / "ci-tests.xml"
    payload["junit_sha256"] = (
        hashlib.sha256(junit.read_bytes()).hexdigest() if junit.is_file() else None
    )
    _ci_pristine(root)
    if _ci_identity(root) != identity:
        raise SignedReceiptError(
            "E_CI_IDENTITY", "runner identity changed during checks"
        )
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return payload


def combine_ci_receipts(root: Path, directory: Path, output: Path) -> dict:
    """Combine check receipts after the workflow verifies every attestation."""
    identity = _ci_identity(root)
    _ci_pristine(root)
    receipts = [
        _ci_check_receipt(directory / f"ci-{name}.json", identity, name, argv)
        for name, argv in CI_COMMANDS
    ]
    payload = {
        "schema": CI_RECEIPT_SCHEMA,
        "ok": True,
        "identity": identity,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "commands": [r["commands"][0] for r in receipts],
        "environment": {
            name: r["environment"] for (name, _), r in zip(CI_COMMANDS, receipts)
        },
        "dependencies": {
            name: r["dependencies"] for (name, _), r in zip(CI_COMMANDS, receipts)
        },
        "junit_sha256": receipts[0]["junit_sha256"],
        "check_receipt_sha256": {
            name: hashlib.sha256(
                (directory / f"ci-{name}.json").read_bytes()
            ).hexdigest()
            for name, _ in CI_COMMANDS
        },
        "authority": "none",
        "signature_status": "requires_verified_ci_attestation",
    }
    validate_ci_payload(payload, identity["commit"])
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return payload


def _ci_check_receipt(
    path: Path, identity: dict, name: str, argv: tuple[str, ...]
) -> dict:
    receipt = validate_receipt(path)
    commands = receipt.get("commands", [])
    if (
        receipt.get("schema") != CI_CHECK_SCHEMA
        or receipt.get("ok") is not True
        or receipt.get("identity") != identity
        or len(commands) != 1
    ):
        raise SignedReceiptError(
            "E_CI_RECEIPT", "check receipt identity or result is invalid"
        )
    command = commands[0]
    if (
        command.get("name") != name
        or command.get("argv") != list(argv)
        or command.get("exit_code") != 0
    ):
        raise SignedReceiptError(
            "E_CI_RECEIPT", "check command does not match its fixed contract"
        )
    return receipt


def validate_ci_receipt(path: Path, commit: str) -> dict:
    """Check exact executed-command and commit bindings after attestation verification."""
    payload = validate_receipt(path)
    return validate_ci_payload(payload, commit)


def validate_ci_payload(payload: dict, commit: str) -> dict:
    """Validate the exact source and fixed-command bindings of an aggregate."""
    identity = payload.get("identity", {})
    commands = payload.get("commands", [])
    actual = [(item.get("name"), tuple(item.get("argv", []))) for item in commands]
    if (
        payload.get("schema") != CI_RECEIPT_SCHEMA
        or payload.get("ok") is not True
        or identity.get("commit") != commit
        or identity.get("ref") != "refs/heads/main"
        or actual != list(CI_COMMANDS)
        or not payload.get("junit_sha256")
        or any(item.get("exit_code") != 0 for item in commands)
    ):
        raise SignedReceiptError(
            "E_CI_RECEIPT", "missing, failed, or candidate-mismatched CI evidence"
        )
    return payload


def ci_receipt_main(argv: Sequence[str] | None = None) -> int:
    """Generate CI-only evidence or validate a receipt already verified cryptographically."""
    values = list(sys.argv[1:] if argv is None else argv)
    routes = {
        "verify-ci": (3, _ci_verify_main),
        "run-ci": (2, _ci_generate_main),
        "combine-ci": (2, _ci_combine_main),
        "fetch-ci": (3, _ci_fetch_main),
    }
    route = routes.get(values[0]) if values else None
    if route is None or len(values) != route[0]:
        raise SignedReceiptError(
            "E_CI_RECEIPT", "invalid CI receipt command or arguments"
        )
    return route[1](values)


def _ci_verify_main(values: list[str]) -> int:
    validate_ci_receipt(Path(values[1]), values[2])
    return 0


def _ci_generate_main(values: list[str]) -> int:
    output = Path(f"ci-{values[1]}.json")
    return 0 if produce_ci_receipt(Path.cwd(), output, values[1])["ok"] else 1


def _ci_combine_main(values: list[str]) -> int:
    combine_ci_receipts(Path.cwd(), Path(values[1]), Path("ci-receipt.json"))
    return 0


def _ci_fetch_main(values: list[str]) -> int:
    fetch_ci_receipt(values[1], Path(values[2]))
    return 0


def fetch_ci_receipt(commit: str, output: Path) -> dict:
    """Fetch and verify protected-main CI evidence for exactly one release candidate."""
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or not re.fullmatch(
        r"[\w.-]+/[\w.-]+", repository
    ):
        raise SignedReceiptError(
            "E_CI_RECEIPT", "candidate or repository identity is invalid"
        )
    runs = json.loads(
        subprocess.check_output(
            [
                "gh",
                "run",
                "list",
                "--repo",
                repository,
                "--workflow",
                "signed-receipts.yml",
                "--commit",
                commit,
                "--branch",
                "main",
                "--status",
                "success",
                "--limit",
                "1",
                "--json",
                "databaseId,headSha,event",
            ],
            text=True,
            timeout=30,
        )
    )
    if not runs or runs[0].get("headSha") != commit:
        raise SignedReceiptError(
            "E_CI_RECEIPT", "no successful clean-main receipt for this candidate"
        )
    run_id = str(runs[0]["databaseId"])
    output.mkdir(parents=True, exist_ok=False)
    subprocess.run(
        [
            "gh",
            "run",
            "download",
            run_id,
            "--repo",
            repository,
            "--name",
            "signed-factory-receipt",
            "--dir",
            str(output),
        ],
        check=True,
        timeout=120,
    )
    path = output / "ci-receipt.json"
    subprocess.run(
        [
            "gh",
            "attestation",
            "verify",
            str(path),
            "--repo",
            repository,
            "--signer-workflow",
            f"{repository}/.github/workflows/signed-receipts.yml",
            "--source-digest",
            commit,
            "--source-ref",
            "refs/heads/main",
            "--deny-self-hosted-runners",
        ],
        check=True,
        timeout=120,
    )
    payload = validate_ci_receipt(path, commit)
    if (
        payload["identity"].get("repository") != repository
        or payload["identity"].get("run_id") != run_id
    ):
        raise SignedReceiptError(
            "E_CI_RECEIPT", "receipt must bind the selected repository and CI run"
        )
    return payload


class SignedReceiptError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class SigstoreResult:
    receipt_path: str
    bundle_path: str
    verdict: str
    expected_identity: str | None = None
    expected_issuer: str | None = None
    verification_method: str | None = None
    schema: str = RESULT_SCHEMA

    def to_dict(self) -> dict:
        """Return the Sigstore operation result as a stable serializable dictionary."""
        return {
            "schema": self.schema,
            "receipt_path": self.receipt_path,
            "bundle_path": self.bundle_path,
            "expected_identity": self.expected_identity,
            "expected_issuer": self.expected_issuer,
            "verification_method": self.verification_method,
            "verdict": self.verdict,
        }


def bundle_path_for(receipt_path: Path) -> Path:
    """Return the conventional Sigstore bundle path for a receipt file."""
    return Path(f"{Path(receipt_path)}.sigstore.json")


def validate_receipt(receipt_path: Path) -> dict:
    """Validate receipt structure or raise SignedReceiptError with a stable code."""
    path = Path(receipt_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SignedReceiptError("E_INVALID_RECEIPT", str(exc)) from exc
    if not isinstance(payload, dict):
        raise SignedReceiptError("E_INVALID_RECEIPT", "receipt must be a JSON object")
    schema = payload.get("schema")
    if not isinstance(schema, str) or not schema.startswith("factory.receipt."):
        raise SignedReceiptError(
            "E_INVALID_RECEIPT", "receipt schema must begin with factory.receipt."
        )
    return payload


def resolve_sigstore_command(command: Sequence[str] | None = None) -> list[str]:
    """Resolve a safe Sigstore argv prefix or raise SignedReceiptError if unavailable."""
    if command:
        return list(command)
    executable = shutil.which("sigstore")
    if executable:
        return [executable]
    if importlib.util.find_spec("sigstore") is not None:
        return [sys.executable, "-m", "sigstore"]
    raise SignedReceiptError(
        "E_SIGSTORE_UNAVAILABLE",
        "install with: pip install factoryline-code-factory[sigstore]",
    )


def _run(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SignedReceiptError("E_SIGNING_FAILED", str(exc)) from exc


def receipt_status(receipt_path: Path) -> SigstoreResult:
    """Report whether a receipt and its detached Sigstore bundle are present."""
    validate_receipt(receipt_path)
    receipt_path = Path(receipt_path).resolve()
    bundle_path = bundle_path_for(receipt_path)
    verdict = "SIGNATURE_PRESENT_UNVERIFIED" if bundle_path.is_file() else "UNSIGNED"
    return SigstoreResult(str(receipt_path), str(bundle_path), verdict)


def sign_receipt(
    receipt_path: Path,
    *,
    command: Sequence[str] | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    overwrite: bool = False,
) -> SigstoreResult:
    """Sign one validated receipt or raise SignedReceiptError on any tool failure."""
    validate_receipt(receipt_path)
    receipt_path = Path(receipt_path).resolve()
    bundle_path = bundle_path_for(receipt_path)
    if bundle_path.exists():
        if not overwrite:
            raise SignedReceiptError(
                "E_SIGNING_FAILED", f"bundle already exists: {bundle_path}"
            )
        bundle_path.unlink()
    proc = _run(
        resolve_sigstore_command(command) + ["sign", str(receipt_path)], timeout=timeout
    )
    if proc.returncode != 0 or not bundle_path.is_file():
        diagnostic = (
            proc.stderr or proc.stdout or "Sigstore produced no bundle"
        ).strip()
        raise SignedReceiptError("E_SIGNING_FAILED", diagnostic)
    return SigstoreResult(str(receipt_path), str(bundle_path), "SIGNED")


def verify_receipt(
    receipt_path: Path,
    *,
    cert_identity: str,
    cert_oidc_issuer: str,
    command: Sequence[str] | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> SigstoreResult:
    """Verify a receipt bundle and exact identity or raise SignedReceiptError."""
    validate_receipt(receipt_path)
    if not cert_identity.strip() or not cert_oidc_issuer.strip():
        raise SignedReceiptError(
            "E_IDENTITY_REQUIRED",
            "expected certificate identity and OIDC issuer are required",
        )
    receipt_path = Path(receipt_path).resolve()
    bundle_path = bundle_path_for(receipt_path)
    if not bundle_path.is_file():
        return SigstoreResult(str(receipt_path), str(bundle_path), "UNSIGNED")
    args = resolve_sigstore_command(command) + [
        "verify",
        "identity",
        str(receipt_path),
        "--cert-identity",
        cert_identity,
        "--cert-oidc-issuer",
        cert_oidc_issuer,
    ]
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SignedReceiptError("E_VERIFICATION_FAILED", str(exc)) from exc
    if proc.returncode != 0:
        diagnostic = (
            proc.stderr or proc.stdout or "Sigstore verification failed"
        ).strip()
        raise SignedReceiptError("E_VERIFICATION_FAILED", diagnostic)
    return SigstoreResult(
        str(receipt_path),
        str(bundle_path),
        "SIGSTORE_IDENTITY_VERIFIED",
        expected_identity=cert_identity,
        expected_issuer=cert_oidc_issuer,
        verification_method="sigstore_identity",
    )


if __name__ == "__main__":
    raise SystemExit(ci_receipt_main())
