"""Sigstore identity signatures for existing factory receipt files."""
from __future__ import annotations

from dataclasses import dataclass
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Sequence


RESULT_SCHEMA = "factory.sigstore.result.v1"
DEFAULT_TIMEOUT_SECONDS = 300


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
    return Path(f"{Path(receipt_path)}.sigstore.json")


def validate_receipt(receipt_path: Path) -> dict:
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
    validate_receipt(receipt_path)
    receipt_path = Path(receipt_path).resolve()
    bundle_path = bundle_path_for(receipt_path)
    if bundle_path.exists():
        if not overwrite:
            raise SignedReceiptError(
                "E_SIGNING_FAILED", f"bundle already exists: {bundle_path}"
            )
        bundle_path.unlink()
    proc = _run(resolve_sigstore_command(command) + ["sign", str(receipt_path)], timeout=timeout)
    if proc.returncode != 0 or not bundle_path.is_file():
        diagnostic = (proc.stderr or proc.stdout or "Sigstore produced no bundle").strip()
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
        diagnostic = (proc.stderr or proc.stdout or "Sigstore verification failed").strip()
        raise SignedReceiptError("E_VERIFICATION_FAILED", diagnostic)
    return SigstoreResult(
        str(receipt_path),
        str(bundle_path),
        "SIGSTORE_IDENTITY_VERIFIED",
        expected_identity=cert_identity,
        expected_issuer=cert_oidc_issuer,
        verification_method="sigstore_identity",
    )
