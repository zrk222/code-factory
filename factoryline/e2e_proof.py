"""Native, proof-by-sabotage E2E command-pair verification.

The E2E Proof Gate intentionally does not implement a browser, call a hosted
test vendor, or infer that a green test establishes production readiness.  It
runs an explicit, human-approved local command pair: a positive check expected
to exit zero and a negative mutation expected to exit non-zero.  The resulting
receipt binds only the commands, captured output digests, and declared local
artifacts supplied for that run.
"""
from __future__ import annotations

from base64 import b64decode, b64encode
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
from time import perf_counter_ns
from typing import Any


E2E_PROOF_MANIFEST_SCHEMA = "factory.e2e_proof_manifest.v1"
E2E_PROOF_RECEIPT_SCHEMA = "factory.e2e_proof_receipt.v1"
MAX_TIMEOUT_SECONDS = 900
MAX_ARGV_ITEMS = 64
MAX_ARGV_ITEM_CHARS = 4096
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")

AUTHORITY = {
    "execution": True,
    "test_execution": True,
    "approval": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
    "source_write": False,
    "repair": False,
}


class E2EProofError(ValueError):
    """A malformed manifest or tampered E2E Proof receipt."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _sha(value: object) -> str:
    return _sha_bytes(_canonical(value))


def _reject(code: str, message: str) -> None:
    raise E2EProofError(code, message)


def _workspace_path(root: Path, value: object, field: str, *, directory: bool = False) -> Path:
    if not isinstance(value, str) or not value.strip():
        _reject("E2E_MANIFEST_INVALID", f"{field} must be a non-empty workspace-relative path")
    raw = value.replace("\\", "/").strip()
    if raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw) or any(part == ".." for part in raw.split("/")):
        _reject("E2E_MANIFEST_INVALID", f"{field} must stay inside the workspace")
    resolved = (root / raw).resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        _reject("E2E_MANIFEST_INVALID", f"{field} resolves outside the workspace")
    if directory and not resolved.is_dir():
        _reject("E2E_MANIFEST_INVALID", f"{field} must name an existing workspace directory")
    return resolved


def _relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root).as_posix()


def _text(value: object, field: str, *, pattern: re.Pattern[str] | None = None, limit: int = 128) -> str:
    if not isinstance(value, str) or not value.strip():
        _reject("E2E_MANIFEST_INVALID", f"{field} must be a non-empty string")
    result = value.strip()
    if len(result) > limit:
        _reject("E2E_MANIFEST_INVALID", f"{field} must be at most {limit} characters")
    if pattern and not pattern.fullmatch(result):
        _reject("E2E_MANIFEST_INVALID", f"{field} has an unsupported format")
    return result


def _argv(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_ARGV_ITEMS:
        _reject("E2E_MANIFEST_INVALID", f"{field} must contain 1 through {MAX_ARGV_ITEMS} argv items")
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item or "\x00" in item or len(item) > MAX_ARGV_ITEM_CHARS:
            _reject("E2E_MANIFEST_INVALID", f"{field}[{index}] must be a non-empty argv string of at most {MAX_ARGV_ITEM_CHARS} characters")
        result.append(item)
    return result


def _load_manifest(root: Path, manifest_path: Path) -> tuple[dict[str, Any], Path, str]:
    candidate = Path(manifest_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        _reject("E2E_MANIFEST_INVALID", "manifest path must stay inside the workspace")
    if not candidate.is_file():
        _reject("E2E_MANIFEST_INVALID", "manifest path must name a readable JSON file")
    raw = candidate.read_bytes()
    try:
        source = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _reject("E2E_MANIFEST_INVALID", f"manifest cannot be decoded as JSON: {exc}")
    if not isinstance(source, dict):
        _reject("E2E_MANIFEST_INVALID", "manifest must contain one JSON object")
    return source, candidate, _sha_bytes(raw)


def _validate_manifest_shape(source: dict[str, Any]) -> None:
    allowed = {
        "schema", "id", "approval", "working_directory", "timeout_seconds",
        "network_egress", "positive", "negative", "artifact_paths",
    }
    if set(source) != allowed:
        _reject("E2E_MANIFEST_INVALID", "manifest must contain exactly schema, id, approval, working_directory, timeout_seconds, network_egress, positive, negative, and artifact_paths")
    if source.get("schema") != E2E_PROOF_MANIFEST_SCHEMA:
        _reject("E2E_MANIFEST_INVALID", f"schema must be {E2E_PROOF_MANIFEST_SCHEMA}")


def _validate_approval(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"state", "approved_by"}:
        _reject("E2E_MANIFEST_INVALID", "approval must contain exactly state and approved_by")
    if value.get("state") != "approved":
        _reject("E2E_MANIFEST_UNAPPROVED", "approval.state must be approved before commands can run")
    return {"state": "approved", "approved_by": _text(value.get("approved_by"), "approval.approved_by")}


def _validate_timeout(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_TIMEOUT_SECONDS:
        _reject("E2E_MANIFEST_INVALID", f"timeout_seconds must be an integer from 1 through {MAX_TIMEOUT_SECONDS}")
    return value


def _validate_commands(source: dict[str, Any]) -> dict[str, dict[str, list[str]]]:
    commands: dict[str, dict[str, list[str]]] = {}
    for name in ("positive", "negative"):
        command = source.get(name)
        if not isinstance(command, dict) or set(command) != {"argv"}:
            _reject("E2E_MANIFEST_INVALID", f"{name} must contain exactly argv")
        commands[name] = {"argv": _argv(command.get("argv"), f"{name}.argv")}
    return commands


def _validate_artifact_paths(root: Path, value: object) -> list[str]:
    if not isinstance(value, list):
        _reject("E2E_MANIFEST_INVALID", "artifact_paths must be an array")
    relative_paths = [_relative(root, _workspace_path(root, item, "artifact_paths")) for item in value]
    if len(relative_paths) != len(set(relative_paths)):
        _reject("E2E_MANIFEST_INVALID", "artifact_paths must not contain duplicates")
    return relative_paths


def validate_e2e_proof_manifest(root: Path, manifest_path: Path) -> dict[str, Any]:
    """Validate one approved, local-only E2E proof command-pair manifest."""
    workspace = Path(root).resolve()
    source, path, manifest_sha256 = _load_manifest(workspace, manifest_path)
    _validate_manifest_shape(source)
    approval = _validate_approval(source.get("approval"))
    working_directory = _workspace_path(workspace, source.get("working_directory"), "working_directory", directory=True)
    if source.get("network_egress") != "not_granted":
        _reject("E2E_EGRESS_NOT_GRANTED", "network_egress must be not_granted; this runner cannot enforce host egress")
    return {
        "schema": E2E_PROOF_MANIFEST_SCHEMA,
        "id": _text(source.get("id"), "id", pattern=_IDENTIFIER),
        "approval": approval,
        "working_directory": _relative(workspace, working_directory),
        "timeout_seconds": _validate_timeout(source.get("timeout_seconds")),
        "network_egress": "not_granted",
        **_validate_commands(source),
        "artifact_paths": _validate_artifact_paths(workspace, source.get("artifact_paths")),
        "manifest_path": _relative(workspace, path),
        "manifest_sha256": manifest_sha256,
    }


def _capture(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    return value.encode("utf-8", errors="replace") if isinstance(value, str) else value


def _run_command(argv: list[str], *, cwd: Path, timeout_seconds: int) -> tuple[dict[str, Any], dict[str, str]]:
    started = perf_counter_ns()
    try:
        completed = subprocess.run(argv, cwd=str(cwd), shell=False, capture_output=True, timeout=timeout_seconds, check=False)
        stdout, stderr = _capture(completed.stdout), _capture(completed.stderr)
        status = "completed"
        exit_code: int | None = completed.returncode
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = _capture(exc.stdout), _capture(exc.stderr)
        status, exit_code = "timed_out", None
    except OSError as exc:
        stdout, stderr = b"", f"E2E_COMMAND_ERROR: {exc}".encode("utf-8", errors="replace")
        status, exit_code = "spawn_error", None
    duration_ms = (perf_counter_ns() - started) // 1_000_000
    captures = {"stdout": b64encode(stdout).decode("ascii"), "stderr": b64encode(stderr).decode("ascii")}
    return {
        "argv": list(argv),
        "status": status,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "stdout_sha256": _sha_bytes(stdout),
        "stderr_sha256": _sha_bytes(stderr),
    }, captures


def _artifact_hashes(root: Path, artifact_paths: list[str]) -> tuple[list[dict[str, str]], list[str]]:
    found: list[dict[str, str]] = []
    missing: list[str] = []
    for relative in artifact_paths:
        path = _workspace_path(root, relative, "artifact_paths")
        if not path.is_file():
            missing.append(relative)
            continue
        found.append({"path": relative, "sha256": _sha_bytes(path.read_bytes())})
    return found, missing


def _terminal(positive: dict[str, Any], negative: dict[str, Any], missing_artifacts: list[str]) -> tuple[str, str, bool]:
    if positive["status"] == "timed_out":
        return "positive_timeout", "E2E_POSITIVE_TIMEOUT", False
    if positive["status"] == "spawn_error" or positive["exit_code"] != 0:
        return "positive_nonzero", "E2E_POSITIVE_FAILED", False
    if negative["status"] == "timed_out":
        return "negative_timeout", "E2E_NEGATIVE_TIMEOUT", False
    if negative["status"] == "spawn_error" or negative["exit_code"] == 0:
        return "negative_zero", "HOLLOW_E2E_TEST", False
    if missing_artifacts:
        return "artifact_missing", "E2E_ARTIFACT_MISSING", False
    return "proof_pass", "E2E_PROOF_PASS", True


def _mermaid(receipt: dict[str, Any]) -> str:
    marker = receipt["marker"]
    return "\n".join([
        "flowchart LR",
        '  P["Approved positive command"] --> POS["Positive result"]',
        '  N["Declared negative mutation"] --> NEG["Negative result"]',
        '  POS --> G["Native E2E Proof Gate"]',
        '  NEG --> G',
        f'  G --> R["{marker}"]',
        '  R --> H["Human release decision remains external"]',
        "",
    ])


def _markdown(receipt: dict[str, Any]) -> str:
    manifest = receipt["manifest"]
    return "\n".join([
        "# E2E Proof Gate",
        "",
        f"- Proof ID: `{manifest['id']}`",
        f"- Approver: `{manifest['approval']['approved_by']}`",
        f"- Result: `{receipt['marker']}` ({'passing' if receipt['ok'] else 'non-passing'})",
        f"- Receipt SHA-256: `{receipt['receipt_sha256']}`",
        "",
        "## Command evidence",
        "",
        f"- Positive: `{receipt['commands']['positive']['status']}`, exit `{receipt['commands']['positive']['exit_code']}`",
        f"- Negative: `{receipt['commands']['negative']['status']}`, exit `{receipt['commands']['negative']['exit_code']}`",
        "",
        "## Scope limit",
        "",
        "This receipt proves only the declared local command pair and captured output digests. It does not enforce egress, isolate a browser or host, approve a merge, or establish production readiness.",
        "",
    ])


def _public(receipt: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in receipt.items() if key != "_captures"}


def verify_e2e_proof(root: Path, manifest_path: Path) -> dict[str, Any]:
    """Run the exact approved E2E command pair and return a bounded receipt."""
    workspace = Path(root).resolve()
    manifest = validate_e2e_proof_manifest(workspace, manifest_path)
    cwd = _workspace_path(workspace, manifest["working_directory"], "working_directory", directory=True)
    positive, positive_captures = _run_command(manifest["positive"]["argv"], cwd=cwd, timeout_seconds=manifest["timeout_seconds"])
    negative, negative_captures = _run_command(manifest["negative"]["argv"], cwd=cwd, timeout_seconds=manifest["timeout_seconds"])
    artifacts, missing_artifacts = _artifact_hashes(workspace, manifest["artifact_paths"])
    run_state, marker, ok = _terminal(positive, negative, missing_artifacts)
    core = {
        "schema": E2E_PROOF_RECEIPT_SCHEMA,
        "marker": marker,
        "ok": ok,
        "run_state": run_state,
        "manifest": manifest,
        "commands": {"positive": positive, "negative": negative},
        "artifacts": artifacts,
        "missing_artifacts": missing_artifacts,
        "authority": AUTHORITY,
        "scope_limits": [
            "Commands are caller-approved argv arrays executed locally with shell=False; this receipt does not grant merge, release, deployment, signing, credential, connector, or message authority.",
            "network_egress not_granted is a manifest declaration; this runner does not enforce host or process network isolation.",
            "The receipt proves the declared positive command exited zero and the declared negative command exited non-zero only when marker is E2E_PROOF_PASS.",
            "A passing command pair does not establish browser isolation, production coverage, quality, security, or release readiness.",
        ],
    }
    receipt = {**core, "receipt_sha256": _sha(core)}
    receipt["mermaid"] = _mermaid(receipt)
    receipt["receipt_markdown"] = _markdown(receipt)
    receipt["_captures"] = {"positive": positive_captures, "negative": negative_captures}
    return receipt


def _validate_receipt_shape(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != E2E_PROOF_RECEIPT_SCHEMA:
        _reject("E2E_PROOF_RECEIPT_INVALID", f"a {E2E_PROOF_RECEIPT_SCHEMA} payload is required")
    required = {
        "schema", "marker", "ok", "run_state", "manifest", "commands", "artifacts", "missing_artifacts",
        "authority", "scope_limits", "receipt_sha256", "mermaid", "receipt_markdown",
    }
    allowed = required | {"_captures"}
    if not required.issubset(value) or set(value) - allowed:
        _reject("E2E_PROOF_RECEIPT_INVALID", "receipt has unsupported or missing fields")
    if value["authority"] != AUTHORITY:
        _reject("E2E_PROOF_RECEIPT_INVALID", "E2E Proof authority boundary changed")
    return value


def _validate_receipt_hash(value: dict[str, Any]) -> None:
    required = set(value) - {"_captures"}
    core = {key: value[key] for key in required - {"receipt_sha256", "mermaid", "receipt_markdown"}}
    if not isinstance(value["receipt_sha256"], str) or not _SHA256.fullmatch(value["receipt_sha256"]):
        _reject("E2E_PROOF_RECEIPT_INVALID", "receipt_sha256 must be a lowercase SHA-256 digest")
    if value["receipt_sha256"] != _sha(core):
        _reject("E2E_PROOF_RECEIPT_INVALID", "receipt SHA-256 does not match")


def _validate_receipt_result(value: dict[str, Any]) -> None:
    expected = {
        "positive_timeout": ("E2E_POSITIVE_TIMEOUT", False),
        "positive_nonzero": ("E2E_POSITIVE_FAILED", False),
        "negative_timeout": ("E2E_NEGATIVE_TIMEOUT", False),
        "negative_zero": ("HOLLOW_E2E_TEST", False),
        "artifact_missing": ("E2E_ARTIFACT_MISSING", False),
        "proof_pass": ("E2E_PROOF_PASS", True),
    }
    state = value["run_state"]
    if not isinstance(value["ok"], bool) or state not in expected or (value["marker"], value["ok"]) != expected[state]:
        _reject("E2E_PROOF_RECEIPT_INVALID", "marker, ok, and run_state are inconsistent")


def _validate_receipt_views(value: dict[str, Any]) -> None:
    if not isinstance(value["mermaid"], str) or not isinstance(value["receipt_markdown"], str):
        _reject("E2E_PROOF_RECEIPT_INVALID", "receipt views must be strings")
    if value["mermaid"] != _mermaid(value) or value["receipt_markdown"] != _markdown(value):
        _reject("E2E_PROOF_RECEIPT_INVALID", "receipt Markdown or Mermaid does not match the receipt facts")


def _validate_captures(value: dict[str, Any]) -> None:
    captures = value.get("_captures")
    if captures is None:
        return
    if not isinstance(captures, dict) or set(captures) != {"positive", "negative"}:
        _reject("E2E_PROOF_RECEIPT_INVALID", "private captures must contain positive and negative command output")
    for name in ("positive", "negative"):
        capture = captures[name]
        if not isinstance(capture, dict) or set(capture) != {"stdout", "stderr"}:
            _reject("E2E_PROOF_RECEIPT_INVALID", f"private {name} capture is invalid")
        for stream in ("stdout", "stderr"):
            try:
                raw = b64decode(capture[stream].encode("ascii"), validate=True)
            except (AttributeError, ValueError) as exc:
                raise E2EProofError("E2E_PROOF_RECEIPT_INVALID", f"private {name} {stream} capture is invalid base64") from exc
            if _sha_bytes(raw) != value["commands"][name][f"{stream}_sha256"]:
                _reject("E2E_PROOF_RECEIPT_INVALID", f"private {name} {stream} capture hash does not match")


def validate_e2e_proof_receipt(value: object) -> dict[str, Any]:
    """Verify the canonical public receipt and any optional private captures."""
    receipt = _validate_receipt_shape(value)
    _validate_receipt_hash(receipt)
    _validate_receipt_result(receipt)
    _validate_receipt_views(receipt)
    _validate_captures(receipt)
    return receipt


def _atomic_bytes(path: Path, content: bytes) -> str:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(content)
    temporary.replace(path)
    return _sha_bytes(content)


def write_e2e_proof_artifacts(receipt: dict, out_dir: Path) -> dict:
    """Write public receipt views and captured command output below one explicit directory."""
    receipt = validate_e2e_proof_receipt(receipt)
    captures = receipt.get("_captures")
    if captures is None:
        raise E2EProofError("E2E_PROOF_CAPTURE_UNAVAILABLE", "captured output is unavailable; run the proof in this process before writing artifacts")
    destination = Path(out_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    stem = f"e2e-proof-{receipt['receipt_sha256'][:12]}"
    paths = {
        "json": destination / f"{stem}.json",
        "markdown": destination / f"{stem}.md",
        "mermaid": destination / f"{stem}.mmd",
        "positive_stdout": destination / f"{stem}.positive.stdout.log",
        "positive_stderr": destination / f"{stem}.positive.stderr.log",
        "negative_stdout": destination / f"{stem}.negative.stdout.log",
        "negative_stderr": destination / f"{stem}.negative.stderr.log",
    }
    public = _public(receipt)
    contents = {
        "json": json.dumps(public, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n",
        "markdown": receipt["receipt_markdown"].encode("utf-8"),
        "mermaid": receipt["mermaid"].encode("utf-8"),
        "positive_stdout": b64decode(captures["positive"]["stdout"].encode("ascii")),
        "positive_stderr": b64decode(captures["positive"]["stderr"].encode("ascii")),
        "negative_stdout": b64decode(captures["negative"]["stdout"].encode("ascii")),
        "negative_stderr": b64decode(captures["negative"]["stderr"].encode("ascii")),
    }
    digests = {name: _atomic_bytes(paths[name], content) for name, content in contents.items()}
    return {
        "marker": "E2E_PROOF_ARTIFACTS_WRITTEN",
        "paths": {name: str(path) for name, path in paths.items()},
        "sha256": digests,
    }


def public_e2e_proof_receipt(receipt: dict) -> dict:
    """Return the JSON-safe receipt projection without captured command bytes."""
    validate_e2e_proof_receipt(receipt)
    return _public(receipt)
