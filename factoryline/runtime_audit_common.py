"""Strict, zero-authority primitives for runtime assurance artifacts."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import stat
from functools import wraps
from pathlib import Path, PurePosixPath
from typing import Any, Callable

MAX_ARTIFACT_BYTES = 1_048_576
MAX_CHALLENGE_FILES = 64
MAX_CHALLENGE_SOURCE_BYTES = 8 * 1_048_576
MAX_NATIVE_ARTIFACTS = 16
MAX_NATIVE_ARTIFACT_BYTES = 8 * 1_048_576
NATIVE_ARTIFACT_ROLES = {
    "codeql": {"sarif_report", "query_inventory"},
    "semgrep": {"sarif_report", "rule_inventory"},
    "trivy": {"sarif_report", "policy_inventory"},
    "osv": {"osv_json_report", "advisory_db_identity"},
    "gitleaks": {"sarif_report", "gitleaks_rule_ledger"},
    "runtime": {"junit_xml", "coverage_json"},
    "atheris": {"fuzz_result", "corpus_manifest"},
    "jazzer": {"fuzz_result", "corpus_manifest"},
    "zap": {"zap_report"},
    "syft": {"sbom_json"},
}
NATIVE_REPORT_ROLE = {
    "codeql": "sarif_report",
    "semgrep": "sarif_report",
    "trivy": "sarif_report",
    "osv": "osv_json_report",
    "gitleaks": "sarif_report",
    "runtime": "junit_xml",
    "atheris": "fuzz_result",
    "jazzer": "fuzz_result",
    "zap": "zap_report",
}
IGNORED_VERDICT_FIELDS = {"passed", "ok", "verdict", "decision"}
FORBIDDEN_SECRET_FIELDS = {"body", "headers", "token", "password", "secret"}


class RuntimeAuditError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def canonical_bytes(value: object) -> bytes:
    """Serialize a JSON-compatible value into the single canonical byte representation used for digests."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    """Return a lowercase SHA-256 digest for already bounded bytes without assigning any trust authority."""
    return hashlib.sha256(value).hexdigest()


def exact_keys(
    value: dict[str, Any], required: set[str], optional: set[str] | None = None
) -> None:
    """Reject missing or unknown object fields while ignoring only explicitly non-authoritative verdict labels."""
    if not isinstance(value, dict):
        raise RuntimeAuditError("E_ARTIFACT_FIELDS", "expected an object")
    optional = (optional or set()) | IGNORED_VERDICT_FIELDS
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing:
        raise RuntimeAuditError(
            "E_ARTIFACT_FIELDS", f"missing fields: {sorted(missing)}"
        )
    if unknown:
        raise RuntimeAuditError(
            "E_ARTIFACT_FIELDS", f"unknown fields: {sorted(unknown)}"
        )


def require_str(
    value: object, field: str, *, minimum: int = 1, maximum: int = 256
) -> str:
    """Validate a printable bounded string and return it without coercing another input type."""
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or not value.strip()
        or any(ord(c) < 32 for c in value)
    ):
        raise RuntimeAuditError(
            "E_FIELD", f"{field} must be a string of {minimum}..{maximum} characters"
        )
    return value


def require_digest(value: object, field: str) -> str:
    """Validate and return one canonical lowercase SHA-256 hexadecimal digest string."""
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise RuntimeAuditError(
            "E_DIGEST", f"{field} must be a lowercase SHA-256 hex digest"
        )
    return value


def require_bool(value: object, field: str) -> bool:
    """Require a real JSON boolean rather than accepting integer truthiness or string approximations."""
    if type(value) is not bool:
        raise RuntimeAuditError("E_FIELD", f"{field} must be boolean")
    return value


def require_int(value: object, field: str, *, minimum: int, maximum: int) -> int:
    """Validate a bounded integer while explicitly refusing booleans and implicit numeric coercion."""
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise RuntimeAuditError(
            "E_FIELD", f"{field} must be an integer in {minimum}..{maximum}"
        )
    return value


def require_number(value: object, field: str, *, minimum: float = 0.0) -> float:
    """Validate a finite numeric observation above the declared floor and return a float."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeAuditError("E_FIELD", f"{field} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        raise RuntimeAuditError("E_FIELD", f"{field} must be finite and >= {minimum}")
    return result


def require_unique_strings(
    value: object, field: str, *, minimum: int, maximum: int
) -> list[str]:
    """Validate a bounded list of distinct printable strings without silently deduplicating evidence."""
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise RuntimeAuditError(
            "E_FIELD", f"{field} must contain {minimum}..{maximum} items"
        )
    items = [require_str(item, f"{field}[]") for item in value]
    if len(items) != len(set(items)):
        raise RuntimeAuditError("E_DUPLICATE_ID", f"{field} contains duplicates")
    return items


def reject_secret_material(
    value: object,
    *,
    path: str = "artifact",
    depth: int = 0,
    max_string_length: int = 4096,
) -> None:
    """Recursively reject secret-shaped fields, excessive depth, non-finite numbers, and oversized strings."""
    if depth > 32:
        raise RuntimeAuditError("E_ARTIFACT_DEPTH", "maximum nesting depth is 32")
    if isinstance(value, dict):
        _reject_secret_fields(value, path, depth, max_string_length)
    elif isinstance(value, list):
        _reject_secret_list(value, path, depth, max_string_length)
    elif isinstance(value, float) and not math.isfinite(value):
        raise RuntimeAuditError("E_NONFINITE", f"non-finite number at {path}")
    elif isinstance(value, str) and len(value) > max_string_length:
        raise RuntimeAuditError("E_FIELD_SIZE", f"string too long at {path}")


def _reject_secret_fields(
    value: dict, path: str, depth: int, max_string_length: int
) -> None:
    """Check object keys before descending into their values."""
    for key, child in value.items():
        if str(key).lower() in FORBIDDEN_SECRET_FIELDS:
            raise RuntimeAuditError(
                "E_SECRET_MATERIAL", f"forbidden field at {path}.{key}"
            )
        reject_secret_material(
            child,
            path=f"{path}.{key}",
            depth=depth + 1,
            max_string_length=max_string_length,
        )


def _reject_secret_list(
    value: list, path: str, depth: int, max_string_length: int
) -> None:
    """Preserve index paths while checking nested evidence."""
    for index, child in enumerate(value):
        reject_secret_material(
            child,
            path=f"{path}[{index}]",
            depth=depth + 1,
            max_string_length=max_string_length,
        )


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeAuditError("E_DUPLICATE_FIELD", key)
        result[key] = value
    return result


def parse_json_bytes(raw: bytes, *, max_string_length: int = 4096) -> dict[str, Any]:
    """Strictly decode one bounded JSON object while rejecting duplicate keys and unsafe evidence values."""
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise RuntimeAuditError("E_ARTIFACT_SIZE", "artifact too large")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RuntimeAuditError("E_ARTIFACT_JSON", "invalid bounded JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeAuditError("E_ARTIFACT_JSON", "artifact must be a JSON object")
    reject_secret_material(value, max_string_length=max_string_length)
    return value


def read_stable_json(
    path: Path, *, max_string_length: int = 4096
) -> tuple[dict[str, Any], str]:
    """Read a non-symlink JSON artifact twice and return its parsed object plus exact-byte digest."""
    if not path.is_file():
        raise RuntimeAuditError("E_ARTIFACT_MISSING", str(path))
    if path.is_symlink():
        raise RuntimeAuditError("E_ARTIFACT_LINK", "symlink artifacts are forbidden")
    with path.open("rb") as stream:
        first = stream.read(MAX_ARTIFACT_BYTES + 1)
    if len(first) > MAX_ARTIFACT_BYTES:
        raise RuntimeAuditError(
            "E_ARTIFACT_SIZE", f"artifact exceeds {MAX_ARTIFACT_BYTES} bytes"
        )
    with path.open("rb") as stream:
        second = stream.read(MAX_ARTIFACT_BYTES + 1)
    if first != second:
        raise RuntimeAuditError("E_ARTIFACT_CHANGED", str(path))
    return parse_json_bytes(first, max_string_length=max_string_length), sha256_bytes(
        first
    )


def lane_result(
    lane: str,
    state: str,
    finding: str,
    consequence: str,
    *,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct one closed-state audit result from independently computed facts and bounded details."""
    if state not in {"PASS", "FAIL", "INCOMPLETE"}:
        raise RuntimeAuditError("E_STATE", state)
    return {
        "lane": lane,
        "state": state,
        "finding": finding,
        "consequence": consequence,
        "details": details or {},
    }


def _validate_lane_result(result: Any, lane: str) -> None:
    """Require the lane's closed result contract and bounded serialized output."""
    if (
        not isinstance(result, dict)
        or result.get("lane") != lane
        or result.get("state") not in {"PASS", "FAIL", "INCOMPLETE"}
        or not isinstance(result.get("finding"), str)
        or re.fullmatch(r"[A-Za-z0-9_]{1,128}", result["finding"]) is None
        or not isinstance(result.get("consequence"), str)
        or not isinstance(result.get("details"), dict)
    ):
        raise RuntimeAuditError("E_EVALUATOR_RESULT", "invalid lane result")
    if len(canonical_bytes(result)) > MAX_ARTIFACT_BYTES:
        raise RuntimeAuditError("E_EVALUATOR_LIMIT", "lane result exceeds byte budget")


def guarded_lane_evaluator(lane: str):
    """Turn malformed lane evidence into a bounded INCOMPLETE result, never a crash or pass."""

    def decorate(evaluator: Callable[..., dict[str, Any]]):
        @wraps(evaluator)
        def guarded(*args, **kwargs):
            try:
                result = evaluator(*args, **kwargs)
                _validate_lane_result(result, lane)
                return result
            except Exception as exc:
                code = getattr(exc, "code", "E_ARTIFACT_INVALID")
                if (
                    not isinstance(code, str)
                    or re.fullmatch(r"[A-Z0-9_]{1,64}", code) is None
                ):
                    code = "E_ARTIFACT_INVALID"
                return lane_result(
                    lane,
                    "INCOMPLETE",
                    code,
                    "The lane evidence could not be evaluated safely; provide a corrected, complete artifact.",
                    details={"error_code": code},
                )

        return guarded

    return decorate


def _stat_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    """Return fields that reveal file replacement or mutation during bounded reads."""
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _linked_entry(info: os.stat_result) -> bool:
    """Reject symbolic links and Windows reparse-point entries such as junctions."""
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & reparse
    )


def _bounded_target(path: Path, root: Path | None) -> Path:
    """Resolve a path lexically under its optional root and reject linked ancestors."""
    target = path
    if root is not None:
        base = root.resolve(strict=True)
        target = path if path.is_absolute() else base / path
        try:
            relative = target.relative_to(base)
        except ValueError as exc:
            raise RuntimeAuditError(
                "E_CHALLENGE_PATH", "path outside bound root"
            ) from exc
        if ".." in relative.parts:
            raise RuntimeAuditError("E_CHALLENGE_PATH", "parent traversal forbidden")
        for part in relative.parts:
            base = base / part
            if _linked_entry(base.lstat()):
                raise RuntimeAuditError(
                    "E_CHALLENGE_PATH", "symlink component forbidden"
                )
        target = base
    else:
        target = path.absolute()
        cursor = Path(target.anchor)
        for part in target.parts[1:-1]:
            cursor = cursor / part
            if _linked_entry(cursor.lstat()):
                raise RuntimeAuditError(
                    "E_CHALLENGE_PATH", "linked input parent forbidden"
                )
    return target


def _bounded_file(path: Path, *, root: Path | None = None) -> bytes:
    """Read one stable, regular, non-link file under the artifact size cap."""
    target = _bounded_target(path, root)
    try:
        before = target.lstat()
        if (
            _linked_entry(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_size > MAX_ARTIFACT_BYTES
        ):
            raise RuntimeAuditError(
                "E_CHALLENGE_INPUT", "bounded regular file required"
            )
        descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            raw = stream.read(MAX_ARTIFACT_BYTES + 1)
            after = os.fstat(stream.fileno())
        current = target.lstat()
    except OSError as exc:
        raise RuntimeAuditError(
            "E_CHALLENGE_INPUT", "challenge input unavailable"
        ) from exc
    if (
        len(raw) > MAX_ARTIFACT_BYTES
        or _stat_identity(before) != _stat_identity(opened)
        or _stat_identity(opened) != _stat_identity(after)
        or _stat_identity(after) != _stat_identity(current)
        or after.st_size != len(raw)
    ):
        raise RuntimeAuditError(
            "E_CHALLENGE_INPUT", "challenge input changed or exceeded cap"
        )
    return raw


def _render_profile_argv(template: list[str], values: dict[str, str]) -> list[str]:
    """Render a closed native profile argv template without accepting free-form shell text."""
    names = {
        "source",
        "output",
        "report",
        "scratch",
        "candidate_sha256",
        "factory_ledger",
        "config",
    }
    if (
        not isinstance(template, list)
        or not 1 <= len(template) <= 128
        or set(values) != names
    ):
        raise RuntimeAuditError(
            "E_CHALLENGE_PROFILE", "bounded closed profile template required"
        )
    result = []
    for raw in template:
        value = require_str(raw, "profile argv item", maximum=4096)
        for name, bound in values.items():
            value = value.replace(
                "{" + name + "}", require_str(bound, name, maximum=4096)
            )
        if "{" in value or "}" in value:
            raise RuntimeAuditError(
                "E_CHALLENGE_PROFILE", "unresolved profile placeholder"
            )
        result.append(value)
    return result


def _validate_runner_facts(facts: Any, timeout: int) -> dict[str, Any]:
    """Reject absent or malformed process facts instead of filling them with success defaults."""
    required = {
        "exit_code",
        "timed_out",
        "timeout_seconds",
        "duration_ms",
        "launch_error",
        "output_limit_exceeded",
        "cleanup_confirmed",
        "stdout_sha256",
        "stderr_sha256",
        "stdout_bytes",
        "stderr_bytes",
    }
    if not isinstance(facts, dict) or not required <= set(facts):
        raise RuntimeAuditError(
            "E_CHALLENGE_FACTS", "runner returned incomplete process facts"
        )
    for field in (
        "timed_out",
        "launch_error",
        "output_limit_exceeded",
        "cleanup_confirmed",
    ):
        require_bool(facts[field], field)
    if "cancelled" in facts:
        require_bool(facts["cancelled"], "cancelled")
    require_int(facts["timeout_seconds"], "timeout_seconds", minimum=1, maximum=3600)
    require_int(facts["duration_ms"], "duration_ms", minimum=0, maximum=3_600_000)
    if facts["timeout_seconds"] != timeout:
        raise RuntimeAuditError(
            "E_CHALLENGE_FACTS", "runner timeout differs from requested budget"
        )
    if facts["exit_code"] is not None:
        require_int(facts["exit_code"], "exit_code", minimum=0, maximum=255)
    for field in ("stdout_sha256", "stderr_sha256"):
        require_digest(facts[field], field)
    for field in ("stdout_bytes", "stderr_bytes"):
        require_int(facts[field], field, minimum=0, maximum=1024 * 1024 * 1024)
    return facts


def _validate_native_bindings(
    values: dict[str, str],
    source: Path,
    scratch: Path,
    report: Path,
    ledger: Path,
    config: Path,
    evidence: dict[str, Any],
) -> None:
    """Ensure every closed argv placeholder resolves to this exact isolated run."""
    expected = {
        "source": source,
        "output": scratch,
        "report": report,
        "scratch": scratch,
        "factory_ledger": ledger,
        "config": config,
    }
    for name, path in expected.items():
        if (
            Path(require_str(values.get(name), name, maximum=4096)).absolute()
            != path.absolute()
        ):
            raise RuntimeAuditError(
                "E_CHALLENGE_BINDING", f"{name} path binding differs"
            )
    if values.get("candidate_sha256") != evidence["challenge_source_sha256"]:
        raise RuntimeAuditError(
            "E_CHALLENGE_BINDING",
            "profile candidate placeholder is not challenge-only source",
        )
    if (
        report.absolute().parent != scratch.absolute()
        or ledger.absolute().parent != scratch.absolute()
    ):
        raise RuntimeAuditError(
            "E_CHALLENGE_BINDING",
            "native outputs must be direct children of run scratch",
        )


def _challenge_state(facts: dict[str, Any], expected_exit: int) -> str:
    """Classify execution only when launch, timeout, output, exit and cleanup facts agree."""
    if (
        facts["launch_error"]
        or facts["timed_out"]
        or facts.get("cancelled", False)
        or facts["output_limit_exceeded"]
        or not facts["cleanup_confirmed"]
        or facts["exit_code"] is None
    ):
        return "INCOMPLETE"
    return "PASS" if facts["exit_code"] == expected_exit else "FAIL"


def _challenge_report(
    raw: bytes,
    parser: Callable[[bytes], dict[str, Any]],
    *,
    engine: str,
    fixture_sha: str,
    rule_id: str,
    enabled: bool,
) -> tuple[dict[str, Any], str]:
    """Parse a bounded sanitized native report and wrap it in the stable signed report shape."""
    native = parser(raw)
    if not isinstance(native, dict):
        raise RuntimeAuditError("E_CHALLENGE_REPORT", "native report must be an object")
    reject_secret_material(native)
    report = {
        "schema": "factory.deep-challenge-observation.v1",
        "engine": engine,
        "fixture_sha256": fixture_sha,
        "detector_rule_id": rule_id,
        "detector_enabled": enabled,
        "native_report": native,
    }
    if len(canonical_bytes(report)) > MAX_ARTIFACT_BYTES:
        raise RuntimeAuditError(
            "E_CHALLENGE_REPORT", "sanitized report exceeds artifact cap"
        )
    return report, sha256_bytes(raw)


def _challenge_manifest(
    value: object, anchor_path: str, anchor_sha: str
) -> dict[str, str]:
    """Validate a canonical signed path-to-digest map and preserve v1 singleton controls."""
    if value is None:
        return {anchor_path: anchor_sha}
    if not isinstance(value, dict) or not 1 <= len(value) <= MAX_CHALLENGE_FILES:
        raise RuntimeAuditError(
            "E_CHALLENGE_MANIFEST", "bounded source manifest required"
        )
    result = {}
    for raw_path, raw_sha in value.items():
        path = require_str(raw_path, "manifest path", maximum=2048)
        parsed = PurePosixPath(path)
        if (
            "\\" in path
            or ":" in path
            or not parsed.parts
            or path == "."
            or parsed.is_absolute()
            or parsed.as_posix() != path
            or any(part in {".", ".."} for part in parsed.parts)
            or any(_unsafe_manifest_component(part) for part in parsed.parts)
        ):
            raise RuntimeAuditError(
                "E_CHALLENGE_PATH", "manifest path is not canonical"
            )
        result[path] = require_digest(raw_sha, "manifest source digest")
    if len(result) != len(value) or result.get(anchor_path) != anchor_sha:
        raise RuntimeAuditError(
            "E_CHALLENGE_MANIFEST", "anchor must match one unique manifest entry"
        )
    return dict(sorted(result.items()))


def _unsafe_manifest_component(part: str) -> bool:
    """Reject Windows path aliases that could resolve differently on the host."""
    reserved = r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?"
    return (
        part.endswith((".", " "))
        or re.fullmatch(reserved, part, re.IGNORECASE) is not None
    )


def _native_artifact_paths(
    engine: str, roles: object, paths: object
) -> dict[str, Path]:
    """Require the signed engine role set and one distinct direct scratch output per role."""
    allowed = NATIVE_ARTIFACT_ROLES.get(engine)
    if engine == "syft" or allowed is None:
        raise RuntimeAuditError(
            "E_NATIVE_ROLE", "engine has no challenge artifact profile"
        )
    if not isinstance(roles, list) or any(not isinstance(item, str) for item in roles):
        raise RuntimeAuditError("E_NATIVE_ROLE", "signed roles must be strings")
    if roles != sorted(set(roles)) or set(roles) != allowed:
        raise RuntimeAuditError(
            "E_NATIVE_ROLE", "signed artifact roles do not match engine"
        )
    if not isinstance(paths, dict) or set(paths) != allowed:
        raise RuntimeAuditError(
            "E_NATIVE_ROLE", "signed artifact roles do not match engine"
        )
    converted = {}
    for role, raw_path in paths.items():
        if not isinstance(role, str) or not isinstance(raw_path, Path):
            raise RuntimeAuditError(
                "E_NATIVE_ROLE", "artifact role paths must be typed"
            )
        converted[role] = raw_path
    if len(set(path.absolute() for path in converted.values())) != len(allowed):
        raise RuntimeAuditError("E_NATIVE_ROLE", "artifact paths must be distinct")
    return converted


def _validate_native_artifact_paths(
    engine: str, paths: dict[str, Path], scratch: Path, report: Path, ledger: Path
) -> None:
    """Bind each profile output to one direct scratch child and the expected report path."""
    root = scratch.absolute()
    for path in paths.values():
        if (
            path.is_absolute() is False
            or path.parent != root
            or path.name in {"", ".", ".."}
        ):
            raise RuntimeAuditError(
                "E_NATIVE_PATH", "native artifacts must be scratch children"
            )
    report_role = NATIVE_REPORT_ROLE[engine]
    if paths[report_role] != report.absolute():
        raise RuntimeAuditError(
            "E_NATIVE_PATH", "report path differs from role binding"
        )
    if engine == "gitleaks" and paths["gitleaks_rule_ledger"] != ledger.absolute():
        raise RuntimeAuditError(
            "E_NATIVE_PATH", "Gitleaks ledger path differs from role binding"
        )


def _native_artifact_records(paths: dict[str, Path]) -> list[dict[str, Any]]:
    """Hash exact bounded native outputs without retaining report or tool output bytes."""
    records = []
    total = 0
    for role, path in sorted(paths.items()):
        raw = _bounded_file(path)
        total += len(raw)
        if total > MAX_NATIVE_ARTIFACT_BYTES:
            raise RuntimeAuditError(
                "E_NATIVE_LIMIT", "native artifacts exceed aggregate budget"
            )
        records.append({"kind": role, "sha256": sha256_bytes(raw), "bytes": len(raw)})
    return records


def _validate_v2_lane(
    engine: str,
    kind: str,
    detector_rule_id: str,
    baseline_ids: list[str],
    effective_sha: str,
    rule_ids: object,
    mutation_hashes: object,
) -> None:
    """Bind the signed rule inventory and exact target-removal digest for v2 controls."""
    if not isinstance(rule_ids, list):
        raise RuntimeAuditError(
            "E_CHALLENGE_RULES", "signed rule inventory must be a list"
        )
    normalized_ids = require_unique_strings(
        rule_ids, "signed rule ids", minimum=1, maximum=4096
    )
    if normalized_ids != sorted(normalized_ids):
        raise RuntimeAuditError(
            "E_CHALLENGE_RULES", "signed rule inventory must be sorted and unique"
        )
    if sorted(baseline_ids) != normalized_ids or not isinstance(mutation_hashes, dict):
        raise RuntimeAuditError(
            "E_CHALLENGE_RULES", "baseline differs from signed rule inventory"
        )
    if set(mutation_hashes) != set(normalized_ids):
        raise RuntimeAuditError(
            "E_CHALLENGE_RULES", "mutation digest map keys differ from rule inventory"
        )
    for value in mutation_hashes.values():
        require_digest(value, "mutation ruleset digest")
    if kind == "mutation":
        if engine == "syft" or detector_rule_id not in mutation_hashes:
            raise RuntimeAuditError(
                "E_CHALLENGE_RULES", "mutation target is not authorized"
            )
        if effective_sha != mutation_hashes[detector_rule_id]:
            raise RuntimeAuditError(
                "E_CHALLENGE_RULES", "effective ruleset digest differs from signed map"
            )


def _source_tree_entries(root: Path) -> tuple[Path, set[str], set[str]]:
    """Enumerate a bounded source tree while rejecting links and traversal errors."""
    if _linked_entry(root.lstat()) or not root.is_dir():
        raise RuntimeAuditError(
            "E_CHALLENGE_SOURCE", "isolated source directory required"
        )
    root = root.resolve(strict=True)
    actual_dirs, actual_files, count = set(), set(), 0
    walk_errors = []
    for current, dirs, files in os.walk(
        root, followlinks=False, onerror=walk_errors.append
    ):
        base = Path(current)
        for name in dirs:
            path = base / name
            count += 1
            if _linked_entry(path.lstat()):
                raise RuntimeAuditError(
                    "E_CHALLENGE_SOURCE", "linked source directory forbidden"
                )
            actual_dirs.add(path.relative_to(root).as_posix())
        for name in files:
            path = base / name
            count += 1
            if _linked_entry(path.lstat()) or not stat.S_ISREG(path.lstat().st_mode):
                raise RuntimeAuditError(
                    "E_CHALLENGE_SOURCE", "non-regular source entry forbidden"
                )
            actual_files.add(path.relative_to(root).as_posix())
        if count > 256 or len(actual_files) > MAX_CHALLENGE_FILES:
            raise RuntimeAuditError(
                "E_CHALLENGE_SOURCE", "source tree exceeds entry budget"
            )
    if walk_errors:
        raise RuntimeAuditError(
            "E_CHALLENGE_SOURCE", "source tree traversal was incomplete"
        )
    return root, actual_dirs, actual_files


def _manifest_directories(manifest: dict[str, str]) -> set[str]:
    """Return the exact parent directory set implied by canonical manifest paths."""
    expected_dirs = set()
    for name in manifest:
        parts = PurePosixPath(name).parts
        expected_dirs.update(
            PurePosixPath(*parts[:index]).as_posix() for index in range(1, len(parts))
        )
    return expected_dirs


def _read_manifest_files(root: Path, manifest: dict[str, str]) -> dict[str, bytes]:
    """Read each signed file once within per-file and aggregate source limits."""
    collected = {}
    total = 0
    for name, expected_sha in manifest.items():
        raw = _bounded_file(Path(name), root=root)
        total += len(raw)
        if total > MAX_CHALLENGE_SOURCE_BYTES:
            raise RuntimeAuditError(
                "E_CHALLENGE_SOURCE", "source tree exceeds byte budget"
            )
        if sha256_bytes(raw) != expected_sha:
            raise RuntimeAuditError("E_CHALLENGE_SOURCE", "source file digest differs")
        collected[name] = raw
    return collected


def _challenge_source_files(root: Path, manifest: dict[str, str]) -> dict[str, bytes]:
    """Require the bounded scanner source tree to match every signed file and no others."""
    root, actual_dirs, actual_files = _source_tree_entries(root)
    expected_dirs = _manifest_directories(manifest)
    if actual_files != set(manifest) or actual_dirs != expected_dirs:
        raise RuntimeAuditError(
            "E_CHALLENGE_SOURCE", "source tree must contain only signed manifest files"
        )
    return _read_manifest_files(root, manifest)


def _challenge_source(root: Path, relative: Path) -> bytes:
    """Require the isolated scanner tree to contain only one signed v1 fixture."""
    if relative.is_absolute() or ".." in relative.parts:
        raise RuntimeAuditError("E_CHALLENGE_PATH", "fixture must be relative")
    name = relative.as_posix()
    if name in {"", "."} or "\\" in name or ":" in name:
        raise RuntimeAuditError("E_CHALLENGE_PATH", "fixture path is not canonical")
    expected = _bounded_file(relative, root=root)
    files = _challenge_source_files(root, {name: sha256_bytes(expected)})
    return files[name]


def _owned_scratch(scratch: Path, parent: Path) -> tuple[Path, tuple[int, int]]:
    """Require a dedicated direct child directory with no symlinked path components."""
    owner = parent.resolve(strict=True)
    target = scratch.absolute()
    if target.parent != owner or scratch == parent:
        raise RuntimeAuditError(
            "E_CHALLENGE_SCRATCH", "scratch must be one child of its owned temp parent"
        )
    cursor = Path(target.anchor)
    for part in target.parts[1:-1]:
        cursor = cursor / part
        if _linked_entry(cursor.lstat()):
            raise RuntimeAuditError(
                "E_CHALLENGE_SCRATCH", "linked scratch path forbidden"
            )
    if scratch.exists() and _linked_entry(scratch.lstat()):
        raise RuntimeAuditError("E_CHALLENGE_SCRATCH", "linked scratch leaf forbidden")
    if scratch.exists() and not scratch.is_dir():
        raise RuntimeAuditError("E_CHALLENGE_SCRATCH", "scratch directory required")
    if not scratch.exists():
        scratch.mkdir()
    if any(scratch.iterdir()):
        raise RuntimeAuditError("E_CHALLENGE_SCRATCH", "scratch must start empty")
    info = scratch.lstat()
    return owner, (info.st_dev, info.st_ino)


def _validate_challenge(
    challenge: dict[str, Any],
    source_root: Path,
    expected_ruleset: str,
    baseline_path: Path,
    effective_path: Path,
    detector_rule_id: str,
    enabled: bool,
    kind: str,
    config_rule_ids: Callable[[bytes], list[str]],
    verify_mutation: Callable[[bytes, bytes, str], bool],
) -> dict[str, Any]:
    """Bind signed fixture/config inputs and prove mutation is the exact authorized rule removal."""
    required = {
        "kind",
        "fixture_path",
        "fixture_sha256",
        "expected_report_sha256",
        "expected_exit_code",
    }
    exact_keys(challenge, required, {"fixture_manifest", "fixture_manifest_sha256"})
    has_manifest = "fixture_manifest" in challenge
    if has_manifest != ("fixture_manifest_sha256" in challenge):
        raise RuntimeAuditError(
            "E_CHALLENGE_MANIFEST", "manifest and digest must appear together"
        )
    fixture_path = Path(
        require_str(challenge["fixture_path"], "fixture path", maximum=2048)
    )
    if (
        fixture_path.is_absolute()
        or ".." in fixture_path.parts
        or challenge["fixture_path"] != fixture_path.as_posix()
    ):
        raise RuntimeAuditError(
            "E_CHALLENGE_PATH", "fixture must be relative to isolated source"
        )
    fixture_sha = require_digest(challenge["fixture_sha256"], "fixture_sha256")
    manifest = _challenge_manifest(
        challenge.get("fixture_manifest"), fixture_path.as_posix(), fixture_sha
    )
    manifest_sha = sha256_bytes(canonical_bytes(manifest))
    if has_manifest and manifest_sha != require_digest(
        challenge["fixture_manifest_sha256"], "fixture_manifest_sha256"
    ):
        raise RuntimeAuditError("E_CHALLENGE_MANIFEST", "manifest digest differs")
    fixture = _bounded_file(fixture_path, root=source_root)
    if sha256_bytes(fixture) != fixture_sha:
        raise RuntimeAuditError(
            "E_CHALLENGE_FIXTURE", "fixture digest differs from signed contract"
        )
    fixture_files = _challenge_source_files(source_root, manifest)
    fixture = fixture_files[fixture_path.as_posix()]
    if sha256_bytes(fixture) != fixture_sha:
        raise RuntimeAuditError(
            "E_CHALLENGE_FIXTURE", "fixture digest differs from signed contract"
        )
    baseline, effective = _bounded_file(baseline_path), _bounded_file(effective_path)
    baseline_sha, effective_sha = sha256_bytes(baseline), sha256_bytes(effective)
    if baseline_sha != require_digest(expected_ruleset, "ruleset_sha256"):
        raise RuntimeAuditError(
            "E_CHALLENGE_CONFIG", "baseline differs from pinned ruleset"
        )
    baseline_ids = require_unique_strings(
        config_rule_ids(baseline), "baseline rule ids", minimum=1, maximum=4096
    )
    effective_ids = require_unique_strings(
        config_rule_ids(effective), "effective rule ids", minimum=0, maximum=4096
    )
    if kind == "mutation":
        if (
            enabled
            or detector_rule_id not in baseline_ids
            or effective_ids
            != [item for item in baseline_ids if item != detector_rule_id]
            or verify_mutation(baseline, effective, detector_rule_id) is not True
        ):
            raise RuntimeAuditError(
                "E_CHALLENGE_MUTATION", "mutation is not the exact target rule removal"
            )
    elif not enabled or effective != baseline:
        raise RuntimeAuditError(
            "E_CHALLENGE_CONFIG", "control must use exact baseline config"
        )
    return {
        "fixture": fixture,
        "fixture_sha": fixture_sha,
        "fixture_manifest": manifest,
        "fixture_manifest_sha": manifest_sha,
        "fixture_files": fixture_files,
        "challenge_v2": has_manifest,
        "baseline": baseline,
        "effective": effective,
        "baseline_sha": baseline_sha,
        "effective_sha": effective_sha,
        "baseline_ids": baseline_ids,
        "effective_ids": effective_ids,
    }


def _run_native_challenge(
    argv: list[str],
    source_root: Path,
    timeout: int,
    scratch: Path,
    runner: Callable[..., dict[str, Any]],
    report_path: Path,
    ledger_path: Path,
    expected_exit: int,
    expected_report: str,
    report_parser: Callable[[bytes], dict[str, Any]],
    engine: str,
    fixture_sha: str,
    rule_id: str,
    enabled: bool,
    ledger_required: bool = True,
) -> dict[str, Any]:
    """Execute once, then derive report evidence only from bounded native output files."""
    raw_facts = runner(argv, source_root, timeout, scratch)
    try:
        facts = _validate_runner_facts(raw_facts, timeout)
    except RuntimeAuditError:
        cleanup = (
            isinstance(raw_facts, dict) and raw_facts.get("cleanup_confirmed") is True
        )
        return {
            "state": "INCOMPLETE",
            "facts": {},
            "cleanup_confirmed": cleanup,
            "report": None,
            "raw_report_sha": None,
            "ledger_sha": None,
        }
    state = _challenge_state(facts, expected_exit)
    report = None
    raw_sha = ledger_sha = None
    if state != "INCOMPLETE":
        try:
            raw = _bounded_file(report_path, root=scratch)
            if ledger_required:
                ledger_sha = sha256_bytes(_bounded_file(ledger_path, root=scratch))
            report, raw_sha = _challenge_report(
                raw,
                report_parser,
                engine=engine,
                fixture_sha=fixture_sha,
                rule_id=rule_id,
                enabled=enabled,
            )
            if sha256_bytes(canonical_bytes(report)) != expected_report:
                state = "FAIL"
        except (RuntimeAuditError, OSError, ValueError, TypeError):
            state, report = "INCOMPLETE", None
    return {
        "state": state,
        "facts": facts,
        "cleanup_confirmed": facts["cleanup_confirmed"],
        "report": report,
        "raw_report_sha": raw_sha,
        "ledger_sha": ledger_sha,
    }


def _native_execution(
    state: str,
    facts: dict[str, Any],
    expected_exit: int,
    argv_sha: str,
    data: dict[str, Any],
    execution_bindings: dict[str, Any],
    ledger_sha: str,
    scratch_clean: bool,
    cleanup: bool | None,
    kind: str,
    rule_id: str,
    timeout: int,
) -> dict[str, Any]:
    """Build hash-sealed execution facts while labeling identity as a supplied binding."""
    mutation = None
    if kind == "mutation":
        mutation = {
            "disabled_rule_id": rule_id,
            "remaining_rule_inventory_sha256": sha256_bytes(
                canonical_bytes(sorted(data["effective_ids"]))
            ),
        }
    result = {
        "schema": "factory.native-challenge-execution.v1",
        "status": {"PASS": "VERIFIED", "FAIL": "FAILED", "INCOMPLETE": "INCOMPLETE"}[
            state
        ],
        "launched": not facts["launch_error"]
        if type(facts.get("launch_error")) is bool
        else None,
        "completed": facts["exit_code"] is not None and not facts["timed_out"]
        if type(facts.get("timed_out")) is bool and "exit_code" in facts
        else None,
        "timed_out": facts.get("timed_out")
        if type(facts.get("timed_out")) is bool
        else None,
        "cleanup_confirmed": cleanup,
        "scratch_cleanup_verified": scratch_clean,
        "timeout_seconds": timeout,
        "duration_ms": facts.get("duration_ms"),
        "exit_code": facts.get("exit_code"),
        "argv_sha256": argv_sha,
        "raw_report_sha256": data.get("raw_report_sha"),
        "stdout_sha256": facts.get("stdout_sha256"),
        "stdout_bytes": facts.get("stdout_bytes"),
        "stderr_sha256": facts.get("stderr_sha256"),
        "stderr_bytes": facts.get("stderr_bytes"),
        "fixture_sha256": data["fixture_sha"],
        "candidate_binding_sha256": execution_bindings["candidate_sha256"],
        "challenge_source_sha256": execution_bindings["challenge_source_sha256"],
        "profile_binding_sha256": execution_bindings["profile_sha256"],
        "image_binding_sha256": execution_bindings["image_sha256"],
        "tool_version": execution_bindings["tool_version"],
        "version_probe_sha256": execution_bindings["version_probe_sha256"],
        "baseline_config_sha256": data["baseline_sha"],
        "effective_config_sha256": data["effective_sha"],
        "ledger_sha256": ledger_sha,
        "mutation": mutation,
    }
    result["execution_sha256"] = sha256_bytes(canonical_bytes(result))
    return result


def _native_execution_v2(
    state,
    facts,
    expected_exit,
    argv_sha,
    data,
    bindings,
    ledger_sha,
    scratch_clean,
    cleanup,
    kind,
    rule_id,
    timeout,
    artifacts,
):
    """Seal v2 execution facts, multi-file source identity, and typed output digests."""
    mutation = None
    if kind == "mutation":
        mutation = {
            "disabled_rule_id": rule_id,
            "remaining_rule_inventory_sha256": sha256_bytes(
                canonical_bytes(sorted(data["effective_ids"]))
            ),
        }
    result = {
        "schema": "factory.native-challenge-execution.v2",
        "status": {"PASS": "VERIFIED", "FAIL": "FAILED", "INCOMPLETE": "INCOMPLETE"}[
            state
        ],
        "launched": not facts.get("launch_error")
        if type(facts.get("launch_error")) is bool
        else None,
        "completed": facts.get("exit_code") is not None and not facts.get("timed_out")
        if type(facts.get("timed_out")) is bool
        else None,
        "timed_out": facts.get("timed_out")
        if type(facts.get("timed_out")) is bool
        else None,
        "cleanup_confirmed": cleanup,
        "scratch_cleanup_verified": scratch_clean,
        "timeout_seconds": timeout,
        "duration_ms": facts.get("duration_ms"),
        "exit_code": facts.get("exit_code"),
        "argv_sha256": argv_sha,
        "raw_report_sha256": data.get("raw_report_sha"),
        "stdout_sha256": facts.get("stdout_sha256"),
        "stdout_bytes": facts.get("stdout_bytes"),
        "stderr_sha256": facts.get("stderr_sha256"),
        "stderr_bytes": facts.get("stderr_bytes"),
        "fixture_sha256": data["fixture_sha"],
        "fixture_manifest_sha256": data["fixture_manifest_sha"],
        "candidate_binding_sha256": bindings["candidate_sha256"],
        "challenge_source_sha256": bindings["challenge_source_sha256"],
        "profile_binding_sha256": bindings["profile_sha256"],
        "image_binding_sha256": bindings["image_sha256"],
        "tool_version": bindings["tool_version"],
        "version_probe_sha256": bindings["version_probe_sha256"],
        "baseline_config_sha256": data["baseline_sha"],
        "effective_config_sha256": data["effective_sha"],
        "ledger_sha256": ledger_sha,
        "native_artifacts": artifacts,
        "mutation": mutation,
    }
    result["execution_sha256"] = sha256_bytes(canonical_bytes(result))
    return result


def _challenge_kind(challenge: dict[str, Any]) -> str:
    """Require one of the signed positive, negative or detector-disabled controls."""
    kind = require_str(
        challenge.get("kind") if isinstance(challenge, dict) else None,
        "challenge kind",
        maximum=16,
    )
    if kind not in {"positive", "negative", "mutation"}:
        raise RuntimeAuditError("E_CHALLENGE_KIND", "unsupported challenge control")
    return kind


def _validate_execution_bindings(
    challenge: dict[str, Any], data: dict[str, Any], bindings: dict[str, Any]
) -> None:
    """Verify copied identity bindings and a completed, hash-bound tool version probe."""
    exact_keys(
        bindings,
        {
            "candidate_sha256",
            "challenge_source_sha256",
            "profile_sha256",
            "image_sha256",
            "tool_version",
            "version_probe_sha256",
            "version_probe_facts",
        },
    )
    for field in (
        "candidate_sha256",
        "challenge_source_sha256",
        "profile_sha256",
        "image_sha256",
    ):
        require_digest(bindings[field], field)
    require_str(bindings["tool_version"], "tool_version", maximum=128)
    version_facts = bindings["version_probe_facts"]
    version_timeout = require_int(
        version_facts.get("timeout_seconds")
        if isinstance(version_facts, dict)
        else None,
        "version timeout",
        minimum=1,
        maximum=3600,
    )
    facts = _validate_runner_facts(version_facts, version_timeout)
    if (
        facts["exit_code"] != 0
        or facts["timed_out"]
        or facts["launch_error"]
        or facts["output_limit_exceeded"]
        or facts.get("cancelled", False)
        or not facts["cleanup_confirmed"]
    ):
        raise RuntimeAuditError(
            "E_TOOLCHAIN_PROBE", "version probe execution was not clean"
        )
    if sha256_bytes(canonical_bytes(facts)) != require_digest(
        bindings["version_probe_sha256"], "version_probe_sha256"
    ):
        raise RuntimeAuditError(
            "E_TOOLCHAIN_PROBE", "version probe facts digest differs"
        )
    expected_source = sha256_bytes(canonical_bytes(data["fixture_manifest"]))
    if bindings["challenge_source_sha256"] != expected_source:
        raise RuntimeAuditError(
            "E_CHALLENGE_BINDING", "challenge-only source manifest differs"
        )


def _prepare_native_challenge(
    challenge,
    obligation_id,
    engine,
    detector_rule_id,
    detector_enabled,
    profile_argv,
    bindings,
    source_root,
    baseline_config_path,
    effective_config_path,
    report_path,
    ledger_path,
    scratch,
    scratch_parent,
    timeout_seconds,
    expected_ruleset_sha256,
    execution_bindings,
    config_rule_ids,
    verify_mutation,
    native_artifact_roles,
    native_artifacts,
    rule_ids,
    mutation_ruleset_sha256,
):
    """Validate all signed inputs and prepare the closed native command and evidence context."""
    kind = _challenge_kind(challenge)
    rule_id = require_str(detector_rule_id, "detector_rule_id", maximum=256)
    require_bool(detector_enabled, "detector_enabled")
    timeout = require_int(timeout_seconds, "timeout_seconds", minimum=1, maximum=3600)
    data = _validate_challenge(
        challenge,
        source_root,
        expected_ruleset_sha256,
        baseline_config_path,
        effective_config_path,
        rule_id,
        detector_enabled,
        kind,
        config_rule_ids,
        verify_mutation,
    )
    if data["challenge_v2"]:
        roles = _native_artifact_paths(engine, native_artifact_roles, native_artifacts)
        _validate_native_artifact_paths(
            engine, roles, scratch, report_path, ledger_path
        )
        _validate_v2_lane(
            engine,
            kind,
            rule_id,
            data["baseline_ids"],
            data["effective_sha"],
            rule_ids,
            mutation_ruleset_sha256,
        )
        data["native_artifact_paths"] = roles
    elif any(
        value is not None
        for value in (
            native_artifact_roles,
            native_artifacts,
            rule_ids,
            mutation_ruleset_sha256,
        )
    ):
        raise RuntimeAuditError(
            "E_NATIVE_ROLE", "v2 lane bindings supplied for v1 challenge"
        )
    _validate_execution_bindings(challenge, data, execution_bindings)
    scratch_parent, scratch_identity = _owned_scratch(scratch, scratch_parent)
    _validate_native_bindings(
        bindings,
        source_root,
        scratch,
        report_path,
        ledger_path,
        effective_config_path,
        execution_bindings,
    )
    argv = _render_profile_argv(profile_argv, bindings)
    expected_exit = require_int(
        challenge["expected_exit_code"], "expected_exit_code", minimum=0, maximum=255
    )
    expected_report = require_digest(
        challenge["expected_report_sha256"], "expected_report_sha256"
    )
    return locals()


def _finish_native_challenge(context, *, runner, report_parser) -> dict[str, Any]:
    """Run once, recheck mounted inputs, and preserve uncertainty through cleanup."""
    data = context["data"]
    facts = None
    cleanup = False
    run = {
        "state": "INCOMPLETE",
        "report": None,
        "raw_report_sha": None,
        "ledger_sha": None,
        "native_artifacts": None,
    }
    try:
        run = _run_native_challenge(
            context["argv"],
            context["source_root"],
            context["timeout"],
            context["scratch"],
            runner,
            context["report_path"],
            context["ledger_path"],
            context["expected_exit"],
            context["expected_report"],
            report_parser,
            context["engine"],
            data["fixture_sha"],
            context["rule_id"],
            context["detector_enabled"],
            ledger_required=(
                context["engine"] == "gitleaks" or not context["data"]["challenge_v2"]
            ),
        )
        facts, cleanup = run["facts"], run["cleanup_confirmed"]
        if facts and run["state"] != "INCOMPLETE" and context["data"]["challenge_v2"]:
            run["native_artifacts"] = _native_artifact_records(
                context["data"]["native_artifact_paths"]
            )
            _verify_artifact_anchor(context, run)
    except (RuntimeAuditError, OSError, ValueError, TypeError):
        run["state"], run["report"] = "INCOMPLETE", None
        run.setdefault("native_artifacts", None)
    if facts is not None:
        _recheck_challenge_inputs(context, run)
        if context["data"]["challenge_v2"]:
            _recheck_native_artifacts(context, run)
    scratch_clean = _clean_challenge_scratch(
        context["scratch"],
        context["scratch_parent"],
        context["scratch_identity"],
        cleanup,
    )
    if not scratch_clean:
        run["state"] = "INCOMPLETE"
    data["raw_report_sha"] = run["raw_report_sha"]
    execution_builder = (
        _native_execution_v2 if data["challenge_v2"] else _native_execution
    )
    execution = execution_builder(
        run["state"],
        facts or {},
        context["expected_exit"],
        sha256_bytes(canonical_bytes(context["argv"])),
        data,
        context["execution_bindings"],
        run["ledger_sha"],
        scratch_clean,
        cleanup,
        context["kind"],
        context["rule_id"],
        context["timeout"],
        *([run["native_artifacts"]] if data["challenge_v2"] else []),
    )
    report = run["report"]
    return {
        "obligation_id": require_str(context["obligation_id"], "obligation_id"),
        "kind": context["kind"],
        "fixture_sha256": data["fixture_sha"],
        "report": report,
        "observation_sha256": sha256_bytes(canonical_bytes(report)) if report else None,
        "exit_code": facts.get("exit_code") if facts else None,
        "execution": execution,
    }


def _recheck_challenge_inputs(context, run):
    """Mark results incomplete when the fixture tree or either config changed during execution."""
    try:
        current = _challenge_source_files(
            context["source_root"], context["data"]["fixture_manifest"]
        )
        same = current == context["data"]["fixture_files"]
        same = (
            same
            and _bounded_file(context["baseline_config_path"])
            == context["data"]["baseline"]
        )
        same = (
            same
            and _bounded_file(context["effective_config_path"])
            == context["data"]["effective"]
        )
    except (RuntimeAuditError, OSError):
        same = False
    if not same:
        run["state"], run["report"] = "INCOMPLETE", None


def _verify_artifact_anchor(context, run):
    """Ensure the parsed primary report and mandatory Gitleaks ledger match typed artifacts."""
    records = {item["kind"]: item for item in run["native_artifacts"]}
    engine = context["engine"]
    report_role = NATIVE_REPORT_ROLE[engine]
    if records[report_role]["sha256"] != run["raw_report_sha"]:
        run["state"], run["report"] = "INCOMPLETE", None
    if engine == "gitleaks":
        ledger = records["gitleaks_rule_ledger"]["sha256"]
        if ledger != run["ledger_sha"]:
            run["state"], run["report"] = "INCOMPLETE", None


def _recheck_native_artifacts(context, run):
    """Re-read all typed output artifacts before cleanup and reject post-parse drift."""
    try:
        current = _native_artifact_records(context["data"]["native_artifact_paths"])
        same = current == run["native_artifacts"]
    except (RuntimeAuditError, OSError):
        same = False
    if not same:
        run["state"], run["report"] = "INCOMPLETE", None


def _clean_challenge_scratch(
    scratch: Path, parent: Path, identity: tuple[int, int], cleanup: bool
) -> bool:
    """Delete only an owned run directory after revalidating ownership and process cleanup."""
    try:
        owner = parent.resolve(strict=True)
        target = scratch.absolute()
        if target.parent != owner or _linked_entry(owner.lstat()):
            return False
        cursor = Path(target.anchor)
        for part in target.parts[1:-1]:
            cursor = cursor / part
            if _linked_entry(cursor.lstat()):
                return False
        info = scratch.lstat()
        if _linked_entry(info) or (info.st_dev, info.st_ino) != identity:
            return False
    except OSError:
        return False
    if cleanup:
        try:
            shutil.rmtree(scratch)
        except OSError:
            return False
    return cleanup and not scratch.exists()


def execute_native_challenge(
    challenge: dict[str, Any],
    *,
    obligation_id: str,
    engine: str,
    detector_rule_id: str,
    detector_enabled: bool,
    profile_argv: list[str],
    bindings: dict[str, str],
    source_root: Path,
    baseline_config_path: Path,
    effective_config_path: Path,
    report_path: Path,
    ledger_path: Path,
    scratch: Path,
    scratch_parent: Path,
    timeout_seconds: int,
    expected_ruleset_sha256: str,
    execution_bindings: dict[str, Any],
    runner: Callable[..., dict[str, Any]],
    report_parser: Callable[[bytes], dict[str, Any]],
    config_rule_ids: Callable[[bytes], list[str]],
    verify_mutation: Callable[[bytes, bytes, str], bool],
    native_artifact_roles: list[str] | None = None,
    native_artifacts: dict[str, Path] | None = None,
    rule_ids: list[str] | None = None,
    mutation_ruleset_sha256: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run one profile-bound challenge and separate its report from execution facts."""
    context = _prepare_native_challenge(
        challenge,
        obligation_id,
        engine,
        detector_rule_id,
        detector_enabled,
        profile_argv,
        bindings,
        source_root,
        baseline_config_path,
        effective_config_path,
        report_path,
        ledger_path,
        scratch,
        scratch_parent,
        timeout_seconds,
        expected_ruleset_sha256,
        execution_bindings,
        config_rule_ids,
        verify_mutation,
        native_artifact_roles,
        native_artifacts,
        rule_ids,
        mutation_ruleset_sha256,
    )
    return _finish_native_challenge(context, runner=runner, report_parser=report_parser)
