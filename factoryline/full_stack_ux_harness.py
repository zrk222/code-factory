"""Evidence-bound full-stack engineering and ethical UX release review."""

from __future__ import annotations


import json
import os
import tempfile
from pathlib import Path, PureWindowsPath
from typing import Any
from . import utc_iso as _now
from . import canonical_json_bytes as _canonical  # noqa: F401 - module encoder contract
from . import canonical_or_bytes_sha as _sha
from . import PrefixedCodedError


MANIFEST_SCHEMA = "factory.full-stack-ux-harness.manifest.v1"
RECEIPT_SCHEMA = "factory.full-stack-ux-harness.receipt.v1"
MAX_MANIFEST_BYTES = 1_048_576
MAX_EVIDENCE_BYTES = 10_000_000
APPROVED_PROVENANCE = frozenset(
    {"human_confirmed", "trusted_source", "observed_production"}
)

CORE_CHECKS = (
    "architecture.separation_of_concerns",
    "contracts.strict_types_and_boundary_validation",
    "states.loading_empty_partial_error_recovery",
    "state.deterministic_locality",
    "performance.render_and_compute_efficiency",
    "performance.resource_loading",
    "security.no_hardcoded_secrets",
    "security.input_output_safety",
    "security.origin_and_content_policy",
    "privacy.data_minimization",
    "testing.main_journey_and_negative_states",
    "release.native_test_lint_build",
)

UI_CHECKS = (
    "ui.responsive_layout",
    "ui.keyboard_navigation",
    "ui.screen_reader_semantics",
    "ui.wcag_contrast",
    "ui.immediate_honest_feedback",
    "ui.visual_system_consistency",
    "ui.claims_and_signals_truth",
)

JUDGMENTS = (
    "truth",
    "regret",
    "transparency",
    "alignment",
    "comprehension",
    "vulnerability",
)


class FullStackUXHarnessError(PrefixedCodedError):
    """Stable refusal for a malformed or unsafe quality-harness input."""


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        unexpected = sorted(actual - expected)
        missing = sorted(expected - actual)
        raise FullStackUXHarnessError(
            "E_UX_MANIFEST_SCHEMA",
            f"{label} keys must be exact; missing={missing}, unexpected={unexpected}",
        )


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    handle, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def quality_harness_template(*, ui_in_scope: bool) -> dict[str, Any]:
    """Return the closed manifest shape without claiming that any check passed."""
    check_ids = [*CORE_CHECKS, *UI_CHECKS] if ui_in_scope else list(CORE_CHECKS)
    return {
        "schema": MANIFEST_SCHEMA,
        "ui_in_scope": ui_in_scope,
        "checks": [
            {
                "id": check_id,
                "state": "unknown",
                "provenance": "agent_proposed",
                "evidence": [],
            }
            for check_id in check_ids
        ],
        "reviewer": {"name": "", "type": "unassigned"},
        "judgments": [
            {"id": judgment_id, "approved": False, "rationale": ""}
            for judgment_id in JUDGMENTS
        ],
    }


def write_quality_harness_template(
    root: Path, out: Path, *, ui_in_scope: bool
) -> dict[str, Any]:
    """Write one template inside the workspace without overwriting existing work."""
    workspace = Path(root).resolve()
    destination = Path(out) if Path(out).is_absolute() else workspace / out
    destination = destination.resolve()
    try:
        destination.relative_to(workspace)
    except ValueError as exc:
        raise FullStackUXHarnessError(
            "E_UX_MANIFEST_PATH", "template must stay inside the workspace"
        ) from exc
    if destination.exists():
        raise FullStackUXHarnessError(
            "E_UX_MANIFEST_EXISTS", f"refusing to replace {destination}"
        )
    payload = quality_harness_template(ui_in_scope=ui_in_scope)
    _atomic_json(destination, payload)
    return {**payload, "path": str(destination)}


def _load_manifest(root: Path, path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    workspace = root.resolve()
    source = path if path.is_absolute() else workspace / path
    source = source.resolve()
    try:
        relative = source.relative_to(workspace)
    except ValueError as exc:
        raise FullStackUXHarnessError(
            "E_UX_MANIFEST_PATH", "manifest must stay inside the workspace"
        ) from exc
    try:
        data = source.read_bytes()
    except OSError as exc:
        raise FullStackUXHarnessError(
            "E_UX_MANIFEST_MISSING", f"cannot read manifest: {relative.as_posix()}"
        ) from exc
    if not data or len(data) > MAX_MANIFEST_BYTES:
        raise FullStackUXHarnessError(
            "E_UX_MANIFEST_SIZE",
            f"manifest must contain 1 to {MAX_MANIFEST_BYTES} bytes",
        )
    try:
        value = json.loads(data.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise FullStackUXHarnessError(
            "E_UX_MANIFEST_JSON", "manifest must be valid UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict) or value.get("schema") != MANIFEST_SCHEMA:
        raise FullStackUXHarnessError(
            "E_UX_MANIFEST_SCHEMA", f"manifest must use {MANIFEST_SCHEMA}"
        )
    _require_exact_keys(
        value, {"schema", "ui_in_scope", "checks", "reviewer", "judgments"}, "manifest"
    )
    return value, {
        "path": relative.as_posix(),
        "sha256": _sha(data),
        "bytes": len(data),
    }


def _evidence_binding(root: Path, value: object, check_id: str) -> dict[str, Any]:
    if not isinstance(value, str) or not value.strip():
        raise FullStackUXHarnessError(
            "E_UX_EVIDENCE_PATH", f"{check_id} evidence must be a relative path"
        )
    relative = Path(value)
    if relative.is_absolute() or PureWindowsPath(value).drive or ".." in relative.parts:
        raise FullStackUXHarnessError(
            "E_UX_EVIDENCE_PATH", f"{check_id} evidence must stay inside the workspace"
        )
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise FullStackUXHarnessError(
            "E_UX_EVIDENCE_PATH", f"{check_id} evidence escapes the workspace"
        ) from exc
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise FullStackUXHarnessError(
            "E_UX_EVIDENCE_MISSING",
            f"{check_id} evidence is missing: {relative.as_posix()}",
        ) from exc
    if not data or len(data) > MAX_EVIDENCE_BYTES:
        raise FullStackUXHarnessError(
            "E_UX_EVIDENCE_SIZE",
            f"{check_id} evidence must contain 1 to {MAX_EVIDENCE_BYTES} bytes",
        )
    return {"path": relative.as_posix(), "sha256": _sha(data), "bytes": len(data)}


def _check_set_expected(manifest: dict[str, Any]) -> tuple[set[str], list[Any]]:
    checks = manifest.get("checks")
    ui_in_scope = manifest.get("ui_in_scope")
    if not isinstance(ui_in_scope, bool) or not isinstance(checks, list):
        raise FullStackUXHarnessError(
            "E_UX_MANIFEST_SCHEMA",
            "ui_in_scope must be boolean and checks must be an array",
        )
    expected = set(CORE_CHECKS) | (set(UI_CHECKS) if ui_in_scope else set())
    return expected, checks


def _check_set_matches(checks: list[Any], expected: set[str]) -> bool:
    ids = [item.get("id") for item in checks if isinstance(item, dict)]
    return (
        len(checks) == len(expected)
        and len(ids) == len(checks)
        and set(ids) == expected
        and len(set(ids)) == len(ids)
    )


def _check_set_mismatch(expected: set[str]) -> dict[str, str]:
    return {
        "code": "E_UX_CHECK_SET_MISMATCH",
        "detail": f"expected exactly {len(expected)} closed check identifiers",
    }


def _check_entry(
    root: Path, item: dict[str, Any]
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    findings: list[dict[str, str]] = []
    check_id = item["id"]
    _require_exact_keys(
        item, {"id", "state", "provenance", "evidence"}, f"check {check_id}"
    )
    state, provenance, evidence = (
        item.get("state"),
        item.get("provenance"),
        item.get("evidence"),
    )
    if state != "passed":
        findings.append({"code": "E_UX_CHECK_NOT_PASSED", "detail": check_id})
    if provenance not in APPROVED_PROVENANCE:
        findings.append({"code": "E_UX_CHECK_PROVENANCE", "detail": check_id})
    bindings, evidence_findings = _check_evidence(root, evidence, check_id)
    findings.extend(evidence_findings)
    return findings, {
        "id": check_id,
        "state": state,
        "provenance": provenance,
        "evidence": bindings,
    }


def _check_evidence(
    root: Path, evidence: object, check_id: str
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= 16:
        return [], [{"code": "E_UX_CHECK_EVIDENCE_INCOMPLETE", "detail": check_id}]
    findings: list[dict[str, str]] = []
    string_evidence = [path for path in evidence if isinstance(path, str)]
    if len(set(string_evidence)) != len(string_evidence):
        findings.append({"code": "E_UX_CHECK_EVIDENCE_DUPLICATE", "detail": check_id})
    return [_evidence_binding(root, path, check_id) for path in evidence], findings


def _check_findings(
    root: Path, manifest: dict[str, Any]
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    expected, checks = _check_set_expected(manifest)
    if not _check_set_matches(checks, expected):
        return [_check_set_mismatch(expected)], []
    bound_checks: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    for item in sorted(checks, key=lambda candidate: candidate["id"]):
        item_findings, bound_check = _check_entry(root, item)
        findings.extend(item_findings)
        bound_checks.append(bound_check)
    return findings, bound_checks


def _judgment_schema(manifest: dict[str, Any]) -> tuple[dict[str, Any], list[Any]]:
    reviewer, judgments = manifest.get("reviewer"), manifest.get("judgments")
    if not isinstance(reviewer, dict) or not isinstance(judgments, list):
        raise FullStackUXHarnessError(
            "E_UX_MANIFEST_SCHEMA", "reviewer and judgments are required"
        )
    _require_exact_keys(reviewer, {"name", "type"}, "reviewer")
    return reviewer, judgments


def _judgment_set_matches(judgments: list[Any]) -> bool:
    ids = [item.get("id") for item in judgments if isinstance(item, dict)]
    return (
        len(judgments) == len(JUDGMENTS)
        and len(ids) == len(judgments)
        and set(ids) == set(JUDGMENTS)
        and len(set(ids)) == len(ids)
    )


def _judgment_entry(
    item: dict[str, Any],
) -> tuple[dict[str, str] | None, dict[str, Any]]:
    _require_exact_keys(item, {"id", "approved", "rationale"}, f"judgment {item['id']}")
    rationale = item.get("rationale")
    approved = item.get("approved") is True
    if (
        not approved
        or not isinstance(rationale, str)
        or not 12 <= len(rationale.strip()) <= 1000
    ):
        finding = {"code": "E_UX_HUMAN_REVIEW_REQUIRED", "detail": item["id"]}
    else:
        finding = None
    return finding, {
        "id": item["id"],
        "approved": approved,
        "rationale": rationale.strip() if isinstance(rationale, str) else "",
    }


def _judgment_findings(
    manifest: dict[str, Any],
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    findings: list[dict[str, str]] = []
    reviewer, judgments = _judgment_schema(manifest)
    name = reviewer.get("name")
    reviewer_type = reviewer.get("type")
    if not isinstance(name, str) or not name.strip() or reviewer_type != "human":
        findings.append(
            {
                "code": "E_UX_HUMAN_REVIEW_REQUIRED",
                "detail": "one named human reviewer is required",
            }
        )
    if not _judgment_set_matches(judgments):
        findings.append(
            {
                "code": "E_UX_JUDGMENT_SET_MISMATCH",
                "detail": "exactly six closed judgments are required",
            }
        )
        return findings, {
            "name": name if isinstance(name, str) else "",
            "type": reviewer_type,
            "judgments": [],
        }
    normalized = []
    for item in sorted(judgments, key=lambda candidate: candidate["id"]):
        finding, normalized_item = _judgment_entry(item)
        if finding:
            findings.append(finding)
        normalized.append(normalized_item)
    return findings, {
        "name": name.strip() if isinstance(name, str) else "",
        "type": reviewer_type,
        "judgments": normalized,
    }


def verify_quality_harness(
    root: Path,
    manifest_path: Path,
    *,
    out: Path | None = None,
    visual_receipt: Path | None = None,
) -> dict[str, Any]:
    """Verify declared evidence and human judgment; never execute checks or release work."""
    workspace = Path(root).resolve()
    manifest, source = _load_manifest(workspace, Path(manifest_path))
    check_findings, checks = _check_findings(workspace, manifest)
    judgment_findings, review = _judgment_findings(manifest)
    findings = [*check_findings, *judgment_findings]
    optical = None
    if visual_receipt is not None:
        optical = verify_visual_behavior_receipt(workspace, visual_receipt)
        if optical["decision"] != "PASS":
            findings.append(
                {"code": "E_UX_VISUAL_INCOMPLETE", "detail": optical["decision"]}
            )
    decision = "READY_FOR_HUMAN_RELEASE_REVIEW" if not findings else "BLOCKED"
    core = {
        "schema": RECEIPT_SCHEMA,
        "source": source,
        "ui_in_scope": manifest.get("ui_in_scope"),
        "decision": decision,
        "checks": checks,
        "review": review,
        "findings": findings,
        "evidence_classes": {
            "deterministic": "file presence, byte size, digest, closed check set, state, and provenance",
            "heuristic": "six named human interaction judgments with recorded rationale",
        },
        "review_identity": {
            "authenticated": False,
            "boundary": "The local reviewer name and type are declared metadata, not authenticated identity.",
        },
        "authority": {
            "execution": False,
            "source_modification": False,
            "approval": False,
            "deployment": False,
            "publication": False,
            "signing": False,
            "credential_access": False,
            "provider_access": False,
            "connector_access": False,
            "messaging": False,
        },
        "claim_boundary": "Local evidence binding plus declared human judgment is not authenticated identity, certification, or measured accessibility, security, conversion, or production-fitness proof. Run the named native tools and preserve release-owner approval.",
    }
    if optical is not None:
        core["visual_evidence"] = {
            "receipt_sha256": optical["receipt_sha256"],
            "decision": optical["decision"],
            "path": str(visual_receipt),
        }
    receipt = {**core, "receipt_sha256": _sha(core), "generated_at": _now()}
    destination = _quality_receipt_destination(workspace, manifest_path, optical, out)
    _atomic_json(destination, receipt)
    return {**receipt, "path": str(destination)}


def _quality_receipt_destination(workspace, manifest_path, optical, out):
    """Resolve the output below the workspace and protect both evidence inputs."""
    manifest_source = (workspace / Path(manifest_path)).resolve()
    destination = (
        Path(out)
        if out
        else workspace
        / ".factory"
        / "quality-harness"
        / f"{Path(manifest_path).stem}.receipt.json"
    )
    if not destination.is_absolute():
        destination = workspace / destination
    destination = destination.resolve()
    try:
        destination.relative_to(workspace)
    except ValueError as exc:
        raise FullStackUXHarnessError(
            "E_UX_RECEIPT_PATH", "receipt must stay inside the workspace"
        ) from exc
    if destination == manifest_source or (
        optical is not None and destination == Path(optical["path"])
    ):
        raise FullStackUXHarnessError(
            "E_UX_RECEIPT_PATH",
            "receipt destination must differ from its inputs",
        )
    return destination


def run_visual_behavior_gate(
    root, contract_path, contract_sha256, *, execute=False, out=None
) -> dict[str, Any]:
    """Execute only the pinned, local visual contract in an owned child process."""
    import sys
    import time
    from .assembly_process import run_cli_detailed

    workspace = Path(root).resolve()
    contract, binding = _visual_contract(workspace, contract_path, contract_sha256)
    parent = workspace / ".factory" / "visual-behavior"
    parent.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
    destination = _visual_destination(workspace, out or directory / "receipt.json")
    core = {
        "schema": "factory.visual-behavior.receipt.v1",
        "contract": binding,
        "candidate": contract["candidate"],
        "decision": "NOT_RUN",
        "execution": None,
        "identity": {"source_sha256": _visual_source_identity()},
        "cases": [],
        "findings": [],
        "artifacts": [],
        "prestige": None,
        "deadline_seconds": 60,
        "authority": {"release": False, "approval": False, "publication": False},
        "claim_boundary": "Local browser measurements in a bounded process, not kernel isolation, exhaustive accessibility, database commit truth or release approval.",
    }
    if execute:
        try:
            _visual_tool_identity()
            script = (
                "import sys;sys.path.insert(0,sys.argv[1]);"
                "from factoryline.full_stack_ux_harness import _visual_child;"
                "_visual_child(*sys.argv[2:])"
            )
            args = [
                "-I",
                "-B",
                "-c",
                script,
                str(Path(__file__).resolve().parent.parent),
                str(workspace),
                str(workspace / binding["path"]),
                contract_sha256,
                str(directory),
            ]
            started = time.monotonic()
            facts = run_cli_detailed(
                sys.executable, args, workspace, timeout=60, max_stream_bytes=65536
            )
            core["execution"] = {
                key: value
                for key, value in facts.items()
                if key not in {"stdout", "stderr", "output"}
            }
            core["execution"].update(
                duration_ms=int((time.monotonic() - started) * 1000),
                deadline_seconds=60,
                argv_sha256=_sha([sys.executable, *args]),
                stdout_sha256=_sha(facts["stdout"]),
                stderr_sha256=_sha(facts["stderr"]),
            )
            result_path = directory / "observations.json"
            observed = _visual_read(result_path)
            core.update(
                {
                    key: observed[key]
                    for key in (
                        "identity",
                        "cases",
                        "artifacts",
                        "prestige",
                        "findings",
                    )
                }
            )
            core["artifacts"].append(
                _visual_artifact(workspace, result_path, "observations")
            )
            core["findings"].extend(
                _visual_current_findings(workspace, contract, binding)
            )
            core["findings"].extend(_visual_process_findings(core["execution"]))
            core["decision"] = _visual_decision(core["findings"])
        except (ImportError, OSError, ValueError, KeyError, TypeError) as error:
            core["decision"] = "INCOMPLETE"
            core["artifacts"] = _visual_partial_artifacts(workspace, directory)
            core["findings"].append(
                _visual_finding(
                    "E_VISUAL_EXECUTION", type(error).__name__, incomplete=True
                )
            )
    receipt = {**core, "receipt_sha256": _sha(core)}
    _visual_write(destination, receipt)
    return {**receipt, "path": str(destination)}


def verify_visual_behavior_receipt(root, receipt_path) -> dict[str, Any]:
    """Recompute current bindings and detector outcomes without starting a browser."""
    workspace = Path(root).resolve()
    source = _visual_path(workspace, receipt_path)
    receipt = _visual_read(source)
    _visual_keys(
        receipt,
        "schema contract candidate decision execution identity cases findings artifacts prestige deadline_seconds authority claim_boundary receipt_sha256",
    )
    core = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if receipt.get("schema") != "factory.visual-behavior.receipt.v1" or _sha(
        core
    ) != receipt.get("receipt_sha256"):
        raise FullStackUXHarnessError("E_VISUAL_RECEIPT", "receipt identity differs")
    contract, binding = _visual_contract(
        workspace, receipt["contract"]["path"], receipt["contract"]["sha256"]
    )
    findings = _visual_current_findings(workspace, contract, binding)
    findings.extend(_visual_receipt_artifacts(workspace, receipt))
    if (
        receipt["candidate"] != contract["candidate"]
        or receipt["identity"].get("source_sha256") != _visual_source_identity()
    ):
        findings.append(
            _visual_finding(
                "E_VISUAL_SOURCE_DRIFT", "candidate or harness changed", incomplete=True
            )
        )
    if receipt["decision"] == "NOT_RUN":
        return {
            **receipt,
            "decision": "INCOMPLETE" if findings else "NOT_RUN",
            "findings": findings,
            "path": str(source),
        }
    findings.extend(_visual_process_findings(receipt["execution"]))
    findings.extend(_visual_profile_findings(contract, receipt["identity"]))
    findings.extend(
        _visual_cases_findings(workspace, contract["cases"], receipt["cases"])
    )
    findings.extend(_visual_prestige_findings(receipt["prestige"], contract["design"]))
    findings.extend(
        _visual_prestige_replay(workspace, contract["design"], receipt["prestige"])
    )
    findings.extend(receipt["findings"])
    return {
        **receipt,
        "decision": _visual_decision(findings),
        "findings": findings,
        "path": str(source),
    }


def _visual_prestige_replay(root, design, recorded):
    if design is None:
        return []
    try:
        if _visual_prestige(root, design) == recorded:
            return []
    except ImportError:
        return [
            _visual_finding(
                "E_VISUAL_PRESTIGE", "Prestige unavailable", incomplete=True
            )
        ]
    return [
        _visual_finding(
            "E_VISUAL_PRESTIGE_DRIFT", "companion evidence differs", incomplete=True
        )
    ]


def _visual_cases_findings(root, expected, observed):
    findings = []
    if len(expected) != len(observed):
        findings.append(
            _visual_finding(
                "E_VISUAL_CAPTURE", "required cases missing", incomplete=True
            )
        )
    for case, observation in zip(expected, observed):
        findings.extend(_visual_case_findings(root, case, observation))
    return findings


def _visual_path(root, value):
    path = Path(value)
    if not path.is_absolute() and (
        PureWindowsPath(str(value)).drive or ".." in path.parts
    ):
        raise FullStackUXHarnessError("E_VISUAL_PATH", "unsafe workspace path")
    resolved = (root / path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise FullStackUXHarnessError(
            "E_VISUAL_PATH", "path escapes workspace"
        ) from error
    return resolved


def _visual_destination(root, value):
    path = _visual_path(root, value)
    if path.exists():
        raise FullStackUXHarnessError("E_VISUAL_EXISTS", "outputs must be fresh")
    return path


def _visual_read(path):
    raw = _visual_bounded_bytes(Path(path))
    if not raw or len(raw) > MAX_EVIDENCE_BYTES:
        raise FullStackUXHarnessError("E_VISUAL_SIZE", "bounded nonempty JSON required")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise FullStackUXHarnessError("E_VISUAL_SCHEMA", "duplicate JSON key")
            result[key] = value
        return result

    return json.loads(
        raw,
        object_pairs_hook=pairs,
        parse_constant=lambda value: _visual_bad("nonfinite JSON"),
    )


def _visual_bad(message):
    raise FullStackUXHarnessError("E_VISUAL_SCHEMA", message)


def _visual_keys(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys.split()):
        _visual_bad("unexpected fields")


def _visual_text(value, maximum=512):
    if (
        not isinstance(value, str)
        or not 1 <= len(value.strip()) <= maximum
        or "\x00" in value
    ):
        _visual_bad("bounded nonempty text required")


def _visual_number(value, low, high, *, integer=True):
    import math

    if (
        isinstance(value, bool)
        or not isinstance(value, int if integer else (int, float))
        or not math.isfinite(value)
        or not low <= value <= high
    ):
        _visual_bad("number outside reviewed bounds")


def _visual_binding(root, binding, *, missing=False):
    import re

    if not isinstance(binding, dict) or set(binding) not in (
        {"path", "sha256"},
        {"path", "sha256", "kind"},
    ):
        _visual_bad("file binding required")
    _visual_text(binding["path"])
    if Path(binding["path"]).is_absolute() or PureWindowsPath(binding["path"]).drive:
        _visual_bad("binding paths must be relative")
    if not isinstance(binding["sha256"], str) or not re.fullmatch(
        "[0-9a-f]{64}", binding["sha256"]
    ):
        _visual_bad("lowercase SHA-256 required")
    path = _visual_path(root, binding["path"])
    if missing and not path.exists():
        return path
    if _sha(_visual_bounded_bytes(path)) != binding["sha256"]:
        raise FullStackUXHarnessError("E_VISUAL_SOURCE_DRIFT", binding["path"])
    return path


def _visual_origin(url):
    from urllib.parse import urlsplit

    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        _visual_bad("only credential-free loopback HTTP targets allowed")
    return parsed.scheme, parsed.hostname, parsed.port or 80


def _visual_contract(root, path, pin):
    source = _visual_path(root, path)
    raw = _visual_bounded_bytes(source)
    if _sha(raw) != pin:
        raise FullStackUXHarnessError("E_VISUAL_CONTRACT_PIN", "contract pin differs")
    value = _visual_read(source)
    _visual_keys(
        value,
        "schema project_id journey_id fixture_only candidate reviewer target browser design cases",
    )
    if value["schema"] != "factory.visual-behavior.contract.v1":
        _visual_bad("unsupported visual contract")
    if value["fixture_only"] is not True:
        _visual_bad("explicit non-sensitive local fixture admission required")
    for key in ("project_id", "journey_id"):
        _visual_text(value[key], 128)
    _visual_keys(value["reviewer"], "name type")
    _visual_text(value["reviewer"]["name"], 128)
    if value["reviewer"]["type"] != "human":
        _visual_bad("named human reviewer required")
    _visual_origin(value["target"])
    _visual_contract_files(root, value)
    _visual_browser_contract(value["browser"])
    _visual_list(value["cases"], 1, 8)
    for case in value["cases"]:
        _visual_case_contract(root, case)
    if len({case["id"] for case in value["cases"]}) != len(value["cases"]):
        _visual_bad("duplicate case")
    return value, {
        "path": source.relative_to(root).as_posix(),
        "sha256": pin,
        "bytes": len(raw),
    }


def _visual_list(value, low, high):
    if not isinstance(value, list) or not low <= len(value) <= high:
        _visual_bad("list outside declared bounds")


def _visual_contract_files(root, value):
    _visual_list(value["candidate"], 1, 128)
    for binding in value["candidate"]:
        _visual_keys(binding, "path sha256 kind")
        _visual_text(binding["kind"], 128)
        _visual_binding(root, binding)
    if len({item["path"] for item in value["candidate"]}) != len(value["candidate"]):
        _visual_bad("duplicate candidate")
    design = value["design"]
    if design is not None:
        _visual_keys(design, "contract html css")
        _visual_list(design["css"], 0, 16)
        for binding in [design["contract"], design["html"], *design["css"]]:
            _visual_binding(root, binding)


def _visual_browser_contract(browser):
    import sys

    _visual_keys(browser, "executable version platform width height")
    for key in ("executable", "version", "platform"):
        _visual_text(browser[key])
    if (
        not Path(browser["executable"]).is_absolute()
        or browser["platform"] != sys.platform
    ):
        _visual_bad("absolute operator browser and current platform required")
    _visual_number(browser["width"], 320, 1920)
    _visual_number(browser["height"], 320, 1080)


def _visual_case_contract(root, case):
    _visual_keys(
        case,
        "id baseline action element state response tokens timeout_ms max_changed_ratio",
    )
    _visual_text(case["id"], 128)
    _visual_number(case["timeout_ms"], 50, 10000)
    _visual_number(case["max_changed_ratio"], 0, 0.01, integer=False)
    if case["baseline"] is not None:
        _visual_binding(root, case["baseline"], missing=True)
    _visual_keys(case["element"], "selector role name enabled")
    for key in ("selector", "role", "name"):
        _visual_text(case["element"][key])
    if type(case["element"]["enabled"]) is not bool:
        _visual_bad("enabled must be boolean")
    _visual_keys(case["state"], "selector text")
    for field in case["state"].values():
        _visual_text(field)
    _visual_action_contract(case)
    _visual_list(case["tokens"], 0, 32)
    for token in case["tokens"]:
        _visual_token_contract(token)


def _visual_action_contract(case):
    from urllib.parse import urlsplit

    if case["action"] is not None:
        _visual_keys(case["action"], "selector")
        _visual_text(case["action"]["selector"])
    response = case["response"]
    if response is None:
        return
    _visual_keys(response, "method path status field value correlation")
    _visual_keys(response["correlation"], "header value")
    for value in response["correlation"].values():
        _visual_text(value, 128)
    import re

    if not re.fullmatch(r"[A-Za-z0-9-]{1,128}", response["correlation"]["header"]):
        _visual_bad("correlation header must be a simple HTTP field name")
    if case["action"] is None or response["method"] not in {
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }:
        _visual_bad("response requires one admitted click")
    _visual_text(response["path"])
    parsed = urlsplit(response["path"])
    if (
        not response["path"].startswith("/")
        or parsed.netloc
        or parsed.fragment
        or parsed.scheme
    ):
        _visual_bad("response path must be origin-relative")
    _visual_number(response["status"], 100, 599)
    _visual_text(response["field"], 128)
    if response["value"] is not None and not isinstance(
        response["value"], (str, int, float, bool)
    ):
        _visual_bad("response value must be JSON scalar")


def _visual_token_contract(token):
    import re

    _visual_keys(token, "selector property value")
    for value in token.values():
        _visual_text(value)
    allowed = {
        "color",
        "background-color",
        "font-family",
        "font-size",
        "font-weight",
        "line-height",
        "border-radius",
    }
    if token["property"] not in allowed and not re.fullmatch(
        r"--[A-Za-z0-9_-]{1,128}", token["property"]
    ):
        _visual_bad("unsupported computed style")


def _visual_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        stream.write(
            json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)
        )


def _visual_source_identity():
    return _sha(Path(__file__).read_bytes())


def _visual_tool_identity():
    import importlib.metadata
    import sys
    import PIL

    return {
        "playwright": importlib.metadata.version("playwright"),
        "pillow": PIL.__version__,
        "python": sys.version,
        "source_sha256": _visual_source_identity(),
    }


def _visual_finding(code, detail, *, case_id=None, incomplete=False):
    return {
        "code": code,
        "detail": str(detail)[:512],
        "case_id": case_id,
        "outcome": "INCOMPLETE" if incomplete else "FAIL",
    }


def _visual_decision(findings):
    outcomes = {item["outcome"] for item in findings}
    return "INCOMPLETE" if "INCOMPLETE" in outcomes else "FAIL" if outcomes else "PASS"


def _visual_artifact(root, path, kind):
    path = _visual_path(root, path)
    raw = _visual_bounded_bytes(path)
    if not raw or len(raw) > MAX_EVIDENCE_BYTES:
        _visual_bad("artifact outside size limit")
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": _sha(raw),
        "bytes": len(raw),
        "kind": kind,
    }


def _visual_current_findings(root, contract, binding):
    try:
        _visual_contract(root, binding["path"], binding["sha256"])
        return []
    except (OSError, ValueError):
        return [
            _visual_finding(
                "E_VISUAL_SOURCE_DRIFT",
                "bound bytes changed during capture",
                incomplete=True,
            )
        ]


def _visual_process_findings(facts):
    if (
        not isinstance(facts, dict)
        or facts.get("ok") is not True
        or "reason" not in facts
        or facts.get("exit_code") != 0
        or facts.get("cleanup_confirmed") is not True
        or facts.get("streams_closed") is not True
    ):
        return [
            _visual_finding(
                "E_VISUAL_PROCESS", "execution or cleanup unconfirmed", incomplete=True
            )
        ]
    bad = any(
        facts.get(key)
        for key in ("timed_out", "launch_error", "output_limit_exceeded", "cancelled")
    )
    bad = (
        bad
        or facts.get("reason") is not None
        or facts.get("deadline_seconds") != 60
        or not 0 <= facts.get("duration_ms", -1) <= 60000
    )
    return (
        [
            _visual_finding(
                "E_VISUAL_PROCESS", "bounded runner did not finish", incomplete=True
            )
        ]
        if bad
        else []
    )


def _visual_child(root, contract_path, pin, directory):
    from .candidate_lineage import _sha_file
    from playwright.sync_api import sync_playwright

    workspace, output = Path(root).resolve(), Path(directory).resolve()
    contract, _ = _visual_contract(workspace, contract_path, pin)
    identity = _visual_tool_identity()
    executable = Path(contract["browser"]["executable"])
    identity["executable_sha256"] = _sha_file(executable)
    observations, artifacts, findings = [], [], []
    with sync_playwright() as tools:
        browser = tools.chromium.launch(executable_path=str(executable), headless=True)
        try:
            identity["browser"] = browser.version
            identity["platform"] = contract["browser"]["platform"]
            identity["viewport"] = {
                key: contract["browser"][key] for key in ("width", "height")
            }
            if browser.version != contract["browser"]["version"]:
                findings.append(
                    _visual_finding("E_VISUAL_PROFILE", "browser version differs")
                )
            for index, case in enumerate(contract["cases"]):
                observed = _visual_capture(
                    browser, workspace, output, contract, case, index
                )
                observations.append(observed)
                artifacts.extend(observed["artifacts"])
                findings.extend(_visual_case_findings(workspace, case, observed))
        finally:
            browser.close()
    prestige = _visual_prestige(workspace, contract["design"])
    findings.extend(_visual_prestige_findings(prestige, contract["design"]))
    _visual_write(
        output / "observations.json",
        {
            "identity": identity,
            "cases": observations,
            "artifacts": artifacts,
            "findings": findings,
            "prestige": prestige,
        },
    )


def _visual_capture(browser, root, output, contract, case, index):
    import time

    settings = contract["browser"]
    context = browser.new_context(
        viewport={key: settings[key] for key in ("width", "height")},
        device_scale_factor=1,
        color_scheme="light",
        locale="en-US",
        timezone_id="UTC",
        service_workers="block",
    )
    started = time.monotonic()
    deadline = started + case["timeout_ms"] / 1000
    context.route(
        "**/*", lambda route: _visual_route(route, contract["target"], deadline)
    )
    context.route_web_socket("**/*", lambda socket: socket.close())
    page = context.new_page()
    observed = {"id": case["id"], "artifacts": [], "capture_error": None}
    responses = []
    try:
        page.goto(
            contract["target"],
            wait_until="domcontentloaded",
            timeout=_visual_budget(page, deadline),
        )
        _visual_budget(page, deadline)
        observed["before_action"] = _visual_element(page, case)
        observed["action_identity"] = _visual_action_identity(page, case)
        if observed["action_identity"]:
            observed.update(
                _visual_action(page, case, contract["target"], deadline, responses)
            )
        _visual_budget(page, deadline)
        observed.update(_visual_element(page, case))
        _visual_budget(page, deadline)
        observed["tokens"] = [_visual_style(page, token) for token in case["tokens"]]
    except Exception as error:
        observed["capture_error"] = type(error).__name__
    finally:
        try:
            screenshot = output / f"case-{index}.png"
            page.screenshot(
                path=str(screenshot),
                animations="disabled",
                timeout=_visual_budget(page, deadline),
            )
            observed["screenshot"] = _visual_artifact(root, screenshot, "screenshot")
            observed["artifacts"].append(observed["screenshot"])
            snapshot = output / f"case-{index}.accessibility.json"
            _visual_write(
                snapshot,
                {
                    "snapshot": page.locator("body").aria_snapshot(
                        timeout=_visual_budget(page, deadline)
                    )
                },
            )
            observed["artifacts"].append(
                _visual_artifact(root, snapshot, "accessibility")
            )
        except Exception as error:
            observed["capture_error"] = type(error).__name__
        finally:
            observed["response_count"] = len(responses)
            if len(responses) == 1:
                try:
                    observed["response"] = _visual_response_observation(
                        responses[0], case["response"]
                    )
                    _visual_budget(page, deadline)
                except Exception as error:
                    observed["capture_error"] = type(error).__name__
            context.close()
    observed["duration_ms"] = int((time.monotonic() - started) * 1000)
    observed["timed_out"] = (
        observed.get("timed_out", False) or observed["duration_ms"] > case["timeout_ms"]
    )
    return observed


def _visual_route(route, target, deadline):
    import time
    from urllib.parse import urlsplit
    from playwright.sync_api import Error as BrowserError

    parsed = urlsplit(route.request.url)
    origin = parsed.scheme, parsed.hostname, parsed.port or 80
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining < 1 or origin != _visual_origin(target):
        route.abort("blockedbyclient")
        return
    # Playwright routes only the initial request in a redirect chain.
    try:
        response = route.fetch(max_redirects=0, timeout=remaining)
    except BrowserError:
        route.abort("failed")
        return
    try:
        if 300 <= response.status < 400 and "location" in response.headers:
            route.abort("blockedbyclient")
        else:
            route.fulfill(response=response)
    finally:
        response.dispose()


def _visual_budget(page, deadline):
    import time
    from playwright.sync_api import TimeoutError as BrowserTimeout

    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining < 1:
        raise BrowserTimeout("case deadline exhausted")
    page.set_default_timeout(remaining)
    return remaining


def _visual_action_identity(page, case):
    if case["action"] is None:
        return True
    element = case["element"]
    source = page.locator(element["selector"])
    match = source.and_(
        page.get_by_role(element["role"], name=element["name"], exact=True)
    )
    return (
        source.count() == 1
        and match.count() == 1
        and source.is_visible()
        and source.is_enabled() is element["enabled"]
        and source.and_(page.locator(case["action"]["selector"])).count() == 1
    )


def _visual_action(page, case, target, deadline, responses):
    from playwright.sync_api import TimeoutError as BrowserTimeout, expect

    result = {
        "response": None,
        "state_text": None,
        "state_count": 0,
        "state_visible": False,
        "timed_out": False,
    }
    try:
        _visual_click(page, case, target, deadline, responses)
        state = page.locator(case["state"]["selector"])
        expect(state).to_have_text(
            case["state"]["text"], timeout=_visual_budget(page, deadline)
        )
        result.update(
            state_text=state.inner_text(),
            state_count=state.count(),
            state_visible=state.is_visible(),
        )
    except BrowserTimeout:
        result["timed_out"] = True
    except AssertionError:
        result["timed_out"] = True
    return result


def _visual_click(page, case, target, deadline, responses):
    from urllib.parse import urlsplit

    if case["action"] is None:
        return
    control = page.locator(case["element"]["selector"]).and_(
        page.locator(case["action"]["selector"])
    )
    if case["response"] is None:
        control.click(timeout=_visual_budget(page, deadline))
        return
    expected = case["response"]

    def matches(response):
        parsed = urlsplit(response.url)
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        return (
            (parsed.scheme, parsed.hostname, parsed.port or 80)
            == _visual_origin(target)
            and path == expected["path"]
            and response.request.method == expected["method"]
        )

    page.on(
        "response",
        lambda response: responses.append(response) if matches(response) else None,
    )
    with page.expect_response(matches, timeout=_visual_budget(page, deadline)):
        control.click(timeout=_visual_budget(page, deadline))


def _visual_response_observation(response, expected):
    headers = response.headers
    length = headers.get("content-length", "")
    if (
        not length.isdecimal()
        or not 1 <= int(length) <= MAX_EVIDENCE_BYTES
        or "transfer-encoding" in headers
        or "content-encoding" in headers
    ):
        _visual_bad("response requires bounded plain Content-Length framing")
    raw = response.body()
    if len(raw) != int(length) or len(raw) > MAX_EVIDENCE_BYTES:
        _visual_bad("response body length differs")
    payload = json.loads(
        raw, parse_constant=lambda value: _visual_bad("nonfinite response JSON")
    )
    present = isinstance(payload, dict) and expected["field"] in payload
    return {
        "method": response.request.method,
        "path": expected["path"],
        "status": response.status,
        "field_present": present,
        "value_sha256": _sha(payload[expected["field"]]) if present else None,
        "correlation_sha256": _sha(
            response.request.header_value(expected["correlation"]["header"])
        ),
    }


def _visual_element(page, case):
    expected = case["element"]
    element = page.locator(expected["selector"])
    count = element.count()
    return {
        "element_count": count,
        "visible": count == 1 and element.is_visible(),
        "enabled": element.is_enabled() if count == 1 else None,
        "accessible_matches": element.and_(
            page.get_by_role(expected["role"], name=expected["name"], exact=True)
        ).count(),
        "accessible_snapshot": element.aria_snapshot() if count == 1 else "",
    }


def _visual_style(page, token):
    element = page.locator(token["selector"])
    count = element.count()
    value = (
        element.evaluate(
            "(element, property) => getComputedStyle(element).getPropertyValue(property)",
            token["property"],
        )
        if count == 1
        else None
    )
    return {
        "selector": token["selector"],
        "property": token["property"],
        "count": count,
        "value": value,
    }


def _visual_pixel(root, baseline, screenshot, threshold):
    from PIL import Image, ImageChops

    if baseline is None or not _visual_path(root, baseline["path"]).exists():
        return {"state": "INCOMPLETE", "reason": "reviewed baseline missing"}
    paths = [_visual_binding(root, baseline), _visual_path(root, screenshot["path"])]
    images = []
    for path in paths:
        if path.stat().st_size > MAX_EVIDENCE_BYTES:
            _visual_bad("PNG exceeds byte budget")
        with Image.open(path) as image:
            if image.format != "PNG" or image.width * image.height > 4_000_000:
                _visual_bad("bounded PNG required")
            image.load()
            images.append(image.convert("RGBA"))
    if images[0].size != images[1].size:
        return {"state": "FAIL", "reason": "pixel dimensions differ"}
    difference = ImageChops.difference(*images)
    changed = sum(any(pixel) for pixel in difference.getdata())
    total = images[0].width * images[0].height
    return {
        "state": "FAIL" if changed / total > threshold else "PASS",
        "changed_pixels": changed,
        "total_pixels": total,
        "changed_ratio": changed / total,
    }


def _visual_case_findings(root, expected, observed):
    findings = []

    def add(code, detail, incomplete=False):
        findings.append(
            _visual_finding(code, detail, case_id=expected["id"], incomplete=incomplete)
        )

    if (
        observed.get("id") != expected["id"]
        or observed.get("capture_error")
        or "screenshot" not in observed
    ):
        add("E_VISUAL_CAPTURE", "capture incomplete", True)
        return findings
    if observed.get("timed_out"):
        add("E_VISUAL_DEADLINE", "terminal UI/response deadline expired", True)
    element = expected["element"]
    if (
        observed.get("action_identity") is not True
        or observed.get("element_count") != 1
        or observed.get("visible") is not True
        or observed.get("enabled") is not element["enabled"]
        or observed.get("accessible_matches") != 1
        or not _visual_accessible(observed.get("accessible_snapshot", ""), element)
    ):
        add("E_VISUAL_SEMANTICS", "expected one visible accessible control")
    if not observed.get("timed_out") and (
        observed.get("state_text") != expected["state"]["text"]
        or observed.get("state_count") != 1
        or observed.get("state_visible") is not True
    ):
        add("E_VISUAL_STATE", "terminal UI text differs")
    findings.extend(_visual_response_findings(expected, observed))
    for token, actual in zip(
        expected["tokens"], observed.get("tokens", []), strict=True
    ):
        if actual != {**token, "count": 1}:
            add("E_VISUAL_TOKEN", f"computed style differs: {token['property']}")
    pixel = _visual_pixel(
        root,
        expected["baseline"],
        observed["screenshot"],
        expected["max_changed_ratio"],
    )
    if pixel["state"] != "PASS":
        add(
            "E_VISUAL_PIXELS",
            pixel.get("reason", "changed pixels exceed threshold"),
            pixel["state"] == "INCOMPLETE",
        )
    return findings


def _visual_response_findings(expected, observed):
    response = expected["response"]
    if response is None:
        return []
    actual = observed.get("response")
    if actual is None or observed.get("response_count") != 1:
        return [
            _visual_finding(
                "E_VISUAL_RESPONSE_MISSING",
                "no same-action response",
                case_id=expected["id"],
                incomplete=True,
            )
        ]
    wanted = {
        "method": response["method"],
        "path": response["path"],
        "status": response["status"],
        "field_present": True,
        "value_sha256": _sha(response["value"]),
        "correlation_sha256": _sha(response["correlation"]["value"]),
    }
    return (
        []
        if actual == wanted
        else [
            _visual_finding(
                "E_VISUAL_RUNTIME",
                "same-action API/UI mismatch",
                case_id=expected["id"],
            )
        ]
    )


def _visual_prestige(root, design):
    if design is None:
        return None
    from prestige_design.tokens import report_tokens, verify_tokens  # type: ignore[import-untyped]
    from prestige_design.provenance import provenance  # type: ignore[import-untyped]

    html = _visual_binding(root, design["html"]).read_text(encoding="utf-8")
    css = "\n".join(
        _visual_binding(root, item).read_text(encoding="utf-8")
        for item in design["css"]
    )
    contract = _visual_binding(root, design["contract"])
    return {
        "report": report_tokens(html, contract, css),
        "mutations": verify_tokens(html, contract, css),
        "provenance": provenance(),
        "bindings": design,
    }


def _visual_prestige_findings(observed, design):
    if design is None:
        return []
    if not isinstance(observed, dict):
        return [
            _visual_finding(
                "E_VISUAL_PRESTIGE", "companion evidence missing", incomplete=True
            )
        ]
    report, mutation = observed["report"], observed["mutations"]
    valid = (
        report["n_checked"] >= 1
        and report["n_passed"] == report["n_checked"]
        and mutation["mutants_killed"] >= 1
        and mutation["mutants_total"] == mutation["mutants_killed"]
        and all(item["killed"] is True for item in mutation["mutations"])
    )
    return (
        []
        if valid
        else [
            _visual_finding("E_VISUAL_PRESTIGE", "tokens or deletion mutations failed")
        ]
    )


def _visual_receipt_artifacts(root, receipt):
    findings = []
    for artifact in receipt["artifacts"]:
        actual = _visual_artifact(root, artifact["path"], artifact["kind"])
        if actual != artifact:
            findings.append(
                _visual_finding(
                    "E_VISUAL_ARTIFACT_DRIFT", artifact["path"], incomplete=True
                )
            )
    if receipt["decision"] != "NOT_RUN":
        findings.extend(_visual_artifact_inventory(root, receipt))
    return findings


def _visual_artifact_inventory(root, receipt):
    """Require actual producer artifacts, not just caller-supplied registrations."""
    try:
        captures = [
            artifact for case in receipt["cases"] for artifact in case["artifacts"]
        ]
        observations = [
            item for item in receipt["artifacts"] if item["kind"] == "observations"
        ]
        expected = [*captures, *observations]
        if len(observations) != 1 or sorted(map(_sha, expected)) != sorted(
            map(_sha, receipt["artifacts"])
        ):
            _visual_bad("required artifact registrations differ")
        if len({item["path"] for item in expected}) != len(expected):
            _visual_bad("duplicate artifact path")
        producer = _visual_read(_visual_path(root, observations[0]["path"]))
        for key in ("identity", "cases", "prestige"):
            if producer[key] != receipt[key]:
                _visual_bad("receipt differs from captured observations")
        if producer["artifacts"] != captures:
            _visual_bad("producer artifact inventory differs")
        for case in receipt["cases"]:
            _visual_capture_artifacts(root, case)
    except (OSError, ValueError, KeyError, TypeError):
        return [
            _visual_finding(
                "E_VISUAL_ARTIFACT_MISSING",
                "capture artifact inventory or observations differ",
                incomplete=True,
            )
        ]
    return []


def _visual_capture_artifacts(root, case):
    artifacts = case["artifacts"]
    if len(artifacts) != 2 or {item["kind"] for item in artifacts} != {
        "screenshot",
        "accessibility",
    }:
        _visual_bad("screenshot and accessibility artifacts required")
    screenshot = next(item for item in artifacts if item["kind"] == "screenshot")
    if case["screenshot"] != screenshot:
        _visual_bad("screenshot reference differs")
    accessibility = next(item for item in artifacts if item["kind"] == "accessibility")
    snapshot = _visual_read(_visual_path(root, accessibility["path"]))
    _visual_keys(snapshot, "snapshot")
    if not isinstance(snapshot["snapshot"], str) or not snapshot["snapshot"]:
        _visual_bad("actual accessibility snapshot required")


def _visual_partial_artifacts(root, directory):
    artifacts = []
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix in {".png", ".json"}:
            try:
                artifacts.append(_visual_artifact(root, path, "partial"))
            except (OSError, ValueError):
                continue
    return artifacts


def _visual_accessible(snapshot, expected):
    import re

    match = re.match(r'^- ([a-z][a-z0-9-]*)\s+("(?:[^"\\]|\\.)*")', snapshot)
    return bool(
        match
        and match[1] == expected["role"]
        and json.loads(match[2]) == expected["name"]
    )


def _visual_profile_findings(contract, identity):
    from .candidate_lineage import _sha_file

    expected = contract["browser"]
    try:
        tools = _visual_tool_identity()
    except ImportError:
        return [
            _visual_finding(
                "E_VISUAL_PROFILE", "browser tools unavailable", incomplete=True
            )
        ]
    if (
        not isinstance(identity, dict)
        or set(identity)
        != set(tools) | {"executable_sha256", "browser", "platform", "viewport"}
        or any(identity.get(key) != value for key, value in tools.items())
    ):
        return [
            _visual_finding(
                "E_VISUAL_PROFILE",
                "complete current tool identity required",
                incomplete=True,
            )
        ]
    try:
        actual = _sha_file(Path(expected["executable"]))
    except OSError:
        return [
            _visual_finding(
                "E_VISUAL_PROFILE", "browser executable unavailable", incomplete=True
            )
        ]
    valid = (
        identity.get("executable_sha256") == actual
        and identity.get("browser") == expected["version"]
        and identity.get("platform") == expected["platform"]
        and identity.get("viewport")
        == {key: expected[key] for key in ("width", "height")}
    )
    return (
        []
        if valid
        else [
            _visual_finding("E_VISUAL_PROFILE", "browser identity or viewport differs")
        ]
    )


def _visual_bounded_bytes(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_EVIDENCE_BYTES + 1)
    if not raw or len(raw) > MAX_EVIDENCE_BYTES:
        _visual_bad("file outside evidence byte budget")
    return raw
