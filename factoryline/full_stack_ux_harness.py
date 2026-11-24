"""Evidence-bound full-stack engineering and ethical UX release review."""

from __future__ import annotations


from collections.abc import Mapping, Sequence
from difflib import unified_diff
from html import escape
import json
import os
import tempfile
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit
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
    result, _, _ = _verify_visual_behavior(root, receipt_path)
    return result


def _verify_visual_behavior(root, receipt_path):
    """Expose the verified contract and independent observations to comparison."""
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
        result = {
            **receipt,
            "decision": "INCOMPLETE" if findings else "NOT_RUN",
            "findings": findings,
            "path": str(source),
        }
        return result, contract, findings
    findings.extend(_visual_process_findings(receipt["execution"]))
    findings.extend(_visual_profile_findings(contract, receipt["identity"]))
    findings.extend(
        _visual_cases_findings(workspace, contract["cases"], receipt["cases"])
    )
    findings.extend(_visual_prestige_findings(receipt["prestige"], contract["design"]))
    findings.extend(
        _visual_prestige_replay(workspace, contract["design"], receipt["prestige"])
    )
    combined = [*findings, *receipt["findings"]]
    return (
        {
            **receipt,
            "decision": _visual_decision(combined),
            "findings": combined,
            "path": str(source),
        },
        contract,
        findings,
    )


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
    fields = (
        "id baseline action element state response tokens timeout_ms max_changed_ratio"
    )
    _visual_keys(
        case,
        fields + (" steps" if isinstance(case, dict) and "steps" in case else ""),
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
    if "steps" in case:
        _visual_steps_contract(case["steps"])


def _visual_steps_contract(steps):
    _visual_list(steps, 1, 16)
    names = set()
    for step in steps:
        _visual_keys(step, "id kind selector value")
        _visual_text(step["id"], 128)
        _visual_text(step["selector"])
        if step["id"] in names:
            _visual_bad("duplicate journey step")
        names.add(step["id"])
        _visual_step_value(step["kind"], step["value"])


def _visual_step_value(kind, value):
    if kind in ("click", "focus") and value is None:
        return
    if kind == "press" and value in ("Enter", "Space", "Escape", "Tab", "Shift+Tab"):
        return
    if kind == "visible" and type(value) is bool:
        return
    if kind == "count":
        _visual_number(value, 0, 500)
        return
    _visual_bad("unsupported journey step")


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
        observed.update(
            observed["before_action"]
            if "steps" in case
            else _visual_element(page, case)
        )
        _visual_budget(page, deadline)
        observed["tokens"] = [_visual_style(page, token) for token in case["tokens"]]
        if (
            "steps" in case
            and observed["action_identity"]
            and not observed.get("timed_out")
            and observed.get("state_visible") is True
        ):
            observed["steps"] = _visual_capture_steps(page, case["steps"], deadline)
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


def _visual_capture_steps(page, steps, deadline):
    observations = []
    for step in steps:
        ok = _visual_capture_step(page, step, deadline)
        observations.append({"id": step["id"], "ok": ok})
        if not ok:
            break
    return observations


def _visual_capture_step(page, step, deadline):
    timeout = _visual_budget(page, deadline)
    target = page.locator(step["selector"])
    count = target.count()
    kind, value = step["kind"], step["value"]
    if kind == "count":
        return count == value
    if kind == "visible":
        return count <= 1 and (count == 1 and target.is_visible()) is value
    if count != 1:
        return False
    if kind == "click":
        if not target.is_visible() or not target.is_enabled():
            return False
        target.click(timeout=timeout)
        return True
    focused = target.and_(page.locator(":focus")).count() == 1
    if kind == "press" and focused:
        page.keyboard.press(value)
    return focused


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
    _visual_step_findings(expected, observed, add)
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


def _visual_step_findings(expected, observed, add):
    steps = expected.get("steps", [])
    results = observed.get("steps", [])
    if not steps and not results:
        return
    if not _visual_step_trace_valid(steps, results):
        add("E_VISUAL_STEP_EVIDENCE", "journey steps are missing or out of order", True)
    elif not results[-1]["ok"]:
        add("E_VISUAL_STEP", f"journey step failed: {results[-1]['id']}")


def _visual_step_trace_valid(steps, results):
    if not isinstance(results, list) or not 0 < len(results) <= len(steps):
        return False
    for expected, observed in zip(steps, results):
        if (
            observed
            not in (
                {"id": expected["id"], "ok": True},
                {"id": expected["id"], "ok": False},
            )
            or type(observed["ok"]) is not bool
        ):
            return False
    return all(row["ok"] for row in results[:-1]) and (
        len(steps) == len(results) or not results[-1]["ok"]
    )


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


# Journey receipt comparison

JOURNEY_COMPARISON_SCHEMA = "factory.journey-evidence.comparison.v1"
MAX_DIFF_BYTES = 16_384
MAX_DIFF_LINES = 240
MAX_SOURCE_BYTES = 32_768
MAX_SOURCE_LINES = 1_024
_SOURCE_SUFFIXES = {".html", ".css", ".js", ".mjs", ".ts", ".tsx", ".jsx", ".py"}
_OBSERVED = {"PASS", "FAIL"}


class _PreviewSourceDrift(ValueError):
    pass


def _display(value: str) -> str:
    """Keep visible text and make control characters visible without executing them."""
    return "".join(char if char.isprintable() else ascii(char)[1:-1] for char in value)


def _finding(code: str, detail: str) -> dict[str, Any]:
    return {"code": code, "detail": detail, "case_id": None, "outcome": "INCOMPLETE"}


def _read_side(root: Path, receipt_path: Path | str) -> tuple[dict, dict | None, dict]:
    summary: dict[str, Any] = {
        "status": "INCOMPLETE",
        "receipt_sha256": None,
        "contract_sha256": None,
        "components": [],
        "findings": [],
        "profile": None,
        "evidence": [],
    }
    try:
        receipt, contract, independent_findings = _verify_visual_behavior(
            root, receipt_path
        )
        binding = receipt["contract"]
        components = [
            {
                **component,
                "path": _visual_path(root, component["path"])
                .relative_to(root)
                .as_posix(),
            }
            for component in receipt["candidate"]
        ]
        if len({component["path"] for component in components}) != len(components):
            raise ValueError("candidate paths must identify distinct files")
        status = receipt["decision"]
        observed_findings = receipt["findings"]
        if status == "FAIL":
            observed_findings = independent_findings
            outcomes = {item["outcome"] for item in observed_findings}
            if outcomes != {"FAIL"}:
                status = "INCOMPLETE"
                observed_findings = [
                    _finding(
                        "E_JOURNEY_FAILURE_UNVERIFIED",
                        "Recorded failure could not be reproduced from bound observations.",
                    )
                ]
        findings = list(
            {
                (item["code"], item["detail"], item["case_id"], item["outcome"]): {
                    key: item[key] for key in ("code", "detail", "case_id", "outcome")
                }
                for item in observed_findings
            }.values()
        )
        steps = {
            case["id"]: {step["id"]: step["ok"] for step in case.get("steps", [])}
            for case in receipt["cases"]
        }
        for item in findings:
            if item["code"] == "E_VISUAL_STEP":
                failed_step = next(
                    (
                        step
                        for step, ok in steps.get(item["case_id"], {}).items()
                        if ok is False
                    ),
                    None,
                )
                if failed_step is not None:
                    item["step_id"] = failed_step
        summary.update(
            status=status,
            receipt_sha256=receipt["receipt_sha256"],
            contract_sha256=binding["sha256"],
            components=sorted(components, key=lambda item: item["path"]),
            findings=findings,
            profile=receipt["identity"] if status in _OBSERVED else None,
            evidence=receipt["artifacts"] if status != "NOT_RUN" else [],
        )
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        IndexError,
        RuntimeError,
    ) as error:
        code = (
            error.code
            if isinstance(error, FullStackUXHarnessError)
            else "E_JOURNEY_RECEIPT"
        )
        summary["findings"] = [
            _finding(code, "Receipt or bound evidence failed verification.")
        ]
        return summary, None, {}
    return summary, contract, steps


def _scope(contract: dict, components: list[dict]) -> dict:
    target = urlsplit(contract["target"])
    design = contract["design"]
    return {
        "journey": [
            contract["project_id"],
            contract["journey_id"],
            contract["reviewer"],
        ],
        "target": [target.hostname, target.path or "/", target.query],
        "browser": {
            key: value
            for key, value in contract["browser"].items()
            if key != "executable"
        },
        "cases": {case["id"]: case for case in contract["cases"]},
        "design": None
        if design is None
        else [
            design["contract"],
            design["html"]["path"],
            [item["path"] for item in design["css"]],
        ],
        "components": {item["path"]: item["kind"] for item in components},
    }


def _case_status(side: dict, case_id: str) -> str:
    if side["status"] not in _OBSERVED:
        return side["status"]
    return (
        "FAIL"
        if any(item["case_id"] == case_id for item in side["findings"])
        else "PASS"
    )


def _step_status(side: dict, observed: dict, case_id: str, step_id: str) -> str:
    if side["status"] not in _OBSERVED:
        return side["status"]
    ok = observed.get(case_id, {}).get(step_id)
    if ok is None:
        return "INCOMPLETE"
    return "PASS" if ok is True else "FAIL"


def _case_rows(
    contract: dict, before: dict, after: dict, before_steps: dict, after_steps: dict
) -> list[dict]:
    cases = []
    for case in contract["cases"]:
        case_id = case["id"]
        row = {
            "id": case_id,
            "before_status": _case_status(before, case_id),
            "after_status": _case_status(after, case_id),
        }
        if "steps" in case:
            row["steps"] = [
                {
                    "id": step["id"],
                    "before_status": _step_status(
                        before, before_steps, case_id, step["id"]
                    ),
                    "after_status": _step_status(
                        after, after_steps, case_id, step["id"]
                    ),
                }
                for step in case["steps"]
            ]
        cases.append(row)
    return cases


def _source_lines(root: Path, binding: dict) -> list[str]:
    path = _visual_path(root, binding["path"])
    relative = path.relative_to(root)
    if (
        path.suffix.lower() not in _SOURCE_SUFFIXES
        or binding["kind"] != "source"
        or any(part.startswith(".") for part in relative.parts)
    ):
        raise ValueError("candidate is outside the fixture source preview scope")
    with path.open("rb") as stream:
        raw = stream.read(MAX_SOURCE_BYTES + 1)
    if len(raw) > MAX_SOURCE_BYTES:
        raise ValueError("candidate exceeds the preview byte limit")
    if _sha(raw) != binding["sha256"]:
        raise _PreviewSourceDrift("candidate bytes changed")
    source = raw.decode("utf-8")
    if any(not (char.isprintable() or char in "\t\r\n") for char in source):
        raise ValueError("candidate contains non-displayable source")
    lines = source.splitlines(keepends=True)
    if len(lines) > MAX_SOURCE_LINES:
        raise ValueError("candidate exceeds the preview line limit")
    return lines


def _diff(
    before_root: Path, before: dict, after_root: Path, after: dict
) -> tuple[list[dict], dict]:
    before_by_path = {item["path"]: item for item in before["components"]}
    after_by_path = {item["path"]: item for item in after["components"]}
    changes = [
        {
            "path": path,
            "kind": item["kind"],
            "before_sha256": before_by_path[path]["sha256"],
            "after_sha256": item["sha256"],
        }
        for path, item in after_by_path.items()
        if before_by_path[path]["sha256"] != item["sha256"]
    ]
    if not changes:
        return [], {"status": "UNCHANGED", "text": "", "truncated": False}

    lines = []
    line_count = 0
    remaining = MAX_DIFF_BYTES
    try:
        sources = [
            (
                path,
                _source_lines(before_root, before_by_path[path]),
                _source_lines(after_root, after_by_path[path]),
            )
            for path in (change["path"] for change in changes)
        ]
        for path, before_lines, after_lines in sources:
            for line in unified_diff(
                before_lines,
                after_lines,
                fromfile=f"a/{_display(path)}",
                tofile=f"b/{_display(path)}",
            ):
                if not line.endswith("\n"):
                    line += "\n\\ No newline at end of file\n"
                size = len(line.encode("utf-8"))
                line_count += line.count("\n")
                if size > remaining or line_count > MAX_DIFF_LINES:
                    return changes, {
                        "status": "AVAILABLE",
                        "text": "".join(lines),
                        "truncated": True,
                    }
                remaining -= size
                lines.append(line)
    except _PreviewSourceDrift:
        raise
    except (OSError, ValueError, RuntimeError):
        return changes, {
            "status": "UNAVAILABLE",
            "text": "",
            "truncated": False,
            "reason": "A changed candidate is outside the verified fixture text preview limits.",
        }
    return changes, {"status": "AVAILABLE", "text": "".join(lines), "truncated": False}


def _next_action(status: str, findings: list[dict]) -> str | None:
    if status == "PASS":
        return None
    if status == "INCOMPLETE":
        return "Capture and verify both fixtures under the same reviewed journey and browser profile."
    code = findings[0]["code"]
    actions = {
        "E_VISUAL_SEMANTICS": "Inspect the accessible control for the failing case and rerun it.",
        "E_VISUAL_STATE": "Inspect the terminal UI state for the failing case and rerun it.",
        "E_VISUAL_RUNTIME": "Inspect the same-action API response and terminal UI state, then rerun the case.",
        "E_VISUAL_PIXELS": "Inspect the captured screenshot against the reviewed baseline and rerun the case.",
        "E_VISUAL_TOKEN": "Inspect the computed style against the reviewed token expectation and rerun the case.",
        "E_VISUAL_STEP": "Inspect the failed journey step and rerun the reviewed case.",
    }
    return actions.get(
        code, "Inspect the recorded finding and rerun the reviewed journey."
    )


def _display_payload(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: item if key == "text" else _display_payload(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_display_payload(item) for item in value]
    return _display(value) if isinstance(value, str) else value


def compare_journey_evidence(
    before_root: Path | str,
    before_receipt: Path | str,
    after_root: Path | str,
    after_receipt: Path | str,
) -> dict[str, Any]:
    """Replay two fixture receipts and compare the after result under equivalent scope."""
    baseline = Path(before_root).resolve()
    candidate = Path(after_root).resolve()
    before, before_contract, before_steps = _read_side(baseline, before_receipt)
    after, after_contract, after_steps = _read_side(candidate, after_receipt)
    result: dict[str, Any] = {
        "schema": JOURNEY_COMPARISON_SCHEMA,
        "fixture_only": True,
        "authority": {"release": False, "approval": False, "publication": False},
        "claim_boundary": "Local fixture replay with unauthenticated receipt origin. The preview can include local fixture source excerpts.",
        "project_id": None,
        "journey_id": None,
        "status": "INCOMPLETE",
        "before": before,
        "after": after,
        "cases": [],
        "findings": [],
        "component_hints": [],
        "source_diff": {"status": "UNAVAILABLE", "text": "", "truncated": False},
    }

    if before_contract is None or after_contract is None:
        result["findings"] = [*before["findings"], *after["findings"]]
    else:
        before_scope = _scope(before_contract, before["components"])
        after_scope = _scope(after_contract, after["components"])
        differing = [
            key for key in before_scope if before_scope[key] != after_scope[key]
        ]
        if differing:
            result["findings"] = [
                _finding(
                    "E_JOURNEY_SCOPE", "Reviewed scope differs: " + ", ".join(differing)
                )
            ]
        else:
            result.update(_compare_matching(baseline, before, candidate, after))
            if not any(
                item["code"] == "E_JOURNEY_PROFILE" for item in result["findings"]
            ):
                result["cases"] = _case_rows(
                    after_contract, before, after, before_steps, after_steps
                )
            result.update(
                project_id=after_contract["project_id"],
                journey_id=after_contract["journey_id"],
            )
    result["next_action"] = _next_action(result["status"], result["findings"])
    result = _display_payload(result)
    return {**result, "comparison_sha256": _sha(result)}


def _compare_matching(
    before_root: Path, before: dict, after_root: Path, after: dict
) -> dict[str, Any]:
    if before["status"] not in _OBSERVED or after["status"] not in _OBSERVED:
        return {
            "findings": [
                _finding(
                    "E_JOURNEY_INCOMPLETE",
                    "Both receipts need complete browser observations.",
                ),
                *before["findings"],
                *after["findings"],
            ],
        }
    if before["profile"] != after["profile"]:
        return {
            "findings": [
                _finding(
                    "E_JOURNEY_PROFILE", "Captured browser or tool identities differ."
                )
            ],
        }

    try:
        hints, preview = _diff(before_root, before, after_root, after)
    except _PreviewSourceDrift:
        return {
            "findings": [
                _finding(
                    "E_VISUAL_SOURCE_DRIFT",
                    "Bound source changed while preparing the preview.",
                )
            ],
        }
    return {
        "status": after["status"],
        "findings": after["findings"],
        "component_hints": hints,
        "source_diff": preview,
    }


# Standalone evidence report

_JOURNEY_REPORT_STYLE = """
:root {
  color-scheme: light;
  --ink: #152526; --muted: #475f60; --paper: #f1f5f3; --surface: #fff;
  --edge: #ccd9d5; --accent: #17564e; --pass: #205847; --pass-bg: #e4f3ed;
  --fail: #802c20; --fail-bg: #fff0eb; --pending: #644909; --pending-bg: #fbf1d4;
  font-family: system-ui, sans-serif;
  font-size: 16px;
  line-height: 1.6;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--paper); color: var(--ink); }
main { max-width: 68rem; margin: auto; padding: 3rem 1.5rem; }
h1, h2, h3, p { margin: 0; }
h1 { font-size: clamp(2rem, 5vw, 3.4rem); line-height: 1.5; letter-spacing: -.035em; }
h2 { font-size: 1.25rem; }
h3 { font-size: 1rem; }
p { max-width: 65ch; overflow-wrap: anywhere; }
p + p { margin-top: .65rem; }
.eyebrow { color: var(--muted); font-weight: 650; margin-bottom: .5rem; }
.muted { color: var(--muted); }
.card, details { background: var(--surface); border: 1px solid var(--edge); border-radius: .8rem; }
.card { padding: 1.4rem; }
.intro { margin-bottom: 1.4rem; }
.intro p:last-child { margin-top: .7rem; }
.grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .85rem; }
.content { display: grid; gap: .85rem; }
.row { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: .5rem 1rem; }
.readout { margin: .65rem 0; font-size: 1.1rem; }
.action { align-self: start; }
.action p { margin: .5rem 0 1rem; }
a { color: var(--accent); text-underline-offset: .16em; }
.button { background: var(--accent); color: #fff; border-radius: .5rem; min-height: 44px;
  display: inline-flex; align-items: center; padding: .5rem 1rem; font-weight: 650;
  transition: background-color .15s ease; }
.button:hover { background: #104439; }
@media (prefers-reduced-motion: reduce) { .button { transition: none; } }
.return { display: inline-flex; align-items: center; min-height: 44px; margin-top: .7rem; }
:focus-visible { outline: 3px solid #925718; outline-offset: 3px; }
.status { display: inline-block; border-radius: .35rem; padding: .15rem .5rem;
  font-weight: 700; background: var(--pending-bg); color: var(--pending); }
.pass { background: var(--pass-bg); color: var(--pass); }
.fail { background: var(--fail-bg); color: var(--fail); }
summary { cursor: pointer; padding: .8rem 1.4rem; min-height: 44px; font-weight: 650; }
.detail { padding: 0 1.4rem 1.4rem; }
dl, ul { margin: .65rem 0 0; }
dl { overflow-wrap: anywhere; }
dt { color: var(--muted); margin-top: .5rem; }
dd { margin: 0; }
code, pre { font-family: ui-monospace, Consolas, monospace; }
code { overflow-wrap: anywhere; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; background: var(--paper);
  padding: 1rem; border-radius: .5rem; margin: .75rem 0 0; }
ul { padding-inline-start: 1.25rem; }
li + li { margin-top: .45rem; }
.case { display: grid; grid-template-columns: minmax(0, 1fr) 9rem 9rem; gap: .4rem 1rem;
  align-items: center; padding: .7rem 0; border-top: 1px solid var(--edge); }
.case span { overflow-wrap: anywhere; }
.case-label { margin-right: .35rem; }
.step { padding-inline-start: 1rem; }
.cases { margin-top: .75rem; }
footer { padding-top: 1rem; }
#done { display: none; }
#done:target { display: block; }
#done:target + #review { display: none; }
@media (max-width: 640px) {
  main { padding: 1.75rem 1rem; }
  .grid { grid-template-columns: minmax(0, 1fr); }
  .card, summary { padding-inline: 1rem; }
  .detail { padding-inline: 1rem; }
  .case { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .case > :first-child { grid-column: span 2; }
  .case-label { display: block; }
}
"""


def _text(value: object) -> str:
    return escape(str(value)) if value is not None else "Unavailable"


def _status(value: object) -> str:
    css_class, label = {
        "PASS": ("pass", "Pass"),
        "FAIL": ("fail", "Fail"),
        "INCOMPLETE": ("", "Incomplete"),
        "NOT_RUN": ("", "Not run"),
    }.get(str(value), ("", str(value) if value is not None else "Unavailable"))
    return f'<span class="status {css_class}">{_text(label)}</span>'


def _hash_rows(values: Mapping[str, object]) -> str:
    rows = "".join(
        f"<dt>{_text(label)}</dt><dd><code>{_text(value)}</code></dd>"
        for label, value in values.items()
    )
    return f"<dl>{rows}</dl>"


def _findings(items: Sequence[Mapping[str, Any]]) -> str:
    if not items:
        return "<p>No findings recorded.</p>"
    rows = []
    for item in items:
        case = f" · {_text(item['case_id'])}" if item.get("case_id") else ""
        step = f" / {_text(item['step_id'])}" if item.get("step_id") else ""
        rows.append(
            f"<li><strong>{_text(item['code'])}</strong>{case}{step}<br>{_text(item['detail'])}</li>"
        )
    return f"<ul>{''.join(rows)}</ul>"


def _proof(label: str, side: Mapping[str, Any]) -> str:
    return f"""<section class="card">
      <div class="row"><h2>{label} proof</h2>{_status(side.get("status"))}</div>
      {
        _hash_rows(
            {
                "Receipt SHA-256": side.get("receipt_sha256"),
                "Contract SHA-256": side.get("contract_sha256"),
            }
        )
    }
    </section>"""


def _evidence(label: str, side: Mapping[str, Any]) -> str:
    profile = side.get("profile")
    profile_html = (
        f"<pre>{_text(json.dumps(profile, indent=2, ensure_ascii=False))}</pre>"
        if profile
        else ("<p>Execution profile unavailable.</p>")
    )
    artifacts = "".join(
        f"<li><strong>{_text(item['kind'])}</strong> · <code>{_text(item['path'])}</code><br>"
        f"SHA-256 <code>{_text(item['sha256'])}</code> · {_text(item['bytes'])} bytes</li>"
        for item in side.get("evidence", [])
    )
    components = "".join(
        f"<li><code>{_text(item['path'])}</code> · {_text(item['kind'])}<br>"
        f"SHA-256 <code>{_text(item['sha256'])}</code></li>"
        for item in side.get("components", [])
    )
    return f"""<details>
      <summary>{label} evidence</summary>
      <div class="detail content">
        <section><h3>Execution profile</h3>{profile_html}</section>
        <section><h3>Artifacts</h3>{f"<ul>{artifacts}</ul>" if artifacts else "<p>No artifacts recorded.</p>"}</section>
        <section><h3>Components</h3>{f"<ul>{components}</ul>" if components else "<p>No component bindings recorded.</p>"}</section>
        <section><h3>Findings</h3>{_findings(side.get("findings", []))}</section>
      </div>
    </details>"""


def _cases(items: Sequence[Mapping[str, Any]]) -> str:
    if not items:
        return '<p class="cases">No paired cases recorded.</p>'
    rows = []
    for item in items:
        steps = "".join(_case_row(step, is_step=True) for step in item.get("steps", []))
        steps_section = (
            f'<div role="list" aria-label="Steps">{steps}</div>' if steps else ""
        )
        rows.append(f'<div role="listitem">{_case_row(item)}{steps_section}</div>')
    return f'<div class="cases" role="list">{"".join(rows)}</div>'


def _case_row(item: Mapping[str, Any], *, is_step: bool = False) -> str:
    class_name = "case step" if is_step else "case"
    role = ' role="listitem"' if is_step else ""
    label = "Step" if is_step else "Case"
    return (
        f'<div class="{class_name}"{role}><span><span class="case-label muted">{label}</span>'
        f"<strong>{_text(item['id'])}</strong></span>"
        f'<span><span class="case-label muted">Before</span>{_status(item.get("before_status"))}</span>'
        f'<span><span class="case-label muted">After</span>{_status(item.get("after_status"))}</span></div>'
    )


def _source_diff(diff: Mapping[str, Any], hints: Sequence[Mapping[str, Any]]) -> str:
    status = diff.get("status")
    content = {
        "UNCHANGED": "The bound source components are unchanged.",
        "UNAVAILABLE": "Source diff unavailable.",
    }.get(str(status), "Changed lines from local fixture source")
    if diff.get("truncated"):
        content += " · Diff truncated"
    diff_text = (
        f"<pre><code>{_text(diff['text'])}</code></pre>" if diff.get("text") else ""
    )
    paths = "".join(
        f"<li><strong>{_text(item['path'])}</strong> · {_text(item['kind'])}"
        f"{_hash_rows({'Before SHA-256': item.get('before_sha256'), 'After SHA-256': item.get('after_sha256')})}</li>"
        for item in hints
    )
    components = (
        f"<section><h3>Changed component bindings</h3><ul>{paths}</ul></section>"
        if paths
        else ""
    )
    return f"""<details>
      <summary>Components and source diff</summary>
      <div class="detail content">{components}<section><p>{content}</p>{diff_text}</section></div>
    </details>"""


def _journey_step_summary(cases):
    first_failure = first_incomplete = last_verified = None
    for case in cases:
        for step in case.get("steps", []):
            label = f"{_text(case['id'])} / {_text(step['id'])}"
            status = step["after_status"]
            if status == "PASS":
                last_verified = label
            elif status == "FAIL":
                first_failure = first_failure or label
            elif status in {"INCOMPLETE", "NOT_RUN"}:
                first_incomplete = first_incomplete or label
    return first_failure, first_incomplete, last_verified


def _journey_progress(comparison):
    cases, findings = comparison["cases"], comparison["findings"]
    failed_step, incomplete_step, last_verified = _journey_step_summary(cases)
    first_failure = next((item for item in findings if item.get("case_id")), None)
    if failed_step:
        readout = f"First failing step · {failed_step}"
    elif incomplete_step and comparison["status"] != "FAIL":
        readout = f"First incomplete step · {incomplete_step}"
    elif first_failure:
        readout = f"First affected case · {_text(first_failure['case_id'])}"
    elif findings:
        readout = f"First finding · {_text(findings[0]['code'])}"
    else:
        count = len(cases)
        readout = f"{count} paired {'case' if count == 1 else 'cases'} recorded"
    verified_readout = (
        f'<p class="muted">Last verified After step · {last_verified or "None recorded"}</p>'
        if any((failed_step, incomplete_step, last_verified))
        else ""
    )
    return readout, verified_readout


def render_journey_comparison(comparison: Mapping[str, Any]) -> str:
    """Use the comparison verdict and display recorded evidence as inert text."""
    before, after = comparison["before"], comparison["after"]
    cases, findings = comparison["cases"], comparison["findings"]
    readout, verified_readout = _journey_progress(comparison)
    action = _text(
        comparison.get("next_action")
        or ("Review the evidence if needed, or select Done to finish.")
    )
    scope = (
        "Local fixture evidence"
        if comparison.get("fixture_only")
        else "Recorded journey evidence"
    )
    identity = " / ".join(
        _text(comparison[key])
        for key in ("project_id", "journey_id")
        if comparison.get(key)
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
  <title>Journey evidence comparison</title>
  <style>{_JOURNEY_REPORT_STYLE}</style>
</head>
<body>
<main>
  <section id="done" class="card" tabindex="-1" aria-labelledby="done-heading">
    <h2 id="done-heading">Review ended</h2>
    <p>You can close this tab.</p>
    <a class="return" href="#review">Return to comparison</a>
  </section>
  <article id="review" tabindex="-1">
    <header class="intro">
      <p class="eyebrow">{scope}</p>
      <h1>Journey evidence comparison</h1>
      <p class="muted">{identity}</p>
    </header>
    <div class="content">
      <div class="grid">
        <section class="card">
          <div class="row"><h2>Comparison verdict</h2>{_status(comparison["status"])}</div>
          <p class="readout">{readout}</p>
          {verified_readout}
          <p class="muted">Scope covers the recorded cases and execution profile.</p>
        </section>
        <section class="card action">
          <h2>Next action</h2>
          <p>{action}</p>
          <a class="button" href="#done">Done</a>
        </section>
      </div>
      <section class="card">
        <h2>Case progress</h2>
        {_cases(cases)}
      </section>
      <div class="grid">{_proof("Before", before)}{_proof("After", after)}</div>
      <details><summary>Comparison findings</summary><div class="detail">{_findings(findings)}</div></details>
      {_evidence("Before", before)}
      {_evidence("After", after)}
      {_source_diff(comparison["source_diff"], comparison["component_hints"])}
    </div>
    <footer class="muted">
      <p>Authority stays with the separate approval, release and publication workflows.</p>
      {_hash_rows({"Comparison SHA-256": comparison.get("comparison_sha256")})}
    </footer>
  </article>
</main>
</body>
</html>
"""
