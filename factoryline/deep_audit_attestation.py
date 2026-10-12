"""Offline signer, binding, and freshness checks for deep-audit evidence."""

from __future__ import annotations

from . import deep_audit_io as _deep_audit_io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .deep_audit import _read_receipt
from .deep_audit_io import local_file
from .deep_audit_io import (
    digest,
    strict_json,
    LIMIT,
    read_run_json,
    run_directory,
    inventory_candidate,
)
from .runtime_audit_common import sha256_bytes
import base64
from .enterprise_receipts import EnterpriseReceiptError, verify_signed_document
from .runtime_audit_common import (
    RuntimeAuditError,
    require_bool,
    require_digest,
    require_int,
    require_str,
)

SCHEMA = "factory.deep-audit-attestation.v1"
PAYLOAD_TYPE = "application/vnd.factory.deep-audit-attestation.v1+json"
RESULT_SCHEMA = "factory.deep-audit-attestation-verification.v1"
DEFAULT_MAX_AGE_SECONDS = 3600
MAX_VALIDITY_SECONDS = 86400


def _execution_bytes(path: Path) -> bytes:
    path = Path(path)
    source = local_file(path.parent, path.name)
    with source.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise RuntimeAuditError(
            "E_REVIEW_SIZE", "review document exceeds the byte bound"
        )
    return raw


def _execution_document(
    path: Path,
    trust_root: Path,
    trust_pin: str,
    identity: str,
    keyid: str,
    schema: str,
    *,
    return_envelope_sha256: bool = False,
) -> dict | tuple[dict, str]:
    """Authenticate exact locally trusted identities; no implied provider endorsement."""
    raw, trust = _execution_bytes(path), _execution_bytes(trust_root)
    if sha256_bytes(trust) != trust_pin:
        raise RuntimeAuditError("E_TRUST_ROOT_PIN", "trust root changed")
    envelope, trust_value = strict_json(raw), strict_json(trust)
    try:
        encoded = envelope["payload"]
        parsed = strict_json(
            base64.b64decode(
                encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
            )
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeAuditError("E_REVIEW_PAYLOAD", "invalid signed payload") from exc
    verified = verify_signed_document(
        path,
        payload_type=f"application/vnd.{schema}+json",
        schema=schema,
        trust_root_path=trust_root,
    )
    _execution_signer(verified["signature"], trust_value, identity, keyid)
    if (
        verified["payload"] != parsed
        or _execution_bytes(path) != raw
        or _execution_bytes(trust_root) != trust
    ):
        raise RuntimeAuditError(
            "E_REVIEW_DRIFT", "signed inputs changed during verification"
        )
    _execution_freshness(parsed)
    if return_envelope_sha256:
        # Run artifacts add a self-integrity field outside the signed envelope.
        signed_envelope = {
            key: value for key, value in envelope.items() if key != "sha256"
        }
        return parsed, digest(signed_envelope)
    return parsed


def _execution_signer(signature, trust_value, identity, keyid):
    if signature["identity"] != identity or signature["keyid"] != keyid:
        raise RuntimeAuditError(
            "E_REVIEW_IDENTITY", "signature is not from the pinned identity and key"
        )
    keys = [item for item in trust_value.get("keys", []) if item.get("keyid") == keyid]
    if len(keys) != 1 or keys[0].get("revoked") or keys[0].get("revoked_at"):
        raise RuntimeAuditError(
            "E_REVIEW_REVOKED", "signer is missing, ambiguous, or revoked"
        )


def _execution_freshness(parsed):
    now = datetime.now(timezone.utc)
    issued, expires = (
        _instant(parsed.get("issued_at"), "issued_at"),
        _instant(parsed.get("expires_at"), "expires_at"),
    )
    if (
        not issued <= now < expires
        or not 0 < (expires - issued).total_seconds() <= 3600
    ):
        raise RuntimeAuditError(
            "E_REVIEW_FRESHNESS",
            "signed execution documents must be current and valid for at most one hour",
        )
    if parsed.get("authority") != "none":
        raise RuntimeAuditError(
            "E_REVIEW_AUTHORITY", "audit evidence cannot grant release authority"
        )


def _execution_keys(plan: dict, trust_root: Path) -> None:
    trust = strict_json(_execution_bytes(trust_root))
    keys = []
    for role, identity in (
        ("implementer", "implementer_id"),
        ("reviewer", "reviewer_identity"),
        ("coordinator", "coordinator_identity"),
    ):
        found = [
            key
            for key in trust.get("keys", [])
            if key.get("keyid") == plan[f"{role}_keyid"]
            and key.get("identity") == plan[identity]
        ]
        if (
            len(found) != 1
            or found[0].get("revoked")
            or found[0].get("revoked_at")
            or role not in found[0].get("roles", [])
        ):
            raise RuntimeAuditError(
                "E_REVIEW_TRUST",
                "all three role keys must be distinct, active, and explicitly trusted",
            )
        keys.append(found[0].get("public_key"))
    if any(not isinstance(key, str) or not key for key in keys) or len(set(keys)) != 3:
        raise RuntimeAuditError(
            "E_SHARED_REVIEW_KEY", "role aliases cannot reuse the same signing material"
        )


def verify_execution_authorization(
    plan: dict,
    manifest_sha256: str,
    authorization: Path,
    trust_root: Path,
    trust_root_sha256: str,
    *,
    return_envelope_sha256: bool = False,
) -> dict | tuple[dict, str]:
    """Verify coordinator authorization over the exact pinned execution contract."""
    if plan["trust_root_sha256"] != trust_root_sha256:
        raise RuntimeAuditError(
            "E_TRUST_ROOT_PIN", "operator trust pin differs from the manifest"
        )
    verified = _execution_document(
        authorization,
        trust_root,
        trust_root_sha256,
        plan["coordinator_identity"],
        plan["coordinator_keyid"],
        "factory.deep-execution-authorization.v1",
        return_envelope_sha256=return_envelope_sha256,
    )
    payload, envelope_sha256 = verified if return_envelope_sha256 else (verified, None)
    _execution_keys(plan, trust_root)
    expected = {
        "manifest_sha256": manifest_sha256,
        "candidate_sha256": plan["candidate_sha256"],
        "manifest_content_sha256": digest(plan),
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        raise RuntimeAuditError(
            "E_EXECUTION_AUTHORIZATION",
            "execution authorization does not bind this manifest and candidate",
        )
    if payload.get("adapter_images") != {
        lane["id"]: lane["image"] for lane in plan["lanes"]
    }:
        raise RuntimeAuditError(
            "E_ADAPTER_AUTHORIZATION",
            "coordinator must approve every exact adapter image",
        )
    return (payload, envelope_sha256) if return_envelope_sha256 else payload


def _review_dispositions(review, coordinator, inventory):
    common = {
        "schema",
        "run_id",
        "candidate_sha256",
        "manifest_sha256",
        "evidence_sha256",
        "read_set_sha256",
        "issued_at",
        "expires_at",
        "authority",
        "provider",
        "model",
        "invocation_id",
        "specialty",
        "prompt_sha256",
        "response_sha256",
    }
    if set(review) != common | {"decision", "findings", "coverage_gaps"}:
        raise RuntimeAuditError(
            "E_SPECIALTY_SCHEMA",
            "review must include exact findings and coverage dispositions",
        )
    if set(coordinator) != common | {"review_payload_sha256", "read_only"}:
        raise RuntimeAuditError("E_INVOCATION_SCHEMA", "unexpected invocation fields")
    if review["decision"] not in {"ACCEPT", "FINDINGS", "INCOMPLETE"}:
        raise RuntimeAuditError("E_SPECIALTY_SCHEMA", "unknown review decision")
    if not isinstance(review["findings"], list) or len(review["findings"]) > 4096:
        raise RuntimeAuditError(
            "E_SPECIALTY_SCHEMA", "review findings must be a bounded list"
        )
    if (
        not isinstance(review["coverage_gaps"], list)
        or len(review["coverage_gaps"]) > 4096
    ):
        raise RuntimeAuditError(
            "E_SPECIALTY_SCHEMA", "review coverage gaps must be a bounded list"
        )
    for gap in review["coverage_gaps"]:
        require_str(gap, "coverage_gap", maximum=2048)
    for finding in review["findings"]:
        _review_finding(finding, inventory)


def _review_finding(finding, inventory):
    if not isinstance(finding, dict) or set(finding) != {
        "id",
        "severity",
        "path",
        "evidence",
        "remediation",
    }:
        raise RuntimeAuditError("E_SPECIALTY_FINDING", "invalid specialty finding")
    for field in ("id", "evidence", "remediation"):
        require_str(finding[field], field, maximum=2048)
    if finding["path"] not in {item["path"] for item in inventory["files"]} or finding[
        "severity"
    ] not in {"critical", "high", "medium", "low"}:
        raise RuntimeAuditError(
            "E_SPECIALTY_FINDING", "unbound specialty finding or severity"
        )


def _review_provenance(review, coordinator, binding):
    for payload in (review, coordinator):
        if any(payload.get(key) != value for key, value in binding.items()):
            raise RuntimeAuditError(
                "E_REVIEW_BINDING",
                "review belongs to different inputs or run; replay rejected",
            )
        for key in ("provider", "model", "invocation_id", "specialty"):
            require_str(payload.get(key), key)
        for key in ("prompt_sha256", "response_sha256"):
            require_digest(payload.get(key), key)
    for key in (
        "provider",
        "model",
        "invocation_id",
        "specialty",
        "prompt_sha256",
        "response_sha256",
    ):
        if review[key] != coordinator[key]:
            raise RuntimeAuditError(
                "E_REVIEW_INVOCATION", "review and independent invocation record differ"
            )
    if (
        coordinator.get("review_payload_sha256") != digest(review)
        or coordinator.get("read_only") is not True
    ):
        raise RuntimeAuditError(
            "E_REVIEW_PROVENANCE",
            "trusted coordinator must bind a read-only specialty worker response",
        )


def _review_native_lanes(plan, evidence, inventory, run_id, directory):
    from .deep_audit_sarif import normalize_execution_bundle

    lanes = {lane["id"]: lane for lane in plan["lanes"]}
    if (
        len(evidence["lanes"]) != len(lanes)
        or {lane["lane_id"] for lane in evidence["lanes"]} != lanes.keys()
    ):
        raise RuntimeAuditError("E_REVIEW_LANES", "required lanes are missing")
    for observation in evidence["lanes"]:
        lane = lanes[observation["lane_id"]]
        bundle = read_run_json(directory, f"bundle-{lane['id']}.json")
        normalized = normalize_execution_bundle(
            bundle, lane, inventory, run_id, plan["obligations"]
        )
        if digest(bundle) != observation["bundle_sha256"]:
            raise RuntimeAuditError("E_REVIEW_BUNDLE", "native evidence changed")
        _review_fuzz_control_replay(
            plan, observation, normalized, lane, bundle, inventory
        )
        # Rerun instructions are added by the coordinator, not the native parser.
        recorded = [
            {key: value for key, value in finding.items() if key != "rerun"}
            for finding in observation["findings"]
        ]
        if normalized["findings"] != recorded or normalized["state"] != "OBSERVED":
            raise RuntimeAuditError(
                "E_REVIEW_NORMALIZATION",
                "native evidence is incomplete or normalized findings changed",
            )
        facts = observation.get("execution", {})
        if (
            facts.get("exit_code") != 0
            or facts.get("cleanup_confirmed") is not True
            or any(
                facts.get(key) is not False
                for key in (
                    "timed_out",
                    "output_limit_exceeded",
                    "launch_error",
                    "cancelled",
                )
            )
        ):
            raise RuntimeAuditError(
                "E_REVIEW_EXECUTION",
                "execution facts do not establish successful bounded completion",
            )


def _review_fuzz_control_replay(plan, observation, normalized, lane, bundle, inventory):
    from .deep_audit import apply_fuzz_control_replay, has_fuzz_controls

    if has_fuzz_controls(lane, inventory, plan["obligations"]) and observation.get(
        "fuzz_replay"
    ):
        apply_fuzz_control_replay(
            normalized,
            observation["fuzz_replay"],
            lane,
            bundle,
            inventory,
            plan["obligations"],
        )


def _review_candidate(
    root, plan, evidence, inventory, trust_root, trust_root_sha256, directory
):
    if (
        plan["trust_root_sha256"] != trust_root_sha256
        or digest(plan) != evidence["manifest_content_sha256"]
    ):
        raise RuntimeAuditError(
            "E_REVIEW_PLAN", "manifest or operator trust binding changed"
        )
    _execution_keys(plan, trust_root)
    from .deep_audit import _scope_gaps

    _authorized, authorization_sha256 = verify_execution_authorization(
        plan,
        evidence["manifest_sha256"],
        directory / "authorization.json",
        trust_root,
        trust_root_sha256,
        return_envelope_sha256=True,
    )
    persisted_authorization = read_run_json(directory, "authorization.json")
    if digest(persisted_authorization) != authorization_sha256:
        raise RuntimeAuditError(
            "E_REVIEW_AUTHORIZATION",
            "persisted authorization envelope differs from the verified envelope",
        )
    if authorization_sha256 != evidence["authorization_sha256"]:
        raise RuntimeAuditError(
            "E_REVIEW_AUTHORIZATION",
            "execution authorization differs from the reviewed run",
        )
    if _scope_gaps(plan, inventory):
        raise RuntimeAuditError(
            "E_REVIEW_COVERAGE", "source obligations are incomplete"
        )
    current = inventory_candidate(root)
    if current["candidate_sha256"] != evidence["candidate_sha256"] or current["gaps"]:
        raise RuntimeAuditError(
            "E_REVIEW_CANDIDATE",
            "current worktree differs from the complete reviewed candidate",
        )
    if (
        inventory["candidate_sha256"] != evidence["candidate_sha256"]
        or inventory["gaps"]
    ):
        raise RuntimeAuditError(
            "E_REVIEW_INVENTORY", "stored inventory is incomplete or different"
        )


def verify_execution_review(
    root: Path,
    run_id: str,
    attestation: Path,
    invocation: Path,
    trust_root: Path,
    trust_root_sha256: str,
) -> dict:
    """Require separate specialty-review and coordinator signatures over exact evidence."""
    directory = run_directory(root, run_id)
    evidence = read_run_json(directory, "evidence.json")
    plan = read_run_json(directory, "manifest.json")
    inventory = read_run_json(directory, "inventory.json")
    _review_candidate(
        root, plan, evidence, inventory, trust_root, trust_root_sha256, directory
    )
    _review_native_lanes(plan, evidence, inventory, run_id, directory)
    review = _execution_document(
        attestation,
        trust_root,
        trust_root_sha256,
        plan["reviewer_identity"],
        plan["reviewer_keyid"],
        "factory.deep-specialty-review.v1",
    )
    coordinator = _execution_document(
        invocation,
        trust_root,
        trust_root_sha256,
        plan["coordinator_identity"],
        plan["coordinator_keyid"],
        "factory.deep-review-invocation.v1",
    )
    _review_dispositions(review, coordinator, inventory)
    binding = {
        "run_id": run_id,
        "candidate_sha256": evidence["candidate_sha256"],
        "manifest_sha256": evidence["manifest_sha256"],
        "evidence_sha256": digest(evidence),
        "read_set_sha256": digest(inventory["files"]),
    }
    _review_provenance(review, coordinator, binding)
    complete = (
        evidence.get("analysis_complete") is True
        and not evidence["gaps"]
        and not review["coverage_gaps"]
    )
    findings = [finding for lane in evidence["lanes"] for finding in lane["findings"]]
    blocked = any(
        finding["severity"] in {"critical", "high"}
        for finding in findings + review["findings"]
    )
    decision = (
        "BLOCKED"
        if blocked
        else "READY_FOR_HUMAN_REVIEW"
        if complete and review["decision"] == "ACCEPT"
        else "INCOMPLETE"
    )
    return {
        "schema": "factory.deep-reviewed-run.v1",
        **binding,
        "state": decision,
        "specialty_ai_review": "COORDINATOR_ATTESTED",
        "review_sha256": digest(review),
        "invocation_sha256": digest(coordinator),
        "findings": findings,
        "reviewer_findings": review["findings"],
        "reviewer_coverage_gaps": review["coverage_gaps"],
        "provenance_limit": "Coordinator-attested invocation; no independent model-provider signature is claimed.",
        "authority": "none",
        "release_approval": False,
    }


class DeepAuditAttestationError(ValueError):
    """Stable, review-safe error for an invalid external deep-audit attestation."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _fail(code: str, message: str) -> None:
    raise DeepAuditAttestationError(code, message)


def _relative(root: Path, value: Path | str, field: str) -> str:
    try:
        candidate = Path(value)
    except (TypeError, ValueError) as exc:
        _fail("E_DEEP_ATTESTATION_PATH", f"{field} must be a workspace path")
        raise AssertionError from exc
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        _fail("E_DEEP_ATTESTATION_PATH", f"{field} must be inside the workspace")
    return relative.as_posix()


def _file(root: Path, value: Path | str, field: str) -> Path:
    relative = _relative(root, value, field)
    try:
        return local_file(root, relative)
    except (RuntimeAuditError, OSError) as exc:
        _fail("E_DEEP_ATTESTATION_PATH", f"{field} is not a regular workspace file")
        raise AssertionError from exc


def _digest(value: object, field: str) -> str:
    try:
        return require_digest(value, field)
    except RuntimeAuditError as exc:
        _fail(
            "E_DEEP_ATTESTATION_BINDING", f"{field} is not a lowercase SHA-256 digest"
        )
        raise AssertionError from exc


def _text(value: object, field: str, maximum: int = 256) -> str:
    try:
        return require_str(value, field, maximum=maximum)
    except RuntimeAuditError as exc:
        _fail("E_DEEP_ATTESTATION_SCHEMA", f"{field} is invalid")
        raise AssertionError from exc


def _exact(value: object, required: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != required:
        _fail("E_DEEP_ATTESTATION_SCHEMA", f"{field} has missing or unknown fields")
    return value


def _instant(value: object, field: str) -> datetime:
    text = _text(value, field, 40)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        _fail("E_DEEP_ATTESTATION_FRESHNESS", f"{field} is not an ISO-8601 instant")
        raise AssertionError from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail("E_DEEP_ATTESTATION_FRESHNESS", f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _verified_document(path: Path, trust_root: Path) -> dict[str, Any]:
    try:
        return verify_signed_document(
            path, payload_type=PAYLOAD_TYPE, schema=SCHEMA, trust_root_path=trust_root
        )
    except EnterpriseReceiptError as exc:
        _fail(
            "E_DEEP_ATTESTATION_SIGNATURE",
            f"offline DSSE verification failed ({exc.code})",
        )
        raise AssertionError from exc


def _validate_payload(
    payload: dict[str, Any], receipt: dict[str, Any], claimed_receipt: str
) -> tuple[dict, dict, datetime, datetime]:
    _validate_payload_header(payload, receipt, claimed_receipt)
    verifier = _validate_verifier(payload["verifier"], receipt)
    observations = _validate_observations(payload["observations"], receipt)
    return (
        verifier,
        observations,
        _instant(payload["issued_at"], "issued_at"),
        _instant(payload["expires_at"], "expires_at"),
    )


def _validate_payload_header(
    payload: dict[str, Any], receipt: dict[str, Any], claimed_receipt: str
) -> None:
    required = {
        "schema",
        "attestation_id",
        "receipt_sha256",
        "plan_sha256",
        "candidate_sha256",
        "ruleset_sha256",
        "canary_set_sha256",
        "issued_at",
        "expires_at",
        "verifier",
        "observations",
        "authority",
    }
    _exact(payload, required, "payload")
    if payload["schema"] != SCHEMA:
        _fail("E_DEEP_ATTESTATION_SCHEMA", "unexpected schema")
    _text(payload["attestation_id"], "attestation_id")
    if payload["authority"] != "none":
        _fail("E_DEEP_ATTESTATION_BINDING", "authority must remain none")
    for field, expected in (
        ("receipt_sha256", claimed_receipt),
        ("plan_sha256", receipt["plan_sha256"]),
        ("candidate_sha256", receipt["candidate_sha256"]),
        ("ruleset_sha256", receipt["ruleset_sha256"]),
        ("canary_set_sha256", receipt["canary_set_sha256"]),
    ):
        if _digest(payload[field], field) != _digest(expected, f"receipt.{field}"):
            _fail(
                "E_DEEP_ATTESTATION_BINDING", f"{field} differs from the signed receipt"
            )


def _validate_verifier(value: object, receipt: dict[str, Any]) -> dict[str, Any]:
    verifier = _exact(value, {"id", "version", "independent"}, "verifier")
    verifier_id = _text(verifier["id"], "verifier.id")
    _text(verifier["version"], "verifier.version")
    try:
        independent = require_bool(verifier["independent"], "verifier.independent")
    except RuntimeAuditError as exc:
        _fail("E_DEEP_ATTESTATION_INDEPENDENCE", "verifier.independent must be true")
        raise AssertionError from exc
    if not independent or verifier_id in set(receipt["report_hashes"]):
        _fail(
            "E_DEEP_ATTESTATION_INDEPENDENCE",
            "verifier must be independent of every analyzer",
        )
    return verifier


def _validate_observations(value: object, receipt: dict[str, Any]) -> dict[str, Any]:
    observations = _exact(value, {"report_hashes", "canary_hashes"}, "observations")
    for field in ("report_hashes", "canary_hashes"):
        observed = observations[field]
        expected = receipt[field]
        if not isinstance(observed, dict) or not 1 <= len(observed) <= 8:
            _fail("E_DEEP_ATTESTATION_BINDING", f"{field} coverage is incomplete")
        if set(observed) != set(expected):
            _fail(
                "E_DEEP_ATTESTATION_BINDING",
                f"{field} coverage differs from the receipt",
            )
        _validate_observation_hashes(field, observed, expected)
    return observations


def _validate_observation_hashes(
    field: str, observed: dict[str, Any], expected: dict[str, Any]
) -> None:
    for key, value in observed.items():
        _text(key, f"{field} analyzer id")
        if _digest(value, f"{field}.{key}") != _digest(
            expected[key], f"receipt.{field}.{key}"
        ):
            _fail(
                "E_DEEP_ATTESTATION_BINDING",
                f"{field}.{key} differs from the receipt",
            )


def _freshness(
    issued: datetime, expires: datetime, now: datetime | None, max_age_seconds: int
) -> dict[str, Any]:
    max_age = _max_attestation_age(max_age_seconds)
    _validate_attestation_window(issued, expires)
    current = _freshness_current_time(now)
    if issued > current or current >= expires:
        _fail("E_DEEP_ATTESTATION_FRESHNESS", "attestation is future-dated or expired")
    age = (current - issued).total_seconds()
    if age > max_age:
        _fail(
            "E_DEEP_ATTESTATION_FRESHNESS",
            "attestation is older than the allowed observation age",
        )
    return {
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "age_seconds": int(age),
        "max_age_seconds": max_age,
    }


def _max_attestation_age(max_age_seconds: int) -> int:
    try:
        return require_int(
            max_age_seconds, "max_age_seconds", minimum=1, maximum=MAX_VALIDITY_SECONDS
        )
    except RuntimeAuditError as exc:
        _fail(
            "E_DEEP_ATTESTATION_FRESHNESS",
            "max_age_seconds is outside the bounded window",
        )
        raise AssertionError from exc


def _validate_attestation_window(issued: datetime, expires: datetime) -> None:
    if expires <= issued or (expires - issued).total_seconds() > MAX_VALIDITY_SECONDS:
        _fail(
            "E_DEEP_ATTESTATION_FRESHNESS",
            "attestation validity exceeds the 24-hour bound",
        )


def _freshness_current_time(now: datetime | None) -> datetime:
    actual = datetime.now(timezone.utc)
    supplied = actual if now is None else now
    if not isinstance(supplied, datetime):
        _fail("E_DEEP_ATTESTATION_FRESHNESS", "now must be a datetime")
    if supplied.tzinfo is None or supplied.utcoffset() is None:
        _fail("E_DEEP_ATTESTATION_FRESHNESS", "now must include a timezone")
    return max(actual, supplied.astimezone(timezone.utc))


def verify_deep_audit_attestation(
    root: Path,
    attestation_path: Path,
    trust_root_path: Path,
    receipt_path: Path,
    *,
    now: datetime | None = None,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    """Verify one fresh independent DSSE attestation without executing or authorizing anything."""
    root = Path(root).resolve()
    attestation = _file(root, attestation_path, "attestation")
    trust_root = _file(root, trust_root_path, "trust_root")
    receipt_file = _file(root, receipt_path, "receipt")
    try:
        receipt, claimed_receipt, _ = _read_receipt(root, receipt_file)
    except (RuntimeAuditError, OSError, ValueError, KeyError, TypeError) as exc:
        _fail(
            "E_DEEP_ATTESTATION_BINDING",
            "receipt is not a valid self-hash deep-audit receipt",
        )
        raise AssertionError from exc
    verified = _verified_document(attestation, trust_root)
    verifier, _, issued, expires = _validate_payload(
        verified["payload"], receipt, claimed_receipt
    )
    freshness = _freshness(issued, expires, now, max_age_seconds)
    return {
        "schema": RESULT_SCHEMA,
        "state": "VERIFIED",
        "marker": "DEEP_AUDIT_ATTESTATION_VERIFIED",
        "receipt_sha256": claimed_receipt,
        "attestation_sha256": verified["payload_sha256"],
        "plan_sha256": receipt["plan_sha256"],
        "candidate_sha256": receipt["candidate_sha256"],
        "keyid": verified["signature"]["keyid"],
        "identity": verified["signature"]["identity"],
        "issuer": verified["signature"]["issuer"],
        "verifier": verifier,
        "freshness": freshness,
        "authority": "none",
        "release_approval": False,
        "claim_boundary": "Offline DSSE signer, receipt binding, and freshness verification only; semantic correctness and release approval remain unproven.",
    }


def _gitleaks_stderr_path(directory, lane):
    if lane.get("engine") == "gitleaks" and lane.get("tool_version") == "8.28.0":
        return directory / "stderr.log"
    return None


def _attach_gitleaks_ledger(invocation, command, directory):
    if "{factory_ledger}" not in " ".join(command["argv"]):
        return
    try:
        ledger, ledger_sha256, ledger_json = _deep_audit_io._read_gitleaks_ledger(
            directory / "rule-ledger.json"
        )
        invocation["native_rule_ledger"] = ledger
        invocation["native_rule_ledger_sha256"] = ledger_sha256
        invocation["native_rule_ledger_json"] = ledger_json
    except _deep_audit_io.RuntimeAuditError as exc:
        invocation["native_rule_ledger"] = None
        invocation["native_rule_ledger_error"] = exc.code


def _read_gitleaks_ledger(path: _deep_audit_io.Path) -> tuple[dict, str, str]:
    if path.is_symlink() or not path.is_file():
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_LEDGER_MISSING", "native ledger missing"
        )
    try:
        descriptor = _deep_audit_io.os.open(
            path,
            _deep_audit_io.os.O_RDONLY | getattr(_deep_audit_io.os, "O_NOFOLLOW", 0),
        )
        with _deep_audit_io.os.fdopen(descriptor, "rb") as stream:
            opened = _deep_audit_io.os.fstat(stream.fileno())
            if (
                not _deep_audit_io.stat.S_ISREG(opened.st_mode)
                or opened.st_size > _deep_audit_io.NATIVE_LEDGER_LIMIT
            ):
                raise _deep_audit_io.RuntimeAuditError(
                    "E_GITLEAKS_LEDGER_SIZE", "native ledger over budget"
                )
            raw = stream.read(_deep_audit_io.NATIVE_LEDGER_LIMIT + 1)
            after = _deep_audit_io.os.fstat(stream.fileno())
        current = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_LEDGER_READ", "native ledger could not be read safely"
        ) from exc
    if not _deep_audit_io._stable_ledger_read(opened, after, current, raw):
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_LEDGER_SIZE", "native ledger changed while read"
        )
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_LEDGER_READ", "native ledger encoding invalid"
        ) from exc
    return _deep_audit_io.strict_json(raw), _deep_audit_io.sha256_bytes(raw), text


def _stable_ledger_read(opened, after, current, raw):
    if len(raw) > _deep_audit_io.NATIVE_LEDGER_LIMIT or not _deep_audit_io.stat.S_ISREG(
        current.st_mode
    ):
        return False
    if (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino):
        return False
    if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
        return False
    return _deep_audit_io._ledger_metadata_matches(opened, after, current, raw)


def _ledger_metadata_matches(opened, after, current, raw):
    return (
        opened.st_size == after.st_size
        and opened.st_mtime_ns == after.st_mtime_ns
        and opened.st_ctime_ns == after.st_ctime_ns
        and opened.st_mtime_ns == current.st_mtime_ns
        and opened.st_ctime_ns == current.st_ctime_ns
        and len(raw) == opened.st_size
    )


def _gitleaks_ledger_matrix(
    ledger, ledger_sha, lane, inventory, inventory_sha, invocations, raw_report
):
    required = {
        item["path"]: item["sha256"]
        for item in inventory["files"]
        if item["language"] in lane["languages"]
    }
    if not _deep_audit_io._gitleaks_ledger_shape(ledger):
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_LEDGER_SHAPE", "native ledger schema differs"
        )
    if not _deep_audit_io._gitleaks_ledger_binding(ledger, lane, inventory):
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_LEDGER_BINDING", "native ledger binding incomplete"
        )
    source_map = _deep_audit_io._gitleaks_source_map(inventory["files"])
    source_map_sha = inventory["candidate_sha256"]
    counts = _deep_audit_io._gitleaks_ledger_rows(
        ledger["rows"], lane["rule_ids"], source_map
    )
    accounting = _deep_audit_io._gitleaks_accounting(
        ledger_sha,
        lane,
        required,
        counts,
        inventory_sha,
        source_map_sha,
        invocations,
        raw_report,
    )
    return accounting, source_map, source_map_sha


def _gitleaks_ledger_shape(ledger):
    expected = {
        "schema",
        "root_sha256",
        "source_identity_kind",
        "source_sha256",
        "config_sha256",
        "prefilter_bypassed",
        "complete",
        "overflow",
        "invalid_paths",
        "rows",
    }
    return (
        isinstance(ledger, dict)
        and set(ledger) == expected
        and isinstance(ledger.get("rows"), list)
        and len(ledger["rows"]) <= 200_000
    )


def _gitleaks_ledger_binding(ledger, lane, inventory):
    return _deep_audit_io._gitleaks_ledger_identity(
        ledger, lane, inventory
    ) and _deep_audit_io._gitleaks_ledger_status(ledger)


def _gitleaks_ledger_identity(ledger, lane, inventory):
    return (
        ledger["schema"] == "gitleaks.factory-rule-ledger.v1"
        and ledger["source_identity_kind"] == "adapter_candidate_sha256"
        and ledger["source_sha256"] == inventory["candidate_sha256"]
        and ledger["config_sha256"] == lane["ruleset_sha256"]
        and ledger["root_sha256"] == _deep_audit_io.sha256_bytes(b"/src")
    )


def _gitleaks_ledger_status(ledger):
    return (
        ledger["prefilter_bypassed"] is True
        and ledger["complete"] is True
        and ledger["overflow"] is False
        and type(ledger["invalid_paths"]) is int
        and ledger["invalid_paths"] == 0
    )


def _gitleaks_source_map(files):
    estimate = sum(
        len(_deep_audit_io.canonical_bytes(item["path"]))
        + len(_deep_audit_io.canonical_bytes(item["language"]))
        + 112
        for item in files
    )
    if estimate > _deep_audit_io.NATIVE_SOURCE_MAP_LIMIT:
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_LEDGER_SIZE", "native source map over budget"
        )
    sources = {item["path"]: item["sha256"] for item in files}
    if (
        _deep_audit_io._json_size_upper_bound(files)
        > _deep_audit_io.NATIVE_SOURCE_MAP_LIMIT
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_LEDGER_SIZE", "native source map over budget"
        )
    if (
        len(_deep_audit_io.canonical_bytes(files))
        > _deep_audit_io.NATIVE_SOURCE_MAP_LIMIT
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_LEDGER_SIZE", "native source map over budget"
        )
    return sources


def _gitleaks_ledger_rows(rows, rule_ids, required):
    observed = {}
    allowed = {
        "attempted",
        "suppressed_skip_report",
        "suppressed_rule_allowlist",
        "suppressed_global_allowlist",
        "path_evaluated",
        "not_applicable_path_mismatch",
        "not_applicable_no_regex",
        "not_run_size_limit",
        "regex_executed",
        "regex_match",
        "finding",
    }
    for row in rows:
        path, rule_id, counts = _deep_audit_io._gitleaks_row_values(row, allowed)
        if (
            path not in required
            or rule_id not in rule_ids
            or (path, rule_id) in observed
        ):
            raise _deep_audit_io.RuntimeAuditError(
                "E_GITLEAKS_LEDGER_ROW", "native ledger row unbound"
            )
        observed[path, rule_id] = counts
    return observed


def _gitleaks_row_values(row, allowed):
    if not isinstance(row, dict) or set(row) != {"path", "rule_id", "counts"}:
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_LEDGER_ROW", "native ledger row malformed"
        )
    path, rule_id, counts = row["path"], row["rule_id"], row["counts"]
    if not isinstance(path, str) or not isinstance(rule_id, str):
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_LEDGER_ROW", "native ledger row malformed"
        )
    if not isinstance(counts, dict) or not counts or not set(counts) <= allowed:
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_LEDGER_ROW", "native counters malformed"
        )
    _deep_audit_io._gitleaks_counter_values(counts)
    return path, rule_id, counts


def _gitleaks_counter_values(counts):
    if any(
        type(value) is not int or not 1 <= value <= 2**63 - 1
        for value in counts.values()
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_LEDGER_ROW", "native counter invalid"
        )
    attempted = counts.get("attempted", 0)
    evaluated = max(counts.get("regex_executed", 0), counts.get("path_evaluated", 0))
    if attempted < evaluated or counts.get("finding", 0) > counts.get("regex_match", 0):
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_LEDGER_ROW", "native counters are inconsistent"
        )


def _gitleaks_accounting(
    ledger_sha,
    lane,
    required,
    counts,
    inventory_sha,
    source_map_sha,
    invocations,
    raw_report,
):
    pairs = len(lane["rule_ids"]) * len(required)
    estimate = 512 + pairs * 512
    estimate += len(lane["rule_ids"]) * sum(
        len(_deep_audit_io.canonical_bytes(path)) for path in required
    )
    estimate += len(required) * sum(
        len(_deep_audit_io.canonical_bytes(rule_id)) for rule_id in lane["rule_ids"]
    )
    if pairs > 200_000 or estimate > _deep_audit_io.NATIVE_ACCOUNTING_LIMIT:
        _deep_audit_io._native_budget_error(
            "E_GITLEAKS_LEDGER_SIZE",
            len(required),
            len(lane["rule_ids"]),
            estimate,
            _deep_audit_io.NATIVE_ACCOUNTING_LIMIT,
        )
    rules = []
    for rule_id in sorted(lane["rule_ids"]):
        sources = []
        for path, source_sha in sorted(required.items()):
            native_counts = counts.get((path, rule_id), {})
            disposition = _deep_audit_io._gitleaks_disposition(native_counts)
            evidence = {
                "ledger_sha256": ledger_sha,
                "source_sha256": source_sha,
                "path": path,
                "rule_id": rule_id,
                "counts": native_counts,
            }
            sources.append(
                {
                    "path": path,
                    "source_sha256": source_sha,
                    "disposition": disposition,
                    "native_counts": native_counts,
                    "evidence_sha256": _deep_audit_io.digest(evidence),
                }
            )
        rules.append({"rule_id": rule_id, "sources": sources})
    body = {
        "schema": "factory.deep-rule-accounting.v1",
        "ruleset_sha256": lane["ruleset_sha256"],
        "rule_inventory_sha256": inventory_sha,
        "native_ledger_sha256": ledger_sha,
        "native_source_inventory_sha256": source_map_sha,
        "invocation_sha256": _deep_audit_io.digest(invocations),
        "native_report_sha256": _deep_audit_io.digest(raw_report),
        "rules": rules,
    }
    accounting = {**body, "accounting_sha256": _deep_audit_io.digest(body)}
    if (
        len(_deep_audit_io.canonical_bytes(accounting))
        > _deep_audit_io.NATIVE_ACCOUNTING_LIMIT
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_LEDGER_SIZE", "native accounting over budget"
        )
    return accounting


def _gitleaks_disposition(counts):
    if any(key.startswith("suppressed_") for key in counts):
        return "suppressed"
    if counts.get("not_run_size_limit", 0) > 0:
        return "not_run"
    if counts.get("regex_executed", 0) > 0 or counts.get("path_evaluated", 0) > 0:
        return "executed"
    if (
        counts.get("not_applicable_path_mismatch", 0) > 0
        or counts.get("not_applicable_no_regex", 0) > 0
    ):
        return "not_applicable"
    return "not_run"


def _gitleaks_scanned_bytes(stderr: bytes, tool_version: str) -> int:
    """Read v8.28.0's integer detector counter; the parenthesized size is display-only."""
    import re

    if tool_version != "8.28.0":
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_COUNTER_VERSION", "counter format is unpinned"
        )
    plain = re.sub(rb"\x1b\[[0-9;]*m", b"", stderr)
    lines = [line for line in plain.splitlines() if b"scanned ~" in line]
    if len(lines) != 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_COUNTER", "one consistent native byte counter required"
        )
    match = re.fullmatch(
        rb"[0-9]{1,2}:[0-9]{2}(?:AM|PM) INF scanned ~([0-9]+) bytes "
        rb"\(([0-9]+(?:\.[0-9]+)?) (bytes|KB|MB|GB)\) in [0-9.]+(?:ms|s)",
        lines[0],
    )
    if match is None:
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_COUNTER", "malformed native byte counter"
        )
    counter, _displayed, _unit = match.groups()
    value = int(counter)
    if value > _deep_audit_io.SOURCE_LIMIT:
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_COUNTER", "native byte count is invalid"
        )
    return value


def _native_runtime_accounting(report: dict, inventory: dict, lane: dict) -> dict:
    """Expose actual observed source accounting separately from requested inventory."""
    required = {
        item["path"]: item["sha256"]
        for item in inventory["files"]
        if item["language"] in lane["languages"]
    }
    measured = report.get("source_coverage")
    if not isinstance(measured, dict):
        return {
            "state": "UNAVAILABLE",
            "required_paths": sorted(required),
            "measured_paths": [],
            "missing_paths": sorted(required),
        }
    if set(measured) - set(required):
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_COVERAGE", "measured source is outside declared lane"
        )
    if any(
        not isinstance(item, dict) or item.get("sha256") != required[path]
        for path, item in measured.items()
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_COVERAGE", "measured source hash differs"
        )
    missing = sorted(set(required) - set(measured))
    return {
        "state": "PARTIAL" if missing else "COMPLETE",
        "required_paths": sorted(required),
        "measured_paths": sorted(measured),
        "missing_paths": missing,
    }


def _retained_fuzz_corpus(report, sources):
    try:
        raw = _deep_audit_io._codeql_blob_bytes(
            report.get("fuzz_corpus"), maximum=4_194_304
        )
        return _deep_audit_io._validate_fuzz_corpus(raw, report, sources)
    except _deep_audit_io.RuntimeAuditError as error:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_CORPUS", "retained fuzz evidence rejected"
        ) from error


def _fuzz_replay_control_evidence(request):
    if "obligations" not in request:
        return None
    inventory = request["inventory"]
    return _deep_audit_io.verify_fuzz_retained_evidence(
        request["challenges"],
        request["obligations"],
        request["lane"],
        {item["path"]: item["sha256"] for item in inventory["files"]},
        inventory["candidate_sha256"],
        request["coverage"],
    )


def _atheris_challenge_retained_budget(observations):
    total = 0
    for observation in observations:
        evidence = observation.get("atheris_native_evidence", {})
        for key in ("raw_report", "corpus_manifest", "effective_config"):
            total += _deep_audit_io.require_int(
                evidence.get(key, {}).get("bytes"),
                "Atheris retained bytes",
                minimum=0,
                maximum=_deep_audit_io.LIMIT,
            )
    if total > _deep_audit_io.NATIVE_COVERAGE_LIMIT:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "retained controls exceed budget"
        )


def verify_fuzz_retained_evidence(
    challenges, obligations, lane, sources, candidate_sha256, coverage
):
    """Validate retained signed Atheris controls without granting coverage."""
    try:
        _deep_audit_io._fuzz_retained_bundle_shape(challenges)
        candidate_sha256 = _deep_audit_io.require_digest(
            candidate_sha256, "candidate_sha256"
        )
        expected = _deep_audit_io._fuzz_retained_expected(obligations, lane, sources)
        observed = _deep_audit_io._fuzz_retained_observations(
            challenges, expected, lane, sources, candidate_sha256, coverage
        )
        _deep_audit_io._fuzz_retained_gaps(challenges["gaps"], expected)
        _deep_audit_io._atheris_challenge_retained_budget(challenges["observations"])
        controls = [observed[key] for key in sorted(expected)]
    except _deep_audit_io.RuntimeAuditError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, OSError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "retained Atheris controls invalid"
        ) from exc
    control_bindings = [
        {
            "obligation_id": item["obligation_id"],
            "kind": item["kind"],
            "evidence": item["native_evidence"],
        }
        for item in controls
    ]
    return (
        {
            "challenge_sha256": _deep_audit_io.digest(challenges),
            "obligations_sha256": _deep_audit_io.digest(obligations),
            "covered_obligations": sorted({key[0] for key in expected}),
            "controls_sha256": _deep_audit_io.digest(control_bindings),
            "control_count": len(controls),
        },
        controls,
    )


def _fuzz_retained_bundle_shape(challenges):
    _deep_audit_io.exact_keys(challenges, {"schema", "observations", "gaps"})
    if (
        challenges["schema"] != "factory.deep-challenges.v1"
        or not isinstance(challenges["observations"], list)
        or not isinstance(challenges["gaps"], list)
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "challenge bundle shape differs"
        )


def _fuzz_retained_expected(obligations, lane, sources):
    if (
        lane.get("engine") != "atheris"
        or lane.get("family") != "fuzz"
        or not isinstance(obligations, list)
        or not isinstance(sources, dict)
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "signed Atheris obligations required"
        )
    obligations = [
        item
        for item in obligations
        if isinstance(item, dict)
        and item.get("engine") == "atheris"
        and item.get("family") == "fuzz"
        and isinstance(item.get("paths"), list)
        and set(item["paths"]) <= set(sources)
    ]
    if not obligations or len(obligations) > 64:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "applicable obligations required"
        )
    expected = {}
    for obligation in obligations:
        _deep_audit_io._fuzz_retained_obligation_valid(obligation, sources)
        identity = _deep_audit_io.require_str(
            obligation.get("id"), "obligation id", maximum=128
        )
        if identity in {key[0] for key in expected}:
            raise _deep_audit_io.RuntimeAuditError(
                "E_FUZZ_ARTIFACT", "duplicate obligation"
            )
        by_kind = _deep_audit_io._fuzz_retained_control_kinds(obligation)
        for kind, challenge in by_kind.items():
            key = (identity, kind)
            if key in expected:
                raise _deep_audit_io.RuntimeAuditError(
                    "E_FUZZ_ARTIFACT", "duplicate signed control"
                )
            expected[key] = (challenge, obligation)
    if len(expected) > 192:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "control count exceeds budget"
        )
    return expected


def _fuzz_retained_obligation_valid(obligation, sources):
    if not isinstance(obligation, dict):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "obligation object required"
        )
    valid = (
        obligation.get("engine") == "atheris"
        and obligation.get("family") == "fuzz"
        and obligation.get("detector_rule_id") == "FUZZ_EXCEPTION"
        and isinstance(obligation.get("paths"), list)
        and set(obligation["paths"]) <= set(sources)
    )
    if not valid:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "obligation binding differs"
        )


def _fuzz_retained_control_kinds(obligation):
    controls = obligation.get("challenges")
    if not isinstance(controls, list) or len(controls) != 3:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "three signed controls required"
        )
    by_kind = {item.get("kind"): item for item in controls if isinstance(item, dict)}
    if set(by_kind) != {"positive", "negative", "mutation"} or len(by_kind) != 3:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "signed control triplet differs"
        )
    return by_kind


def _fuzz_retained_observations(
    challenges, expected, lane, sources, candidate_sha256, coverage
):
    from .deep_audit_sarif import _challenge_execution_gap, _challenge_gap

    approved = {key: value for key, value in expected.items()}
    observed = {}
    for observation in challenges["observations"]:
        if not isinstance(observation, dict):
            raise _deep_audit_io.RuntimeAuditError(
                "E_FUZZ_ARTIFACT", "challenge observation required"
            )
        key = (observation.get("obligation_id"), observation.get("kind"))
        if key not in expected or key in observed:
            raise _deep_audit_io.RuntimeAuditError(
                "E_FUZZ_ARTIFACT", "unknown or duplicate control"
            )
        challenge, obligation = expected[key]
        challenge_gap = _challenge_gap(observation, key, approved, lane, sources)
        execution_gap = _challenge_execution_gap(
            observation,
            challenge,
            obligation,
            key,
            lane,
            coverage,
            candidate_sha256,
        )
        if challenge_gap or execution_gap:
            raise _deep_audit_io.RuntimeAuditError(
                "E_FUZZ_ARTIFACT", "signed challenge validation failed"
            )
        observed[key] = _deep_audit_io._fuzz_retained_control_evidence(
            observation, challenge, obligation, lane, sources
        )
    if set(observed) != set(expected):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "signed control triplet incomplete"
        )
    return observed


def _fuzz_retained_control_evidence(observation, challenge, obligation, lane, sources):
    evidence = observation.get("atheris_native_evidence")
    _deep_audit_io.exact_keys(
        evidence,
        {
            "schema",
            "source_manifest",
            "source_manifest_sha256",
            "raw_report",
            "corpus_manifest",
            "effective_config",
        },
    )
    manifest = evidence["source_manifest"]
    if (
        evidence["schema"] != "factory.atheris-retained-challenge.v1"
        or manifest != challenge.get("fixture_manifest")
        or evidence["source_manifest_sha256"] != _deep_audit_io.digest(manifest)
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "retained source manifest differs"
        )
    _deep_audit_io._fuzz_fixture_manifest_binding(
        manifest, obligation, sources, challenge["fixture_path"]
    )
    raw_report = _deep_audit_io._codeql_blob_bytes(
        evidence["raw_report"], _deep_audit_io.LIMIT
    )
    corpus_raw = _deep_audit_io._codeql_blob_bytes(
        evidence["corpus_manifest"], _deep_audit_io.LIMIT
    )
    config = _deep_audit_io._codeql_blob_bytes(evidence["effective_config"], 4096)
    _deep_audit_io._fuzz_retained_execution_artifacts(
        observation, raw_report, corpus_raw, config
    )
    raw = _deep_audit_io.strict_json(raw_report)
    normalized = _deep_audit_io._atheris_challenge_report(
        raw_report, corpus_raw, config, challenge, lane, manifest
    )
    report = observation.get("report")
    if not isinstance(report, dict) or normalized != report.get("native_report"):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "retained report differs"
        )
    corpus = _deep_audit_io._validate_fuzz_corpus(corpus_raw, raw, manifest)
    return {
        "obligation_id": obligation["id"],
        "kind": challenge["kind"],
        "harness": {
            "path": challenge["fixture_path"],
            "sha256": manifest[challenge["fixture_path"]],
        },
        "report": raw,
        "corpus": corpus,
        "config": config,
        "native_evidence": evidence,
        "detector_enabled": _deep_audit_io._fuzz_control_ids(config)
        == ["FUZZ_EXCEPTION"],
        "corpus_hashes": {item["sha256"] for item in corpus["inputs"]},
        "retained_failure_inputs": sorted(
            {item["input_sha256"] for item in raw["findings"]}
        ),
    }


def _fuzz_retained_execution_artifacts(observation, raw_report, corpus_raw, config):
    execution = observation["execution"]
    expected = sorted(
        [
            {
                "kind": "fuzz_result",
                "bytes": len(raw_report),
                "sha256": _deep_audit_io.sha256_bytes(raw_report),
            },
            {
                "kind": "corpus_manifest",
                "bytes": len(corpus_raw),
                "sha256": _deep_audit_io.sha256_bytes(corpus_raw),
            },
        ],
        key=lambda item: item["kind"],
    )
    if (
        execution.get("native_artifacts") != expected
        or execution.get("raw_report_sha256") != _deep_audit_io.sha256_bytes(raw_report)
        or execution.get("effective_config_sha256")
        != _deep_audit_io.sha256_bytes(config)
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "retained control execution artifacts differ"
        )


def _fuzz_retained_gaps(gaps, expected):
    if not isinstance(gaps, list) or len(gaps) != len(expected):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "unexpected challenge gaps"
        )
    actual = set()
    for gap in gaps:
        if (
            not isinstance(gap, dict)
            or set(gap) != {"obligation_id", "kind", "reason"}
            or gap.get("reason") != "FUZZ_CHALLENGE_REPLAY_REQUIRED"
        ):
            raise _deep_audit_io.RuntimeAuditError(
                "E_FUZZ_ARTIFACT", "challenge gap is not replay-only"
            )
        key = (gap["obligation_id"], gap["kind"])
        if key not in expected or key in actual:
            raise _deep_audit_io.RuntimeAuditError(
                "E_FUZZ_ARTIFACT", "challenge gap identity differs"
            )
        actual.add(key)
    if actual != set(expected):
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "replay gaps are incomplete"
        )


def _osv_database_identity(lane, deadline=None):
    _deep_audit_io._osv_check_deadline(deadline)
    policy = lane.get("native_policy")
    path_text = "/opt/factory/osv-db/osv-scanner/PyPI/all.zip"
    if not isinstance(policy, dict) or policy.get("database_path") != path_text:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_POLICY", "pinned database path required"
        )
    path = _deep_audit_io.local_file(_deep_audit_io.Path("/"), path_text.lstrip("/"))
    before = path.stat()
    if not path.is_file() or before.st_size > 128 * 1024 * 1024:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_DATABASE", "bounded database file required"
        )
    hasher = _deep_audit_io.hashlib.sha256()
    total = 0
    try:
        descriptor = _deep_audit_io.os.open(
            path,
            _deep_audit_io.os.O_RDONLY | getattr(_deep_audit_io.os, "O_NOFOLLOW", 0),
        )
        with _deep_audit_io.os.fdopen(descriptor, "rb") as stream:
            opened = _deep_audit_io.os.fstat(stream.fileno())
            while chunk := stream.read(1024 * 1024):
                _deep_audit_io._osv_check_deadline(deadline)
                total += len(chunk)
                if total > 128 * 1024 * 1024:
                    raise _deep_audit_io.RuntimeAuditError(
                        "E_OSV_DATABASE", "database exceeds identity byte budget"
                    )
                hasher.update(chunk)
            after = _deep_audit_io.os.fstat(stream.fileno())
    except OSError as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_DATABASE", "database identity unavailable"
        ) from exc
    current = path.stat()
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        any(
            (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns) != identity
            for item in (opened, after, current)
        )
        or total != before.st_size
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_DATABASE", "database changed while hashing"
        )
    actual = hasher.hexdigest()
    if actual != _deep_audit_io.require_digest(
        policy.get("database_sha256"), "database_sha256"
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_DATABASE", "pinned database hash differs"
        )
    _deep_audit_io._osv_check_deadline(deadline)
    return {"path": path_text, "sha256": actual, "bytes": total}


def _osv_challenge_retained_budget(observations):
    total = 0
    for observation in observations:
        evidence = observation.get("osv_native_evidence", {})
        for key in ("raw_report", "effective_config", "database_identity"):
            total += _deep_audit_io.require_int(
                evidence.get(key, {}).get("bytes"),
                "OSV retained bytes",
                minimum=0,
                maximum=_deep_audit_io.LIMIT,
            )
    if total > _deep_audit_io.NATIVE_COVERAGE_LIMIT:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_ARTIFACT", "retained OSV artifacts exceed aggregate budget"
        )


def _osv_native_blob(raw):
    try:
        return _deep_audit_io._codeql_native_blob(raw, _deep_audit_io.LIMIT)
    except _deep_audit_io.RuntimeAuditError as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_ARTIFACT", "OSV artifact exceeds bounds"
        ) from exc


def _osv_native_bytes(blob):
    try:
        return _deep_audit_io._codeql_blob_bytes(blob, _deep_audit_io.LIMIT)
    except _deep_audit_io.RuntimeAuditError as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_ARTIFACT", "invalid retained OSV artifact"
        ) from exc


def _osv_primary_evidence(execution, required):
    raw = execution.get("raw_report_bytes")
    database = execution.get("osv_database_identity")
    if not isinstance(raw, bytes) or not isinstance(database, bytes):
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_ARTIFACT", "primary native artifacts missing"
        )
    return {
        "schema": "factory.osv-native-evidence.v1",
        "source_bindings": dict(sorted(required.items())),
        "primary": {
            "raw_report": _deep_audit_io._osv_native_blob(raw),
            "database_identity": _deep_audit_io._osv_native_blob(database),
        },
    }


def _osv_database_artifact(blob, lane):
    raw = _deep_audit_io._osv_native_bytes(blob)
    identity = _deep_audit_io.strict_json(raw)
    if (
        not isinstance(identity, dict)
        or set(identity) != {"path", "sha256", "bytes"}
        or identity.get("path") != lane["native_policy"].get("database_path")
        or identity.get("sha256") != lane["native_policy"].get("database_sha256")
        or type(identity.get("bytes")) is not int
        or not 0 < identity["bytes"] <= 128 * 1024 * 1024
        or _deep_audit_io.canonical_bytes(identity) != raw
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_ARTIFACT", "database identity binding differs"
        )
    return identity


def _osv_normalize_retained_paths(report, source_root, manifest):
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_ARTIFACT", "native OSV results required"
        )
    root = _deep_audit_io._osv_source_root_prefix(source_root)
    for item in report["results"]:
        _deep_audit_io._osv_normalize_result_source(item, root, manifest)
    _deep_audit_io._osv_lookup_paths(
        report,
        lambda path: _deep_audit_io._osv_normalize_lookup_path(path, root, manifest),
    )
    return report


def _osv_source_root_prefix(source_root):
    if not isinstance(source_root, str) or not source_root.startswith("/"):
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_ARTIFACT", "absolute fixture root required"
        )
    parts = source_root.split("/")
    if "\\" in source_root or any(part in {"", ".", ".."} for part in parts[1:]):
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_ARTIFACT", "absolute fixture root required"
        )
    return source_root + "/"


def verify_osv_retained_challenge(observation, lane, bound, obligation, kind):
    """Validate bounded retained OSV control artifacts against approved bindings."""
    from .deep_audit_sarif import _osv_challenge_rows

    try:
        evidence = observation["osv_native_evidence"]
        manifest = _deep_audit_io._osv_challenge_manifest(evidence, bound, kind)
        _deep_audit_io._osv_challenge_execution(observation, lane, manifest)
        raw = _deep_audit_io._osv_challenge_report_bytes(
            evidence, lane, observation, obligation, kind
        )
        report = _deep_audit_io._osv_normalize_retained_paths(
            _deep_audit_io.strict_json(raw), evidence["source_root"], manifest
        )
        if _deep_audit_io.canonical_bytes(report) != _deep_audit_io.canonical_bytes(
            observation["report"]["native_report"]
        ):
            raise ValueError("normalized challenge report differs")
        summary = _osv_challenge_rows(report, lane, manifest, obligation, kind)
        if summary != observation.get("osv_control_evidence"):
            raise ValueError("challenge semantics differ")
        return summary
    except (
        _deep_audit_io.RuntimeAuditError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    ) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_ARTIFACT", "retained OSV challenge invalid"
        ) from exc


def verify_osv_retained_evidence(
    coverage, lane, required, report, challenges, obligations
):
    """Validate primary and control artifacts without granting replay authority."""
    try:
        accounting = _deep_audit_io._osv_primary_retained(
            coverage, lane, required, report
        )
        observed = _deep_audit_io._osv_retained_observations(
            challenges, obligations, lane, required
        )
        return {
            "state": "REPLAY_REQUIRED",
            "source_accounting": accounting,
            "controls": len(observed),
        }
    except (
        _deep_audit_io.RuntimeAuditError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    ) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_ARTIFACT", "retained OSV evidence invalid"
        ) from exc


def _osv_primary_retained(coverage, lane, required, report):
    from .deep_audit_sarif import _osv_source_accounting

    evidence = coverage["osv_native_evidence"]
    _deep_audit_io.exact_keys(evidence, {"schema", "source_bindings", "primary"})
    if (
        evidence["schema"] != "factory.osv-native-evidence.v1"
        or evidence["source_bindings"] != dict(sorted(required.items()))
        or set(evidence["primary"])
        != {
            "raw_report",
            "database_identity",
        }
    ):
        raise ValueError("primary evidence binding differs")
    raw = _deep_audit_io._osv_native_bytes(evidence["primary"]["raw_report"])
    _deep_audit_io._osv_database_artifact(
        evidence["primary"]["database_identity"], lane
    )
    native = _deep_audit_io.strict_json(raw)
    if _deep_audit_io.digest(native) != coverage["native_report_sha256"]:
        raise ValueError("retained primary native report hash differs")
    _deep_audit_io._native_dependency_paths(native, "osv-json", required)
    if _deep_audit_io.canonical_bytes(native) != _deep_audit_io.canonical_bytes(report):
        raise ValueError("primary normalized report differs")
    if _deep_audit_io.digest(report) != coverage["report_sha256"]:
        raise ValueError("primary report hash differs")
    accounting = _osv_source_accounting(report, required, lane["mode"])
    if accounting["state"] != "COMPLETE" or accounting != coverage["source_accounting"]:
        raise ValueError("source accounting incomplete or differs")
    return accounting


def _osv_retained_observations(challenges, obligations, lane, required):
    _deep_audit_io.exact_keys(challenges, {"schema", "observations", "gaps"})
    if challenges["schema"] != "factory.deep-challenges.v1":
        raise ValueError("challenge schema differs")
    expected = _deep_audit_io._osv_retained_expected(obligations, lane, required)
    observed = _deep_audit_io._osv_retained_observed(challenges, expected, lane)
    _deep_audit_io._osv_challenge_retained_budget(challenges["observations"])
    if set(observed) != set(expected) or challenges.get("gaps"):
        raise ValueError("retained controls incomplete")
    _deep_audit_io._osv_retained_controls_match(observed, obligations)
    return observed


def _osv_retained_expected(obligations, lane, required):
    expected = {
        (item["id"], control["kind"]): (item, control)
        for item in obligations
        if item["engine"] == "osv"
        and item["family"] == lane["family"]
        and set(item["paths"]) <= set(required)
        for control in item["challenges"]
    }
    if not expected or len(expected) > 192:
        raise ValueError("complete bounded control set required")
    return expected


def _osv_retained_observed(challenges, expected, lane):
    observed = {}
    for observation in challenges.get("observations", []):
        key = (observation.get("obligation_id"), observation.get("kind"))
        if key not in expected or key in observed:
            raise ValueError("unexpected or duplicate control")
        item, control = expected[key]
        observed[key] = _deep_audit_io.verify_osv_retained_challenge(
            observation, lane, control, item, control["kind"]
        )
    return observed


def _osv_retained_controls_match(observed, obligations):
    for item in obligations:
        if (item["id"], "positive") not in observed:
            continue
        rows = {
            kind: observed[(item["id"], kind)]
            for kind in ("positive", "negative", "mutation")
        }
        if not _deep_audit_io._osv_challenge_controls_match(rows):
            raise ValueError("OSV challenge controls do not match")


def verify_trivy_rule_execution(
    evidence, lane, sources, report, *, disabled_rule_id=None
):
    """Re-derive Trivy applicability and outcomes from paired native JSON/SARIF bytes."""
    from .runtime_audit_common import _validate_runner_facts

    config, ignore, observations = _deep_audit_io._trivy_evidence_inputs(
        evidence, lane, sources, disabled_rule_id
    )
    expected_ids = _deep_audit_io._trivy_expected_ids(lane, disabled_rule_id)
    decoded = [_deep_audit_io._trivy_observation_bytes(item) for item in observations]
    _deep_audit_io._trivy_pair_identity(
        observations[0]["argv"], observations[1]["argv"]
    )
    for item in observations:
        facts = item["execution"]
        _validate_runner_facts(facts, facts.get("timeout_seconds"))
        budget = _deep_audit_io.require_int(
            facts["timeout_seconds"],
            "Trivy timeout",
            minimum=1,
            maximum=lane["timeout_seconds"],
        )
        _deep_audit_io.require_int(
            facts["duration_ms"], "Trivy duration", minimum=0, maximum=budget * 1000
        )
        if _deep_audit_io._adapter_command_failed(facts, [0], float("inf")):
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_EXECUTION", "paired Trivy command did not complete"
            )
    native_report = _deep_audit_io.strict_json(decoded[1])
    source_bytes = _deep_audit_io._trivy_decode_source_bytes(evidence, sources)
    bindings = _deep_audit_io._trivy_target_bindings(
        native_report, sources, source_bytes
    )
    if evidence.get("target_bindings") != bindings:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_APPLICABILITY", "Trivy target bindings differ"
        )
    matrix = _deep_audit_io._trivy_native_checks(native_report, sources, bindings)
    _deep_audit_io._trivy_matrix_ids(matrix, expected_ids)
    sarif = _deep_audit_io.strict_json(decoded[0])
    fail_rows = _deep_audit_io._trivy_expected_failures(
        native_report, bindings, sarif, sources, observations[0]["argv"][-1]
    )
    if (
        _deep_audit_io._trivy_sarif_failures(
            sarif, sources, observations[0]["argv"][-1]
        )
        != fail_rows
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "native JSON and SARIF findings differ"
        )
    if _deep_audit_io._trivy_expected_failures(
        native_report, bindings, report, sources
    ) != _deep_audit_io._trivy_sarif_failures(report, sources):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "normalized report differs from native status"
        )
    return {"state": "VERIFIED", "checks": matrix, "findings": len(fail_rows)}


def _trivy_evidence_inputs(evidence, lane, sources, disabled_rule_id):
    import base64

    if (
        not isinstance(evidence, dict)
        or set(evidence)
        != {
            "schema",
            "config_base64",
            "ignore_base64",
            "sources",
            "observations",
            "target_bindings",
            "source_bytes_base64",
        }
        or evidence["schema"] != "factory.trivy-rule-execution.v1"
        or evidence["sources"] != sources
        or not isinstance(lane.get("native_policy"), dict)
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "signed Trivy evidence is missing"
        )
    try:
        config = base64.b64decode(evidence["config_base64"], validate=True)
        ignore = base64.b64decode(evidence["ignore_base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "Trivy policy bytes are malformed"
        ) from exc
    if _deep_audit_io.sha256_bytes(config) != lane["native_policy"]["config_sha256"]:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_POLICY", "Trivy config identity differs"
        )
    observations = evidence["observations"]
    if (
        not isinstance(observations, list)
        or len(observations) != 2
        or any(not isinstance(item, dict) for item in observations)
        or [item.get("format") for item in observations] != ["sarif", "json"]
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "paired Trivy observations are missing"
        )
    expected_ignore = lane["native_policy"]["baseline_ignore_sha256"]
    if disabled_rule_id is not None:
        expected_ignore = lane.get("mutation_config_sha256", {}).get(disabled_rule_id)
    if not expected_ignore or _deep_audit_io.sha256_bytes(ignore) != expected_ignore:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_POLICY", "Trivy ignorefile identity differs"
        )
    if disabled_rule_id is not None and not _deep_audit_io._trivy_mutation_valid(
        b"", ignore, disabled_rule_id
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_MUTATION", "Trivy target ignore differs"
        )
    return config, ignore, observations


def _semgrep_rule_inventory(config, lane):
    import yaml

    if _deep_audit_io.sha256_bytes(config) != lane["ruleset_sha256"]:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_RULESET", "pinned Semgrep ruleset differs"
        )
    try:
        rules = yaml.safe_load(config)["rules"]
    except (yaml.YAMLError, KeyError, TypeError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_RULESET", "invalid Semgrep rules"
        ) from exc
    if not isinstance(rules, list) or not 1 <= len(rules) <= 64:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_RULESET", "bounded rules required"
        )
    if any(not isinstance(rule, dict) for rule in rules):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_RULESET", "rule objects required"
        )
    ids = [
        _deep_audit_io.require_str(rule.get("id"), "rule id", maximum=256)
        for rule in rules
    ]
    if len(set(ids)) != len(ids) or sorted(ids) != lane.get("rule_ids"):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_RULESET", "signed rule inventory differs"
        )
    inventory = {"ruleset_sha256": lane["ruleset_sha256"], "rule_ids": sorted(ids)}
    return sorted(rules, key=lambda rule: rule["id"]), {
        "state": "VERIFIED",
        "rule_ids": sorted(ids),
        "sha256": _deep_audit_io.digest(inventory),
    }


def _semgrep_rule_runs(profile, lane, source, scratch, rules, started):
    import base64
    from .runtime_audit_process import run_bounded_command

    observations = []
    deadline = started + lane["timeout_seconds"]
    for index, rule in enumerate(rules):
        remaining = int(deadline - _deep_audit_io.time.monotonic())
        if remaining < 1:
            raise _deep_audit_io.RuntimeAuditError(
                "E_ADAPTER_TIMEOUT", "Semgrep rule budget exhausted"
            )
        directory = scratch / f"semgrep-rule-{index}"
        directory.mkdir()
        config = _deep_audit_io.canonical_bytes({"rules": [rule]})
        config_path, report_path = directory / "rule.json", directory / "report.json"
        config_path.write_bytes(config)
        argv = [
            profile["commands"][0]["argv"][0],
            "scan",
            "--json",
            "--strict",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--disable-nosem",
            "--no-rewrite-rule-ids",
            "--config",
            str(config_path),
            "--json-output",
            str(report_path),
            str(source),
        ]
        facts = run_bounded_command(argv, source, remaining, directory)
        if _deep_audit_io._adapter_command_failed(facts, [0], deadline):
            raise _deep_audit_io.RuntimeAuditError(
                "E_SEMGREP_EXECUTION", "native rule execution failed"
            )
        with _deep_audit_io.local_file(directory, "report.json").open("rb") as stream:
            raw = stream.read(_deep_audit_io.LIMIT + 1)
        report = _deep_audit_io.strict_json(raw)
        observations.append(
            {
                "rule_id": rule["id"],
                "rule_config_sha256": _deep_audit_io.sha256_bytes(config),
                "rule_config_base64": base64.b64encode(config).decode("ascii"),
                "argv_sha256": _deep_audit_io.digest(argv),
                "argv": argv,
                "execution": facts,
                "native_report": report,
                "native_report_sha256": _deep_audit_io.digest(report),
                "raw_report_sha256": _deep_audit_io.sha256_bytes(raw),
                "raw_report_base64": base64.b64encode(raw).decode("ascii"),
            }
        )
    return {"schema": "factory.semgrep-rule-execution.v1", "observations": observations}


def verify_semgrep_rule_execution(evidence, lane, sources, report):
    """Re-derive execution and findings from exact pinned rules plus per-rule native JSON."""
    from .runtime_audit_common import _validate_runner_facts

    rules, observations = _deep_audit_io._semgrep_evidence_inputs(
        evidence, lane, sources
    )
    findings, dispositions = [], []
    for index, (rule, observation) in enumerate(zip(rules, observations)):
        _deep_audit_io._semgrep_observation_identity(rule, observation, index)
        facts = observation["execution"]
        _validate_runner_facts(facts, facts.get("timeout_seconds"))
        if facts["timeout_seconds"] > lane["timeout_seconds"]:
            raise _deep_audit_io.RuntimeAuditError(
                "E_SEMGREP_EXECUTION", "rule exceeds signed budget"
            )
        if _deep_audit_io._adapter_command_failed(facts, [0], float("inf")):
            raise _deep_audit_io.RuntimeAuditError(
                "E_SEMGREP_EXECUTION", "native rule did not complete"
            )
        native = observation["native_report"]
        expected = _deep_audit_io._semgrep_rule_sources(rule, sources)
        scanned = _deep_audit_io._semgrep_scanned_sources(native, sources, lane)
        if scanned != expected:
            raise _deep_audit_io.RuntimeAuditError(
                "E_SEMGREP_EXECUTION", "native source execution differs"
            )
        findings.extend(
            _deep_audit_io._semgrep_json_findings(native, rule["id"], sources)
        )
        dispositions.append(
            {
                "rule_id": rule["id"],
                "executed_sources": sorted(scanned),
                "not_applicable_sources": sorted(set(sources) - scanned),
                "native_report_sha256": observation["native_report_sha256"],
            }
        )
    baseline = _deep_audit_io._semgrep_sarif_findings(report, lane["rule_ids"], sources)
    if sorted(findings) != sorted(baseline):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "per-rule findings contradict baseline"
        )
    return {"state": "VERIFIED", "rules": dispositions, "findings": len(findings)}


def _semgrep_evidence_inputs(evidence, lane, sources):
    import base64

    if (
        not isinstance(evidence, dict)
        or set(evidence) != {"schema", "ruleset_base64", "observations"}
        or evidence["schema"] != "factory.semgrep-rule-execution.v1"
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "native rule evidence missing"
        )
    try:
        config = base64.b64decode(evidence["ruleset_base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_RULESET", "invalid native ruleset"
        ) from exc
    rules, _inventory = _deep_audit_io._semgrep_rule_inventory(config, lane)
    observations = evidence["observations"]
    if not isinstance(observations, list) or len(observations) != len(rules):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "rule observation inventory differs"
        )
    if len(sources) > 64:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "bounded source inventory required"
        )
    return rules, observations


def _semgrep_observation_identity(rule, observation, index):
    import base64

    fields = {
        "rule_id",
        "rule_config_sha256",
        "rule_config_base64",
        "argv_sha256",
        "argv",
        "execution",
        "native_report",
        "native_report_sha256",
        "raw_report_sha256",
        "raw_report_base64",
    }
    if not isinstance(observation, dict) or set(observation) != fields:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "invalid native rule record"
        )
    if observation["rule_id"] != rule["id"] or observation[
        "rule_config_sha256"
    ] != _deep_audit_io.digest({"rules": [rule]}):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_RULESET", "isolated native rule differs"
        )
    if observation["rule_config_base64"] != base64.b64encode(
        _deep_audit_io.canonical_bytes({"rules": [rule]})
    ).decode("ascii"):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_RULESET", "native config bytes differ"
        )
    for key in ("argv_sha256", "raw_report_sha256"):
        _deep_audit_io.require_digest(observation[key], key)
    if (
        _deep_audit_io.digest(observation["native_report"])
        != observation["native_report_sha256"]
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "native report digest differs"
        )
    _deep_audit_io._semgrep_raw_bindings(observation, index)


def _semgrep_raw_bindings(observation, index):
    import base64
    from pathlib import PurePosixPath

    argv = observation["argv"]
    prefix = [
        "/usr/bin/semgrep",
        "scan",
        "--json",
        "--strict",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--disable-nosem",
        "--no-rewrite-rule-ids",
        "--config",
    ]
    if not isinstance(argv, list) or len(argv) != 14 or argv[:10] != prefix:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "isolated command differs"
        )
    config, report = PurePosixPath(argv[10]), PurePosixPath(argv[12])
    if (
        argv[11] != "--json-output"
        or argv[13] != "/src"
        or config.name != "rule.json"
        or report.name != "report.json"
        or config.parent != report.parent
        or config.parent.name != f"semgrep-rule-{index}"
        or not config.is_absolute()
        or ".." in config.parts
        or not str(config).startswith("/tmp/factory-native-")
        or _deep_audit_io.digest(argv) != observation["argv_sha256"]
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "native command binding differs"
        )
    encoded = observation["raw_report_base64"]
    if (
        not isinstance(encoded, str)
        or len(encoded) > (_deep_audit_io.LIMIT + 2) // 3 * 4
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "bounded raw report required"
        )
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "invalid raw report"
        ) from exc
    if (
        len(raw) > _deep_audit_io.LIMIT
        or _deep_audit_io.sha256_bytes(raw) != observation["raw_report_sha256"]
        or _deep_audit_io.strict_json(raw) != observation["native_report"]
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "raw report binding differs"
        )


def _native_profile_coverage(
    execution, report, inventory, lane, profile, challenges, covered_obligations
):
    ledger = execution["ledger"]
    ledger_sha256 = execution["ledger_sha256"]
    rule_accounting = None
    native_source_inventory = None
    native_source_inventory_sha256 = None
    if lane["engine"] == "gitleaks" and ledger is not None and ledger_sha256:
        _deep_audit_io._gitleaks_coverage_preflight(
            execution, report, inventory, lane, challenges, covered_obligations
        )
        (
            rule_accounting,
            native_source_inventory,
            native_source_inventory_sha256,
        ) = _deep_audit_io._gitleaks_ledger_matrix(
            ledger,
            ledger_sha256,
            lane,
            inventory,
            execution["rule_inventory"]["sha256"],
            execution["invocations"],
            execution["raw_report"],
        )
    errors = ["NATIVE_SOURCE_ACCOUNTING_REQUIRED", "NATIVE_CHALLENGES_REQUIRED"]
    complete = False
    if lane["engine"] == "gitleaks":
        errors = _deep_audit_io._gitleaks_coverage_errors(
            rule_accounting, challenges, covered_obligations
        )
        complete = not errors
    elif lane["engine"] == "trivy":
        errors = _deep_audit_io._trivy_coverage_errors(
            execution, report, inventory, lane, challenges, covered_obligations
        )
        complete = not errors
    elif lane["engine"] == "runtime" and profile["report_format"] == "runtime-junit":
        errors = _deep_audit_io._runtime_coverage_errors(
            report, inventory, lane, challenges, covered_obligations
        )
        complete = not errors
    elif execution.get("semgrep_rule_execution") is not None:
        _deep_audit_io._semgrep_source_accounting(execution, inventory, lane)
        errors = (
            []
            if _deep_audit_io._gitleaks_challenges_complete(
                challenges, covered_obligations
            )
            else ["NATIVE_CHALLENGES_REQUIRED"]
        )
        complete = not errors
    elif lane["engine"] == "osv":
        from .deep_audit_sarif import _osv_lookup_binding_gaps

        errors = _osv_lookup_binding_gaps(report, lane)
        if (
            _deep_audit_io._native_source_accounting(
                execution, report, inventory, lane
            )["state"]
            != "COMPLETE"
        ):
            errors.append("NATIVE_SOURCE_ACCOUNTING_REQUIRED")
        if not _deep_audit_io._osv_challenges_complete(challenges, covered_obligations):
            errors.append("NATIVE_CHALLENGES_REQUIRED")
        complete = not errors
    coverage = {
        "profile_sha256": _deep_audit_io.digest(profile),
        "image_binding_sha256": _deep_audit_io.sha256_bytes(
            str(lane.get("image", "")).encode("utf-8")
        ),
        "schema": "factory.deep-coverage.v1",
        "complete": complete,
        "sources": {
            item["path"]: item["sha256"]
            for item in inventory["files"]
            if item["language"] in lane["languages"]
        },
        "mode": lane["mode"],
        "fallback": False,
        "tool_version": profile["tool_version"],
        "ruleset_sha256": profile["ruleset_sha256"],
        "report_sha256": _deep_audit_io.digest(report),
        "native_report_sha256": _deep_audit_io.digest(execution["raw_report"]),
        "source_accounting": _deep_audit_io._native_source_accounting(
            execution, report, inventory, lane
        ),
        "native_invocations": execution["invocations"],
        "invocation_sha256": _deep_audit_io.digest(execution["invocations"]),
        "version_probe": execution["version_probe"],
        "errors": errors,
        "obligations": covered_obligations,
        **(
            {"codeql_query_inventory": execution["codeql_query_inventory"]}
            if execution.get("codeql_query_inventory") is not None
            else {}
        ),
        **(
            {"codeql_query_execution": execution["codeql_query_execution"]}
            if execution.get("codeql_query_execution") is not None
            else {}
        ),
        **(
            {"codeql_source_execution": execution["codeql_source_execution"]}
            if execution.get("codeql_source_execution") is not None
            else {}
        ),
        **(
            {"semgrep_rule_execution": execution["semgrep_rule_execution"]}
            if execution.get("semgrep_rule_execution") is not None
            else {}
        ),
        **(
            {"trivy_rule_execution": execution["trivy_rule_execution"]}
            if execution.get("trivy_rule_execution") is not None
            else {}
        ),
        **(
            {"rule_inventory": execution["rule_inventory"]}
            if execution["rule_inventory"] is not None
            else {}
        ),
        **(
            {
                "candidate_sha256": inventory["candidate_sha256"],
                "native_rule_ledger_json": execution["ledger_json"],
                "native_rule_ledger_sha256": ledger_sha256,
                "native_source_inventory": inventory["files"]
                if ledger is not None
                else None,
                "native_source_inventory_sha256": native_source_inventory_sha256,
            }
            if ledger is not None
            else {}
        ),
        **({"rule_accounting": rule_accounting} if rule_accounting is not None else {}),
    }
    if lane["engine"] == "gitleaks":
        source_count = len(coverage["sources"])
        rule_count = len(lane["rule_ids"])
        _deep_audit_io._bounded_json_bytes(
            coverage,
            _deep_audit_io.NATIVE_COVERAGE_LIMIT,
            "E_GITLEAKS_LEDGER_SIZE",
            source_count,
            rule_count,
        )
    return coverage


def _codeql_native_blob(raw, maximum=67_108_864):
    import base64
    import zlib

    if not isinstance(raw, bytes) or len(raw) > maximum:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_ARTIFACT", "native artifact budget exceeded"
        )
    compressed = zlib.compress(raw)
    if len(compressed) > _deep_audit_io.NATIVE_COVERAGE_LIMIT:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_ARTIFACT", "compressed artifact budget exceeded"
        )
    return {
        "encoding": "zlib-base64",
        "bytes": len(raw),
        "sha256": _deep_audit_io.sha256_bytes(raw),
        "data": base64.b64encode(compressed).decode("ascii"),
    }


def _codeql_blob_bytes(blob, maximum=67_108_864):
    import base64
    import zlib

    try:
        if not isinstance(blob, dict) or set(blob) != {
            "encoding",
            "bytes",
            "sha256",
            "data",
        }:
            raise ValueError("exact artifact fields required")
        size = _deep_audit_io.require_int(
            blob["bytes"], "artifact bytes", minimum=0, maximum=maximum
        )
        seal = _deep_audit_io.require_digest(blob["sha256"], "artifact hash")
        if (
            blob["encoding"] != "zlib-base64"
            or not isinstance(blob["data"], str)
            or len(blob["data"]) > 4 * ((_deep_audit_io.NATIVE_COVERAGE_LIMIT + 2) // 3)
        ):
            raise ValueError("bounded compressed artifact required")
        compressed = base64.b64decode(blob["data"], validate=True)
        if len(compressed) > _deep_audit_io.NATIVE_COVERAGE_LIMIT:
            raise ValueError("compressed artifact budget exceeded")
        decoder = zlib.decompressobj()
        raw = decoder.decompress(compressed, size + 1)
        if (
            len(raw) != size
            or not decoder.eof
            or decoder.unconsumed_tail
            or decoder.unused_data
            or _deep_audit_io.sha256_bytes(raw) != seal
        ):
            raise ValueError("native artifact bytes differ")
        return raw
    except (
        _deep_audit_io.RuntimeAuditError,
        ValueError,
        TypeError,
        KeyError,
        zlib.error,
    ) as error:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_ARTIFACT", "invalid retained native artifact"
        ) from error


def verify_codeql_retained_evidence(coverage, lane, required):
    """Verify retained native bytes; opaque BQRS still requires independent replay."""
    try:
        inventory, records = _deep_audit_io._codeql_retained_inventory(coverage, lane)
        seen, total = set(), 0
        for record in records:
            rule_id = record["rule_id"]
            if (
                rule_id in seen
                or inventory["query_ids"].get(rule_id) != record["query_path"]
            ):
                raise ValueError("duplicate or unexpected query record")
            seen.add(rule_id)
            total += _deep_audit_io._codeql_verify_retained_query(record, inventory)
            if total > 536_870_912:
                raise ValueError("aggregate native artifact budget exceeded")
        source = _deep_audit_io._codeql_verify_retained_source(
            coverage["codeql_source_execution"], required
        )
        return {
            "state": "REPLAY_REQUIRED",
            "queries": len(seen),
            "source_accounting": source,
        }
    except (
        _deep_audit_io.RuntimeAuditError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    ) as error:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_ARTIFACT", "retained CodeQL evidence is unverified"
        ) from error


def _codeql_retained_inventory(coverage, lane):
    inventory = coverage["codeql_query_inventory"]
    _deep_audit_io.verify_codeql_query_selection(inventory)
    execution = coverage["codeql_query_execution"]
    if (
        execution["schema"] != "factory.codeql-query-execution.v1"
        or execution["query_inventory_sha256"] != inventory["query_inventory_sha256"]
        or execution["ruleset_sha256"] != lane["ruleset_sha256"]
        or execution["suite_sha256"] != inventory["suite_sha256"]
    ):
        raise ValueError("query execution inventory differs")
    records = execution["rules"]
    if (
        not isinstance(records, list)
        or len(records) != len(inventory["query_ids"])
        or lane["rule_ids"] != sorted(inventory["query_ids"])
    ):
        raise ValueError("complete native query records required")
    return inventory, records


def _codeql_verify_retained_query(record, inventory):
    blobs = record["native_artifacts"]
    if set(blobs) != {"result", "info"}:
        raise ValueError("native query artifact roles differ")
    raw = _deep_audit_io._codeql_blob_bytes(blobs["result"])
    info = _deep_audit_io._codeql_blob_bytes(blobs["info"], 65_536)
    if (
        not raw
        or len(raw) != record["result_bytes"]
        or _deep_audit_io.sha256_bytes(raw) != record["result_sha256"]
        or record["query_sha256"] != inventory["queries"][record["query_path"]]
        or record["result_path"]
        != _deep_audit_io._codeql_result_path(record["query_path"])
    ):
        raise ValueError("native result binding differs")
    invocation = record["invocation"]
    _deep_audit_io._codeql_retained_invocation(invocation)
    if (
        invocation["argv_sha256"] != _deep_audit_io.digest(invocation["argv"])
        or _deep_audit_io.sha256_bytes(info) != invocation["execution"]["stdout_sha256"]
        or len(info) != invocation["execution"]["stdout_bytes"]
        or _deep_audit_io._codeql_result_sets(info) != record["result_sets"]
    ):
        raise ValueError("native result metadata differs")
    return len(raw)


def _codeql_retained_invocation(invocation):
    from .runtime_audit_common import _validate_runner_facts

    facts = invocation["execution"]
    _validate_runner_facts(facts, facts["timeout_seconds"])
    if (
        invocation["argv_sha256"] != _deep_audit_io.digest(invocation["argv"])
        or facts["exit_code"] != 0
        or facts["timed_out"]
        or facts["launch_error"]
        or facts["output_limit_exceeded"]
        or facts["cleanup_confirmed"] is not True
        or facts.get("cancelled")
    ):
        raise ValueError("native invocation incomplete")


def _codeql_verify_retained_source(measurement, required):
    blobs = measurement["native_artifacts"]
    if set(blobs) != {"query", "package", "result", "decoded", "archive", "info"}:
        raise ValueError("native source artifact roles differ")
    raw = {key: _deep_audit_io._codeql_blob_bytes(blob) for key, blob in blobs.items()}
    invocations = measurement["native_invocations"]
    if not isinstance(invocations, list) or len(invocations) != 3:
        raise ValueError("all source measurement steps required")
    for invocation in invocations:
        _deep_audit_io._codeql_retained_invocation(invocation)
    if invocations[-1]["execution"]["stdout_sha256"] != _deep_audit_io.sha256_bytes(
        raw["info"]
    ) or invocations[-1]["execution"]["stdout_bytes"] != len(raw["info"]):
        raise ValueError("source metadata stream differs")
    for role, field in {
        "query": "query_sha256",
        "package": "package_sha256",
        "result": "result_sha256",
        "decoded": "decoded_sha256",
        "archive": "archive_sha256",
    }.items():
        if _deep_audit_io.sha256_bytes(raw[role]) != measurement[field]:
            raise ValueError("source artifact binding differs")
    rows = _deep_audit_io._codeql_parse_rows(raw["decoded"])
    if rows != measurement["rows"] or _deep_audit_io._codeql_result_sets(
        raw["info"]
    ) != [{"name": "#select", "rows": len(rows), "columns": 3}]:
        raise ValueError("native source rows differ")
    archived = _deep_audit_io._codeql_retained_archive(
        raw["archive"], measurement["archive_prefix"], required
    )
    if archived != measurement["archived_sources"]:
        raise ValueError("archived source bindings differ")
    inventory = {
        "files": [
            {"path": path, "sha256": seal, "language": "required"}
            for path, seal in required.items()
        ]
    }
    return _deep_audit_io._codeql_source_accounting(
        measurement, inventory, {"languages": ["required"]}
    )


def _codeql_retained_archive(raw, prefix, required):
    import io
    import zipfile

    if (
        not isinstance(prefix, str)
        or not prefix.endswith("/")
        or prefix.startswith("/")
        or "\\" in prefix
        or ".." in prefix.split("/")
    ):
        raise ValueError("canonical archive prefix required")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zipped:
            entries = zipped.infolist()
            if (
                len(entries) > 100_000
                or sum(item.file_size for item in entries) > 536_870_912
            ):
                raise ValueError("source archive budget exceeded")
            names = _deep_audit_io.Counter(item.filename for item in entries)
            archived = {}
            for path in required:
                name = prefix + _deep_audit_io.relative_path(path)
                if names[name] != 1:
                    continue
                with zipped.open(name) as member:
                    captured = member.read(_deep_audit_io.LIMIT + 1)
                if len(captured) > _deep_audit_io.LIMIT:
                    raise ValueError("source member budget exceeded")
                archived[path] = _deep_audit_io.sha256_bytes(captured)
            return archived
    except (zipfile.BadZipFile, OSError, RuntimeError) as error:
        raise ValueError("invalid retained source archive") from error


def _codeql_source_measurement(profile, source, scratch, inventory, lane, deadline):
    remaining = int(deadline - _deep_audit_io.time.monotonic())
    if remaining < 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "source evidence deadline exhausted"
        )
    library, query = _deep_audit_io._codeql_source_query(profile)
    directory = scratch / "source-evidence"
    directory.mkdir()
    pack = directory / "pack"
    pack.mkdir()
    package = (
        f"name: factory/{library}-source-accounting\nversion: 0.0.1\n"
        f"dependencies:\n  codeql/{library}-all: '*'\n"
    ).encode("utf-8")
    (pack / "sources.ql").write_bytes(query)
    (pack / "qlpack.yml").write_bytes(package)
    executable = profile["version_argv"][0]
    result, decoded = directory / "sources.bqrs", directory / "sources.json"
    argv = [
        [
            executable,
            "query",
            "run",
            str(pack / "sources.ql"),
            f"--database={scratch / 'codeql-db'}",
            f"--output={result}",
            "--search-path=/opt/codeql/codeql/qlpacks",
            "--threads=2",
            "--ram=2048",
        ],
        [
            executable,
            "bqrs",
            "decode",
            str(result),
            "--format=json",
            f"--output={decoded}",
        ],
        [executable, "bqrs", "info", str(result), "--format=json"],
    ]
    _, invocations = _deep_audit_io._codeql_steps_runner(
        [{"argv": command, "accepted_exit_codes": [0]} for command in argv],
        source,
        remaining,
        directory,
    )
    with _deep_audit_io.local_file(directory, decoded.name).open("rb") as stream:
        raw = stream.read(_deep_audit_io.NATIVE_COVERAGE_LIMIT + 1)
    rows = _deep_audit_io._codeql_parse_rows(raw)
    with _deep_audit_io.local_file(directory / "step-2", "stdout.log").open(
        "rb"
    ) as stream:
        info = stream.read(65_537)
    if _deep_audit_io._codeql_result_sets(info) != [
        {"name": "#select", "rows": len(rows), "columns": 3}
    ]:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_SOURCE", "source result metadata differs"
        )
    with _deep_audit_io.local_file(directory, result.name).open("rb") as stream:
        binary = stream.read(67_108_865)
    if not binary or len(binary) > 67_108_864:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_SOURCE", "source result budget exceeded"
        )
    required = {
        item["path"]: item["sha256"]
        for item in inventory["files"]
        if item["language"] in lane["languages"]
    }
    archived, archive_sha = _deep_audit_io._codeql_archived_sources(
        source, scratch, required
    )
    with _deep_audit_io.local_file(scratch / "codeql-db", "src.zip").open(
        "rb"
    ) as stream:
        archive = stream.read(67_108_865)
    if _deep_audit_io.sha256_bytes(archive) != archive_sha:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_SOURCE", "source archive changed"
        )
    return {
        "schema": "factory.codeql-source-execution.v1",
        "rows": rows,
        "archived_sources": archived,
        "archive_sha256": archive_sha,
        "query_sha256": _deep_audit_io.sha256_bytes(query),
        "package_sha256": _deep_audit_io.sha256_bytes(package),
        "decoded_sha256": _deep_audit_io.sha256_bytes(raw),
        "result_sha256": _deep_audit_io.sha256_bytes(binary),
        "native_invocations": invocations,
        "archive_prefix": source.resolve().as_posix().lstrip("/") + "/",
        "native_artifacts": {
            "query": _deep_audit_io._codeql_native_blob(query),
            "package": _deep_audit_io._codeql_native_blob(package),
            "result": _deep_audit_io._codeql_native_blob(binary),
            "decoded": _deep_audit_io._codeql_native_blob(raw),
            "archive": _deep_audit_io._codeql_native_blob(archive),
            "info": _deep_audit_io._codeql_native_blob(info),
        },
    }


def _codeql_source_accounting(measurement, inventory, lane):
    try:
        rows, archived = measurement["rows"], measurement["archived_sources"]
        if not isinstance(rows, dict) or not isinstance(archived, dict):
            raise ValueError("source evidence maps required")
        checks = {}
        for item in inventory["files"]:
            if item["language"] in lane["languages"]:
                path = _deep_audit_io.relative_path(item["path"])
                if path in checks:
                    raise ValueError("duplicate source inventory")
                seal = _deep_audit_io.require_digest(item["sha256"], "source hash")
                checks[path] = {
                    "state": _deep_audit_io._codeql_source_state(
                        rows.get(path), archived.get(path), seal
                    ),
                    "sha256": seal,
                }
        measured = sorted(
            path for path, item in checks.items() if item["state"] == "EXTRACTED"
        )
        missing = sorted(
            path for path, item in checks.items() if item["state"] == "NOT_EXTRACTED"
        )
        degraded = sorted(set(checks) - set(measured) - set(missing))
        unexpected = sorted(set(rows) - {item["path"] for item in inventory["files"]})
        return {
            "state": "COMPLETE"
            if checks and len(measured) == len(checks) and not unexpected
            else "INCOMPLETE",
            "checks": checks,
            "required_paths": sorted(checks),
            "measured_paths": measured,
            "missing_paths": missing,
            "degraded_paths": degraded,
            "unexpected_paths": unexpected,
            "claim_boundary": "Syntax model and parser diagnostics for candidate-bound archived source bytes; not runtime behavior or per-query source reachability.",
        }
    except (_deep_audit_io.RuntimeAuditError, ValueError, TypeError, KeyError) as error:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_SOURCE", "invalid source accounting evidence"
        ) from error


def _codeql_source_state(row, archived, seal):
    if row is None:
        return "NOT_EXTRACTED"
    nodes = _deep_audit_io.require_int(
        row["syntax_nodes"], "syntax nodes", minimum=0, maximum=2**31 - 1
    )
    errors = _deep_audit_io.require_int(
        row["parse_errors"], "parse errors", minimum=0, maximum=2**31 - 1
    )
    if errors:
        return "PARSE_ERROR"
    if not nodes:
        return "NO_SYNTAX_MODEL"
    if archived != seal:
        return "SOURCE_MISMATCH"
    return "EXTRACTED"


def _codeql_archived_sources(source, scratch, required):
    import io
    import zipfile

    archive = _deep_audit_io.local_file(scratch / "codeql-db", "src.zip")
    with archive.open("rb") as stream:
        raw = stream.read(67_108_865)
    if len(raw) > 67_108_864:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_SOURCE", "source archive budget exceeded"
        )
    prefix = source.resolve().as_posix().lstrip("/") + "/"
    measured = {}
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zipped:
            names = zipped.namelist()
            if len(names) > 100_000:
                raise _deep_audit_io.RuntimeAuditError(
                    "E_CODEQL_SOURCE", "source archive entry budget exceeded"
                )
            for path, seal in required.items():
                name = prefix + _deep_audit_io.relative_path(path)
                if names.count(name) != 1:
                    continue
                candidate = _deep_audit_io.bound_bytes(
                    source, {"path": path, "sha256": seal}
                )
                with zipped.open(name) as member:
                    captured = member.read(len(candidate) + 1)
                measured[path] = _deep_audit_io.sha256_bytes(captured)
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError) as error:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_SOURCE", "invalid native source archive"
        ) from error
    return measured, _deep_audit_io.sha256_bytes(raw)


def _codeql_query_execution(profile, inventory, source, scratch, deadline):
    _deep_audit_io.verify_codeql_query_selection(inventory)
    records, total_bytes = [], 0
    database = scratch / "codeql-db"
    for rule_id, query_path in sorted(inventory["query_ids"].items()):
        result_path = _deep_audit_io._codeql_result_path(query_path)
        artifact = _deep_audit_io.local_file(database, result_path)
        with artifact.open("rb") as stream:
            raw = stream.read(67_108_865)
        total_bytes += len(raw)
        if not raw or len(raw) > 67_108_864 or total_bytes > 536_870_912:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_EXECUTION", "result artifact budget exceeded"
            )
        records.append(
            _deep_audit_io._codeql_query_result_record(
                profile,
                source,
                scratch,
                deadline,
                rule_id,
                query_path,
                inventory["queries"][query_path],
                result_path,
                artifact,
                raw,
            )
        )
    return {
        "schema": "factory.codeql-query-execution.v1",
        "ruleset_sha256": profile["ruleset_sha256"],
        "query_inventory_sha256": inventory["query_inventory_sha256"],
        "suite_sha256": inventory["suite_sha256"],
        "rules": records,
        "claim_boundary": "Native BQRS artifacts from the fresh database, including zero-row results; not per-source query coverage or detection accuracy.",
    }


def _codeql_query_result_record(
    profile,
    source,
    scratch,
    deadline,
    rule_id,
    query_path,
    query_sha,
    result_path,
    artifact,
    raw,
):
    from .runtime_audit_process import run_bounded_command
    from .runtime_audit_common import _validate_runner_facts

    remaining = int(deadline - _deep_audit_io.time.monotonic())
    if remaining < 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "query evidence deadline exhausted"
        )
    directory = scratch / (
        "query-evidence-" + _deep_audit_io.sha256_bytes(rule_id.encode())[:16]
    )
    directory.mkdir()
    out = directory / "stdout.json"
    argv = [profile["version_argv"][0], "bqrs", "info", str(artifact), "--format=json"]
    facts = run_bounded_command(argv, source, remaining, directory, stdout_path=out)
    _validate_runner_facts(facts, remaining)
    if _deep_audit_io._adapter_command_failed(facts, [0], deadline):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_EXECUTION", "native result inspection failed"
        )
    with _deep_audit_io.local_file(directory, out.name).open("rb") as stream:
        info = stream.read(65_537)
    if (
        len(info) != facts["stdout_bytes"]
        or _deep_audit_io.sha256_bytes(info) != facts["stdout_sha256"]
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_EXECUTION", "result info bytes differ"
        )
    with _deep_audit_io.local_file(artifact.parent, artifact.name).open("rb") as stream:
        current = stream.read(len(raw) + 1)
    if current != raw:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_EXECUTION", "result artifact changed"
        )
    return {
        "rule_id": rule_id,
        "query_path": query_path,
        "query_sha256": query_sha,
        "result_path": result_path,
        "result_sha256": _deep_audit_io.sha256_bytes(raw),
        "result_bytes": len(raw),
        "result_sets": _deep_audit_io._codeql_result_sets(info),
        "native_artifacts": {
            "result": _deep_audit_io._codeql_native_blob(raw),
            "info": _deep_audit_io._codeql_native_blob(info),
        },
        "invocation": {
            "argv": argv,
            "argv_sha256": _deep_audit_io.digest(argv),
            "execution": facts,
        },
    }


def _codeql_steps_facts(invocations, streams, started, budget, expected_steps=3):
    if expected_steps not in (2, 3) or len(invocations) != expected_steps:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_CHALLENGE", "all native steps required"
        )
    return dict(
        exit_code=invocations[-1]["execution"]["exit_code"],
        timed_out=False,
        timeout_seconds=budget,
        duration_ms=int((_deep_audit_io.time.monotonic() - started) * 1000),
        launch_error=False,
        output_limit_exceeded=False,
        cleanup_confirmed=True,
        stdout_sha256=_deep_audit_io.sha256_bytes(bytes(streams["stdout"])),
        stdout_bytes=len(streams["stdout"]),
        stderr_sha256=_deep_audit_io.sha256_bytes(bytes(streams["stderr"])),
        stderr_bytes=len(streams["stderr"]),
    )


def _native_source_accounting(execution, report, inventory, lane):
    if lane.get("engine") == "osv":
        from .deep_audit_sarif import _osv_source_accounting

        return _osv_source_accounting(
            report, _deep_audit_io._trivy_source_map(inventory, lane), lane.get("mode")
        )
    if execution.get("codeql_source_execution") is not None:
        return _deep_audit_io._codeql_source_accounting(
            execution["codeql_source_execution"], inventory, lane
        )
    if execution.get("semgrep_rule_execution") is not None:
        return _deep_audit_io._semgrep_source_accounting(execution, inventory, lane)
    if lane.get("engine") == "trivy":
        try:
            return _deep_audit_io.verify_trivy_rule_execution(
                execution["trivy_rule_execution"],
                lane,
                _deep_audit_io._trivy_source_map(inventory, lane),
                report,
            )
        except (KeyError, _deep_audit_io.RuntimeAuditError, TypeError, ValueError):
            return {"state": "INCOMPLETE", "checks": {}, "findings": 0}
    return _deep_audit_io._native_runtime_accounting(report, inventory, lane)


def _semgrep_source_accounting(execution, inventory, lane):
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    checked = _deep_audit_io.verify_semgrep_rule_execution(
        execution["semgrep_rule_execution"], lane, sources, execution["raw_report"]
    )
    measured = set().union(
        *(set(rule["executed_sources"]) for rule in checked["rules"])
    )
    required = {
        item["path"]
        for item in inventory["files"]
        if item["language"] in lane["languages"]
    }
    missing = sorted(required - measured)
    if missing:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "native source accounting incomplete"
        )
    return {
        "state": "COMPLETE",
        "required_paths": sorted(required),
        "measured_paths": sorted(measured),
        "missing_paths": missing,
        "rule_execution_sha256": _deep_audit_io.digest(checked),
    }


def _runtime_coverage_errors(report, inventory, lane, challenges, obligations):
    errors = []
    source_state = _deep_audit_io._native_runtime_accounting(report, inventory, lane)[
        "state"
    ]
    if source_state != "COMPLETE":
        errors.append("NATIVE_SOURCE_ACCOUNTING_REQUIRED")
    if not _deep_audit_io._gitleaks_challenges_complete(challenges, obligations):
        errors.append("NATIVE_CHALLENGES_REQUIRED")
    return errors


def _trivy_coverage_errors(execution, report, inventory, lane, challenges, obligations):
    errors = []
    evidence = execution.get("trivy_rule_execution")
    if evidence is None or not lane.get("native_policy"):
        errors.append("NATIVE_SOURCE_ACCOUNTING_REQUIRED")
    else:
        try:
            _deep_audit_io.verify_trivy_rule_execution(
                evidence,
                lane,
                _deep_audit_io._trivy_source_map(inventory, lane),
                report,
            )
        except (_deep_audit_io.RuntimeAuditError, ValueError, TypeError, KeyError):
            errors.append("NATIVE_SOURCE_ACCOUNTING_INVALID")
    if not _deep_audit_io._gitleaks_challenges_complete(challenges, obligations):
        errors.append("NATIVE_CHALLENGES_REQUIRED")
    return errors


def _trivy_challenge_evidence(
    config, ignore, sources, paired, observation, source_root
):
    import base64

    sarif_raw = paired.get("sarif_raw")
    json_raw = paired.get("json_raw")
    if not isinstance(sarif_raw, bytes) or not isinstance(json_raw, bytes):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "paired native output is missing"
        )
    artifact_rows = observation.get("execution", {}).get("native_artifacts", [])
    policy = next(
        (item for item in artifact_rows if item.get("kind") == "policy_inventory"), None
    )
    if (
        not isinstance(policy, dict)
        or policy.get("sha256") != _deep_audit_io.sha256_bytes(json_raw)
        or policy.get("bytes") != len(json_raw)
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_EXECUTION", "native policy artifact binding differs"
        )
    source_bytes = _deep_audit_io._trivy_source_bytes(source_root, sources)
    native = _deep_audit_io.strict_json(json_raw)
    return {
        "schema": "factory.trivy-rule-execution.v1",
        "config_base64": base64.b64encode(config).decode("ascii"),
        "ignore_base64": base64.b64encode(ignore).decode("ascii"),
        "sources": sources,
        "source_bytes_base64": {
            path: base64.b64encode(raw).decode("ascii")
            for path, raw in sorted(source_bytes.items())
        },
        "target_bindings": _deep_audit_io._trivy_target_bindings(
            native, sources, source_bytes
        ),
        "observations": [
            _deep_audit_io._trivy_observation(
                "sarif", paired["sarif_argv"], paired["sarif_facts"], sarif_raw
            ),
            _deep_audit_io._trivy_observation(
                "json", paired["json_argv"], paired["json_facts"], json_raw
            ),
        ],
    }


def _gitleaks_coverage_errors(accounting, challenges, obligations):
    errors = []
    if not _deep_audit_io._gitleaks_accounting_complete(accounting):
        errors.append("NATIVE_SOURCE_ACCOUNTING_REQUIRED")
    if not _deep_audit_io._gitleaks_challenges_complete(challenges, obligations):
        errors.append("NATIVE_CHALLENGES_REQUIRED")
    return errors


def _gitleaks_accounting_complete(accounting):
    if not isinstance(accounting, dict) or not isinstance(
        accounting.get("rules"), list
    ):
        return False
    return all(
        isinstance(rule, dict)
        and isinstance(rule.get("sources"), list)
        and bool(rule["sources"])
        and all(row.get("disposition") == "executed" for row in rule["sources"])
        for rule in accounting["rules"]
    )


def _semgrep_fixture_binding(manifest, obligation, source, fixture_path):
    obligation_paths = set(obligation.get("paths", []))
    if (
        not isinstance(manifest, dict)
        or not manifest
        or fixture_path not in obligation_paths
        or fixture_path not in manifest
        or not set(manifest) <= obligation_paths
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CHALLENGE_BINDING",
            "fixture paths must be a bound subset of obligation paths",
        )
    for path, source_sha in manifest.items():
        _deep_audit_io.bound_bytes(
            source, {"path": _deep_audit_io.relative_path(path), "sha256": source_sha}
        )


def _gitleaks_preflight(inventory, lane, contract):
    source_count = sum(
        item["language"] in lane["languages"] for item in inventory["files"]
    )
    rule_count = len(lane["rule_ids"])
    pairs = source_count * rule_count
    per_pair = (
        768
        + max(
            (
                _deep_audit_io._json_string_size(item["path"])
                for item in inventory["files"]
            ),
            default=0,
        )
        + max(
            (_deep_audit_io._json_string_size(rule) for rule in lane["rule_ids"]),
            default=0,
        )
    )
    estimate = pairs * per_pair + _deep_audit_io._json_size_upper_bound(
        inventory["files"]
    )
    if pairs > 200_000 or estimate > _deep_audit_io.NATIVE_COVERAGE_LIMIT:
        _deep_audit_io._native_budget_error(
            "E_GITLEAKS_LEDGER_SIZE",
            source_count,
            rule_count,
            estimate,
            _deep_audit_io.NATIVE_COVERAGE_LIMIT,
        )
    _deep_audit_io._gitleaks_obligations(contract, lane)
