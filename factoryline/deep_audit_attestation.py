"""Offline signer, binding, and freshness checks for deep-audit evidence."""

from __future__ import annotations

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
    path: Path, trust_root: Path, trust_pin: str, identity: str, keyid: str, schema: str
) -> dict:
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
) -> dict:
    """Verify coordinator authorization over the exact pinned execution contract."""
    if plan["trust_root_sha256"] != trust_root_sha256:
        raise RuntimeAuditError(
            "E_TRUST_ROOT_PIN", "operator trust pin differs from the manifest"
        )
    payload = _execution_document(
        authorization,
        trust_root,
        trust_root_sha256,
        plan["coordinator_identity"],
        plan["coordinator_keyid"],
        "factory.deep-execution-authorization.v1",
    )
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
    return payload


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

    authorized = verify_execution_authorization(
        plan,
        evidence["manifest_sha256"],
        directory / "authorization.json",
        trust_root,
        trust_root_sha256,
    )
    if digest(authorized) != evidence["authorization_sha256"]:
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
