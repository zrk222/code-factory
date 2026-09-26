"""Provider-neutral, deterministic SaaS identity-to-entitlement proof."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
import hashlib
import json
import os
import tempfile


CONTRACT_SCHEMA = "factory.saas-proof.contract.v1"
EVIDENCE_SCHEMA = "factory.saas-proof.evidence.v1"
RECEIPT_SCHEMA = "factory.saas-proof.receipt.v1"
MAX_BYTES = 1_048_576
AUTHORITY = {
    "execution": False,
    "approval": False,
    "publication": False,
    "deployment": False,
    "billing": False,
    "credential": False,
    "identity_provider_write": False,
    "entitlement_write": False,
}
ALLOWED_PROTOCOLS = {"oidc", "oauth2"}
ALLOWED_FLOWS = {"authorization_code_pkce", "client_credentials"}
SENSITIVE_KEYS = {
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "secret",
    "password",
    "authorization",
    "cookie",
    "code_verifier",
}
REQUIRED_EVENTS = (
    "auth_success",
    "authorization_bound",
    "checkout_completed",
    "webhook_verified",
    "entitlement_granted",
    "feature_access",
)
RELEASE_CANDIDATE_KEYS = (
    "bundle_identifier",
    "version",
    "build_number",
    "source_commit",
)


class SaasProofError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _local(root: Path, value: Path, *, exists: bool = True) -> Path:
    workspace = root.resolve()
    candidate = (
        value.resolve() if value.is_absolute() else (workspace / value).resolve()
    )
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise SaasProofError(
            "SAAS_PROOF_PATH_REJECTED", "path must remain inside the workspace"
        ) from exc
    if exists and not candidate.is_file():
        raise SaasProofError(
            "SAAS_PROOF_INPUT_UNAVAILABLE", "input must be a regular workspace file"
        )
    return candidate


def _read(root: Path, path: Path, schema: str) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise SaasProofError("SAAS_PROOF_INPUT_TOO_LARGE", "input exceeds 1 MiB")
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SaasProofError(
            "SAAS_PROOF_INPUT_INVALID", "input must be valid JSON"
        ) from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise SaasProofError("SAAS_PROOF_SCHEMA_REJECTED", f"expected {schema}")
    if _contains_sensitive(value):
        raise SaasProofError(
            "SAAS_PROOF_SECRET_REJECTED",
            "raw credentials, tokens, cookies, and secrets are not accepted",
        )
    return value, source


def _contains_sensitive(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).lower() in SENSITIVE_KEYS or _contains_sensitive(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_sensitive(item) for item in value)
    return False


def _text(value: object, field: str) -> str:
    result = str(value or "").strip()
    if not result or len(result) > 300:
        raise SaasProofError(
            "SAAS_PROOF_CONTRACT_INVALID", f"{field} must be a non-empty bounded string"
        )
    return result


def _release_candidate(value: object, field: str) -> dict[str, str] | None:
    """Normalize an optional mobile release candidate without widening old proofs.

    SaaS proof remains useful for non-mobile systems.  When a candidate is
    declared, however, it is an exact, four-part binding and the paired
    evidence must declare the identical candidate.
    """
    if value is None:
        return None
    if not isinstance(value, dict):
        raise SaasProofError(
            "SAAS_PROOF_RELEASE_CANDIDATE_INVALID", f"{field} must be an object"
        )
    return {
        key: _text(value.get(key), f"{field}.{key}") for key in RELEASE_CANDIDATE_KEYS
    }


def _validate_issuer(issuer_value: str) -> None:
    issuer = urlparse(issuer_value)
    if issuer.scheme != "https" or not issuer.netloc or issuer.fragment:
        raise SaasProofError(
            "SAAS_PROOF_ISSUER_INVALID",
            "provider.issuer must be an absolute HTTPS URL without a fragment",
        )


def _provider_contract(provider: object) -> dict[str, Any]:
    claims = provider.get("claims") if isinstance(provider, dict) else None
    if not isinstance(provider, dict) or not isinstance(claims, dict):
        raise SaasProofError(
            "SAAS_PROOF_CONTRACT_INVALID", "provider and provider.claims are required"
        )
    protocol = _text(provider.get("protocol"), "provider.protocol").lower()
    flow = _text(provider.get("flow"), "provider.flow").lower()
    if protocol not in ALLOWED_PROTOCOLS or flow not in ALLOWED_FLOWS:
        raise SaasProofError(
            "SAAS_PROOF_PROVIDER_UNSUPPORTED",
            "use OIDC/OAuth2 with authorization_code_pkce or client_credentials",
        )
    if flow == "authorization_code_pkce" and provider.get("pkce_required") is not True:
        raise SaasProofError(
            "SAAS_PROOF_PKCE_REQUIRED", "authorization-code clients must require PKCE"
        )
    normalized_provider = {
        "name": _text(provider.get("name"), "provider.name"),
        "protocol": protocol,
        "flow": flow,
        "issuer": _text(provider.get("issuer"), "provider.issuer"),
        "audience": _text(provider.get("audience"), "provider.audience"),
        "pkce_required": provider.get("pkce_required") is True,
        "claims": {
            key: _text(claims.get(key), f"provider.claims.{key}")
            for key in ("subject", "tenant", "roles")
        },
    }
    _validate_issuer(normalized_provider["issuer"])

    return normalized_provider


def _contract_promises(promises: object) -> list[dict[str, str]]:
    if not isinstance(promises, list) or not promises or len(promises) > 50:
        raise SaasProofError(
            "SAAS_PROOF_CONTRACT_INVALID", "promises must contain 1-50 entries"
        )
    normalized, ids = [], set()
    for raw in promises:
        if not isinstance(raw, dict):
            raise SaasProofError(
                "SAAS_PROOF_CONTRACT_INVALID", "each promise must be an object"
            )
        item = {
            key: _text(raw.get(key), f"promise.{key}")
            for key in ("id", "sku", "entitlement")
        }
        if item["id"] in ids:
            raise SaasProofError(
                "SAAS_PROOF_CONTRACT_INVALID", "promise ids must be unique"
            )
        ids.add(item["id"])
        normalized.append(item)

    return normalized


def _contract(value: dict[str, Any]) -> dict[str, Any]:
    normalized_provider = _provider_contract(value.get("provider"))
    normalized_promises = _contract_promises(value.get("promises"))
    return {
        "app_id": _text(value.get("app_id"), "app_id"),
        "provider": normalized_provider,
        "promises": normalized_promises,
        "release_candidate": _release_candidate(
            value.get("release_candidate"), "contract.release_candidate"
        ),
    }


def _event_sequence(raw: object) -> int:
    if (
        not isinstance(raw, dict)
        or isinstance(raw.get("sequence"), bool)
        or not isinstance(raw.get("sequence"), int)
    ):
        raise SaasProofError(
            "SAAS_PROOF_EVIDENCE_INVALID", "each event requires an integer sequence"
        )
    return raw["sequence"]


def _event_identifier(raw: dict[str, Any], ids: set[str], prior: int) -> str:
    event_id = _text(raw.get("id"), "event.id")
    if event_id in ids or raw["sequence"] <= prior:
        raise SaasProofError(
            "SAAS_PROOF_EVENT_ORDER_INVALID",
            "event ids must be unique and sequence must strictly increase",
        )
    return event_id


def _optional_event_text(raw: dict[str, Any], field: str) -> str | None:
    return str(raw.get(field) or "").strip() or None


def _optional_event_bool(raw: dict[str, Any], field: str) -> bool | None:
    value = raw.get(field)
    return value if isinstance(value, bool) else None


def _normalized_event(
    raw: dict[str, Any], event_id: str, sequence: int
) -> dict[str, Any]:
    return {
        "id": event_id,
        "provider_event_id": _optional_event_text(raw, "provider_event_id"),
        "sequence": sequence,
        "type": _text(raw.get("type"), "event.type"),
        "subject": _optional_event_text(raw, "subject"),
        "tenant": _optional_event_text(raw, "tenant"),
        "role": _optional_event_text(raw, "role"),
        "sku": _optional_event_text(raw, "sku"),
        "entitlement": _optional_event_text(raw, "entitlement"),
        "verified": _optional_event_bool(raw, "verified"),
        "issuer": _optional_event_text(raw, "issuer"),
        "audience": _optional_event_text(raw, "audience"),
        "token_active": _optional_event_bool(raw, "token_active"),
    }


def _events(value: dict[str, Any]) -> list[dict[str, Any]]:
    raw_events = value.get("events")
    if not isinstance(raw_events, list) or not raw_events or len(raw_events) > 1000:
        raise SaasProofError(
            "SAAS_PROOF_EVIDENCE_INVALID", "events must contain 1-1000 objects"
        )
    result, ids, prior = [], set(), -1
    for raw in raw_events:
        sequence = _event_sequence(raw)
        event_id = _event_identifier(raw, ids, prior)
        ids.add(event_id)
        prior = sequence
        result.append(_normalized_event(raw, event_id, sequence))
    return result


def _event_check(event_type: str, candidates: list[dict[str, Any]]) -> dict[str, Any]:
    if not candidates:
        return {
            "gate": event_type,
            "status": "unknown",
            "reason": "no observation supplied",
        }
    bad = [event for event in candidates if event["verified"] is not True]
    return {
        "gate": event_type,
        "status": "failed" if bad else "passed",
        "event_ids": [event["id"] for event in candidates],
        "reason": "unverified observation" if bad else "verified observation supplied",
    }


def _event_contract_findings(
    event: dict[str, Any],
    promises: set[tuple[str, str]],
    provider_ids: set[str],
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    provider_id = event["provider_event_id"]
    if provider_id and provider_id in provider_ids:
        findings.append(
            {"code": "SAAS_PROOF_DUPLICATE_PROVIDER_EVENT", "event_id": event["id"]}
        )
    if provider_id:
        provider_ids.add(provider_id)
    if (
        event["type"] in {"checkout_completed", "entitlement_granted", "feature_access"}
        and (event["sku"], event["entitlement"]) not in promises
    ):
        findings.append({"code": "SAAS_PROOF_PROMISE_DRIFT", "event_id": event["id"]})
    if event["type"] in REQUIRED_EVENTS and not all(
        (event["subject"], event["tenant"], event["entitlement"])
    ):
        findings.append(
            {"code": "SAAS_PROOF_IDENTITY_BINDING_MISSING", "event_id": event["id"]}
        )
    if event["type"] in {"authorization_bound", "feature_access"} and not event["role"]:
        findings.append(
            {"code": "SAAS_PROOF_ROLE_BINDING_MISSING", "event_id": event["id"]}
        )
    return findings


def _identity_lifecycle_findings(group: list[dict[str, Any]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    positions = {event["type"]: event["sequence"] for event in group}
    required = [positions.get(name) for name in REQUIRED_EVENTS]
    if all(value is not None for value in required) and required != sorted(required):
        findings.append(
            {
                "code": "SAAS_PROOF_LIFECYCLE_ORDER_INVALID",
                "event_id": group[-1]["id"],
            }
        )
    if "feature_access" in positions and (
        "entitlement_granted" not in positions
        or positions["feature_access"] < positions["entitlement_granted"]
    ):
        findings.append(
            {
                "code": "SAAS_PROOF_ACCESS_WITHOUT_ENTITLEMENT",
                "event_id": group[-1]["id"],
            }
        )
    terminal = max(
        positions.get("cancellation", -1),
        positions.get("refund", -1),
        positions.get("subscription_expired", -1),
    )
    if terminal >= 0 and positions.get("entitlement_revoked", -1) <= terminal:
        findings.append(
            {"code": "SAAS_PROOF_STALE_ENTITLEMENT", "event_id": group[-1]["id"]}
        )
    if "feature_access" in positions and any(
        name not in positions for name in REQUIRED_EVENTS
    ):
        findings.append(
            {
                "code": "SAAS_PROOF_CROSS_IDENTITY_OR_TENANT_JOURNEY",
                "event_id": group[-1]["id"],
            }
        )
    return findings


def _token_binding_findings(
    contract: dict[str, Any], events: list[dict[str, Any]]
) -> list[dict[str, str]]:
    provider = contract["provider"]
    findings: list[dict[str, str]] = []
    auth = [event for event in events if event["type"] == "auth_success"]
    for event in auth:
        if (
            event["issuer"] != provider["issuer"]
            or event["audience"] != provider["audience"]
            or event["token_active"] is not True
        ):
            findings.append(
                {"code": "SAAS_PROOF_TOKEN_BINDING_INVALID", "event_id": event["id"]}
            )
    return findings


def _semantic_findings(
    contract: dict[str, Any], events: list[dict[str, Any]]
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    promises = {(item["sku"], item["entitlement"]) for item in contract["promises"]}
    by_identity: dict[
        tuple[str | None, str | None, str | None], list[dict[str, Any]]
    ] = defaultdict(list)
    provider_ids: set[str] = set()
    for event in events:
        key = (event["subject"], event["tenant"], event["entitlement"])
        by_identity[key].append(event)
        findings.extend(_event_contract_findings(event, promises, provider_ids))
    for group in by_identity.values():
        findings.extend(_identity_lifecycle_findings(group))
    findings.extend(_token_binding_findings(contract, events))
    return sorted(findings, key=lambda item: (item["code"], item["event_id"]))


def verify_saas_proof(
    root: Path, contract_path: Path, evidence_path: Path, out: Path
) -> dict[str, Any]:
    """Verify observed identity, billing, entitlement, and revocation evidence without provider access."""
    workspace = root.resolve()
    raw_contract, contract_source = _read(workspace, contract_path, CONTRACT_SCHEMA)
    raw_evidence, evidence_source = _read(workspace, evidence_path, EVIDENCE_SCHEMA)
    contract = _contract(raw_contract)
    if _text(raw_evidence.get("app_id"), "evidence.app_id") != contract["app_id"]:
        raise SaasProofError(
            "SAAS_PROOF_APP_BINDING_INVALID", "contract and evidence app_id must match"
        )
    build_id = _text(raw_evidence.get("build_id"), "evidence.build_id")
    evidence_candidate = _release_candidate(
        raw_evidence.get("release_candidate"), "evidence.release_candidate"
    )
    if evidence_candidate != contract["release_candidate"]:
        raise SaasProofError(
            "SAAS_PROOF_RELEASE_CANDIDATE_BINDING_INVALID",
            "contract and evidence release_candidate must both be absent or exactly match",
        )
    events = _events(raw_evidence)
    grouped = defaultdict(list)
    for event in events:
        grouped[event["type"]].append(event)
    gates = [_event_check(name, grouped[name]) for name in REQUIRED_EVENTS]
    findings = _semantic_findings(contract, events)
    counts = Counter(gate["status"] for gate in gates)
    verdict = (
        "verified"
        if counts["passed"] == len(REQUIRED_EVENTS) and not findings
        else "blocked"
    )
    core = {
        "schema": RECEIPT_SCHEMA,
        "marker": "SAAS_PROMISE_PERMISSION_VERIFIED"
        if verdict == "verified"
        else "SAAS_PROMISE_PERMISSION_BLOCKED",
        "action_summary": "Compare supplied OAuth/OIDC, checkout, webhook, entitlement, access, and revocation observations with the reviewed SaaS promise contract; do not contact or mutate any provider.",
        "verdict": verdict,
        "app_id": contract["app_id"],
        "build_id": build_id,
        "release_candidate": contract["release_candidate"],
        "provider": contract["provider"],
        "contract_sha256": hashlib.sha256(contract_source.read_bytes()).hexdigest(),
        "evidence_sha256": hashlib.sha256(evidence_source.read_bytes()).hexdigest(),
        "gates": gates,
        "summary": {
            "passed": counts["passed"],
            "failed": counts["failed"],
            "unknown": counts["unknown"],
            "findings": len(findings),
        },
        "findings": findings,
        "authority": AUTHORITY,
        "claim_boundary": "supplied local observations only; not provider certification, production uptime, payment settlement, legal compliance, or authorization to deploy",
    }
    core["receipt_sha256"] = _sha(core)
    destination = _local(workspace, out, exists=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(core, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {**core, "path": destination.relative_to(workspace).as_posix()}


def saas_proof_projection(root: Path) -> dict[str, Any]:
    """Return only hash-valid local SaaS proof receipt metadata."""
    current, invalid = [], []
    directory = root.resolve() / ".factory" / "saas-proof"
    for path in sorted(directory.glob("*.json"))[:250]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            receipt = value.pop("receipt_sha256", None)
            valid = (
                value.get("schema") == RECEIPT_SCHEMA
                and isinstance(receipt, str)
                and _sha(value) == receipt
            )
            item = {
                "path": path.relative_to(root.resolve()).as_posix(),
                "marker": value.get("marker"),
                "verdict": value.get("verdict"),
                "receipt_sha256": receipt,
            }
            (current if valid else invalid).append(item)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            invalid.append(
                {
                    "path": path.relative_to(root.resolve()).as_posix(),
                    "marker": "SAAS_PROOF_RECEIPT_INVALID",
                }
            )
    return {
        "marker": "SAAS_PROOF_READ_ONLY",
        "current_count": len(current),
        "invalid_count": len(invalid),
        "latest": current[-1] if current else None,
        "invalid": invalid,
        "authority": AUTHORITY,
    }
