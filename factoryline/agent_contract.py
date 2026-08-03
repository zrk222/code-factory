"""Strict, secret-free Core-5 agent contracts and verifier attestations.

The contract is deliberately small and deterministic.  It describes the
model, prompt, tools, harness, context, and handoff seams an agent may use;
it does not inject credentials or grant execution authority.  A contract is
canonicalized and hash-bound before a runtime may consume it.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Any


AGENT_CONTRACT_SCHEMA = "factory.agent-contract.v2"
ATTESTATION_SCHEMA = "factory.verifier-attestation.v1"
CONTRACT_MARKER = "AGENT_CONTRACT_BOUND"
ATTESTATION_MARKER = "VERIFIER_ADAPTER_ATTESTED"
MAX_TOKENS = 12_000
MAX_LATENCY_MS = 5_000
MAX_COST_USD = 0.50
QUALITY_TIERS = ("economy", "balanced", "frontier")
PRIVACY_CLASSES = ("standard", "restricted", "local_only")
CONTRACT_KEYS = frozenset({
    "schema", "id", "role", "context", "model", "prompt", "tools",
    "harness", "handoff", "contract_digest", "markers",
})
SECRET_KEYS = frozenset({"key", "token", "secret", "password", "credential", "api_key"})


class AgentContractError(ValueError):
    """Closed, machine-readable contract validation failure."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AgentContractError("AGENT_CONTRACT_INVALID", f"contract is not canonical JSON: {exc}") from exc


def _text(value: Any, label: str, *, max_len: int = 200) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_len:
        raise AgentContractError("AGENT_CONTRACT_INVALID", f"{label} must be a non-empty string of at most {max_len} characters")
    return value.strip()


def _digest(value: Any, label: str) -> str:
    value = _text(value, label, max_len=128)
    if len(value) < 16 or any(char not in "0123456789abcdef" for char in value.lower()):
        raise AgentContractError("AGENT_CONTRACT_INVALID", f"{label} must be a hexadecimal digest")
    return value.lower()


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AgentContractError("AGENT_CONTRACT_RAILS_ENFORCED", f"{label} must be an integer from {minimum} through {maximum}")
    return value


def _bounded_cost(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or value < 0 or value > MAX_COST_USD:
        raise AgentContractError("AGENT_CONTRACT_RAILS_ENFORCED", f"max_cost_usd must be between 0 and {MAX_COST_USD:g}")
    return round(float(value), 6)


def _strings(value: Any, label: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value) or not all(isinstance(item, str) and item.strip() for item in value):
        raise AgentContractError("AGENT_CONTRACT_INVALID", f"{label} must be a list of non-empty strings")
    return sorted(set(item.strip() for item in value))


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgentContractError("AGENT_CONTRACT_INVALID", f"{label} must be an object")
    if SECRET_KEYS.intersection(value):
        raise AgentContractError("AGENT_CONTRACT_SECRET_FIELD", f"{label} must not contain credential fields")
    return value


def _exact_keys(value: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise AgentContractError("AGENT_CONTRACT_UNKNOWN_FIELD", f"{label} contains unknown fields: {', '.join(sorted(unknown))}")


def _core5(value: dict[str, Any]) -> dict[str, Any]:
    _exact_keys(value, set(CONTRACT_KEYS), "contract")
    if value.get("schema") != AGENT_CONTRACT_SCHEMA:
        raise AgentContractError("AGENT_CONTRACT_SCHEMA_MISMATCH", f"schema must be {AGENT_CONTRACT_SCHEMA}")
    context = _object(value.get("context"), "context")
    _exact_keys(context, {"recipe_id", "digest", "max_tokens", "sources"}, "context")
    sources = _strings(context.get("sources"), "context.sources", allow_empty=False)
    if any(source.startswith(("http:", "https:")) for source in sources):
        raise AgentContractError("AGENT_CONTRACT_CONTEXT_UNTRUSTED", "context.sources must be local, reviewed identifiers")
    model = _object(value.get("model"), "model")
    _exact_keys(model, {"id", "tier", "max_latency_ms", "max_cost_usd", "capabilities", "privacy_class"}, "model")
    tier = _text(model.get("tier"), "model.tier", max_len=20)
    if tier not in QUALITY_TIERS:
        raise AgentContractError("AGENT_CONTRACT_INVALID", "model.tier must be economy, balanced, or frontier")
    privacy = _text(model.get("privacy_class"), "model.privacy_class", max_len=20)
    if privacy not in PRIVACY_CLASSES:
        raise AgentContractError("AGENT_CONTRACT_INVALID", "model.privacy_class must be standard, restricted, or local_only")
    prompt = _object(value.get("prompt"), "prompt")
    _exact_keys(prompt, {"id", "version", "digest"}, "prompt")
    tools = _object(value.get("tools"), "tools")
    _exact_keys(tools, {"allow", "deny"}, "tools")
    harness = _object(value.get("harness"), "harness")
    _exact_keys(harness, {"context_wall", "subagents", "permissions"}, "harness")
    wall = harness.get("context_wall")
    if wall not in {"isolated", "shared_readonly"}:
        raise AgentContractError("AGENT_CONTRACT_INVALID", "harness.context_wall must be isolated or shared_readonly")
    handoff = _object(value.get("handoff"), "handoff")
    _exact_keys(handoff, {"input_schema", "output_schema"}, "handoff")
    normalized = {
        "schema": AGENT_CONTRACT_SCHEMA,
        "id": _text(value.get("id"), "id", max_len=96),
        "role": _text(value.get("role"), "role", max_len=64),
        "context": {
            "recipe_id": _text(context.get("recipe_id"), "context.recipe_id"),
            "digest": _digest(context.get("digest"), "context.digest"),
            "max_tokens": _bounded_int(context.get("max_tokens"), "context.max_tokens", 1, MAX_TOKENS),
            "sources": sources,
        },
        "model": {
            "id": _text(model.get("id"), "model.id", max_len=128),
            "tier": tier,
            "max_latency_ms": _bounded_int(model.get("max_latency_ms"), "model.max_latency_ms", 1, MAX_LATENCY_MS),
            "max_cost_usd": _bounded_cost(model.get("max_cost_usd")),
            "capabilities": _strings(model.get("capabilities"), "model.capabilities"),
            "privacy_class": privacy,
        },
        "prompt": {
            "id": _text(prompt.get("id"), "prompt.id"),
            "version": _text(prompt.get("version"), "prompt.version", max_len=40),
            "digest": _digest(prompt.get("digest"), "prompt.digest"),
        },
        "tools": {"allow": _strings(tools.get("allow"), "tools.allow"), "deny": _strings(tools.get("deny"), "tools.deny")},
        "harness": {
            "context_wall": wall,
            "subagents": _strings(harness.get("subagents"), "harness.subagents"),
            "permissions": _strings(harness.get("permissions"), "harness.permissions"),
        },
        "handoff": {
            "input_schema": _text(handoff.get("input_schema"), "handoff.input_schema"),
            "output_schema": _text(handoff.get("output_schema"), "handoff.output_schema"),
        },
    }
    if set(normalized["tools"]["allow"]).intersection(normalized["tools"]["deny"]):
        raise AgentContractError("AGENT_CONTRACT_TOOL_CONFLICT", "tools.allow and tools.deny must be disjoint")
    if normalized["harness"]["context_wall"] == "isolated" and "creator_scratchpad" in normalized["context"]["sources"]:
        raise AgentContractError("AGENT_CONTRACT_CONTEXT_WALL", "isolated context may not include creator scratchpad")
    return normalized


def validate_agent_contract(value: Path | dict[str, Any]) -> dict[str, Any]:
    """Validate and return a hash-bound Core-5 contract without secrets."""
    if isinstance(value, (str, Path)):
        path = Path(value)
        try:
            value = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AgentContractError("AGENT_CONTRACT_INVALID", f"cannot read contract: {exc}") from exc
    if not isinstance(value, dict):
        raise AgentContractError("AGENT_CONTRACT_INVALID", "contract must be a JSON object")
    core = _core5(value)
    digest = sha256(_canonical(core)).hexdigest()
    supplied = value.get("contract_digest")
    if supplied is not None and supplied != digest:
        raise AgentContractError("AGENT_CONTRACT_DIGEST_MISMATCH", "contract_digest does not match canonical contract")
    return {**core, "contract_digest": digest, "markers": [CONTRACT_MARKER]}


def validate_verifier_attestation(value: Path | dict[str, Any], *, mission_digest: str | None = None,
                                  contract_digest: str | None = None) -> dict[str, Any]:
    """Validate a fresh creator/verifier adapter receipt with a context wall."""
    if isinstance(value, (str, Path)):
        try:
            value = json.loads(Path(value).read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AgentContractError("VERIFIER_ATTESTATION_INVALID", f"cannot read attestation: {exc}") from exc
    if not isinstance(value, dict):
        raise AgentContractError("VERIFIER_ATTESTATION_INVALID", "attestation must be a JSON object")
    allowed = {"schema", "mission_digest", "contract_digest", "creator_id", "verifier_id", "verifier_context", "fresh_session", "context_wall", "evidence_digest", "adapter_id"}
    _exact_keys(value, allowed, "attestation")
    if value.get("schema") != ATTESTATION_SCHEMA:
        raise AgentContractError("VERIFIER_ATTESTATION_INVALID", f"schema must be {ATTESTATION_SCHEMA}")
    creator = _text(value.get("creator_id"), "creator_id", max_len=96)
    verifier = _text(value.get("verifier_id"), "verifier_id", max_len=96)
    if creator == verifier:
        raise AgentContractError("VERIFIER_IDENTITY_DISTINCT", "creator and verifier identities must differ")
    if value.get("fresh_session") is not True or value.get("context_wall") != "isolated":
        raise AgentContractError("VERIFIER_CONTEXT_WALL", "verifier must use a fresh isolated context wall")
    context = _strings(value.get("verifier_context"), "verifier_context", allow_empty=False)
    forbidden = {"creator_scratchpad", "creator_reasoning", "creator_hidden_trace"}
    if forbidden.intersection(context):
        raise AgentContractError("VERIFIER_CONTEXT_WALL", "verifier context contains forbidden creator traces")
    mission = _digest(value.get("mission_digest"), "mission_digest")
    contract = _digest(value.get("contract_digest"), "contract_digest")
    if mission_digest is not None and mission != mission_digest:
        raise AgentContractError("VERIFIER_ATTESTATION_BINDING", "mission digest does not match the requested mission")
    if contract_digest is not None and contract != contract_digest:
        raise AgentContractError("VERIFIER_ATTESTATION_BINDING", "contract digest does not match the requested contract")
    evidence = _digest(value.get("evidence_digest"), "evidence_digest")
    adapter = _text(value.get("adapter_id"), "adapter_id", max_len=96)
    core = {"schema": ATTESTATION_SCHEMA, "mission_digest": mission, "contract_digest": contract,
            "creator_id": creator, "verifier_id": verifier, "verifier_context": context,
            "fresh_session": True, "context_wall": "isolated", "evidence_digest": evidence, "adapter_id": adapter}
    return {**core, "attestation_digest": sha256(_canonical(core)).hexdigest(), "markers": [ATTESTATION_MARKER]}
