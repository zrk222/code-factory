"""Secret-free BYOK policy and deterministic multi-provider routing."""
from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse
import hashlib
import json
import math
import os
import re
import tempfile

from .failure_guidance import explain_failure
from .mission_graph import QUALITY_TIERS, mission_graph_status, recommend_mission_route


POLICY_SCHEMA = "factory.provider-policy.v1"
ROUTE_SCHEMA = "factory.provider-route.v1"
SUPPORTED_IDES = frozenset({"cli", "studio", "vscode", "jetbrains"})
PROVIDER_FIELDS = frozenset({"id", "key_env", "endpoint", "models", "allowed_ides"})
MODEL_FIELDS = frozenset({"id", "tier", "input_cost_per_million", "output_cost_per_million"})
MAX_ID_LENGTH = 80
MIN_ENV_LENGTH = 3
ID_PATTERN = re.compile(rf"^[a-z0-9][a-z0-9._-]{{0,{MAX_ID_LENGTH - 1}}}$")
ENV_PATTERN = re.compile(rf"^[A-Z][A-Z0-9_]{{{MIN_ENV_LENGTH - 1},{MAX_ID_LENGTH - 1}}}$")
MAX_PROVIDERS = 32
MAX_MODELS_PER_PROVIDER = 64


class ProviderRouterError(ValueError):
    """Closed, machine-readable provider-policy or routing failure."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.guidance = explain_failure(code, message)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", f"policy must be canonical JSON: {exc}") from exc


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", f"cannot read provider policy {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", "provider policy must be a JSON object")
    return value


def _atomic_json(path: Path, value: dict[str, Any], *, force: bool) -> Path:
    data = json.dumps(value, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_text(encoding="utf-8") == data:
            return path
        if not force:
            raise ProviderRouterError("PROVIDER_POLICY_EXISTS", f"refusing to replace {path}; use --force")
    handle, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    return path


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", f"{label} must match {ID_PATTERN.pattern}")
    return value


def _price(value: Any, label: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", f"{label} must be a finite non-negative number or null")
    return float(value)


def _endpoint(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 500:
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", "endpoint must be a URL of at most 500 characters")
    parsed = urlparse(value)
    loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", "remote provider endpoints must use HTTPS; HTTP is loopback-only")
    if parsed.username or parsed.password or not parsed.hostname:
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", "endpoint must not contain credentials and must name a host")
    return value.rstrip("/")


def _ides(values: Any, label: str) -> list[str]:
    if not isinstance(values, list) or not values or not all(isinstance(item, str) for item in values):
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", f"{label} must be a non-empty list")
    result = sorted(set(values))
    unknown = set(result) - SUPPORTED_IDES
    if unknown:
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", f"unsupported IDE selectors: {', '.join(sorted(unknown))}")
    return result


def _normalize_model(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - MODEL_FIELDS:
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", "model entries contain unknown fields")
    tier = value.get("tier")
    if tier not in QUALITY_TIERS:
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", "model tier must be economy, balanced, or frontier")
    return {
        "id": _identifier(value.get("id"), "model id"),
        "tier": tier,
        "input_cost_per_million": _price(value.get("input_cost_per_million"), "input cost"),
        "output_cost_per_million": _price(value.get("output_cost_per_million"), "output cost"),
    }


def _normalize_provider(value: Any, policy_ides: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - PROVIDER_FIELDS:
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", "provider entries contain unknown fields")
    key_env = value.get("key_env")
    if key_env is not None and (not isinstance(key_env, str) or not ENV_PATTERN.fullmatch(key_env)):
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", "key_env must be an uppercase environment-variable name")
    models = value.get("models")
    if not isinstance(models, list) or not 1 <= len(models) <= MAX_MODELS_PER_PROVIDER:
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", f"each provider requires 1-{MAX_MODELS_PER_PROVIDER} models")
    normalized_models = [_normalize_model(item) for item in models]
    model_ids = [item["id"] for item in normalized_models]
    if len(model_ids) != len(set(model_ids)):
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", "model ids must be unique within a provider")
    provider_ides = _ides(value.get("allowed_ides", policy_ides), "provider allowed_ides")
    if not set(provider_ides).issubset(policy_ides):
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", "provider IDEs must be a subset of policy IDEs")
    return {
        "id": _identifier(value.get("id"), "provider id"),
        "key_env": key_env,
        "endpoint": _endpoint(value.get("endpoint")),
        "allowed_ides": provider_ides,
        "models": normalized_models,
    }


def _normalize(owner: str, providers: list[dict[str, Any]], allowed_ides: list[str],
               max_cost_usd: float, quality_floor: str, routing_bias: int) -> dict[str, Any]:
    owner = owner.strip() if isinstance(owner, str) else ""
    if not owner or len(owner) > 120:
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", "owner must contain 1-120 characters")
    ides = _ides(allowed_ides, "allowed_ides")
    if not isinstance(providers, list) or not 1 <= len(providers) <= MAX_PROVIDERS:
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", f"policy requires 1-{MAX_PROVIDERS} providers")
    normalized = [_normalize_provider(item, ides) for item in providers]
    provider_ids = [item["id"] for item in normalized]
    if len(provider_ids) != len(set(provider_ids)):
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", "provider ids must be unique")
    ceiling = _price(max_cost_usd, "max_cost_usd")
    if ceiling is None or ceiling <= 0:
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", "max_cost_usd must be greater than zero")
    if quality_floor not in QUALITY_TIERS:
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", "quality_floor must be economy, balanced, or frontier")
    if isinstance(routing_bias, bool) or not isinstance(routing_bias, int) or not 0 <= routing_bias <= 100:
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", "routing_bias must be an integer from 0 through 100")
    return {
        "schema": POLICY_SCHEMA,
        "owner": owner,
        "providers": normalized,
        "allowed_ides": ides,
        "rails": {
            "max_cost_usd": ceiling,
            "quality_floor": quality_floor,
            "routing_bias": routing_bias,
            "credential_transport": "environment_reference_only",
            "provider_calls": False,
        },
        "markers": [
            "PROVIDER_POLICY_SECRET_FREE", "PROVIDER_CREDENTIAL_REFERENCE_ONLY",
            "PROVIDER_NO_CALL_AUTHORITY",
        ],
    }


def create_provider_policy(root: Path, owner: str, providers: list[dict[str, Any]],
                           allowed_ides: list[str], max_cost_usd: float,
                           quality_floor: str = "balanced", routing_bias: int = 50,
                           force: bool = False) -> dict:
    """Write one canonical provider policy containing references but no keys."""
    core = _normalize(owner, providers, allowed_ides, max_cost_usd, quality_floor, routing_bias)
    policy = {**core, "policy_sha256": _sha_bytes(_canonical(core))}
    path = Path(root).resolve() / ".factory" / "providers" / "policy.json"
    _atomic_json(path, policy, force=force)
    return {
        **policy,
        "path": str(path),
        "marker": "PROVIDER_POLICY_SECRET_FREE",
    }


def verify_provider_policy(policy_path: Path) -> dict:
    """Verify the canonical policy hash and every provider, model, IDE, and rail."""
    errors: list[str] = []
    try:
        policy = _load(Path(policy_path))
        if policy.get("schema") != POLICY_SCHEMA:
            raise ProviderRouterError("PROVIDER_POLICY_INVALID", f"expected schema {POLICY_SCHEMA}")
        core = {key: value for key, value in policy.items() if key not in {"policy_sha256", "path", "marker"}}
        normalized = _normalize(
            core.get("owner"), core.get("providers"), core.get("allowed_ides"),
            core.get("rails", {}).get("max_cost_usd"),
            core.get("rails", {}).get("quality_floor"),
            core.get("rails", {}).get("routing_bias"),
        )
        if normalized != core:
            errors.append("policy contains unknown or non-canonical fields")
        if _sha_bytes(_canonical(core)) != policy.get("policy_sha256"):
            errors.append("policy hash mismatch")
    except ProviderRouterError as exc:
        errors.append(exc.message)
        policy = {}
    result = {
        "schema": "factory.provider-policy.verification.v1",
        "valid": not errors,
        "status": "verified" if not errors else "invalid",
        "policy_sha256": policy.get("policy_sha256"),
        "errors": errors,
        "marker": "PROVIDER_POLICY_VERIFIED" if not errors else "PROVIDER_POLICY_INVALID",
        "authority": "configuration verification only; no provider call or spend authority",
    }
    if errors:
        result["failure"] = explain_failure("PROVIDER_POLICY_INVALID", "; ".join(errors), errors=errors)
    return result


def provider_doctor(policy_path: Path) -> dict:
    """Report credential-reference presence without reading or returning key values."""
    verification = verify_provider_policy(policy_path)
    if not verification["valid"]:
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", "; ".join(verification["errors"]))
    policy = _load(Path(policy_path))
    providers = [
        {
            "id": item["id"],
            "key_env": item["key_env"],
            "credential_present": item["key_env"] is None or item["key_env"] in os.environ,
            "models": len(item["models"]),
            "allowed_ides": item["allowed_ides"],
        }
        for item in policy["providers"]
    ]
    return {
        "schema": "factory.provider.doctor.v1",
        "policy_sha256": policy["policy_sha256"],
        "providers": providers,
        "ready_providers": sum(item["credential_present"] for item in providers),
        "credential_values_returned": 0,
        "marker": "PROVIDER_CREDENTIAL_REFERENCE_ONLY",
        "markers": ["PROVIDER_POLICY_VERIFIED", "PROVIDER_NO_CALL_AUTHORITY"],
    }


def _model_cost(model: dict[str, Any]) -> float:
    values = [model["input_cost_per_million"], model["output_cost_per_million"]]
    return sum(value for value in values if value is not None) if any(value is not None for value in values) else math.inf


def _eligible_candidates(policy: dict[str, Any], ide: str, minimum_tier: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for provider in policy["providers"]:
        present = provider["key_env"] is None or provider["key_env"] in os.environ
        if ide not in provider["allowed_ides"] or not present:
            continue
        for model in provider["models"]:
            if QUALITY_TIERS.index(model["tier"]) >= minimum_tier:
                candidates.append({
                    "provider": provider["id"], "model": model["id"], "tier": model["tier"],
                    "input_cost_per_million": model["input_cost_per_million"],
                    "output_cost_per_million": model["output_cost_per_million"],
                    "listed_cost_index": _model_cost(model), "key_env": provider["key_env"],
                    "credential_present": present, "endpoint": provider["endpoint"],
                })
    return candidates


def _filter_preference(candidates: list[dict[str, Any]], provider: str | None,
                       model: str | None) -> list[dict[str, Any]]:
    if provider is not None:
        candidates = [item for item in candidates if item["provider"] == provider]
    if model is not None:
        candidates = [item for item in candidates if item["model"] == model]
    return candidates


def _select_candidate(candidates: list[dict[str, Any]], cache_provider: str | None,
                      cache_model: str | None) -> tuple[dict[str, Any], bool]:
    if not candidates:
        raise ProviderRouterError("PROVIDER_ROUTE_RAILS_ENFORCED", "no credential-ready route satisfies the IDE, provider, model, tier, and policy rails")
    candidates.sort(key=lambda item: (item["listed_cost_index"], QUALITY_TIERS.index(item["tier"]), item["provider"], item["model"]))
    selected = candidates[0]
    cached = next((item for item in candidates if item["provider"] == cache_provider and item["model"] == cache_model), None)
    preserve = bool(cached is not None and cached["listed_cost_index"] <= selected["listed_cost_index"])
    return (cached, True) if preserve else (selected, False)


def route_provider(policy_path: Path, mission_path: Path, root: Path, ide: str, risk: str,
                   preferred_provider: str | None = None, preferred_model: str | None = None,
                   cache_provider: str | None = None, cache_model: str | None = None) -> dict:
    """Select one policy-eligible provider/model without making a provider call."""
    verification = verify_provider_policy(policy_path)
    if not verification["valid"]:
        raise ProviderRouterError("PROVIDER_POLICY_INVALID", "; ".join(verification["errors"]))
    policy = _load(Path(policy_path))
    if ide not in SUPPORTED_IDES or ide not in policy["allowed_ides"]:
        raise ProviderRouterError("PROVIDER_ROUTE_RAILS_ENFORCED", f"IDE {ide!r} is not allowed by policy")
    status = mission_graph_status(mission_path, root)
    effective_ceiling = min(policy["rails"]["max_cost_usd"], status["budgets"]["max_cost_usd"])
    recommendation = recommend_mission_route(
        mission_path, root, risk, policy["rails"]["quality_floor"],
        cache_continuity=bool(cache_provider and cache_model),
    )
    candidates = _eligible_candidates(policy, ide, QUALITY_TIERS.index(recommendation["tier"]))
    candidates = _filter_preference(candidates, preferred_provider, preferred_model)
    selected, cache_preserved = _select_candidate(candidates, cache_provider, cache_model)
    public_selected = {key: value for key, value in selected.items() if key != "listed_cost_index"}
    reasons = [
        f"IDE {ide} is policy-allowed",
        f"tier {selected['tier']} satisfies recommended {recommendation['tier']}",
        f"effective mission cost ceiling is {effective_ceiling:g} USD",
        "credential reference is present" if selected["credential_present"] else "credential reference is absent",
    ]
    if cache_preserved:
        reasons.append("eligible current route preserved prompt-cache continuity without a higher listed cost")
    return {
        "schema": ROUTE_SCHEMA,
        "mission_id": status["mission_id"],
        "policy_sha256": policy["policy_sha256"],
        "ide": ide,
        "selected": public_selected,
        "effective_max_cost_usd": effective_ceiling,
        "routing_bias": policy["rails"]["routing_bias"],
        "quality_floor": policy["rails"]["quality_floor"],
        "cache_preserved": cache_preserved,
        "reasons": reasons,
        "provider_calls": 0,
        "credential_values_returned": 0,
        "marker": "PROVIDER_ROUTE_EXPLAINED",
        "markers": [
            "PROVIDER_IDE_SELECTED", "PROVIDER_ROUTE_RAILS_ENFORCED",
            "PROVIDER_CREDENTIAL_REFERENCE_ONLY", "PROVIDER_CACHE_AWARE",
            "PROVIDER_NO_CALL_AUTHORITY",
        ],
        "authority": "route recommendation only; external runtime supplies credentials and authorizes spend",
    }
