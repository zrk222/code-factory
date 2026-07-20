from __future__ import annotations

from pathlib import Path
import json

import pytest

from factoryline.provider_router import (
    ProviderRouterError,
    create_provider_policy,
    provider_doctor,
    route_provider,
    verify_provider_policy,
)
from test_mission_graph import _pipeline


def _providers():
    return [
        {
            "id": "provider-a",
            "key_env": "PROVIDER_A_KEY",
            "endpoint": "https://api.provider-a.example/v1",
            "allowed_ides": ["cli", "jetbrains", "vscode"],
            "models": [
                {
                    "id": "balanced-a",
                    "tier": "balanced",
                    "input_cost_per_million": 1.0,
                    "output_cost_per_million": 2.0,
                },
                {
                    "id": "frontier-a",
                    "tier": "frontier",
                    "input_cost_per_million": 4.0,
                    "output_cost_per_million": 8.0,
                },
            ],
        },
        {
            "id": "provider-b",
            "key_env": "PROVIDER_B_KEY",
            "endpoint": "https://api.provider-b.example/v1",
            "allowed_ides": ["jetbrains", "studio"],
            "models": [
                {
                    "id": "frontier-b",
                    "tier": "frontier",
                    "input_cost_per_million": 3.0,
                    "output_cost_per_million": 6.0,
                },
            ],
        },
    ]


def test_provider_policy_is_hash_bound_and_secret_free(tmp_path: Path, monkeypatch):
    policy = create_provider_policy(
        tmp_path, "platform-owner", _providers(), ["cli", "studio", "vscode", "jetbrains"],
        20.0, quality_floor="balanced", routing_bias=35,
    )
    assert verify_provider_policy(Path(policy["path"]))["valid"] is True
    text = Path(policy["path"]).read_text(encoding="utf-8")
    assert "PROVIDER_A_KEY" in text
    assert "credential-value" not in text
    monkeypatch.setenv("PROVIDER_A_KEY", "credential-value")
    doctor = provider_doctor(Path(policy["path"]))
    assert doctor["providers"][0]["credential_present"] is True
    assert doctor["credential_values_returned"] == 0
    assert "credential-value" not in json.dumps(doctor)

    stored = json.loads(text)
    stored["rails"]["routing_bias"] = 101
    Path(policy["path"]).write_text(json.dumps(stored), encoding="utf-8")
    assert verify_provider_policy(Path(policy["path"]))["valid"] is False


def test_router_enforces_ide_quality_provider_and_byok_rails(tmp_path: Path, monkeypatch):
    mission = _pipeline(tmp_path)
    policy = create_provider_policy(
        tmp_path, "platform-owner", _providers(), ["cli", "studio", "vscode", "jetbrains"],
        20.0, quality_floor="balanced",
    )
    monkeypatch.setenv("PROVIDER_A_KEY", "a-value")
    monkeypatch.setenv("PROVIDER_B_KEY", "b-value")
    result = route_provider(Path(policy["path"]), Path(mission["path"]), tmp_path, "jetbrains", "high")
    assert result["selected"]["provider"] == "provider-b"
    assert result["selected"]["model"] == "frontier-b"
    assert result["provider_calls"] == 0
    assert result["credential_values_returned"] == 0
    assert "a-value" not in json.dumps(result)
    assert "b-value" not in json.dumps(result)
    with pytest.raises(ProviderRouterError, match="PROVIDER_ROUTE_RAILS_ENFORCED"):
        route_provider(Path(policy["path"]), Path(mission["path"]), tmp_path, "cli", "high", preferred_provider="provider-b")
    with pytest.raises(ProviderRouterError, match="PROVIDER_ROUTE_RAILS_ENFORCED"):
        route_provider(Path(policy["path"]), Path(mission["path"]), tmp_path, "unknown-ide", "high")


def test_router_preserves_equal_cost_cache_and_rejects_unsafe_policy(tmp_path: Path, monkeypatch):
    mission = _pipeline(tmp_path)
    providers = _providers()
    for provider in providers:
        provider["allowed_ides"] = ["jetbrains"]
    providers[0]["models"][1]["input_cost_per_million"] = 3.0
    providers[0]["models"][1]["output_cost_per_million"] = 6.0
    policy = create_provider_policy(
        tmp_path, "platform-owner", providers, ["jetbrains"], 10.0, quality_floor="frontier",
    )
    monkeypatch.setenv("PROVIDER_A_KEY", "a")
    monkeypatch.setenv("PROVIDER_B_KEY", "b")
    result = route_provider(
        Path(policy["path"]), Path(mission["path"]), tmp_path, "jetbrains", "high",
        cache_provider="provider-a", cache_model="frontier-a",
    )
    assert result["selected"]["provider"] == "provider-a"
    assert result["cache_preserved"] is True
    unsafe = _providers()
    unsafe[0]["endpoint"] = "http://provider-a.example/v1"
    with pytest.raises(ProviderRouterError, match="remote provider endpoints must use HTTPS"):
        create_provider_policy(tmp_path / "unsafe", "owner", unsafe, ["cli", "studio", "vscode", "jetbrains"], 5.0)
    unknown = _providers()
    unknown[0]["credential"] = "should-never-be-accepted"
    with pytest.raises(ProviderRouterError, match="unknown fields"):
        create_provider_policy(tmp_path / "unknown", "owner", unknown, ["cli", "studio", "vscode", "jetbrains"], 5.0)
