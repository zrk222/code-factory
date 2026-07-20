# Multi-Provider BYOK Routing

The provider router selects an allowed provider/model pair; it never calls a
provider and never stores a credential. A policy names environment-variable
references such as `OPENAI_API_KEY`, per-model quality tiers and price metadata,
allowed IDE surfaces, and budget/quality rails.

```json
{
  "owner": "platform-team",
  "allowed_ides": ["cli", "studio", "vscode", "jetbrains"],
  "max_cost_usd": 25,
  "quality_floor": "balanced",
  "routing_bias": 60,
  "providers": [
    {
      "id": "provider-a",
      "key_env": "PROVIDER_A_API_KEY",
      "endpoint": "https://api.example.com",
      "allowed_ides": ["cli", "studio", "vscode", "jetbrains"],
      "models": [{
        "id": "model-a",
        "tier": "balanced",
        "input_cost_per_million": 1.0,
        "output_cost_per_million": 4.0
      }]
    }
  ]
}
```

Create and verify the canonical, hash-bound policy from a secret-free config:

```bash
factory provider init provider-config.json --root . --json
factory provider verify .factory/providers/policy.json --json
factory provider doctor .factory/providers/policy.json --json
factory provider route .factory/providers/policy.json <mission.json> --root . --ide jetbrains --risk high --json
```

The doctor reports only whether each named environment variable is present. It
does not read or return its value. Routing fails closed when the IDE, provider,
model, quality floor, credential reference, mission budget, or endpoint rail
does not match. Cache continuity is an explicit input to avoid silently trading
away prompt-cache value.

Provider execution belongs to a separately governed runtime adapter. Route
receipts explicitly carry `provider_calls: false` and grant no spend or secret
access authority.
