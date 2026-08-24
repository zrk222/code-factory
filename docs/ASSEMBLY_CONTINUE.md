# Assembly continuation

Code Factory 0.22 includes one state-aware entry point:

```console
factory continue [feature] --root .
```

If `feature` is omitted, continuation proceeds only when exactly one feature is
discoverable. It executes installed, safe local stages and returns one of:

- `completed` with exit code 0;
- `waiting_for_human` with exit code 3 and exactly one typed next action;
- `halted` with exit code 1 and the exact failed stage.

Use `--json` for the full machine-readable report. Every non-dry run writes one
atomic receipt beneath `.factory/runs/`. Exact model usage can be supplied with
`--usage-json`; otherwise token and cost values remain `null` with quality
`unknown`.

Export a publication-safe aggregate:

```console
factory metrics --root . --out assembly-metrics.json
```

The export omits feature names, paths, prompts, logs, and result bodies. It does
not claim time or token savings without a measured counterfactual baseline.

Factory Studio exposes the same continuation function on its loopback-only,
session-token-protected Assembly tab. Studio still has no authority to publish,
deploy, sign, send messages, inject credentials, or grant connectors.
