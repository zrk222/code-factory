# Continuous Controls

Code Factory now provides the enterprise control-plane layer that sits above
the six audit lanes. A policy pack is a small, versioned JSON contract. Each
control names its provenance, forbidden behaviour, gate, independent test, and
required evidence. A human-confirmed or trusted-source pack can block; an
agent-proposed pack remains visibly advisory until a different person approves
it.

## The safe loop

```text
intent → control → forbidden behavior → gate → test → receipt → decision
```

The evaluator is intentionally boring: it reads sealed receipts and hashes,
never runs a command, never changes policy, and never approves a release. It
works for a working tree and for `merge`, `agent_action`, or `deployment`
events, so a policy change or stale receipt is visible as drift immediately.

## Commands

```text
factory controls manifest --root . --policy controls/policy-pack.json --json
factory controls evaluate --root . --event-kind merge --commit <sha> \
  --evidence .factory/evidence/control-001.json --out .factory/controls/eval.json --json
factory controls dossier .factory/controls/eval.json --root . --json
factory controls exception CTRL-001 --root . --owner security \
  --reason "temporary provider outage" --scope release/123 --ttl-days 7 \
  --evidence incident.md --author alice --approver bob \
  --out controls/exceptions/CTRL-001.json --json
factory controls fleet --root . --manifest controls/fleet.json --json
factory controls projection --root . --json
```

`evaluate` returns exactly one next action for the first blocking control and
writes a content-addressed evaluation. `dossier` emits JSON, Markdown, and
Mermaid files suitable for a PR comment or IDE Mission Control. `fleet` reports
which repositories inherit the baseline and which controls are missing.

## Fail-closed guarantees

- Parent packs are workspace-contained and SHA-256 bound. Deleted controls,
  widened thresholds, lowered severities, removed evidence, or changed gates
  and tests are rejected with `E_CONTROL_DELETED` or `E_CONTROL_WEAKENING`.
- Exceptions are named, scoped, evidence-bound, separately approved, and
  expire within 30 days by default. An expired or altered exception blocks.
- The output explicitly sets release, merge, deploy, and credential authority
  to `false`; final release ownership stays with a human.
- Graph Ops projects the latest evaluation read-only, including coverage,
  drift state, digest validity, and the full chain above.

The feature is a local evidence coordinator. It complements CI, Qodana,
CodeRabbit, device clouds, and provider-specific scanners rather than claiming
to replace them.
