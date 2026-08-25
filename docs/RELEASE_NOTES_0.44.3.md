# Code Factory 0.44.3 — Journey Proof and Audited Healing

Code Factory 0.44.3 proves the journey around a result, not only the final
screen or test status.

## What changed

- **Journey Reality** compares declared and observed states, transitions,
  requirements, and outcomes. Missing observations remain unknown.
- **Failure Capsules** isolate the failed step with adjacent, bounded evidence
  so a reviewer or repair agent does not need the entire transcript.
- **Stateful Workflow Proof** checks producer/consumer state, cleanup, and
  idempotency for multi-step work.
- **Proof-Gated Healing** supports human-controlled and supervised-auto modes.
  A repair is accepted only when the positive proof passes and its negative
  control fails.
- **Independent agent audit** checks the repair agent's scope and evidence
  before the candidate can be recommended.

## Control boundary

BYOK/local execution is the default. A future managed execution tier must use
the same verifier. Code Factory does not grant approval, merge, release,
credential, or production authority in either mode.

## Try it

```bash
pip install factoryline-code-factory==0.44.3
factory journey --help
factory graph ops --root . --json
```

## Verification

The release is gated by the complete Python suite, package build and metadata
validation, clean-environment import, the VS Code audit/test/package gate, the
JetBrains native release gate, and public-surface metadata tests.
