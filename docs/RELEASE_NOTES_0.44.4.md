# Code Factory 0.44.4 — Intent and Metadata Integrity

Code Factory 0.44.4 closes a class of trust-boundary gaps where an AI coding
assistant could present vague intent, unobservable acceptance criteria, or a
rebound proof record as if it were verified work.

## What changed

- **Shared intent quality gate:** Intake Grill, Intent Ledger, Reality Check,
  Counterexample, and Gauntlet reject placeholders, vague requests, and claims
  without an observable outcome before they can become proof obligations.
- **Promise binding:** Gauntlet outcomes must bind the original promise,
  proposal, and Reality failure case. Resealing a card with different text no
  longer changes what was actually tested.
- **Codex metadata audit:** `factory ops metadata` hashes complete files,
  parses JSON/JSONL safely, identifies unsupported provider/release claims, and
  reports historical records that require review instead of treating them as
  authority.
- **Enterprise documentation:** The same boundary is documented across all
  intake and proof surfaces so teams can explain exactly what is checked and
  what remains human or independently verified.

## Existing 0.44.3 capabilities retained

Journey Reality, bounded Failure Capsules, stateful workflow proof,
Proof-Gated Healing, and independent repair-agent audit remain part of the
release. Local/BYOK execution is still the default; no capability grants
approval, merge, release, deploy, publish, credential, or production authority.

## Verify locally

```powershell
python -m pip install factoryline-code-factory==0.44.4
factory first-proof --root .
factory ops metadata --root . --path context --path skills --path envelopes --json
```

The metadata command is intentionally non-zero when historical records need
review. That is a safety signal, not a failed claim being rewritten as success.
