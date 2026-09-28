# Governed Instruction Learning

The learning lane turns successful task outcomes into reusable instructions
without carrying worker reasoning into the next context:

```text
task + milestone -> fresh worker packet -> outcome -> instruction candidate
                                                -> independent validation
                                                -> human promotion -> active AKU
```

Create the task and its exact milestone contract:

```powershell
factory learning init checkout-hardening --root . --owner product-owner `
  --objective "Ship checkout with verified rollback" --milestones milestones.json --json
factory learning packet .factory/learning/checkout-hardening/task.json `
  --milestone spec --worker worker-001 --json
```

`milestones.json` is an ordered list. Each criterion has an id and observable
statement. Later milestones remain blocked until earlier promotions verify.

After the worker finishes, keep its result beneath the workspace and propose a
compact JSON instruction array. Each edit names one of the six harness control
surfaces (`d1_context_assembly` through `d6_output_processing`):

```json
[
  {
    "dimension": "d6_output_processing",
    "instruction": "Run strict schema validation before reporting success."
  }
]
```

Then bind the outcome and candidate:

```powershell
factory learning propose .factory/learning/checkout-hardening/task.json `
  --root . --milestone spec --worker worker-001 --outcome evidence/outcome.json `
  --instructions evidence/instructions.json --json
```

A different identity validates every criterion exactly once. Every passing
criterion needs at least one evidence file beneath the workspace:

```powershell
factory learning validate .factory/learning/checkout-hardening/candidates/<candidate>.json `
  --root . --validator validator-001 --results evidence/results.json --json
factory learning promote .factory/learning/checkout-hardening/validations/<validation>.json `
  --owner product-owner --json
```

The worker, validator, and recorded owner must be three distinct identities.
Only the final command activates the AKU. Promotion rechecks every bound file,
so changed outcomes or validation evidence fail closed.

When intentionally superseding an active promotion, pass `--force`. The prior
sealed promotion is retained under the task's `promotions/history/` directory.
Restore it by exact promotion hash; the restore writes a hash-sealed rollback
receipt and makes the selected version active again:

```powershell
factory learning promote --restore <promotion-sha256> `
  --task .factory/learning/checkout-hardening/task.json `
  --owner product-owner --json
```

The command rejects hashes outside that task's immutable promotion history and
requires the task owner. It restores the exact prior promotion; it does not
rewrite the archived record or authenticate the local CLI caller.

## Observer intake from forensic rejection

Factory-B evidence can enter the same learning lane as a sealed
`factory.forensic-rejection.v1` packet. Create and validate one with
`seal_forensic_rejection_packet` and `validate_forensic_rejection_packet` in
`factoryline.learning_loop`; bind the candidate and source SHA, mutation seeds,
policy breaches, counterfactual profiles, reviewer corrections, validator
versions, evidence file hashes, and explicit unknowns. The packet validator
rejects missing fields, unbound evidence, and changed files.

Pass the sealed packet to `factory learning propose --forensic-packet`. The
Observer emits a bounded cause hypothesis and the affected control dimension;
it cannot edit packaged skills, approve itself, or activate instructions.
Forensic milestones must include `forensic-replay`, `holdout-regression`,
`false-positive-control`, and `specialty-ai-review`. Replay artifacts must bind
the exact candidate and packet hashes, and the specialty review artifact must
name the distinct `specialty-ai:<agent-id>` validator. Every gate receipt must
be a DSSE Ed25519 envelope using
`application/vnd.factory.observer-gate.v1+json`. Validate with
`factory learning validate ... --observer-trust-root <path>`; the offline trust
root must be administered separately and stored outside the candidate
workspace. Unsigned JSON, unknown keys, changed payloads, or signer/validator
mismatches fail closed. This authenticates the signer against that configured
trust root; it does not independently prove that a claimed remote run occurred
or authenticate a live AI provider session. Promotion remains a separate owner
action. Promoted instructions are versioned and enter only the fresh,
task-scoped worker packet; they do not rewrite the installed skill library.

The local CLI records identity strings and does not authenticate the operating
system caller. A hosted adapter must map authenticated principals to worker,
validator, and owner identities before invoking promotion.

## Harbor and Terminal-Bench evidence

Harbor remains an optional external harness. For example, the official
Terminal-Bench 2.0 smoke command is:

```bash
harbor run -d terminal-bench/terminal-bench-2 -a oracle -l 5
```

Run Harbor under its own reviewed sandbox and credential policy. Export the
relevant result JSON beneath this repository, then reference that file from a
milestone result. Code Factory binds its bytes like any other evidence; it does
not launch Harbor, read provider keys, infer that a benchmark score proves a
product requirement, submit a leaderboard entry, or promote instructions.

Architecture-level corrections use `factory opinion correct` separately. A
learning promotion cannot edit the Opinion Dock.

## ASHA, Hyperband, and BOHB plans

Create a bounded offline search plan over selected control dimensions:

```powershell
factory learning experiment .factory/learning/checkout-hardening/task.json `
  --space evidence/search-space.json --variant asha --max-resource 50 `
  --grace-period 5 --reduction-factor 3 --max-concurrent 32 --samples 100 --json
```

ASHA is the default for asynchronous parallel runs. `hyperband` records a
synchronous bracket policy, while `bohb` requests a guided sampler. The plan is
runner-neutral and does not import Ray. An approved Ray Tune or Harbor adapter
may consume it and must report iteration, correctness, cost, tokens, latency,
and a local evidence path.

Ranking is lexicographic: maximize correctness first, then minimize cost,
tokens, and latency only to break correctness ties. Search output is still an
untrusted proposal. It must pass the milestone validator and recorded owner
promotion before entering a worker packet.
