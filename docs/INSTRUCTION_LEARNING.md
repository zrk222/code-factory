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

The local CLI records identity strings; it does not authenticate the operating
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
