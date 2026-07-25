# Paired Savings Tracker

Code Factory 0.22 records exact baseline-versus-Factory observations and
computes signed savings without filling in missing measurements.

## Record a pair

```bash
factory savings record checkout-2026-07-25 --root . \
  --baseline-elapsed-ms 600000 --factory-elapsed-ms 300000 \
  --baseline-tokens 12000 --factory-tokens 8000 \
  --baseline-cost-usd 6.00 --factory-cost-usd 4.00
```

Each receipt is stored atomically under `.factory/savings/`. Reusing a pair ID
is refused unless `--replace` is explicit. Pair IDs cannot traverse outside the
workspace receipt directory.

The calculations are:

- `saved = baseline - Factory`
- `savings rate = saved / baseline`
- `productivity gain = baseline elapsed / Factory elapsed - 1`

Negative values are valid regressions and are never clamped. A metric stays
`null` if either observation is missing or its denominator is zero.

## Prove equivalent outcomes

Time reduction alone does not prove productivity. To calculate productivity
gain, explicitly attest equivalent outcomes and bind the receipt to a local
evidence file:

```bash
factory savings record checkout-proven --root . \
  --baseline-elapsed-ms 600000 --factory-elapsed-ms 300000 \
  --equivalent-outcome --evidence .factory/receipts/verification.json
```

The private receipt stores the evidence file's SHA-256 digest. Code Factory
does not inspect the evidence semantics, make an equivalence claim for you, or
execute either workflow.

## Export a public report

```bash
factory savings report --root . --out savings-public.json
```

The `factory.savings-report.public.v1` export contains pair counts, exact
aggregate totals, weighted savings rates, and proven-productivity coverage. It
omits pair identifiers, evidence paths, evidence digests, and individual
baseline or Factory observations. The report is also visible in Factory
Studio's Savings view and in the VS Code and JetBrains editor integrations.

Treat a public sample as evidence only for the recorded observations. It does
not establish causality, generalize to other projects, or prove equivalent
quality when productivity remains withheld.
