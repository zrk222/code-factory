# Code Factory 0.42.0

## Route the hard change to the right attention before review

Code Factory 0.42.0 adds a small but important missing link to Engineering
Judgment: a **human-declared Change Profile**.

For an explicit set of changed paths, a named reviewer can declare the change
kinds they know are present—for example `concurrency`, `public-api`, or
`architecture-boundary`. The profile is canonical JSON with a SHA-256 binding.
The Safety Case compares those declarations with independently promoted
Judgment Capsules and returns one visible attention route:

- `routine` only when no stronger declared fact exists;
- `domain` for a matching capsule's stated floor;
- `specialist` for missing proof, decision drift, an unclassified path, or a
  novel declared change kind; and
- `architecture` for a novel declared architecture boundary.

This is not source-code interpretation. FactoryLine does not inspect syntax,
Git history, tickets, chat, or model output to infer a change kind. Missing or
hash-invalid profiles stay explicit rather than being silently replaced.

## What a reviewer sees

Every Safety Case now includes:

- route and required named reviewer;
- known versus novel declared change kinds;
- descriptive Capsule drift (`proof_missing`, `review_due`,
  `reconsideration_pending`, or `declared_proof_bound`); and
- the smallest deterministic set of human questions that remains.

The same read-only result is available in the CLI, MCP, Graph Ops, and the
FactoryLine JetBrains tab. In JetBrains, a conventional
`.factory/judgment/change-profile.json` is included automatically when present
for the selected Change List.

```powershell
factory judgment safety-case --root . `
  --changed src/payments/checkout.py `
  --change-profile .factory/judgment/change-profile.json --json
```

No release, test execution, source write, repair, approval, merge, publishing,
deployment, signing, messaging, credential, or connector authority is added.
See [Engineering Judgment Safety Case](ENGINEERING_JUDGMENT.md) for the exact
schema and limits.
