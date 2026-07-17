# Plan: capability-packs

1. Define the signed pack schema, required component manifests, trust root, and canonical payload hashes.
2. Ship four first-party target packs for worker, web, mobile, and agent UI generation.
3. Prove pack validators reject four meaningful structural mutations.
4. Replace the hard-coded target inventory with pack-derived metadata and bind pack id plus version into outputs.
5. Add fail-closed list, validate, and atomic install CLI commands with rollback and path-containment checks.
6. Add tests, smoke, ADR, operator docs, packaging metadata, clean-wheel checks, and release evidence.
