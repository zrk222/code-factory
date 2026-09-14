# Plan: full-stack-ux-harness-contract-v1

1. Add a native strict YAML loader and normalize both the established SSAT
   envelope and the explicit mobile harness envelope.
2. Emit immutable source-bound receipts and provide a replay verifier.
3. Expose `quality-harness spec-validate` and `spec-verify` for IDE, agent, and
   CI use without provider authority.
4. Add focused regression tests for valid projections, malformed contracts,
   duplicate keys, path safety, and stale receipts.
5. Add a read-only GitHub Actions workflow and user-facing contract guidance.

Validation: focused pytest, full pytest, Ruff, compile, SpecLine strict/validator
gates, ForgeLine architecture/QA/test/smoke gates, and package checks.
