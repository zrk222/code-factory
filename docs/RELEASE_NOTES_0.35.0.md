# Code Factory 0.35.0

## Factory Continuity and Graph Ops Decision Replay

Factory Continuity records the minimum governance metadata needed to decide
whether a prior verified result is safe to reconsider: an opaque reference,
exact repository scope, purpose/version, evidence hashes, expiry, and
independent promotion state. It deliberately rejects private content,
embeddings, vectors, prompts, and transcripts.

- `factory continuity init|record|recall|promote|prove|status` provides a
  local-only, SQLite-backed workflow with idempotent writes and a hash-chained
  audit trail.
- Recall fails closed across tenant, purpose, scope, expiry, and promotion
  boundaries. Expired matching records are visibly withheld rather than reused.
- Graph Ops renders a read-only Decision Replay lane using redacted hashes. It
  cannot write continuity data, execute repairs, merge, publish, or deploy.

## Evidence boundary

This release is a governed local reference ledger, not a hosted memory
service. It does not provide hosted authentication, RLS, encryption/KMS,
external audit anchoring, deletion guarantees, model inference, or autonomous
execution. It makes no time, token, cost, productivity, or production-readiness
claim without separately supplied evidence.

## Install

```powershell
pip install factoryline-code-factory==0.35.0
factory continuity --help
factory graph ops --root . --json
```
