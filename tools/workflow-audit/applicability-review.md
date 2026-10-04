# Specialty AI scope review: universal workflow audit

Reviewed candidate: local read-only Python evidence validator, CLI routing,
resource bounds, regression tests and evidence binding. This is a scoped
specialty-agent review and grants no project, merge or release authority.

- Accessibility: applicable. CLI JSON state and failure output are the
  accessible, machine-readable interface; assert stable states and nonzero
  failure exits.
- Performance: applicable. Catalogs and evidence cause hashing and parsing;
  explicit input, artifact, aggregate-byte and profile limits must reject
  oversized work before unbounded processing.
- External effects: inapplicable to this feature as implemented. The evaluator
  reads workspace files and returns a receipt; it does not execute project
  commands, call providers, make payments, send messages, deploy, or approve.
  Reassess if writes or integrations are added.
- Security/privacy: containment and hashes are checked for a stable local
  workspace. Concurrent hostile path/symlink replacement is explicitly outside
  the guarantee; use an immutable isolated snapshot for adversarial inputs.

The remaining five categories are applicable and require recorded checks.
This decision is only for this candidate; other projects must make their own
applicability decisions. Hash binding proves evidence bytes, not reviewer
identity or the correctness of the judgment.
