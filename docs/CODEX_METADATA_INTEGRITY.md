# Codex metadata integrity

`factory ops metadata` audits local Codex/ForgeLine records without executing
their commands. Active records are the release-safe default; `--scope archive`
explicitly inspects historical terminal records, and `--scope all` returns
both. Every finding carries `scope: active` or `scope: archive`.

The audit rejects unbound terminal claims, self-attested gates, weak evidence,
unclear intent, malformed input, out-of-order progress timestamps, stale
`head=` values, and terminal `.forge` state without hash-bearing sibling
receipt lineage. Archive history is never promoted into active release proof.
Receipts use `factory.codex-metadata-integrity.v1` with `schema_version: 2` and
remain authority-free; they are evidence for review, not approval or
publication.
