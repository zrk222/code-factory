# Independent review: preflight rejection journal

**Scope:** Uncommitted changes in `scripts/evaluate_jev.mjs` and `scripts/evaluate_jev.test.mjs` on `codex/jev-preflight-failure-journal`, based on `44afd87`. Read-only review; no source edits. The original review is preserved in `rejection-review-initial.md`; its false resource-leak finding is withdrawn.

## Disposition

No blocking finding remains in this bounded review. The current `recordRejectedTrial` closes the handle in `finally` and catches close failures, returning `UNRECORDED/rejection_write_error` rather than allowing cleanup failure to mask the preflight error. `runCli` then attaches that sanitized tracking state to the original failure. The previously noted close-error masking edge is resolved in the current diff.

## Evidence and limits

- Rejection records include only generated run ID, timestamp, sanitized error code and `provider_requests: 0`; raw argv, credentials, state and paths are absent. Generic errors are normalized to `preflight_failed`. The preflight path precedes evaluation/provider requests; mocked tests assert zero calls for invalid input. This is application-flow evidence, not proof against external requests.
- Recording uses the secured archive root, exclusive creation, restrictive file mode and append/fsync. Failures return a sanitized `UNRECORDED` marker; partial files after a failed append can remain and will not verify. Tests exercise success, malformed input, missing key, zero-provider-call behavior, and linked/escaping archive roots; injected write/close failures are not covered.
- `verifyJournal` recognizes the separate one-event `VERIFIED_REJECTION` state and validates record shape, chain hash and zero request count. Existing evaluation journal handling remains distinct; operator feedback only admits `VERIFIED` complete evaluation journals. Verification shows event integrity, not judgment correctness or approval. The supplied operator receipt records exit code 2 for invalid arguments and offline `VERIFIED_REJECTION` with `externally_anchored: false`.
- The supplied rejection test log reports 60/60 passing; I did not rerun tests. These checks do not establish external repository authenticity or release readiness.

## Current source hashes

- `scripts/evaluate_jev.mjs`: SHA-256 `a070c71ed23281bbee9b5a239aa3d1899a665cc8e565b334733a6dd282250735`
- `scripts/evaluate_jev.test.mjs`: SHA-256 `daccd6becf904cfd6b019ed77bc1c46f9228614704e6447149f80fd79f241084`

