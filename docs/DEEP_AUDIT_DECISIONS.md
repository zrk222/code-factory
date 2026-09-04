# Deep audit decisions

Turn bound analyzer reports into a prioritized repair queue, without letting the
analyzer approve its own work.

## Current entry point

`factoryline.deep_audit.execute_deep_audit(plan_path, trust_root_path,
trust_root_sha256, workspace_root)` verifies the signed plan and pinned trust
root, normalizes each target and separate canary report, evaluates the approved
rules, then rechecks input bindings before persisting a receipt.

The pure `evaluate_deep_audit` helper does not authenticate caller dictionaries.
Use the execute entry point for signed intake. No scanner or repair is executed.

## What blocks readiness

- Missing exact failing, unsuppressed canary: `HOLLOW_DEEP_AUDIT`.
- Unapproved suppression: `DEEP_SUPPRESSION_UNAPPROVED`.
- Unknown introduced error: `DEEP_UNKNOWN_ERROR`.
- Insufficient trace or missing ordered source-to-sink flow: `DEEP_TRACE_INCOMPLETE`.
- Signed total/new threshold exceeded: `DEEP_RULE_THRESHOLD`.
- Invalid or missing inputs raise a closed error; they never become a clean receipt.

Each repair item includes its rule/obligation, location where available,
remediation and consequence. Signed severity controls priority. Cross-analyzer
and cross-category clusters help route investigation; they do not prove causation.

All mapped results count toward the total threshold, even results labelled pass,
absent or suppressed. Only new, updated and unbaselined results count toward the
introduced threshold. This conservative policy may require review of producer
output; relabelling findings cannot silently create a green decision.

## Evidence and limits

Receipts live in `.factory/deep-audits/<content-sha256>.json`. Identical writes
are idempotent; differing existing contents fail. An interrupted write may leave
an incomplete receipt, which status rejects rather than reporting readiness.
Receipts bind candidate, signed envelope, normalized reports, rules and canaries.

`deep_audit_status(workspace_root)` reads the latest file by modification time;
it verifies its self-hash, filename and decision consistency. It does **not**
authenticate the writer, prove freshness, or authorize release. A local writer
can recompute a self-hash. Linked directories and invalid receipts are INCOMPLETE.

The only successful decision is READY_FOR_HUMAN_REVIEW, never approved. Evidence
can establish that these checks passed, not that the candidate has no defects.
Graph/repair-loop lineage integration remains a subsequent slice.

## IDE and agent access

Use `factory deep-audit evaluate --plan <signed.json> --trust-root <trust.json>
--trust-root-sha256 <sha256> --root <workspace>` to evaluate existing reports and
write the local receipt. No scanner, repair or release runs. Required paths are
explicit; JSON output is always produced. Exit 0 means ready for human review,
1 means blocked, and 2 means invalid inputs or an execution error.

Use `factory deep-audit status --root <workspace> --json` or the read-only MCP
tool `factory.deep_audit_status` to inspect it. Status returns exit 1 for NOT_RUN
or INCOMPLETE too: missing evidence is not a green audit. MCP accepts no arguments
and cannot start an audit. The IDE playbook identifies when to use this tool.

Mission Control includes the deep-audit evidence and marks BLOCKED/INCOMPLETE as
blockers. A ready receipt requires human review, never approval. Its profile now
measures six readers; these local timings do not establish an overall speedup.
