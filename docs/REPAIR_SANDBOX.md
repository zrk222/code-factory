# Verified Repair Sandbox

The Verified Repair Sandbox is a local-first professional workflow for using a
supervised repair agent with an exact scope. Scope preparation and inspection
remain read-only; explicit approval can authorize isolated patch execution.

```text
Native Change List
  -> Scope Passport (exact paths, current hashes, measured context bytes)
  -> Proof Mission pasted into Junie or another AI coding agent
  -> returned Change List or external supervised candidate patch
  -> FactoryLine intent, hollow-test, and path-scope review
  -> independent verifier evidence
  -> human reviews and applies in the IDE
```

It solves a narrow but costly problem: an agent or teammate can produce a
plausible patch while silently absorbing unrelated work, touching release or
infrastructure files, or leaving no durable explanation of what was in scope.
FactoryLine makes the scope and the handoff inspectable without pretending that
the patch is correct.

## Junie + FactoryLine: the connected proof loop

Junie helps you build. FactoryLine helps you know whether the build and its
tests deserve trust. After preparing the Scope Passport, choose **Copy Proof
Mission for AI agent** and paste the compact contract into Junie. The mission
names the sealed paths, forbids weakening a failing test just to get green, and
asks the agent to return changed paths, tests, failures, and unknowns.

When Junie finishes, choose **Review returned Change List**. FactoryLine opens
its existing local Proof Review over the actual workspace delta. It does not
trust the agent's completion claim, and it does not grant Junie permission,
start it, read its chat, or imply JetBrains endorsement. Teams can use the same
loop with any coding agent; the local stdio MCP configuration remains available
for clients that support it.

## Prepare a Scope Passport

Use the JetBrains **Repair Sandbox** tab and choose **Prepare Change List**.
FactoryLine reads one native local Change List and refuses to proceed if one of
its changes is outside the opened project or has no resolvable file path. After
the explicit workspace confirmation it runs:

```powershell
factory repair scope --root . --change-list "Checkout hardening" `
  --changed src/service.py --changed src/checkout.kt `
  --out-dir .factory/repair-sandboxes --json
```

The packet contains:

- an exact sorted file list and file-or-deletion SHA-256 baselines;
- the existing Diff-to-Proof review hash, findings, and next action;
- a **Context Budget**: exact file count and current bytes against a selected
  threshold. This is a split recommendation only - not a token, credit, latency,
  or quality estimate;
- a required-check list for scope freshness, path-scoped candidate, independent
  verifier evidence, and human apply; and
- JSON, Markdown, and Mermaid artifacts below the explicitly selected local
  `.factory/repair-sandboxes` directory.

The default Context Budget threshold is 262,144 bytes. You can set a different
local review threshold with `--context-budget-bytes`; it never predicts
provider usage or savings.

## Inspect a Candidate Patch

An external, owner-configured supervised runner may save a textual standard Git
diff inside the same workspace. FactoryLine never calls that runner itself.
Select **Validate candidate patch** and choose the patch, or run:

```powershell
factory repair candidate --root . `
  --scope .factory/repair-sandboxes/repair-scope-<id>.json `
  --patch .factory/candidates/checkout.patch `
  --out-dir .factory/repair-sandboxes --json
```

FactoryLine checks that the Scope Passport is current and untampered, then
binds the patch SHA-256 to that scope. The initial protocol supports unquoted,
UTF-8 textual `diff --git a/<path> b/<path>` patches. It rejects binary,
combined, quoted, parent-traversal, and out-of-scope paths rather than guessing
how a patch application might behave.

## Approve & Repair: one patch, isolated verification

After reviewing an audit finding and its candidate patch, an operator can
approve the exact candidate hash, expiry, pinned container image and check
commands. The first execution protocol handles one patch per approval. It
does not generate a patch or infer permission from a scan verdict.

Save a workspace-local JSON array of checks. Each positive check must reproduce
the known baseline failure and then pass on the repaired candidate; each
negative check must fail on the repaired candidate with its declared exit code
and failure signature. Infrastructure errors and timeouts are not proof.

```json
[
  {"id":"regression","kind":"positive","argv":["python","-m","pytest","tests/test_regression.py"],"failure":{"exit_code":1,"signature":"EXPECTED_REGRESSION_FAILURE"}},
  {"id":"negative-control","kind":"negative","argv":["python","-m","pytest","tests/test_negative_control.py"],"failure":{"exit_code":1,"signature":"EXPECTED_NEGATIVE_CONTROL_FAILURE"}}
]
```

These signatures are examples: choose specific messages from the actual
reviewed controls. Use the candidate hash returned by `factory repair candidate` and the inspected
SHA-256 image identity, rather than copying example values:

```powershell
factory repair approve --root . --scope <scope.json> --patch <candidate.patch> `
  --approved-by <operator> --confirmation "APPROVE REPAIR <candidate_sha256>" `
  --expires-at <timezone-qualified-expiry> --container-image <local-image> `
  --container-digest <sha256-image-id> --checks <checks.json> `
  --checks-sha256 <reviewed-checks-file-sha256> --json
factory repair run --root . --approval <returned-approval-path> --json
```

`approve` records permission; it does not execute. `run` consumes it once,
applies the patch in a disposable Git worktree, and runs only the approved
commands in an isolated container with read-only source, no network, dropped
capabilities and bounded resources. `--checks-sha256` binds the approval to the
exact bounded JSON bytes the operator reviewed; the CLI rejects a mismatch.
Commands needing scratch output must use
the container's temporary directory; source-writing builds need a separate
supported execution profile. The primary checkout stays unchanged.
Source drift, protected tests or gates, failed controls and uncertain cleanup
prevent `VERIFIED`. The result and local logs distinguish verification from
failure. Review the retained patch before promoting it through your normal
merge workflow.

Use `factory repair revoke --approval-sha256 <hash> --requested-by <operator>
--reason <reason>` to revoke permission, or `factory repair stop` with the same
arguments to request termination of an active attempt. Both accept `--root`
and `--json`. A stopped or failed single-use approval cannot be replayed;
retry requires inspection and fresh approval.

The JetBrains Repair Sandbox exposes an **Approve & Repair** tab with explicit
operator, expiry, container image, image digest, checks path and revoke/stop
reason fields. Approval displays the exact candidate and scope hashes, patch,
touched paths, parsed check commands and failure signatures, reviewed checks
hash, image digest, expiry, and confirmation phrase before recording a
single-use approval. Separate buttons run the approved attempt, revoke an
approval, or request a stop. The UI requires a positive and negative check and
binds the reviewed checks bytes by SHA-256. The CLI's `--checks-sha256` is
optional for direct use; the UI always supplies it.

The UI uses the configured FactoryLine executable and the existing explicit
IDE confirmation flow. A runner timeout or malformed run response leaves
cleanup unknown, blocks retries, and directs the operator to request stop and
inspect durable attempt evidence. No success is shown unless the CLI response
matches the approved hash and reports `VERIFIED` with cleanup confirmed and
the primary checkout unchanged. The operator name is an audit label in a local
filesystem-owner trust model, not authenticated identity or a second
reviewer's signature. Checks establish only their declared behavior;
`VERIFIED` does not prove every audit lane, production safety or independent
detection accuracy. The UI source and focused tests are present; a rendered
IDE interaction has not been verified here.

## Non-negotiable boundary

Preparing a scope or validating a candidate **does not** run an agent, create a
worktree, apply a patch, modify source, execute tests, commit, merge, publish,
deploy, sign, access credentials, send project data, or make a release
decision. A scoped candidate is neither a pass nor a quality claim. Use the
existing Verifier Plane for separately supplied independent evidence, then use
your normal JetBrains diff/apply workflow to make the final human decision.

For large teams dealing with project-analysis delays, FactoryLine should point
to, not replace, JetBrains Shared Indexes. JetBrains documents Shared Indexes
as a way to reuse precomputed project analysis across developers and provides a
CLI to evaluate the before/after analysis time; FactoryLine does not run or
configure that infrastructure automatically.
