# Verified Repair Sandbox

The Verified Repair Sandbox is a local-first professional workflow for using a
supervised repair agent without giving it an undefined working tree or an
automatic apply path.

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
