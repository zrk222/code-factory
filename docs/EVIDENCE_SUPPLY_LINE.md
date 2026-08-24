# Evidence Supply Line

Code Factory can only govern agent autonomy when real runs produce evidence.
The Evidence Supply Line closes that gap without claiming to contain or
authenticate the agent process.

## 1. Wrap any local agent CLI

Create a normal Loop Passport and READY run-admission packet that declares an
agent identity, scope, actions, and `max_wall_seconds`. Then define independent
validators in a workspace-contained manifest:

```json
{
  "schema": "factory.session-recorder.validators.v1",
  "verifier_subject": "team-test-runner",
  "validators": [
    {
      "id": "unit-and-sabotage",
      "argv": ["python", "-m", "pytest", "-q"],
      "timeout_seconds": 300
    }
  ]
}
```

The manifest must exist **before** the admission is sealed, because admission
binds the current workspace fingerprint.

```powershell
factory wrap --root . `
  --admission .factory/admissions/rate-limit.admission.json `
  --validators .factory/session-validators.json `
  --run-id rate-limit-run-01 -- `
  claude -p "add rate limiting"
```

The wrapper:

1. fails closed unless the packet is `READY` immediately before launch;
2. applies the admitted wall-time cap;
3. snapshots up to 10,000 workspace files outside VCS, dependency, and cache state;
4. runs the agent command without a shell;
5. records created, modified, and deleted paths with before/after SHA-256;
6. classifies scope escape, crash, timeout, or validator failure;
7. runs every declared validator without a shell;
8. writes hash-bound result, verification, session, and Agent License receipts.

The receipt never retains the agent prompt, command arguments, raw stdout,
raw stderr, credentials, or environment values. It stores command and output
digests, byte counts, exit facts, durations, and file hashes.

### Trust boundary

`factory wrap` is **observed execution, not sandboxed execution**. The host or
selected harness must enforce OS identity, filesystem containment, network
policy, and credential isolation. A READY packet is a local metadata boundary,
not proof of external identity or runtime containment.

## 2. Draft promises from structure

```powershell
factory gauntlet draft --root . --source-id first-proof --json
```

The command performs static inspection only. It reads:

- `[project.scripts]` from `pyproject.toml`;
- literal Python route decorators such as `@app.get("/health")`;
- existing Python and JavaScript/TypeScript test paths;
- built-in target-pack entrypoint shapes.

For a declared CLI entrypoint it proposes a DRAFT positive/negative command
shape. For an HTTP route it records the route but withholds execution when the
repository does not provide an exact harness command. It never converts prose
into executable commands.

Every output uses a DRAFT-only schema that the executable Gauntlet rejects.
A human must review and promote the promise plus paired E2E manifest to the
existing executable schemas, name an approver, compile the proposal, and issue
a separate expiring Gauntlet admission.

## 3. Optional Claude Code hook trace

The `code-factory-session-recorder` Claude Code plugin registers bounded
`PreToolUse` hooks for `Edit`, `Write`, and `Bash`, plus a `Stop` hook. It stores
only a hashed session key, tool name, tool-input digest, timestamp, and previous
event digest under `.factory/session-recorder/claude-hooks/`.

This trace helps establish ordering but is not a governed result. Use
`factory wrap` when the run must feed Earned Autonomy or Combine.

## Built-in target templates

Code Factory ships an inert, package-level target-template registry at
`factoryline/data/gauntlet_target_promises.json`. Keeping the registry outside
the signed pack directories preserves their reviewed signatures. Its seven
templates describe a first promise and the required positive/sabotage shape
without approving or executing anything.

If the optional Claude hook is active, include its
`.factory/session-recorder/claude-hooks/` output in the admitted path scope or
the recorder will correctly classify those writes as a scope escape.
