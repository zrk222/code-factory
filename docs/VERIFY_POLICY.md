# Verify Policy

`factory verify-policy` proves that a policy evaluator rejects every deleted or
inverted policy rule. A policy file is not evidence by itself: its evaluator
must fail when the requirement it claims to enforce is removed.

Create a reviewed challenge manifest. `command` is an argv array, never a shell
string, and `{policy}` is replaced with the temporary baseline or mutated file.

```json
{
  "command": ["python", "scripts/check_release_policy.py", "{policy}"],
  "cwd": ".",
  "timeout": 60
}
```

Then run:

```powershell
factory verify-policy --root . --challenge policy.challenge.json
```

The original policy must pass. Each delete/invert mutation must make the
evaluator return non-zero. If one mutated policy still passes, the receipt is
`HOLLOW_POLICY` and the command exits non-zero. A missing command, shell-like
string, missing `{policy}` placeholder, failed baseline, escaped working
directory, or timeout is an error, not a passing result.

The command writes a local receipt at
`.factory/policy-challenges/verify-policy.json` by default. It does not publish,
merge, deploy, or grant approval authority.

Copy-paste Python and TypeScript evaluators are in
[`examples/verify-policy`](../examples/verify-policy/README.md). The Python
example also contains a deliberately hollow evaluator for seeing the failure
mode yourself.
