# Code Factory Session Recorder for Claude Code

This plugin records bounded, hash-chained `PreToolUse` and `Stop` envelopes for
Claude Code sessions. It stores only a session-key hash, tool name, tool-input
hash, time, and previous-event hash under `.factory/session-recorder/claude-hooks/`.

It never stores prompts, tool arguments, tool output, credentials, or environment
values. The hook trace is observational and is **not a sandbox or a governed run
receipt**. To feed an admitted session into Agent License and Combine, use:

```text
factory wrap --root . --admission .factory/admissions/<id>.admission.json \
  --validators .factory/session-validators.json --run-id <unique-id> -- \
  claude -p "your task"
```

`factory wrap` verifies admission before launch, observes the exact workspace
delta, runs the declared independent validators, and emits immutable receipts.
