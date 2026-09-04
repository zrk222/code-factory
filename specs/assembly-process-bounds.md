# Spec: Assembly process bounds
## MUST - Functional core
### Requirements (EARS)
- When `REQ_OUTPUT` executes an Assembly CLI, it shall capture at most 4194304 bytes per output stream and return failure on overflow or stream read failure.
- When `REQ_STOP` encounters a 300 second deadline or cancelled heartbeat, it shall terminate the child tree using OS facilities and return failure without an unbounded pipe wait.
- When `REQ_EXIT` completes execution within 300 seconds, it shall return success only for exit code 0 with both readers finished and no cancellation, overflow or cleanup error.
### Acceptance criteria
```gherkin
Scenario: Excess output
 Given REQ_OUTPUT receives output above its configured bound
 When REQ_OUTPUT evaluates the child
 Then REQ_OUTPUT returns failure
Scenario: Cancelled operation
 Given REQ_STOP receives a false heartbeat
 When REQ_STOP evaluates the child
 Then REQ_STOP terminates the child and returns failure
Scenario: Successful output
 Given REQ_EXIT receives exit code 0 with finished readers
 When REQ_EXIT evaluates completion
 Then REQ_EXIT returns success and captured output
```
## SHOULD - Structural
- Use 65536 byte reads, 0.05 second polling and reader grace, 2 second reader and kill waits, and a 5 second Windows tree-kill timeout. UTF-8 decoding replaces invalid bytes. No shell or stdin. Preserve existing CLI argv and working directory. Tests may inject smaller resource bounds.
- Process cleanup is best effort and fail closed, not a sandbox or a guarantee against malicious process escape. No publication authority.
