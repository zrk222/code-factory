# Plan: proof-continuity-ledger-v1

Spec: specs/proof-continuity-ledger-v1.md

1. Reuse the sealed Oracle source/rule model, never a worker-authored gate.
2. Bind a repository revision to complete critical chains and hash-valid local
   evidence lanes, including but not centered on AppForge.
3. Make later confirmation, contradiction, and uncertainty explicit. Reopen on
   contradiction and require human-supervised recovery.
4. Project the audit in CLI, MCP, and Graph Ops without adding execution or
   provider authority.
