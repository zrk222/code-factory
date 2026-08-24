# Code Factory 0.38.0

## Live proof context, without hidden authority

Code Factory 0.38.0 makes the local evidence loop easier to follow while a
Factory Assembly is in progress.

- Factory Studio and Unified Graph Ops now expose refreshable local activity:
  current stage, elapsed local time, completed/failed/skipped stages, and a
  cooperative stop request for the one active local Assembly. Finished meter
  rows remain the source of historical measurement; no missing token, cost, or
  productivity value is turned into zero.
- `factory memory brief` and the read-only `factory.developer_memory` MCP tool
  turn the exact current diff into a capped, explanatory next-proof brief. Each
  action states what changed, why it matters, what to do next, and the evidence
  it is bound to.
- Studio and Graph Ops add refresh controls and a local five-second
  auto-refresh. They show only redacted Continuity facts and observed local Git
  contributor context. Git authorship is never represented as verified seats,
  approvers, ownership, billing, or productivity.
- The JetBrains and VS Code adapters reuse the local Studio/Graph Ops surfaces
  so developers can reach the refreshed evidence view from the IDE without a
  source upload or provider connection.

## Install

```powershell
pip install factoryline-code-factory==0.38.0
factory studio --root .
factory memory brief --root . --json
```

## Boundary

This release adds no autonomous proof execution, repair, approval, merge,
publication, deployment, signing, credential, connector, or external-message
authority. Time, token, cost, and productivity savings remain unavailable until
an exact paired measurement supports them.
