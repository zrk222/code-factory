# Code Factory overview

Code Factory is a local-first software assembly workflow. Give it an outcome,
choose a target, and it produces an inspectable application-shaped starting
state rather than pretending that generated code is already production ready.
The same workflow expresses requirements, value slices, missions, tests,
approvals, and validation evidence as a Product Graph so a team can see what is
known, what is missing, and the one fact-derived next action.

## What it does

- **Gets a project moving quickly.** `factory mvp "..."` provides an
  outcome-first route to a contained MVP. `factory create` supports web, mobile,
  API, CLI, worker, MCP, and agent-UI starters.
- **Makes delivery state legible.** Factory Studio, Graph Ops, and the VS Code
  and JetBrains integrations present requirements, gates, proofs, and blocked
  work in one local, read-only view.
- **Gives agents bounded context.** The local stdio MCP server exposes the same
  Graph Ops facts, impact, and next action without execution or external
  authority. Every generated starter also includes a deterministic Mermaid
  output map.
- **Protects the definition of done.** Coverage and completion claims require
  non-hollow tests and verifiable receipts. A fresh scaffold remains explicitly
  blocked until real evidence exists.
- **Avoids unnecessary repeat work.** Content-addressed proof reuse can route a
  matching read-only validation to RUN, REUSE, SKIP, or BLOCK, preserving the
  reason and paired savings evidence instead of silently skipping a check.
- **Scales without blurring authority.** Capability packs, signed receipts,
  approval boundaries, and the optional hosted adapter support team and
  enterprise workflows while keeping publishing, credential access, approvals,
  deployments, and external messages human-controlled.

## Typical path

```powershell
pip install factoryline-code-factory==0.24.1
factory mvp "Build an approval tracker" --root .
factory studio --root .
factory graph ops --root . --mermaid
```

Start with the local MVP, open Studio to inspect its state, then use Graph Ops
to follow relationships and impact before choosing the next proof. The visual
surfaces do not execute commands or take external actions; they reveal the
evidence and the next action that the local facts support.

## Who it is for

For a developer new to delivery automation, Code Factory provides a guided
path from outcome to an honest MVP. For experienced developers and teams, it
provides a shared, auditable model of delivery state, deterministic validation
receipts, and reusable proof routing. In both cases, speed never replaces the
evidence needed to certify work.

## Boundaries that matter

Code Factory is local by default. It does not discover credentials, publish,
deploy, sign, approve, message, or grant connectors merely because a graph or
UI exists. Those actions stay behind explicit human-controlled or supervised
boundaries. Savings reports keep unknown token or cost values unknown; they do
not invent productivity claims.

Next: follow [Start Here](START_HERE.md), explore [Unified Graph Ops](GRAPH_OPS.md),
connect the [Local MCP inspection server](MCP.md), or see the
[Target Compiler and Factory Studio](TARGET_COMPILER.md).
