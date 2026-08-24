# Code Factory 0.41.0

## Keep engineering decisions reviewable when the next diff arrives

Code Factory 0.41.0 adds **Engineering Judgment**: a local, repository-tracked
decision contract for the design trade-offs a team does not want an agent,
handoff, or later change to rediscover from scratch.

A named human proposes a Capsule with exact project-contained path scope, an
owner, a review date, rationale references, and declared proof obligations. A
different named human promotes it. The new Change Safety Case then evaluates
only explicit changed paths and hash-bound declared proof receipts:

- `BLACK`: the tracked decision store is invalid;
- `RED`: a matching decision lacks valid declared evidence;
- `AMBER`: matching evidence is bound and the named owner must review it;
- `GREEN`: no active tracked decision matched—never an approval or safety
  conclusion.

CLI, MCP, Graph Ops, and the JetBrains **Engineering Judgment** tab expose the
same read-only facts. None execute tests, inspect source semantics, infer an
intent, promote or waive a decision, repair code, modify VCS, merge, publish,
deploy, sign, message, or access credentials.

See [Engineering Judgment Safety Case](ENGINEERING_JUDGMENT.md) for the exact
schema, route meanings, and supervision boundary.
