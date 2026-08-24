# Code Factory 0.40.0

## Intent before implementation

Code Factory now adds **Intake Grill**, a native pre-mission decision gate. It
turns the exact PRD bytes into a small decision tree, then requires a named
human to bind the delivery framework, exact intent, observable acceptance
evidence, and external-effects posture. A Product Graph can bind that
confirmation, and `factory mission create --require-intake` fails closed when
the binding is absent, stale, or from different PRD bytes.

The framework shortlist is deterministic keyword evidence, not an AI-selected
architecture. Intake Grill does not create a mission, write source, run a
worker, select a framework, or authorize implementation.

## Evidence-gated repair retries

The **Proof-Delta Loop** now prevents a Mission Graph retry from repeating the
same failed attempt. A retry must bind the latest failed criterion, a changed
candidate diff, and at least one fresh hash-checked evidence reference. A
no-gain packet halts rather than consuming another retry. Graph Ops projects
the admission facts in a read-only lane, and MCP exposes a read-only status
tool for clients that need to inspect it.

## Earned autonomy, not a permission toggle

**Earned Autonomy** adds a local, expiry-bound Agent License derived only from
admitted, independently verified governed events. Current policy values are
explicit: three clean current events can reach supervised; autonomous requires
20 clean events, 15 independent verifications, and a stable common workspace
scope. A hollow test, hollow validator, or scope escape immediately demotes the
affected declared agent to human controlled. A license caps a Loop Passport at
admission; it does not authenticate the agent, start a model, or grant merge,
repair, release, deployment, signing, or credential authority.

`factory combine` complements that record with a deterministic, offline-
verifiable scoreboard for already-completed governed events on one human-written,
sealed task. It ranks passing result and declared failure classes—not elapsed
time, token usage, cost, unmeasured quality, or vendor capability. Graph Ops and
local MCP show these supervision facts without gaining mutation authority.

## Proof of survival

The new **Gauntlet** turns explicitly human-written promise sabotages into a
supervised local batch. `factory gauntlet plan` hash-binds a promise source, its
Reality Check manifests, and its existing positive/negative E2E argv pairs
without executing them. A named reviewer must create an expiry-bound, one-run
admission before `factory gauntlet run` can execute that exact current batch.

The resulting **Survival Card** exposes each declared case as survived, hollow,
or blocked and lists unproven promises. The card has deterministic JSON,
Markdown, and SVG views and can be integrity-verified offline. Optional DSSE
sealing binds a caller-supplied key and trust root to the exact card hash.
Graph Ops and `factory.gauntlet_status` MCP access project only read-only local
facts.

Where teams need extra context precision, a Gauntlet source can bind only
already verified, unexpired, exact-scope Continuity metadata. The proposal and
card contain hashes and evidence digests—not memory bodies, prompts, or private
summaries—and go stale if the selected context is no longer eligible.

Gauntlet never writes source, invents an argv command from prose, automatically
repairs code, approves, merges, publishes, deploys, messages, accesses
credentials, or calls a connector. A Survival Card is not a security,
coverage, performance, cost, token-savings, quality, release, or
production-readiness certificate.

## Local MCP and visual surface

The existing local stdio MCP server now exposes `factory.intake_status`,
`factory.proof_delta_status`, and `factory.gauntlet_status`. The tools are
read-only and cannot write source,
choose a framework, create a mission, run a worker, apply a repair, approve,
merge, publish, deploy, sign, message, access credentials, or call a connector.

Graph Ops projects source-bound intake confirmations and proof-delta receipts
beside the existing Product Graph and Mission Graph facts. These are visual
inspection aids only; execution authority remains outside Graph Ops.

**Graph Forensics** adds a read-only semantic debugger for two hash-sealed graph
lineages. It identifies a first divergence and its causal cone, plus deterministic
stale-read, stale-write, parallel-write-conflict, and duplicate-side-effect
findings. Its recovery preview does not fork a checkpoint or execute a graph;
a human and the target runtime retain that authority.

## Boundary

Version 0.40.0 does not establish framework correctness, product-market fit,
runtime success, a passing acceptance check, time savings, token savings, cost
savings, productivity improvement, or production readiness. It proves only the
declared local byte bindings and the deterministic retry-admission condition.
