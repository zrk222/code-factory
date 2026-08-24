# Spec: graph-portfolio-admission-v1
Status: approved
SpecFactor-target: 0.75-2.5

## MUST — Functional core
### Description
Graph Portfolio Planner turns an existing, bounded Graph Ops snapshot into a
deterministic, read-only execution proposal for developers and teams. It
identifies dependency cycles, the structural critical path, safe scheduling
slack, and high-fan-out proof candidates. A sealed Run Admission Packet binds
an external worker's proposed run to the current workspace, graph, Loop
Passport, budget, allowed paths, and required human approvals. Neither surface
executes a worker, applies a repair, invokes a provider, authenticates an
identity, or grants publication, deployment, merge, credential, or connector
authority.

### User roles
- Developer reviews the next smallest safe proof sequence for one workspace.
- Team lead supplies a reviewed Loop Passport and records a proposed external
  run that must be rechecked immediately before the selected harness starts.
- External harness consumes a verified admission packet but remains responsible
  for real sandboxing, authentication, network policy, credentials, and tool
  execution.

### Requirements (EARS)
<!-- Every requirement uses an EARS keyword: shall / When / While / If / Where -->
- When a complete Graph Ops snapshot contains an acyclic dependency relation, the system shall return `GRAPH_PORTFOLIO_STRUCTURAL_PLAN` with the structural critical path, slack for every related node, shared candidates, and an ordered workset. [R1]
- When a complete Graph Ops snapshot contains a dependency cycle, the system shall return `GRAPH_PORTFOLIO_CYCLE_BLOCKED` with lexical strongly connected components and an empty workset. [R2]
- When a portfolio request has zero valid positive duration observations, the system shall return `GRAPH_PORTFOLIO_SAVINGS_UNMEASURED` with null duration, critical-path-time, time-saved, token-saved, cost-saved, and productivity fields. [R3]
- When two ready nodes have identical disposition and priority, the system shall return `GRAPH_PORTFOLIO_STABLE_ORDER` with the node identifiers in lexical order. [R4]
- When a node reaches at least two distinct downstream nodes, the system shall return `GRAPH_PORTFOLIO_SHARED_CANDIDATE` with that node identifier and exact descendant count while leaving proof-reuse authority false. [R5]
- When two ready nodes have the same structural depth and no blocking ancestor, the system shall return `GRAPH_PORTFOLIO_SAFE_PARALLEL_WAVES` with those node identifiers in one proposal-only wave. [R5a]
- When a blocked node reaches a downstream node, the system shall return `GRAPH_PORTFOLIO_BLOCKER_CHAINS` with that blocked node identifier in the downstream node's lexical blocker list and shall assign the downstream node disposition `BLOCK`. [R5b]
- When a valid verified Loop Passport, complete Graph Ops snapshot, and workspace-contained request bind together, the system shall return `ADMISSION_PACKET_SEALED` after atomically writing one packet with repository, graph, passport, request, budget, action, path, trigger, approval, and `valid_until` digests. The `valid_until` timestamp shall be no more than one hour after sealing. [R6]
- The system shall reject every admission request with an invalid passport, incomplete graph, escaping path, undeclared action, missing approval, approval expiry timestamp at or before the current UTC timestamp, validity deadline at or before the current UTC timestamp, validity deadline more than 3,600 seconds after the current UTC timestamp, validity deadline after the earliest required approval expiry timestamp, or mismatched binding digest; it shall return `ADMISSION_PACKET_BLOCKED` and write zero packets. [R7]
- The system shall return `ADMISSION_READY` only after a sealed admission packet has current workspace, graph, Passport, request, approval, and `valid_until` bindings, and every external-effect authority shall be false. [R8]
- When a sealed admission packet has a changed workspace or graph binding, the system shall return `ADMISSION_STALE` without executing a worker or changing workspace bytes. [R9]
- Where Graph Ops projects a valid portfolio or admission packet, Graph Ops shall return `GRAPH_OPS_PORTFOLIO_ADMISSION_READ_ONLY` with disabled execution, approval, repair, merge, publication, deployment, signing, credential, connector, and messaging controls. [R10]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: globally efficient structural proposal
  Given a complete Graph Ops snapshot with three acyclic dependency nodes and one prerequisite that reaches two downstream nodes
  When the user compiles a portfolio plan without duration observations
  Then the result returns GRAPH_PORTFOLIO_STRUCTURAL_PLAN and GRAPH_PORTFOLIO_SHARED_CANDIDATE
  And the result returns GRAPH_PORTFOLIO_SAVINGS_UNMEASURED with null time, token, cost, and productivity fields

Scenario: cycle fails closed
  Given a Graph Ops snapshot with a dependency cycle
  When the user compiles a portfolio plan
  Then the verdict is GRAPH_PORTFOLIO_CYCLE_BLOCKED
  And no runnable workset is returned

Scenario: equal portfolio candidates remain stably ordered
  Given two ready nodes with identical disposition and priority
  When the user compiles a portfolio plan
  Then the result returns GRAPH_PORTFOLIO_STABLE_ORDER with node identifiers in lexical order

Scenario: safe parallelism and blocker propagation remain visible
  Given two ready nodes at one structural depth and one blocked ancestor with one downstream node
  When the user compiles a portfolio plan
  Then the result returns GRAPH_PORTFOLIO_SAFE_PARALLEL_WAVES with the two ready nodes in one proposal-only wave
  And the downstream node returns GRAPH_PORTFOLIO_BLOCKER_CHAINS with its blocked ancestor in a lexical blocker list and disposition BLOCK

Scenario: admission sealing is bounded and verifies fresh bindings
  Given a valid Loop Passport, complete Graph Ops snapshot, workspace-contained request, and valid_until within 3,600 seconds
  When the user prepares and immediately verifies an admission packet
  Then preparation returns ADMISSION_PACKET_SEALED with bound repository, graph, Passport, request, budget, action, path, trigger, approval, and valid_until digests
  And verification returns ADMISSION_READY with all external-effect authority false

Scenario: malformed or expired admission remains blocked
  Given an admission request with an undeclared action or valid_until that is expired, exceeds 3,600 seconds, or exceeds a required approval expiry
  When the user prepares or verifies the admission packet
  Then the result returns ADMISSION_PACKET_BLOCKED and no packet is written for preparation

Scenario: undeclared admission action is rejected before a packet exists
  Given an admission request whose action is absent from its Loop Passport
  When the user prepares the admission packet
  Then the result returns ADMISSION_PACKET_BLOCKED
  And the admission packet count is zero

Scenario: admission becomes stale after graph change
  Given a verified Passport, complete graph, and sealed admission packet
  When a graph-bound proof input changes
  Then admission verification returns ADMISSION_STALE
  And admission verification does not execute a worker or alter workspace bytes

Scenario: portfolio evidence is visible but cannot execute
  Given a Graph Ops snapshot with a portfolio or sealed admission packet
  When Graph Ops renders the Portfolio Flight Plan
  Then the result returns GRAPH_OPS_PORTFOLIO_ADMISSION_READ_ONLY with disabled execution, approval, repair, merge, publication, deployment, signing, credential, connector, and messaging controls

Scenario: every portfolio and admission requirement has an observable marker
  Given the Graph Portfolio and Run Admission contract
  When strict validator mutation runs
  Then contract markers include `GRAPH_PORTFOLIO_STRUCTURAL_PLAN`, `GRAPH_PORTFOLIO_CYCLE_BLOCKED`, `GRAPH_PORTFOLIO_SAVINGS_UNMEASURED`, `GRAPH_PORTFOLIO_STABLE_ORDER`, `GRAPH_PORTFOLIO_SHARED_CANDIDATE`, `GRAPH_PORTFOLIO_SAFE_PARALLEL_WAVES`, `GRAPH_PORTFOLIO_BLOCKER_CHAINS`, `ADMISSION_PACKET_SEALED`, `ADMISSION_PACKET_BLOCKED`, `ADMISSION_READY`, `ADMISSION_STALE`, and `GRAPH_OPS_PORTFOLIO_ADMISSION_READ_ONLY`
```

## SHOULD — Technical/structural
- Data model: `factory.graph-portfolio.v1`,
  `factory.run-admission.request.v1`, and `factory.run-admission.packet.v1`.
- CLI contract: `factory graph portfolio`, `factory admission prepare`, and
  `factory admission verify` support `--json`; successful proposal and
  verification results are readable JSON with SHA-256 digests.
- Runtime boundary: the planner uses only existing local graph artifacts and
  the admission verifier only reads local files. A selected external harness
  must enforce its own actual sandbox, egress, identity, secret, and tool
  boundaries.

## SHOULD NOT — Implementation details
- Do not introduce a model call, scheduler, remote API, worker runner, source
  upload, persistent secret store, heuristic duration estimate, or automatic
  repair/application action.
- Do not treat structural sharing as proof reuse; exact proof-reuse validation
  remains the existing independent gate.

## Decision logic (factory candidates)
Reject invalid source bindings before any plan is emitted. For a complete
acyclic graph, derive the structural workset; for a cyclic graph, return the
blocking components. Preserve null quantitative facts unless valid supplied
observations support them. Verify every admission binding again immediately
before a selected external harness is allowed to read the packet.
