# The grilling ladder — from request to review

Code Factory uses small decision stages so a coding agent cannot turn an
ambiguous request into a self-approved implementation.

| Stage | Human decision | Evidence produced | Stops when |
| --- | --- | --- | --- |
| **Intent Grill** | Delivery surface, intended outcome, acceptance observation, forbidden behavior, negative case, and external-effects boundary | Source-bound intake worksheet | The request is vague or the owner cannot name a boundary. |
| **PRD Grill** | Requirements, actors, journey, trust boundary, approval path, and success event | Bounded clarification frontier | Essential product facts are missing. |
| **Oracle Firewall** | Approved obligations, invariants, gate values, sources, exceptions, and negative cases | Signed, versioned Oracle Contract | A worker proposes a blocking rule, weakens an oracle, changes scope, or changes a source binding. |
| **Proof Review / PR** | Whether the observed diff and independent evidence satisfy the sealed contract | Review receipt and exact changed-path linkage | The test only passes because its oracle was weakened, the negative case is absent, or the receipt is stale. |
| **Independent challenge** | Whether counterfactual and boundary cases were reviewed | Challenge evidence tied to the contract | The challenge context cannot validate the current contract or tries to modify code/intent. |

The ladder is intentionally provider-agnostic. A provider export can contribute
hash-bound evidence through the Agent Proof Bridge, but it cannot edit the
Oracle Contract, grant approval, submit a PR, post a worklog, deploy, or release
on the strength of its own output.
