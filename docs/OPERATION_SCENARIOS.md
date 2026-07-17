# Operations Scenario Matrix

This matrix defines the supported operator paths for Product Missions and the
Signal Loop. It is a coverage model for lifecycle states, roles, failures, and
approval boundaries; it does not claim to predict every future product domain.

| Stage | Scenario | Factory behavior | Owner or resolver | Artifact and next action |
| --- | --- | --- | --- | --- |
| Setup | New local workspace | Create bounded `.factory` directories | Factory steward | Status receipt; initialize Opinion Dock |
| Setup | Existing repository | Adopt sources without overwriting | Factory steward | Adoption receipt; review SSAT |
| Setup | Unsupported or missing companion tool | Fail the behavioral canary | Factory steward | Failure summary; install or repair exact package |
| Starter | Choose worker, web, mobile, or agent UI | Show pack-owned use case and deployment routes | Builder | `factory targets`; select target and route |
| Starter | No deployment route supplied | Select the target's local or device-preview route | Deterministic compiler | Bound local profile; compile blocked starter |
| Starter | Unsupported deployment route | Reject before writing output | Builder | Choose an id shown by `factory targets` |
| Starter | External deployment route selected | Bind prerequisites, build, verify, release, and approval with external effects false | Builder and release owner | Target workflow; prove locally, then request exact approval |
| Signal | Valid manual evidence | Normalize as untrusted local data | Product Owner | `factory.signal.v1`; triage |
| Signal | Slack, GitHub, Sentry, social, or telemetry copy | Preserve source and authorization; never execute text | Product Owner | Provenance-bound signal; triage |
| Signal | Duplicate content | Reuse content-hash receipt and queue entry | Auto-resolve safe | Idempotent signal result |
| Signal | Instruction-like content | Mark instruction-like and keep execution false | Auto-resolve safe | Untrusted signal; review normally |
| Signal | Oversized or malformed input | Reject before write | Author or coding loop | Causal failure and bounded input fix |
| Signal | Unverified connector entitlement | Reject or retain as public reference only | Product Owner | Authorization failure; obtain entitlement |
| Opinion | First dock | Write owner, rules, profiles, authority, hash | Product Owner | `factory.opinion_dock.v1` |
| Opinion | Rule correction | Replace active rule and append hash-linked rationale | Product Owner | Correction chain; retriage later signals |
| Opinion | More than 2,000 lines | Block triage | Product Owner | Consolidate or retire rules |
| Triage | No rule match | Severity-only score and owner decision required | Product Owner | Explainable triage receipt |
| Triage | Review rule match | Raise profile without invoking a model | Product Owner | Advisory routing profile |
| Triage | Hands-off rule match | Recommend blocked | Product Owner | Leave blocked or record named override |
| Triage | Product need rejected | Preserve rationale; no promotion | Product Owner | Decision receipt; stop |
| Triage | Product need deferred | Preserve rationale; no promotion | Product Owner | Decision receipt; revisit later |
| Triage | Product need approved | Bind signal, triage, dock, and owner | Product Owner | Owner decision; promote |
| Product Graph | Requirements or Gherkin missing | Write needs-input PRD draft; no mission | Human approval | Add missing product facts |
| Product Graph | Advisory actor, outcome, or UX gap | Compile but retain visible gap inventory | Human or auto-resolve review | Review gap before mission execution |
| Product Graph | Complete supplied facts | Create stable requirements and bindings | Deterministic compiler | Product Graph; plan slices |
| Slicing | Every requirement assigned once | Emit dependency-ordered vertical slices | Deterministic compiler | Value-slice receipt |
| Slicing | Dependency cycle or orphan | Block mission creation | Product Owner and architect | Repair PRD dependencies |
| Mission | Budget within ceiling | Bind inputs and Loop Passport | Mission owner | Approval-ready mission |
| Mission | Budget over ceiling | Reject without mission execution | Author or coding loop | Lower budget; retry |
| Mission | Human approval mode | Show risk, criteria, budget, and actions | Mission owner | Approve, defer, or reject receipt |
| Mission | Auto-resolve safe mode | Apply only idempotent mechanical local fixes | Deterministic resolver | Resolved list plus human-only blockers |
| Mission | Execution approved | Authorize only bounded executor actions | Mission owner | Execution decision; run isolated mission |
| Mission | Deferred or rejected | Keep execute false | Mission owner | Decision receipt; stop |
| Build | Creator produces candidate | Work in declared workspace and budget | Creator | Candidate diff and evidence manifest |
| Build | Iteration, wall-time, token, or cost exhausted | Stop the loop | Coding loop and owner | Budget failure; narrow mission or approve a new one |
| Verify | Creator equals verifier | Reject completion | Orchestrator | Assign a fresh verifier identity |
| Verify | Creator-private context supplied | Reject completion | Orchestrator | Rebuild allowed verifier context |
| Verify | Criterion missing, duplicated, false, or unproved | Reject completion without weakening gates | Creator and verifier | Repair earliest failing criterion |
| Verify | Evidence outside root or missing | Reject completion | Creator | Produce local reviewable evidence |
| Verify | All exact criteria pass | Hash mission, validation, and evidence | Independent verifier | Completion receipt |
| Verify | Bound file drifts later | Invalidate completion | Coding loop | Restore input or regenerate downstream proof |
| PR | Completion verified | Draft evidence-linked review packet | Reviewer | Review outcome, risk, screenshots, gates, rollback |
| PR | Unproven claim remains | Label explicitly; do not promote to fact | Reviewer | Add evidence or remove claim |
| Release | Merge, publish, deploy, signing, connector, or message requested | Require separate human authority | Release owner | Platform-specific approval and receipt |
| Release | Worker container route | Require reviewed image, registry, smoke input, host adapter, and rollback | Release owner | `container-host` route receipt |
| Release | Web split-hosting route | Verify frontend, API, health, browser, and cross-origin behavior independently | Release owner | `split-hosting` route receipt |
| Release | Mobile store route | Verify Expo, signed device, EAS, spend, and store credentials | Release owner | `eas-store` route receipt |
| Release | Agent UI private-host route | Verify identity, TLS, approval boundary, registry, canary, and rollback | Release owner | `private-container-host` route receipt |
| Release | Gate or policy mutation survives | Block release as hollow validation | Factory steward | Strengthen validator; rerun mutation |
| Runtime | Canary fails | Stop or roll back under release policy | Release owner | Canary and rollback receipt |
| Outcome | Measured result available | Append source-bound measured record | Product Owner | Outcome chain; compare target |
| Outcome | Observed, modeled, or unknown result | Preserve evidence class without upgrading it | Product Owner | Honest outcome record |
| Feedback | Outcome reveals a new need | Capture as a new signal | Product Owner | New provenance-bound loop iteration |

## Resolution policy

`human_approval` is the default. `auto_resolve_safe` is opt-in and restricted to
idempotent, deterministic, local changes whose expected output is already fixed
by a stronger source. It may deduplicate signals, reuse identical artifacts, or
regenerate derived views from unchanged hashes. It may not invent product facts,
alter a validator, cross a hands-off rule, raise a budget, approve execution,
or authorize an external effect.

Every failed command and Studio request returns `factory.failure_summary.v1`
with the failed stage, causal code, why, evidence, retry safety, next action, and
the shared instruction to repair the earliest failure before proceeding.
