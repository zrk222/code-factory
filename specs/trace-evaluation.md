# Spec: trace-evaluation
Status: approved

## MUST Functional core
### Description
Integrate the supplied trace-evaluation and eval-driven-development requirements with existing CF evidence, benchmark, verifier and operations modules. Implement deterministic evaluators before optional sampled model judgments; preserve explicit missing evidence and admission boundaries.
### User roles
- Operator: supplies authorized evidence and policy.
- Evaluator: computes bounded, reproducible per-criterion observations.
- Reviewer: independently checks labels, disagreements and proposed changes.
### Requirements (EARS)
- The system shall reject a `TRACE_UNBOUND` input unless trace, candidate, source artifacts, tool, model, prompt, rubric, dataset and policy identities are hash-bound and current, with at most 10000 spans and at most 2000000 bytes per request or artifact and at most 20000000 bytes across unique referenced artifacts.
- The system shall apply per-span criterion applicability only from a current hash-bound policy artifact with explicit reasons and source references, reject exemptions that hide present claim or tool facts, report evaluated versus not-applicable counts separately, and return INCOMPLETE when no criterion is evaluated across at most 10000 spans.
- The system shall return `NUMERIC_UNGROUNDED` for numeric claims whose reference value, unit, denominator or declared precision disagrees with bound evidence, and reject non-finite values or a zero denominator.
- The system shall return `CONTEXT_INCOMPLETE` when any declared required context or requested outcome lacks current supporting evidence, and store contradicted and omitted requirements in distinct lists, with a maximum of 2000000 bytes per context artifact.
- The system shall return `TOOL_SILENT_FAILURE` when a tool reports success without its required result or observed state, and accept empty output only under an explicit bound tool contract permitting empty output.
- The system shall emit `TOOL_REDUNDANT` only for matching tool, argument, candidate, relevant-state and freshness bindings without a verified retry or revalidation requirement; each referenced justification artifact shall have a maximum of 2000000 bytes.
- The system shall store `JUDGE_CALIBRATION` results with per-category confusion counts, abstentions, coverage, undefined rates as null, uncertainty, raw annotator agreement and separately reported adjudicated labels; unverified identity shall not establish independent evaluation.
- The system shall store a `TRACE_SAMPLING` ledger with every eligible trace counted, deterministic risk strata, selection policy, sampled and unscored denominators, exact or unknown cost and latency, and enforced approved budgets; each sampling artifact shall have a maximum of 2000000 bytes.
- The system shall admit live Jev trials only under an explicit per-trial dispatch policy with at most 100 cases and 60000 milliseconds per request, persist each admission before transport, retain every denied or unscored case in the denominator, reconcile provider-reported cost and measured latency, and halt further transport on unknown usage or budget overrun. Local policy references shall not be represented as authenticated approvals; local admission shall not claim enforcement of provider billing or cross-trial shared allowances.
- The system shall reject `REGRESSION_GATES` promotion when paired baseline and candidate evidence differs in dataset, workload, environment or policy, when a mandatory metric is missing, or when an approved threshold is breached.
- The system shall return `LIVE_ROLLOUT_UNVERIFIED` unless applicable deployment, kill-switch, rollback and randomized experiment controls have observed evidence; offline replay shall not claim a live rollout.
- The system shall store `FAILED_TRACE_RECOVERY` evidence for failed attempts with reproducible next actions, deidentified development cases, independent holdout boundaries and failed/impacted repair verification; each recovery artifact shall have a maximum of 2000000 bytes, and provider calls and production effects require their existing separate authority.

- The system shall run every applicable local audit lane by default in `factory scan`, discover an existing workspace-native worker configuration without requiring a deep-scan opt-in, and retain signed authorization checks before worker execution. Explicit static-only execution shall remain available.

- The system shall record a native repository scan as a parent span with a child span for every executed local lane, preserving failed spans, at most 10000 spans per recorder and at most 4096 bytes of attributes per span, measured durations and hash-bound lane-result references without raw source or exception messages.

- The system shall return Jev semantic review evidence only from bound task inputs, outputs, rubric criteria and byte-range source excerpts, with at most 8192 bytes per input or output and at most 32768 bytes per excerpt; mismatched digests, invalid ranges and absent semantic evidence shall not establish semantic correctness.

- The system shall emit ordered Jev review batches covering every requested span exactly once with at most 8 spans, 128 claims and 256000 packet bytes per batch, retaining the full evaluation identity; a single oversized span shall reject batching rather than silently omit evidence.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: input binding and span metrics
  Given a candidate with missing source bindings
  When evaluation is requested
  Then the input is rejected as `TRACE_UNBOUND`
  And mismatched numeric evidence returns `NUMERIC_UNGROUNDED`
  And missing required context returns `CONTEXT_INCOMPLETE`
  And success without required results returns `TOOL_SILENT_FAILURE`
  And unchanged identical calls without justified retry emit `TOOL_REDUNDANT`
Scenario: calibration, sampling and promotion
  Given labelled cases and trace observations
  When the evaluator computes report metrics
  Then the report contains `JUDGE_CALIBRATION` and `TRACE_SAMPLING`
  And stale or failing paired evidence rejects `REGRESSION_GATES` promotion
  And unobserved deployment controls return `LIVE_ROLLOUT_UNVERIFIED`
  And failed attempts retain `FAILED_TRACE_RECOVERY` evidence
```

## SHOULD Technical structure
- Reuse audit_trace.py, operations.py, runtime_audit_performance.py, benchmark_lab.py, verifier_plane.py, run_metrics.py and the current judge framework. No new Python file; keep 460 tracked Python files and all original file ceilings.
- Each phase has its own candidate-bound workflow evidence. Passing one phase does not prove the entire integration.
- Observe actions, references and concise rationales; redact sensitive data, retain access/retention policy and never collect private model reasoning by default.
## SHOULD NOT
- Do not fabricate human labels, independence, provider-measured cost, live execution, 99.85% accuracy, production performance, or complete coverage from fixture results.
- Do not add a hosted provider dependency or override deterministic failures with a model score.
