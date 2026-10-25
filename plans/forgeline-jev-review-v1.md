# Plan: forgeline-jev-review-v1

## Packet A — ForgeLine bounded context and review hook
Own forgeline/orchestrator.py, forgeline/cli.py and existing tests in the authoritative ForgeLine repository. Capture profile/material and candidate before review, preserve deterministic outputs, check candidate again before admission, and append advisory observations to the existing receipt history. Reuse current snapshot helpers. No provider runtime dependency by default.

## Packet B — Shared CF evidence adapter
Own factoryline/jev_classifier.py and tests/test_audit_rule_search.py. Map the versioned ForgeLine context into the existing CF review-evidence packet and normalizer. Preserve exact source/request/claim/evidence bindings, explicit omissions, provider metadata and no-authority fields. Add no Python module or alternate ledger.

## Packet C — Operator join and adversarial proof
Demonstrate all four profiles through the actual ForgeLine hook and shared CF validator using a controlled transport, plus missing-provider, malformed-response, unsupported-authority and source-change controls. Record source hashes and actual commands. This proves the local integration, not live provider accuracy. Reuse the existing Vercel runner for any separately authorized live dispatch rather than adding another provider client.

## Packet D — Installed CF actionability review through Vercel Gateway

Owner-authorized addition: expose `factory audit actionability --cases <cases.json>`
through the existing packaged `evaluate_jev.mjs` runner and a distinct
`security_actionability` profile. Default to offline. Live dispatch requires
`--live`, a local `AI_GATEWAY_API_KEY`, and an explicit hash-bound budget policy.
Require Node 18 or newer; resolve installed wheel assets without a source checkout.
Reuse the existing process bounds, provider endpoint, journals, response validation
and abstention policy. Do not add another HTTP client or a mandatory provider
dependency. Bind source, callers, trust boundaries, counterevidence and unknowns;
API presence alone is not actionable. Keep raw scanner decisions unchanged.
Verify missing/stale inputs, label isolation, positive/negative/unresolved mock
responses, installed-wheel execution and separately recorded live-provider tests.
The scoped acceptance contract is `.factory/precision286/cli-acceptance-contract.json`.

## Limits and gates
CF remains <=460 tracked Python files. Measure formatted byte/line budgets before every write; never exceed current per-file ceilings. Changed functions must pass Ruff and Forge complexity <=10. Run only new/directly invalidated tests, SpecLine strict/validator/drift gates, CF doctor/workflow evidence gates, independent Astra MED review of Luna work and normal CI. Provider usage remains unknown when absent. Source transfers and external effects require current operator authorization. Existing full-goal requirements remain active.

## Atomic tasks
Architect verdict: PASS
Scoped dependency decision: ForgeLine owns context capture and deterministic gates; CF owns the existing JEV validator. The optional callback boundary avoids mandatory reverse dependencies. Existing receipt stores remain authoritative for local history. No second provider client or evaluator is authorized by this packet.

- [x] T1 | slice=factoryline | files=factoryline/jev_classifier.py,tests/test_audit_rule_search.py | verify=`python -m pytest -q tests/test_audit_rule_search.py -k forgeline` | Implement and challenge the shared versioned ForgeLine evidence adapter.
- [x] T2 | slice=forgeline | files=forgeline/orchestrator.py,forgeline/gates/judge.py,forgeline/cli.py,tests/test_forgeline.py | verify=`python -m pytest -q tests/test_forgeline.py -k jev` | In the separately identified ForgeLine root, add the bounded context and optional review hook with existing receipt history.
- [x] T3 | slice=specs | files=specs/forgeline-jev-review-v1.md | verify=`specline strict forgeline-jev-review-v1` | Exercise the real companion hook with the shared CF validator and retain hash-bound observations, source review and package limitations.

- [x] T4 | slice=plans | files=plans/forgeline-jev-review-v1.md | verify=`specline tasks forgeline-jev-review-v1` | Preserve operator acceptance, receipt locations and the remaining native provider join in the plan.

## Pre-push candidate gate
Freeze all owned files and record source hashes before final checks. Reconcile current protected main into the candidate and prove the exact intended file delta. Run the applicable exact CI format, package-data/public-docstring, architecture and Forge-quality checks against that tree; compare Forge complexity as well as Ruff. Run new, failed or directly invalidated tests only. Bind independent review and workflow observations to the same file hashes/tree. Publish only that tested/reviewed tree, preserving normal required remote matrices and exact-head review status. Every failed first run remains retained; a source change invalidates affected evidence before another push.

## Local packet evidence

ForgeLine candidate committed as `461e587` in the authoritative companion repo.
Its scoped workflow receipt is `.factory/ops-jev-final/` in `forgeline-review`: PASS,
receipt `7d35d4f31708147995714a8937528f1f8487a1d9edbfc08b2dbf7213ba740d3c`.
Controlled source integration: 30 focused tests passed, including seven shared
adapter cases. Five dispatcher controls and the 23-route parser check passed.
Four malformed-material cases plus the prior invalid/stale case passed after
Astra Medium's finding. Scoped Forge QA: A, maximum complexity 9, no findings.

CF adapter: 13 focused cases passed before the final deterministic-context fix;
seven invalid-context cases passed after it. Astra Medium reproduced missing and
non-mapping result contexts and confirmed zero transport calls. SpecLine strict
and four-task validation passed. Local transport controls establish wiring and
failure handling; live provider quality, release publication and installation
remain separate obligations. No model agreement is independent ground truth.
