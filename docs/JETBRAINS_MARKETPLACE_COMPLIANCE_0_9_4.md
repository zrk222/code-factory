# FactoryLine 0.9.4 — Marketplace compliance evidence map

| Requirement or review risk | 0.9.4 evidence | Status and boundary |
| --- | --- | --- |
| Identity and version | `editors/intellij/build.gradle.kts` declares `0.9.4`; `plugin.xml` keeps id `app.factoryline`; `editors/intellij/CHANGELOG.md` leads with `0.9.4`. | Local metadata is aligned; a Marketplace listing read-back is still required. |
| User-facing value | `plugin.xml` and the IntelliJ README lead with First Proof, six audit lanes, senior evidence, and optional proof-coupled Junie attribution. | Copy is source-reviewable; moderation and listing presentation remain external. |
| Junie compatibility | The taxonomy and contribution card bind known tools, changed-file rationale, hashes, unknowns, and a visible credit line to a digest. | Junie is optional; FactoryLine does not require, execute, control, or imply endorsement by Junie. |
| Independent evidence boundary | `factoryline.independent_execution` verifies signed candidate/plan/runner bindings, freshness, cleanup, and resource observations while rejecting supervised-only assurance. | The package verifies supplied attestations; it does not host or prove the runner. |
| Defect quality | `factoryline.benchmark_lab` requires immutable source/bug/fix digests and emits case-level precision/recall; missed known defects block the receipt. | The corpus and replay execution are supplied by the reviewer. |
| Safe incremental review | `factoryline.incremental_scheduler` validates DAGs, dependency closure, side effects, assurance drift, and incremental/full shadow equivalence. | Planning is review-only; no gate or provider action runs. |
| Reproducible remediation | `factoryline.senior_assurance` replays the exact source/dependency/policy/input contract, compares original/fix/negative controls, explains safe reuse, and emits an evidence-linked failure briefing. | Replay is bounded process/workspace isolation; it is not a kernel/container sandbox and cannot approve a Marketplace submission. |
| Release controls | `guardianReleaseGate`, Plugin Verifier, signing, and protected Marketplace workflow remain required. | Upload, processing, manual moderation, and approval are JetBrains-only external states. |

This checklist records local evidence and boundaries. It does not promise
Marketplace acceptance or approval.
