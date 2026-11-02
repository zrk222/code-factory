# Precision checkpoint: 66.67% known-TP retention

At `135e62c1`, the exposed regression cohort retains **8/12 known TPs (66.67%)**, up from 7/12, with **zero FP or UNCLEAR admissions and no prior TP loss**. Four known TPs remain missed. References contain 12 TP, 15 FP and 13 UNCLEAR labels from two independent AI reviewers, without outside human adjudication.

At that commit, final public CLI validation covers all 40 selected cases across 32 repositories in **404.702 seconds, zero timeouts**. All 63 raw diagnostics survive; all 8 admitted security findings reach candidate-bound repair packets. Eleven separate non-security quality advisory packets remain visible and receive no security TP credit.

Shared checkpoint fixes enforce parent revisions, paused-policy identity, transactional resealing, full diagnostic multiplicity and exact packet/witness binding. The checkpoint/handoff suite passed 84 tests; after the final native-partition extraction, all 41 sealing tests passed again. At that commit, repository-wide Forge quality passed Grade A; strict architecture and independent ECC review passed. No production module, dependency or detector family was added.

This is an **exposed development replay against sealed labels**, not fresh held-out precision. The untouched frozen run at `110b87cb2e9f50ac24d233a9c6720e69180720b0` admitted 7 TP and 0 FP; its 27 decided references fall below the registered minimum 40. Original labels and study seals remain unchanged.

Exact local receipts: `.factory/checkpoint-integration/public-cli-exposed40-delta.json`, `ecc-review.json`, and the scoped workflow audit.

Subsequent runtime handoff repair: all eight failed hosted cases and sealing controls pass in a 50-test targeted run. The recovered TP still reaches its public CLI repair packet. This repair adds no fresh precision measurement.
