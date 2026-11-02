# Precision checkpoint: 66.67% known-TP retention

Current repair replay: **8/12 known TPs retained (66.67%)**, up from 7/12 (58.33%). No prior TP admissions were lost; no reference FP or UNCLEAR cases were admitted. Four known TPs remain missed.

All 40 selected cases across 32 repositories completed in **57.516 seconds, zero timeouts**. All 63 underlying raw diagnostics were retained. N438-021 is the new TP admission; the final public CLI also produced one supported defect and one repair action with 13/13 Python files audited in 3.876 seconds.

This is an **exposed development replay against sealed labels**, not a fresh held-out precision estimate. Precision among admitted replay cases is 8/8; retention uses all 12 known reference TPs. References contain 12 TP, 15 FP and 13 UNCLEAR labels from two independent AI reviewers, without outside human adjudication.

The untouched frozen run at `110b87cb2e9f50ac24d233a9c6720e69180720b0` admitted 7 TP and 0 FP. Its 27 decided references fall below the registered minimum of 40. Original labels and study seals remain unchanged.

Local evidence: `.factory/precision438-preflight/continuation-110b/shared-repair-exposed40-delta.json` (SHA256 `46323aaa` prefix); independent ECC review: `shared-repair-final-ecc-review.json`. Exact full artifact hashes are recorded in the scoped workflow audit.
