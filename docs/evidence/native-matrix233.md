# Current source native test matrix

Exact tested source: `ffcac7960d33fce39da63e9ebd96106521c92ae9`.
[Native CI run 39765104022](https://github.com/zrk222/code-factory/actions/runs/39765104022).
Nine existing CI JUnit artifacts were downloaded and checked; no jobs or passing
local tests were rerun to produce this receipt.

All nine Ubuntu, macOS and Windows jobs on Python 3.10–3.12 pass. Each report has
8,364 cases and zero failures/errors. Ubuntu/macOS: 8,352 passed, 12 skipped;
Windows: 8,348 passed, 16 skipped. Skips are not treated as passes.

The workflow remains failed because native candidate quality remains FAIL.
The unchanged local native audit has 90 complexity findings; architecture passes
at 429 Python files / 133 core modules, within unchanged 464/133 caps. This is
neither a full-CI-green claim nor merge qualification.

CodeQL alerts 87/88 were dismissed as source-reviewed false positives. Their
traces start at password-comparison diagnostic-return functions. The returned
payload contains fixed rule/message/severity metadata and AST coordinates, not
the target password literal or request value. Root verified four relevant Git
blob identities against the analyzed merge, and a separate ECC reviewer checked
the source. Both dismissal states were read back through the API. This applies
only to those two paths and is not a CF precision gain. Original SARIF and review
receipts remain under `.factory/precision231/`.

Latest qualified actionable precision is unchanged: Study225 **0 TP / 49 FP /
8 unclear; 0/49 = 0%**, nominal alert-level Wilson 95% **0–7.27%**. Same-family AI
reviews, incomplete semantic coverage and exposed-data limitations remain.
Neither the 35% merge bar nor 80% publication bar is met.
