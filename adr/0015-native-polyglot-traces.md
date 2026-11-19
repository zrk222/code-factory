# Native polyglot traces

Reuse the existing Semgrep-compatible worker with OpenGrep OSS 1.15.0.
The pinned Semgrep 1.141.0 formatter removes SARIF and JSON dataflow traces
without login. Native source/sink evidence is required by the polyglot upgrade.

Replace that worker's binary with the official LGPL-2.1 OpenGrep release,
verified by its release SHA256. Reuse the existing SDK image and Python import
closure. Preserve the adapter family, rule schema, isolation and per-rule
execution receipts; validate the actual `Opengrep OSS` identity and version.
Existing Semgrep receipts retain their original identity and validators.

Acceptance requires all 30 rules, 97 expected findings, safe and suppression
controls, detector removals, and 16 source/sink trace checks through the existing
source-hash-bound SARIF normalizer. Missing traces fail acceptance. These controls
establish bounded fixture behavior, not fresh precision or interfile analysis.

Sources: [release](https://github.com/opengrep/opengrep/releases/tag/v1.15.0),
[native formatter](https://github.com/opengrep/opengrep/blob/v1.15.0/src/osemgrep/reporting/Sarif_output.ml).
