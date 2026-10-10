# Independent review: JEV test-oracle profile

**Review scope:** `factoryline/data/judge_framework.json`, `scripts/evaluate_jev.mjs`, `scripts/evaluate_jev.test.mjs`, and `.factory/independent-ai/jev-separated-report.json` only. Read-only review; no tests run.

## Findings

No blocking defect found in the reviewed scope.

- **Evidence preflight:** `loadTrial(..., 'test_oracle')` runs `validateTestOracleCases` before evaluation. It requires nonempty supplied source, a 40-hex commit, nonempty path, and a 64-hex excerpt digest matching the exact UTF-8 source bytes. Tests cover mismatched digest, missing source, and malformed commit. This binds the packet to its stated bytes before a provider call.
- **Bound on that guarantee:** The preflight checks revision shape only. It does not fetch/authenticate the repository revision or validate `source_file_sha256`/that the excerpt belongs to the stated path and commit. The framework accurately says the model does not authenticate upstream and calls host verification a digest/revision-shape check; keep claims at that level. If upstream provenance is a required guarantee, this needs a separate deterministic checkout/source verification gate.
- **Optional evidence criteria:** `evidence_criteria`, when present, requires exactly nonempty bounded `true` and `false` strings plus evidence instructions. Those instructions are separately type/length checked. The explicit evidence question stays atomic and omits finding criterion text/criteria; tests assert this separation and expected-label redaction. Without `evidence_criteria`, the existing combined evidence question now includes the exact finding criterion and its criteria. No regression found.
- **Authority and thresholds:** The selected profile and rubric are included in trial hashing; true/false thresholds are included in configuration hashing and report output. The report continues to mark experimental=true and release/approval/scanner_override=false. The inspected separated report marks itself `INCOMPLETE`, with 31 abstentions, zero decided cases, and `advisory_grade`/`experimental_score` null; its threshold values are recorded. It makes no accuracy claim.

**Disposition:** Source-level review only. No runtime or human-certification claim. Upstream source authenticity remains outside this preflight's guarantee.
