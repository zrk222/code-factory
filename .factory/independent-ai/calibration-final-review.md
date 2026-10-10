# Calibration follow-up review

**Scope:** Read-only review of the current diffs in `factoryline/data/judge_framework.json`, `.github/workflows/worker-verification.yml`, and `scripts/verify_worker_cves.test.mjs`. No tests were run; no source files were changed.

## Review outcome

No blocking findings in the scoped changes.

- The oracle-profile evidence question now asks only whether Python test-function source text is present. Its rubric separates that packet-presence check from semantic oracle assessment. As described for this trial, deterministic host preflight checks revision/path/source digest before any provider call; model evidence probability is not repository authentication.
- The workflow path filters cover `.dockerignore`, the four `factoryline` modules used by Docker `COPY`, the verifier scripts and the workflow itself, without the broad `factoryline/**` trigger. The added test derives `factoryline/` sources from Docker `COPY` statements, checks both PR and push filters include them, and normalizes CRLF. This is a scoped trigger-coverage check; it does not validate Docker build/runtime behavior or every possible future build input form.
- The framework additions explicitly preserve the boundaries for lexical call-edge facts, controlled execution observations, and unresolved follow-up. Those are evidence guidance, not a claim that the current trial gathered those evidence types.

## Trial claim boundary

The supplied trial summary reports 27/31 admitted decisions correct, zero false positives, and four unresolved. This is an experimental result on that labeled set, not 99.85% accuracy, calibrated performance, or production reliability. Preserve the abstentions and do not reduce thresholds or substitute scanner labels for unresolved model judgments. The result does not certify repository provenance, helper semantics, runtime coverage, human adjudication, CI behavior, or release readiness.

**Disposition:** No source-level blocker identified in these three diffs. This review is not runtime verification or human certification.
