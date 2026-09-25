---
name: cf-fl-build-audit
description: Interpret the automatic Code Factory and ForgeLine build checks and state exact outcomes.
---

# Code Factory and ForgeLine build audit

After a code build, report the automatic checks with the exact labels `Code Factory:` and `ForgeLine:`. State pass, fail, skipped, or unavailable accurately. A successful build command or Muse turn alone does not prove the audits passed.

The hook runs Code Factory's configured pattern and guard-path audits only when the repository contains `.factory/review-audits.json`. Without that policy, it reports those checks as skipped. Code Factory's security scan parses Python ASTs only; it does not cover other languages, runtime behavior, or whole-program security.

ForgeLine `qa --repo-wide` is an inventory check. It is not feature-scoped SSAT QA, an architecture gate, or a release decision. Use the feature's SSAT for its feature gate.

For changed PRD/spec Markdown, the hook routes matching native/mobile/App Store scope to the existing read-only AppForge status projection. SaaS, identity, subscription, or entitlement scope routes to Code Factory's provider-neutral `saas_proof` status projection. This project does not ship a separate SaaSForge engine; the hook reports that mapping explicitly.

The automatic status calls never generate a design, execute tests, contact a provider, write source, approve, publish, deploy, merge, sign, or release. Their local receipts are evidence for review, not approval.
