# Study434: fresh held-out candidate results

Measured scanner candidate: [`c0bdb8ef6d7686c257482396c5b3e14983c8e440`](https://github.com/zrk222/code-factory/commit/c0bdb8ef6d7686c257482396c5b3e14983c8e440).

**Known-TP retention: 68.57% (24/35).**
This is retention among independently labelled raw TPs in this fixed sample, not precision or an unconditional recall estimate.

| Candidate output | TP | FP | UNCLEAR | Decided precision |
| --- | ---: | ---: | ---: | ---: |
| Raw observations before admission | 35 | 17 | 24 | 67.31% (35/52) |
| Admitted findings | 24 | 2 | 6 | 92.31% (24/26) |

Eleven labelled raw TPs were not admitted; two FPs were admitted. Unresolved findings remain visible and are excluded from decided-label denominators. This study measures one candidate and does not establish a before/after repair gain.

## Method and qualification

- The original metadata selection was reduced to its first 200 roots in original order before native predictions or labels were inspected. Of these, 182 completed the native Python profile and 18 were source-ineligible. The 18 are accounted separately and are not security-validation successes.
- The captured roots contained 88 raw security observations. The frozen admission-independent sampler selected 76 packets across 58 repositories, with a maximum of three packets per repository.
- Each packet received two blind AI review passes, independent of the implementation and each other. Pass A used Luna with a disjoint Luna-high workshare; pass B used Sol 6.1 high. These are AI labels, without outside human adjudication.
- There were 11 actionable-label disagreements. Only exact TP/FP agreement is decided; actionable disagreements and agreed UNCLEAR results remain UNCLEAR.
- The admitted result contains 26 decided alerts, below the preregistered minimum of 40: **UNDERPOWERED_BELOW_MINIMUM_DECIDED; not qualified for the 80% gate claim.** Its Wilson 95% lower confidence bound is 75.86%.
- One unchanged-candidate scan exceeded its original 180-second budget and completed in 300.297 seconds under a recorded 600-second recovery ceiling. The other 181 native checkpoints were reused. The original latency contract did not pass.
- Reviewer envelopes were sealed before scoring. A metadata-only conversion wrapped their non-object `missing_context` fields as objects; labels, reasoning and citations were unchanged, and original envelopes were preserved.

## Evidence and release boundary

[Exact scorer output (gzip)](study434-held-out-score.json.gz), SHA-256 `46911632bfccb179cfd9566c5795cd6ffd215a763ba848e7a1fdabcfe9639f58`.

The scorer checksum above refers to the decompressed original bytes. Gzip avoids storing redundant expanded JSON in the repository.

Packet seal SHA-256: `cbe19d8bd3b0f1ae6936502d94e0576f7a41fc57ff125b6b59f443b9dec3e8ca`.

Original reviewer A envelope SHA-256: `3ff73713126910df91010f16d269deae854b29b03081ba9d5f5389e6129c7d7b`.

Original reviewer B envelope SHA-256: `1d5b54fde2ecdbff7f246eac1dfacd652d874941a010c4a27a426bc53306ca67`.

The scorer output records the normalized envelope hashes. Detailed source packets and reviewer citations remain in the local sealed evidence set; this public report contains no source snippets or credential values.

These results describe the unreleased candidate above. They are not a measurement of the existing 0.49.5 release binaries, DSSE cryptographic verification accuracy, or universal scanner coverage. Later changes require their own validation; this cohort is exposed after this measurement.

## Sampling, concentration and error register

[Full sampling frame, 200 pinned roots, per-repository counts and 13-case error register](study434-sampling-and-errors.json.gz). The frame targets small, low-star Python web applications, not all Python repositories. It combines 103 previously unprobed metadata entries with six GitHub framework queries (stars 1–9, non-archived, non-forks; star-descending pages 4–10), deduplicates names/IDs and recorded exposures, then applies the frozen hash rank. The union contains 2,175 candidates. The original 600-eligible-root acquisition was reduced to its first 200 before native predictions or labels.

The 24 admitted TPs come from **24 different repositories**; the largest admitted-TP repository share is **1/24 (4.17%)**. Raw TPs span 32 repositories; the largest raw-TP repository share is 3/35 (8.57%). Counts for every reviewed repository are in the linked register.

Freeze: **2026-10-31 14:55:39 UTC**, commit `c0bdb8ef6d7686c257482396c5b3e14983c8e440`; freeze-record SHA-256 `f0d0f2f4d7dbfc04358abeda996ad2852ba3f409e7678ad78298c1416f094edc`; runtime-manifest SHA-256 `43b82607a7272f86835eace2b9446c914af2fe56fbf0c0ad7e04279c5def25b3`. The freeze record states zero new target requests, predictions and labels. All 537 frozen runtime files were revalidated unchanged after scoring. Selected repository names/IDs have zero overlap with recorded exposure exclusions. These local records support the stated boundary; they do not prove global historical/content non-exposure or supply an independent timestamp attestation.

No scanner tuning occurred between the candidate freeze and sealed scoring. Operational changes are disclosed above and in the register. After unblinding, this cohort is exposed; the newly requested repairs will be measured separately as development results. The retained current aggregate includes the original timeout row; the completed pre-label snapshot and recovered individual report remain preserved.

| ID | Error | Repository and source |
| --- | --- | --- |
| N434-001 | Missed TP | [dinkardongre/E-Commerce-Backend-Platform — src/controllers/user_controller.py:10](https://github.com/dinkardongre/E-Commerce-Backend-Platform/blob/7854229bd1f7b72a4dea407c67531dffb5885dab/src/controllers/user_controller.py#L10) |
| N434-008 | Missed TP | [KhitMinnyo/dv-bookshop — app.py:1642](https://github.com/KhitMinnyo/dv-bookshop/blob/d4d286cfb42554d708e199bbc9b394c79da30d95/app.py#L1642) |
| N434-009 | Missed TP | [anotherik/ThreatByte — server/routes.py:264](https://github.com/anotherik/ThreatByte/blob/ede28f27e7e5061866a67b19b6088df4dd11c569/server/routes.py#L264) |
| N434-020 | Missed TP | [dmt94/nourish — nourish/settings.py:27](https://github.com/dmt94/nourish/blob/4acc1bc7d207d1ddab3a39008075f186a2f55ccc/nourish/settings.py#L27) |
| N434-021 | Missed TP | [KhitMinnyo/dv-bookshop — app.py:1780](https://github.com/KhitMinnyo/dv-bookshop/blob/d4d286cfb42554d708e199bbc9b394c79da30d95/app.py#L1780) |
| N434-022 | Admitted FP | [aidanlister/blog-docker-walkthrough — myapp/settings.py:22](https://github.com/aidanlister/blog-docker-walkthrough/blob/7e6b65ccd568f9e2b4db815bb5c289ac6c3f84df/myapp/settings.py#L22) |
| N434-023 | Missed TP | [KhitMinnyo/dv-bookshop — app.py:1535](https://github.com/KhitMinnyo/dv-bookshop/blob/d4d286cfb42554d708e199bbc9b394c79da30d95/app.py#L1535) |
| N434-028 | Missed TP | [gr/Btools — models.py:136](https://github.com/gr/Btools/blob/ef8d672762e5850e5587aecd0ec4a008bae87afa/models.py#L136) |
| N434-030 | Missed TP | [just-digital/django-ng-spa — simpletime/settings.py:20](https://github.com/just-digital/django-ng-spa/blob/2d2a94b2642551396a4804739cb9004b94e8b884/simpletime/settings.py#L20) |
| N434-032 | Admitted FP | [celerityweb/django-teslacoil — test_project/test_project/settings.py:85](https://github.com/celerityweb/django-teslacoil/blob/753de0c2762914516582f5544ad2d9abac8a147c/test_project/test_project/settings.py#L85) |
| N434-048 | Missed TP | [anotherik/ThreatByte — server/config.py:7](https://github.com/anotherik/ThreatByte/blob/ede28f27e7e5061866a67b19b6088df4dd11c569/server/config.py#L7) |
| N434-049 | Missed TP | [saapooch/Flask-Boilerplate — app/server/config.py:6](https://github.com/saapooch/Flask-Boilerplate/blob/ab750357a1f7241b9c6197de15d05638b27c3728/app/server/config.py#L6) |
| N434-070 | Missed TP | [avuletica/CloudZilla — src/settings.py:24](https://github.com/avuletica/CloudZilla/blob/a442c0717acebd7f3997128a20705c6bc88ae9b1/src/settings.py#L24) |
