# Deep audit engine considerations

CF coordinates external evidence rather than reimplementing analysis engines.
The current implemented interchange is a deliberately strict SARIF 2.1.0 subset.

Primary reference reviewed: [Semgrep JSON and SARIF fields](https://docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif).
Its documentation distinguishes fields by edition, including fingerprints.
Consequently, SARIF output alone does not guarantee compatibility with CF's
required native fingerprint, driver/version, completion, source binding and
canary fields. No blanket plug-and-play Semgrep compatibility is claimed.

CodeQL, Infer, Clang, Qodana and SonarQube remain possible producers or adapter
targets, not a claim that their native outputs were exercised in this release.
Adapters must retain producer identity, source hashes, suppressions, ordered
flows and failure states. They must not invent absent fingerprints or relabel
an incomplete run as successful to satisfy the importer.

Validation currently uses signed synthetic fixtures and explicit mechanism
mutations. Real-project engine integration tests and independent field evidence
are separate from those local conformance receipts. This distinction matters:
schema correctness and a detected canary do not establish complete defect coverage.
