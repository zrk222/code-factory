# factory-memory-core fork boundary

This folder is reserved for the future, independently governed Memory Service. The Week 2 architecture gate selects either an approved WizeMe fork or a clean-room Code Factory implementation behind the same contract.

It currently contains no WizeMe source code. Creating a fork requires an approved upstream repository, immutable source commit, license/provenance review, preserved attribution, SBOM, security baseline, and explicit import record. If that approval is unavailable, the service is implemented clean-room without copying restricted source.

## Owned capabilities

- memory write/retrieval and attribution;
- tenant, agent, subject, and purpose scoping;
- provenance, confidence, retention, correction, deletion, export, and legal hold;
- storage adapters and memory-specific threat controls.

## Forbidden dependencies

- no direct WizeMe application-folder dependency;
- no Trust database, signing key, provider credential, or billing data;
- no authority derived from recalled content;
- no hidden SaaS-only data format that prevents customer export.

The service will communicate through a versioned contract and independent release artifacts.
