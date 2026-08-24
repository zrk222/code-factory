# factory-trust-core fork boundary

This folder is reserved for the future, independently governed Trust Service. The Week 2 architecture gate selects either an approved WizeMe fork or a clean-room Code Factory implementation behind the same contract.

It currently contains no WizeMe source code. Creating a fork requires an approved upstream repository, immutable source commit, license/provenance review, preserved attribution, SBOM, security baseline, and explicit import record. If that approval is unavailable, the service is implemented clean-room without copying restricted source.

## Owned capabilities

- policy decisions and parameter constraints;
- short-lived capability grants;
- approval, revocation, replay protection, and separation of duties;
- signed action, approval, and deletion evidence verification.

## Forbidden dependencies

- no direct WizeMe application-folder dependency;
- no semantic-memory ranking or raw model prompt ownership;
- no storage of reusable human connector credentials;
- no authorization based solely on model output or memory content.

The service will communicate through a versioned contract and independent release artifacts.
