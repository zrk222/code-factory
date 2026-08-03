# Code Factory 0.23.2

Code Factory 0.23.2 adds governed agent contracts and release-grade execution
rails across the factory. The release binds the Core-5 agent configuration to a
canonical digest, keeps creator and verifier context isolated, reconciles
telemetry without leaking public-sensitive details, and enforces provider
capability, privacy, cost, latency, context, and output contracts before route
selection. Mission completion now requires an independent verifier attestation,
and UI-scoped assemblies receive a strict Prestige gate.

Validation for this release includes the full Python test suite, strict doctor
and SpecLine gates, package build, and Twine distribution checks.
