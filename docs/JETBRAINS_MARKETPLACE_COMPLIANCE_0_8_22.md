# FactoryLine 0.8.22 — Marketplace compliance evidence map

This is a local preflight map, not a promise of JetBrains approval.

| Review area | Repository or package evidence | Gate |
| --- | --- | --- |
| Identity and version | `plugin.xml` id `app.factoryline`; Gradle version `0.8.22` | `marketplacePreflight` |
| Compatibility | platform dependency and declared IDE baseline in the packaged descriptor | `guardianReleaseGate` plus Plugin Verifier |
| Honest functionality | listing says the Atomic adapter is read-only and does not execute, approve, merge, publish, or deploy | publication metadata tests |
| Privacy and credentials | local evidence paths and hashes only; raw credential access is not added | Graph Ops/MCP authority tests |
| Licensing and contact | dual-license notice, public repository, and vendor contact in `plugin.xml` | package inspection |
| Change notes | 0.8.22 user impact and authority boundary in both plugin and repository changelogs | publication metadata tests |
| Signing and upload | protected Marketplace environment; no credential is stored in the artifact | protected publication workflow |

Before submission, the protected workflow must recheck the live update slot,
build with JDK 21, run the native tests and verifier, bind the ZIP to its exact
commit and tag, and return the provider receipt. A queued or uploaded update is
not public approval.
