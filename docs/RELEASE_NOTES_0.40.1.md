# Code Factory 0.40.1

## IDE health without automatic tuning

This release adds **IDE Health Flight Recorder** to the FactoryLine JetBrains
plugin. A developer can explicitly record a short local window of aggregate
heap, process CPU when the runtime exposes it, indexing state, and EDT dispatch
delay. The view retains at most 20 samples in plugin memory and clearly leaves
a missing CPU signal unavailable.

It is an observation surface, not a tuning agent: it does not touch heap
settings, caches, indexes, plugins, inspections, files, credentials, or remote
connections. It also does not attribute a symptom to a plugin or claim a
performance improvement.

## Structural continuity before recovery

**Index Continuity Guard** adds versioned, hash-checked local baselines:

```text
factory workspace continuity baseline --root . --out .factory/index-continuity/baseline.json --json
factory workspace continuity compare --root . --baseline .factory/index-continuity/baseline.json --json
```

The compare result names changed structural files, source roots, managed
directory topology, and path classification, then asks for a `stable`,
`targeted_reanalysis`, or `broad_reanalysis` review. It neither accesses nor
repairs a JetBrains index, predicts reindex time, or declares a cache corrupt.

## Evidence boundary

Version 0.40.1 proves only the supplied local structural bindings and the
aggregate runtime observations exposed by the current JVM. It does not prove a
runtime root cause, plugin attribution, performance improvement, productivity
gain, security outcome, or release readiness.
