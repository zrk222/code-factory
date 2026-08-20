# IDE Health Flight Recorder and Index Continuity Guard

Use these JetBrains controls when the IDE is slow, has a long pause, or appears
to reanalyse a project unexpectedly. They make two different kinds of evidence
visible; neither is an automatic fixer.

## 1. Record the symptom

Open **Tools > FactoryLine > Open IDE Health Flight Recorder**, then select
**Start local recording** while the problem is present. It takes one aggregate
sample every three seconds and retains the newest 20 samples in memory until
the project closes.

Each sample shows:

- JVM heap used and maximum heap.
- FactoryLine process CPU and system CPU when the bundled JVM exposes them.
- Whether JetBrains reports the project in indexing mode.
- The measured delay before an EDT dispatch probe runs.

The recorder deliberately does not send samples anywhere, inspect source or
file contents, identify a “bad” plugin, change settings, invalidate caches, or
claim that any single signal caused the symptom. CPU may be unavailable on a
given JVM; it stays unavailable rather than becoming an estimate.

## 2. Compare project structure

Use **Capture Index Continuity Baseline** when the project is in a known-good
state. It writes only the explicit local file:

```powershell
factory workspace continuity baseline --root . `
  --out .factory/index-continuity/baseline.json --json
```

After a package update, branch change, generated-output change, or reindexing
symptom, compare the same baseline:

```powershell
factory workspace continuity compare --root . `
  --baseline .factory/index-continuity/baseline.json --json
```

The Guard compares build/dependency manifests, named source roots, managed
generated/dependency directory topology, and local path classification. The
baseline stores file name, byte count, and a SHA-256 where the structural file
is at most 8 MB—never file content.

It classifies the next manual review as:

| Scope | Meaning | Next step |
| --- | --- | --- |
| `stable` | No observed structural drift. | Use IDE Health observations if the symptom remains. |
| `targeted_reanalysis` | Managed generated/dependency topology drifted. | Check that project-model visibility is intentional. |
| `broad_reanalysis` | A manifest, source root, or local workspace classification changed. | Let the IDE's normal project-model flow complete before considering manual recovery. |

The result does not read or repair an index, predict how long reindexing will
take, or say that a cache is corrupt. Only the developer decides whether a
JetBrains-supported recovery step is appropriate.

## Safe operating order

1. Reproduce the actual symptom and record a short window.
2. Capture or compare the structural baseline.
3. Review time-aligned facts, not a guessed cause.
4. Make any IDE setting or cache decision in the IDE, under your own control.

This keeps a performance investigation explainable: the runtime sample says
what the local process exposed, and the continuity comparison says exactly what
in the workspace structure changed. Neither substitutes for an IDE profiler or
JetBrains support diagnostic when those are needed.
