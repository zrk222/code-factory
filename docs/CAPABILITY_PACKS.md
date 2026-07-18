# Capability Packs

Capability Packs make Code Factory targets extensible without turning pack
installation into execution authority. Version 0.17.3 includes 29 signed packs:
seven runnable starter targets plus surface, language, capability, data, and
operations contracts that can be validated and composed before implementation.

```mermaid
flowchart LR
    A["Signed Capability Pack"] --> B["Manifest and complete file map"]
    B --> C["Offline DSSE Ed25519 verification"]
    C --> D["Ten structural mutations"]
    D --> E{"Every mutation rejected?"}
    E -->|"no"| F["Fail closed; preserve existing install"]
    E -->|"yes"| G["Atomic staged installation"]
    G --> H["Worker, web, mobile, or agent UI target"]
    H --> I["Compatible hash-bound composition"]
    I --> J["Product Graph and value-slice gates"]
    classDef input fill:#dbeafe,stroke:#2563eb,color:#172554
    classDef gate fill:#fef3c7,stroke:#d97706,color:#451a03
    classDef fail fill:#fee2e2,stroke:#dc2626,color:#450a0a
    classDef proof fill:#dcfce7,stroke:#16a34a,color:#052e16
    classDef target fill:#ede9fe,stroke:#7c3aed,color:#2e1065
    class A,B input
    class C,D,E gate
    class F fail
    class G,I proof
    class H,J target
```

See [Code Factory Architecture](ARCHITECTURE.md) for the full component and
authority topology.

```powershell
factory pack list
factory pack validate factoryline/builtin_packs/target-worker
factory pack install factoryline/builtin_packs/target-worker --root .
factory pack compose factoryline/builtin_packs/target-web `
  factoryline/builtin_packs/surface-nextjs `
  factoryline/builtin_packs/language-typescript `
  factoryline/builtin_packs/capability-auth --root . --name review-portal
```

Validation checks canonical UTF-8/LF file hashes against an offline DSSE
Ed25519 signature, then proves the structural validator rejects ten mutations:
required-field deletion, kind replacement, canary removal, accessibility-state
removal, deployment removal, generator mismatch, validator removal, golden
removal, migration-policy relaxation, and provided-capability removal.
Text-file verification is stable across Git's CRLF/LF checkout normalization;
binary files remain byte-exact.
Every pack must include nonempty validators, goldens, and canaries; all standard
UX states; and a migration policy that denies breaking changes, requires human
review, and requires rollback.

Installation writes only below `.factory/packs/<pack-id>`. Existing installs are
preserved unless `--force` is explicit. Force replacement stages the new pack,
backs up the old pack, swaps atomically, and restores the backup on failure.

Composition validates every signature and mutation suite, rejects duplicate or
conflicting packs, enforces required pack kinds and compatible targets, and
writes `.factory/pack-compositions/<name>.json` atomically. The composition is a
review plan: `generate`, `execute`, `deploy`, and `publish` authority all remain
`false` until a Product Graph value slice and independent proof bind the work.

## Built-in catalog

| Kind | Packs |
| --- | --- |
| Target | CLI, API, MCP, worker, web, Expo mobile, supervised agent UI |
| Surface | React, Next.js, Expo, Manifest V3 browser extension |
| Language | Python, TypeScript/JavaScript ESM, Java, Kotlin, .NET/C#, Go, Rust, C/C++ |
| Capability | auth, billing, search, import/export, accessibility, i18n, offline/sync |
| Data | data pipelines, evaluation harnesses |
| Operations | admin and operator control rooms |

The CLI, API, and MCP target packs are executable starter generators. Other
packs are explicit integration contracts: their adapter, validators, goldens,
canaries, UX states, migration policy, deployment profiles, compatibility, and
provided capabilities are reviewable before product code is generated. A
composition never pretends those product-specific integrations already exist.

```mermaid
flowchart TB
    T["Choose one target pack"]
    S["Choose zero or more surface packs"]
    L["Choose language packs"]
    C["Choose capability packs"]
    D["Choose data and ops packs"]
    V["Verify signatures and 10 mutations per pack"]
    X{"Compatibility and required kinds pass?"}
    R["Hash-bound composition receipt"]
    P["Product Graph value slice"]
    N["No generation or release authority"]
    F["Actionable incompatibility failure"]
    T --> V
    S --> V
    L --> V
    C --> V
    D --> V
    V --> X
    X -->|"yes"| R --> P --> N
    X -->|"no"| F
    classDef input fill:#dbeafe,stroke:#2563eb,color:#172554
    classDef gate fill:#fef3c7,stroke:#d97706,color:#451a03
    classDef proof fill:#dcfce7,stroke:#16a34a,color:#052e16
    classDef human fill:#fce7f3,stroke:#db2777,color:#500724
    classDef fail fill:#fee2e2,stroke:#dc2626,color:#450a0a
    class T,S,L,C,D input
    class V,X gate
    class R,P proof
    class N human
    class F fail
```

## Authority boundary

A verified pack may describe a generator. It cannot execute agents, call a
model, access a connector, use credentials, deploy, publish, sign a release, or
send an external message. Those actions remain separate reviewed workflows.

## Pack layout

```text
pack.yaml
generator/adapter.json
validators/manifest.json
goldens/manifest.json
canaries/manifest.json
ux-states/manifest.json
migration-policy.json
pack.trust.json
pack.signature.json
```
