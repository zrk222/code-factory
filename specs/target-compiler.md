# Spec: target-compiler
Status: approved
SpecFactor-target: 0.75-2.5

## MUST - Functional core

### Description

Code Factory shall compile one PRD or plain-language prompt into one of four
reviewable starter targets: a headless worker, a web app, an Expo mobile app,
or an agent operator UI. Every target carries a governance manifest, an SSAT
contract, non-hollow smoke hooks, a blocked ForgeLine state, a Mermaid proof
map, and a hash-bound compile receipt. The generated target is starting state,
not evidence that product-specific behavior is complete.

### User roles

- Engineer: selects a target and reviews generated files and constraints.
- Maintainer: runs proof gates and approves promotion or release.
- Operator: uses a generated agent UI after product-specific hardening.

### Requirements (EARS)

- The system shall return marker `TARGET_KIND_SET` and expose factory create
  with exactly four target kinds: worker, web, mobile, and agent-ui.
- The system shall return marker `SOURCE_EXACTLY_ONE` after accepting exactly
  one source: a non-empty prompt or an existing UTF-8 PRD file.
- When the output directory is non-empty, the system shall return marker `OUTPUT_EXISTS`
  before writing any byte.
- The system shall return marker `TARGET_MANIFEST_WRITTEN` after writing
  target_manifest.json with schema factory.target.v1, governance fields, and
  blocked promotion state.
- The system shall return marker `COMPILE_RECEIPT_BOUND` after writing the
  target compile receipt with source, manifest, and generated-file SHA-256
  values.
- The system shall return marker `MERMAID_PROOF_WRITTEN` after writing the
  target architecture map with intent, runtime, proof, receipt, and human
  release nodes.
- When target_kind is worker, the system shall return marker `WORKER_EMITTED`
  after writing runnable Python, smoke, and SSAT files without network or
  external-message capabilities.
- When target_kind is web, the system shall return marker `WEB_EMITTED` after
  writing the existing factory app starter plus the target proof contract.
- When target_kind is mobile, the system shall return marker `MOBILE_EMITTED`
  after writing an Expo SDK 57 TypeScript Continuous Native Generation starter
  without native directories.
- When target_kind is agent-ui, the system shall return marker `AGENT_UI_EMITTED`
  after writing a Next.js operator surface, local FastAPI
  task boundary, receipt view, and approval-required actions.
- When factory studio starts, the system shall return marker `STUDIO_STARTED`
  with a local browser URL serving the target builder.
- While Factory Studio is running, the system shall return marker `STUDIO_CONTAINED`,
  listener address 127.0.0.1, and reject request bodies
  larger than 64 KiB or studio_root values classified as escaped.
- While Factory Studio is running, the system shall return marker `ACTION_FORBIDDEN`
  for publish, deploy, sign, external-message, credential,
  and connector-grant requests.
- When factory studio check JSON runs, the system shall return marker `STUDIO_STATUS_EXACT`
  with the local boundary and target inventory without
  starting a server.
- When an editor requests Factory Studio, the system shall return marker `EDITOR_TRUST_CONFIRMED`
  after invoking factory studio behind workspace trust
  or explicit confirmation and opening the URL through the editor API.
- If generation fails, the system shall return marker `COMPILE_FAILED`, a
  non-zero exit, and no compiled-target claim.

### Acceptance criteria (Gherkin)

```gherkin
Scenario: Compile each target from the same intent
  Given an empty output root and a non-empty product intent
  When factory create runs once for worker, web, mobile, and agent-ui
  Then each target has its expected runnable scaffold
  And each target has a blocked target manifest, SSAT, smoke hook, Mermaid map, and hash-bound receipt

Scenario: Refuse destructive generation
  Given an output directory containing an existing source file
  When factory create targets that directory
  Then generation fails before changing the existing file

Scenario: Contain Studio writes
  Given Factory Studio rooted at a temporary workspace
  When a request supplies a traversal name or an oversized body
  Then Studio rejects the request and writes nothing outside the workspace

Scenario: Keep promotion human-owned
  Given any generated target
  When its target manifest is inspected
  Then deploy, publish, destructive actions, external messages, and receipt signing require approval
  And promotion state is blocked pending proof

Scenario: Every requirement has an observable validator marker
  Given the target compiler contract
  When strict validator mutation runs
  Then contract markers include TARGET_KIND_SET, SOURCE_EXACTLY_ONE, OUTPUT_EXISTS, TARGET_MANIFEST_WRITTEN, COMPILE_RECEIPT_BOUND, MERMAID_PROOF_WRITTEN, WORKER_EMITTED, WEB_EMITTED, MOBILE_EMITTED, AGENT_UI_EMITTED, STUDIO_STARTED, STUDIO_CONTAINED, ACTION_FORBIDDEN, STUDIO_STATUS_EXACT, EDITOR_TRUST_CONFIRMED, and COMPILE_FAILED
```

## SHOULD - Technical and structural

- ADR references: `adr/0007-target-compiler-and-local-studio.md`
- Data model: `factory.target.v1`, `factory.target_compile_receipt.v1`
- API contract: `GET /api/status`, `POST /api/create` on loopback Studio only
- Data model: TargetRequest(target_kind: `worker`|`web`|`mobile`|`agent-ui`, source_kind: `prompt`|`prd`, source_text: string, name: string, purpose: string, trigger: string, studio_root: `contained`|`escaped`, promotion_action: `none`|`publish`|`deploy`|`sign`|`external-message`)
- Existing `factory app from-prd|from-prompt` commands remain backward compatible.
- Expo versions follow the official SDK 57 project contract and are checked by
  `npx expo install --check` after dependency installation.
- Target-specific behavior remains isolated from Factoryline assembly and
  receipt verification modules.

### Authorized bounded constants

These values are part of the feature contract, not tuning parameters:

- Studio binds to loopback with port `0` selecting an ephemeral port; valid
  explicit ports are `1` through `65535`.
- Studio accepts at most `64 * 1024` bytes (`65536` bytes), while its browser
  form caps intent text at `60000` characters.
- Generated operator instructions are capped at `4000` characters.
- Project names are at most `48` characters and use a regex tail of `{0,47}`.
- Studio session tokens use `secrets.token_urlsafe(32)`.
- Studio uses HTTP status codes `200`, `400`, `403`, `404`, `409`, and `413`;
  generated health checks require status `200`.
- The Studio form uses `100%` field width. This is presentation geometry, not
  a product success metric.

## SHOULD NOT - Implementation details

- Do not claim a generated starter is production ready.
- Do not add a model call to target generation or Studio.
- Do not serve arbitrary workspace files from Studio.
- Do not add a remote bind flag or silent editor command execution.
- Do not reuse product-specific public benchmark claims as fixture data.

## Decision logic (factory candidates)

| # | if | then |
|---|----|------|
| 1 | target_kind == `worker` | EMIT_WORKER |
| 2 | target_kind == `web` | EMIT_WEB |
| 3 | target_kind == `mobile` | EMIT_MOBILE |
| 4 | target_kind == `agent-ui` | EMIT_AGENT_UI |
| 5 | studio_root == `escaped` | REJECT_PATH |
| 6 | promotion_action == `publish` | REQUIRE_APPROVAL |
| 7 | promotion_action == `deploy` | REQUIRE_APPROVAL |
| 8 | promotion_action == `sign` | REQUIRE_APPROVAL |
| 9 | promotion_action == `external-message` | REQUIRE_APPROVAL |
| 10 | else | COMPILE_BLOCKED_STARTER |
