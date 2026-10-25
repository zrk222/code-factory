# Spec: captured-program-origin-v1
Status: approved
SpecFactor-target: 0.75–2.5

## MUST — Functional core
### Description
CF traces a file-backed dynamic program to captured repository bytes and independently checks its interpretation-time effects. File provenance alone is not a negative decision. Unsupported origins, effects and namespaces retain the raw security diagnostic.

### User roles
- A repository owner inspects source-bound diagnostics and their declared proof scope.
- An independent reviewer replays the input-origin and effect checks from captured bytes.

### Requirements (EARS)
- When `PROGRAM_ORIGIN_REQUESTED` identifies an exec or eval call, the system shall resolve a single captured program source through lexical assignments, file reads and compile operations within 512 evidence states and 64 captured sources, or return incomplete. [R1]
- When `PROGRAM_PATH_REQUESTED` contains file-relative pathlib or os.path operations, the system shall derive a normalized repository-relative path from the captured caller location and closed literal components with 0 target file reads and 0 target imports. [R2]
- When `PROGRAM_ORIGIN_UNSUPPORTED` contains external inputs, unknown path components, rebinding, escaped file-object references, ambiguous providers, missing bytes or a source hash mismatch, the system shall retain the raw finding with its original severity and emit 0 proven-primitive decisions. [R3]
- When `PROGRAM_EFFECT_REQUESTED` contains at most 16384 program bytes and 1024 AST nodes, the system shall admit only closed assignments, inert declarations and canonical future-annotation imports with 0 target executions; unsupported interpretation-time calls, decorators, defaults, imports, namespace controls and effects shall remain incomplete. [R4]
- When `PROGRAM_DECISION_REQUESTED` has a source-bound origin and validated effects, the system shall regenerate the complete witness from current bytes within 512 evidence states and emit PROVEN_CAPTURED_DECLARATIVE_PROGRAM only when caller, program, namespace, builtin identities and source inventory hashes match. [R5]
- When `PROGRAM_DECISION_TAMPERED` changes any origin, effect, namespace, source span, source hash or positive security premise, the system shall retain the active finding with its original priority and reject the negative witness. [R6]
- When `PROGRAM_MEASUREMENT_REQUESTED` runs, the system shall freeze scanner and source hashes, preserve all 96 existing labels and use identical context additions in both comparison profiles, with 0 exclusions of timed-out claims from a qualified score. [R7]
- When `PROGRAM_IMPLEMENTATION_CHECKED` runs, the system shall add 0 production modules, 0 dependencies and 0 cross-application references; bounded case qualification shall finish within 30 seconds or remain incomplete. [R8]

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Captured file origin is independently bound
  Given `PROGRAM_ORIGIN_REQUESTED` with a lexical file read and compile chain
  When `PROGRAM_PATH_REQUESTED` resolves the captured caller location
  Then R1 and R2 bind exactly one current program source

Scenario: Origin is insufficient to establish inert interpretation
  Given `PROGRAM_EFFECT_REQUESTED` with an unsupported interpretation-time call
  When `PROGRAM_DECISION_REQUESTED` runs
  Then the raw diagnostic remains active as required by R3 and R4

Scenario: Independent admission rejects altered evidence
  Given `PROGRAM_DECISION_TAMPERED` with a changed program hash
  When source admission runs
  Then R5 and R6 reject the negative witness

Scenario: Paired measurements preserve the comparison
  Given `PROGRAM_MEASUREMENT_REQUESTED`
  And `PROGRAM_IMPLEMENTATION_CHECKED`
  When regression qualification completes
  Then R7 preserves all 96 labels and R8 adds zero modules
```

## SHOULD — Technical/structural
### Closed interpretation grammar
- Values are None, bool, int with at most 4096 bits, finite float, str/bytes of at most 16384 bytes, and recursively closed tuple/list/dict values. Each value-node evaluation consumes one of the 512 evidence states.
- Names resolve only to earlier closed assignments within the program. Supported expressions are literals, same-type string/bytes/tuple/list addition, builtin numeric addition, constant indexing/slicing, and f-string interpolation of closed values without a format specification.
- The only interpreted call forms are closed str.join(sequence), str.rstrip(optional closed str), and str.join(map(str, closed sequence)). The last form requires separately bound canonical map and str identities. Arbitrary calls, attributes, operators and iteration protocols decline.
- Module statements are docstrings, pass, closed single-name assignments, ordinary function declarations with no decorators and closed defaults, and from __future__ import annotations. Class declarations decline. Function bodies are parsed and compiler-validated but never invoked; body statements are not interpretation-time effects.
- Without a program-owned future-annotations directive, evaluated function annotations must be closed builtin type expressions. A future directive is admitted only at a compiler-valid position. Program validation uses canonical compile mode exec with flags=0 and dont_inherit=True, without executing the resulting code object.
- Writes to __builtins__, exec, eval, compile, open, map, str, globals, locals and __import__ decline. Names and function headers cannot silently replace a required builtin.

### Namespace and provider grammar
- The new witness accepts exec(program, global_dict) and exec(program, global_dict, local_dict) with positional arguments only. Each dictionary must be an unescaped, uniquely assigned fresh {} or dict() allocation, or a canonical builtin globals()/locals() result from the selected caller frame. Other mapping objects, function parameters, keywords and implicit namespace forms decline in this mechanism.
- Namespace allocations must precede the sink; writes to __builtins__, required intrinsic names, escapes or intervening unresolved calls that can access a global namespace decline. Allowed intervening operations are the proven path, open/read and compile chain itself.
- Canonical identity of exec, compile, open, globals, locals, dict, map, str, imported pathlib.Path and imported os.path operations must be re-established from current captured imports, bindings and source-visible provider-mutation evidence. A name match or caller validation flag is insufficient.
- compile inputs require mode='exec', literal flags=0 or omitted flags, and optimize in {-1,0}; explicit dont_inherit=True or a source-proven caller future context containing only annotations is admitted. Other compile flags, modes, inherited future contexts and opaque code objects decline.
- File operations are canonical open/Path.open in r/rt/rb mode, full read() or read(-1), and Path.read_text(). Text decoding requires ASCII-only captured bytes when encoding is implicit, or explicit UTF-8 with strict errors. Default universal-newline translation is recorded; custom openers, unresolved encoding/errors and partial reads decline.
- The selected path must remain within the captured repository root after lexical normalization. Resolution uses no target stat, resolve, open or read operation. Captured symlink-dependent or ambiguous file identities decline.

### Witness and admission
- Required witness fields are schema, disposition, source_path, source_sha256, sink_span, program_source_path, program_source_sha256, effective_program_sha256, origin_edges, compile_profile, namespace_profile, required_builtin_identities, effect_witness, selected_source_hashes, evidence_states, evidence_source_count and target_execution='not_performed'.
- origin_edges bind source spans and operation names for every path, allocation, read, assignment and compile edge. effect_witness binds statement kinds, closed namespace-write identities, required intrinsic identities and the interpreted program hash; it contains no plaintext target values.
- The producer and sealer both derive the witness from bytes. Independent admission compares the complete regenerated row and retains contrary positive security premises. Missing or different evidence rejects the negative decision.

- Reuse captured source indexes, provider-binding guards and existing primitive partitioning.
- Keep origin, effect and namespace observations distinct; none is a caller validation flag.
- Closed path operations cover file-relative parent/dirname, normalization, literal joins and pathlib division; paths outside the captured root and symlink-dependent resolution decline.
- Source reads are interpreted as AST operations against supplied bytes; they never open target paths at verification time.
- Ordinary function bodies are not executed at definition time. Their decorators, defaults and evaluated annotations require separate closed-value checks. Class bodies are not automatically inert.
- Qualification candidates are the four file-backed claims documented in .factory/precision312/dynamic-family-review.json. Their labels or package names must never enter a production decision.
- Report other active claims and additional unlabelled emissions separately. Exposed replay is not fresh held-out evidence.

## SHOULD NOT — Implementation details
- Do not trust a file name, test path, repository reputation, model probability or owner-provided assertion as an effect proof.
- Do not change existing raw priorities, install dependencies, execute target programs or silently broaden a failed proof.

## Decision logic (factory candidates)
| # | if | then |
|---|----|------|
| 1 | PROGRAM_ORIGIN_UNSUPPORTED | retain raw finding and return incomplete |
| 2 | PROGRAM_DECISION_TAMPERED | reject negative witness and retain active finding |
| 3 | PROGRAM_DECISION_REQUESTED | require independent origin, effect and namespace validation |
