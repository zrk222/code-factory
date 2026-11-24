# Plan: full-stack-ux-harness-v1
Spec: specs/full-stack-ux-harness-v1.md
Architect verdict: PASS

## Logical decomposition (phases)

1. Compile the attachment into a bounded contract and evidence verifier.
2. Make the reusable skill discoverable to agents and IDE/A2A workflows.
3. Add adversarial tests and validate package/repository integrity.

## Tasks (atomic - each independently shippable)

- [x] T1 | slice=factoryline | files=<=3 | verify=`python -m pytest -q tests/test_full_stack_ux_harness.py` | Add the manifest template, fail-closed evaluator, and CLI route.
- [x] T2 | slice=skills | files=<=4 | verify=`python C:/Users/rkatz/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/full-stack-ux-harness` | Add the repository-owned skill, concise operator guide, and IDE playbook trigger.
- [x] T3 | slice=integration | files=<=4 | verify=`python -m pytest -q tests/test_full_stack_ux_harness.py tests/test_adoption_guide.py tests/test_publication_metadata.py` | Route frontend changes through the harness and prove packaging plus existing metadata remain valid.
- [ ] T4 | slice=visual-core | files=<=3 | verify=`py -3.11 -m pytest -q tests/test_full_stack_ux_harness.py` | Add the admitted visual worker, actual pixel and state checks, and Prestige token reuse in the existing harness.
- [ ] T5 | slice=visual-cli | files=<=3 | verify=`py -3.11 -m pytest -q tests/test_full_stack_ux_harness.py tests/test_cli_bootstrap.py` | Expose visual execution and receipt replay through the existing lazy CLI and quality evidence path.
- [ ] T6 | slice=visual-proof | files=<=5 | verify=`py -3.11 -m pytest -q tests/test_full_stack_ux_harness.py tests/test_full_stack_ux_spec.py` | Prove real local-browser negative controls, unchanged legacy checks, current source bindings and explicit missing-tool behavior.
- [ ] T7 | slice=release | files=<=3 | verify=`py -3.11 -m pytest -q tests/test_publication_metadata.py tests/test_adoption_guide.py` | Include the optical and Prestige evidence workflow with all Claude and Codex repairs in0.50.0 and1.3.6 previews; publication remains gated.

### Exact change ownership and checkpoints

- T4 modifies only factoryline/full_stack_ux_harness.py: strict pinned admission,
  fixed same-module `_visual_child` invocation, browser measurements, Prestige
  public token API reuse and current-byte replay. Checkpoint: public signatures
  compile, legacy tests pass, NOT_RUN launches nothing and invalid contracts reject.
- T5 modifies factoryline/cli_quality.py and the existing verify_quality_harness
  function only: explicit visual subcommand and optional --visual-receipt. No
  cli.py eager import or MCP mutation tool. Checkpoint: both actual module CLI
  and parser tests, no implicit capture from legacy verify.
- T4 also owns factoryline/full_stack_ux_spec.py and the existing feature spec;
  T5 owns the envelope envelopes/full-stack-ux-harness-v1.json, whose seal uses
  normalized LF specification text after approved contract edits.
- T6 modifies tests/test_full_stack_ux_harness.py, smoke/full-stack-ux-harness-v1.json,
  tests/test_full_stack_ux_spec.py and full-stack-ux-harness-v1.ssat.yaml.
  Checkpoint: full focused suite, actual Chromium positive and negative
  controls, cleanup/privacy tests, SpecLine drift and Forge smoke/stub challenge.
- T7 modifies CHANGELOG.md, README.md and docs/RELEASE_CHANNELS.md to summarize
  measured visual/Prestige functionality and outstanding target limits. Existing
  release tooling builds the Python package from the same module and the
  already-versioned1.3.6 editor/Devin adapters; no new package/dependency/manifest.
  Checkpoint: public metadata tests, wheel consumer proof, exact final release
  scope includes Claude branches and Codex changes. No publication from a
  partial candidate. Existing context/PROGRESS.md is workflow-managed history,
  not another public implementation document or authority source.
