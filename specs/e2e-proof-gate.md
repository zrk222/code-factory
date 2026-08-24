# Spec: E2E Proof Gate

Status: approved

## Intent

Provide a native Code Factory gate that runs a human-approved local E2E
positive command and a declared negative mutation command.  A passing positive
run is insufficient: the negative command must fail.  This creates direct
evidence that the declared E2E check can say no, without a vendor runner,
provider account, cloud browser, credential, upload, or external API.

## MUST — Functional core

### Data model

`factory.e2e_proof_manifest.v1` has these normalized facts:

| Fact | Allowed value | Purpose |
|---|---|---|
| `approval_state` | `approved` | authorizes the exact local command pair |
| `approved_by` | named human | identifies the command-pair approver |
| `positive_argv` | non-empty argv array | command expected to exit zero |
| `negative_argv` | non-empty argv array | deliberate mutation check expected to exit non-zero |
| `working_directory` | workspace-relative directory | process working directory |
| `timeout_seconds` | integer from 1 through 900 | per-command execution limit |
| `argv_item_count` | at most 64 | bounded command surface |
| `argv_item_length` | at most 4096 characters | bounded command surface |
| `named_approval_length` | at most 128 characters | bounded approval identity |
| `network_egress` | `not_granted` | declared no-egress contract; not host enforcement |
| `artifact_paths` | zero or more workspace-relative files | optional artifacts hashed after both commands |
| `run_state` | `manifest_invalid`, `positive_timeout`, `positive_nonzero`, `negative_timeout`, `negative_zero`, `artifact_missing`, `proof_pass` | derived terminal state |
| `receipt_marker` | `E2E_MANIFEST_INVALID`, `E2E_POSITIVE_TIMEOUT`, `E2E_POSITIVE_FAILED`, `E2E_NEGATIVE_TIMEOUT`, `HOLLOW_E2E_TEST`, `E2E_ARTIFACT_MISSING`, `E2E_PROOF_PASS` | emitted result marker |

Implementation and smoke data are UTF-8 encoded. Public proof-packet filenames
use a 12-character prefix of the canonical receipt SHA-256. The reverse-classical
smoke fixture uses a 10-second per-command timeout within the required 1-through-900-second range.

### Requirements (EARS)

- The system shall validate `REQ_E2E_MANIFEST` and accept only a `factory.e2e_proof_manifest.v1` JSON object
  with exact allowed fields, a named approval, argv arrays, a 1-through-900
  second timeout, no more than 64 argv items of at most 4096 characters each,
  a named approval of at most 128 characters, workspace-relative paths, and
  `network_egress: not_granted`.
- When `REQ_E2E_EXECUTION` starts, the system shall emit stdout and stderr capture files after running both argv arrays with `shell=False`, the approved working directory, and a 900-second command duration.
- When `REQ_E2E_POSITIVE_FAILURE` is true and `run_state` is `positive_nonzero`, the system shall emit a non-passing
  receipt with `receipt_marker` equal to `E2E_POSITIVE_FAILED`.
- When `REQ_E2E_HOLLOW_FAILURE` is true and `run_state` is `negative_zero`, the system shall emit a non-passing
  receipt with `receipt_marker` equal to `HOLLOW_E2E_TEST`.
- When `REQ_E2E_POSITIVE_TIMEOUT` is true and `run_state` is `positive_timeout` after the declared 1-through-900-second duration, the system shall emit a non-passing receipt with `receipt_marker` equal to `E2E_POSITIVE_TIMEOUT`.
- When `REQ_E2E_NEGATIVE_TIMEOUT` is true and `run_state` is `negative_timeout` after the declared 1-through-900-second duration, the system shall emit a non-passing receipt with `receipt_marker` equal to `E2E_NEGATIVE_TIMEOUT`.
- When `REQ_E2E_ARTIFACT_FAILURE` is true and `run_state` is `artifact_missing`, the system shall emit a non-passing
  receipt with `receipt_marker` equal to `E2E_ARTIFACT_MISSING`.
- When `REQ_E2E_PROOF_PASS` is true and `run_state` is `proof_pass`, the system shall emit a passing receipt
  whose conclusion is limited to the declared command pair and captured output
  digests.
- When `REQ_E2E_MANIFEST_REJECT` is true and `run_state` is `manifest_invalid`, the system shall return an input
  error before running either command or writing a receipt.
- When `--out-dir` is supplied, the system shall write only a canonical (REQ_E2E_ARTIFACT_OUTPUT)
  receipt, a Markdown summary, a Mermaid map, and captured command outputs
  below that explicit directory.

### Acceptance criteria

```gherkin
Scenario: Prove an E2E check can reject a declared mutation
  Given an approved manifest with positive and negative argv commands
  And `factory.e2e_proof_manifest.v1`
  And REQ_E2E_MANIFEST
  And `shell=False`
  And REQ_E2E_EXECUTION
  And the positive command exits zero
  And the negative mutation command exits non-zero
  When factory e2e verify runs
  Then it emits an E2E_PROOF_PASS receipt with hashes of captured outputs
  And REQ_E2E_POSITIVE_FAILURE
  And REQ_E2E_HOLLOW_FAILURE
  And REQ_E2E_POSITIVE_TIMEOUT
  And REQ_E2E_NEGATIVE_TIMEOUT
  And REQ_E2E_ARTIFACT_FAILURE
  And REQ_E2E_PROOF_PASS
  And REQ_E2E_MANIFEST_REJECT
  And REQ_E2E_ARTIFACT_OUTPUT
  And `positive_nonzero`
  And `negative_zero`
  And `positive_timeout`
  And `negative_timeout`
  And `artifact_missing`
  And `proof_pass`
  And `manifest_invalid`
  And `--out-dir`
  And the receipt does not claim browser isolation, network enforcement, release readiness, or production quality

Scenario: Refuse a hollow E2E check
  Given an approved manifest whose negative mutation command exits zero
  When factory e2e verify runs
  Then it emits a HOLLOW_E2E_TEST receipt
  And the command-pair receipt is non-passing
```

## SHOULD — Structural contract

- New module: `factoryline/e2e_proof.py`.
- Public command: `factory e2e verify --root workspace --manifest e2e-proof.json`.
- Unit tests: `tests/test_e2e_proof.py`.
- User contract: `docs/E2E_PROOF_GATE.md`.
- Governance classification: human controlled.  A named human authorizes each
  arbitrary local command pair; validation does not turn that authority into a
  merge, release, deployment, signing, or publication grant.

## Non-goals

- No TestMu, Kane, cloud-browser, device-grid, provider process, remote API,
  credential, external upload, code generation, or automatic healing.
- No sandbox, browser isolation, host network enforcement, or evidence that an
  arbitrary production user journey was covered.
- No merge, publish, deployment, signing, approval, credential, connector, or
  external-message authority.

## Decision logic

| # | if | then |
|---|----|------|
| 1 | `run_state` is `manifest_invalid` | return input error before command execution |
| 2 | `run_state` is `positive_timeout` | emit `E2E_POSITIVE_TIMEOUT` non-passing receipt |
| 3 | `run_state` is `positive_nonzero` | emit `E2E_POSITIVE_FAILED` non-passing receipt |
| 4 | `run_state` is `negative_timeout` | emit `E2E_NEGATIVE_TIMEOUT` non-passing receipt |
| 5 | `run_state` is `negative_zero` | emit `HOLLOW_E2E_TEST` non-passing receipt |
| 6 | `run_state` is `artifact_missing` | emit `E2E_ARTIFACT_MISSING` non-passing receipt |
| 7 | `run_state` is `proof_pass` | emit `E2E_PROOF_PASS` limited receipt |
