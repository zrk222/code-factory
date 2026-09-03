# AppForge Device Reality Gate

The Device Reality Gate turns a supervised physical-device walkthrough into a
hash-bound local receipt. It exists to catch a common false positive: a
desktop storyboard, simulator result, or agent narrative is presented as if it
proved the exact mobile candidate behaved correctly on a real device.

It is intentionally narrow. It validates supplied artifact hashes and their
binding to one sealed intent envelope; it does not operate an iPhone or iPad,
run Phone Harness, inspect pixels, access test-account credentials, upload a
build, contact Apple, or promise approval.

## Proof path

```text
sealed Oracle intent + policy sources
  -> named human reviewer
  -> Device Reality intent envelope
  -> approved candidate + user-design-input hash
  -> required journey + forbidden outcome
  -> human-supervised capture metadata + artifact SHA-256
  -> local receipt or explicit blocker
```

Only human-confirmed or trusted-source Oracle rules can supply blocking
obligations to the envelope. A capture worker cannot relax a forbidden outcome,
replace an approved journey, change the candidate, or select a new transport
without producing a different envelope that must go through the normal human
Oracle approval path.

## Create the envelope

First create a current AppForge Oracle Authority receipt from a sealed Oracle
contract. Then complete the generated `device-reality-journeys.json` with
human-confirmed outcomes and negatives—placeholder values are deliberately
invalid.

```powershell
factory revenue device-reality-intent --root . `
  --oracle-authority .factory/appforge/oracle-authority.json `
  --design-input .factory/appforge/user-design-input.md `
  --journeys .factory/appforge/evidence/device-reality-journeys.json `
  --transport manual_physical_device `
  --transport phone_harness `
  --out .factory/appforge/device-reality-intent.json --json
```

`phone_harness` is a declared, user-authorized capture transport only. It is
not an authority source and Code Factory does not invoke it. The human remains
responsible for the physical device, account privacy, OS prompts, and the
meaning of what they observe.

## Verify supplied evidence

The evidence names the exact envelope hash, candidate, reviewed design-input
hash, named envelope approver, authorized transport, and one artifact per
sealed journey. Each artifact must remain inside the workspace and match its
SHA-256.

```powershell
factory revenue device-reality-gate --root . `
  --intent-envelope .factory/appforge/device-reality-intent.json `
  --evidence .factory/appforge/device-reality-evidence.json `
  --out .factory/appforge/device-reality.json --json
```

The receipt is `APPFORGE_DEVICE_REALITY_READY` only when every sealed journey
has exactly one hash-valid, human-supervised passing observation. Candidate,
design, envelope, transport, capture, and supervision mismatches fail closed.

## What this does not prove

This gate is not Apple policy certification, semantic screenshot analysis,
hardware compatibility proof, TestFlight completion, App Store Connect state,
App Review submission, or approval. A ready receipt means only that the
specified local evidence stayed bound to the specified sealed intent.
