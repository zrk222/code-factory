# AppForge Fastlane Capture Contract

AppForge can now prepare a **capture-only Fastlane Snapshot contract**. It
connects the exact release candidate to the reviewed device-family matrix and
truthful storefront scenes before anyone opens Xcode.

## What it checks locally

- one candidate across the Surface Matrix, Storefront Story, and capture plan;
- one Fastlane `snapshot("name")` per reviewed storefront scene;
- an iPhone and 13-inch iPad in the Snapfile, plus English locale, a shared
  scheme, clean output directory, status-bar override, first-error stop, and
  prior-output clearing;
- a capture-only Fastfile lane—no signing, upload, delivery, TestFlight, or
  App Review action;
- local source hashes and credential-like key rejection; and
- raw-only versus reviewed Framefile posture.

```powershell
py -3 -m factoryline.cli revenue appforge-fastlane-capture `
  --root . `
  --candidate candidate.json `
  --surface-matrix .factory/appforge/surface-matrix.json `
  --storefront-story .factory/appforge/storefront-story.json `
  --contract fastlane-capture-contract.json `
  --out .factory/appforge/fastlane-capture.json --json
```

## Windows boundary

The contract, CLI, receipts, Graph Ops, and MCP readback run locally on
Windows. Fastlane Snapshot itself drives XCUITest and therefore needs a
separately authorized macOS/Xcode environment. AppForge never substitutes a
Windows emulator or CI artifact for real iOS capture evidence.

After a separately authorized capture run, hash and review the raw output with
Store Media and Device Reality. Frames are presentation only; they cannot prove
what an app does or justify a factual Store claim.

The contract never runs Fastlane/Xcode, controls a simulator or device, reads
credentials, generates images, uploads media, contacts Apple, or submits a
release.
