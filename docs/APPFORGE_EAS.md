# AppForge EAS handoff

AppForge can validate a **local, candidate-bound EAS handoff** before a human
uses Expo Application Services. It is intentionally a preflight, not an EAS
runner: Code Factory never reads Expo, Apple, or CI credentials; runs an EAS
build; uploads to TestFlight; submits to App Review; or claims approval.

```powershell
factory revenue appforge-eas `
  --root . `
  --candidate .factory/appforge/release-candidate.json `
  --eas-json eas.json `
  --build-profile production `
  --submit-profile production `
  --out .factory/appforge/eas-preflight.json `
  --json
```

The check requires a candidate in
`factory.appforge.release-candidate.v1` format, a named build profile, and a
named `submit.<profile>.ios.ascAppId`. It hashes the local `eas.json` and
candidate, refuses credential-like keys in `eas.json`, and emits either
`APPFORGE_EAS_PREFLIGHT_READY` or an explicit blocker.

Use the receipt only to prepare a safe human handoff: run the reviewed EAS
build from the developer's authenticated environment, inspect the completed
candidate, then separately authorize any EAS submit or App Store Connect
action. EAS itself documents separate build and submission flows; its
non-interactive workflows depend on credentials maintained outside this
preflight. See the official [EAS CLI](https://docs.expo.dev/eas/cli/) and
[iOS submission](https://docs.expo.dev/submit/ios/) guidance.

The Graph/AppForge status projection shows only hash-valid local packets. It
does not display credentials or provider state.
