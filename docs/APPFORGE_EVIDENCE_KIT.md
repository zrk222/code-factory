# AppForge evidence kit

The AppForge evidence kit is the novice-friendly start to an iOS submission
review. Give it one exact release candidate and the user-approved design input.
It creates candidate-bound contracts, intentionally incomplete evidence
templates, and a worklist. It never turns placeholders into a pass.

For a first-time project, start with `appforge-init`. It records the user’s
mission and candidate once, then writes the `release-candidate.json` and
`user-design-input.md` consumed by this kit. Omit `--source-commit` in a clean
git checkout to record `HEAD` (the receipt then says `source_commit_derived: true`);
an explicit value must be the full 40-character SHA and is checked before
anything is written:

```powershell
factory revenue appforge-init --root . --out-dir .factory/appforge/init-42 `
  --app-name "My app" --bundle-identifier com.example.app --version 2.4.0 `
  --build-number 42 --source-commit <40-character-commit-sha> --audience "Who it serves" `
  --primary-job "What they need to do" --desired-emotion "How it should feel" --json
```

```powershell
factory revenue evidence-kit --root . `
  --candidate .factory/appforge/init-42/release-candidate.json `
  --design-input .factory/appforge/init-42/user-design-input.md `
  --out-dir .factory/appforge/ios-2.4.0-42 `
  --json
```

`release-candidate.json` must be:

```json
{
  "schema": "factory.appforge.release-candidate.v1",
  "candidate": {
    "bundle_identifier": "com.example.app",
    "version": "2.4.0",
    "build_number": "42",
    "source_commit": "40-character-commit-sha"
  }
}
```

The kit asks for ten distinct iPhone journeys and three distinct 13-inch iPad
journeys. That is an AppForge product-quality bundle designed to make the
submission story easy to review; it is not a claim about Apple’s global
minimum screenshot count. The final dossier still requires all four real,
hash-valid gate receipts for the same candidate.

See [Submission Assurance](APPFORGE_SUBMISSION_ASSURANCE.md) for the final
Markdown/PDF dossier command and its strict authority boundary.
