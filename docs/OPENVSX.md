# Open VSX release lane

Code Factory’s VS Code extension can be distributed through the
[Open VSX Registry](https://open-vsx.org/) in addition to its existing editor
surfaces. This repository contains a guarded, manual release workflow at
`.github/workflows/openvsx.yml`.

## Current status

The release lane is prepared but **not published**. It intentionally has no
stored token in source control, and publication needs a scoped
`OPENVSX_TOKEN` in GitHub’s protected `openvsx` environment. A VSIX package or
workflow is not evidence of an available marketplace listing.

## Publish a verified extension

1. Create or confirm the `zrk222` Open VSX publisher namespace outside this
   repository, then store a least-privilege `OPENVSX_TOKEN` in the protected
   `openvsx` GitHub environment.
2. Start **Publish Open VSX extension** manually and supply an existing,
   immutable repository tag such as `v0.24.2`.
3. Leave `publish` false to produce and retain only the verified VSIX candidate,
   SHA-256 manifest, audit result, and tests.
4. Set `publish` true only after the environment reviewer approves the target
   tag and package. The workflow rechecks the candidate SHA-256 immediately
   before it calls the pinned `ovsx@1.1.0` publisher.

The workflow refuses a branch, a non-version tag, a tag that does not resolve
to its checked-out commit, a missing token, an untested extension, or a
modified candidate. It does not create namespaces, secrets, or credentials.
