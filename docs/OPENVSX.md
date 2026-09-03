# Open VSX release lane

Code Factory’s VS Code extension can be distributed through the
[Open VSX Registry](https://open-vsx.org/) in addition to its existing editor
surfaces. This repository contains a guarded, manual release workflow at
`.github/workflows/openvsx.yml`.

## Current status

FactoryLine is published in Open VSX under the `zrk222` namespace. The registry
showed 144 downloads on 2026-08-21, but also displayed **publisher not verified
for namespace**. That warning is a provider trust gap, not a package-test result.

The official ownership request is now open as
[EclipseFdn/open-vsx.org #12688](https://github.com/EclipseFdn/open-vsx.org/issues/12688).
The claim supplies the Open VSX listing, matching Visual Studio Marketplace
publisher, repository metadata, and public identity history. Per the official
[Namespace Access](https://github.com/eclipse-openvsx/openvsx/wiki/Namespace-Access)
process, the warning remains externally pending until an Eclipse administrator
grants namespace ownership. Code Factory must not describe the namespace as
verified before that provider action occurs.

## Publish a verified extension

1. Create or confirm the `zrk222` Open VSX publisher namespace outside this
   repository, then store a least-privilege `OPENVSX_TOKEN` in the protected
   `openvsx` GitHub environment.
2. Start **Publish Open VSX extension** manually and supply an existing,
   immutable repository tag such as `v0.46.0` for the 0.9.0 FactoryLine adapter.
3. Leave `publish` false to produce and retain only the verified VSIX candidate,
   SHA-256 manifest, audit result, and tests.
4. Set `publish` true only after the environment reviewer approves the target
   tag and package. The workflow rechecks the candidate SHA-256 immediately
   before it calls the pinned `ovsx@1.1.0` publisher.

The workflow refuses a branch, a non-version tag, a tag that does not resolve
to its checked-out commit, a missing token, an untested extension, or a
modified candidate. It does not create namespaces, secrets, or credentials.
