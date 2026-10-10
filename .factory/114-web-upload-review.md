# VS Code website-upload authorization review

Reviewed the current two-file diff in `.github/workflows/vscode-marketplace.yml` and `tests/test_release_integrity.py`.

For `web_upload=true`, the workflow still enters the `vscode-marketplace` protected environment, while the PAT check is conditional on CLI publication mode (`web_upload != true`). The website-upload authorization step runs only for `web_upload=true` and records the protected approval without reading or requiring `VSCE_PAT`. The validate job still depends on both `authorize` and `attested-source`, and for `publish=true` still requires successful authorization before candidate validation proceeds. The publish job remains conditioned on `inputs.web_upload != true`, so website-upload mode cannot invoke CLI publication. Immutable source/tag checks and candidate validation were not changed by this diff.

The integrity test asserts the default is website-upload mode, the protected environment is unchanged, credential and website steps have disjoint conditions, and validation depends on successful authorization. Workflow YAML parsing succeeded (`yaml.safe_load`).

No release-gate weakening found in this bounded diff. The website-upload step records workflow authorization; it does not prove a provider-side upload or publication.
