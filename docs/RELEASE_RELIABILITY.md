# Release reliability

Before dispatching a release or marketplace workflow, inspect the declared
local safety boundaries:

```powershell
factory release integrity --root . --json
```

The command is read-only. It verifies that release validation is partitioned
into independent Python, VS Code, and JetBrains jobs; that publication fans in
their separately sealed artifacts; that PyPI still uses protected OIDC; that
Open VSX and Visual Studio Marketplace authorize protected publication before
candidate work; that JetBrains credential admission and its pending-update guard
occur before Java or Gradle setup; and that Hugging Face admission occurs before
Space checkout or upload tooling.

It also checks that the IntelliJ adapter uses supported choice dialogs and the
Kotlin JVM-default configuration that avoids synthetic internal-API bridges.
The Hugging Face workflow validates the Space card before it installs a client
or attempts an upload, including the service's 60-character description limit.
Python wheel data is explicitly declared rather than inferred from source
directories, keeping packaging behavior and build output deterministic.

It cannot inspect or create credentials, approve a Marketplace update, dispatch
a workflow, publish an artifact, or alter a release. Those remain external,
human-controlled gates:

- Open VSX needs `OPENVSX_TOKEN` configured in the protected `openvsx`
  environment. With `publish: true`, the workflow fails before candidate
  packaging if that token is absent.
- JetBrains Marketplace must clear its pending prior update before the workflow
  builds a new candidate. This protects listing order; it is not a repository
  defect that source code can bypass.
- Hugging Face Space publication needs the configured `HF_TOKEN` GitHub Actions
  secret. The workflow stops before checkout when it is absent; static source
  inspection cannot prove that a secret exists or that a Space is reachable.

The release workflow validates Python, VS Code, and JetBrains artifacts in
parallel. Publication starts only after all three jobs have passed and their
artifacts have been downloaded into the immutable release bundle.
