# Release reliability

Before dispatching a release or marketplace workflow, inspect the declared
local safety boundaries:

```powershell
factory release integrity --root . --json
```

The command is read-only. It verifies that release validation is partitioned
into independent Python, VS Code, and JetBrains jobs; that publication fans in
their separately sealed artifacts; that PyPI still uses protected OIDC; that
Open VSX authorizes protected publication before candidate work; and that the
JetBrains pending-update guard occurs before Java or Gradle setup.

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

The release workflow validates Python, VS Code, and JetBrains artifacts in
parallel. Publication starts only after all three jobs have passed and their
artifacts have been downloaded into the immutable release bundle.
