# Code Factory 0.28.0

Code Factory 0.28.0 extends the proof-first workflow into three supervised
developer controls:

- **Proof Review** turns the current diff into an attention-first local review
  with JSON, Markdown, and Mermaid handoff artifacts.
- **Verified Repair Sandbox** seals one native Change List and checks candidate
  patch scope and measured bytes before a developer hands the packet to an
  independent verifier.
- **Workspace Load Advisor** reports bounded project-shape and remote/WSL
  preflight facts before a developer considers a workspace change.

The controls are intentionally conservative. They do not edit code, call an AI
runner, run tests, commit, publish, access credentials, upload source, or claim
runtime sandboxing, IDE performance improvement, or production readiness. The
existing Verifier Plane remains the independent-evidence contract.

## Install

```powershell
pip install factoryline-code-factory==0.28.0
```

The release also includes the VS Code VSIX and FactoryLine JetBrains plugin
ZIP. Marketplace moderation and publisher-token lanes are reported separately
from the immutable GitHub release.
