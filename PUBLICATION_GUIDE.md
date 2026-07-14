# Code Factory Publication Guide

This is the public release playbook for the five-repo Code Factory set. Publish
the baseplate first, then the numbered bricks in order.

## Repo Order

```mermaid
flowchart LR
    A["code-factory<br/>baseplate"] --> B["1 spec<br/>SpecLine"]
    B --> C["2 forge<br/>ForgeLine"]
    C --> D["3 compile<br/>HSF"]
    C --> E["4 design<br/>Prestige"]
    D --> F["Receipts, badges, releases"]
    E --> F
    F --> V["VS Code VSIX\nand JetBrains ZIP"]
    classDef base fill:#e0f2fe,stroke:#0284c7,color:#10233f
    classDef brick fill:#fef3c7,stroke:#d97706,color:#10233f
    classDef proof fill:#dcfce7,stroke:#16a34a,color:#10233f
    classDef adapter fill:#ede9fe,stroke:#7c3aed,color:#10233f
    class A base
    class B,C,D,E brick
    class F proof
    class V adapter
```

1. `code-factory`: the baseplate and public map of the ecosystem.
2. `code-factory-1-spec`: turns intent into strict specs and task packets.
3. `code-factory-2-forge`: runs the gated build state machine.
4. `code-factory-3-compile`: compiles decision workflows into deterministic Python.
5. `code-factory-4-design`: audits and improves public UI quality.

## GitHub Publish Steps

Run this inside each repo after creating an empty public GitHub repository:

```bash
git init
git add .
git commit -m "Initial public release"
git branch -M main
git remote add origin https://github.com/YOUR_ORG/REPO_NAME.git
git push -u origin main
```

Recommended GitHub topics:

```text
llm, ai-agents, prompt-injection, deterministic, workflow-engine,
software-factory, ci, python, codex, claude-code
```

Enable Issues and Discussions. Pin an issue titled `Share your spec` so users
can contribute workflow examples.

## Install And Use

```bash
pip install factoryline-code-factory==0.13.1 code-factory-1-spec==0.5.3 code-factory-2-forge==0.10.4 code-factory-3-compile==0.5.4 code-factory-4-design==0.7.3

factory doctor
factory plan
factory init .
factory assemble my_feature
factory meter
```

## PyPI Trusted Publishing

This repo currently publishes through an encrypted repository-scoped
`PYPI_TOKEN` GitHub Actions secret. The workflow is
`.github/workflows/publish.yml`; a published GitHub release builds the
wheel/sdist, checks them with Twine, attaches them to the GitHub release, and
publishes only after those checks pass.

The planned hardening is PyPI Trusted Publishing: after the publisher is
configured, remove the `PYPI_TOKEN` secret and the action credentials so PyPI
uses short-lived GitHub OIDC credentials instead of a stored token.

The encrypted secret protects the token at rest, but does not make it
short-lived or non-replayable after it reaches a release runner. Keep it
project-scoped, treat it as an interim fallback, and do not describe this path
as supply-chain provenance. Trusted Publishing is the path that removes the
stored-token replay surface.

For a brand-new PyPI project, create a pending publisher on pypi.org before
publishing the first release:

```text
PyPI project name : factoryline-code-factory
Owner             : zrk222
Repository name   : code-factory
Workflow name     : publish.yml
Environment name  : pypi
```

Then publish a GitHub release from a version tag such as `v0.3.0`. The first
successful publish creates the PyPI project and converts the pending publisher
into the normal publisher for future releases.

Useful checks before release:

```bash
python -m pytest -q
python -m build
python -m twine check dist/*
pip install dist/code_factory-*.whl
factory --help
```

## Claude Code And Codex

Use SpecLine to write agent instructions into the repo:

```bash
specline agent claude
specline agent codex
```

Claude Code reads the generated `CLAUDE.md`. Codex reads the generated or
updated `AGENTS.md`. After that, ask the agent to follow the Code Factory flow:

```text
Use SpecLine for the spec, ForgeLine for the build loop, HSF for deterministic
decision logic, and Prestige for public UI changes. Run the gates and report
the receipts before calling the work done.
```

For global Codex use on one machine, install the corresponding Codex skill under
your Codex skills directory and add the same policy to the global `AGENTS.md`.
Keep repository-local instructions in the public repos so contributors get the
same workflow without needing your private setup.

## Why This Saves Time And Money

Code Factory saves time by catching expensive failures earlier:

- Atomic Knowledge Units activate dense institutional guidance at the point of
  work, reducing the senior-engineer correction tax.
- SpecLine rejects ambiguity before an agent writes drifting code.
- ForgeLine forces architecture, implementation, review, runtime smoke, and
  promotion through repeatable gates.
- HSF compiles recurring decision logic into static Python, so each future run
  avoids a model call.
- Prestige catches public UI trust and conversion problems before release.
- Receipts replace hand-copied claims, so CI proves the project on every push.

The money story should stay evidence-owned: use `factory meter`, HSF receipts,
and generated badges instead of manually typing savings claims.

## Launch Links

- Hacker News Show HN: <https://news.ycombinator.com/show>
- Lobste.rs: <https://lobste.rs/>
- PyPI publishing: <https://pypi.org/>
- Zenodo new upload: <https://zenodo.org/deposit>
- Reddit r/Python: <https://www.reddit.com/r/Python/>
- Reddit r/LLMDevs: <https://www.reddit.com/r/LLMDevs/>
- Reddit r/AI_Agents: <https://www.reddit.com/r/AI_Agents/>
- Reddit r/programming: <https://www.reddit.com/r/programming/>

Suggested Show HN title:

```text
Show HN: A factory that compiles LLM workflows into deterministic, gated Python
```

Lead with the injection demo for the compile repo:

```text
Prompt injection cannot reach code that has no prompt.
```

Enterprise angle:

```text
The factory turns private engineering knowledge into Atomic Knowledge Units:
small, validated skills with tools, governance, continuations, and receipts.
```

## Release Checklist

Before pushing each repo:

```bash
python -m pytest -q
python -m build
```

Then remove generated local artifacts before committing:

```text
build/
dist/
*.egg-info/
__pycache__/
.pytest_cache/
```

After publishing:

1. Add the demo GIF near the top of the compile repo README.
2. Confirm PyPI published successfully so `pip install factoryline-code-factory` works.
3. Create GitHub releases for all five repos.
4. Create a Zenodo record for the architecture/release artifact.
5. Post the Show HN only after all install links and CI badges work.
