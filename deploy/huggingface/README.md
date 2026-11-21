---
title: Code Factory
emoji: 🏭
colorFrom: yellow
colorTo: gray
sdk: static
app_file: index.html
thumbnail: https://raw.githubusercontent.com/zrk222/code-factory/main/docs/assets/github-social-preview-1280x640.png
tags:
  - developer-tools
  - ai-agents
  - devops
  - software-quality
  - design-review
  - ui-quality
  - mcp
  - model-context-protocol
  - cursor
  - opencode
  - local-first
pinned: false
license: apache-2.0
short_description: Polyglot code evidence for AI-assisted teams.
---

# Code Factory

Your AI writes the change. Code Factory shows what was actually checked.
The 0.50.0 release line brings 12-language native security rules, SARIF review
and bounded agent proof into one local-first evidence workflow.

**[Open the preview](https://huggingface.co/spaces/zrk222/code-factory)** ·
[Source](https://github.com/zrk222/code-factory) ·
[Release availability](https://github.com/zrk222/code-factory/releases)

## What's bigger in 0.50.0

- **Polyglot teams:** 30 native rules cover C, C++, C#, Go, Java, JavaScript,
  PHP, Python, Ruby, Rust, Swift and TypeScript through a configured worker.
- **Less review guesswork:** source-bound traces, byte-exact mutation diffs,
  signed-observation checks and explicit missing evidence.
- **Fits existing work:** frozen JSON, SARIF 2.1.0, opt-in pre-commit and a
  read-only eight-tool Devin plugin, alongside VS Code and JetBrains 1.3.6.
- **Measured default-tier precision:** 54 TP / 6 FP / 0 unclear across 60 alerts
  = **90%** (Wilson 95% **79.9–95.3%**). This panel used AI labels and covered
  **six observed languages**, with 15 shortfall fills. It is not twelve-language
  precision, review-tier precision, recall or independent human validation.

[Results and limits](https://github.com/zrk222/code-factory/pull/354).

## Watch the workflow

- **WMM build story, 57 seconds.** How Code Factory helped assemble a real product. Screens use example data; this is not a customer case or certification.
- **Proof-layer how-to, 1:45.** Approved inputs, proof-plan execution and receipt inspection using PR 354 source. Command templates and reformatted local fixture results, not a screen recording or live Devin session.

Both videos are embedded in the preview.

## From requirement to review

| Step | What it provides |
| --- | --- |
| SpecLine | Requirements and acceptance checks |
| ForgeLine | Scoped changes and challenged checks |
| FactoryLine | Recorded evidence, visible gaps and human review |

CodeRabbit can consume completed neutral GitHub Check output when configured. PR 354 adds a bounded, read-only Devin evidence profile. Other tools can hand off repository work for local CLI review; native Blitzy or Mastra integration is not claimed.

## Try a local check

```sh
python -m pip install factoryline-code-factory==0.50.0
factory first-proof --root .
```

First Proof uses a generated sandbox to check the demonstration, not your repository. Define your own scope, policy and checks before relying on a repository audit.

## Versions and limits

Core 0.50.0 and plugins 1.3.6 are the prepared release line. Publication and
marketplace moderation are verified per channel; preparation is not availability.
The install example targets that release and requires its PyPI publication.

The Proof Agent runs a human-approved signed plan and records evidence. It does not approve its result. Signed-observation checks verify a recorded binding, not code correctness or release readiness. Local tests do not establish live provider support or marketplace availability.

Audit depth depends on language, policy and supplied evidence. The security scanner inspects Python ASTs; static inventory is not runtime proof. This static preview does not scan or upload your repository. Missing evidence stays incomplete.

## Go deeper

- [PR 354 source and review](https://github.com/zrk222/code-factory/pull/354)
- [Client setup and boundaries](https://github.com/zrk222/code-factory/blob/codex/coordinator-crash-controls-20261120/docs/AI_CLIENTS.md)
- [CodeRabbit handoff](https://github.com/zrk222/code-factory/blob/codex/coordinator-crash-controls-20261120/docs/CODERABBIT_INTEROP.md)
- [Teams operations manual](https://github.com/zrk222/code-factory/blob/main/docs/ENTERPRISE_TEAMS_OPERATIONS.md)
- [PyPI package](https://pypi.org/project/factoryline-code-factory/0.50.0/)
- [GitHub release](https://github.com/zrk222/code-factory/releases/tag/v0.50.0)
- [Zenodo collection](https://doi.org/10.5281/zenodo.21381405)
