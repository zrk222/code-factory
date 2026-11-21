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
short_description: Audit code, review evidence, and resolve defects.
---

# Code Factory

Build a scoped change. Inspect its evidence. Keep the release decision with people.

**[Open the preview](https://huggingface.co/spaces/zrk222/code-factory)** ·
[Source](https://github.com/zrk222/code-factory) ·
[Released core 0.49.7](https://github.com/zrk222/code-factory/releases/tag/v0.49.7)

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
python -m pip install factoryline-code-factory==0.49.7
factory first-proof --root .
```

First Proof uses a generated sandbox to check the demonstration, not your repository. Define your own scope, policy and checks before relying on a repository audit.

## Versions and limits

Core 0.49.7 is the released baseline reviewed here. Core 0.50.0 and plugins 1.3.6 are publication targets after PR 354 merges, not a claim of current availability.

The Proof Agent runs a human-approved signed plan and records evidence. It does not approve its result. Signed-observation checks verify a recorded binding, not code correctness or release readiness. Local tests do not establish live provider support or marketplace availability.

Audit depth depends on language, policy and supplied evidence. The security scanner inspects Python ASTs; static inventory is not runtime proof. This static preview does not scan or upload your repository. Missing evidence stays incomplete.

## Go deeper

- [PR 354 source and review](https://github.com/zrk222/code-factory/pull/354)
- [Client setup and boundaries](https://github.com/zrk222/code-factory/blob/codex/coordinator-crash-controls-20261120/docs/AI_CLIENTS.md)
- [CodeRabbit handoff](https://github.com/zrk222/code-factory/blob/codex/coordinator-crash-controls-20261120/docs/CODERABBIT_INTEROP.md)
- [Teams operations manual](https://github.com/zrk222/code-factory/blob/main/docs/ENTERPRISE_TEAMS_OPERATIONS.md)
- [PyPI package](https://pypi.org/project/factoryline-code-factory/0.49.7/)
- [Zenodo collection](https://doi.org/10.5281/zenodo.21381405)
