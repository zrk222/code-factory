# Code Factory

Review agent-written code, trace findings to their source, and record which
checks support your decision.

**Core 0.49.7 · Editor packages 1.3.5**

[Release downloads](https://github.com/zrk222/code-factory/releases/tag/v0.49.7) ·
[Quick guide](docs/START_HERE.md) · [Screenshots](#product-walkthrough)

```powershell
python -m pip install factoryline-code-factory
factory scan --root . --static-only
```

| What you need | Command |
| --- | --- |
| Quick Python source review | `factory scan --root . --static-only` |
| Deeper review with available evidence | `factory scan --root .` |
| Visual review workspace | `factory studio --root .` |

Review the findings, repair the code, and rerun your tests and affected checks.
Quick scan reads Python source without running your project. Deep scan adds
applicable evidence lanes and shows what was unmeasured. Native analysis for
JavaScript, shell, and other languages needs configured workers. A clean static
scan does not establish runtime coverage. Missing evidence stays **INCOMPLETE**.

`factory --help` shows the common paths; `factory --help-all` lists the full CLI.
The [quick guide](docs/START_HERE.md) explains scan results and CI options.

## Build, check, review

**SpecLine** captures what needs to be true, **ForgeLine** coordinates scoped
execution, and **FactoryLine** records the proof and next review action.
Core 0.49.7 connects these steps in a resumable local mission with recorded
recovery and resource-aware checks.
See the [changelog](CHANGELOG.md) and [proof workflow](docs/PROOF_REVIEW_WORKFLOW.md).

## Product walkthrough

<details>
<summary>Four annotated screenshots from the 0.49.6 preview</summary>

![Factory Studio Product Mission draft with intent and review callouts](https://github.com/zrk222/code-factory/releases/download/v0.49.6/studio-product-mission-0496.png)

![Graph Ops guide for choosing the next proof](https://github.com/zrk222/code-factory/releases/download/v0.49.6/graph-ops-proof-guide-0496.png)

![Graph Ops local scan with source coverage and incomplete evidence](https://github.com/zrk222/code-factory/releases/download/v0.49.6/graph-ops-findings-0496.png)

![Expanded Graph Ops finding with its source line and rationale](https://github.com/zrk222/code-factory/releases/download/v0.49.6/graph-ops-finding-detail-0496.png)

The fictional workspace contains a planted finding. Its scan has complete source
coverage and incomplete overall evidence.

</details>

<details>
<summary>Historical precision measurement: N443-38 exposed replay</summary>

On the same observed cases, decided actionable precision was **88.24% (30/34)**
versus 85.71%; 37 of 38 cases returned and all 30 original true positives were
retained. The original sealed first pass was 83.33% on decided labels (30/36)
and 78.95% counting all 38 selected cases. Two blind AI reviewers supplied the
labels. [Case ledger](https://github.com/zrk222/code-factory/releases/download/v0.49.6/original38-regression-0.49.6.json)

</details>

## Reference

[Runtime assurance](docs/RUNTIME_ASSURANCE.md) ·
[GitHub review](docs/GITHUB_PROOF_REVIEW.md) ·
[Release channels](docs/RELEASE_CHANNELS.md) ·
[Commercial availability](docs/COMMERCIAL_PACKAGING.md) ·
[Documentation index](docs/DOCUMENTATION_INDEX.json)

If Code Factory helps you, a GitHub star helps others find it.

<!-- mcp-name: io.github.zrk222/code-factory -->
