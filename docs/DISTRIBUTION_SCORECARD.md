# Distribution and activation scorecard

Observed 2026-08-21. These provider counters are deliberately non-additive:
one person can appear on several surfaces, downloads can be automated or
repeated, and none proves activation.

| Surface | Observed provider signal | Meaning |
| --- | ---: | --- |
| PyPI | 429 day / 1,437 week / 3,445 month downloads | Package retrievals, not unique users |
| GitHub | 5 stars; 2,265 clones / 280 unique cloners; 329 views / 26 unique visitors over 14 days | Repository interest, not verified outcomes |
| JetBrains Marketplace | 54 downloads | Marketplace counter; public update remains review-dependent |
| Open VSX | 144 downloads; 0 ratings | Distribution; namespace verification claim pending in issue #12688 |
| Visual Studio Marketplace | 0 installs; 0 ratings | No activation receipt |
| Product Hunt | 11 followers; 0 reviews | Audience signal, not usage |
| Hugging Face | 1 like | Surface engagement |
| Zenodo v0.43 | 21 views; 0 downloads | Research record traffic |

The product-controlled funnel begins only when a user explicitly runs
`factory first-proof`. `factory adoption status --root .` reports local
milestones without transmitting identity. Provider counts must never be summed
into a claimed user total.
