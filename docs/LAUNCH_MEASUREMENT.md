# Launch Measurement

Capture raw distribution signals before interpreting them. The helper saves
PyPI and, when authenticated through `gh`, GitHub traffic responses in one JSON
receipt. It does not calculate users, conversion, or savings.

```powershell
.\scripts\capture_launch_metrics.ps1 `
  -Campaign "linkedin-launch" `
  -PostUrl "https://www.linkedin.com/posts/..."
```

The output goes to `.factory/launch-metrics/` and records the observation time,
raw sources, and any unavailable source errors. Run it before posting, on the
next day, and after material discussions or posts. Compare dated observations;
do not describe PyPI downloads as unique humans or attribute them to a campaign
without a separate source.
