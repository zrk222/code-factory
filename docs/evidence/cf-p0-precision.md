# CF-P0 scanner precision

| Measurement | Raw precision | True positives | False positives | Unclear | Admitted precision |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original blind 40 | 58.06% | 18 | 13 | 9 | 100% (5/5) |
| Exposed 40 before fixes | 75.00% | 18 | 6 | 9 | 100% (5/5) |
| Exposed 40 after fixes | 90.00% | 18 | 2 | 9 | 100% (5/5) |

The original blind result pools four ten-alert tranches. The paired replay
uses the same 40 reviewed alerts as an exposed regression panel. Raw precision
uses decided labels. The nine unclear labels yield a 62.07%–93.10% range for
the fixed panel.

The replay preserved all known true positives. Each build scanned the same
1,059 Python files across 42 repository captures, including the separate
15-case retention controls.

The aggregate reports and checksum manifest are published as
[precision evidence release assets](https://github.com/zrk222/code-factory/releases/tag/cf-p0-precision-evidence-2026-11-18).
