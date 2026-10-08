# Native deep-audit worker image recipes

These are bounded worker SDK templates, not scanner-readiness claims. Build on
Linux/amd64 from the repository root and use the final target named below. The
host must still validate signed lanes, image digests, candidate bindings,
timeouts, memory limits, challenge outcomes, and report completeness.

| Family / target | Bundled tool | Evidence format | Scope limit |
| --- | --- | --- | --- |
| `codeql-python-worker` | CodeQL 2.27.1 Python bundle | SARIF | Full interprocedural Python query suite; this target covers Python only. |
| `semgrep-worker` | Semgrep 1.141.0, one local Python rule | SARIF | Pattern-limited only. It cannot satisfy the repository's `interprocedural-full` static gate. The pinned CLI still honors candidate `.semgrepignore`; native source accounting remains necessary. |
| `osv-worker` | OSV-Scanner 2.2.0 + immutable PyPI database snapshot | OSV JSON | Offline PyPI dependency scanning only; the pinned database snapshot ages and does not cover other ecosystems. |
| `syft-worker` | Syft 1.33.0 | Syft JSON | Inventory only; this is not a vulnerability scan. |
| `gitleaks-worker` | Gitleaks 8.28.0 | SARIF | Built-in rules are pinned with the image; native accounting limitations remain. |
| `trivy-worker` | Trivy 0.68.1 | SARIF | Configuration checks only; no vulnerability database scan is requested. |
| `runtime-worker` | coverage.py 7.16.1 + pytest 9.1.1 | coverage JSON plus JUnit XML | Requires candidate `tests/test_runtime_harness.py`; its actual execution and source coverage must be validated. |
| `fuzz-worker` | Atheris 3.0.0 + coverage.py 7.16.1 | runtime JSON | Requires candidate `.factory/fuzz_harness.py` exporting `TestOneInput(bytes)`; the image runner owns Atheris setup. Run counts and distinct-input counts are snapshot lower bounds; Python arcs are coverage.py observations, not native fuzzer edge coverage. Native source accounting and independent challenge evidence remain required. |

All profile argv is fixed in the image and uses only the documented source,
output, report, and scratch placeholders. Profiles carry exact version probes.
The Semgrep rules file is content-hashed. The other profile fingerprints refer
to their pinned tool bundle, not to a claim that a remote advisory database or
all tool-internal checks are separately content-addressed. Runtime, fuzz and CodeQL bootstrap wheels are version- and SHA-256-pinned for
Linux/amd64 CPython 3.11. Pip requires hashes and binary wheels, rejecting
unlisted wheel bytes and source builds. The shared SDK uses Python 3.11.17
slim-bookworm pinned to the Linux/amd64 manifest digest. Unused setuptools
and wheel packages are removed from the SDK; this does not mean the Debian
base has no published advisories.
The vendored Gitleaks rules come from the official [v8.28.0 configuration](https://github.com/gitleaks/gitleaks/blob/v8.28.0/config/gitleaks.toml). The full upstream MIT license and Copyright 2019 Zachary Rice notice are included in the repository and image at [GITLEAKS-LICENSE.txt](rules/GITLEAKS-LICENSE.txt).

CodeQL's immutable official 2.27.1 bundle digest pins the CLI and its Python
query pack. This target does not claim compiled-language coverage. OSV uses
offline mode because the signed host run uses `--network=none`. This
image bundles the verified PyPI snapshot at GCS generation 1791370055357324;
it does not include other ecosystems. Trivy config scanning does not
update the vulnerability database. The source-bound runtime and fuzz harnesses
are candidate inputs, never copied into these images. No image should set deep
coverage complete merely because the native process exited successfully.

## Isolated startup and bounded execution

Final worker targets start the installed SDK with Python isolated mode (`-I`).
Candidate packages and `sitecustomize.py` cannot replace the SDK at startup.
The runtime profile imports the image's coverage and pytest packages before
adding the candidate source path, and disables candidate coverage configuration.
Candidate tests and fuzz callbacks still execute untrusted code inside the
restricted container; isolated imports are not a claim of tamper-proof harnesses.

The CodeQL target precompiles the same full Python security-extended query suite
during image construction. This moves query compilation out of each audit run;
the runtime profile retains its two-thread and 1,400 MB analysis limits.

CodeQL's SARIF uses `%SRCROOT%` without exporting a URI base. The fixed image
profile supplies the source root from its `/src` database-create invocation,
without overriding an existing base. Its derived SARIF retains the original
report hash in `properties.factory_native_raw_sha256` and records that basis.
The SDK still rejects paths outside the exact candidate inventory.
Descriptor-only CodeQL pack extensions are retained as run properties for
strict importer compatibility. Extensions containing rules or taxa are rejected;
external property files and unresolved rule references remain unsupported.
# 0.48.0 worker security refresh

The SDK retains CPython 3.11.17 and uses a digest-pinned Debian Forky base,
the signed 2026-10-08 Debian archive snapshot, and exact OpenSSL 3.6.5-1
packages from Sid. Apt signature and package hash verification remain enabled.
Python build dependencies use wheel hashes; pip and Pygments are patched.

Trivy's Forky/Sid OS coverage is insufficient to establish remediation.
Validate installed **source-package** versions against Debian Security Tracker
fixed versions with `dpkg --compare-versions`, and retain the feed digest,
image digest, package manifest, and per-CVE decisions. Language-package scans
remain useful. Native clean/failing runtime and fuzz controls must also pass.
This refresh does not establish vulnerability-free images or full audit coverage.
