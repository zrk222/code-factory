# Native deep-audit worker image recipes

These are bounded worker SDK templates, not scanner-readiness claims. Build on
Linux/amd64 from the repository root and use the final target named below. The
host must still validate signed lanes, image digests, candidate bindings,
timeouts, memory limits, challenge outcomes, and report completeness.

| Family / target | Bundled tool | Evidence format | Scope limit |
| --- | --- | --- | --- |
| `codeql-python-worker` | CodeQL 2.27.1 Python bundle | SARIF | Full interprocedural Python query suite; this target covers Python only. |
| `codeql-javascript-worker` | CodeQL 2.27.1, JavaScript queries 2.4.6 | SARIF with source-bound code flows | Full JavaScript/TypeScript security-extended suite, including modeled cross-module flows. Candidate extraction and framework models determine coverage. |
| `codeql-actions-worker` | CodeQL 2.27.1, Actions queries 0.6.36 | SARIF with workflow source-to-sink flows | Full GitHub Actions security-extended suite; workflow injection and trust-boundary models depend on extracted YAML. This does not execute workflows or prove external actions safe. |
| `semgrep-worker` | Semgrep 1.141.0, eight local Python/JavaScript/TypeScript rules | SARIF | Tracks declared request sources through local aliases into SQL, command and HTML sinks; also checks unsafe Python deserialization and disabled TLS. Pattern-limited only: it cannot satisfy the `interprocedural-full` static gate. Candidate `.semgrepignore` still requires native source accounting. |
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
from the pinned slim-trixie image on a pinned Debian Forky SDK snapshot. Unused setuptools
and wheel packages are removed from the SDK; this does not mean the Debian
base has no published advisories.
The vendored Gitleaks rules come from the official [v8.28.0 configuration](https://github.com/gitleaks/gitleaks/blob/v8.28.0/config/gitleaks.toml). The full upstream MIT license and Copyright 2019 Zachary Rice notice are included in the repository and image at [GITLEAKS-LICENSE.txt](rules/GITLEAKS-LICENSE.txt).

CodeQL's immutable official 2.27.1 bundle digest pins the CLI and its Python
and JavaScript query packs. These targets do not claim compiled-language coverage. OSV uses
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
The JavaScript target inherits that pinned SDK and verifies that every selected
query has its precompiled artifact in the SHA-pinned official bundle. It avoids
redundant recompilation of the JavaScript security-extended suite.
Both new targets make bundled query-pack files and directories readable by the
non-root worker. This includes the hidden precompiled payloads referenced by
the `.qlx` descriptors; descriptor presence alone did not establish readability.
Use `profiles/codeql-javascript-full.json` and declare
`javascript` and `typescript` in the signed lane's languages. It does not install
candidate dependencies, run a candidate build, or fetch remote models.

Run `node scripts/verify_codeql_cross_file.mjs
factory-codeql-javascript-worker:0.48.0 <receipt.json>` to execute two bound
controls through the actual adapter: request data crosses `route.js` and
`service.js` into a shell sink; the safe variant uses `execFile` with a fixed
executable and argv. The vulnerable report must contain ordered code-flow
locations in both files, and the safe control must have no findings. Receipts
bind fixture hashes, profile hashes, image ID and native report bytes.

The Actions target likewise verifies all 24 selected compiled query artifacts
from the pinned bundle without redundantly recompiling the suite.
Use `profiles/codeql-actions-full.json` with the signed lane's `configuration`
language. Run `node scripts/verify_codeql_cross_file.mjs
factory-codeql-actions-worker:0.48.0 <receipt.json> actions` for an untrusted PR
title interpolated into a shell command and its safe quoted environment-variable
control. A native injection finding at the exact workflow source location is required for
the vulnerable variant; the safe variant must produce no findings.
The one-location Actions control may emit no code-flow array; that is recorded
as `NOT_EMITTED`, never synthesized as an observed trace.

## Efficient unified operation

Use `factory scan --deep --worker-config PATH --json` with explicit signed,
digest-pinned configuration. Select relevant profiles, rather than every image
for every edit. Bundled compiled JavaScript/Actions queries avoid redundant
compilation; Python's existing target precompiles its full suite. Reuse an existing image by its
verified digest. Evidence reuse additionally requires matching candidate,
profile, tool, trust and execution bindings; image reuse alone cannot clear
findings. Receipt discovery filters names before filesystem inspection, avoiding
unnecessary per-file checks on unrelated logs. None of these optimizations
reduces the selected suite or treats an unmeasured lane as passing.

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

## Expanded native scanning controls

The Semgrep profile disables inline `nosemgrep` suppression and requests
data-flow traces. The pinned community engine did not emit SARIF code-flow
traces in native controls, so trace coverage is recorded as `NOT_MEASURED`.
Its ruleset hash binds eight rules to the image profile.
Request-to-sink rules follow assignments and concatenations within supported
local flows. Parameterized SQL, argv execution without a shell, static HTML,
safe YAML loading, enabled TLS, and values rebound to constants have negative
controls. These controls measure rule behavior on declared fixtures; they do
not establish accuracy on arbitrary repositories. Aliased imports, custom
framework sources, escaping helpers and cross-file flows require additional
models or the full CodeQL lane. HTML `send` findings require checking the
response content type and output context during review.

Reproduce the native rule tests in a temporary folder by copying
`rules/tests/python-controls.txt` to `semgrep-pattern-limited.py`,
`rules/tests/javascript-controls.js` to both `semgrep-pattern-limited.js` and
`semgrep-pattern-limited.ts`, and the rules YAML beside those files. Run the
pinned Semgrep image with `semgrep --test --metrics=off
--disable-version-check <folder>`. Set `HOME=/tmp` and
`SEMGREP_SETTINGS_FILE=/tmp/settings.yml` when the container is read-only.
