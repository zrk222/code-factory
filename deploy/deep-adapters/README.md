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
| `semgrep-worker` | Semgrep 1.141.0, fifteen local Python/JavaScript/TypeScript/PHP rules | SARIF | Tracks declared request sources through local aliases into SQL, command, HTML and filesystem-path sinks; also checks unsafe Python deserialization and disabled TLS. Pattern-limited only: it cannot satisfy the `interprocedural-full` static gate. Candidate `.semgrepignore` still requires native source accounting. |
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
image bundles the verified PyPI snapshot at GCS generation 1792839797362039;
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
Its ruleset hash binds fifteen rules to the image profile.
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

### Signed ZAP request-associated source tracing

ZAP target execution uses a separately digest-pinned app container and scanner
on a private internal Docker network. It is an explicit signed-target route,
not an additional preconfigured profile in the ten-profile inventory above.
For a Python script using stdlib `http.server`, add this optional descriptor to
the signed `native_target` before signing its manifest:

```json
"source_trace": {
  "schema": "factory.zap-source-trace.config.v1",
  "provider": "python-stdlib-http.v1",
  "max_events": 50000
}
```

The target argv must begin with an absolute Python executable followed by a
canonical `/src/<bound-script.py>` path; optional script arguments follow.
Each route must have a unique method/path pair and current source hashes.
Read the shared `factory audit taxonomy --json` contract at
`agent_usage_contract.six_lane_review.zap_source_trace` for agent and Junie
requirements. Existing signed authorization and trust-root requirements apply.

The host retains raw and normalized trace digests and observed line IDs for
each route/source pair, verifies retained source bytes and fresh replay, and
reports missing pairs or invalid traces as actionable incomplete evidence.
Signed positive, safe and exact-disabled controls remain separately required.
Trace capture uses bounded `docker exec` with the signed isolated interpreter;
no writable host output is mounted. All containers and private networks are
removed after the run.

This provider covers Python stdlib HTTP request-associated lines only.
In-process instrumentation can be forged or disabled by candidate code;
observed line hits do not prove authenticity, complete branches, vulnerability
causality or detection accuracy. ASGI, WSGI and other runtimes need separate
providers and remain unsupported by this tracing provider.

### Bounded PHP security review

The supplemental Semgrep lane adds `php.request-command-injection`,
`php.request-sql-injection`, `php.request-path-traversal`,
`php.request-file-inclusion` and `php.request-unsafe-deserialization`.
These are local request-to-operation candidates, with unresolved PHP callee
provider identity; a same-named namespaced/user-defined function may match.
Object methods are excluded. No finding proves exploitability or gadget execution.
Sources are exact reads from GET/POST/REQUEST/COOKIE superglobals. Sink operands
exclude SQL bound-value arrays and file-write content. HTML escaping, trimming,
decoding and `allowed_classes=false` do not clear taint. Shell escaping and
filesystem guards require review, not a universal sanitizer exemption.

Only ordinary `.php` files are in scope. Blade `.blade.php`, `.phtml`, `.inc`,
Twig, dynamic invocations, references, variable variables, framework sources,
PDO, closures/cross-function/cross-file flows, XSS, SSRF, CSRF and access control
are unsupported/unresolved, never safe negatives. The basic Python security
scan remains Python-only. PHP requires the configured signed supplemental
Semgrep worker through `factory scan --root PATH --deep --worker-config
.factory/worker-config.json --json`; this cannot satisfy `interprocedural-full`.
Missing authorization, native execution, challenge or source evidence remains
INCOMPLETE. Source accounting COMPLETE means processed paths, not full security.

Native fixture preparation: copy `rules/tests/php-controls.php` as
`semgrep-pattern-limited.php` alongside the matching rules YAML, then run the
existing pinned image's `semgrep --test --metrics=off --disable-version-check`
fixture command. Do not execute the PHP fixture. Native parser behavior and
PHP JSON/SARIF-to-signed-CLI ingestion must be measured separately; authored
fixtures or Python validator tests do not establish native execution or accuracy.


PHP 8 named operands are supported for every procedural sink, including reordered
names and mixed positional/named forms. Sink parameter names follow PHP's
standard/mysqli/pgsql stubs: `command`, `filename`, `data`, and SQL `query`.
The PostgreSQL two-argument legacy overload is modeled separately so bound
parameter arrays do not become SQL-text sinks. Inclusion syntax has no named
argument form. Native named-operand controls include all fifteen functions,
33 positive candidates and 18 safe operand/provider controls.
