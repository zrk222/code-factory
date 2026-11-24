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
| `codeql-ruby-worker` | CodeQL 2.27.1, Ruby queries 1.6.11 | SARIF with source-bound code flows | Full Ruby security-extended suite with modeled Rails/Rack sources and library-input queries; no build or dependency installation. |
| `codeql-java-worker` | CodeQL 2.27.1, Java queries 1.11.11 | SARIF and source accounting | Java source-only extraction using the bundled minimal JDK when needed. Kotlin and build-generated source require another profile. |
| `codeql-csharp-worker` | CodeQL 2.27.1, C# queries 1.10.0, .NET SDK 10.0.404 | SARIF and source accounting | C# source-only extraction. Unavailable dependencies or target packs can leave coverage incomplete. |
| `codeql-go-worker` | CodeQL 2.27.1, Go queries 1.6.11, Go SDK 1.27.2 | SARIF and source accounting | Compile-only extraction in declared module roots. Supports source-contained and vendored dependencies. Missing modules, cgo and absent external dependencies leave gaps. |
| `semgrep-worker` | OpenGrep OSS 1.15.0 (Semgrep-compatible), thirty rules across twelve source languages | SARIF with source-bound local flows | Request-to-shell/SQL checks cover Python, JS/TS, PHP, Go, Java, C# and Ruby; explicit unsafe API/trust checks also cover Rust, C/C++ and Swift. Native controls verify safe counterparts, aliases, trace endpoints and detector removal. Pattern-limited only; no interfile or `interprocedural-full` claim. Candidate `.semgrepignore` still requires native source accounting. |
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

CodeQL's immutable official 2.27.1 bundle digest pins the CLI and bundled query packs. OSV uses
offline mode because the signed host run uses `--network=none`. This
image bundles the verified PyPI snapshot from GCS generation 1794393188720263.
The release asset retains those bytes after the upstream object rolls over.
The archive is an unchanged [OSV.dev PyPI export](https://google.github.io/osv.dev/data/#per-ecosystem-downloads).
See [OSV's source and license list](https://google.github.io/osv.dev/data/#current-data-sources)
for the GitHub Advisory Database, PyPI Advisory Database, OSS-Fuzz, and OpenSSF Malicious Packages.
Docker verifies its SHA-256 before the worker can use it;
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

The Ruby target verifies all 50 selected compiled query artifacts the same way.
Use `profiles/codeql-ruby-full.json` with the signed lane's `ruby` language;
Ruby extraction needs no build, network or installed gems. Run
`node scripts/verify_codeql_cross_file.mjs factory-codeql-ruby-worker:<tag>
<receipt.json> ruby`: `params` in a Rails controller reaches a shell string in
`lib/exporter.rb`; the safe variant passes an argument vector. The vulnerable
report must hold an ordered flow from the controller into the exporter, and the
safe control must have no findings.

Use `codeql-java-full.json`, `codeql-csharp-full.json` or `codeql-go-full.json`
for signed static lanes with the matching language. The Go worker discovers
at most 64 module roots and compiles at most 2,048 packages from normal source
directories, including tests. Its root discovery skips hidden, vendor and
testdata directories. It compiles test binaries without running them.
Go SDK auto-download, proxy lookups and cgo are disabled. Go workspace files
require a separately qualified profile. Local module replacements must resolve
inside the mounted source. All workers retain
the source-hash and database-accounting checks. Missing or degraded source stays
incomplete. PHP continues to use pattern-limited OpenGrep for its documented
request shapes. Blade templates and inter-file PHP analysis require separate
coverage.

Compiled-language CI uses `node scripts/verify_codeql_structural.mjs IMAGE
RECEIPT SDK_TARGET` to run the fixture twice against one built image ID, using a
fresh network-isolated container each time. The check binds the profile and fixture bytes, compares
native findings, diagnostics, and source coverage, and retains both reports and
timings. These runs measure fixture repeatability on a local image. Signed
six-family acceptance, analyzer-cache comparisons, and recall require their
own measurements.

Library-level recall ([evidence](../../docs/evidence/codeql-recall-20261121.json)):
stock CodeQL 2.27.1 security-extended suites, unmodified, ran on 86 fixed
advisories (15 per ecosystem, registered before the first scan) that the
pattern lane detected 0 times. In fix hunks it found Ruby 5 of 15, Python 3 of
15 and JavaScript/TypeScript 2 of 15: 10 of 45 (22%, Wilson 12.5-36.3%) for
the three network-free lanes, against 0 of 45 for the pattern lane. Go (0 of 11,
4 autobuild failures), Java (0 of 13), C# (0 of 2; 7 failed without a .NET SDK)
and Rust (0 of 2) found nothing on that sample. The structural worker recipes
for Java, C# and Go address bounded offline extraction. The study did not
measure those recipes.
Route library-level findings to the CodeQL lanes; the pattern lane stays a
local web-handler and unsafe-API detector.

Factory-level advisory recall ([record](../../docs/evidence/advisory-recall-factory-20261121.json),
verify with `python scripts/verify_precision_gain.py advisory-recall <record>
[--prefix-cache DIR --opengrep BIN]`): on the 161 advisories where the pattern lane alone scored 0,
20 are detected in fix hunks by at least one lane. That combined figure is
descriptive and **not held out**. The record keeps the lanes apart:

- CodeQL (untuned stock queries; the Ruby worker decision used part of these
  results; 36 of the analyzed advisories were added after registration): 15 of
  91 analyzed (Wilson 10.3-25.4%): Ruby 8 of 25, JS/TS 4 of 25, Python 3 of
  25, and 0 of 16 across Go, Maven and crates.io.
- Pattern lane (exposed: its Java trust and Ruby TLS shapes were developed on
  these advisories): 6 of 161 (Maven 4, Ruby 2). One Ruby advisory is detected
  by both lanes.
- Not executed by CodeQL: Packagist 25 (no extractor); 33 Go and Maven
  advisories outside the sample; 10 extraction failures (Go 2, Maven 1,
  NuGet 7); 2 NuGet advisories with no class-matching query.

Each case binds the fix and pre-fix revisions, pre-fix file digests, fix hunks
and every detection. The record also binds the ruleset, OpenGrep binary,
CodeQL bundle, query packs and selected query sets. The verifier recomputes
the summary from the cases. With a pre-fix cache it re-runs the pattern lane
and requires identical detections. Neither a wider CodeQL threat model (0
changes on 25 paired advisories) nor a PHP library-input rule (2 of 25 fresh
advisories; 0 of 19 decided fresh alerts supported) closes the gap, so
neither ships.

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
data-flow traces. Earlier controls recorded trace coverage as `NOT_MEASURED`.
The v7 native run observed code-flow traces in 107 of its 121 fixture findings;
that is fixture-specific transport evidence, not complete flow coverage.
Its ruleset hash binds thirty rules to the image profile.
Request-to-sink rules follow assignments and concatenations within supported
local flows. Parameterized SQL, argv execution without a shell, static HTML,
safe YAML loading, enabled TLS, and values rebound to constants have negative
controls. These controls measure rule behavior on declared fixtures; they do
not establish accuracy on arbitrary repositories. Aliased imports, custom
framework sources, escaping helpers and cross-file flows require additional
models or the full CodeQL lane. HTML `send` findings are limited to template
literals, string concatenation and direct request values; objects serialized as
JSON, binary buffers and helper results are left to review and the CodeQL lane,
and findings still require checking the response content type. The
pattern-only `python.subprocess-shell-true` rule is not part of this
precision profile (2 confirmed of 12 decided across four held-out panels);
request data reaching a shell is reported by `python.request-command-injection`.
Python `verify=False`
and Go `InsecureSkipVerify` are reported only where the call or enclosing
function carries credentials or session material, so unauthenticated probes are
not reported; credential evidence is matched as identifiers (token, secret,
password, Authorization, cookie), not substrings such as `/etc/passwd`.
This credential and opt-in scoping replaces the earlier report-every-bypass
policy on held-out evidence: four pre-registered fresh panels (rounds 1-4,
177 alerts, two independent review contexts) took emitted-alert precision
from 44.1% to 69.8% (round 4, Wilson 56.5-80.5%), and blinded checks of
removed alerts found 34 of 38 decided removals were false positives.
TLS bypasses behind an explicit operator opt-in (`if args.insecure`,
`if cfg.insecure {}`) are not reported, and Rust clients are reported only
when the function carries credentials, session or user identity.
`pickle.load` of a file the program opens itself is not reported, records
looked up by a request key (`findById`, `findProject`, `resolveSection`) are
server-side data for JavaScript path traversal, and named
containment helpers (`safe*`, `sanitize*`, `*within*`) sanitize JavaScript path
traversal. Every rule skips tests, fixtures, exploit or CVE proof-of-concept
corpora, generated code, vendored dependencies (`node_modules`, `vendor`,
`third_party`, `site-packages`, virtualenvs, bundled `Lib/` copies), minified
files and editor `.history` copies; PHP request rules treat integer casts as
sanitizers, and the JavaScript SQL rule does not assume helper return values
carry request text. Copy `rules/tests/php-controls.php` to
`semgrep-pattern-limited.php` and `rules/tests/go-controls.txt` to
`semgrep-pattern-limited.go`, and `rules/tests/rust-controls.txt` to
`semgrep-pattern-limited.rs` when running the native rule tests.

Rules are split into two tiers so that tiering, not suppression, carries
precision. Default-tier rules (severity ERROR/WARNING, SARIF error/warning,
finding severity high/medium) are the high-confidence lane. Context-dependent
rules carry `metadata.tier: review` and severity INFO (SARIF note, finding
severity low): JavaScript, Go, Java, C# and Ruby request taint, TLS and
trust bypasses (Go, Python, Rust, Java hostname, Ruby, Swift), unscoped Python
deserialization (`python.unsafe-deserialization-unscoped`, any pickle/YAML
source) and PHP file inclusion. Review-tier findings stay in the report; they
need peer, reachability or framework context that a local pattern cannot see.
The C# certificate rule stays in the default tier on its held-out record.
Default-tier Python deserialization reports request or socket-event data only.
JavaScript validator and allowlist guards (`isValid*`, `validate*`, `.has`,
`.includes`), `path.basename` and `{text, values}` query objects, Java
`Integer`/`Long` parsing and PHP `preg_replace` with a negated character class
are sanitizers; WordPress core (`wp-admin`, `wp-includes`), Rust
`tests.rs`/`test_utils.rs` and `TestUtils` helpers are excluded like other
test or vendored code. Evidence: a pre-registered fresh panel of 60 default-tier
alerts (round 6, repositories unseen in rounds 1-5, two independent review
contexts) measured 54 of 60 decided alerts supported, 90.0% (Wilson
79.9-95.3%); the blinded check of the 4 baseline (v4) alerts absent from every
tier found all 4 were false positives. Round 5, before tiering, measured 73.2%
across all rules, with JavaScript taint at 5 of 11 and TLS bypasses at 4 of 12.
Round 6 contained alerts from six observed languages; fifteen slots were
shortfall fills, and eighteen findings used the C/C++ `c.unsafe-gets` rule.
This is not a twelve-language precision estimate or a general recall result;
review-tier precision was not measured in that round.

The [v7 native verification run](https://github.com/zrk222/code-factory/actions/runs/44888372954)
passed controls across twelve declared languages, all thirty detector-removal
challenges, and source-bound SARIF normalization. Its 121 synthetic findings
include 45 review-tier notes retained by the normalizer. Native control
readiness and held-out panel precision are separate measurements.

Polyglot readiness ([evidence](../../docs/evidence/polyglot-readiness-round7.json))
was measured on the same ruleset with two pre-registered studies. Round 7
sampled up to 14 fresh alerts per declared language at every tier (no
shortfall fill; two independent review contexts, 96.8% raw agreement). Recall
was measured on fixed GitHub-reviewed advisories and on real uses of the
dangerous APIs the explicit-API rules target.

| Language | Round 7 supported / decided (tier) | Alert pool | API-occurrence recall |
|---|---|---:|---|
| C | 7/8 (default) | 160 | 17/25 (all 17 libc `gets` calls) |
| C++ | 8/8 (default) | 759 | 8/25 (all 8 libc `gets` calls) |
| PHP | 10/11 default, 3/3 review | 1,175 | - |
| Python | 7/7 default, 5/6 review | 228 | 4/25 `verify=False` |
| JavaScript | 7/13 (review) | 96 | - |
| TypeScript | 6/14 (review) | 43 | - |
| C# | 4/4 (default), insufficient | 31 | - |
| Go | 1/1 default, 2/2 review, insufficient | 5 | 7/25 `InsecureSkipVerify` |
| Java | 1/1 (default), insufficient | 1 | - |
| Rust | 0/2 (review), insufficient | 3 | 3/25 `danger_accept_invalid_certs` |
| Ruby | no alerts found | 0 | 0/25 `VERIFY_NONE` |
| Swift | no alerts found | 0 | 0/25 trust overrides |

Default tier: 38 of 40 decided alerts supported, 95.0% (Wilson 83.5-98.6%),
with 12 unclear `gets` cases in contest code. Review tier: 23 of 40, 57.5%
(Wilson 42.2-71.5%). Six languages had fewer than five decided alerts, so they
have native controls but no measured precision. Ruby and Swift produced no
alerts from fresh repositories: their trust rules match one call shape each
(`SSLContext.new.verify_mode =` and `SecTrustSetExceptions`). None of 161 fixed
advisories in rule-scope CWEs (25 per ecosystem; 9 NuGet, 2 crates.io) was
detected in its fix hunks or anywhere in its changed files (0%, Wilson 0-2.3%):
the rules see request-to-sink flows inside one web handler, while published
advisories are mostly library APIs whose input arrives as function parameters.
This lane is a high-precision local web-handler and unsafe-API detector; it is
not a vulnerability-recall claim.

Coverage round ([evidence](../../docs/evidence/polyglot-coverage-round8.json)):
the Go, Java, C# and Ruby request rules now read framework sources (Go
`net/http` query, form and `mux` values plus Gin and Echo context getters;
Jakarta servlets and Spring `@RequestParam`/`@PathVariable`; WebForms and MVC
`Request.QueryString`/`Form`/`Params`; Rails, Sinatra and Grape `params`) and
common sinks (Go `QueryRow`/`*Context`/GORM `Raw` and shell or request-chosen
programs; `Connection.prepareStatement`, `JdbcTemplate`, `EntityManager` and
`Runtime.exec`; ADO.NET providers and EF `FromSqlRaw`/`ExecuteSqlRaw`; `system`,
`exec`, `IO.popen`, `Open3`, `find_by_sql` and string `where`). Ruby trust
checks cover `verify_mode` assignments and `VERIFY_NONE`/`verify: false`
options, and Swift checks cover delegates that return `URLCredential(trust:)`
without evaluating or pinning the trust. A fresh pre-registered panel (round 8,
14 alerts per changed language) measured the widened request rules at 25 of 47
decided alerts supported (53%; Go SQL 2 of 13, prepared statements and
allowlisted `ORDER BY` fragments), so they joined the review tier, and Go SQL
sinks now need a database-handle receiver that is not a prepared statement.
Review-tier trust rules measured Ruby 5 of 5 and Swift 7 of 13. Swift
trust-override recall on fresh files rose from 0 of 25 to 18 of 25; Ruby had no
eligible fresh file (re-scanning the round-7 files: 0 to 9 of 25). The next 63
fixed Go, Maven and RubyGems advisories were still not detected.

Trust coverage ([evidence](../../docs/evidence/trust-coverage-round9.json)):
the Java rule also reports `setHostnameVerifier((h, s) -> true)`, Apache
`NoopHostnameVerifier`, `ALLOW_ALL_HOSTNAME_VERIFIER`, `TrustAllStrategy`,
accept-all `loadTrustMaterial` lambdas, `verify(...)` returning `true` and
empty `checkServerTrusted` trust managers; the Go rule also reports
`InsecureSkipVerify = true` assignments. On all 79 scorable, previously untried
Maven, Go and PyPI trust advisories, fix-hunk recall rose from 2 to 10 (12.7%,
Wilson 7.0-21.8%; Maven 0 to 6 of 28, Go 1 to 3 of 22). A fresh panel of 20
Java trust alerts had 7 of 9 decided alerts supported and 11 unclear (trust-all
code reviewers could not tie to security-relevant traffic), which is why the
rule stays in the review tier.

Reproduce the native rule tests in a temporary folder by copying
`rules/tests/python-controls.txt` to `semgrep-pattern-limited.py`,
`rules/tests/javascript-controls.js` to both `semgrep-pattern-limited.js` and
`semgrep-pattern-limited.ts`, and the rules YAML beside those files. Run the
pinned Semgrep-compatible OpenGrep image with `semgrep --test --metrics=off
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
