# Plan: structural-polyglot-tooling
Spec: specs/structural-polyglot-tooling.md
Architect verdict: CONCERNS until the candidate images and signed acceptance are verified.

## Logical decomposition

1. Verify build and offline extraction prerequisites in the pinned Linux worker.
2. Add and register profiles with an actual isolated fixture for each supported target.
3. Verify repository integration and evidence boundaries. Reuse existing signed matrix and paired timing where host, operator credentials and exact candidate inputs permit.

## Fixed offline inputs

- CodeQL 2.27.1 and its immutable bundle digest come from the existing Python worker stage. Use the verified precompiled Java 1.11.11, C# 1.10.0 and Go 1.6.11 security-extended suites.
- Java uses build mode `none` with the bundle's minimal JDK fallback. Count only Java compilation units and severity four or greater diagnostics. The source archive must bind each declared source. Include full-source prerequisites in coverage, including any Kotlin or generated artifacts the configured lane cannot cover.
- C# uses build mode `none` and the .NET 10.0.404 Linux x64 archive with SHA-256 `c0610757a818fde4b960d27a0ac421f273068a05dc5ec7abafc01dbf84e9cb4d`. The image launcher sets invariant globalization and offline SDK settings after the adapter has sanitized inherited environment variables. Count C# syntax elements, compiler errors and extractor errors.
- Go reuses the existing Go 1.27.2 Linux/amd64 OCI source, digest `5bc7f572bbaa98885a3a1fd9c0aa76b59e3e14e8628bfc316bbfd0c701e4818c`. CodeQL runs the image-owned Python compiler command. Its fixed list/compile-only invocations traverse discovered normal module roots with readonly or vendored dependencies and disable cgo, module proxy and toolchain download. Never invoke a candidate build script or run a compiled test. Bound the workload to 64 modules and 2,048 packages; count Go source-file models and file-associated extraction diagnostics.
- PHP retains the existing pattern-limited OpenGrep route and can select the separate OpenGrep 2.0.0 PHP worker. It derives the five existing PHP rules, requires cross-file flags for baseline, per-rule and challenge execution, and leaves Blade incomplete. Kotlin needs a separately qualified lane. Missing inventory bytes or native rows remain incomplete.
- Candidate CI builds each exact target, runs the compiled fixture in two fresh containers and checks source hashes and report coverage for both runs. Compare native findings and source accounting after removing CodeQL timing telemetry. Retain both raw bundles. Track signed six-family acceptance and cache-specific cold/warm comparisons independently.

## Tasks

- [ ] T1 | slice=deploy/deep-adapters | files=deploy/deep-adapters/Dockerfile,deploy/deep-adapters/profiles/codeql-java-full.json,deploy/deep-adapters/profiles/codeql-csharp-full.json,deploy/deep-adapters/profiles/codeql-go-full.json | verify=`docker build --target codeql-java-worker -f deploy/deep-adapters/Dockerfile .` | Pin compiled-language extraction prerequisites.
- [ ] T2 | slice=scripts | files=scripts/select_worker_targets.mjs,scripts/verify_worker_cves.mjs,scripts/verify_codeql_structural.mjs | verify=`node --test scripts/select_worker_targets.test.mjs scripts/verify_worker_cves.test.mjs` | Bind the structural tests to the exact built image and fixed profile.
- [ ] T3 | slice=.github/workflows | files=.github/workflows/worker-verification.yml | verify=`git diff --check` | Register the new variants in the conservative worker matrix.
- [ ] T4 | slice=factoryline | files=factoryline/audit_taxonomy.py,factoryline/deep_audit.py,factoryline/deep_audit_sarif.py | verify=`py -3.11 -m pytest -q tests/test_deep_audit.py -k 'codeql or uncovered_static_source'` | Expose the worker recipes and prove source accounting and the lower-depth fallback through existing diagnostics.
- [ ] T5 | slice=deploy/deep-adapters | files=deploy/deep-adapters/Dockerfile,deploy/deep-adapters/profiles/semgrep-php-interfile.json,scripts/verify_php_interfile.mjs | verify=`node scripts/verify_php_interfile.mjs factory-php-interfile:local .factory/php-interfile.json` | Verify the opt-in cross-file PHP worker and its incomplete Blade state.
