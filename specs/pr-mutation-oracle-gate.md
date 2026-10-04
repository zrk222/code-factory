# Spec: pr-mutation-oracle-gate
Status: proposed
SpecFactor-target: 0.75

## MUST - Functional core
### Description
Run bounded, evidence-producing mutation checks for changed production Python modules in `factoryline/` on pull requests. The gate uses a behavior-oracle map that already exists at the trusted PR base commit, so the candidate cannot add or weaken its own oracle in the same change. The bootstrap map PR, gate implementation PR, and first production-code PR are separate changes. This is mutation adequacy evidence for the mapped Python slice; it is not a replacement for unit tests or a code-correctness certificate.

### User roles
- Pull request author: supplies a candidate change and observes mapped coverage, survivors and actionable blocking reasons.
- CI runner: computes the exact changed source scope, validates baseline oracle evidence, runs pinned mutation checks in an isolated snapshot, and emits a commit-bound receipt.
- Specialty AI reviewer: independently reviews a proposed oracle-map change before it becomes a baseline; the review artifact records exact manifest/oracle hashes, reviewer/model identity assertion, and result. Hashes bind bytes but do not authenticate reviewer identity or prove independence; reviewer opinion does not authorize merge or release.

### Requirements (EARS)
- When a pull request changes tracked `factoryline/**/*.py` files, the system shall compute source scope from the trusted GitHub base/head event SHAs using `git diff --find-renames=50% --find-copies=50% --find-copies-harder --name-status -z`, parse its NUL-delimited records, include added, copied, modified and renamed destination paths, and accept at most 10 changed production modules per run.
- If Git returns an unrecognized, malformed, or unclassifiable name-status record, or a relevant rename/copy cannot be resolved to its source and destination paths, the gate shall return `BLOCKED` before mutation execution.
- If any changed production Python source has no unique oracle-map entry in `.factory/mutation-oracles.json` at the PR base commit, the gate shall return `BLOCKED` with each uncovered path.
- If the baseline oracle map is missing, malformed, duplicated, unbounded, or outside schema `factory.mutation-oracles.v1`, the gate shall return `BLOCKED`.
- If any mapped behavioral oracle file is missing at the base SHA, escapes the repository, is not under `tests/`, or differs from the SHA256 pinned in the base-commit map, the gate shall return `BLOCKED` before mutation execution.
- If the base-commit map does not name a valid `.factory/mutation-harness-lock.json` and its SHA256, or any test-harness input required by a mapped oracle is absent, ambiguous, dynamically discovered without an explicit lock entry, or hash-mismatched in that lock, the gate shall return `BLOCKED` before mutation execution.
- When the mutation runner prepares a mapped oracle, it shall load the complete execution closure from the trusted base snapshot: oracle source bytes; transitive repository test helpers and applicable `conftest.py` files; test-discovery and pytest/mutmut configuration; explicitly enabled plugins; fixed command/profile; Python/runtime identity; and hash-pinned, binary-only dependency artifacts. It shall reject ambient configuration and implicit plugin autoload.
- When the candidate changes a file in a mapped oracle's locked harness closure, the mutation runner shall set `candidate_harness_changed=true`, execute only the base-SHA harness bytes, and identify the changed paths in its receipt. It shall not import candidate versions of test helpers or configuration. The ordinary PR test job remains responsible for candidate test and harness bytes.
- If the candidate diff deletes one or more production Python files under `factoryline/`, the gate shall emit one `BLOCKED` deletion-impact row for each deleted path and shall not count those paths as mutation-covered.
- When a changed module has exactly one valid base-commit mapping, the runner shall execute the candidate production source against its 1-to-20 declared oracle files using the verified base-SHA harness snapshot and pinned mutmut 3.8.0 in a disposable, explicitly assembled execution copy, then emit exactly one result row for each changed source path.
- If the sum of all source executions exceeds the 20-minute total mutation budget, produces zero mutants for any source, or reports any surviving, skipped, suspicious, timed-out, interrupted, unclassified, or failed mutant, the gate shall return `BLOCKED` and preserve the failed execution log and survivor diagnostics.
- When no production Python source changed and no production Python file was deleted, the workflow shall emit `NOT_APPLICABLE` and explicitly state that no behavioral adequacy was established; this result shall not be presented as a mutation `PASS` or satisfy an evidence check that claims adequacy.
- When a receipt is emitted, it shall identify the base SHA, candidate SHA, source/oracle mapping, pinned oracle hashes, tool/runtime identity, executed command, mutant counters, GitHub Actions run ID, result-log hashes, elapsed time, resource limits, and false authority fields; repair, approval, merge, signing, publishing, deployment and credential authority shall remain false.
- When a `pull_request` workflow executes, the runner shall upload the receipt, execution log and survivor diagnostics as one artifact; the workflow shall stop after 30 minutes.
- When the mutation runner selects an oracle, it shall read at most 2 MiB per locked file and verify the trusted base-manifest and harness-lock SHA256 values; if a candidate SHA256 for any locked path differs, the receipt shall set `candidate_harness_changed=true` and mutmut shall execute only the verified base bytes. The ordinary PR test job shall execute candidate test and configuration bytes separately.
- If a candidate changes an oracle mapping or test, the mutation runner shall not use the candidate bytes for that PR; a subsequent pull request may use those bytes only when its trusted base SHA contains them and the specialty-AI review artifact names their exact hashes.
- When any pull request runs the workflow, the workflow shall use the `pull_request` event, request only `contents: read`, set checkout `persist-credentials: false`, and pass only an allowlist of non-secret environment variables to the candidate test container; the container shall receive no GitHub token, cloud credential, package credential, publisher secret, repository secret, or credential-bearing `.git/config`.
- When candidate-controlled test code executes, the workflow shall run it in a disposable container with network disabled, read-only root filesystem, no added capabilities, no-new-privileges, only a writable candidate/work directory and read-only wheelhouse mounts; the container limits shall be 2 CPU cores, 4096 MiB of memory, 256 PIDs, 10240 MiB of temporary storage, and 20 minutes of total wall time. If any container limit cannot be enforced, the gate shall return `BLOCKED` before running candidate code.
- When CI dependencies are prepared, the runner shall use a base-commit dependency lock with hashes and binary-only artifacts; if a complete trusted lock or required wheel is unavailable, the gate shall return `BLOCKED` before running candidate code.
- When GitHub Actions run, every third-party action shall be pinned to an immutable full commit SHA; the workflow shall not use `pull_request_target` or change branch-protection settings.
- When a pull request is evaluated, the trusted mutation controller shall load the gate implementation, policy and workflow definition from the base commit or a separately controlled repository revision identified by a commit SHA that is exactly 40 characters long; candidate changes to those files shall not replace the controller producing the required result.
- When the mutation result participates in merge eligibility, branch protection shall block merge unless the `factory-mutation-oracle-gate` status check is `success` and its source is the registered GitHub App identity; a same-named job result emitted by candidate-controlled workflow configuration is insufficient.
- If the trusted controller source or expected check-app identity cannot be established from live repository ruleset/branch-protection readback, the result shall be `INCOMPLETE` and shall not be described as required or enforceable.

### Acceptance criteria (Gherkin)
```gherkin
Scenario: Unmapped production source blocks
  Given a pull request changes factoryline/new_module.py
  And the base-commit oracle map has no entry for that source
  When the mutation gate runs
  Then it returns BLOCKED and identifies factoryline/new_module.py
  And it does not execute mutants

Scenario: Modified candidate oracle is not trusted
  Given a base-commit map pins tests/test_behavior.py
  When the pull request changes tests/test_behavior.py
  Then the mutation gate executes only the base-commit bytes
  And the ordinary PR test job separately executes the candidate bytes

Scenario: Candidate test harness changes cannot alter the oracle run
  Given a base-commit harness lock pins tests/conftest.py and the oracle's imported helpers
  When the pull request changes tests/conftest.py or a pinned helper
  Then the mutation gate executes only the base-commit locked bytes
  And the receipt lists the changed harness paths
  And the ordinary PR test job separately executes the candidate harness bytes

Scenario: Unresolved dynamic harness dependency blocks
  Given a mapped oracle dynamically imports a helper not declared in the base lock
  When the mutation gate resolves its execution closure
  Then it returns BLOCKED before running mutants
  And it identifies the unresolved import

Scenario: Renamed or copied production source is classified
  Given a pull request renames or copies a Python module into factoryline/
  When the mutation gate parses the fixed NUL-delimited diff
  Then it creates coverage rows for each destination path under factoryline/
  And it preserves deletion-impact rows for source paths removed from factoryline/
  And it blocks if Git's change record cannot be fully classified

Scenario: Candidate cannot replace the required gate controller
  Given a pull request changes the mutation workflow or controller files
  When the mutation gate evaluates the pull request
  Then the authoritative result is produced by implementation loaded from the protected base or protected control repository
  And a check emitted only by candidate-controlled workflow configuration is not accepted as required evidence

Scenario: Missing trusted check source remains incomplete
  Given repository protection does not pin the required mutation check to the trusted controller identity
  When merge-enforcement state is read back
  Then the mutation gate reports INCOMPLETE
  And it does not claim the result is merge-enforced

Scenario: Bootstrap cannot consume its own mapping
  Given the base commit has no oracle map
  And a pull request adds the oracle map
  When the gate is enabled for the candidate
  Then changed production sources remain BLOCKED
  And the gate does not consume the candidate's newly added map

Scenario: Deleted production module needs separate impact review
  Given a pull request deletes factoryline/legacy.py
  When the mutation gate runs
  Then it returns BLOCKED and lists the deleted path
  And it does not claim mutation evidence covers the deletion

Scenario: Mapped behavior survives mutation
  Given a changed source has a valid base-commit mapping to an unchanged oracle
  When one or more generated mutants survive or the report is incomplete
  Then the gate returns BLOCKED and preserves the survivor evidence

Scenario: No eligible Python changes
  Given a pull request changes no production Python source under factoryline/
  When the mutation gate runs
  Then the receipt state is NOT_APPLICABLE
  And the receipt does not claim behavioral adequacy
```

## SHOULD - Technical/structural
- The GitHub Actions workflow configuration in scope is `.github/workflows/mutation-audit.yml`; it is candidate-controlled input and is never itself proof that the trusted controller ran.
- Oracle map: `.factory/mutation-oracles.json`, read from the PR base commit, with exactly one row per source: `{source, requirement_id, oracle_files:[{path,sha256}], harness_lock:{path,sha256}}`. Each row requires 1 to 20 oracle files. Every field is bounded and exact-schema validated.
- Harness lock: `.factory/mutation-harness-lock.json`, read from the same trusted PR base commit, with one exact-schema profile per supported runtime. Each profile lists the oracle-specific transitive harness closure and hashes, all applicable `conftest.py` and repository helper files, configuration files, enabled plugin identities, fixed command and environment, runtime image/digest, and hash-pinned wheel filenames. Dynamic imports, ambient plugin discovery, unbounded environment reads, network-fetched dependencies, or unresolved harness inputs block that profile.
- Bootstrap order is mandatory: (1) a baseline-only PR adds the initial reviewed oracle map, harness lock, and review artifact without changing production, test, helper, or runtime configuration files; (2) a later gate-implementation PR adds the runner/workflow and reads the already-merged map and lock; (3) subsequent PRs use only the base-commit versions. Candidate-added/changed oracles and harness inputs are excluded from same-PR mutation execution and become eligible only after merge plus separate specialty-AI review over their exact hashes.
- The workflow compares trusted event base/head snapshots with a fixed invocation equivalent to `git diff --find-renames=50% --find-copies=50% --find-copies-harder --name-status -z BASE_SHA HEAD_SHA -- .`; it parses NUL-delimited records, includes destination paths under `factoryline/`, treats deleted Python paths as deletion-impact rows, and blocks on any unrecognized or unresolved record. It does not trust caller-provided source/test lists on pull requests.
- Assemble a disposable execution tree from candidate `factoryline/` source paths and base-SHA locked test/harness inputs. Prevent Python import resolution from finding candidate test/config copies; pass configuration explicitly and disable ambient pytest plugin autoload. If the runner cannot prove which bytes and plugins were loaded, return `BLOCKED`.
- Initial limits: at most 10 changed production modules, 20 oracle files per module, 2 MiB per oracle, 20 minutes total across all source runs, and a 30-minute job timeout. Exceeding any limit is `BLOCKED`, not partial `PASS`.
- Receipt and logs are evidence artifacts from the trusted controller. They bind controller source identity, expected check-app identity, source diff records, base/head snapshots, oracle-map and harness-lock digests, every loaded harness path/hash, candidate harness-change paths, tool/runtime/dependency identity, and observed execution. A local receipt or uploaded artifact alone does not prove GitHub signer identity, branch protection, or merge approval. Container controls reduce exposure but do not claim protection against a kernel or container-runtime escape.
- Ordinary unit tests remain enabled. Replacement is explicitly out of scope until a blinded holdout benchmark demonstrates equivalent detection for a narrowly named behavior class.

## SHOULD NOT - Implementation details
- Do not make a new top-level CLI group.
- Do not update branch protection, release policy, package versions, provider settings, or external platforms as part of this feature.
- Do not add languages other than Python in this increment.
- Do not infer statistical independence or correctness from reviewer/model agreement.
