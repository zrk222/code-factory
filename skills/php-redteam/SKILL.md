---
name: php-redteam
description: Static PHP red-team pass — taint-tracked detection of RCE, file write, object injection, SQLi, XSS and auth/crypto weakness, with safe fixes and a report. Use when auditing, reviewing, or hardening PHP, or when a bug report smells like taint reaching a sink.
---

# PHP red team

Run a real attack pass over PHP, fix what is safe to fix, and report the rest.

## When to use

- Auditing a PHP app, plugin, or theme.
- Reviewing a diff that touches `include`, `eval`, `unserialize`, SQL, or `echo`.
- Hardening a legacy tree before it goes public.

Skip for a one-line config tweak with no taint.

## Loop

Run from this skill directory.

1. **Scope** — list the PHP to cover. Exclude `vendor/`, `node_modules/`, `.git/` (already skipped).
2. **Scan** — `php phprt.php scan <path> --json > out.json`.
3. **Triage high** — every `high` is a plausible unauthenticated path to RCE, file write, object
   injection, or SQLi. For each: follow the variable to its source, check for a prefix/allowlist/
   `realpath` guard, check  it is reachable without auth.
4. **Fix**
   - `php phprt.php fix <path>` (dry run) then `--write` for the safe rewrites.
   - Finish the rest by hand from each `fix:` line.
5. **Verify** — `php -l` every touched file, re-scan to zero high.
6. **Report** — `php report.php out.json "<target>" > report.md`, then fill the accepted-risk
   section.

## Severity policy

| Band | Meaning | Ship-blocking |
| --- | --- | --- |
| high | unauth RCE, file write, object injection, SQLi | yes |
| medium | XSS, auth weakness, crypto misuse, upload | yes before public |
| low | hardening, config | no |
| info | suppressed-I/O style | no |

## Attack classes encoded

RCE: include/require taint, eval, dynamic callbacks, shell exec, preg_replace/e,
create_function, unserialize. Files: traversal, upload without extension check. SQL:
concatenation, literal interpolation, ORDER BY/LIMIT. Output: reflected XSS, attribute context.
Auth: type-juggled compare, md5/sha1 passwords, weak RNG, session fixation, cookie flags. Crypto:
hardcoded secrets, mcrypt, ECB/fixed IV, disabled TLS verify. Hardening: display_errors, extract,
suppressed I/O, 0777.

## Rules of engagement

- Read-only until `--write`. Back up an unfamiliar tree first.
- A hit is a lead, not proof. Follow the taint before calling it exploitable.
- Do not "fix" `vendor/` — patch upstream or pin.
- An unsafe autofix is worse than none: leave it to a human and say why.

## Exit codes

`0` clean, `1` findings, `2` usage/IO error. CI-ready as-is.

## Tool reference

Requires PHP 8.1+ with `tokenizer`. No application boot or network is needed.

```sh
php phprt.php rules
php phprt.php scan <path>
php phprt.php scan <path> --json
php phprt.php scan <path> --min=high
php phprt.php fix <path>             # dry run
php phprt.php fix <path> --write     # explicitly authorized writes only
php report.php scan.json "my app" > report.md
php tests.php
```

Token rules use bounded source/sink windows; source rules match configuration
literals and crypto/TLS shapes. These heuristics do not prove general dataflow,
reachability, exploitability, authorization or the absence of vulnerabilities.
Escaped-output contexts suppress selected findings, not every possible XSS case.

The fixer rewrites `display_errors`, `0777` permissions and simple reflected
superglobal output, and annotates `mcrypt_encrypt`. Review every proposed change;
PHP lint checks syntax, not semantic correctness. Other findings need manual repair.

`lib/Engine.php` owns scanning, `lib/php-rules.php` the rule catalogue,
`phprt.php` CLI/fixes, `report.php` Markdown output. `tests.php` checks the seeded
`samples/vuln.php`, safe controls and fix syntax. The sample is intentionally
vulnerable and must never be served or executed as an application.

Earlier PR notes reported runs on DVWA and phpseclib. Those are historical,
exposed observations, not fresh accuracy benchmarks or evidence for this revision.
The removed PR/tool prose remains in Git history; this is the single usage owner.
