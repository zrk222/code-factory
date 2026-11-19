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
