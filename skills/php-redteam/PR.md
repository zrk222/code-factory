# phprt — PHP red-team skill and scanner

## What this adds

A repeatable PHP attack pass: a tokenizer-based, taint-tracked scanner over the classes that
actually land RCE, file write, object injection and SQLi; safe autofixes for the unambiguous
cases; a report generator; and a skill that encodes the workflow and the rules of engagement.

Static only. No PHP needed beyond `tokenizer`, no app boot, no network.

## Why token-based

Regex over PHP matches prose. This walks the real lexer, so `include $_GET['page']` inside a
comment never fires, and a superglobal is only a hit when it reaches a sink within a bounded
window. Handling of quotes, heredocs and interleaved HTML is the engine's job, not a pattern's.

## What it finds

High: include/require taint, eval, dynamic callbacks, shell exec, `preg_replace`/e,
`create_function`, `unserialize`, traversal, SQLi, session fixation, hardcoded secrets.
Medium: reflected XSS (script and attribute context), upload without extension check,
type-juggled hash compare, md5/sha1 passwords, weak RNG, cookie flags, mcrypt, ECB/fixed IV,
disabled TLS verify, 0777.
Low/info: `display_errors`, `extract`, suppressed I/O.

## What it fixes

Only unambiguous rewrites, each re-linted: `display_errors` off, `0777`→`0755`,
`echo $_GET[x];`→`htmlspecialchars(...)`, and a TODO tag on `mcrypt_encrypt`. Everything else
gets a `fix:` line because a wrong autofix is worse than none.

## Verification

- `php skills/php-redteam/tests.php` — asserts every rule fires on its sample line, asserts four
  safe controls stay silent, asserts the fix pass reduces the count, and lints the result with
  `php -l`. Passes.
- `samples/vuln.php` has one instance of every high class plus a safe-control block.

Real-world check, unmodified checkout of DVWA (169 PHP files, deliberately vulnerable):

- 22 findings: 8 high, 13 medium, 1 low.
- The 8 highs are all genuine: session fixation in `dvwaPage.inc.php`, token compare,
  three hardcoded-secret hits, traversal in `view_source_all.php`, and the low/medium uploads.
- Discrimination holds on the upload ladder: `low.php` and `medium.php` fire both FILE-003 and
  HARD-006; `high.php` and `impossible.php`, which guard the extension, stay silent.
- phpseclib (611 files, not vulnerable): 16 findings, none high-and-wrong; the noise is
  suppressed-I/O style and test keys.

## Files

- `SKILL.md` — the workflow, severity policy, engagement rules.
- `phprt.php` — CLI (`rules`, `scan`, `fix`); exit 0/1/2 is CI-ready.
- `lib/Engine.php` — lexer walker, matcher, scanner, escaping/safe-context checks.
- `lib/php-rules.php` — rule catalogue.
- `report.php` — JSON scan to markdown report.
- `tests.php`, `samples/vuln.php` — regression coverage.
- `TOOL.md` — tool usage.

## Limits

- Static: it proves reachability, not exploitability. Taint must be followed by hand.
- No version- or framework-specific checks yet (no Symfony, Laravel or WP sinks).
- `vendor/`, `node_modules/`, `.git/` skipped by design.
