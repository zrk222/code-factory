# phprt — PHP red-team scanner and fixer

Static red-team pass over PHP: taint-tracked detection of the attack classes that actually land
RCE, file write, SQLi and object injection, plus safe automatic fixes and a report generator.

No PHP extensions beyond `tokenizer`. Comments and strings are handled by the real lexer, so a
rule never fires on prose.

## Use

```sh
php phprt.php rules                                  # what it looks for, by severity
php phprt.php scan <path>                            # human output
php phprt.php scan <path> --json                     # machine output
php phprt.php scan <path> --min=high                 # triage only ship-blockers
php phprt.php fix  <path>                            # dry run: what it would change
php phprt.php fix  <path> --write                    # apply the safe rewrites
php report.php scan.json "my app" > report.md        # report from a scan
```

Exit codes: `0` clean, `1` findings, `2` usage/IO error — so it drops into CI unchanged.

## Severity

| Band | Meaning | Blocks a ship |
| --- | --- | --- |
| high | unauth RCE, file write, object injection, SQLi | yes |
| medium | XSS, auth weakness, crypto misuse, upload | yes before public |
| low | hardening, config | no |
| info | style-level (suppressed I/O) | no |

## How detection works

Two strategies, both taint-first:

- **token** — walks the lexer stream and requires a superglobal (`$_GET $_POST $_REQUEST $_COOKIE
  $HTTP_*_VARS`, or `$_FILES` for uploads) within a bounded window of the sink. Backward scan
  catches `echo $_GET[...]`, forward scan catches `include $page` where `$page` is tainted.
- **source** — regex only where tokens add nothing (config literals, TLS flags, `md5($password)`
  shapes).

False positives are suppressed structurally, not with a mute list: an `echo` whose target is
wrapped in `htmlspecialchars` / `htmlentities` / `esc_html` / `intval` / `json_encode` does not
fire, and `addslashes`/`mcrypt` only fire when they are the sink.

## Fixes it writes

Only unambiguous cases, each re-linted by PHP:

- `display_errors` on → `ini_set('display_errors', '0')`
- `chmod(..., 0777)` → `0755`
- `echo $_GET[x];` → wrapped in `htmlspecialchars(..., ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`
- `mcrypt_encrypt(` → tagged with a TODO to move to `openssl_encrypt` AES-256-GCM

Everything else gets a `fix:` line and is left to a human, because a wrong autofix is worse than
none.

## Validate

```sh
php phprt.php scan samples/vuln.php          # 23 findings, every class present
php phprt.php scan samples/vuln.php --json > out.json
php report.php out.json "samples" > report.md
```

`samples/vuln.php` contains one instance of every high class and a safe-control block at the end
that must stay silent.

## Limits

- Static: reachability is proven, exploitability is not. Follow the taint before claiming a hit.
- `vendor/`, `node_modules/`, `.git/` are skipped.
- Backed by rule knowledge, not a CVE feed; no version- or framework-specific checks yet.
- Works on PHP 8.1+. `tokenizer` must be enabled (it is by default).
