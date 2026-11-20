<?php
declare(strict_types=1);

/**
 * Rule catalogue. Taint-first: a sink only fires when a superglobal reaches it.
 *
 * `requireAny` is the OR set of taint sources. `requires` is the ordered AND set
 * used where the sink alone is ambiguous (e.g. ORDER BY needs the SQL keyword).
 * `skipIf` suppresses a known-safe shape.
 */

$u = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$HTTP_GET_VARS', '$HTTP_POST_VARS'];

$rule = static function (
    string $id, string $sev, string $title, array $anyOf, int $window,
    string $why, string $fix, string $cwe,
    array $requires = [], array $skipIf = [], ?array $requireAny = null
) use ($u): Rule {
    return new Rule($id, $sev, $title, 'token', $anyOf, $requires, $window, $why, $fix, $cwe,
        $skipIf, $requireAny ?? $u);
};

$srcRule = static fn (
    string $id, string $sev, string $title, array $anyOf,
    string $why, string $fix, string $cwe
) => new Rule($id, $sev, $title, 'source', $anyOf, [], 0, $why, $fix, $cwe);

return [
    // ---------------------------------------------------------------- RCE
    $rule('RCE-001', 'high', 'include/require on user input',
        ['T_INCLUDE', 'T_INCLUDE_ONCE', 'T_REQUIRE', 'T_REQUIRE_ONCE'], 12,
        'A superglobal decides which file is loaded. Without a prefix check this is local or remote file inclusion and usually straight to code execution.',
        "Constrain the path: \$page = basename(\$_GET['page']); require __DIR__ . '/pages/' . \$page . '.php';"
        . ' For a whitelist use in_array() against a known array.',
        'CWE-98'),

    $rule('RCE-002', 'high', 'eval() on user input',
        ['eval'], 14,
        'eval executes whatever string it is given. Any superglobal reaching it is remote code execution.',
        'Prefer a whitelist dispatcher over eval. If eval is required, never pass raw $_GET/$_POST.',
        'CWE-95'),

    $rule('RCE-003', 'high', 'call_user_func with user-controlled callback',
        ['call_user_func', 'call_user_func_array'], 10,
        'The callback name comes from the request. An attacker can invoke any function, including system/exec/passthru.',
        'Map the requested action to a fixed allowlist of approved callables. Reject unknown actions; function_exists is not authorization.',
        'CWE-470'),

    $rule('RCE-004', 'high', 'command execution on user input',
        ['exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open'], 10,
        'Shell metacharacters (; | && $( )) in a superglobal run as a second command.',
        "escapeshellarg(\$_GET['x']) for values, escapeshellcmd() for the whole line."
        . ' For arguments prefer the array form of proc_open.',
        'CWE-78'),

    $srcRule('RCE-005', 'high', 'preg_replace /e modifier',
        ['~\bpreg_replace\s*\(\s*([\'"])((?:\\\\.|(?!\1)[^\\\\])*)\1~s'],
        'The /e modifier evaluates the replacement as PHP. Removed in PHP 7, but legacy code still relies on it.',
        'Move to preg_replace_callback().',
        'CWE-95'),

    $rule('RCE-006', 'medium', 'create_function()',
        ['create_function'], 12,
        'create_function compiles its body at runtime and shares the eval pitfalls.',
        'Replace with a named function or a closure.',
        'CWE-95'),

    $rule('RCE-007', 'high', 'unserialize() on user input',
        ['unserialize'], 10,
        'Object injection: any __wakeup/__destruct in the autoload graph runs. A POP chain means file write or RCE.',
        "unserialize(\$data, ['allowed_classes' => [MyClass::class]]) or json_decode for plain data.",
        'CWE-502'),

    // ------------------------------------------------------- file and path
    $rule('FILE-001', 'high', 'file read/write path from user input',
        ['file_get_contents', 'file_put_contents', 'fopen', 'readfile', 'unlink', 'rename', 'copy', 'move_uploaded_file'], 10,
        'The path is attacker-influenced. `../` escapes the intended directory, and absolute paths leak or overwrite files.',
        "realpath() or basename() the input, then require a prefix: if (!str_starts_with(realpath(\$p), \$root)) { reject(); }",
        'CWE-22'),

    $rule('FILE-003', 'medium', 'upload handling without extension check nearby',
        ['move_uploaded_file'], 20,
        'The uploaded temp file is the source. Without an extension or MIME check a .php lands in the webroot.',
        'Whitelist extensions against pathinfo($name, PATHINFO_EXTENSION), re-detect MIME with finfo, and store outside the webroot when possible.',
        'CWE-434', [], [], ['$_FILES']),

    // ------------------------------------------------------------- SQL
    $srcRule('SQL-001', 'high', 'query built by concatenation',
        ['/(?:mysql_(?:query|real_escape_string)|mysqli_query|->query|->exec|pg_query)\s*\(\s*[\'"][^\'"]*[\'"]\s*\.\s*\$/',
         '/[\'"][^\'"]*(?:SELECT|INSERT|UPDATE|DELETE)[^\'"]*[\'"]\s*\.\s*\$[A-Za-z_]/i'],
        'String interpolation into SQL. A quote in the value breaks out of the literal.',
        'Prepared statements (PDO with bound params, or mysqli_stmt). If concatenating, cast to int or run real_escape_string.',
        'CWE-89'),

    $srcRule('SQL-002', 'medium', 'superglobal interpolated into a SQL string literal',
        ['/(?:SELECT|INSERT|UPDATE|DELETE|WHERE|LIMIT|ORDER BY).*?\{?\$_(?:GET|POST|REQUEST|COOKIE)/i'],
        'The value sits inside the SQL literal. Escaping is easy to forget and varies by driver.',
        'Bind the parameter. Keep the SQL text static.',
        'CWE-89'),

    $srcRule('SQL-003', 'high', 'ORDER BY / LIMIT from user input',
        ['/(?:ORDER\s+BY|LIMIT)\s*[\'"]?\s*\.\s*\$_/i'],
        'Column names and directions cannot be bound as parameters; they must be allowlisted.',
        "in_array(\$col, ['id','name','created'], true) and cast LIMIT with (int).",
        'CWE-89'),

    $rule('SQL-004', 'medium', 'addslashes() as the only SQL defence',
        ['addslashes'], 8,
        'addslashes is not character-set aware and adds quotes around the value in the SQL, so underflowing values still break out.',
        'Prefer prepared statements; if escaping, use the driver escape (real_escape_string) and quote in SQL.',
        'CWE-89', [], [], []),

    // --------------------------------------------------------- output/XSS
    $rule('XSS-001', 'medium', 'superglobal echoed without escaping',
        ['T_ECHO', 'T_PRINT'], 6,
        'Reflected XSS: the value prints straight into the response.',
        "htmlspecialchars(\$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') at the sink, or rely on a template engine autoescape.",
        'CWE-79', [], ['htmlspecialchars', 'htmlentities', 'esc_html', 'esc_attr', 'intval', 'absint', 'json_encode']),


    $srcRule('XSS-002', 'medium', 'attribute value from superglobal',
        ['/<[a-z][^>]*=[^>]*<\?php\s+(?:echo|print)\s+\$_(?:GET|POST|REQUEST|COOKIE)/i'],
        'Inside an attribute an unescaped quote ends the attribute, so an attacker injects new attributes or a handler.',
        'Escape at the sink; htmlspecialchars with ENT_QUOTES covers both quote styles.',
        'CWE-79'),

    // --------------------------------------------------------- auth/session
    $srcRule('AUTH-001', 'high', 'loose comparison on a hash or token',
        ['/\$[^;\s]*\s*(?:===?|!==?)\s*\$[A-Za-z_]*(?:hash|token|password|secret|sig)[A-Za-z_]*\b/i'],
        'Using == on hash strings allows type juggling (0e123 == 0e456) and is not constant time.',
        'hash_equals($known, $given) for any secret compare.',
        'CWE-697'),

    $rule('AUTH-002', 'medium', 'md5/sha1 used for passwords',
        ['md5', 'sha1'], 12,
        'md5 and sha1 are fast, so offline cracking is cheap on a leaked dump.',
        'password_hash($pw, PASSWORD_DEFAULT) and password_verify().',
        'CWE-916', [], [], ['$password']),

    $rule('AUTH-003', 'medium', 'mt_rand used for a secret',
        ['mt_rand', 'rand'], 12,
        'mt_rand is predictable once a few outputs are seen.',
        'random_int() or random_bytes() for anything security-relevant.',
        'CWE-338', [], [], ['$token']),

    $srcRule('AUTH-004', 'high', 'session id taken from the request',
        ['/session_id\s*\(\s*\$_/'],
        'Accepting a client-chosen session id permits fixation.',
        'Call session_regenerate_id(true) after a successful login.',
        'CWE-384'),

    $srcRule('AUTH-005', 'medium', 'no SameSite / Secure flags on setcookie',
        ['/setcookie\s*\((?:(?!\b(?:secure|samesite)\b)[^)])*\)/i'],
        'Default cookies travel on plain HTTP and cross-site, widening interception and CSRF.',
        "setcookie(\$n, \$v, ['secure' => true, 'httponly' => true, 'samesite' => 'Lax']);",
        'CWE-614'),

    // ------------------------------------------------------ config/crypto
    $srcRule('CRYPT-001', 'high', 'hardcoded secret or key',
        ['/\$(?:password|passwd|pwd|secret|api_?key|token|priv(?:ate)?_?key)\s*=\s*[\'"][^\'"]{6,}[\'"]/i'],
        'A literal credential ships with the source, and in a public repo it is already leaked.',
        'Move to an env var read via getenv()/$_ENV and keep a .env.example in the repo.',
        'CWE-798'),

    $rule('CRYPT-002', 'medium', 'mcrypt_* still in use',
        ['mcrypt_encrypt', 'mcrypt_decrypt'], 6,
        'mcrypt is removed in PHP 7.2 and its padding differs from standard.',
        'openssl_encrypt/openssl_decrypt with AES-256-GCM.',
        'CWE-327', [], [], []),

    $srcRule('CRYPT-003', 'medium', 'openssl_encrypt with ECB or a fixed IV',
        ['/openssl_encrypt\s*\([^)]*ecb/i',
         '/openssl_(?:en|de)crypt\s*\([^)]*[\'"][A-Za-z0-9+\/=]{8,}[\'"]/i'],
        'ECB leaks block structure; a fixed IV makes ciphertexts deterministic and re-usable.',
        'Use AES-256-GCM (or CBC) with random_bytes(16) as the IV, stored alongside the ciphertext.',
        'CWE-329'),

    $srcRule('CRYPT-004', 'medium', 'TLS verification disabled',
        ['/CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)\b/i', '/ssl\s*=>\s*(?:false|0)\b/i',
         '/verify_peer(?:_name)?\s*[\'"]?\s*=>\s*false/i'],
        'Any certificate is accepted, so a MITM on the network reads or rewrites the exchange.',
        'Leave verify_peer true and ship a CA bundle (curl.cainfo / openssl.cafile).',
        'CWE-295'),

    // --------------------------------------------------------- hardening
    $srcRule('HARD-001', 'low', 'error reporting left on',
        ['/display_errors["\x27]?\s*[,=>]+\s*["\x27]?(?:1|true|On|E_ALL)/i'],
        'Stack traces and paths render to visitors in production.',
        'display_errors=Off in php.ini, log_errors=On, and a custom error handler.',
        'CWE-209'),

    $srcRule('HARD-003', 'low', 'extract() on a superglobal',
        ['/extract\s*\(\s*\$_/'],
        'extract overwrites local variables a caller already set — classic variable overloading.',
        'extract($_GET, EXTR_SKIP) or be explicit about the keys.',
        'CWE-621'),

    $srcRule('HARD-004', 'info', 'suppressed errors on I/O',
        ['/(?<![\w>$])@(?:fopen|unlink|rename|file_get_contents|mkdir|copy|include)/'],
        'A suppressed error hides a failed write, and the code continues with a false path.',
        'Check the return value and throw, or log the message.',
        'CWE-391'),

    $srcRule('HARD-005', 'medium', 'world-writable permissions',
        ['/chmod\s*\([^)]*0777/'],
        'World-writable files and directories let any local user replace them.',
        '0755 for directories and 0644 for files; 0700 only where the server owns them.',
        'CWE-732'),

    $rule('HARD-006', 'high', 'PHP execution in an upload directory (guard)',
        ['move_uploaded_file'], 24,
        'Nothing checks the extension, so a .php upload is served and executed.',
        'Append an allowlist: in_array(strtolower(pathinfo($name, PATHINFO_EXTENSION)), [\'jpg\',\'png\',\'pdf\'], true).',
        'CWE-434', [], ['in_array', 'PATHINFO_EXTENSION'], ['$_FILES']),
    // -------------------------- type juggling (PayloadsAllTheThings)
    $srcRule('JUGG-001', 'high', 'loose == on a user-controlled value',
        ['/$[A-Za-z_]\w*\s*==\s*$_|$_\w*\s*==\s*$[A-Za-z_]/'],
        'PHP type juggling: "0e123" == "0e456" is true, so any magic-hash input matches. md5([]) is NULL too.',
        'Use === or hash_equals(); cast to int before comparing ints.',
        'CWE-697'),

    $srcRule('JUGG-002', 'high', 'strcmp / non-strict in_array',
        ['/strcmp\s*\(\s*$_/', '/in_array\s*\([^,]+,[^,]+\)(?!\s*,\s*true)/'],
        'strcmp(array) returns NULL, and in_array without the third argument compares loosely.',
        'Compare with ===, and always pass true as the third in_array argument.',
        'CWE-697'),

    // ------------------------------------------------ SSTI (Twig / Smarty)
    $srcRule('SSTI-001', 'high', 'user input rendered as a template',
        ['/$twig->render\s*\(\s*$_|$smarty->(?:display|fetch)\s*\(\s*$_/',
         '/(?:createTemplate|fromString)\s*\(\s*$_/'],
        'A user string compiled as template source executes template syntax. Probe {{7*7}} -> 49.',
        'Render a fixed template name and pass parameters, not a user-supplied template.',
        'CWE-1336'),

    // ------------------------------------- deserialization header trust
    $srcRule('DESER-001', 'high', 'serialized data accepted from the client',
        ['/unserialize\s*\(\s*$_(?:GET|POST|REQUEST|COOKIE)/',
         '/maybe_unserialize\s*\(\s*$_/'],
        'PHP serialized form is O:, a:, s:. Accepting it is object injection; a POP chain in the autoload graph runs on __wakeup/__destruct.',
        'unserialize($v, [\'allowed_classes\' => [Known::class]]) and never trust the type prefix alone.',
        'CWE-502'),

    // --------------------------------------------- LFI / RFI
    $srcRule('LFI-001', 'high', 'include of a request value',
        ['/include\s*\(?\s*$_(?:GET|POST|REQUEST|COOKIE)/'],
        'With allow_url_include a ?page=http://evil/shell.txt executes remotely. ../, %00 (PHP<5.3.4) and php://filter all apply.',
        'basename() plus an allowlist, or a realpath() prefix check inside a fixed directory.',
        'CWE-98'),

    // ------------------------------------------------------------- XXE
    $srcRule('XXE-001', 'high', 'XML parsed without entity protection',
        ['/simplexml_load_(?:string|file)\s*\(\s*$_/',
         '/new\s+DOMDocument[^;]*->load(?:XML)?\s*\(\s*$_/i'],
        'Default libxml on older builds expands external entities: <!ENTITY x SYSTEM "file:///etc/passwd"> leaks files.',
        'libxml_disable_entity_loader(true) before PHP 8, plus LIBXML_NOENT; otherwise set parser flags explicitly.',
        'CWE-611'),

    // ------------------------------------------------------------ SSRF
    $srcRule('SSRF-001', 'high', 'HTTP client fetches a request URL',
        ['/curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*$_/',
         '/file_get_contents\s*\(\s*$_/i'],
        'An attacker URL reaches the client: 169.254.169.254 metadata, localhost services, file:// via file_get_contents.',
        'Allowlist scheme and host; block link-local and loopback unless needed.',
        'CWE-918'),

    // ---------------------------------------------- error disclosure
    $srcRule('INFO-001', 'low', 'raw exception message printed',
        ['/die\s*\(\s*$e->getMessage\(\)/i', '/exit\s*\(\s*$e->getMessage\(\)/i'],
        'Driver, path and SQL detail renders to the visitor.',
        'Log $e and show a generic message; gate detail behind debug.',
        'CWE-209'),
];
