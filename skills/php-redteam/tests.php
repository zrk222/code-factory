<?php
declare(strict_types=1);

/**
 * Self-test. Asserts every rule fires on its sample and the safe controls stay
 * silent. Run: php tests.php   (exit 0 = all pass)
 */

require __DIR__ . '/phprt.php';

$rules = array_merge(require __DIR__ . '/lib/php-rules.php', require __DIR__ . '/lib/framework-rules.php');
$scanner = new Scanner($rules);
$src = file_get_contents(__DIR__ . '/samples/vuln.php');
$found = [];
foreach ($scanner->scanFile('v.php', $src) as $f) {
    $found[$f->rule][] = $f->line;
}

$mustFire = [
    'RCE-001' => 6, 'RCE-002' => 8, 'RCE-003' => 10, 'RCE-004' => 12, 'RCE-007' => 14,
    'FILE-001' => 16, 'SQL-001' => 20, 'SQL-002' => 22, 'SQL-003' => 23,
    'XSS-001' => 25, 'AUTH-001' => 29, 'AUTH-002' => 28, 'AUTH-003' => 30,
    'AUTH-005' => 31, 'CRYPT-001' => 33, 'CRYPT-002' => 34, 'CRYPT-004' => 37,
    'HARD-001' => 39, 'HARD-003' => 41, 'HARD-005' => 40, 'XSS-002' => 43,
];

$fail = 0;
foreach ($mustFire as $rule => $line) {
    if (!isset($found[$rule])) {
        echo "MISS  $rule (expected at line $line)\n";
        $fail++;
        continue;
    }
    if (!in_array($line, $found[$rule], true)) {
        echo "LINE  $rule fired at " . implode(',', $found[$rule]) . " not $line\n";
        $fail++;
    }
}

$silent = [26 => ['XSS-001'], 48 => ['SQL-001'], 50 => ['AUTH-002'], 51 => ['AUTH-003']];
foreach ($silent as $line => $banned) {
    foreach ($banned as $rule) {
        if (isset($found[$rule])
            && in_array($line, $found[$rule], true)) {
            echo "FP    $rule fired on safe line $line\n";
            $fail++;
        }
    }
}

$fwRules = require __DIR__ . '/lib/framework-rules.php';
$fwScanner = new Scanner($fwRules);
$fwSrc = file_get_contents(__DIR__ . '/samples/framework.php');
$fwFound = [];
foreach ($fwScanner->scanFile('f.php', $fwSrc) as $f) {
    $fwFound[$f->rule][] = $f->line;
}
foreach (['WP-001' => 8, 'WP-002' => 6, 'WP-003' => 11, 'WP-004' => 14, 'WP-007' => 22,
    'LAR-001' => 25, 'LAR-002' => 8, 'LAR-003' => 28, 'LAR-004' => 29, 'LAR-005' => 30,
    'SYM-001' => 33, 'SYM-002' => 34, 'SYM-003' => 35, 'SYM-004' => 36] as $rule => $line) {
    if (!isset($fwFound[$rule]) || !(in_array($line, $fwFound[$rule], true) || in_array($line + 1, $fwFound[$rule], true))) {
        echo "FW    $rule missing at $line (fired: " . implode(',', $fwFound[$rule] ?? []) . ")\n";
        $fail++;
    }
}
if (isset($fwFound['WP-001']) && (in_array(9, $fwFound['WP-001'], true) || in_array(10, $fwFound['WP-001'], true))) {
    echo "FP    WP-001 fired on esc_html control\n";
    $fail++;
}
$fixed = $src;
foreach ($scanner->scanFile('v.php', $fixed) as $f) {
    $fixed = applyFix($f, $fixed) ?? $fixed;
}
$after = count($scanner->scanFile('v.php', $fixed));
$before = count($scanner->scanFile('v.php', $src));
if ($after >= $before) {
    echo "FIX   no reduction ($before -> $after)\n";
    $fail++;
}
$tmp = tempnam(sys_get_temp_dir(), 'phprt');
file_put_contents($tmp, $fixed);
$lintOut = [];
$lintCode = 0;
exec(PHP_BINARY . ' -l ' . escapeshellarg($tmp) . ' 2>&1', $lintOut, $lintCode);
unlink($tmp);
if ($lintCode !== 0) {
    echo 'LINT  fixed file does not parse: ' . implode(' ', $lintOut) . "\n";
    $fail++;
}

$regressions = [
    ['XSS-001', '<?php htmlspecialchars($other); echo $_GET["x"];', true, 1],
    ['WP-001', '<?php esc_html($other); echo $_GET["x"];', true, 1],
    ['XSS-001', '<?php echo $_GET["x"]; htmlspecialchars($other);', true, 1],
    ['WP-001', '<?php echo $_GET["x"]; esc_html($other);', true, 1],
    ['XSS-001', '<?php echo htmlspecialchars($_GET["x"]);', false, 1],
    ['WP-001', '<?php echo esc_html($_GET["x"]);', false, 1],
    ['XSS-001', '<?php echo $_GET["x"] . htmlspecialchars($other);', true, 1],
    ['WP-001', '<?php echo esc_html($other) . $_GET["x"];', true, 1],
    ['SQL-001', '<?php $id = $_GET["id"];' . "\n" . '$db->query("SELECT * FROM t WHERE id = " . $id);', true, 2],
    ['SQL-001', '<?php $db->query("SELECT * FROM t");', false, 1],
    ['RCE-004', '<?php \\system($_GET["cmd"]);', true, 1],
    ['RCE-007', '<?php \\unserialize($_POST["data"]);', true, 1],
    ['FILE-001', '<?php \\file_get_contents($_GET["path"]);', true, 1],
    ['RCE-004', '<?php \\Custom\\system($_GET["cmd"]);', false, 1],
    ['RCE-004', '<?php Custom\\system($_GET["cmd"]);', false, 1],
];
foreach (['/p/e', '/p/ei', '/p/ie', '#p#e', '{p}e', '/p/i', '#e#i'] as $pattern) {
    $regressions[] = ['RCE-005', '<?php preg_replace(' . var_export($pattern, true) . ', $_GET["r"], $subject);', str_ends_with($pattern, 'e') || str_ends_with($pattern, 'ei'), 1];
}
foreach ($regressions as [$rule, $source, $expected, $line]) {
    $actual = array_filter($scanner->scanFile('regression.php', $source),
        fn (Finding $f): bool => $f->rule === $rule && $f->line === $line);
    if (($actual !== []) !== $expected) {
        echo "REGRESSION $rule exact line $line expected " . ($expected ? 'finding' : 'silent') . "\n";
        $fail++;
    }
}
$unterminated = '<?php preg_replace(\'' . str_repeat('\\', 10000);
$patternScanner = new Scanner(array_values(array_filter($rules, fn (Rule $r): bool => $r->id === 'RCE-005')));
$patternScanner->scanFile('unterminated.php', $unterminated);
if (preg_last_error() !== PREG_NO_ERROR) {
    echo "REGRESSION unterminated escaped pattern exceeded regex limits\n";
    $fail++;
}
$callback = array_values(array_filter($rules, fn (Rule $r): bool => $r->id === 'RCE-003'))[0];
if (!str_contains($callback->fix, 'allowlist') || str_contains($callback->fix, 'if (function_exists')) {
    echo "REGRESSION callback remediation must require an allowlist\n";
    $fail++;
}
$unchanged = tempnam(sys_get_temp_dir(), 'phprt-stale-');
file_put_contents($unchanged, 'new bytes');
if (writeFixCandidate($unchanged, 'old bytes', 'replacement') || file_get_contents($unchanged) !== 'new bytes') {
    echo "REGRESSION stale source was overwritten\n";
    $fail++;
}
unlink($unchanged);
$rewriteCases = [
    ["<?php ini_set('display_errors', 1); save_order(\$order);\n", "<?php ini_set('display_errors', '0'); save_order(\$order);\n", 1],
    ["<?php if (ready()) { ini_set('display_errors', 1); save_order(\$order); }\n", "<?php if (ready()) { ini_set('display_errors', '0'); save_order(\$order); }\n", 1],
    ["<?php chmod(\$dir, 0777); \$reference = '07771234';\n", "<?php chmod(\$dir, 0755); \$reference = '07771234';\n", 1],
    ['<?php $example = "ini_set(\'display_errors\', 1);";', '<?php $example = "ini_set(\'display_errors\', 1);";', 0],
    ["<?php\necho \$_GET['x'];\nbroken(;\n", "<?php\necho \$_GET['x'];\nbroken(;\n", 2],
];
foreach ($rewriteCases as [$source, $expected, $exit]) {
    $tmp = tempnam(sys_get_temp_dir(), 'phprt-regression-');
    file_put_contents($tmp, $source);
    $output = [];
    exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/phprt.php')
        . ' fix ' . escapeshellarg($tmp) . ' --write 2>&1', $output, $code);
    if (file_get_contents($tmp) !== $expected || $code !== $exit) {
        echo "REWRITE preservation/exit regression: expected $exit, got $code\n";
        $fail++;
    }
    unlink($tmp);
}

echo $fail === 0 ? "OK: all assertions passed\n" : "FAILED: $fail assertion(s)\n";
exit($fail === 0 ? 0 : 1);
