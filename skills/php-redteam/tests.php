<?php
declare(strict_types=1);

/**
 * Self-test. Asserts every rule fires on its sample and the safe controls stay
 * silent. Run: php tests.php   (exit 0 = all pass)
 */

require __DIR__ . '/lib/Engine.php';

$rules = array_merge(require __DIR__ . '/lib/php-rules.php', require __DIR__ . '/lib/framework-rules.php');
$scanner = new Scanner($rules);
$src = file_get_contents(__DIR__ . '/samples/vuln.php');
$found = [];
foreach ($scanner->scanFile('v.php', $src) as $f) {
    $found[$f->rule][] = $f->line;
}

$mustFire = [
    'RCE-001' => 6, 'RCE-002' => 8, 'RCE-003' => 10, 'RCE-004' => 12, 'RCE-007' => 14,
    'FILE-001' => 16, 'SQL-001' => 22, 'SQL-002' => 22, 'SQL-003' => 23,
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
    if (!in_array($line, $found[$rule], true) && !in_array($line + 1, $found[$rule], true)) {
        echo "LINE  $rule fired at " . implode(',', $found[$rule]) . " not $line\n";
        $fail++;
    }
}

$silent = [26 => ['XSS-001'], 48 => ['SQL-001'], 50 => ['AUTH-002'], 51 => ['AUTH-003']];
foreach ($silent as $line => $banned) {
    foreach ($banned as $rule) {
        if (isset($found[$rule])
            && (in_array($line, $found[$rule], true) || in_array($line + 1, $found[$rule], true))) {
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
    $fixed = applyFixForTest($f, $fixed) ?? $fixed;
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

echo $fail === 0 ? "OK: all assertions passed\n" : "FAILED: $fail assertion(s)\n";
exit($fail === 0 ? 0 : 1);

function applyFixForTest(Finding $f, string $src): ?string
{
    $lines = explode("\n", $src);
    $i = $f->line - 1;
    if (!isset($lines[$i])) {
        return null;
    }
    switch ($f->rule) {
        case 'HARD-005':
            if (str_contains($lines[$i], '0777')) {
                $lines[$i] = str_replace('0777', '0755', $lines[$i]);
                return implode("\n", $lines);
            }
            return null;
        case 'XSS-001':
            $p = '/(echo\s+)(\$_' . '(?:GET|POST|REQUEST|COOKIE)\[[^\]]+\])(\s*;)/';
            if (preg_match($p, $lines[$i], $m)) {
                $lines[$i] = str_replace($m[0],
                    $m[1] . "htmlspecialchars({$m[2]}, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')" . $m[3],
                    $lines[$i]);
                return implode("\n", $lines);
            }
            return null;
        case 'HARD-001':
            if (preg_match('/display_errors/i', $lines[$i])) {
                $lines[$i] = "ini_set('display_errors', '0');";
                return implode("\n", $lines);
            }
            return null;
    }
    return null;
}
