<?php
declare(strict_types=1);

/**
 * phprt — PHP red-team scanner and fixer.
 *
 * usage:
 *   php phprt.php scan  <path> [--json] [--min=low|medium|high]
 *   php phprt.php fix   <path> [--write]      safe, comment-tagged rewrites
 *   php phprt.php rules
 *
 * Exit codes: 0 clean, 1 findings, 2 usage/IO error.
 */

require_once __DIR__ . '/lib/Engine.php';

const SEV_ORDER = ['low' => 1, 'medium' => 2, 'high' => 3];

function usage(): never
{
    fwrite(STDERR, "usage: php phprt.php scan|fix|rules <path> [--json] [--write] [--min=low|medium|high]\n");
    exit(2);
}

/** @return list<Rule> */
function loadRules(): array
{
    $rules = require __DIR__ . '/lib/php-rules.php';
    return $rules;
}

/** @return list<string> */
function targetFiles(string $path): array
{
    if (is_file($path)) {
        return [$path];
    }
    if (!is_dir($path)) {
        fwrite(STDERR, "no such path: $path\n");
        exit(2);
    }
    $out = [];
    $it = new RecursiveIteratorIterator(
        new RecursiveCallbackFilterIterator(
            new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
            fn (SplFileInfo $f): bool => !in_array($f->getFilename(), ['vendor', 'node_modules', '.git'], true)
        )
    );
    foreach ($it as $f) {
        if ($f->isFile() && $f->getExtension() === 'php') {
            $out[] = $f->getPathname();
        }
    }
    sort($out);
    return $out;
}

function severityAtLeast(string $sev, string $min): bool
{
    return (SEV_ORDER[$sev] ?? 0) >= (SEV_ORDER[$min] ?? 1);
}

/** Relative path for stable output. */
function rel(string $base, string $file): string
{
    $base = rtrim(str_replace('\\', '/', $base), '/');
    $file = str_replace('\\', '/', $file);
    return str_starts_with($file, $base . '/') ? substr($file, strlen($base) + 1) : $file;
}

/**
 * Safe autofixes. Each returns the rewritten source or null when it does not
 * apply. Only unambiguous cases are rewritten; everything is marked so a
 * reviewer sees exactly what changed.
 */
function applyFix(Finding $f, string $source): ?string
{
    if (in_array($f->rule, ['HARD-001', 'HARD-005'], true)) {
        return literalArgumentFix($f, $source);
    }
    $lines = explode("\n", $source);
    $idx = $f->line - 1;
    if (!isset($lines[$idx])) {
        return null;
    }
    $line = $lines[$idx];

    switch ($f->rule) {
        case 'XSS-001':
            $pat = '/^(\s*echo\s+)(\$_' . '(?:GET|POST|REQUEST|COOKIE)\[[^\]]+\])(\s*;)\s*$/';
            if (preg_match($pat, $line, $m)) {
                $lines[$idx] = str_replace(
                    $m[0],
                    $m[1] . "htmlspecialchars({$m[2]}, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')" . $m[3],
                    $line
                );
                return implode("\n", $lines);
            }
            return null;

    }
    return null;
}

/** Replace only a lexer-identified literal argument; never rewrite its line. */
function literalArgumentFix(Finding $f, string $source): ?string
{
    $tokens = [];
    $offset = 0;
    $line = 1;
    foreach (token_get_all($source) as $token) {
        $text = is_array($token) ? $token[1] : $token;
        $kind = is_array($token) ? $token[0] : 0;
        if (!in_array($kind, [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
            $tokens[] = [$kind, $text, $line, $offset];
        }
        $line += substr_count($text, "\n");
        $offset += strlen($text);
    }
    $call = $f->rule === 'HARD-001' ? 'ini_set' : 'chmod';
    foreach ($tokens as $i => $token) {
        if ($token[2] !== $f->line || !in_array($token[0], [T_STRING, T_NAME_FULLY_QUALIFIED], true)
            || strtolower(ltrim($token[1], '\\')) !== $call || ($tokens[$i + 1][1] ?? '') !== '('
            || in_array($tokens[$i - 1][1] ?? '', ['->', '?->', '::', 'function', 'new'], true)) {
            continue;
        }
        $args = [[]];
        $depth = 0;
        for ($j = $i + 2; $j < count($tokens); $j++) {
            $text = $tokens[$j][1];
            if ($text === ')' && $depth === 0) {
                break;
            }
            if ($text === ',' && $depth === 0) {
                $args[] = [];
                continue;
            }
            $depth += in_array($text, ['(', '[', '{'], true) ? 1 : (in_array($text, [')', ']', '}'], true) ? -1 : 0);
            $args[array_key_last($args)][] = $tokens[$j];
        }
        if ($j === count($tokens) || count($args) !== 2 || count($args[1]) !== 1) {
            continue;
        }
        $value = $args[1][0];
        if ($f->rule === 'HARD-001') {
            if (count($args[0]) !== 1 || $args[0][0][0] !== T_CONSTANT_ENCAPSED_STRING
                || strtolower(substr($args[0][0][1], 1, -1)) !== 'display_errors'
                || !in_array($value[0], [T_LNUMBER, T_CONSTANT_ENCAPSED_STRING, T_STRING], true)
                || ($value[0] === T_STRING && strtolower($value[1]) !== 'true')
                || !in_array(strtolower(trim($value[1], "\"'")), ['1', 'on', 'true'], true)) {
                continue;
            }
            $replacement = "'0'";
        } else {
            if ($value[0] !== T_LNUMBER || $value[1] !== '0777') {
                continue;
            }
            $replacement = '0755';
        }
        return substr_replace($source, $replacement, $value[3], strlen($value[1]));
    }
    return null;
}

/** Lint without loading application code and always remove the owned scratch file. */
function validFixCandidate(string $source): bool
{
    $temp = tempnam(sys_get_temp_dir(), 'phprt-lint-');
    if ($temp === false) {
        return false;
    }
    try {
        if (file_put_contents($temp, $source) !== strlen($source)) {
            return false;
        }
        $output = [];
        exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($temp) . ' 2>&1', $output, $code);
        return $code === 0;
    } finally {
        unlink($temp);
    }
}

/** Preserve original bytes on failed validation or replacement. */
function writeFixCandidate(string $file, string $original, string $source): bool
{
    if (is_link($file) || file_get_contents($file) !== $original) {
        return false;
    }
    $temp = tempnam(dirname($file), '.phprt-');
    if ($temp === false) {
        return false;
    }
    try {
        $mode = fileperms($file);
        return file_put_contents($temp, $source) === strlen($source)
            && $mode !== false && chmod($temp, $mode & 0777)
            && file_get_contents($file) === $original && !is_link($file)
            && rename($temp, $file);
    } finally {
        if (is_file($temp)) {
            unlink($temp);
        }
    }
}

function printRules(array $rules): void
{
    $bySev = ['high' => [], 'medium' => [], 'low' => []];
    foreach ($rules as $r) {
        $bySev[$r->severity][] = $r;
    }
    foreach ($bySev as $sev => $group) {
        printf("\n%s (%d)\n", strtoupper($sev), count($group));
        foreach ($group as $r) {
            printf("  %-9s %s [%s]\n", $r->id, $r->title, $r->cwe);
        }
    }
}

function main(array $argv): int
{
    $cmd = $argv[1] ?? '';
    if ($cmd === '' || $cmd === '-h' || $cmd === '--help') {
        usage();
    }
    $rules = loadRules();
    if ($cmd === 'rules') {
        printRules($rules);
        return 0;
    }
    if (!in_array($cmd, ['scan', 'fix'], true)) {
        usage();
    }

    $path = $argv[2] ?? '';
    if ($path === '') {
        usage();
    }
    $json = in_array('--json', $argv, true);
    $write = in_array('--write', $argv, true);
    $min = 'low';
    foreach ($argv as $a) {
        if (str_starts_with($a, '--min=')) {
            $min = substr($a, 6);
        }
    }
    if (!isset(SEV_ORDER[$min])) {
        usage();
    }

    $scanner = new Scanner($rules);
    $files = targetFiles($path);
    $all = [];
    $originals = [];
    foreach ($files as $file) {
        $source = @file_get_contents($file);
        if ($source === false) {
            continue;
        }
        $originals[$file] = $source;
        foreach ($scanner->scanFile($file, $source) as $f) {
            if (severityAtLeast($f->severity, $min)) {
                $all[] = [$f, $source];
            }
        }
    }

    if ($cmd === 'fix') {
        $applied = 0;
        $perFile = [];
        foreach ($all as [$f, $source]) {
            $next = applyFix($f, $perFile[$f->file] ?? $source);
            if ($next !== null && $next !== ($perFile[$f->file] ?? $source)) {
                $perFile[$f->file] = $next;
                $applied++;
            }
        }
        foreach ($perFile as $file => $source) {
            if (!validFixCandidate($source)) {
                fwrite(STDERR, "refusing invalid PHP candidate: $file\n");
                return 2;
            }
        }
        foreach ($perFile as $file => $source) {
            $rel = rel($path, $file);
            if ($write) {
                if (!writeFixCandidate($file, $originals[$file], $source)) {
                    fwrite(STDERR, "refusing changed, unowned or unwritable target: $file\n");
                    return 2;
                }
                fwrite(STDERR, "wrote $rel\n");
            } else {
                fwrite(STDERR, "would write $rel\n");
            }
        }
        fwrite(STDERR, sprintf("%d change(s) %s across %d file(s)\n",
            $applied, $write ? 'written' : 'available (use --write)', count($perFile)));
        return $applied === 0 ? 0 : 1;
    }

    usort($all, fn ($a, $b) => [$a[0]->file, $a[0]->line] <=> [$b[0]->file, $b[0]->line]);

    if ($json) {
        $rows = array_map(fn ($p) => [
            'rule' => $p[0]->rule, 'severity' => $p[0]->severity, 'title' => $p[0]->title,
            'file' => rel($path, $p[0]->file), 'line' => $p[0]->line,
            'snippet' => $p[0]->snippet, 'why' => $p[0]->why, 'fix' => $p[0]->fix,
            'cwe' => $p[0]->cwe,
        ], $all);
        echo json_encode(['findings' => $rows, 'count' => count($rows)], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
        return $all === [] ? 0 : 1;
    }

    $counts = ['high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
    foreach ($all as [$f]) {
        $counts[$f->severity]++;
    }
    printf("phprt: %d finding(s) — %d high, %d medium, %d low\n\n",
        count($all), $counts['high'], $counts['medium'], $counts['low']);

    foreach ($all as [$f]) {
        printf("%s:%d  [%s %s]\n  %s\n  %s\n  fix: %s\n\n",
            rel($path, $f->file), $f->line, $f->severity, $f->rule, $f->title,
            $f->snippet, $f->fix);
    }
    return $all === [] ? 0 : 1;
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    exit(main($argv));
}
