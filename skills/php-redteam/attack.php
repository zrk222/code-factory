<?php
declare(strict_types=1);

/**
 * phprt attack — aggressive live runtime.
 *
 * usage: php attack.php <base-url> [--json] [--root <source-path>] [--timeout-ms N]
 *
 * Fires the live probes, then optionally maps confirmed hits back to source
 * lines by re-scanning <root> and matching param names in the findings.
 * Exit 0 clean, 1 findings, 2 usage/IO.
 */

require __DIR__ . '/lib/Engine.php';
require __DIR__ . '/lib/Runtime.php';

$url = $argv[1] ?? '';
if ($url === '' || !preg_match('#^https?://#', $url)) {
    fwrite(STDERR, "usage: php attack.php <base-url> [--json] [--root <dir>] [--timeout-ms N]\n");
    exit(2);
}
$json = in_array('--json', $argv, true);
$root = null;
$timeout = 8000;
foreach ($argv as $i => $a) {
    if ($a === '--root' && isset($argv[$i + 1])) {
        $root = $argv[$i + 1];
    }
    if (str_starts_with($a, '--timeout-ms=')) {
        $timeout = max(1000, (int) substr($a, 13));
    }
}

$http = new Http($url, 4000, $timeout);
$attack = new Attack($http);
$start = microtime(true);
$attack->run($url);
$elapsed = microtime(true) - $start;

// Map to source when a tree is supplied: match the param name of a confirmed
// hit against the rule findings in the file the probe points at.
if ($root !== null && is_dir($root)) {
    $rules = array_merge(require __DIR__ . '/lib/php-rules.php', require __DIR__ . '/lib/framework-rules.php');
    $scanner = new Scanner($rules);
    foreach ($attack->hits as $i => $hit) {
        if (!$hit['confirmed']) {
            continue;
        }
        preg_match('/[?&]([A-Za-z_]\w*)=/', $hit['url'], $m);
        $param = $m[1] ?? null;
        if ($param === null) {
            continue;
        }
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if ($f->getExtension() !== 'php') {
                continue;
            }
            foreach ($scanner->scanFile($f->getPathname(), (string) file_get_contents($f->getPathname())) as $finding) {
                if (str_contains($finding->snippet, $param)) {
                    $attack->hits[$i]['source'] = $f->getPathname() . ':' . $finding->line;
                    break 2;
                }
            }
        }
    }
}

$confirmed = array_filter($attack->hits, fn ($h) => $h['confirmed']);
$counts = ['high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
foreach ($attack->hits as $h) {
    $counts[$h['severity']] = ($counts[$h['severity']] ?? 0) + 1;
}

if ($json) {
    echo json_encode([
        'target' => $url,
        'requests' => $http->requests,
        'seconds' => round($elapsed, 2),
        'confirmed' => count($confirmed),
        'hits' => $attack->hits,
        'probes' => count($attack->probes),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
    exit($attack->hits === [] ? 0 : 1);
}

printf("phprt live: %s\n%d request(s) in %.1fs — %d confirmed, %d high %d medium %d low\n\n",
    $url, $http->requests, $elapsed, count($confirmed), $counts['high'], $counts['medium'], $counts['low']);

foreach ($attack->hits as $h) {
    printf("[%s %s] %s%s\n  %s\n", $h['severity'], $h['confirmed'] ? 'CONFIRMED' : 'hint', $h['title'],
        isset($h['source']) ? ' @ ' . $h['source'] : '', $h['evidence']);
    printf("  fix: %s\n\n", $h['fix']);
}
exit($attack->hits === [] ? 0 : 1);
