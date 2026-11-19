<?php
declare(strict_types=1);

/**
 * phprt report — turn a JSON scan into the markdown report the skill describes.
 * usage: php report.php scan.json <target-label> > report.md
 */

$json = $argv[1] ?? '';
$label = $argv[2] ?? 'target';
$data = json_decode(ltrim((string) @file_get_contents($json), "\xEF\xBB\xBF"), true);
if (!is_array($data)) {
    fwrite(STDERR, "cannot read $json\n");
    exit(2);
}

$rows = $data['findings'] ?? [];
$by = ['high' => [], 'medium' => [], 'low' => [], 'info' => []];
foreach ($rows as $r) {
    $by[$r['severity'] ?? 'info'][] = $r;
}

printf("# PHP security report — %s\n\n", $label);
printf("Scanned with phprt. **%d** high, **%d** medium, **%d** low, %d info.\n\n",
    count($by['high']), count($by['medium']), count($by['low']), count($by['info']));

$sections = [
    'high' => 'High (ship-blocking)',
    'medium' => 'Medium',
    'low' => 'Low',
    'info' => 'Info',
];

foreach ($sections as $sev => $heading) {
    if ($by[$sev] === []) {
        continue;
    }
    printf("## %s\n\n", $heading);
    $grouped = [];
    foreach ($by[$sev] as $r) {
        $grouped[$r['rule']][] = $r;
    }
    foreach ($grouped as $rule => $hits) {
        $first = $hits[0];
        printf("### %s — %s (%s)\n\n", $rule, $first['title'], $first['cwe']);
        printf("%d location(s). Reachable: confirm by following the taint.\n\n", count($hits));
        foreach (array_slice($hits, 0, 20) as $h) {
            printf("- `%s:%d` — `%s`\n", $h['file'], $h['line'], trim($h['snippet']));
        }
        if (count($hits) > 20) {
            printf("- … %d more\n", count($hits) - 20);
        }
        printf("\n**Why:** %s\n\n**Fix:** %s\n\n", $first['why'], $first['fix']);
    }
}

if ($rows === []) {
    echo "No findings.\n";
}

echo "\n## Not fixed / accepted risk\n\n- (fill in during triage)\n";
