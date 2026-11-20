<?php
declare(strict_types=1);

/**
 * Framework rule pack: WordPress, Laravel, Symfony.
 *
 * These encode the idioms that actually carry bugs in the wild â€” unescaped
 * WP output, missing nonce checks, `$wpdb` interpolation, unvalidated
 * redirects, and the framework request sources feeding raw SQL/shell.
 */

$fw = static fn (
    string $id, string $sev, string $title, array $anyOf, string $why, string $fix, string $cwe,
    array $skipIf = []
) => new Rule($id, $sev, $title, 'token', $anyOf, [], 14, $why, $fix, $cwe, $skipIf,
    ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']);

$srcRule = static fn (
    string $id, string $sev, string $title, array $anyOf, string $why, string $fix, string $cwe
) => new Rule($id, $sev, $title, 'source', $anyOf, [], 0, $why, $fix, $cwe);

/** Sink plus a required source, suppressed by a guard. */
$guard = static fn (
    string $id, string $sev, string $title, array $sink, array $needed, string $why, string $fix,
    string $cwe, array $skipIf
) => new Rule($id, $sev, $title, 'token', $sink, [], 18, $why, $fix, $cwe, $skipIf, $needed);

return [
    // ------------------------------------------------------------ WordPress
    $fw('WP-001', 'high', 'unescaped output in a WordPress theme/plugin',
        ['T_ECHO', 'T_PRINT'],
        'WordPress code echoes a request value directly. Themes are the most common reflected-XSS source in the WP ecosystem.',
        "esc_html(\$v) for text, esc_attr(\$v) inside an attribute, esc_url(\$v) for href/src.",
        'CWE-79',
        ['esc_html', 'esc_attr', 'esc_url', 'esc_textarea', 'wp_kses', 'wp_kses_post',
         'absint', 'intval', 'sanitize_text_field']),

    $fw('WP-002', 'high', '$wpdb query with interpolation',
        ['->get_results', '->get_row', '->get_var', '->get_col', '->query'],
        '$wpdb methods take raw SQL. An interpolated request value breaks out of the literal.',
        '$wpdb->prepare("... WHERE id = %d", $id) â€” always for anything but an (int) cast.',
        'CWE-89'),

    $srcRule('WP-003', 'high', 'wp_redirect to a request value (open redirect)',
        ['/wp_(?:safe_)?redirect\s*\(\s*\$_(?:GET|POST|REQUEST|SERVER)/i'],
        'The redirect target comes from the request, so any host can be chosen; with allow_unescaped that includes javascript:.',
        'wp_safe_redirect(esc_url_raw($url)); exit; â€” safe_redirect restricts to the site by default.',
        'CWE-601'),

    $guard('WP-004', 'high', 'form write without nonce check',
        ['update_option', 'delete_option', '->update', '->insert', 'wp_insert_post', 'update_post_meta'],
        ['$_POST'],
        'A POST value is written but no nonce is verified nearby, so the request can be forged (CSRF).',
        'check_admin_referer(\'action\', \'field\') or wp_verify_nonce($_POST[\'_wpnonce\'], \'action\').',
        'CWE-352',
        ['check_admin_referer', 'check_ajax_referer', 'wp_verify_nonce', 'wp_rest']),

    $guard('WP-005', 'medium', 'missing capability check on a privileged write',
        ['update_option', 'delete_option', '->update', '->insert'],
        ['$_POST', '$_GET'],
        'The option/record is written without a capability check nearby, so any logged-in user may reach it.',
        "current_user_can('manage_options') before the write.",
        'CWE-862',
        ['current_user_can']),

    $srcRule('WP-006', 'medium', 'add_query_arg/add_query_arg-less URL building',
        ['/add_query_arg\s*\(/i'],
        'Query args are appended without encoding, so a value containing & or = injects extra parameters.',
        'urlencode() each dynamic value, or build with add_query_arg(array) which encodes for you.',
        'CWE-116'),

    $srcRule('WP-007', 'high', 'unserialize on an option or meta value',
        ['/maybe_unserialize\s*\(\s*(?:\$_|get_)/i'],
        'Options and meta can hold attacker-written serialized data (plugin settings, imported content). A POP chain gives RCE.',
        'Prefer json, or sanitize the shape before using the unserialized value.',
        'CWE-502'),

    // --------------------------------------------------------------- Laravel
    $fw('LAR-001', 'high', 'DB::raw / whereRaw with a request value',
        ['::raw', '->whereRaw', '->selectRaw', '->orderByRaw', '->havingRaw'],
        'Raw fragments are not parameterized, so an interpolated request value is SQL injection.',
        'DB::raw() with bindings, e.g. whereRaw("x = ?", [$v]); allowlist any identifier.',
        'CWE-89'),

    $fw('LAR-002', 'high', 'Blade {!! !!} / echo of a request value',
        ['T_ECHO'],
        'Echo in a Blade/PHP view prints unescaped; Blade {{ }} escapes but a reverse-echoed raw section does not.',
        '{{ $v }} in Blade, or e() / htmlspecialchars() in plain PHP views.',
        'CWE-79',
        ['e(', 'htmlspecialchars', 'esc_html', 'esc_attr', 'esc_url', 'wp_kses']),

    $fw('LAR-003', 'high', 'redirect()->to()/away() to request input (open redirect)',
        ['->to', '->away', '->intended'],
        'The target is attacker-chosen; away() leaves the site entirely.',
        'Validate against an allowlist, or redirect()->route() instead of a free URL.',
        'CWE-601'),

    $srcRule('LAR-004', 'medium', 'model mass-assignment relies on $guarded = []',
        ['/\$guarded\s*=\s*\[\s*\]/'],
        'An empty guard lets the client set any column, including admin flags.',
        'List sensitive columns in $fillable, or keep $guarded explicit.',
        'CWE-915'),

    $srcRule('LAR-005', 'medium', "env with a literal default in source",
        ['/env\s*\(\s*[\'"][A-Z0-9_]+[\'"]\s*,\s*[\'"][^\'"]+[\'"]\s*\)/'],
        'A hardcoded fallback in env() becomes a working value if the env var is absent (and is cached in prod).',
        'Keep the default in .env.example, or move to config() and config caching.',
        'CWE-798'),

    // -------------------------------------------------------------- Symfony
    $fw('SYM-001', 'high', 'raw SQL with a request value',
        ['->query', '->executeQuery', '->prepare'],
        'Doctrine/DBAL raw calls need bound parameters; interpolation is SQLi.',
        '$conn->executeQuery("... WHERE id = ?", [$id]) or a QueryBuilder with setParameter.',
        'CWE-89'),

    $fw('SYM-002', 'high', 'Twig |raw filter on a request value',
        ['|raw'],
        '|raw disables autoescaping for that expression.',
        'Drop |raw, or pass through twig_escape_filter with the html strategy.',
        'CWE-79'),

    $srcRule('SYM-003', 'high', 'unserialize of a request/parameter value',
        ['/unserialize\s*\(\s*(?:\$request|->get\()/i'],
        'Symfony request parameters reach unserialize; object injection follows.',
        "unserialize(\$v, ['allowed_classes' => [...]]) or Symfony Serializer with an allowed class set.",
        'CWE-502'),

    $srcRule('SYM-004', 'medium', 'APP_ENV/APP_DEBUG read from the request',
        ['/\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"]APP_(?:ENV|DEBUG)[\'"]\s*\]/i'],
        'A client can toggle debug and leak a stack trace in production.',
        'Pin APP_ENV/APP_DEBUG in the server env, not the query string.',
        'CWE-489'),
];
