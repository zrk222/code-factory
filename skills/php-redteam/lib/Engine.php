<?php
declare(strict_types=1);

/**
 * phprt — rule engine.
 *
 * Each rule declares a detection strategy. Two kinds exist:
 *   - "token": walks the token stream with a small matcher DSL (string/var/call
 *     sequences), so `$_GET` inside `include` is found without matching the
 *     word "include" in a comment.
 *   - "source": regex over raw source, used only where tokens add nothing
 *     (config/header literals).
 *
 * Severity is not decoration: `high` means a plausible unauthenticated path to
 * RCE or file write, `medium` means data exposure or auth weakness, `low` means
 * hardening.
 */

final class Finding
{
    public function __construct(
        public string $rule,
        public string $severity,
        public string $title,
        public string $file,
        public int $line,
        public string $snippet,
        public string $why,
        public string $fix,
        public string $cwe = '',
    ) {}
}

final class Rule
{
    /**
     * @param list<string> $anyOf       tokens where ANY one is the sink
     * @param list<string> $requires    every item must appear in order (AND)
     * @param list<string> $requireAny  at least one item must appear (OR)
     * @param list<string> $skipIf      suppress when any of these appears (OR)
     */
    public function __construct(
        public string $id,
        public string $severity,
        public string $title,
        public string $kind,
        public array $anyOf,
        public array $requires,
        public int $window,
        public string $why,
        public string $fix,
        public string $cwe = '',
        public array $skipIf = [],
        public array $requireAny = [],
    ) {}

    /** Convenience builder: OR-required superglobal set. */
    public static function withAny(array $anyOf, array ...$args): self
    {
        return new self(...$anyOf, ...$args);
    }
}

/**
 * Token matcher. Comments and whitespace are dropped so a rule can never fire
 * on prose. `$name` matches a variable token, `T_STRING:x` matches a name.
 */
final class TokenWalker
{
    /** @var list<array{0:int,1:string,2:int}> */
    private array $flat = [];

    public function __construct(string $source)
    {
        $line = 1;
        foreach (token_get_all($source) as $t) {
            if (is_array($t)) {
                $line = $t[2];
                if ($t[0] === T_WHITESPACE || $t[0] === T_COMMENT || $t[0] === T_DOC_COMMENT) {
                    continue;
                }
                $this->flat[] = [$t[0], $t[1], $line];
            } else {
                $this->flat[] = [0, $t, $line];
            }
        }
    }

    public function count(): int
    {
        return count($this->flat);
    }

    public function text(int $i): string
    {
        return $this->flat[$i][1] ?? '';
    }

    public function line(int $i): int
    {
        return $this->flat[$i][2] ?? 0;
    }

    public function isVar(int $i): bool
    {
        return ($this->flat[$i][0] ?? null) === T_VARIABLE;
    }

    public function isName(int $i): bool
    {
        return in_array($this->flat[$i][0] ?? null, [T_STRING, T_ISSET, T_EMPTY, T_INCLUDE,
            T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE, T_EVAL, T_EXIT, T_PRINT, T_ECHO,
            T_NEW, T_FUNCTION, T_LIST, T_ARRAY, T_UNSET, T_RETURN], true);
    }

    public function isOpen(int $i): bool
    {
        return ($this->flat[$i][0] ?? null) === 0 && $this->flat[$i][1] === '(';
    }

    public function isArrow(int $i): bool
    {
        return in_array($this->text($i), ['->', '?->'], true);
    }

    /**
     * Exact literal text compare, case-insensitive for names.
     *
     * Forms: `T_STRING` token kind, `T_STRING:name` kind plus name, `->method`
     * object/static member call, `$var` variable, or a bare word.
     */
    public function matches(int $i, string $want): bool
    {
        if (str_starts_with($want, '->')) {
            $name = strtolower(substr($want, 2));
            return $this->isArrow($i - 1) && strtolower($this->text($i)) === $name;
        }
        if (str_starts_with($want, '|')) {
            $name = strtolower(substr($want, 1));
            return $this->text($i - 1) === '|' && strtolower($this->text($i)) === $name;
        }
        if (str_starts_with($want, '::')) {
            $name = strtolower(substr($want, 2));
            return $this->text($i - 1) === '::' && strtolower($this->text($i)) === $name;
        }
        $id = $this->flat[$i][0] ?? null;
        $tok = strtolower($this->text($i));
        if ($id === T_NAME_FULLY_QUALIFIED && substr_count($tok, '\\') === 1) {
            $tok = substr($tok, 1);
            $id = T_STRING;
        }
        if (str_contains($want, ':')) {
            [$kind, $name] = explode(':', $want, 2);
            return $id === constant($kind) && $tok === strtolower($name);
        }
        if (str_starts_with($want, 'T_')) {
            return $id === constant($want);
        }
        $want = strtolower($want);
        if (str_starts_with($want, '$')) {
            return $this->isVar($i) && $tok === $want;
        }
        return $tok === $want;
    }

    /** True when the token is the name inside a member/static/filter call. */
    public function isMember(int $i): bool
    {
        return ($this->isArrow($i - 1) || $this->text($i - 1) === '::' || $this->text($i - 1) === '|')
            && ($this->flat[$i][0] ?? null) === T_STRING;
    }

    /**
     * Framework request sources: WordPress, Laravel/Symfony request objects,
     * and server vars. Treated as tainted the same way as superglobals, so a
     * rule can pin the source without hardcoding each call shape.
     */
    public const FRAMEWORK_SOURCES = [
        '->input', '->query', '->get', '->post', '->cookie', '->header', '->file',
        '->all', '->param', '->request', '::input', '::query', '::get', '::post',
        'get_option', 'get_post_meta', 'get_user_meta', 'update_option',
        '$HTTP_RAW_POST_DATA', '$http_response_header',
    ];

    public function isFrameworkSource(int $i): bool
    {
        $text = strtolower($this->text($i));
        if ($text === '$http_response_header' || $text === '$http_raw_post_data') {
            return true;
        }
        if ($this->isMember($i) && in_array('->' . $text, self::FRAMEWORK_SOURCES, true)) {
            return true;
        }
        return in_array($text, ['get_option', 'get_post_meta', 'get_user_meta'], true);
    }

    /** True when any token in [$i, $i+$span) matches. */
    public function anyNear(int $i, string $want, int $span): bool
    {
        for ($j = $i; $j < min($this->count(), $i + $span); $j++) {
            if ($this->matches($j, $want)) {
                return true;
            }
        }
        return false;
    }

    /** Snippet around a token index, newline-joined, trimmed. */
    public function snippet(int $i, int $span = 3): string
    {
        $parts = [];
        for ($j = $i; $j < min($this->count(), $i + $span); $j++) {
            $parts[] = $this->text($j);
        }
        return trim(implode(' ', $parts));
    }
}

final class Scanner
{
    /** @param list<Rule> $rules */
    public function __construct(private array $rules) {}

    /** @return list<Finding> */
    public function scanFile(string $path, string $source): array
    {
        $findings = [];
        $walker = new TokenWalker($source);
        $lines = explode("\n", $source);

        foreach ($this->rules as $rule) {
            if ($rule->kind === 'source') {
                foreach ($rule->anyOf as $needle) {
                    if (!preg_match_all($needle, $source, $m, PREG_OFFSET_CAPTURE)) {
                        continue;
                    }
                    foreach ($m[0] as $index => $hit) {
                        if ($rule->id === 'RCE-005') {
                            $pattern = $m[2][$index][0];
                            $delimiter = $pattern[0] ?? '';
                            $close = ['(' => ')', '[' => ']', '{' => '}', '<' => '>'][$delimiter] ?? $delimiter;
                            $last = $close === '' ? false : strrpos($pattern, $close);
                            if ($last === false || $last === 0 || ctype_alnum($delimiter)
                                || !preg_match('/^[a-zA-Z]*e[a-zA-Z]*$/', substr($pattern, $last + 1))) {
                                continue;
                            }
                        }
                        $line = substr_count(substr($source, 0, $hit[1]), "\n") + 1;
                        $findings[] = new Finding(
                            $rule->id, $rule->severity, $rule->title, $path, $line,
                            trim($hit[0]), $rule->why, $rule->fix, $rule->cwe
                        );
                    }
                }
                continue;
            }

            for ($i = 0; $i < $walker->count(); $i++) {
                if (!$this->matchesAny($walker, $i, $rule->anyOf)) {
                    continue;
                }
                if ($rule->requires !== [] && !$this->matchesSequence($walker, $i, $rule->requires, $rule->window)) {
                    continue;
                }
                if ($rule->requireAny !== [] && !$this->matchesAnyNear($walker, $i, $rule->requireAny, $rule->window)) {
                    continue;
                }
                $outputRule = in_array($rule->id, ['XSS-001', 'WP-001'], true);
                if (!$outputRule && $rule->skipIf !== [] && $this->matchesSequence($walker, $i, $rule->skipIf, $rule->window)) {
                    continue;
                }
                if ($outputRule && $this->alreadyEscaped($walker, $i, $rule->skipIf)) {
                    continue;
                }
                $line = $walker->line($i);
                $findings[] = new Finding(
                    $rule->id, $rule->severity, $rule->title, $path, $line,
                    $walker->snippet($i, 6), $rule->why, $rule->fix, $rule->cwe
                );
            }
        }

        return $findings;
    }

    /** True when the superglobal under an echo is already wrapped by an escaper. */
    private function alreadyEscaped(TokenWalker $w, int $i, array $escapers): bool
    {
        for ($j = $i + 1; $j < min($w->count(), $i + 8); $j++) {
            if ($w->isOpen($j)) {
                continue;
            }
            if (!in_array(strtolower($w->text($j)), $escapers, true) || !$w->isOpen($j + 1)) {
                return false;
            }
            $depth = 0;
            for ($k = $j + 1; $k < $w->count(); $k++) {
                if ($w->text($k) === '(') {
                    $depth++;
                } elseif ($w->text($k) === ')' && --$depth === 0) {
                    return in_array($w->text($k + 1), [';', ''], true);
                }
            }
            return false;
        }
        return false;
    }

    private function matchesAny(TokenWalker $w, int $i, array $anyOf): bool
    {
        foreach ($anyOf as $want) {
            if ($w->matches($i, $want)) {
                return true;
            }
        }
        return false;
    }
    /** At least one of the wanted tokens appears within the window, either side. */
    private function matchesAnyNear(TokenWalker $w, int $i, array $wanted, int $window): bool
    {
        $lo = max(0, $i - $window);
        $hi = min($w->count(), $i + $window);
        for ($j = $lo; $j < $hi; $j++) {
            foreach ($wanted as $want) {
                if ($w->matches($j, $want)) {
                    return true;
                }
            }
            if ($w->isFrameworkSource($j)) {
                return true;
            }
        }
        return false;
    }

    /** Every item must appear in order inside the window. */
    private function matchesSequence(TokenWalker $w, int $i, array $seq, int $window): bool
    {
        $pos = $i;
        foreach ($seq as $want) {
            $found = false;
            for ($j = $pos; $j < min($w->count(), $i + $window); $j++) {
                if ($w->matches($j, $want)) {
                    $pos = $j + 1;
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                return false;
            }
        }
        return true;
    }
}
