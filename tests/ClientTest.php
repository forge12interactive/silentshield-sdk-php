<?php

declare(strict_types=1);

/**
 * Plain-PHP test runner (no PHPUnit dependency).
 *
 * Run: C:\xampp\php\php.exe tests\ClientTest.php
 * Prints PASS/FAIL per assertion; exits non-zero if any assertion fails.
 */

require __DIR__ . '/../src/Client.php';

use SilentShield\Client;

$failures = 0;

/**
 * Assert that $actual equals the expected $expected (strict) and log it.
 */
function check(string $label, $expected, $actual): void
{
    global $failures;
    if ($expected === $actual) {
        echo "PASS  {$label}\n";
    } else {
        $failures++;
        echo 'FAIL  ' . $label
            . '  (expected ' . var_export($expected, true)
            . ', got ' . var_export($actual, true) . ")\n";
    }
}

$client = new Client('test-key');

// A known AI-agent token in the UA => candidate.
check(
    "isBotCandidate('...GPTBot...', '') === true",
    true,
    $client->isBotCandidate('Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)', '')
);

// A plain browser UA with no signature => not a candidate.
check(
    "isBotCandidate('...Chrome...', '') === false",
    false,
    $client->isBotCandidate('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36', '')
);

// A signed request (Signature header material) => candidate even for a browser UA.
check(
    "isBotCandidate('Chrome', 'sig=:x:') === true (signed)",
    true,
    $client->isBotCandidate('Chrome', 'sig=:x:')
);

// currentPageUrl() builds the page from $_SERVER (private → reflection).
$pageUrl = (function (Client $c): string {
    $m = new ReflectionMethod(Client::class, 'currentPageUrl');
    $m->setAccessible(true);
    return $m->invoke($c);
});

$_SERVER['HTTP_HOST']   = 'shop.example';
$_SERVER['REQUEST_URI'] = '/checkout?step=2';
$_SERVER['HTTPS']       = 'on';
check(
    "currentPageUrl builds https URL from \$_SERVER",
    'https://shop.example/checkout?step=2',
    $pageUrl($client)
);

// No host/URI (e.g. CLI) => empty, so verify() simply sends no page.
unset($_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI']);
check(
    "currentPageUrl returns '' when \$_SERVER has no host/URI",
    '',
    $pageUrl($client)
);

// ---------------------------------------------------------------------
// classifyErrorBody — telling the three different 429s apart (plan 1.9).
//
// This is the whole point: verify() returns a bool, so an exhausted monthly
// quota and a real bot look identical to the caller. Measured against the
// service on 2026-08-06: the quota middleware answers 429 with
// {"error":"quota_exceeded"}, the API-key guard answers 429 with
// {"error":"rate_limited"}, and the generic rate limiter answers 429 with
// {"error":"too many requests"}. One status code, three meanings — and only
// one of them lasts until the 1st of next month.
// ---------------------------------------------------------------------
$classify = (function (int $status, string $body) {
    $m = new ReflectionMethod(Client::class, 'classifyErrorBody');
    $m->setAccessible(true);
    return $m->invoke(null, $status, $body);
});

check(
    'quota 429 is classified as quota_exceeded',
    Client::FAILURE_QUOTA_EXCEEDED,
    $classify(429, '{"error":"quota_exceeded","month":{"ResetSecs":1728000}}')
);

check(
    'api-key-guard 429 is classified as rate_limited',
    Client::FAILURE_RATE_LIMITED,
    $classify(429, '{"error":"rate_limited"}')
);

check(
    'generic limiter 429 is classified as rate_limited',
    Client::FAILURE_RATE_LIMITED,
    $classify(429, '{"error":"too many requests"}')
);

// A 429 we cannot read must NOT be reported as an exhausted quota: that would
// invite an integration to wave submissions through on a body we never
// understood. Unknown stays on the safe side.
check(
    'unreadable 429 body falls back to rate_limited, never to quota',
    Client::FAILURE_RATE_LIMITED,
    $classify(429, 'not json at all')
);

check(
    '500 is a plain http failure',
    Client::FAILURE_HTTP,
    $classify(500, '{"error":"boom"}')
);

check(
    '403 is a plain http failure, not a rate limit',
    Client::FAILURE_HTTP,
    $classify(403, '{"error":"forbidden"}')
);

// A fresh client has nothing to report yet.
check(
    'lastFailure starts empty',
    Client::FAILURE_NONE,
    (new Client('k'))->lastFailure()
);

check(
    'lastRetryAfter starts null',
    null,
    (new Client('k'))->lastRetryAfter()
);


// ── reportBlock: was IHR Code abweist, bevor SilentShield gefragt wird ──────
//
// 🔴 Diese Sperren sind sonst unsichtbar: ein Bot ohne JavaScript laedt das
// Widget nie und taucht in keiner Statistik auf, obwohl er abgewehrt wurde.
//
// ⚠️ Der Ruf selbst geht ueber curl und ist ohne Netz nicht pruefbar. Geprueft
// wird deshalb, was ohne Netz pruefbar ist und trotzdem brechen kann: das
// Vokabular und die Version.

$blockKonstanten = array_filter(
    (new ReflectionClass(Client::class))->getConstants(),
    static fn (string $name) => str_starts_with($name, 'BLOCK_'),
    ARRAY_FILTER_USE_KEY
);

check(
    'reportBlock: das Vokabular deckt alle 13 Sperrgruende ab',
    13,
    count($blockKonstanten)
);

check(
    'reportBlock: no_nonce heisst weiterhin no_nonce',
    'no_nonce',
    Client::BLOCK_NO_NONCE
);

// Alle Gruende sind kleingeschrieben mit Unterstrichen — der Dienst gleicht
// ohne Normalisierung gegen seine Whitelist ab, ein Tippfehler faellt still
// auf "EXTERNAL_BLOCK".
check(
    'reportBlock: alle Gruende sind in der Schreibweise der Whitelist',
    true,
    count(array_filter($blockKonstanten, static fn ($v) => (bool) preg_match('/^[a-z_]+$/', (string) $v)))
        === count($blockKonstanten)
);

// Die Version wandert als Kopfzeile mit — ohne sie kann das Dashboard nicht
// sagen, dass eine Einbindung veraltet ist.
check(
    'die eigene Version ist gesetzt',
    1,
    preg_match('/^\d+\.\d+\.\d+$/', Client::VERSION)
);

echo "\n";
if ($failures > 0) {
    echo "RESULT: {$failures} test(s) FAILED\n";
    exit(1);
}

echo "RESULT: all tests PASSED\n";
exit(0);
