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

echo "\n";
if ($failures > 0) {
    echo "RESULT: {$failures} test(s) FAILED\n";
    exit(1);
}

echo "RESULT: all tests PASSED\n";
exit(0);
