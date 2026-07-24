<?php

declare(strict_types=1);

/**
 * Plain-PHP test runner for the Enforcer (no PHPUnit). Exercises the pure
 * decision logic via reflection (public entry sends a response / exits).
 *
 * Run: php tests/EnforcerTest.php
 */

require __DIR__ . '/../src/Enforcer.php';

use SilentShield\Enforcer;

$failures = 0;

function check(string $label, $expected, $actual): void
{
    global $failures;
    if ($expected === $actual) {
        echo "PASS  {$label}\n";
    } else {
        $failures++;
        echo 'FAIL  ' . $label . '  (expected ' . var_export($expected, true) . ', got ' . var_export($actual, true) . ")\n";
    }
}

if (!function_exists('sodium_crypto_sign_keypair')) {
    echo "SKIP: libsodium not available\n";
    exit(0);
}

$enf = new Enforcer('test-key');

/** Invoke a private method on the enforcer. */
function priv(Enforcer $enf, string $method, array $args)
{
    $m = new \ReflectionMethod(Enforcer::class, $method);
    $m->setAccessible(true);
    return $m->invokeArgs($enf, $args);
}

// --- verifyBundle: sign a bundle and round-trip it ---
$kp     = sodium_crypto_sign_keypair();
$pub    = sodium_crypto_sign_publickey($kp);
$secret = sodium_crypto_sign_secretkey($kp);

$bundle  = ['format_version' => 1, 'mode' => 'enforce', 'rules' => [], 'agents' => []];
$payload = json_encode($bundle);
$sig     = sodium_crypto_sign_detached($payload, $secret);
$env     = json_encode(['payload' => base64_encode($payload), 'alg' => 'ed25519', 'kid' => 'k1', 'sig' => base64_encode($sig)]);
$keys    = ['k1' => $pub];

$got = priv($enf, 'verifyBundle', [$env, $keys]);
check('verifyBundle accepts a good bundle', 'enforce', is_array($got) ? ($got['mode'] ?? null) : null);
check('verifyBundle rejects an unknown kid', null, priv($enf, 'verifyBundle', [$env, []]));

$tampered = json_encode(['payload' => base64_encode($payload), 'alg' => 'ed25519', 'kid' => 'k1', 'sig' => base64_encode(str_repeat("\0", SODIUM_CRYPTO_SIGN_BYTES))]);
check('verifyBundle rejects a bad signature', null, priv($enf, 'verifyBundle', [$tampered, $keys]));

$p2  = json_encode(['format_version' => 2, 'mode' => 'enforce']);
$s2  = sodium_crypto_sign_detached($p2, $secret);
$e2  = json_encode(['payload' => base64_encode($p2), 'alg' => 'ed25519', 'kid' => 'k1', 'sig' => base64_encode($s2)]);
check('verifyBundle rejects a future format_version', null, priv($enf, 'verifyBundle', [$e2, $keys]));

// --- evaluate: first match wins ---
$rules = [
    ['match' => ['type' => 'agent_slug', 'value' => 'gptbot'], 'action' => 'deny'],
    ['match' => ['type' => 'agent_category', 'value' => 'training'], 'action' => 'throttle'],
];
check('evaluate deny (slug)', 'deny', priv($enf, 'evaluate', [$rules, 'gptbot', 'training', false, '/', 'GET'])['action']);
check('evaluate throttle (category)', 'throttle', priv($enf, 'evaluate', [$rules, 'other', 'training', false, '/', 'GET'])['action']);
check('evaluate allow (no match)', null, priv($enf, 'evaluate', [$rules, 'other', 'search', false, '/', 'GET']));

$pathRule = [['match' => ['type' => 'any'], 'path_pattern' => '/admin*', 'action' => 'deny']];
check('evaluate path prefix match', 'deny', priv($enf, 'evaluate', [$pathRule, '', '', false, '/admin/x', 'GET'])['action'] ?? null);
check('evaluate path miss', null, priv($enf, 'evaluate', [$pathRule, '', '', false, '/home', 'GET']));

// --- match types ---
check('match any', true, priv($enf, 'matchApplies', [['type' => 'any'], '', '', true]));
check('match unsigned', true, priv($enf, 'matchApplies', [['type' => 'unsigned'], '', '', false]));
check('match unsigned (verified) false', false, priv($enf, 'matchApplies', [['type' => 'unsigned'], '', '', true]));
check('match bogus false', false, priv($enf, 'matchApplies', [['type' => 'bogus'], 'x', 'y', false]));

// --- path / method matchers ---
check('path * matches', true, priv($enf, 'pathMatches', ['*', '/anything']));
check('path prefix', true, priv($enf, 'pathMatches', ['/blog*', '/blog/post']));
check('path prefix miss', false, priv($enf, 'pathMatches', ['/blog*', '/shop']));
check('path exact', true, priv($enf, 'pathMatches', ['/exact', '/exact']));
check('method empty = any', true, priv($enf, 'methodMatches', [[], 'GET']));
check('method member', true, priv($enf, 'methodMatches', [['post'], 'POST']));
check('method miss', false, priv($enf, 'methodMatches', [['POST'], 'GET']));

// --- CIDR (v4 + v6) ---
check('cidr v4 in', true, priv($enf, 'ipInCidr', ['10.1.2.3', '10.0.0.0/8']));
check('cidr v4 out', false, priv($enf, 'ipInCidr', ['11.1.2.3', '10.0.0.0/8']));
check('cidr v6 in', true, priv($enf, 'ipInCidr', ['2001:db8::1', '2001:db8::/32']));
check('cidr v6 out', false, priv($enf, 'ipInCidr', ['2001:dead::1', '2001:db8::/32']));
check('cidr family mismatch', false, priv($enf, 'ipInCidr', ['10.0.0.1', '2001:db8::/32']));

echo "\n";
if ($failures > 0) {
    echo "RESULT: {$failures} test(s) FAILED\n";
    exit(1);
}
echo "RESULT: all tests passed\n";
