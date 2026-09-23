<?php

declare(strict_types=1);

/**
 * Plain-PHP test runner for the Enforcer (no PHPUnit). Exercises the pure
 * decision logic via reflection (public entry sends a response / exits).
 *
 * Run: php tests/EnforcerTest.php
 */

require __DIR__ . '/../src/Client.php';
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

// --- behaviours (plan/131 E35) ---
// The server ships each agent's behaviour set; an agent_category rule hits the
// category OR any behaviour (api/core/agentpolicy/policy.go matchApplies).
// Before this, "block training" never reached Googlebot (category search,
// behaves as training) — the rule showed as active and blocked nothing.
$trainRule = [['match' => ['type' => 'agent_category', 'value' => 'training'], 'action' => 'deny']];
check('behaviour hit blocks despite other category', 'deny',
    priv($enf, 'evaluate', [$trainRule, 'googlebot', 'search', false, '/', 'GET', ['search', 'training']])['action'] ?? null);
check('category hit still blocks', 'deny',
    priv($enf, 'evaluate', [$trainRule, 'gptbot', 'training', false, '/', 'GET', []])['action'] ?? null);
check('neither category nor behaviour: no match', null,
    priv($enf, 'evaluate', [$trainRule, 'bingbot', 'search', false, '/', 'GET', ['search']]));
check('behaviour compare is exact (case-sensitive, like the server)', false,
    priv($enf, 'matchApplies', [['type' => 'agent_category', 'value' => 'training'], 'x', 'search', false, ['Training']]));

// identify carries the behaviours from the bundle alongside the category.
$bBundle = ['agents' => [[
    'slug' => 'googlebot', 'category' => 'search', 'behaviors' => ['search', 'training'],
    'ua_tokens' => ['Googlebot'], 'cidrs' => [],
]]];
[$bSlug, $bCat, $bVerified, $bBehaviors] = priv($enf, 'identify', ['Mozilla/5.0 (compatible; Googlebot/2.1)', $bBundle, ['REMOTE_ADDR' => '1.2.3.4']]);
check('identify carries behaviours', ['search', 'training'], $bBehaviors);
check('identify + evaluate blocks via behaviour', 'deny',
    priv($enf, 'evaluate', [$trainRule, $bSlug, $bCat, $bVerified, '/', 'GET', $bBehaviors])['action'] ?? null);

// --- spoof verdict (decision 23.09.2026) ---
// A UA claiming an agent whose operator publishes ranges for the source's
// address family, from outside all of them, is refuted — as goagent in the
// server. What cannot be checked (other family, no ranges, an address that may
// be a proxy's) is never spoof.
$spoofRule = [['match' => ['type' => 'spoof'], 'action' => 'deny']];
$gbUA      = 'Mozilla/5.0 (compatible; Googlebot/2.1)';
$direct    = new Enforcer('test-key', ['direct_connection' => true]);
$proxied   = new Enforcer('test-key', ['trusted_proxies' => ['10.0.0.0/8', '192.0.2.7']]);
$spoofCase = function (Enforcer $e, array $cidrs, string $ip, string $xff = '') use ($spoofRule, $gbUA) {
    $sb     = ['agents' => [['slug' => 'googlebot', 'category' => 'search', 'ua_tokens' => ['Googlebot'], 'cidrs' => $cidrs]]];
    $server = ['REMOTE_ADDR' => $ip];
    if ($xff !== '') {
        $server['HTTP_X_FORWARDED_FOR'] = $xff;
    }
    [$s, $c, $v, $bh, $sp] = priv($e, 'identify', [$gbUA, $sb, $server]);
    $rule = priv($e, 'evaluate', [$spoofRule, $s, $c, $v, '/', 'GET', $bh, $sp]);
    return [$v, $sp, $rule['action'] ?? null];
};
$v4 = ['66.249.64.0/19'];
check('spoof (direct): IPv4 ranges, source outside → deny', [false, true, 'deny'], $spoofCase($direct, $v4, '203.0.113.7'));
check('spoof (direct): IPv4 ranges, source inside → verified, no spoof', [true, false, null], $spoofCase($direct, $v4, '66.249.66.1'));
check('spoof (direct): only IPv4 ranges, IPv6 source → no spoof', [false, false, null], $spoofCase($direct, $v4, '2001:db8::1'));
check('spoof (direct): no ranges → no spoof', [false, false, null], $spoofCase($direct, [], '203.0.113.7'));
check('spoof (direct): IPv6 ranges, IPv6 source outside → deny', [false, true, 'deny'], $spoofCase($direct, ['2001:4860:4801::/48'], '2001:db8::1'));
check('spoof (direct): IPv4-mapped peer inside IPv4 range → verified', [true, false, null], $spoofCase($direct, ['66.249.64.0/19', '2001:4860:4801::/48'], '::ffff:66.249.66.1'));
check('spoof (direct): no address → no spoof', [false, false, null], $spoofCase($direct, $v4, ''));
check('match spoof false when not refuted', false, priv($enf, 'matchApplies', [['type' => 'spoof'], 'x', 'y', false, [], false]));

// Without trusted_proxies/direct_connection REMOTE_ADDR may be a proxy: never
// spoof (a spoof rule would block the genuine Googlebot behind every proxy).
check('spoof (no option): source outside → no spoof, no block', [false, false, null], $spoofCase($enf, $v4, '203.0.113.7'));
check('spoof (no option): XFF still ignored for verified', [false, false, null], $spoofCase($enf, $v4, '203.0.113.7', '66.249.66.1'));
check('spoof (all-garbage trusted_proxies) = not configured', [false, false, null],
    $spoofCase(new Enforcer('test-key', ['trusted_proxies' => 'kaputt']), $v4, '203.0.113.7'));

// trusted_proxies: clientIP as in the server — XFF from the right, only behind
// a trusted peer.
check('proxied: rightmost untrusted hop outside → deny', [false, true, 'deny'],
    $spoofCase($proxied, $v4, '10.0.0.5', '66.249.66.1, 203.0.113.7, 192.0.2.7'));
check('proxied: rightmost untrusted hop inside → verified', [true, false, null],
    $spoofCase($proxied, $v4, '10.0.0.5', '203.0.113.7, 66.249.66.1'));
check('proxied: forged left XFF entry changes nothing', [false, true, 'deny'],
    $spoofCase($proxied, $v4, '10.0.0.5', '66.249.66.1, 203.0.113.7'));
check('proxied: untrusted peer with XFF → peer counts (outside)', [false, true, 'deny'],
    $spoofCase($proxied, $v4, '203.0.113.7', '66.249.66.1'));
check('proxied: untrusted peer with XFF → peer counts (inside)', [true, false, null],
    $spoofCase($proxied, $v4, '66.249.66.1', '203.0.113.7'));
check('proxied: garbage stops the walk → peer', '10.0.0.5', priv($proxied, 'clientIp', ['10.0.0.5', '203.0.113.9, kaputt']));
check('proxied: comma-string option works too', '203.0.113.7',
    priv(new Enforcer('test-key', ['trusted_proxies' => '10.0.0.0/8, 192.0.2.7']), 'clientIp', ['10.0.0.5', '66.249.66.1, 203.0.113.7, 192.0.2.7']));

// --- enforcer self-identification on the bundle fetch (plan/79 Inc4) ---
// Without the header the dashboard cannot tell whether this installation
// carries out behaviour and spoof rules. spoof only with a trustworthy visitor
// address. Sorted like FormatEnforcerID.
$ph = priv($enf, 'policyHeaders', []);
check('policy fetch sends the api key', true, in_array('x-api-key: test-key', $ph, true));
check('policy fetch declares the enforcer (no option: no spoof)', true,
    in_array('X-SilentShield-Enforcer: sdk-php/' . \SilentShield\Client::VERSION . ' caps=behaviors', $ph, true));
check('policy fetch declares spoof with direct_connection', true,
    in_array('X-SilentShield-Enforcer: sdk-php/' . \SilentShield\Client::VERSION . ' caps=behaviors,spoof', priv($direct, 'policyHeaders', []), true));
check('policy fetch declares spoof with trusted_proxies', true,
    in_array('X-SilentShield-Enforcer: sdk-php/' . \SilentShield\Client::VERSION . ' caps=behaviors,spoof', priv($proxied, 'policyHeaders', []), true));

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

// --- block reporting flag (plan/65) ---
function privProp(Enforcer $enf, string $prop)
{
    $p = new \ReflectionProperty(Enforcer::class, $prop);
    $p->setAccessible(true);
    return $p->getValue($enf);
}
check('reportBlocks on by default', true, privProp($enf, 'reportBlocks'));
check('reportBlocks off when disabled', false, privProp(new Enforcer('test-key', ['disable_block_reports' => true]), 'reportBlocks'));
check('reportBlocks off without api key', false, privProp(new Enforcer(''), 'reportBlocks'));
// A disabled reporter must be a no-op (no network, no throw).
$noop = new Enforcer('test-key', ['disable_block_reports' => true]);
$noop->reportBlock(['HTTP_USER_AGENT' => 'GPTBot', 'REMOTE_ADDR' => '1.2.3.4', 'REQUEST_URI' => '/x', 'REQUEST_METHOD' => 'GET'], 403);
check('reportBlock is a no-op when disabled', true, true);

echo "\n";
if ($failures > 0) {
    echo "RESULT: {$failures} test(s) FAILED\n";
    exit(1);
}
echo "RESULT: all tests passed\n";
