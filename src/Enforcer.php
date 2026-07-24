<?php

declare(strict_types=1);

namespace SilentShield;

/**
 * SilentShield policy Enforcer — actually BLOCK disallowed AI bots (plan/64).
 *
 * The counterpart to Client::observe(): where observe only reports visits, the
 * enforcer decides whether to block. It fetches the signed policy bundle,
 * verifies its Ed25519 signature (libsodium) against the pinned keys, caches it
 * on disk, and decides per request — sending 403 for a denied bot, 429 for a
 * throttled one.
 *
 * Dependency-free: ext-curl + ext-sodium (both in PHP 8.1 core) + core PHP.
 *
 * Safety guarantees (mirror api/enforcers/goagent):
 *  - **Monitor mode never blocks.** Only mode == "enforce" can block.
 *  - **Fail-open everywhere.** Missing/expired/invalid bundle, no libsodium, any
 *    exception → the request passes. Enforcement must never take a site down.
 *
 * Usage (drop-in, at the very top of your front controller):
 *
 *     (new \SilentShield\Enforcer('YOUR_SITE_KEY'))->enforce();
 *
 * Or decide yourself:
 *
 *     $d = (new \SilentShield\Enforcer('YOUR_SITE_KEY'))->decide();
 *     if ($d !== null) { http_response_code($d['status']); exit; }
 */
final class Enforcer
{
    private const POLICY_URL = 'https://api.silentshield.io/api/v1/agent/policy';
    private const KEYS_URL   = 'https://api.silentshield.io/.well-known/silentshield-agent-keys';

    /** Re-fetch the bundle at most this often (seconds). */
    private const REFRESH_INTERVAL = 300;
    /** A cached bundle stays usable this long if refreshes fail (seconds). */
    private const BUNDLE_TTL = 3600;
    /** Pinned-keys cache lifetime (seconds). */
    private const KEYS_TTL = 3600;

    private string $apiKey;
    private string $policyUrl;
    private string $keysUrl;
    private int $timeout;
    private bool $insecure;
    private string $cacheDir;

    /**
     * @param string               $apiKey Publishable, domain-bound site key.
     * @param array<string,mixed>  $opts   policy_url, keys_url, timeout, insecure, cache_dir
     */
    public function __construct(string $apiKey, array $opts = [])
    {
        $this->apiKey    = $apiKey;
        $this->policyUrl = (string) ($opts['policy_url'] ?? self::POLICY_URL);
        $this->keysUrl   = (string) ($opts['keys_url']   ?? self::KEYS_URL);
        $this->timeout   = (int) ($opts['timeout']       ?? 5);
        $this->insecure  = (bool) ($opts['insecure']     ?? false);
        $this->cacheDir  = rtrim((string) ($opts['cache_dir'] ?? sys_get_temp_dir()), '/\\');
    }

    /**
     * Drop-in enforcement: on a block, sends the response (403/429) and exits.
     * Otherwise returns and your app continues. Fail-open.
     *
     * @param array<string,mixed>|null $server Defaults to $_SERVER.
     */
    public function enforce(?array $server = null): void
    {
        try {
            $d = $this->decide($server);
            if ($d === null) {
                return;
            }
            if (!headers_sent()) {
                http_response_code($d['status']);
                header('Content-Type: text/plain; charset=utf-8');
                if (($d['retry_after'] ?? 0) > 0) {
                    header('Retry-After: ' . $d['retry_after']);
                }
            }
            echo $d['status'] === 429 ? 'Too Many Requests' : 'Forbidden';
            exit;
        } catch (\Throwable $e) {
            // Fail-open: never break the site.
        }
    }

    /**
     * Decide without acting. Returns ['action','status','retry_after'] on a block,
     * or null to allow. Fail-open (returns null on any error).
     *
     * @param array<string,mixed>|null $server
     * @return array{action:string,status:int,retry_after:int}|null
     */
    public function decide(?array $server = null): ?array
    {
        try {
            if (!\function_exists('sodium_crypto_sign_verify_detached') || $this->apiKey === '') {
                return null;
            }
            $server ??= $_SERVER;

            $bundle = $this->loadBundle();
            if (!\is_array($bundle) || (($bundle['mode'] ?? 'monitor') !== 'enforce')) {
                return null;
            }

            $ua     = isset($server['HTTP_USER_AGENT']) ? (string) $server['HTTP_USER_AGENT'] : '';
            $method = isset($server['REQUEST_METHOD']) ? strtoupper((string) $server['REQUEST_METHOD']) : 'GET';
            $path   = $this->requestPath($server);

            [$slug, $category, $verified] = $this->identify($ua, $bundle, $server);
            $rule = $this->evaluate(\is_array($bundle['rules'] ?? null) ? $bundle['rules'] : [], $slug, $category, $verified, $path, $method);
            if ($rule === null) {
                return null;
            }

            $action = (string) ($rule['action'] ?? 'allow');
            if ($action === 'deny') {
                return ['action' => 'deny', 'status' => 403, 'retry_after' => 0];
            }
            if ($action === 'throttle' && !empty($bundle['quota_enabled']) && !empty($rule['rate_limit'])) {
                $key = $slug !== '' ? $slug : ($category !== '' ? 'cat:' . $category : 'any');
                [$ok, $retry] = $this->throttleOk($key, $rule['rate_limit']);
                if (!$ok) {
                    return ['action' => 'throttle', 'status' => 429, 'retry_after' => $retry];
                }
            }
            return null;
        } catch (\Throwable $e) {
            return null; // fail-open
        }
    }

    // --- bundle load / verify -----------------------------------------------

    /** @return array<string,mixed>|null */
    private function loadBundle(): ?array
    {
        $bundleFile = $this->cacheDir . '/silentshield_policy_bundle.json';
        $cached     = $this->readCache($bundleFile, self::BUNDLE_TTL);

        // Fresh enough → no network on the request path.
        if ($cached !== null && (time() - @filemtime($bundleFile)) < self::REFRESH_INTERVAL) {
            return $cached;
        }

        // Claim the refresh slot so concurrent requests don't all fetch.
        $claim = $this->cacheDir . '/silentshield_policy_fresh';
        if (@filemtime($claim) !== false && (time() - (int) @filemtime($claim)) < self::REFRESH_INTERVAL) {
            return $cached; // someone refreshed recently; use what we have
        }
        @touch($claim);

        $keys = $this->signingKeys();
        if ($keys === []) {
            return $cached;
        }
        $body = $this->httpGet($this->policyUrl, ['x-api-key: ' . $this->apiKey]);
        if ($body === null) {
            return $cached;
        }
        $bundle = $this->verifyBundle($body, $keys);
        if ($bundle === null) {
            return $cached;
        }
        @file_put_contents($bundleFile, json_encode($bundle), LOCK_EX);
        return $bundle;
    }

    /** @return array<string,string> kid => raw 32-byte public key */
    private function signingKeys(): array
    {
        $file   = $this->cacheDir . '/silentshield_policy_keys.json';
        $cached = $this->readCache($file, self::KEYS_TTL);
        if (\is_array($cached) && $cached !== []) {
            $out = [];
            foreach ($cached as $kid => $b64) {
                $raw = base64_decode((string) $b64, true);
                if ($raw !== false && \strlen($raw) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                    $out[(string) $kid] = $raw;
                }
            }
            if ($out !== []) {
                return $out;
            }
        }

        $body = $this->httpGet($this->keysUrl, []);
        if ($body === null) {
            return [];
        }
        $data = json_decode($body, true);
        if (!\is_array($data) || !\is_array($data['keys'] ?? null)) {
            return [];
        }
        $store = [];
        $out   = [];
        foreach ($data['keys'] as $k) {
            $kid = (string) ($k['kid'] ?? '');
            $b64 = (string) ($k['key'] ?? '');
            if ($kid === '' || $b64 === '') {
                continue;
            }
            $raw = base64_decode($b64, true);
            if ($raw !== false && \strlen($raw) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                $store[$kid] = $b64;
                $out[$kid]   = $raw;
            }
        }
        if ($store !== []) {
            @file_put_contents($file, json_encode($store), LOCK_EX);
        }
        return $out;
    }

    /**
     * Verify a signed-bundle envelope; return the decoded bundle or null.
     *
     * @param array<string,string> $keys kid => raw public key
     * @return array<string,mixed>|null
     */
    private function verifyBundle(string $body, array $keys): ?array
    {
        $env = json_decode($body, true);
        if (!\is_array($env) || ($env['alg'] ?? '') !== 'ed25519') {
            return null;
        }
        $kid = (string) ($env['kid'] ?? '');
        if ($kid === '' || !isset($keys[$kid])) {
            return null;
        }
        $payload = base64_decode((string) ($env['payload'] ?? ''), true);
        $sig     = base64_decode((string) ($env['sig'] ?? ''), true);
        if ($payload === false || $sig === false || \strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return null;
        }
        if (!sodium_crypto_sign_verify_detached($sig, $payload, $keys[$kid])) {
            return null;
        }
        $bundle = json_decode($payload, true);
        if (!\is_array($bundle) || (int) ($bundle['format_version'] ?? 1) > 1) {
            return null;
        }
        return $bundle;
    }

    // --- decision -----------------------------------------------------------

    /**
     * @param array<string,mixed>      $bundle
     * @param array<string,mixed>      $server
     * @return array{0:string,1:string,2:bool} [slug, category, verified]
     */
    private function identify(string $ua, array $bundle, array $server): array
    {
        $uaLc = strtolower($ua);
        $slug = '';
        $cat  = '';
        $best = 0;
        $matchedCidrs = [];
        foreach (\is_array($bundle['agents'] ?? null) ? $bundle['agents'] : [] as $a) {
            foreach (\is_array($a['ua_tokens'] ?? null) ? $a['ua_tokens'] : [] as $tok) {
                $tl = strtolower((string) $tok);
                if ($tl !== '' && str_contains($uaLc, $tl) && \strlen($tl) > $best) {
                    $best         = \strlen($tl);
                    $slug         = (string) ($a['slug'] ?? '');
                    $cat          = (string) ($a['category'] ?? '');
                    $matchedCidrs = \is_array($a['cidrs'] ?? null) ? $a['cidrs'] : [];
                }
            }
        }
        $verified = false;
        if ($slug !== '' && $matchedCidrs !== []) {
            $ip = isset($server['REMOTE_ADDR']) ? (string) $server['REMOTE_ADDR'] : '';
            foreach ($matchedCidrs as $cidr) {
                if ($this->ipInCidr($ip, (string) $cidr)) {
                    $verified = true;
                    break;
                }
            }
        }
        return [$slug, $cat, $verified];
    }

    /**
     * @param array<int,array<string,mixed>> $rules
     * @return array<string,mixed>|null
     */
    private function evaluate(array $rules, string $slug, string $category, bool $verified, string $path, string $method): ?array
    {
        foreach ($rules as $rule) {
            if (!\is_array($rule)) {
                continue;
            }
            if (!$this->matchApplies(\is_array($rule['match'] ?? null) ? $rule['match'] : [], $slug, $category, $verified)) {
                continue;
            }
            if (!$this->pathMatches((string) ($rule['path_pattern'] ?? ''), $path)) {
                continue;
            }
            if (!$this->methodMatches(\is_array($rule['methods'] ?? null) ? $rule['methods'] : [], $method)) {
                continue;
            }
            return $rule;
        }
        return null;
    }

    /** @param array<string,mixed> $match */
    private function matchApplies(array $match, string $slug, string $category, bool $verified): bool
    {
        return match ((string) ($match['type'] ?? '')) {
            'any'            => true,
            'agent_slug'     => $slug !== '' && $slug === (string) ($match['value'] ?? ''),
            'agent_category' => $category !== '' && $category === (string) ($match['value'] ?? ''),
            'unsigned'       => !$verified,
            default          => false,
        };
    }

    private function pathMatches(string $pattern, string $path): bool
    {
        if ($pattern === '' || $pattern === '*') {
            return true;
        }
        if (str_ends_with($pattern, '*')) {
            return str_starts_with($path, substr($pattern, 0, -1));
        }
        return $path === $pattern;
    }

    /** @param array<int,string> $methods */
    private function methodMatches(array $methods, string $method): bool
    {
        if ($methods === []) {
            return true;
        }
        $m = strtoupper(trim($method));
        foreach ($methods as $allowed) {
            if (strtoupper(trim((string) $allowed)) === $m) {
                return true;
            }
        }
        return false;
    }

    /**
     * Fixed-window throttle counter backed by cache files. Best-effort.
     *
     * @param array{requests?:int,window_sec?:int} $rl
     * @return array{0:bool,1:int} [allowed, retryAfterSeconds]
     */
    private function throttleOk(string $key, array $rl): array
    {
        $requests = (int) ($rl['requests'] ?? 0);
        $window   = (int) ($rl['window_sec'] ?? 0);
        if ($requests <= 0 || $window <= 0) {
            return [true, 0];
        }
        $now    = time();
        $bucket = intdiv($now, $window);
        $file   = $this->cacheDir . '/silentshield_thr_' . md5($key) . '_' . $bucket;
        $count  = (int) @file_get_contents($file);
        $count++;
        @file_put_contents($file, (string) $count, LOCK_EX);
        if ($count > $requests) {
            $retry = (($bucket + 1) * $window) - $now;
            return [false, $retry < 1 ? 1 : $retry];
        }
        return [true, 0];
    }

    // --- helpers ------------------------------------------------------------

    /** @return array<mixed>|null */
    private function readCache(string $file, int $ttl): ?array
    {
        $mtime = @filemtime($file);
        if ($mtime === false || (time() - $mtime) >= $ttl) {
            return null;
        }
        $raw = @file_get_contents($file);
        if ($raw === false) {
            return null;
        }
        $data = json_decode($raw, true);
        return \is_array($data) ? $data : null;
    }

    /** @param array<int,string> $headers */
    private function httpGet(string $url, array $headers): ?string
    {
        $ch = curl_init($url);
        if ($ch === false) {
            return null;
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_SSL_VERIFYPEER => !$this->insecure,
            CURLOPT_SSL_VERIFYHOST => $this->insecure ? 0 : 2,
        ]);
        $body   = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        if (!\is_string($body) || $status !== 200) {
            return null;
        }
        return $body;
    }

    /** @param array<string,mixed> $server */
    private function requestPath(array $server): string
    {
        $uri  = isset($server['REQUEST_URI']) ? (string) $server['REQUEST_URI'] : '/';
        $path = parse_url($uri, PHP_URL_PATH);
        return (\is_string($path) && $path !== '') ? $path : '/';
    }

    private function ipInCidr(string $ip, string $cidr): bool
    {
        if ($ip === '' || !str_contains($cidr, '/')) {
            return false;
        }
        [$subnet, $bitsStr] = explode('/', $cidr, 2);
        $bits    = (int) $bitsStr;
        $ipBin   = @inet_pton($ip);
        $netBin  = @inet_pton($subnet);
        if ($ipBin === false || $netBin === false || \strlen($ipBin) !== \strlen($netBin)) {
            return false;
        }
        $bytes = \strlen($ipBin);
        if ($bits < 0 || $bits > $bytes * 8) {
            return false;
        }
        $full = intdiv($bits, 8);
        if ($full > 0 && strncmp($ipBin, $netBin, $full) !== 0) {
            return false;
        }
        $rem = $bits % 8;
        if ($rem === 0) {
            return true;
        }
        $mask = \chr((0xff << (8 - $rem)) & 0xff);
        return (\ord($ipBin[$full]) & \ord($mask)) === (\ord($netBin[$full]) & \ord($mask));
    }
}
