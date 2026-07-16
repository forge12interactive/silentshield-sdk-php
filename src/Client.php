<?php

declare(strict_types=1);

namespace SilentShield;

/**
 * SilentShield PHP SDK client.
 *
 * One class, two jobs:
 *   1. verify()  — confirm a form submission came from a human (call on submit).
 *   2. observe() — fire-and-forget telemetry about AI-agent / bot traffic
 *                  (call once at bootstrap on every request).
 *
 * Dependency-free: uses only ext-curl and core PHP. No autoloader required —
 * you may `require` this file directly.
 *
 * @see https://silentshield.io
 */
final class Client
{
    /**
     * Base URL for the verify endpoint's host. The full paths are hard-coded
     * per the API contract (verify lives under /v1, telemetry under /api/v1).
     */
    private const VERIFY_URL         = 'https://api.silentshield.io/v1/verify';
    private const TELEMETRY_URL      = 'https://api.silentshield.io/api/v1/agent/telemetry';
    private const BOT_DIRECTORY_URL  = 'https://api.silentshield.io/api/v1/agent/bot-directory';

    /** A submission is human iff confidence meets this floor. */
    private const HUMAN_CONFIDENCE_THRESHOLD = 0.7;

    /** Bot-directory cache time-to-live in seconds (~24h). */
    private const DIRECTORY_CACHE_TTL = 86400;

    /**
     * Embedded fallback list of known AI-agent User-Agent tokens.
     * Used when the live bot-directory cannot be fetched/cached.
     *
     * @var string[]
     */
    private const FALLBACK_UA_TOKENS = [
        'GPTBot',
        'OAI-SearchBot',
        'ChatGPT-User',
        'ClaudeBot',
        'Claude-User',
        'PerplexityBot',
        'Perplexity-User',
        'Bingbot',
        'Applebot',
        'Amazonbot',
        'CCBot',
        'Bytespider',
        'meta-externalagent',
        'Google-Agent',
    ];

    /** @var string SilentShield API key. */
    private string $apiKey;

    /** @var int Total cURL timeout for the (blocking) verify call, seconds. */
    private int $verifyTimeout;

    /** @var int Total cURL timeout for the fire-and-forget observe call, seconds. */
    private int $observeTimeout;

    /** @var bool When true, verify() bypasses TLS peer verification (dev only). */
    private bool $insecure;

    /** @var string Directory used to cache the bot directory. */
    private string $cacheDir;

    /** @var string[]|null Lazily-resolved list of known agent UA tokens. */
    private ?array $agentTokens = null;

    /**
     * @param string $apiKey SilentShield API key.
     * @param array{
     *     verify_timeout?: int,
     *     observe_timeout?: int,
     *     insecure?: bool,
     *     cache_dir?: string
     * } $opts Optional configuration overrides.
     */
    public function __construct(string $apiKey, array $opts = [])
    {
        $this->apiKey         = $apiKey;
        $this->verifyTimeout  = (int) ($opts['verify_timeout']  ?? 5);
        $this->observeTimeout = (int) ($opts['observe_timeout'] ?? 2);
        $this->insecure       = (bool) ($opts['insecure']       ?? false);
        $this->cacheDir       = (string) ($opts['cache_dir']    ?? sys_get_temp_dir());
    }

    // ---------------------------------------------------------------------
    // VERIFY  (blocking, fail-secure)
    // ---------------------------------------------------------------------

    /**
     * Verify a form submission via its SilentShield nonce.
     *
     * Fail-secure: any transport error, non-2xx status, malformed body, or a
     * verdict that is not a confident "human" returns false.
     *
     * @param string $nonce The nonce collected from the submitted form.
     * @return bool True only when the submitter is a confident human.
     */
    public function verify(string $nonce): bool
    {
        $payload = json_encode(['nonce' => $nonce], JSON_UNESCAPED_SLASHES);
        if ($payload === false) {
            return false; // encoding failed — fail secure
        }

        $ch = curl_init(self::VERIFY_URL);
        if ($ch === false) {
            return false;
        }

        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $payload,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->verifyTimeout,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'Accept: application/json',
                'api-key: ' . $this->apiKey,
            ],
            CURLOPT_SSL_VERIFYPEER => !$this->insecure,
            CURLOPT_SSL_VERIFYHOST => $this->insecure ? 0 : 2,
        ]);

        $body   = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        if (!is_string($body) || $status < 200 || $status >= 300) {
            return false; // transport/HTTP error — fail secure
        }

        $data = json_decode($body, true);
        if (!is_array($data)) {
            return false; // malformed body — fail secure
        }

        // Human iff: ok === true && verdict === "human" && confidence >= 0.7
        $ok         = ($data['ok'] ?? null) === true;
        $verdict    = ($data['verdict'] ?? null) === 'human';
        $confidence = (float) ($data['confidence'] ?? 0.0);

        return $ok && $verdict && $confidence >= self::HUMAN_CONFIDENCE_THRESHOLD;
    }

    // ---------------------------------------------------------------------
    // OBSERVE  (deferred, fire-and-forget, fail-open)
    // ---------------------------------------------------------------------

    /**
     * Observe the current request. If (and only if) the request looks like a
     * bot candidate, schedule a fire-and-forget telemetry beacon to run AFTER
     * the response has been delivered to the client.
     *
     * Never throws: observation must never affect the served request.
     *
     * @param array<string,mixed>|null $server Server vars (defaults to $_SERVER).
     */
    public function observe(?array $server = null): void
    {
        try {
            $server = $server ?? $_SERVER;

            $ua = (string) ($server['HTTP_USER_AGENT'] ?? '');

            // Any of the HTTP Message Signature headers marks a signed agent.
            $signature      = (string) ($server['HTTP_SIGNATURE'] ?? '');
            $signatureInput = (string) ($server['HTTP_SIGNATURE_INPUT'] ?? '');
            $signatureAgent = (string) ($server['HTTP_SIGNATURE_AGENT'] ?? '');

            // Only beacon for bot candidates — never for human traffic.
            if (!$this->isBotCandidate($ua, $signature . $signatureInput . $signatureAgent)) {
                return;
            }

            // Strip the query string from the path.
            $rawUri = (string) ($server['REQUEST_URI'] ?? '');
            $path   = $rawUri === '' ? '' : (string) (parse_url($rawUri, PHP_URL_PATH) ?? $rawUri);

            $sighting = [
                'ua'     => $ua,
                'ip'     => (string) ($server['REMOTE_ADDR'] ?? ''),
                'path'   => $path,
                'method' => (string) ($server['REQUEST_METHOD'] ?? ''),
            ];

            // Optional HTTP Message Signature fields — only when present.
            if ($signature !== '') {
                $sighting['signature'] = $signature;
            }
            if ($signatureInput !== '') {
                $sighting['signature_input'] = $signatureInput;
            }
            if ($signatureAgent !== '') {
                $sighting['signature_agent'] = $signatureAgent;
            }
            // authority + scheme give the signed request's target origin.
            $authority = (string) ($server['HTTP_HOST'] ?? '');
            if ($authority !== '') {
                $sighting['authority'] = $authority;
            }
            $scheme = $this->detectScheme($server);
            if ($scheme !== '') {
                $sighting['scheme'] = $scheme;
            }

            $payload = json_encode(['sightings' => [$sighting]], JSON_UNESCAPED_SLASHES);
            if ($payload === false) {
                return; // fail-open
            }

            // Defer the beacon until after the response is flushed.
            $send = function () use ($payload): void {
                // Flush the response to the client first if we can (PHP-FPM).
                if (function_exists('fastcgi_finish_request')) {
                    @fastcgi_finish_request();
                }
                $this->sendTelemetry($payload);
            };

            register_shutdown_function($send);
        } catch (\Throwable $e) {
            // Fail-open: observation must never break the request.
        }
    }

    /**
     * Decide whether a request is a bot candidate worth reporting.
     *
     * A request is a candidate when either:
     *   - its User-Agent contains a known AI-agent token, OR
     *   - it carries any HTTP Message Signature material.
     *
     * @param string $ua        The request User-Agent.
     * @param string $signature Combined signature header material ('' if none).
     * @return bool True if the request is a bot candidate.
     */
    public function isBotCandidate(string $ua, string $signature): bool
    {
        // A signed request is always a candidate, regardless of UA.
        if (trim($signature) !== '') {
            return true;
        }

        if ($ua === '') {
            return false;
        }

        foreach ($this->getAgentTokens() as $token) {
            if ($token !== '' && stripos($ua, $token) !== false) {
                return true;
            }
        }

        return false;
    }

    // ---------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------

    /**
     * Fire-and-forget POST of the telemetry payload. Best-effort only.
     *
     * @param string $payload JSON request body.
     */
    private function sendTelemetry(string $payload): void
    {
        try {
            $ch = curl_init(self::TELEMETRY_URL);
            if ($ch === false) {
                return;
            }

            curl_setopt_array($ch, [
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => $payload,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => $this->observeTimeout,
                CURLOPT_CONNECTTIMEOUT => $this->observeTimeout,
                CURLOPT_HTTPHEADER     => [
                    'Content-Type: application/json',
                    'x-api-key: ' . $this->apiKey,
                ],
                CURLOPT_SSL_VERIFYPEER => !$this->insecure,
                CURLOPT_SSL_VERIFYHOST => $this->insecure ? 0 : 2,
            ]);

            curl_exec($ch);
            curl_close($ch);
        } catch (\Throwable $e) {
            // Swallow everything — telemetry is best-effort.
        }
    }

    /**
     * Resolve the list of known AI-agent UA tokens, preferring a freshly
     * cached copy of the live bot directory and falling back to the embedded
     * constant list.
     *
     * @return string[]
     */
    private function getAgentTokens(): array
    {
        if ($this->agentTokens !== null) {
            return $this->agentTokens;
        }

        $tokens = $this->loadDirectoryTokens();
        if (empty($tokens)) {
            $tokens = self::FALLBACK_UA_TOKENS;
        }

        return $this->agentTokens = array_values(array_unique($tokens));
    }

    /**
     * Load agent UA tokens from a ~24h temp-file cache, refreshing from the
     * live bot-directory endpoint when the cache is missing or stale.
     *
     * @return string[] Empty array on any failure (caller falls back).
     */
    private function loadDirectoryTokens(): array
    {
        $cacheFile = rtrim($this->cacheDir, "/\\")
            . DIRECTORY_SEPARATOR . 'silentshield_bot_directory.json';

        // Fresh cache hit?
        if (is_readable($cacheFile)
            && (time() - (int) @filemtime($cacheFile)) < self::DIRECTORY_CACHE_TTL
        ) {
            $cached = @file_get_contents($cacheFile);
            if (is_string($cached) && $cached !== '') {
                $tokens = $this->parseDirectoryTokens($cached);
                if (!empty($tokens)) {
                    return $tokens;
                }
            }
        }

        // Refresh from the live directory (best-effort).
        $body = $this->fetchBotDirectory();
        if ($body === null) {
            return [];
        }

        $tokens = $this->parseDirectoryTokens($body);
        if (!empty($tokens)) {
            @file_put_contents($cacheFile, $body, LOCK_EX);
        }

        return $tokens;
    }

    /**
     * Extract the flat list of ua_tokens from a bot-directory JSON body.
     *
     * @param string $body Raw JSON from the bot-directory endpoint/cache.
     * @return string[]
     */
    private function parseDirectoryTokens(string $body): array
    {
        $data = json_decode($body, true);
        if (!is_array($data) || !isset($data['agents']) || !is_array($data['agents'])) {
            return [];
        }

        $tokens = [];
        foreach ($data['agents'] as $agent) {
            if (!is_array($agent) || !isset($agent['ua_tokens']) || !is_array($agent['ua_tokens'])) {
                continue;
            }
            foreach ($agent['ua_tokens'] as $token) {
                if (is_string($token) && $token !== '') {
                    $tokens[] = $token;
                }
            }
        }

        return $tokens;
    }

    /**
     * Fetch the raw bot-directory JSON. Best-effort; returns null on failure.
     */
    private function fetchBotDirectory(): ?string
    {
        $ch = curl_init(self::BOT_DIRECTORY_URL);
        if ($ch === false) {
            return null;
        }

        curl_setopt_array($ch, [
            CURLOPT_HTTPGET        => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->observeTimeout,
            CURLOPT_CONNECTTIMEOUT => $this->observeTimeout,
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
            CURLOPT_SSL_VERIFYPEER => !$this->insecure,
            CURLOPT_SSL_VERIFYHOST => $this->insecure ? 0 : 2,
        ]);

        $body   = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        if (!is_string($body) || $status < 200 || $status >= 300) {
            return null;
        }

        return $body;
    }

    /**
     * Best-effort detection of the request scheme (http/https).
     *
     * @param array<string,mixed> $server
     */
    private function detectScheme(array $server): string
    {
        $https = (string) ($server['HTTPS'] ?? '');
        if ($https !== '' && strtolower($https) !== 'off') {
            return 'https';
        }
        $forwarded = strtolower((string) ($server['HTTP_X_FORWARDED_PROTO'] ?? ''));
        if ($forwarded !== '') {
            return $forwarded;
        }
        if ((int) ($server['SERVER_PORT'] ?? 0) === 443) {
            return 'https';
        }
        return '';
    }
}
