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

    /**
     * Minimum confidence required on top of a "human" verdict. Zero: the verdict
     * is trusted on its own.
     *
     * This was 0.7, and it quietly overrode the site owner's own setting. The
     * service decides human-or-not against the bot threshold configured in their
     * dashboard — 0.30 by default — and then reports the score as `confidence`.
     * A second threshold here rejected the whole band in between: measured on
     * production, a submission scored 0.345, came back ok with verdict "human",
     * was recorded by the service as a passed check, and this client still
     * answered "not human", so the site turned a real visitor away.
     */
    private const HUMAN_CONFIDENCE_THRESHOLD = 0.0;

    /**
     * Why the last verify() answered false. Read it with lastFailure().
     *
     * verify() returns a bool, and a bool cannot distinguish "the service
     * judged this a bot" from "we never got an answer". That difference is not
     * academic: when a site's monthly quota runs out the service answers 429,
     * this client fails secure, and every REAL visitor is turned away as if
     * they were a bot — on a site whose owner sees nothing but "bot check
     * failed" and reasonably blames the bot detection.
     *
     * verify() keeps its meaning (fail-secure). These constants only let you
     * see the reason and decide for yourself — see the README for the
     * recommended handling of FAILURE_QUOTA_EXCEEDED.
     */
    public const FAILURE_NONE           = '';                // verify() returned true
    public const FAILURE_BOT            = 'bot';             // answered, not human — the intended case
    public const FAILURE_QUOTA_EXCEEDED = 'quota_exceeded';  // 429, monthly quota used up
    public const FAILURE_RATE_LIMITED   = 'rate_limited';    // 429, short-lived
    public const FAILURE_HTTP           = 'http';            // any other non-2xx
    public const FAILURE_TRANSPORT      = 'transport';       // no answer at all
    public const FAILURE_MALFORMED      = 'malformed';       // answer we could not read

    /** @var string One of the FAILURE_* constants; set by every verify() call. */
    private string $lastFailure = self::FAILURE_NONE;

    /** @var int|null Seconds until the quota resets, from Retry-After. Null when unknown. */
    private ?int $lastRetryAfter = null;

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
     * @param string      $nonce   The nonce collected from the submitted form.
     * @param string|null $pageUrl The page the form sits on. Optional; when
     *        omitted it is auto-detected from $_SERVER. Sent so the dashboard
     *        can name a form the server checks but no scan ever found — a
     *        server-to-server verify carries no Referer, so this is the only
     *        way that page reaches the service. Never affects the verdict.
     * @return bool True only when the service judged the submitter human.
     */
    public function verify(string $nonce, ?string $pageUrl = null): bool
    {
        $body = ['nonce' => $nonce];
        $page = $pageUrl ?? $this->currentPageUrl();
        if ($page !== '') {
            $body['page_url'] = $page;
        }
        $payload = json_encode($body, JSON_UNESCAPED_SLASHES);
        if ($payload === false) {
            return false; // encoding failed — fail secure
        }

        $this->lastFailure    = self::FAILURE_NONE;
        $this->lastRetryAfter = null;

        $ch = curl_init(self::VERIFY_URL);
        if ($ch === false) {
            $this->lastFailure = self::FAILURE_TRANSPORT;
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

        if (!is_string($body)) {
            $this->lastFailure = self::FAILURE_TRANSPORT;
            return false; // no answer at all — fail secure
        }

        if ($status < 200 || $status >= 300) {
            // Read the reason BEFORE failing. A 429 has two very different
            // meanings and the body is what tells them apart.
            $this->lastFailure = self::classifyErrorBody($status, $body);
            if ($this->lastFailure === self::FAILURE_QUOTA_EXCEEDED) {
                $decoded = json_decode($body, true);
                if (is_array($decoded) && isset($decoded['month']['ResetSecs'])) {
                    $this->lastRetryAfter = (int) $decoded['month']['ResetSecs'];
                }
            }
            return false; // HTTP error — fail secure
        }

        $data = json_decode($body, true);
        if (!is_array($data)) {
            $this->lastFailure = self::FAILURE_MALFORMED;
            return false; // malformed body — fail secure
        }

        // Human iff: ok === true && verdict === "human" (the verdict already
        // carries the owner's threshold; see HUMAN_CONFIDENCE_THRESHOLD).
        $ok         = ($data['ok'] ?? null) === true;
        $verdict    = ($data['verdict'] ?? null) === 'human';
        $confidence = (float) ($data['confidence'] ?? 0.0);

        $human = $ok && $verdict && $confidence >= self::HUMAN_CONFIDENCE_THRESHOLD;
        if (!$human) {
            // The service answered and said no. This is the ONLY case in which
            // turning the submission away is what the site owner asked for.
            $this->lastFailure = self::FAILURE_BOT;
        }

        return $human;
    }

    /**
     * Why the last verify() returned false — one of the FAILURE_* constants.
     *
     * Returns FAILURE_NONE after a successful verify. The case worth handling
     * is FAILURE_QUOTA_EXCEEDED: the service never assessed this visitor at
     * all, so rejecting them says nothing about whether they were human.
     *
     * ```php
     * if (!$client->verify($nonce)) {
     *     if ($client->lastFailure() === Client::FAILURE_QUOTA_EXCEEDED) {
     *         // Our quota is used up — this is OUR billing state, not the
     *         // visitor's fault. Fall back to your own checks (honeypot,
     *         // timing) instead of turning real people away for weeks.
     *         error_log('SilentShield quota exhausted, resets in '
     *             . ($client->lastRetryAfter() ?? 0) . 's');
     *     } else {
     *         reject();
     *     }
     * }
     * ```
     */
    public function lastFailure(): string
    {
        return $this->lastFailure;
    }

    /**
     * Seconds until the quota resets, when the last failure was
     * FAILURE_QUOTA_EXCEEDED. Null otherwise. A monthly quota resets on the
     * 1st, so expect a value in days — that alone tells it apart from a rate
     * limit, which is over in seconds.
     */
    public function lastRetryAfter(): ?int
    {
        return $this->lastRetryAfter;
    }

    /**
     * Maps a non-2xx answer to a FAILURE_* constant.
     *
     * A 429 is the whole reason this exists: the quota middleware, the API-key
     * guard and the rate limiter all answer 429, and only the body says which
     * one it was. Static and pure so it can be tested without a network.
     */
    private static function classifyErrorBody(int $status, string $body): string
    {
        if ($status !== 429) {
            return self::FAILURE_HTTP;
        }

        $decoded = json_decode($body, true);
        $error   = is_array($decoded) ? ($decoded['error'] ?? '') : '';

        if ($error === 'quota_exceeded') {
            return self::FAILURE_QUOTA_EXCEEDED;
        }

        // "rate_limited" (api key guard) and "too many requests" (rate limiter)
        // are the same thing to the caller: wait a moment and it passes.
        return self::FAILURE_RATE_LIMITED;
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

    /**
     * Best-effort URL of the page verify() is being called for, from $_SERVER.
     * Returns '' when it cannot be built (e.g. CLI) — the caller then simply
     * sends no page. Capped so a crafted request cannot bloat the payload; the
     * service caps again on its side.
     */
    private function currentPageUrl(): string
    {
        $server = $_SERVER ?? [];
        $host = (string) ($server['HTTP_HOST'] ?? '');
        $uri  = (string) ($server['REQUEST_URI'] ?? '');
        if ($host === '' || $uri === '') {
            return '';
        }
        $scheme = $this->detectScheme($server);
        if ($scheme === '') {
            $scheme = 'https';
        }
        return substr($scheme . '://' . $host . $uri, 0, 1024);
    }
}
