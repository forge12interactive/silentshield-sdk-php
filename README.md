# SilentShield PHP SDK

One dependency-free PHP package that bundles SilentShield's request-time capabilities:

1. **Verify** — confirm a form submission came from a real human (call on submit).
2. **Observe** — fire-and-forget telemetry about AI-agent / bot traffic (call once at bootstrap on every request).
3. **Enforce** — actually block disallowed AI bots per your dashboard policy (403/429).

Requires **PHP 8.1+**, `ext-curl` and `ext-sodium` (the last two ship with PHP core). No third-party dependencies.

## Install

The package is distributed from its GitHub repo (not Packagist). Add the repo as
a Composer source once, then require it by name:

```bash
composer config repositories.silentshield vcs https://github.com/forge12interactive/silentshield-sdk-php
composer require forge12interactive/silentshield-sdk
```

Or add it to your `composer.json` directly:

```json
{
  "repositories": [
    { "type": "vcs", "url": "https://github.com/forge12interactive/silentshield-sdk-php" }
  ],
  "require": {
    "forge12interactive/silentshield-sdk": "^1.0"
  }
}
```

Or, if you prefer no autoloader, just `require` the single source file(s):

```php
require '/path/to/silentshield-sdk-php/src/Client.php';
require '/path/to/silentshield-sdk-php/src/Enforcer.php';
```

## Usage — one package, both jobs

Create the client once with your API key:

```php
use SilentShield\Client;

$client = new Client('YOUR_SILENTSHIELD_API_KEY');
```

### 1. Observe every request (bootstrap)

Call `observe()` as early as possible in your front controller / bootstrap. It
inspects the current request and, **only if it looks like a bot candidate**
(known AI-agent User-Agent token, or an HTTP Message Signature header),
schedules a beacon that runs **after** the response is delivered to the client
(via `fastcgi_finish_request()` when available). It never sends telemetry for
ordinary human traffic, and never throws.

```php
// index.php / bootstrap
$client->observe(); // reads from $_SERVER; safe to call on every request
```

### 2. Verify on form submit

Collect the SilentShield nonce from your form and verify it when the form is
submitted. `verify()` returns `true` **only** for a human verdict
(`ok === true && verdict === "human"`) — the verdict already reflects the bot
threshold you configured in your dashboard. It is **fail-secure**: any
API/transport error returns `false`.

The field is named **`behavior_nonce`** — that is what the widget injects into
your form. (Earlier versions of this README said `silentshield_nonce`; that
field is never set, so following it meant verifying an empty string and
rejecting every submission.)

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nonce = $_POST['behavior_nonce'] ?? '';

    if ($client->verify($nonce)) {
        // Human — process the submission.
    } else {
        // Bot or verification failed — reject / challenge.
        http_response_code(403);
        exit('Verification failed.');
    }
}
```

#### Why `false` is not always "bot"

`verify()` is fail-secure, so it also returns `false` when we could not answer
at all. One of those cases deserves its own handling: **your monthly quota is
used up.** The service then answers `429 quota_exceeded`, and until the 1st of
next month every real visitor would be turned away as a bot — on a site whose
owner sees nothing but "verification failed" and reasonably blames the bot
detection.

`lastFailure()` tells you which case you are in:

```php
if (!$client->verify($nonce)) {
    if ($client->lastFailure() === Client::FAILURE_QUOTA_EXCEEDED) {
        // OUR billing state, not this visitor's fault. Fall back to your own
        // checks (honeypot, timing, rate limit) instead of rejecting humans
        // for the rest of the month — and top up the plan.
        error_log('SilentShield quota exhausted; resets in '
            . ($client->lastRetryAfter() ?? 0) . 's');
        // …your own decision here…
    } else {
        http_response_code(403);
        exit('Verification failed.');
    }
}
```

| `lastFailure()` | Meaning | Suggested handling |
|---|---|---|
| `FAILURE_BOT` | The service assessed the visitor and said no | Reject — this is the case you configured |
| `FAILURE_QUOTA_EXCEEDED` | Monthly quota used up (429). Lasts until the 1st | Fall back to your own checks; upgrade |
| `FAILURE_RATE_LIMITED` | Too many requests right now (429). Over in seconds | Reject or retry |
| `FAILURE_TRANSPORT` | No answer at all (network, timeout) | Your call — reject is the safe default |
| `FAILURE_HTTP` / `FAILURE_MALFORMED` | Any other non-2xx / unreadable answer | Reject, and check your key |

### Options

```php
$client = new Client('YOUR_KEY', [
    'verify_timeout'  => 5,        // seconds, blocking verify call
    'observe_timeout' => 2,        // seconds, fire-and-forget beacon
    'cache_dir'       => sys_get_temp_dir(), // bot-directory cache location
    'insecure'        => false,    // dev only: skip TLS verification
]);
```

## How bot detection works

`observe()` treats a request as a bot candidate when the User-Agent matches a
known AI-agent token **or** any `Signature*` request header is present. The
known-token list is refreshed (and cached ~24h to a temp file) from the live
bot directory at `https://api.silentshield.io/api/v1/agent/bot-directory`, with
an embedded fallback list (GPTBot, ClaudeBot, PerplexityBot, Bingbot, Applebot,
Amazonbot, CCBot, Bytespider, meta-externalagent, and more).

## GDPR / privacy note

The **observe** feature sends minimal telemetry about **bot** requests only —
User-Agent, IP, request path (query string stripped), HTTP method, and any HTTP
Message Signature metadata. It is **never** triggered for human visitors, so no
telemetry about your human users is transmitted. Because the IP address of an
automated agent may in some jurisdictions be treated as personal data, disclose
this processing in your privacy policy and ensure you have a lawful basis (e.g.
legitimate interest in security and abuse prevention). Verification only
transmits the opaque nonce you collected — no form field contents are sent.

## Testing

A dependency-free test runner is included:

```bash
C:\xampp\php\php.exe tests\ClientTest.php
```

## Enforcement — actually block AI bots (`Enforcer`)

`Client::observe()` only records visits. To **block** disallowed bots per the
policy you set in the SilentShield dashboard, use the `Enforcer`. It fetches the
signed policy bundle, verifies its Ed25519 signature (libsodium) against the
pinned keys, caches it on disk, and decides per request — a **403** for a denied
bot, **429** for a throttled one. **Fail-open:** any error, an unverifiable
bundle, or monitor mode lets the request through.

Drop it in at the very top of your front controller:

```php
require __DIR__ . '/vendor/autoload.php';

// Blocks + exits on a denied bot; otherwise returns and your app continues.
(new \SilentShield\Enforcer('YOUR_SITE_KEY'))->enforce();
```

Or decide yourself:

```php
$decision = (new \SilentShield\Enforcer('YOUR_SITE_KEY'))->decide();
if ($decision !== null) {
    http_response_code($decision['status']);          // 403 or 429
    if ($decision['retry_after'] > 0) header('Retry-After: ' . $decision['retry_after']);
    exit;
}
```

Requirements: `ext-sodium` + `ext-curl` (both in PHP 8.1 core). For a real block,
`agent_gateway_enforce` must be enabled and a Block rule set on the key (otherwise
the bundle is `monitor` → nothing blocks). Bots are *verified* only when their
source IP is in the operator's published range; behind a reverse proxy, restore
the real client IP into `$_SERVER['REMOTE_ADDR']`.

> Using **WordPress**? The SilentShield plugin ships this enforcer built-in from
> v2.9.0 — enable it under Advanced → "Block AI crawlers (enforce)". No code.

## License

MIT
