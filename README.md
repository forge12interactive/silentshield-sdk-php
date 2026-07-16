# SilentShield PHP SDK

One dependency-free PHP package that bundles **both** of SilentShield's request-time capabilities:

1. **Verify** — confirm a form submission came from a real human (call on submit).
2. **Observe** — fire-and-forget telemetry about AI-agent / bot traffic (call once at bootstrap on every request).

Requires **PHP 8.1+** and `ext-curl`. No third-party dependencies.

## Install

```bash
composer require silentshield/sdk
```

Or, if you prefer no autoloader, just `require` the single source file:

```php
require '/path/to/silentshield/sdk/src/Client.php';
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
submitted. `verify()` returns `true` **only** for a confident human
(`ok === true && verdict === "human" && confidence >= 0.7`). It is
**fail-secure**: any API/transport error returns `false`.

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nonce = $_POST['silentshield_nonce'] ?? '';

    if ($client->verify($nonce)) {
        // Human — process the submission.
    } else {
        // Bot or verification failed — reject / challenge.
        http_response_code(403);
        exit('Verification failed.');
    }
}
```

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

## License

MIT
