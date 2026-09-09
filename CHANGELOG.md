# Changelog — SilentShield PHP SDK

All notable changes to `forge12interactive/silentshield-sdk`.
This project follows [Semantic Versioning](https://semver.org/).

## [1.3.0] — 2026-09-09

### Added

**`Client::reportBlock()` — melden, was Ihr eigener Code abweist.**

Sperren, die Sie selbst vornehmen, bevor SilentShield gefragt wird, sind für den
Dienst bisher **unsichtbar**: ein Bot ohne JavaScript lädt das Widget nie, sendet
nie Telemetrie und taucht in keiner Statistik auf — obwohl er abgewehrt wurde.
Auf einer echten Kundenseite gemessen (08.09.2026): 6.079 solcher Sperren in
sieben Tagen gegen 2 Absendungen, die den Dienst überhaupt erreichten.

Gemeldete Sperren zählen in „Bots geblockt" und verbrauchen **kein Kontingent**.

Dreizehn Gründe stehen als Konstanten bereit (`Client::BLOCK_HONEYPOT` …): `no_nonce`,
`javascript_missing`, `too_fast`, `token_missing`, `token_unknown`,
`token_reused`, `gibberish`, `ip_blacklisted`, `browser_check`,
`captcha_failed`, `honeypot`, `rate_limited`, `custom_rule`.

🔴 **Nur für Sperren, die den Dienst nie erreicht haben.** Wenn `verify` gefragt
wurde und „nicht menschlich" antwortete, ist die Absendung dort bereits
verzeichnet — eine zusätzliche Meldung zählte dieselbe Absendung ein zweites Mal.
Genau deshalb gibt es für diesen Fall **keine** Konstante: was doppelt zählen
würde, lässt sich mit dieser Schnittstelle gar nicht erst melden.

Die Meldung beeinflusst Ihren Ablauf nicht. Die Sperre ist bei Ihnen bereits
erfolgt, und ein Fehler beim Melden darf daran nichts ändern.

**Die eigene Version wandert als `X-SS-SDK`-Kopfzeile mit** — bei `verify()`,
`observe()` und `reportBlock()`. Ohne sie sieht der Dienst nur Anfragen, aber
nie, womit sie gestellt wurden, und kann Ihnen deshalb auch nicht sagen, wenn
Ihre Einbindung veraltet ist.

## [1.2.0] — 2026-08-07

Two of these are corrections to behaviour that turned real visitors away. If you
run 1.1.0 or older, this is the release to take.

### Fixed

- **A verdict the service called human is no longer rejected by the SDK.**
  `verify()` required a confidence of at least `0.7` on top of the service's
  answer. But the service already decides human-or-not against the bot threshold
  the site owner configured in their dashboard (0.30 by default) and then reports
  the score as `confidence`. The second threshold here silently overrode that
  setting and rejected the whole band in between. Measured on production: a
  submission scored 0.345, came back `ok` with verdict `human`, was counted as a
  passed check in the dashboard — and this SDK still answered "not human", so the
  site turned a real visitor away. The SDK now trusts the verdict; raise the bar
  yourself with the `human_threshold` option if you deliberately want to be
  stricter.

- **An exhausted monthly quota no longer looks like a bot.** `verify()` returned
  `false` for *every* non-2xx answer, so a 429 "quota used up" was
  indistinguishable from "this visitor is a bot" — and a site whose quota ran out
  rejected every real submission until the first of the next month, while the
  operator saw only "bot check failed". `verify()` keeps its meaning (nothing
  breaks), but the reason is now readable:

  ```php
  if (!$client->verify($nonce)) {
      if ($client->lastFailure() === Client::FAILURE_QUOTA_EXCEEDED) {
          // Our fault, not the visitor's — let them through, alert ops.
          error_log('SilentShield quota exhausted, retry after '
              . $client->lastRetryAfter() . 's');
      }
  }
  ```

### Added

- `lastFailure()` returns why the last `verify()` failed, as one of
  `FAILURE_NONE`, `FAILURE_BOT`, `FAILURE_QUOTA_EXCEEDED`, `FAILURE_RATE_LIMITED`,
  `FAILURE_HTTP`, `FAILURE_TRANSPORT`, `FAILURE_MALFORMED`. An answer the SDK
  cannot read is never reported as a quota problem — that would invite an
  integration to wave traffic through on a response nobody understood.
- `lastRetryAfter()` returns the seconds from the `Retry-After` header, or `null`.
  A quota reset is days away, a rate limit is seconds — the number is what tells
  them apart.
- `verify()` takes an optional second argument, the page URL the form sits on;
  when omitted it is auto-detected from `$_SERVER`. A server-to-server verify
  carries no `Referer`, so this is the only way the dashboard can name a form
  that the server checks but no scan ever found. It never affects the verdict.

[1.2.0]: https://github.com/forge12interactive/silentshield-sdk-php/releases/tag/v1.2.0

## [1.1.0] — 2026-07-24

### Added

- Policy enforcer (`SilentShield\Enforcer`) — apply your AI-agent policy in your
  own application, with block reporting back to telemetry.

## [1.0.0] — 2026-07-24

Initial release: human/form verification, AI-agent observation.
