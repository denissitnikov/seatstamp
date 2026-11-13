# Privacy: what the kit stores, sends, and logs

This page lists every value the license server and the Mac SDK keep, why each one counts as personal data or not, and where it goes. Use it as the factual base for your own privacy policy.

## What the license server stores

The Worker keeps all state in one SQLite Durable Object class (`SeatCoordinator`). Each instance is one record, named by its type:

| Record | Field | Purpose | Kept for |
|---|---|---|---|
| `lic:<sha256(domain + purchase key)>` | `meta.tag` | 16-hex order tag printed in every ticket (`ORD-...`) | until the record is wiped |
| | `meta.key_hash` | `sha256(domain + purchase key)`, checked before a seat change | until the record is wiped |
| | `meta.verified_at` | time of the last successful Stripe check (milliseconds) | until the record is wiped |
| | `meta.revoked_before` | ticket cutoff after a seat release (unix seconds) | until the record is wiped |
| | `meta.email_claimed_at` | time the one-time backup email was claimed | until the record is wiped |
| | `meta.email_attempts` | number of backup email send attempts (at most 3) | until the record is wiped |
| | `meta.release_log` | unix seconds of each seat release in the last 365 days (at most 64 entries) | until the record is wiped |
| | `meta.last_evicted_at` | unix seconds of the last automatic eviction | until the record is wiped |
| | `seats.seat` | seat code of each Mac (16 hex), or its HMAC with `SEAT_PEPPER` | active: with the record; released: 30 days |
| | `seats.created_at` | first activation of that Mac (milliseconds) | with the row |
| | `seats.deactivated_at` | release time of that Mac (unix seconds), empty while active | with the row |
| | `seats.last_seen_at` | last activation of that Mac (milliseconds) | with the row |
| `handoff:<sha256(domain + "handoff\|" + chk_ token)>` | `handoff_kind` | marks the record as a browser-checkout handoff | 24 hours |
| | `handoff_session_id` | the raw purchase key (`cs_live_...`) | 24 hours |
| | `handoff_created_at_ms` | time the purchase key was recorded | 24 hours |
| | `handoff_seat` | seat code of the first Mac that polled the handoff (raw, never peppered) | 24 hours |
| | `handoff_first_seen_ms` | first poll by the app | 24 hours |
| | `handoff_last_search_ms` | last fallback search on Stripe | 24 hours |
| | `handoff_search_count` | number of fallback searches | 24 hours |
| `recover:<HMAC-SHA256(Stripe secret, domain + "recover\|" + typed email)>` | `recover_kind` | marks the record as a recovery cooldown | 15 minutes |
| | `recover_claimed_at_ms` | start of the 15-minute cooldown | 15 minutes |

Rows of active Macs stay as long as the license record; rows of deactivated or evicted Macs are deleted 30 days after the release. A license record has no time limit; see "Retention and erasure" below.

The handoff record is the only place where the purchase key itself is stored. It is not encrypted; it deletes itself 24 hours after creation.

## Why these values are personal data

- The purchase hash is `SHA-256(key-hash domain + purchase key)`. It has no secret part, so you (or anyone with your Stripe data) can recompute it for every Stripe Checkout Session and link the record to a sale.
- The seat code is `SHA-256(bundle-ID domain + hardware UUID)`, cut to 16 hex characters (`TrialSeal.seatCode`). Any app on the same Mac can read the hardware UUID and recompute it.
- A hash cannot be reversed, but because both can be recomputed from data that identifies a buyer or a Mac, they are pseudonymous personal data under the GDPR, not anonymous data.
- The optional `SEAT_PEPPER` secret stores `HMAC-SHA256(pepper, seat code)` instead of the seat code, so anyone who reads the stored records without the secret cannot match a row to a Mac. Rows stored before the pepper was set are renamed on their next activation or deactivation. Never change or remove the pepper once set: every active Mac would then look like a new Mac and use another seat.
- The purchase hash and the order tag stay unpeppered, because `license-tool --revoke-key` derives the tag offline from the purchase key.

## What is never stored

Names, email addresses, IP addresses, and payment details (card data, billing addresses, amounts) are never written to the Durable Object or to any other storage by the Worker.

## In memory only

Each Worker isolate keeps a few short-lived maps in memory. They vanish when the isolate stops:

- Rate-limit counters keyed by a salted hash of the client IP address (the salt is random per isolate): one minute for activation, claim, and `/thank-you` limits, 10 minutes for recovery limits.
- A negative cache of purchase hashes that Stripe reported as invalid (5 minutes) and a cache of recently verified purchase hashes (45 seconds).
- With the optional `POST_RATE_LIMITER` binding, the Worker passes `SHA-256(domain + "rl|" + IP address)` to Cloudflare's rate-limiting service, which counts it for up to one minute.

## Logs

The Worker code has no logging call. With the shipped configuration (`observability` off in `worker/wrangler.jsonc`) no request is logged.

If you turn on Workers Logs, Cloudflare stores one log line per request with the method and the full URL, and the `/thank-you?session_id=...` URL contains the license key. If you also keep `invocation_logs` on, the line includes request metadata such as the client IP address. If you add a WAF or rate-limiting rule, every request that matches it appears in Security Events with the client IP address and the request path and query. Keep `invocation_logs` false if you must enable logs, and treat those logs as holding license keys.

## On the buyer's Mac

- `~/Library/Application Support/<bundle ID>/.license_vault` (mode 0600): the purchase key, the signed ticket, any queued deactivation, a pending browser-checkout token, revoked order tags, and the manifest sequence, in plain JSON. It is not excluded from backups, so Time Machine and Migration Assistant copy it to a new Mac.
- Four trial seal anchors that hold the sealed trial start and clock watermark: one `UserDefaults` value, `.vault_seal` in Application Support, `.vault_seal` in Caches, and a Keychain item (only for builds signed with a stable Team ID).
- In builds signed with a stable Team ID, a Keychain copy of `.license_vault`.

Nothing on the Mac contains the buyer's name or email address. The seat code is computed when needed and is not stored on its own.

## What the app sends

| Request | When | What it reveals to your Worker |
|---|---|---|
| `POST /` `activate` or `deactivate` | the user clicks Activate or Deactivate, or a queued release is retried | the purchase key, the seat code, the ticket (deactivate), and the Mac's IP address |
| `POST /` `recover` | the user types an email address and clicks Email Key | the typed email address and the IP address; the Worker passes the address to Stripe and the email provider and stores only an HMAC-keyed cooldown |
| `POST /` `claim_checkout` | after `beginBrowserCheckout(...)`, polling until licensed or cancelled | the random `chk_` token, the seat code, and the IP address |
| `GET` of the update manifest | only with `UpdateChecker`, at most once a week after a successful check | the IP address, the app name, and the app version (`User-Agent`) to the update host |
| `GET` of the download URL | only when the user starts `downloadAndVerifyUpdate()` | the IP address and the app's `User-Agent` to the download host |

## Retention and erasure

| Data | Deleted |
|---|---|
| Handoff records (`handoff:`) | 24 hours after creation, by a Durable Object alarm |
| Recovery cooldown records (`recover:`) | 15 minutes after creation, by a Durable Object alarm |
| Rows of deactivated or evicted Macs | 30 days after `deactivated_at`, on the next activate or deactivate for that purchase or by an alarm armed at the release |
| An active license record (`lic:`) | no time limit; wiped with `deleteAll()` at the first Stripe check after a refund (or another definite "not paid" answer), or by erasure |

A Stripe check happens on the next activation of a new Mac, on a re-activation more than one hour after the last check, and on a `/thank-you` load for that key. Until such a request arrives, the record of a refunded purchase stays.

To erase one purchase on request:

1. Once, set an admin token of at least 32 random characters on the Worker: `npx wrangler -c worker/wrangler.jsonc secret put ADMIN_TOKEN`.
2. Run `SEATSTAMP_ADMIN_TOKEN=... swift run license-tool --erase-key cs_live_... --endpoint https://activate.myapp.com`. The tool reads the token only from the environment, never prints it, and prints `Erased: true` or `Erased: false`.

What erasure does not remove:

- the buyer's offline ticket and purchase key on their Macs (`.license_vault`), which keep working offline;
- Stripe's own records of the payment;
- emails already sent, and the copies your email provider keeps;
- data held by other processors (see below).

Erasing a purchase that is still paid does not block it: the same key can activate again, with a fresh seat count and a fresh release budget.

## Processors

Name these services in your privacy policy:

| Processor | When | What it receives | Retention you should state |
|---|---|---|---|
| Cloudflare (Workers, Durable Objects) | always | every request to the Worker, with the client IP address and the URL in transit (the `/thank-you` URL contains the license key); the stored records listed above | stored records as in "Retention and erasure"; request data only in logs you turn on |
| Stripe | always | the purchase key on every Stripe check; the buyer's email address as a search filter during key recovery | Stripe's own retention for your account |
| Resend | only with `RESEND_API_KEY` | the buyer's email address, the license key, and the activation link in each backup or recovery email | 30 days (message content, metadata, and logs) |
| Your update host | only with `UpdateChecker` | the Mac's IP address, the app name, and the app version for each manifest check, and the same for a download started with `downloadAndVerifyUpdate()` (the download host may be a different service) | your host's log retention |

The buyer's browser also keeps the thank-you URL, which is the license key, in its history, and a copy of the key in `localStorage` for 30 days unless the buyer clicks "Clear saved key".

This page describes the kit, not your business; add your own details before you publish a privacy policy.
