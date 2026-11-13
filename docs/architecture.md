# Architecture

How a purchase turns into an unlocked Mac, and the design decisions behind each step. For the short version, see the [README](../README.md#how-it-works). For an interactive walkthrough, see the [SeatStamp site](https://denissitnikov.github.io/seatstamp/).

## The pieces

The Swift package runs natively on macOS 13+ (SwiftUI or AppKit, Intel and Apple Silicon). Electron, Tauri, and Rust Mac apps can talk to the same Worker over its JSON wire format ([`integrating.md`](integrating.md#3-using-the-worker-and-license-tool-from-non-swift-mac-apps-electron-tauri-rust-go)).

The buyer's Stripe Checkout Session ID (`cs_live_...`) is their license key. On activation, a Cloudflare Worker verifies the session and its underlying charge against the Stripe API, claims a seat in `SeatCoordinator` (an atomic SQLite Durable Object), and returns an Ed25519-signed license ticket (`LK1-<payload>.<sig>`). The ticket is bound to a per-app 16-hex SHA-256 prefix of the Mac's `IOPlatformUUID`, and the app verifies it locally with Apple `CryptoKit`.

```text
┌──────────────────────┐  1. Buyer opens buy.stripe.com?client_reference_id=chk_...
│ Stripe Payment Link  │ ─────────────────────────────────────────────┐
└──────────────────────┘                                              ▼
                                    GET /thank-you?session_id=cs_live_...
                                ┌───────────────────────────────────────┐
                                │  Cloudflare Worker + SQLite Seat DO   │
                                │  • Verifies paid, unrefunded session  │
                                │  • Enforces the seat cap atomically   │
                                │  • Signs LK1-<payload>.<ed25519_sig>  │
                                └───────────────────┬───────────────────┘
  2. The app claims chk_... in the background       │  3. Seat claimed: returns
     (also deep-links myapp:// and saves a .txt)    │     cs_live_... + LK1- ticket
                                                    ▼
                                ┌───────────────────────────────────────┐
                                │  Your Mac app (SeatStamp, CryptoKit)  │
                                │  • Verifies the Ed25519 signature     │
                                │  • No license check-ins afterwards    │
                                └───────────────────────────────────────┘
```

Because `SeatCoordinator` uses SQLite-backed Durable Objects (`new_sqlite_classes`), the Worker deploys and runs on the Cloudflare Workers Free plan as well as the Paid plan.

## Design details

- **Signature before parsing.** `LicenseTicket.verify` checks the 64-byte Ed25519 signature over the raw payload bytes before decoding UTF-8 or splitting fields.
- **Atomic seats.** `SeatCoordinator` enforces the seat limit inside `ctx.storage.transactionSync(...)`. Deactivating a Mac requires presenting its signed `LK1-` ticket, soft-releases the seat (`deactivated_at`), and advances a monotonic `revokedBefore` watermark on both client and server, so a ticket copied before Deactivate is rejected when pasted back into that install.
- **Release budget.** The watermark lives in local sealed anchors, so a Mac that never runs `deactivate()` keeps its ticket. For that reason releases (deactivations plus evictions) are capped at `SEAT_RELEASES_PER_YEAR` per rolling 365 days, and a release over the cap returns `429 release_limit`.
- **Dead Macs.** Optional `EVICT_OLDEST_SEAT_AFTER_DAYS` (for example `"30"`) lets a new Mac evict the least recently activated seat once that seat has been idle for N days, at most once per N days and only while the yearly release budget has room. The evicted Mac, if it still exists, keeps working offline.
- **Migration.** `.license_vault` preserves the parent `cs_live_...` purchase key across Migration Assistant and Time Machine backups while rejecting the old Mac's hardware-bound `LK1-` ticket on the new `IOPlatformUUID`, so a migrated Mac can claim the next seat in one click via `kit.shareableLicenseKey`. `shareableLicenseKey` returns the purchase key (or a universal ticket), never a ticket bound to this Mac.
- **Trial clock.** Trial timestamps (`first`, `high`, `revokedBefore`) are HMAC-SHA256 sealed across four anchors: `UserDefaults`, `Application Support/<bundleID>/.vault_seal`, `Caches/<bundleID>/.vault_seal`, and the Keychain (when the app is signed with an Apple Developer Team ID). `highWaterEpoch` is never lowered, which blocks clock rollback at launch and at run time, and it advances by at most 7 days per step so a bad system clock does not brick a legitimate trial.
- **Update notices.** `UpdateChecker` reads a signed `version.json` (separate offline Ed25519 keypair, pinned download hosts). When the manifest carries a signed `sha256`, `downloadAndVerifyUpdate()` downloads the file, checks the hash and size, keeps the quarantine attribute so Gatekeeper still checks it, and reveals it in Finder. Otherwise it opens the download URL in the browser. For background patching in place, pair SeatStamp with Sparkle 2.
- **Offline revocation.** Every ticket embeds an `ORD-<16-hex>` order tag derived from `SHA256(keyHashDomain + purchaseKey)`. After a refund or chargeback, `swift run license-tool --scheme MYAPP-V1 --revoke-key cs_live_... version.json` adds the tag to your signed manifest (or pass `revokedOrderTags: ["ORD-..."]` to `SeatStampManager.init` in your next release). By default (`revocationBehavior: .suppressUpdates`) that copy stops seeing update notices and keeps running. With `.revokeLocalLicense` it also deactivates the local license. `license-tool --unrevoke-key` undoes a mistake.

## Wire-format constants

These values are part of every ticket, purchase record, and signed manifest. Changing one invalidates what was issued under the old value, so treat them as frozen once you have sold a license:

| Constant | Default | Where |
|---|---|---|
| Ticket prefix | `LK1-` | `LicenseTicket.defaultPrefix`, Worker `TICKET_PREFIX` |
| Key-hash domain | `seatstamp-key-v1\|` | `LicenseTicket.defaultKeyHashDomain`, Worker `KEY_HASH_DOMAIN` |
| License scheme | your `scheme` (default `SEATSTAMP-V1`) | `SeatStampManager(scheme:)`, Worker `TICKET_SCHEME` |
| Update scheme | derived: `MYAPP-V1` becomes `MYAPP-UPDATE-V1` | `UpdateManifest.derivedScheme` |
| Durable Object names | `lic:<hash>`, `handoff:<hash>`, `recover:<hmac>` | `worker/worker.js` |

[`fixtures/golden-vectors.json`](../fixtures/golden-vectors.json) pins all of them. The Swift selftest and the Worker tests both verify against it, so the two implementations cannot drift apart.

## Further reading

- [`privacy.md`](privacy.md): every value stored, sent, and logged, with retention.
- [`threat-model.md`](threat-model.md): what is defended, and what is deliberately left open.
- [`integrating.md`](integrating.md): SwiftUI, AppKit, deep links, update downloads, and the JSON API.
- [`stripe-setup.md`](stripe-setup.md): Payment Link, restricted key, buyer flow, and test mode.
- [`regional-pricing.md`](regional-pricing.md): optional per-country Payment Links.
