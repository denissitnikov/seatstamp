# Changelog

All notable changes to this project are documented in this file.

## [1.0.0] - 2026-11-13

First public release.

### Mac app (Swift package `SeatStamp`)
- Free trial (30 days by default) sealed with HMAC across four local anchors, with a clock that can't be rolled back.
- Activation with a Stripe Checkout Session ID as the license key, returning an Ed25519-signed `LK1-` ticket bound to the Mac.
- Offline verification on every launch with `CryptoKit`; no license checks after unlock.
- Browser checkout handoff: the app opens a Payment Link and activates itself in the background.
- Deactivation that moves a seat to another Mac, queued and retried until the server answers.
- Key recovery by purchase email, and `shareableLicenseKey` for a second Mac.
- Signed `version.json` update notices with pinned download hosts, verified downloads (SHA-256 and size), replay protection (`manifest_seq`), and offline revocation of refunded orders.
- Optional regional pricing with per-country Payment Links.

### Server (Cloudflare Worker)
- One Worker and one SQLite Durable Object (`SeatCoordinator`), on the Cloudflare free plan, with no third-party dependencies.
- Checks payment, refund, and dispute status with Stripe on demand, with no webhooks and no customer database.
- Atomic seat cap, yearly seat-release budget, and optional eviction of an idle seat.
- Thank-you page with copy, `.txt` download, deep link into the app, and an optional one-time backup email.
- Stores no names, email addresses, or IP addresses, and writes no logs by default.

### Tools and docs
- `license-tool`: keypairs, ticket minting, manifest signing, revocation, key rotation, and admin erase.
- Golden test vectors shared by the Swift and JavaScript test suites.
- Interactive walkthrough site, a menu-bar example app, and guides for integration, Stripe setup, privacy, the threat model, and regional pricing.
