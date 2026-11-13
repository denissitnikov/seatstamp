# Working on SeatStamp

Guidance for coding agents and contributors. [README.md](README.md) explains what SeatStamp is; [docs/architecture.md](docs/architecture.md) explains how it works.

## Map

| Path | What it is |
|---|---|
| `Sources/SeatStamp/SeatStampManager.swift` | Public API: trial, activation, checkout handoff, deactivation, the sealed local vault |
| `Sources/SeatStamp/LicenseTicket.swift` | `LK1-` ticket format, Ed25519 verification, order tags |
| `Sources/SeatStamp/TrialSeal.swift` | HMAC-sealed trial anchors and the monotonic clock |
| `Sources/SeatStamp/UpdateManifest.swift`, `UpdateChecker.swift` | Signed `version.json`: canonical bytes, verification, weekly check, verified download |
| `Sources/SeatStamp/RegionalPricing.swift` | Optional per-country Payment Link choice |
| `Sources/license-tool/main.swift` | CLI: keypairs, minting, manifest signing, revocation, admin actions |
| `worker/worker.js` | The whole Cloudflare Worker and the `SeatCoordinator` Durable Object, zero dependencies |
| `fixtures/golden-vectors.json` | Cross-language vectors; Swift and JavaScript tests both verify against them |
| `site/` | Static walkthrough published to GitHub Pages; its examples are checked by `site/site.test.mjs` |
| `Tests/selftest/main.swift` | XCTest-free suite, runs with Command Line Tools only |

## Build and test

```sh
swift build && swift run selftest     # also scans the repo for key files and em/en dashes
node --test worker/worker.test.mjs    # Node 22.12+, no npm install
node --test site/site.test.mjs
cd example && swift build
```

Run all four before you commit. CI runs the same commands.

## Rules

- **Wire-format constants are frozen** once a license has been sold: the `LK1-` prefix, the key-hash domain `seatstamp-key-v1|`, schemes, Durable Object names (`lic:`, `handoff:`, `recover:`), and the canonical byte layouts of tickets and manifests. Changing one invalidates issued licenses. If a change is unavoidable, make it a new major version, regenerate `fixtures/golden-vectors.json`, and document the migration in `CHANGELOG.md`.
- **Never rename** the Durable Object class `SeatCoordinator` or its migration tags; Cloudflare keys deployed state on them.
- **No third-party runtime dependencies** in the Swift package or the Worker.
- **Privacy rules** (see `docs/privacy.md`): no email address or IP address is written to storage or logs; the raw purchase key lives only in the 24-hour handoff record. If behavior changes, update `docs/privacy.md` and `docs/threat-model.md` in the same commit.
- **Signing, hashing, or canonicalization changes** must keep Swift and JavaScript in step; the golden vectors catch drift.
- **The site shows real formats.** Its sample ticket and manifest come from the golden vectors; `site/site.test.mjs` fails if they drift.
- **Writing style:** plain words, no em or en dashes (the selftest enforces this), commits small and imperative with the reason in the body.
- **Never commit key material.** `.key`, `.pem`, and `.pkcs8` files are ignored and rejected by the selftest.
