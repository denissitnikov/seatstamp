# Integrating SeatStamp

This guide covers:
1. SwiftUI integration (Settings view, trial gate, custom URL scheme)
2. AppKit integration (`Combine` + `NSApplicationDelegate`)
3. Wire and token specification (+ a short Node/WebCrypto verifier for Electron, Tauri, Rust, Python, or Go Mac apps)

## 1. SwiftUI Integration

### Add the Swift Package

In Xcode (**File -> Add Package Dependencies...**) or in `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/denissitnikov/seatstamp.git", from: "1.0.0")
],
targets: [
    .executableTarget(
        name: "MyApp",
        dependencies: [
            .product(name: "SeatStamp", package: "seatstamp")
        ]
    )
]
```

### Create a Shared Instance

```swift
import Foundation
import SeatStamp

enum AppLicensing {
    static let kit = SeatStampManager(
        scheme: "MYAPP-V1",
        licensePublicKeyBase64: "<PASTE_YOUR_LICENSE_PUBLIC_KEY>",
        updatePublicKeyBase64: "<PASTE_YOUR_UPDATE_PUBLIC_KEY>",
        activationEndpoints: [
            URL(string: "https://activate.myapp.com")!,
            URL(string: "https://my-app-activate.<subdomain>.workers.dev")!
        ],
        trialLengthDays: 30,
        maxSeats: 2,
        bundleID: "com.example.myapp"
    )

    static let updater = UpdateChecker(
        kit: kit,
        manifestURL: URL(string: "https://myapp.com/version.json")!,
        trustedDownloadHosts: ["myapp.com", "www.myapp.com"],
        fallbackWebsiteURL: URL(string: "https://myapp.com")!
    )
}
```

The `workers.dev` hostname is not covered by firewall rules on your own domain. If you rely on such rules, set `workers_dev` to `false` and use a second custom domain as the failover endpoint.

### Gate Your Pro Feature

`verifyGateAccess()` reads cached in-memory state and integer timestamps without touching disk or Keychain:

```swift
func performProAction() {
    AppLicensing.kit.refreshMonotonicClockIfNeeded()
    guard AppLicensing.kit.verifyGateAccess() else {
        showPaywallOrSettings()
        return
    }
    // Run feature
}
```

### SwiftUI License Settings View

```swift
import AppKit
import SeatStamp
import SwiftUI

final class LicenseFormState: ObservableObject {
    @Published var keyInput = ""
    @Published var feedback = ""
}

struct LicenseSettingsSection: View {
    @ObservedObject var kit: SeatStampManager
    let checkoutURL: URL

    @StateObject private var form = LicenseFormState()

    var body: some View {
        GroupBox("License") {
            VStack(alignment: .leading, spacing: 10) {
                if kit.isLicensed {
                    HStack {
                        Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
                        Text("Licensed (\(kit.maskedKey)) · \(kit.seatsUsed)/\(kit.maxSeats) Macs")
                        Spacer()
                        if let key = kit.shareableLicenseKey {
                            Button("Copy Key for 2nd Mac") {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(key, forType: .string)
                                form.feedback = "Copied to clipboard."
                            }
                        }
                        Button("Deactivate") {
                            kit.deactivate()
                            form.feedback = "This Mac's seat has been released."
                        }
                    }
                } else {
                    HStack {
                        Text(kit.isTrialExpired
                             ? "Your \(kit.trialLengthDays)-day trial has ended."
                             : "\(kit.trialDaysRemaining) days left in your free trial.")
                        Spacer()
                        Button(kit.isAwaitingBrowserCheckout ? "Waiting for Browser..." : "Buy License") {
                            kit.beginBrowserCheckout(paymentLink: checkoutURL, onOutcome: { outcome in
                                if outcome == .activated {
                                    form.feedback = "Activated automatically from browser checkout."
                                } else if outcome == .unconfigured {
                                    form.feedback = "Activation is not set up in this build."
                                }
                            })
                        }
                    }

                    HStack {
                        TextField("License key (cs_live_...) or purchase email", text: $form.keyInput)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))

                        if SeatStampManager.looksLikeEmail(form.keyInput) {
                            // Lost key: same field, the Worker emails every key tied to this address.
                            Button(kit.isRequestingKeyRecovery ? "Sending..." : "Email Key") {
                                Task {
                                    switch await kit.requestKeyRecovery(email: form.keyInput) {
                                    case .sent: form.feedback = "If that email bought a license, the key is on its way."
                                    case .unconfigured: form.feedback = "Key recovery is not enabled on this server."
                                    case .rateLimited: form.feedback = "Too many requests. Try again in a few minutes."
                                    case .invalidEmail: form.feedback = "That does not look like an email address."
                                    case .networkError: form.feedback = "Network error. Please try again in a moment."
                                    }
                                }
                            }
                            .disabled(kit.isRequestingKeyRecovery)
                        } else {
                            Button(kit.isActivatingOnline ? "Activating..." : "Activate") {
                                Task {
                                    switch await kit.activate(key: form.keyInput) {
                                    case .activated:
                                        form.keyInput = ""
                                        form.feedback = "Activated for offline use."
                                    case .seatLimitReached:
                                        form.feedback = "Seat limit (\(kit.maxSeats) Macs) reached. Deactivate another Mac first."
                                    case .networkError:
                                        form.feedback = "Network error. Please try again in a moment."
                                    case .invalidKey:
                                        form.feedback = "License key was not recognized."
                                    case .paymentPending:
                                        form.feedback = "Payment is still processing. Try again in a minute."
                                    case .clockSkew:
                                        form.feedback = "The license server and this Mac disagree about the time. Check the date and time, then try again."
                                    case .unconfigured:
                                        form.feedback = "Activation is not set up in this build."
                                    }
                                }
                            }
                            .disabled(kit.isActivatingOnline || form.keyInput.trimmingCharacters(in: .whitespaces).isEmpty)
                        }
                    }
                }

                if !form.feedback.isEmpty {
                    Text(form.feedback).font(.caption).foregroundStyle(.secondary)
                }
            }
            .padding(6)
        }
        .onAppear {
            // If migrated from another Mac via Migration Assistant, pre-fill the preserved purchase key.
            if !kit.isLicensed, form.keyInput.isEmpty, let migratedKey = kit.shareableLicenseKey {
                form.keyInput = migratedKey
            }
        }
    }
}
```

### Handling `myapp://activate?key=...` Deep Links

Register your URL scheme in `Info.plist` (`CFBundleURLTypes` -> `CFBundleURLSchemes: ["myapp"]`) to match `APP_URL_SCHEME` in `worker/wrangler.jsonc`. Email buttons link to the Worker's `https://<worker>/open#key=...` page, because webmail removes `myapp://` links; that page opens the app. Set `ACTIVATION_PAGE_URL` to use your own https page instead.

Pre-fill the key field when unlicensed rather than auto-submitting network requests or overwriting an existing license:

```swift
.onOpenURL { url in
    guard !kit.isLicensed,
          url.scheme?.lowercased() == "myapp",
          url.host?.lowercased() == "activate",
          let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
          let key = comps.queryItems?.first(where: { $0.name == "key" })?.value else { return }
    form.keyInput = String(key.prefix(256))
}
```

### Update notices and verified downloads

Sign each release with the download attached, so the manifest carries its SHA-256 and size:

```sh
swift run license-tool --scheme MYAPP-V1 --sign-manifest version.json --artifact MyApp-1.2.dmg
```

When the user clicks your "Download update" button, let `UpdateChecker` fetch and check the file instead of opening the browser:

```swift
AppLicensing.updater.downloadAndVerifyUpdate { outcome in
    switch outcome {
    case .verified(let fileURL):
        // Saved to Downloads with the quarantine attribute set, and revealed in Finder.
        print("Verified update at \(fileURL.path)")
    case .openedInBrowser:
        // The manifest has no sha256: the signed URL was opened in the browser.
        break
    case .hashMismatch:
        // The file did not match the signed hash or size and was deleted.
        print("The download was damaged or replaced.")
    case .failed:
        // No update, a network error, or an HTTP status other than 200.
        print("The update could not be downloaded.")
    }
}
```

`downloadAndVerifyUpdate` never opens, mounts, or runs the file. Gatekeeper checks it when the user opens it.

Keep every tag in `revoked_tags` when you sign a new manifest: a client forgets any tag that the newest sequenced manifest does not list. `--revoke-key` and `--sign-manifest` preserve the existing list for you.

## 2. AppKit Integration

`SeatStampManager` and `UpdateChecker` do not require SwiftUI:

```swift
import AppKit
import Combine
import SeatStamp

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var cancellables = Set<AnyCancellable>()

    func applicationDidFinishLaunching(_ notification: Notification) {
        AppLicensing.updater.scheduleLaunchCheck()

        AppLicensing.kit.$isLicensed
            .receive(on: RunLoop.main)
            .sink { isLicensed in
                // Update menu items or status bar icon
            }
            .store(in: &cancellables)
    }
}
```

## 3. Using the Worker and `license-tool` from Non-Swift Mac Apps (Electron, Tauri, Rust, Go)

The Cloudflare Worker and `license-tool` CLI use standard HTTP JSON and RFC 8032 Ed25519. Any macOS app can use them by implementing the wire format below and testing against [`fixtures/golden-vectors.json`](../fixtures/golden-vectors.json).

### Wire Protocol (`POST https://activate.myapp.com/`)

Send `Content-Type: application/json` without a browser `Origin` header (call from Electron's main process or Tauri's Rust backend, not renderer `fetch`).

- Seat hash: `seat = hex(SHA256("<bundleID>.seat.v1|" + IOPlatformUUID)[0..8])` (16 lowercase hex chars).
- Activate request:
  ```json
  { "action": "activate", "key": "cs_live_...", "seat": "b3d8d5e073a07524" }
  ```
  Optional field `minIssued` (non-negative integer, unix seconds): the client's sealed `revokedBefore` cutoff. The Worker mints `issued` at or above it, capped at 366 days ahead. Verify the returned ticket against your stored cutoff and never lower the cutoff from a response.
  - `200`: `{ "ticket": "LK1-<payloadB64Url>.<sigB64Url>", "seatsUsed": 1, "maxSeats": 2, "revokedBefore": 0 }`
  - `409`: `{ "error": "seat_limit_reached", "maxSeats": 2 }`
  - `409` with `Retry-After: 10`: `{ "error": "payment_pending" }` (the checkout session is open or the payment has not settled yet); retry, do not treat the key as invalid
  - `403`: `{ "error": "invalid_key" }`
  - `429` / `502`: rate-limited or Stripe unreachable
  - `404`: `{ "error": "not_found" }` (the URL has a path; the Worker only serves `POST /`). Any 4xx other than `403 invalid_key` and `409` is a setup problem, not a wrong key.
- Deactivate request:
  ```json
  { "action": "deactivate", "key": "cs_live_...", "seat": "b3d8d5e073a07524", "ticket": "LK1-..." }
  ```
  - `200`: `{ "ok": true, "revokedBefore": 1760050000 }`
  - `500`: `{ "error": "signing_error" }` (the Worker's key secret is missing or malformed). Keep the queued deactivation and retry later or on the next endpoint.
  - `429`: `{ "error": "release_limit", "retryAfterSec": 2592000 }`. The yearly release budget is used up and the seat stays assigned. Stop retrying, keep the purchase key, and let the user activate this Mac again.
- Default-browser checkout claim request (used by `kit.beginBrowserCheckout`). Non-Swift clients generate `handoff` themselves as `"chk_" + 32 lowercase hex chars` from 16 random bytes, append it to the Payment Link as `?client_reference_id=<handoff>`, open that URL in the default browser, and then poll:
  ```json
  { "action": "claim_checkout", "handoff": "chk_<32 lowercase hex>", "seat": "b3d8d5e073a07524", "fallbackSearch": false }
  ```
  - `202`: `{ "status": "pending" }` (not paid yet, payment still settling, or paid but `/thank-you` not loaded and no `fallbackSearch`)
  - `200`: `{ "status": "activated", "key": "cs_live_...", "ticket": "LK1-...", "seatsUsed": 1, "maxSeats": 2, "revokedBefore": 0 }`. Store `key` as the parent purchase key so the buyer can copy it for a second Mac. Only the first seat code that polled this handoff receives this answer.
  - `400`: `{ "error": "invalid_params" }` (handoff must match `^chk_[0-9a-f]{32}$`, seat must be 16 lowercase hex)
  - `403`: `{ "error": "invalid_key" }` (session refunded, disputed, wrong Payment Link, or test-mode); stop polling
  - `403`: `{ "error": "handoff_seat_mismatch" }` (another seat code polled this handoff first); stop polling
  - `409`: `{ "error": "seat_limit_reached", "maxSeats": 2 }`; stop polling
  - `429` with `Retry-After`: per-IP claim budget is `30 req/min` (separate from the `12 req/min` activation budget)
  - `502`: `{ "error": "upstream_unavailable" }` (Stripe unreachable or the restricted key lacks `Checkout Sessions: Read`); retry later
  - Send `"fallbackSearch": true` on roughly every fifth poll, on app focus, and on relaunch. It asks the Worker to list recent completed Stripe sessions in case the buyer closed the tab before `/thank-you` loaded; the Worker rate-limits that search to once per 15 seconds per handoff regardless of how often you ask.
  - Recommended cadence: every 3 s for 3 minutes, then every 10 s until 15 minutes, then stop active polling but keep the handoff for up to 24 hours and retry once on next launch.
- Email key recovery request (used by `kit.requestKeyRecovery(email:)`; needs `STRIPE_SECRET_KEY`, `RESEND_API_KEY`, and `RECEIPT_FROM_EMAIL` on the Worker). No `seat` field:
  ```json
  { "action": "recover", "email": "buyer@example.com" }
  ```
  - `200`: `{ "ok": true }` for every well-formed email, matched or not, and also while the 15-minute per-email cooldown is active. Do not try to infer anything from it.
  - `400`: `{ "error": "invalid_params" }` (3 to 254 chars, no whitespace or control characters, one `@`, a dot in the domain)
  - `429` with `Retry-After: 60`: more than 3 recovery requests from one IP in 10 minutes, or `Retry-After: 10` when the Worker's Stripe budget is busy
  - `501`: `{ "error": "recovery_unconfigured" }` when any of the three secrets is missing
  - The lookup and the email run after the response is sent (`ctx.waitUntil`), so response time does not depend on whether the address exists.
- Erase request (developer only, sent by `license-tool --erase-key`; needs the Worker secret `ADMIN_TOKEN`, at least 32 characters). Never ship the token in an app:
  ```json
  { "action": "erase", "key": "cs_live_...", "adminToken": "<ADMIN_TOKEN>" }
  ```
  - `200`: `{ "ok": true, "erased": true }` when the license record of that key was wiped, `{ "ok": true, "erased": false }` when no record exists
  - `400`: `{ "error": "invalid_params" }` (`key` must be 16 to 256 characters, `adminToken` at most 512)
  - `403`: `{ "error": "forbidden" }` (wrong token) or `{ "error": "forbidden_origin" }` (a browser request)
  - `429` with `Retry-After: 60`: more than 5 erase requests from one IP in a minute
  - `501`: `{ "error": "erase_unconfigured" }` when `ADMIN_TOKEN` is unset or shorter than 32 characters
  - The answer never contains the token. A purchase that is still paid can activate again after erasure, with a fresh seat count and release budget.

### Offline Ticket Verification in Node.js / Electron (short, zero npm packages)

```js
import { createHash, webcrypto } from "node:crypto";

export function deriveSeatCode(ioPlatformUUID, domain = "com.example.acme.seat.v1|") {
  return createHash("sha256").update(domain + ioPlatformUUID, "utf8").digest("hex").slice(0, 16);
}

export async function verifyOfflineTicket(raw, { scheme, prefix = "LK1-", publicKeyB64, expectedSeat, revokedBefore = 0, revokedOrderTags = [] }) {
  if (typeof raw !== "string" || raw.length > 512 || !raw.startsWith(prefix)) return null;
  const parts = raw.slice(prefix.length).split(".");
  if (parts.length !== 2) return null;
  const payloadBytes = Buffer.from(parts[0], "base64url");
  const sigBytes = Buffer.from(parts[1], "base64url");
  if (sigBytes.length !== 64) return null;

  const pubKey = await webcrypto.subtle.importKey("raw", Buffer.from(publicKeyB64, "base64"), { name: "Ed25519" }, false, ["verify"]);
  if (!(await webcrypto.subtle.verify("Ed25519", pubKey, sigBytes, payloadBytes))) return null;

  const fields = payloadBytes.toString("utf8").split("|");
  if ((fields.length !== 3 && fields.length !== 4) || fields[0] !== scheme || !fields[1].startsWith("ORD-") || fields[1].length <= 4) return null;
  if (!/^\d{1,12}$/.test(fields[2])) return null;
  const issued = Number(fields[2]);
  if (issued < 1_700_000_000 || issued > 4_102_444_800) return null;
  if (fields.length === 4) {
    if (!/^[0-9a-fA-F]{16}$/.test(fields[3])) return null;
    const seat = fields[3].toLowerCase();
    if (seat !== expectedSeat.toLowerCase()) return null;
    if (revokedBefore > 0 && issued < revokedBefore) return null;
  }
  // Same rule as LicenseTicket.canonicalOrderTag in Swift: trim, "|" -> "-", optional "ORD-" prefix, upper case.
  const canon = (t) => { const s = String(t).trim().replace(/\|/g, "-"); const body = /^ORD-/i.test(s) ? s.slice(4).trim() : s; return body ? "ORD-" + body.toUpperCase() : null; };
  if (revokedOrderTags.some((t) => { const c = canon(t); return c !== null && c === canon(fields[1]); })) return null;
  return { tag: fields[1], issued, boundSeat: fields[3] ? fields[3].toLowerCase() : null };
}
```
