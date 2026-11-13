# SeatStamp

Offline Mac app licensing with Stripe and a $0 Cloudflare Worker.

Add a free trial and one-time paid licenses to a Mac app you sell on your own website. No customer database, no user accounts, and no license checks once the app is unlocked.

**[See how it works, step by step](https://denissitnikov.github.io/seatstamp/)**: an interactive walkthrough of the purchase flow, a real signed ticket you can inspect, and the attacks it stops.

## Why I built it

I built this for [SlideTab](https://slidetab.app), my macOS window switcher. I wanted a simple deal for buyers: try it free for 30 days, then pay once to use it on 2 Macs.

Window switchers can't go in the Mac App Store (Apple doesn't allow the system access they need there), so I had to sell it myself. The usual options were:

- Pay a licensing platform a cut of every sale.
- Build my own backend: a customer database, user accounts, and "phone-home" checks where the app keeps asking a server whether it's still paid for.

Phone-home checks lock honest buyers out when they're offline. If the server ever shuts down, paid copies stop working. And I didn't want a database of customer emails and IP addresses to look after.

So I built something smaller. It's open source (MIT) and runs on free plans, so it costs nothing per month.

## What it does

- A free trial (30 days by default) that counts down on the Mac. Reinstalling the app doesn't restart it.
- Checkout through a Stripe Payment Link. Buyers pay in their own browser with Apple Pay, Google Pay, or a card, and the app unlocks itself.
- One purchase works on 2 Macs (you can set anywhere from 1 to 64). Buyers can deactivate a Mac to move the license to another one (by default up to 2 moves per year).
- Once unlocked, the app works offline for good. It never checks the license again.
- A buyer who loses their key types their purchase email into the app and gets the key emailed to them.
- A refunded purchase can't unlock any more Macs. You can also list it in your signed update file so that copy stops seeing updates (or locks again, if you choose).
- Update notices: once a week the app reads a small signed file on your website and tells the user when a new version is out.

## How it works

Stripe already keeps a record of every payment, so you don't need a second customer database. The buyer's Stripe checkout ID is their license key.

1. The buyer pays. If checkout started from the app, the app unlocks in the background. If they bought on your website, the thank-you page opens the app with one click.
2. A small Cloudflare Worker asks Stripe whether the payment is real and not refunded, makes sure the purchase hasn't reached its Mac limit, and sends back a signed license pass for that Mac.
3. On every launch, the app checks the signature on that pass by itself. It works like a passport stamp: the border guard checks the stamp without calling the government. The app never contacts the server again for that Mac, so it keeps working even if your server is gone years from now.

Moving to a new Mac takes one click, because Migration Assistant and Time Machine carry the purchase key over. If an old Mac died before it was deactivated, an optional setting lets a new Mac take its place after a number of days you choose.

The diagram, the design decisions, and the wire format are in [`docs/architecture.md`](docs/architecture.md).

## How it compares

|  | SeatStamp | Paddle, Lemon Squeezy | Gumroad | Keygen |
|---|---|---|---|---|
| Fee on a $9 sale | Stripe's fee only (about $0.56 for a US card) | 5% + $0.50 (about $0.95) | 10% + $0.50, plus card processing | Monthly plan, plus your payment provider's fee |
| Monthly cost | $0 (Cloudflare and Stripe free plans) | $0 | $0 | Paid plans, or self-host |
| Who handles VAT and sales tax | You (Stripe Tax can help) | They do, as merchant of record | They do | You |
| Who holds customer data | Stripe only | The platform | The platform | Keygen and your payment provider |
| License check after unlock | Never: signed pass, verified offline | Online license API, if you use theirs | Online license API | Online by default, signed offline files available |
| If the vendor shuts down | Unlocked copies keep working | Depends on your integration | Depends on your integration | Depends on your integration |

Fees are the published rates as of November 2026; check each provider's pricing page before deciding.

When something else fits better: if you sell to many countries and don't want to deal with VAT at all, a merchant of record like Paddle takes that job off you, and it's worth the higher fee. SeatStamp fits when you're happy to be the seller of record and want to keep the fee, the customer relationship, and the offline guarantee.

## Quickstart

You need a Stripe account, a Cloudflare account, and about half an hour.

### 1. Create your signing keys

```sh
git clone https://github.com/denissitnikov/seatstamp.git
cd seatstamp

# License keys: the private key signs license passes and goes to your Worker
swift run license-tool --scheme MYAPP-V1 --init-keypair

# Update keys: the private key signs version.json and never leaves your Mac
swift run license-tool --scheme MYAPP-V1 --init-update-keypair
```

Private keys are saved with `0600` permissions under `~/.seatstamp/myapp-v1/`.

### 2. Set up Stripe

1. In **Stripe Dashboard > Payment Links**, create a one-time payment link and set the post-payment redirect to:
   ```text
   https://activate.myapp.com/thank-you?session_id={CHECKOUT_SESSION_ID}
   ```
2. In **Developers > API keys**, create a restricted key (`rk_live_...`) with **Read** permission on `Checkout Sessions`, `PaymentIntents`, `Charges`, and `Disputes`.

Details and test mode: [`docs/stripe-setup.md`](docs/stripe-setup.md).

### 3. Deploy the Worker

Edit `name`, `routes`, and `vars` (`TICKET_SCHEME`, `APP_NAME`, `APP_URL_SCHEME`) in [`worker/wrangler.jsonc`](worker/wrangler.jsonc), then:

```sh
npx wrangler -c worker/wrangler.jsonc deploy
npx wrangler -c worker/wrangler.jsonc secret put ED25519_PKCS8_B64
npx wrangler -c worker/wrangler.jsonc secret put STRIPE_SECRET_KEY
npx wrangler -c worker/wrangler.jsonc secret put STRIPE_ALLOWED_PAYMENT_LINKS
```

For local `wrangler dev`, copy [`worker/.dev.vars.example`](worker/.dev.vars.example) to `worker/.dev.vars`.

### 4. Add SeatStamp to your app

In Xcode, use **File > Add Package Dependencies...**, or in `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/denissitnikov/seatstamp.git", from: "1.0.0")
],
targets: [
    .executableTarget(name: "MyApp", dependencies: [
        .product(name: "SeatStamp", package: "seatstamp")
    ])
]
```

Then create one shared instance:

```swift
import SeatStamp

let kit = SeatStampManager(
    scheme: "MYAPP-V1",
    licensePublicKeyBase64: "<PASTE_LICENSE_PUBLIC_KEY>",
    updatePublicKeyBase64: "<PASTE_UPDATE_PUBLIC_KEY>",
    activationEndpoints: [URL(string: "https://activate.myapp.com")!],
    trialLengthDays: 30,
    maxSeats: 2,
    bundleID: "com.example.myapp"
)

// Gate a paid feature. Reads in-memory state only, so it's safe on hot paths.
if kit.verifyGateAccess() {
    runProFeature()
}

// Buy: opens the Payment Link in the browser, then activates in the background.
kit.beginBrowserCheckout(paymentLink: URL(string: "https://buy.stripe.com/...")!)

// Or activate a key the buyer pasted (cs_live_... online, or an LK1-... ticket offline).
let outcome = await kit.activate(key: userInput)
// .activated, .seatLimitReached, .networkError, .invalidKey, .unconfigured, .paymentPending, .clockSkew

// Free this Mac's seat. Queued and retried until the server answers.
kit.deactivate()
```

SwiftUI and AppKit settings views, deep links, update downloads, and a Node/Electron verifier are in [`docs/integrating.md`](docs/integrating.md). To see the whole flow running, try the example menu-bar app: `cd example && swift run`.

## Privacy and security

**What stays private**
- The Worker stores no names, email addresses, or IP addresses, and the shipped configuration writes no logs.
- It does store hashes of the purchase key and of each Mac's hardware ID. A hash can't be reversed, but it can be recomputed, so treat them as pseudonymous personal data.
- Unlocked apps never call home. The optional weekly update check sends no cookies or device IDs, and users can turn it off.
- Optional receipt and recovery emails go through your email provider (Resend), which sees the buyer's address and keeps sent messages for 30 days.

**What it defends against**
- Key generators: only your Worker holds the signing key. The app holds the public key, which can check a pass but can't create one.
- Unpaid, test-mode, refunded, and disputed orders: the Worker checks Stripe before it signs a pass for a new Mac.
- Sharing one key widely: one purchase reaches at most `MAX_SEATS + SEAT_RELEASES_PER_YEAR` Macs per year.
- A hacked Cloudflare account: update files are signed with a second key that stays offline on your Mac, so an attacker can't change the notice or the download.

**What it doesn't defend against**
- Someone editing your app's code on their own Mac can skip local checks, as with any offline software.
- A determined user can reset the trial by deleting all four local anchors, or by using a fresh macOS user.

Every stored value, with its retention: [`docs/privacy.md`](docs/privacy.md). Every threat, handled or not: [`docs/threat-model.md`](docs/threat-model.md).

## What's in the repo

| Path | What it is | Where it runs |
|---|---|---|
| `Sources/SeatStamp` | Swift package for your app: trial, activation, checkout, update notices | Inside your app |
| `worker/` | Cloudflare Worker that checks payments with Stripe and signs license passes | Cloudflare, free plan |
| `Sources/license-tool` | Command-line tool: create keys, sign your update file, revoke refunded orders | Your Mac |
| `example/` | Small menu-bar app that shows the whole flow | Your Mac |
| `site/` | The interactive walkthrough at [denissitnikov.github.io/seatstamp](https://denissitnikov.github.io/seatstamp/) | GitHub Pages |
| `fixtures/` | Golden test vectors shared by the Swift and JavaScript tests | Tests |
| `docs/` | Architecture, privacy, threat model, integration and Stripe guides | |

## Running the tests

```sh
swift build && swift run selftest     # Swift package, license-tool, golden vectors, repo hygiene
node --test worker/worker.test.mjs    # Worker and Durable Object (Node 22.12+, no npm install)
node --test site/site.test.mjs        # the walkthrough's examples match the real formats
cd example && swift build             # example app
```

## FAQ

**What if a buyer loses their key?**
They type their purchase email into the app and get every key for that address by email. Right after checkout, the thank-you page also offers Copy, Save as `.txt`, and an optional backup email. See [Buyer flow and key recovery](docs/stripe-setup.md#buyer-flow-and-key-recovery).

**What about EU VAT and US sales tax?**
With Stripe Payment Links you are the seller of record. You can turn on Stripe Tax, or register where you owe tax. If you'd rather not, see [How it compares](#how-it-compares).

**What if a Mac dies before it's deactivated?**
Set `EVICT_OLDEST_SEAT_AFTER_DAYS` (for example `"30"`) so a new Mac can take over an idle seat. Or mint a replacement pass yourself: `swift run license-tool --scheme MYAPP-V1 --mint cs_live_... --seat <seat code shown in the app>`.

**Can several apps share one Stripe account?**
Yes. Give each app its own Worker, `scheme`, and keypair, and set `STRIPE_ALLOWED_PAYMENT_LINKS` to that app's `plink_...` IDs.

**Can I use it from Electron, Tauri, or Rust?**
Yes. The Worker speaks plain JSON, and verifying a pass takes a few lines with any Ed25519 library. See [`docs/integrating.md`](docs/integrating.md#3-using-the-worker-and-license-tool-from-non-swift-mac-apps-electron-tauri-rust-go).

## License

MIT. See [`LICENSE`](LICENSE). Contributions are welcome: read [`CONTRIBUTING.md`](CONTRIBUTING.md) first, and report security issues as described in [`SECURITY.md`](SECURITY.md). Provided as is, without a support SLA.
