# Optional Regional Pricing (PPP Payment Links)

Stripe Payment Links let you create per-currency links (for example `$19` USD, `18 €` EUR, `¥2,200` JPY, `₹999` INR) without running a geo-IP service.

`RegionalPricing` in `Sources/SeatStamp/RegionalPricing.swift` is optional. If you use a single USD price worldwide, skip it and link directly to your primary `buy.stripe.com` URL.

## How `RegionalPricing` Selects a Tier

`RegionalPricing.currentTier(for:)` reads two local macOS settings:
1. `Locale.autoupdatingCurrent.region` (*System Settings -> General -> Language & Region -> Region*)
2. `TimeZone.autoupdatingCurrent` (system timezone)

| Tier | Region Match | Timezone Requirement |
|---|---|---|
| `.inr` | `IN` | `GMT+05:30` (`Asia/Kolkata` / `Asia/Calcutta`) |
| `.jpy` | `JP` | `GMT+09:00` (`Asia/Tokyo`) |
| `.cny` | `CN` | `GMT+08:00` |
| `.twd` | `TW` | None |
| `.krw` | `KR` | None |
| `.eur` | Eurozone ISO-2 or `currency == EUR` | None |
| `.usd` | Fallback when region/timezone or link is not set | None |

### Usage in Swift

```swift
import SeatStamp

let paymentLinks = RegionalPricing.PaymentLinks(
    usd: URL(string: "https://buy.stripe.com/<YOUR_USD_LINK>")!,
    eur: URL(string: "https://buy.stripe.com/<YOUR_EUR_LINK>"),
    jpy: URL(string: "https://buy.stripe.com/<YOUR_JPY_LINK>"),
    inr: URL(string: "https://buy.stripe.com/<YOUR_INR_LINK>")
)

let checkoutURL = RegionalPricing.checkoutURL(for: paymentLinks)
```

Include every regional `plink_...` ID in your Worker's `STRIPE_ALLOWED_PAYMENT_LINKS` list so sessions from all configured links are accepted.

## Limitations

Every regional Payment Link URL is public and listed in `STRIPE_ALLOWED_PAYMENT_LINKS`. The INR, JPY, and CNY tiers need two matching settings (Region and time zone), which avoids casual switching. The TWD, KRW, and EUR tiers switch on Region alone, and the EUR tier also matches when the locale's currency is EUR, so one change in System Settings selects them. A user who changes those settings (or extracts the `buy.stripe.com` URL from the binary) can buy at the lower tier. If that trade-off does not fit your price point, use a single USD Payment Link instead.
