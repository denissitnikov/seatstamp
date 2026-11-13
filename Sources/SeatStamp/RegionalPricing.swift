import Foundation

/// Optional regional Stripe Payment Link selector based on `Locale.autoupdatingCurrent.region`
/// and `TimeZone.autoupdatingCurrent`.
public enum RegionalPricing {
    public enum Tier: String, CaseIterable, Equatable, Sendable {
        case usd
        case eur
        case jpy
        case cny
        case twd
        case krw
        case inr
    }

    public struct PaymentLinks: Equatable, Sendable {
        public let usd: URL
        public let eur: URL?
        public let jpy: URL?
        public let cny: URL?
        public let twd: URL?
        public let krw: URL?
        public let inr: URL?

        public init(
            usd: URL,
            eur: URL? = nil,
            jpy: URL? = nil,
            cny: URL? = nil,
            twd: URL? = nil,
            krw: URL? = nil,
            inr: URL? = nil
        ) {
            self.usd = usd
            self.eur = eur
            self.jpy = jpy
            self.cny = cny
            self.twd = twd
            self.krw = krw
            self.inr = inr
        }

        public func url(for tier: Tier) -> URL {
            switch tier {
            case .usd: return usd
            case .eur: return eur ?? usd
            case .jpy: return jpy ?? usd
            case .cny: return cny ?? usd
            case .twd: return twd ?? usd
            case .krw: return krw ?? usd
            case .inr: return inr ?? usd
            }
        }
    }

    private static let eurozoneRegions: Set<String> = [
        "AT", "BE", "BG", "CY", "DE", "EE", "ES", "FI", "FR", "GR", "HR",
        "IE", "IT", "LT", "LU", "LV", "MT", "NL", "PT", "SI", "SK"
    ]

    public static func currentTier(for links: PaymentLinks) -> Tier {
        let locale = Locale.autoupdatingCurrent
        let tz = TimeZone.autoupdatingCurrent
        return resolveTier(
            regionCode: locale.region?.identifier ?? "",
            currencyCode: locale.currency?.identifier ?? "",
            gmtOffsetSeconds: tz.secondsFromGMT(),
            timeZoneIdentifier: tz.identifier,
            links: links
        )
    }

    public static func checkoutURL(for links: PaymentLinks) -> URL {
        links.url(for: currentTier(for: links))
    }

    public static func resolveTier(
        regionCode: String,
        currencyCode: String,
        gmtOffsetSeconds: Int,
        timeZoneIdentifier: String,
        links: PaymentLinks
    ) -> Tier {
        let region = regionCode.uppercased()
        let currency = currencyCode.uppercased()

        switch region {
        case "IN":
            if (gmtOffsetSeconds == 19_800 || timeZoneIdentifier == "Asia/Kolkata" || timeZoneIdentifier == "Asia/Calcutta"),
               links.inr != nil {
                return .inr
            }
            return .usd
        case "JP":
            if (gmtOffsetSeconds == 32_400 || timeZoneIdentifier == "Asia/Tokyo"),
               links.jpy != nil {
                return .jpy
            }
            return .usd
        case "CN":
            if gmtOffsetSeconds == 28_800, links.cny != nil {
                return .cny
            }
            return .usd
        case "TW":
            return links.twd != nil ? .twd : .usd
        case "KR":
            return links.krw != nil ? .krw : .usd
        default:
            if (eurozoneRegions.contains(region) || currency == "EUR"), links.eur != nil {
                return .eur
            }
            return .usd
        }
    }
}
