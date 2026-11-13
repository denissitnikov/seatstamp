import CryptoKit
import Foundation

/// Ed25519 seat ticket verification and encoding.
///
/// Format: `<prefix><base64url(payload)>.<base64url(ed25519_signature)>` (default prefix: `LK1-`)
/// Payload: `<scheme>|ORD-<tag>|<issuedEpoch>[|<16-hex seat code>]`
///
/// The signature is checked over the raw payload bytes before parsing UTF-8 or splitting fields.
public enum LicenseTicket {
    public static let defaultPrefix = "LK1-"
    public static let defaultKeyHashDomain = "seatstamp-key-v1|"
    public static let minReasonableEpoch: Int64 = 1_700_000_000 // Nov 2023
    public static let maxReasonableEpoch: Int64 = 4_102_444_800 // Jan 2100

    public struct Payload: Equatable, Sendable {
        public let tag: String
        public let issued: Int64
        /// Lowercase 16-hex seat code, or `nil` for an unbound ticket.
        public let boundSeat: String?

        public init(tag: String, issued: Int64, boundSeat: String?) {
            self.tag = tag
            self.issued = issued
            self.boundSeat = boundSeat
        }
    }

    public enum Failure: Error, Equatable, Sendable {
        case malformed
        case badSignature
        case badPayload
        case seatMismatch
        case revoked
    }

    /// Derives the 16-hex `ORD-<16-UPPER-HEX>` order tag from a purchase key (`SHA256(domain + trimmedKey)` first 8 bytes).
    public static func deriveOrderTag(forPurchaseKey rawKey: String, domain: String = defaultKeyHashDomain) -> String {
        let trimmed = rawKey.trimmingCharacters(in: .whitespacesAndNewlines)
        let digest = SHA256.hash(data: Data((domain + trimmed).utf8))
        let hex16 = digest.prefix(8).map { String(format: "%02X", $0) }.joined()
        return "ORD-\(hex16)"
    }

    public static func normalizeOrderTag(_ rawTag: String) -> String {
        let trimmed = rawTag.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "|", with: "-")
        if trimmed.uppercased().hasPrefix("ORD-") {
            return "ORD-" + String(trimmed.dropFirst(4))
        }
        return "ORD-" + trimmed
    }

    /// Normalizes a non-empty order tag to canonical uppercase `"ORD-<TAG>"`, or returns `nil` when empty.
    public static func canonicalOrderTag(_ rawTag: String) -> String? {
        let trimmed = rawTag.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "|", with: "-")
        guard !trimmed.isEmpty else { return nil }
        let body: String
        if trimmed.uppercased().hasPrefix("ORD-") {
            body = String(trimmed.dropFirst(4)).trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            body = trimmed
        }
        guard !body.isEmpty else { return nil }
        return "ORD-" + body.uppercased()
    }

    public static func normalizeOrderTagSet<S: Sequence>(_ tags: S) -> Set<String> where S.Element == String {
        Set(tags.compactMap { canonicalOrderTag($0) })
    }

    public static func verify(
        _ raw: String,
        scheme: String,
        prefix: String = defaultPrefix,
        publicKey: Curve25519.Signing.PublicKey,
        expectedSeatCode: String,
        revokedBefore: Int64 = 0,
        revokedOrderTags: Set<String> = []
    ) -> Result<Payload, Failure> {
        guard !prefix.isEmpty, !scheme.isEmpty, raw.count <= 512, raw.hasPrefix(prefix) else {
            return .failure(.malformed)
        }
        let body = String(raw.dropFirst(prefix.count))
        let parts = body.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let payloadData = base64URLDecode(String(parts[0])),
              let sigData = base64URLDecode(String(parts[1])),
              sigData.count == 64 else {
            return .failure(.malformed)
        }
        guard publicKey.isValidSignature(sigData, for: payloadData) else {
            return .failure(.badSignature)
        }
        guard let payloadStr = String(data: payloadData, encoding: .utf8) else {
            return .failure(.badPayload)
        }
        let fields = payloadStr.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
        guard fields.count == 3 || fields.count == 4,
              fields[0] == scheme,
              fields[1].hasPrefix("ORD-"),
              fields[1].count > 4,
              let issued = Int64(fields[2]),
              issued >= minReasonableEpoch,
              issued <= maxReasonableEpoch else {
            return .failure(.badPayload)
        }

        var boundSeat: String? = nil
        if fields.count == 4 {
            let rawSeat = fields[3]
            guard rawSeat.utf8.count == 16, rawSeat.allSatisfy({ $0.isHexDigit }) else {
                return .failure(.badPayload)
            }
            let seat = rawSeat.lowercased()
            guard seat == expectedSeatCode.lowercased() else {
                return .failure(.seatMismatch)
            }
            if revokedBefore > 0, issued < revokedBefore {
                return .failure(.revoked)
            }
            boundSeat = seat
        }

        if !revokedOrderTags.isEmpty,
           let canonicalTicketTag = canonicalOrderTag(fields[1]),
           normalizeOrderTagSet(revokedOrderTags).contains(canonicalTicketTag) {
            return .failure(.revoked)
        }

        return .success(Payload(tag: fields[1], issued: issued, boundSeat: boundSeat))
    }

    public static func canonicalPayload(scheme: String, tag: String, issued: Int64, seat: String?) -> String {
        let normalizedTag = normalizeOrderTag(tag)
        if let seat = seat, !seat.isEmpty {
            return "\(scheme)|\(normalizedTag)|\(issued)|\(seat.lowercased())"
        }
        return "\(scheme)|\(normalizedTag)|\(issued)"
    }

    public static func encode(payload: String, signature: Data, prefix: String = defaultPrefix) -> String {
        prefix + base64URLEncode(Data(payload.utf8)) + "." + base64URLEncode(signature)
    }

    public static func base64URLDecode(_ s: String) -> Data? {
        guard !s.isEmpty else { return nil }
        var b64 = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let rem = b64.count % 4
        if rem != 0 { b64 += String(repeating: "=", count: 4 - rem) }
        return Data(base64Encoded: b64)
    }

    public static func base64URLEncode(_ d: Data) -> String {
        d.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
