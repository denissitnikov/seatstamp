import CryptoKit
import Foundation

/// HMAC-SHA256 trial seal (`TV2|first|high|revokedBefore|mac`, with read support for `TV1|first|high|mac`).
public enum TrialSeal {
    public struct Parsed: Equatable, Sendable {
        public let first: Int64
        public let high: Int64
        public let revokedBefore: Int64

        public init(first: Int64, high: Int64, revokedBefore: Int64) {
            self.first = first
            self.high = high
            self.revokedBefore = revokedBefore
        }
    }

    public static func make(first: Int64, high: Int64, revokedBefore: Int64, key: SymmetricKey) -> String {
        let msg = "TV2|\(first)|\(high)|\(revokedBefore)"
        let mac = HMAC<SHA256>.authenticationCode(for: Data(msg.utf8), using: key)
        return "\(msg)|\(LicenseTicket.base64URLEncode(Data(mac)))"
    }

    public static func verify(_ raw: String, key: SymmetricKey) -> Parsed? {
        guard raw.count <= 256 else { return nil }
        let parts = raw.split(separator: "|", omittingEmptySubsequences: false)
        let msg: String
        let parsed: Parsed
        let macField: String
        if parts.count == 5, parts[0] == "TV2",
           let f = Int64(parts[1]), let h = Int64(parts[2]), let r = Int64(parts[3]) {
            parsed = Parsed(first: f, high: h, revokedBefore: r)
            macField = String(parts[4])
            msg = "TV2|\(f)|\(h)|\(r)"
        } else if parts.count == 4, parts[0] == "TV1",
                  let f = Int64(parts[1]), let h = Int64(parts[2]) {
            parsed = Parsed(first: f, high: h, revokedBefore: 0)
            macField = String(parts[3])
            msg = "TV1|\(f)|\(h)"
        } else {
            return nil
        }
        guard let macData = LicenseTicket.base64URLDecode(macField),
              HMAC<SHA256>.isValidAuthenticationCode(macData, authenticating: Data(msg.utf8), using: key) else {
            return nil
        }
        return parsed
    }

    /// First 8 bytes of `SHA256(domain + hardwareUUID)` formatted as 16 lowercase hex chars.
    public static func seatCode(hardwareUUID: String, domain: String) -> String {
        let digest = SHA256.hash(data: Data((domain + hardwareUUID).utf8))
        return digest.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    public static func hmacKey(hardwareUUID: String, domain: String) -> SymmetricKey {
        SymmetricKey(data: SHA256.hash(data: Data((domain + hardwareUUID).utf8)))
    }
}
