import CryptoKit
import Foundation

/// Canonical serialization and Ed25519 verification for `version.json` update manifests.
public enum UpdateManifest {
    public static let defaultScheme = "SEATSTAMP-UPDATE-V1"

    /// Maps a license scheme to its default update scheme (`"MYAPP-V1"` -> `"MYAPP-UPDATE-V1"`).
    public static func derivedScheme(fromLicenseScheme licenseScheme: String) -> String {
        let trimmed = licenseScheme.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return defaultScheme }
        if let range = trimmed.range(of: #"-V[0-9]+$"#, options: [.regularExpression, .caseInsensitive]) {
            let base = String(trimmed[..<range.lowerBound])
            let ver = String(trimmed[range]).uppercased()
            return "\(base)-UPDATE\(ver)"
        }
        return "\(trimmed)-UPDATE-V1"
    }

    /// Length-prefixed UTF-8 byte serialization signed by `license-tool --sign-manifest`.
    /// When `revokedTags` is empty and `sha256`, `size`, and `manifestSeq` are nil, the output is byte-identical to v1.0 manifests.
    public static func canonicalSigningData(
        scheme: String = defaultScheme,
        version: String,
        url: String,
        summary: String,
        notes: [String],
        summaryI18n: [String: String],
        notesI18n: [String: [String]],
        revokedTags: [String] = [],
        sha256: String? = nil,
        size: Int64? = nil,
        manifestSeq: Int64? = nil
    ) -> Data {
        var out = "\(scheme)\n"
        func appendToken(_ s: String) {
            out.append("\(s.utf8.count):\(s)\n")
        }
        appendToken(version)
        appendToken(url)
        appendToken(summary)
        out.append("notes[\(notes.count)]\n")
        for n in notes { appendToken(n) }
        let sKeys = summaryI18n.keys.sorted()
        out.append("summary_i18n[\(sKeys.count)]\n")
        for k in sKeys {
            appendToken(k)
            appendToken(summaryI18n[k] ?? "")
        }
        let nKeys = notesI18n.keys.sorted()
        out.append("notes_i18n[\(nKeys.count)]\n")
        for k in nKeys {
            appendToken(k)
            let arr = notesI18n[k] ?? []
            out.append("items[\(arr.count)]\n")
            for item in arr { appendToken(item) }
        }
        let canonicalRevoked = LicenseTicket.normalizeOrderTagSet(revokedTags).sorted()
        if !canonicalRevoked.isEmpty {
            out.append("revoked_tags[\(canonicalRevoked.count)]\n")
            for tag in canonicalRevoked {
                appendToken(tag)
            }
        }
        if let sha256 = sha256 {
            out.append("artifact_sha256[1]\n")
            appendToken(sha256.lowercased())
        }
        if let size = size {
            out.append("artifact_size[1]\n")
            appendToken(String(size))
        }
        if let manifestSeq = manifestSeq {
            out.append("manifest_seq[1]\n")
            appendToken(String(manifestSeq))
        }
        return Data(out.utf8)
    }

    public struct Fields: Equatable, Sendable {
        public let version: String
        public let url: String
        public let summary: String
        public let notes: [String]
        public let summaryI18n: [String: String]
        public let notesI18n: [String: [String]]
        /// Canonical uppercase `"ORD-..."` tags sorted lexicographically.
        public let revokedTags: [String]
        /// Lower-case hex SHA-256 of the download, when the manifest binds the file.
        public let sha256: String?
        /// Byte size of the download, when the manifest binds the file.
        public let size: Int64?
        /// Signed sequence number; a client rejects a manifest whose sequence is lower than the highest it accepted.
        public let manifestSeq: Int64?
        public let signature: String?

        public init(
            version: String,
            url: String,
            summary: String,
            notes: [String],
            summaryI18n: [String: String] = [:],
            notesI18n: [String: [String]] = [:],
            revokedTags: [String] = [],
            sha256: String? = nil,
            size: Int64? = nil,
            manifestSeq: Int64? = nil,
            signature: String?
        ) {
            self.version = version
            self.url = url
            self.summary = summary
            self.notes = notes
            self.summaryI18n = summaryI18n
            self.notesI18n = notesI18n
            self.revokedTags = LicenseTicket.normalizeOrderTagSet(revokedTags).sorted()
            self.sha256 = sha256?.lowercased()
            self.size = size
            self.manifestSeq = manifestSeq
            self.signature = signature
        }
    }

    public enum ParseError: Error, Equatable, Sendable {
        case notAnObject, missingVersion, missingURL, missingSummary, badNotes, badSummaryI18n, badNotesI18n, badRevokedTags
        case badSha256, badSize
        case badManifestSeq
    }

    /// Largest integer a JSON number carries exactly (2^53 - 1).
    static let maxJSONInteger: Int64 = 9_007_199_254_740_991

    /// Reads a JSON integer from 1 to 2^53 - 1. Rejects booleans, strings, and fractional numbers.
    static func positiveJSONInteger(_ raw: Any) -> Int64? {
        guard let n = raw as? NSNumber,
              CFGetTypeID(n) != CFBooleanGetTypeID(),
              !CFNumberIsFloatType(n as CFNumber) else { return nil }
        let value = n.int64Value
        guard value >= 1, value <= maxJSONInteger else { return nil }
        return value
    }

    public static func fields(from json: [String: Any]) -> Result<Fields, ParseError> {
        guard let version = (json["version"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines), !version.isEmpty else {
            return .failure(.missingVersion)
        }
        guard let url = (json["url"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines), !url.isEmpty else {
            return .failure(.missingURL)
        }
        guard let summary = json["summary"] as? String else { return .failure(.missingSummary) }
        let notes: [String]
        if let raw = json["notes"] {
            guard let typed = raw as? [String] else { return .failure(.badNotes) }
            notes = typed
        } else { notes = [] }
        let summaryI18n: [String: String]
        if let raw = json["summary_i18n"] {
            guard let typed = raw as? [String: String] else { return .failure(.badSummaryI18n) }
            summaryI18n = typed
        } else { summaryI18n = [:] }
        let notesI18n: [String: [String]]
        if let raw = json["notes_i18n"] {
            guard let typed = raw as? [String: [String]] else { return .failure(.badNotesI18n) }
            notesI18n = typed
        } else { notesI18n = [:] }
        let revokedTags: [String]
        if let raw = json["revoked_tags"] {
            guard let typed = raw as? [String] else { return .failure(.badRevokedTags) }
            var normalized: Set<String> = []
            for item in typed {
                guard let canon = LicenseTicket.canonicalOrderTag(item) else {
                    return .failure(.badRevokedTags)
                }
                normalized.insert(canon)
            }
            revokedTags = normalized.sorted()
        } else {
            revokedTags = []
        }
        var sha256: String? = nil
        if let raw = json["sha256"] {
            guard let typed = (raw as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
                  typed.range(of: "^[0-9A-Fa-f]{64}$", options: .regularExpression) != nil else {
                return .failure(.badSha256)
            }
            sha256 = typed.lowercased()
        }
        var size: Int64? = nil
        if let raw = json["size"] {
            guard let typed = positiveJSONInteger(raw) else { return .failure(.badSize) }
            size = typed
        }
        if size != nil, sha256 == nil { return .failure(.badSize) }
        var manifestSeq: Int64? = nil
        if let raw = json["manifest_seq"] {
            guard let typed = positiveJSONInteger(raw) else { return .failure(.badManifestSeq) }
            manifestSeq = typed
        }
        return .success(Fields(
            version: version,
            url: url,
            summary: summary,
            notes: notes,
            summaryI18n: summaryI18n,
            notesI18n: notesI18n,
            revokedTags: revokedTags,
            sha256: sha256,
            size: size,
            manifestSeq: manifestSeq,
            signature: (json["sig"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        ))
    }

    public static func verify(
        _ f: Fields,
        scheme: String = defaultScheme,
        publicKey: Curve25519.Signing.PublicKey
    ) -> Bool {
        guard let sigRaw = f.signature, !sigRaw.isEmpty,
              let sig = LicenseTicket.base64URLDecode(sigRaw), sig.count == 64 else { return false }
        let canonical = canonicalSigningData(
            scheme: scheme,
            version: f.version,
            url: f.url,
            summary: f.summary,
            notes: f.notes,
            summaryI18n: f.summaryI18n,
            notesI18n: f.notesI18n,
            revokedTags: f.revokedTags,
            sha256: f.sha256,
            size: f.size,
            manifestSeq: f.manifestSeq
        )
        return publicKey.isValidSignature(sig, for: canonical)
    }
}
