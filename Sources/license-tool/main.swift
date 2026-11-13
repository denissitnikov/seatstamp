// license-tool: Ed25519 key generation, seat ticket signing, order-tag derivation, and update manifest signing.
//
// Uses two separate keypairs:
//   ~/.seatstamp/<scheme>/ed25519_private.key         LICENSE key (PKCS#8 uploaded to Cloudflare Worker)
//   ~/.seatstamp/<scheme>/ed25519_update_private.key  UPDATE key  (kept offline on your Mac to sign version.json)
//
// Usage:
//   swift run license-tool --scheme MYAPP-V1 --init-keypair
//   swift run license-tool --scheme MYAPP-V1 --init-update-keypair
//   swift run license-tool --scheme MYAPP-V1 --rotate-keypair
//   swift run license-tool --scheme MYAPP-V1 --print-public-and-pkcs8
//   swift run license-tool --scheme MYAPP-V1 --print-update-public
//   swift run license-tool --scheme MYAPP-V1 --tag-for-key <purchaseKey> [--key-hash-domain myapp-key-v1|]
//   swift run license-tool --scheme MYAPP-V1 --revoke-key <purchaseKeyOrOrdTag> version.json [--key-hash-domain myapp-key-v1|] [--seq]
//   swift run license-tool --scheme MYAPP-V1 --unrevoke-key <purchaseKeyOrOrdTag> version.json [--key-hash-domain myapp-key-v1|]
//   swift run license-tool --scheme MYAPP-V1 --sign-manifest version.json [--artifact MyApp.dmg] [--seq]
//   swift run license-tool --scheme MYAPP-V1 --verify-manifest version.json <updatePubB64> [expectedVersion] [--url-prefix https://myapp.com/download/] [--artifact MyApp.dmg]
//
// --artifact <file> computes the SHA-256 and byte size of the download and signs them into the manifest
// (--sign-manifest), or checks the file against the signed values (--verify-manifest).
// --seq (no value) signs a manifest_seq of max(previous + 1, current unix seconds). --sign-manifest with --artifact
// implies it, and a manifest that already carries manifest_seq always gets a higher one when it is re-signed.
//   swift run license-tool --scheme MYAPP-V1 --mint <purchaseKeyOrOrdTag> --seat <16-hex-seat>
//   swift run license-tool --scheme MYAPP-V1 --mint <purchaseKeyOrOrdTag> --universal
//   SEATSTAMP_ADMIN_TOKEN=... swift run license-tool --erase-key <purchaseKey> --endpoint https://activate.myapp.com

import CryptoKit
import Foundation
import SeatStamp

// RFC 8410 ASN.1 PKCS#8 v1 prefix for a 32-byte Ed25519 private seed (OID 1.3.101.112)
let ed25519PKCS8Header = Data([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20])

func makePKCS8Base64(from rawSeed: Data) -> String {
    var der = Data()
    der.reserveCapacity(48)
    der.append(ed25519PKCS8Header)
    der.append(rawSeed)
    return der.base64EncodedString()
}

func fail(_ msg: String) -> Never {
    fputs("Error: \(msg)\n", stderr)
    exit(1)
}

func sanitizeSlug(_ s: String) -> String {
    let allowed = s.lowercased().map { c -> Character in
        (c.isLetter || c.isNumber || c == "-" || c == "_") ? c : "-"
    }
    let slug = String(allowed).trimmingCharacters(in: CharacterSet(charactersIn: "-"))
    return slug.isEmpty ? "default" : slug
}

var scheme = ProcessInfo.processInfo.environment["SEATSTAMP_SCHEME"] ?? "SEATSTAMP-V1"
var explicitUpdateScheme: String? = nil
var ticketPrefix = LicenseTicket.defaultPrefix
var keyHashDomain = ProcessInfo.processInfo.environment["KEY_HASH_DOMAIN"] ?? LicenseTicket.defaultKeyHashDomain
var explicitKeyDir: String? = nil
var urlPrefixGuard: String? = nil
var artifactPath: String? = nil
var seqFlag = false
var mintSeatArg: String? = nil
var universalFlag = false
var endpointArg: String? = nil
var positional: [String] = []

let knownCommands: Set<String> = [
    "--init-keypair", "--init-update-keypair", "--print-public-and-pkcs8", "--print-update-public",
    "--tag-for-key", "--revoke-key", "--unrevoke-key", "--sign-manifest", "--verify-manifest",
    "--mint", "--rotate-keypair", "--erase-key",
]

let usageText = """
Usage: swift run license-tool [--scheme MYAPP-V1] [--key-dir <dir>] [--key-hash-domain <domain>] <command>

Commands:
  --init-keypair                                    Generate Ed25519 LICENSE keypair (once)
  --init-update-keypair                             Generate offline Ed25519 UPDATE keypair (once)
  --rotate-keypair                                  Archive the LICENSE key and generate a new one
  --print-public-and-pkcs8                          Print license public key + Cloudflare ED25519_PKCS8_B64 secret
  --print-update-public                             Print update public key for SeatStampManager(updatePublicKeyBase64:)
  --tag-for-key <purchaseKey>                       Derive ORD-<16-HEX> tag from a purchase key locally
  --revoke-key <purchaseKeyOrOrdTag> <manifestPath> Add revoked ORD-... tag to version.json and re-sign
  --unrevoke-key <purchaseKeyOrOrdTag> <manifestPath>
                                                    Remove an ORD-... tag, raise manifest_seq, and re-sign
  --sign-manifest <path> [--artifact <file>]        Sign version.json in place with the offline UPDATE key
  --verify-manifest <path> <pubB64> [expectedVer]   Verify version.json signature
        [--artifact <file>]                         Also check the file against the signed sha256 and size
  --mint <purchaseKeyOrOrdTag> (--seat <16-hex> | --universal)
                                                    Mint an offline ticket bound to one Mac (or universal).
                                                    A purchase key is hashed to its ORD- tag.
  --erase-key <purchaseKey> --endpoint <https URL>  Wipe the Worker's record of one purchase (needs the Worker
                                                    secret ADMIN_TOKEN and the same value in the environment
                                                    variable SEATSTAMP_ADMIN_TOKEN)

Options:
  --artifact <file>                                 Sign (or check) the SHA-256 and byte size of the download
  --seq                                             Sign a manifest_seq above the previous one (implied by
                                                    --sign-manifest --artifact; kept rising once present)
"""

let rawArgs = Array(CommandLine.arguments.dropFirst())
var idx = 0
while idx < rawArgs.count {
    let arg = rawArgs[idx]
    switch arg {
    case "--scheme":
        guard idx + 1 < rawArgs.count else { fail("--scheme requires a value (e.g. MYAPP-V1).") }
        scheme = rawArgs[idx + 1].trimmingCharacters(in: .whitespacesAndNewlines)
        idx += 2
    case "--update-scheme":
        guard idx + 1 < rawArgs.count else { fail("--update-scheme requires a value (e.g. MYAPP-UPDATE-V1).") }
        explicitUpdateScheme = rawArgs[idx + 1].trimmingCharacters(in: .whitespacesAndNewlines)
        idx += 2
    case "--prefix":
        guard idx + 1 < rawArgs.count else { fail("--prefix requires a value (e.g. LK1-).") }
        ticketPrefix = rawArgs[idx + 1]
        idx += 2
    case "--key-hash-domain":
        guard idx + 1 < rawArgs.count else { fail("--key-hash-domain requires a value (e.g. myapp-key-v1|).") }
        keyHashDomain = rawArgs[idx + 1]
        idx += 2
    case "--key-dir":
        guard idx + 1 < rawArgs.count else { fail("--key-dir requires a directory path.") }
        explicitKeyDir = rawArgs[idx + 1]
        idx += 2
    case "--url-prefix":
        guard idx + 1 < rawArgs.count else { fail("--url-prefix requires an HTTPS URL prefix.") }
        urlPrefixGuard = rawArgs[idx + 1]
        idx += 2
    case "--artifact":
        guard idx + 1 < rawArgs.count else { fail("--artifact requires a file path (e.g. MyApp-2.0.0.dmg).") }
        artifactPath = rawArgs[idx + 1]
        idx += 2
    case "--seq":
        seqFlag = true
        idx += 1
    case "--seat":
        guard idx + 1 < rawArgs.count else { fail("--seat requires a 16-hex seat code.") }
        mintSeatArg = rawArgs[idx + 1]
        idx += 2
    case "--universal":
        universalFlag = true
        idx += 1
    case "--endpoint":
        guard idx + 1 < rawArgs.count else { fail("--endpoint requires an https URL (e.g. https://activate.myapp.com).") }
        endpointArg = rawArgs[idx + 1]
        idx += 2
    case "--help", "-h":
        print(usageText)
        exit(0)
    default:
        if arg.hasPrefix("--"), !knownCommands.contains(arg) {
            fail("Unknown option '\(arg)'. Run license-tool --help.")
        }
        positional.append(arg)
        idx += 1
    }
}

guard !scheme.isEmpty, !scheme.contains("|") else {
    fail("Scheme must be non-empty and must not contain '|'.")
}
let updateScheme = explicitUpdateScheme ?? UpdateManifest.derivedScheme(fromLicenseScheme: scheme)

let keyDir: URL = {
    if let custom = explicitKeyDir {
        return URL(fileURLWithPath: (custom as NSString).expandingTildeInPath, isDirectory: true)
    }
    // Default ~/.seatstamp/<scheme>.
    return FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".seatstamp", isDirectory: true)
        .appendingPathComponent(sanitizeSlug(scheme), isDirectory: true)
}()
let licensePrivPath = keyDir.appendingPathComponent("ed25519_private.key")
let updatePrivPath = keyDir.appendingPathComponent("ed25519_update_private.key")

func initKeypair(at path: URL, label: String) throws -> Curve25519.Signing.PrivateKey {
    try FileManager.default.createDirectory(at: keyDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    if FileManager.default.fileExists(atPath: path.path) {
        fail("\(label) keypair already exists at \(path.path). It is never overwritten. To rotate the LICENSE key run --rotate-keypair.")
    }
    let priv = Curve25519.Signing.PrivateKey()
    try priv.rawRepresentation.base64EncodedString().write(to: path, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
    print("Saved \(label) private key (0600) to: \(path.path)")
    return priv
}

func loadKey(at path: URL, label: String) -> Curve25519.Signing.PrivateKey {
    guard let b64 = try? String(contentsOf: path, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
          let bytes = Data(base64Encoded: b64) else {
        fail("\(label) private key not found at \(path.path). Run --init-keypair / --init-update-keypair first.")
    }
    let seed: Data = (bytes.count == 48 && bytes.starts(with: ed25519PKCS8Header)) ? bytes.suffix(32) : bytes
    guard let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed) else {
        fail("Invalid Ed25519 private key at \(path.path).")
    }
    return key
}

func resolveOrderTagInput(_ rawInput: String, domain: String) -> String {
    let trimmed = rawInput.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else {
        fail("Order key or tag must not be empty.")
    }
    if trimmed.contains("@") {
        fail("Do not pass an email address; tags and purchase keys must be opaque identifiers.")
    }
    if trimmed.uppercased().hasPrefix("ORD-") {
        guard let canon = LicenseTicket.canonicalOrderTag(trimmed) else {
            fail("Invalid ORD- tag '\(trimmed)'.")
        }
        return canon
    }
    return LicenseTicket.deriveOrderTag(forPurchaseKey: trimmed, domain: domain)
}

/// Streams the file through SHA-256 in 1 MiB chunks; returns lower-case hex and the byte count.
func artifactDigest(at path: String) -> (sha256: String, size: Int64) {
    let url = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
    guard let handle = try? FileHandle(forReadingFrom: url) else {
        fail("Could not read artifact at \(path).")
    }
    defer { try? handle.close() }
    var hasher = SHA256()
    var total: Int64 = 0
    while true {
        let next: Data?
        do {
            next = try handle.read(upToCount: 1024 * 1024)
        } catch {
            fail("Could not read artifact at \(path).")
        }
        guard let chunk = next, !chunk.isEmpty else { break }
        hasher.update(data: chunk)
        total += Int64(chunk.count)
    }
    guard total >= 1 else { fail("Artifact at \(path) is empty.") }
    return (hasher.finalize().map { String(format: "%02x", $0) }.joined(), total)
}

/// The next signed sequence: `max(existing + 1, current unix seconds)`, with a missing value counting as 0.
func nextManifestSeq(after existing: Int64?) -> Int64 {
    max((existing ?? 0) + 1, Int64(Date().timeIntervalSince1970))
}

func signAndWriteManifest(
    fields f: UpdateManifest.Fields,
    includeEmptyNotes: Bool,
    includeEmptyRevokedTags: Bool,
    to fileURL: URL,
    priv: Curve25519.Signing.PrivateKey,
    scheme: String
) throws -> String {
    guard VersionCompare.isValidVersionString(f.version) else {
        fail("Manifest version '\(f.version)' is not a valid dotted version string.")
    }
    guard let parsedURL = URL(string: f.url),
          parsedURL.scheme?.lowercased() == "https",
          !parsedURL.pathComponents.contains("..") else {
        fail("Manifest url must be a valid https:// URL without '..' segments.")
    }
    let canonical = UpdateManifest.canonicalSigningData(
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
    let sig = try priv.signature(for: canonical)
    guard priv.publicKey.isValidSignature(sig, for: canonical) else {
        fail("Ed25519 self-verification failed.")
    }
    let sigB64URL = LicenseTicket.base64URLEncode(sig)

    func q(_ s: String) -> String {
        let d = try! JSONSerialization.data(withJSONObject: [s], options: [.withoutEscapingSlashes])
        return String(String(data: d, encoding: .utf8)!.dropFirst().dropLast())
    }
    var entries: [String] = []
    entries.append("  \"version\": \(q(f.version))")
    entries.append("  \"summary\": \(q(f.summary))")
    if !f.notes.isEmpty || includeEmptyNotes {
        entries.append(f.notes.isEmpty ? "  \"notes\": []" : "  \"notes\": [\n\(f.notes.map { "    \(q($0))" }.joined(separator: ",\n"))\n  ]")
    }
    if !f.summaryI18n.isEmpty {
        let sLines = f.summaryI18n.keys.sorted().map { "    \(q($0)): \(q(f.summaryI18n[$0]!))" }.joined(separator: ",\n")
        entries.append("  \"summary_i18n\": {\n\(sLines)\n  }")
    }
    if !f.notesI18n.isEmpty {
        let nLines = f.notesI18n.keys.sorted().map { k -> String in
            let items = (f.notesI18n[k] ?? []).map { "      \(q($0))" }.joined(separator: ",\n")
            return "    \(q(k)): [\n\(items)\n    ]"
        }.joined(separator: ",\n")
        entries.append("  \"notes_i18n\": {\n\(nLines)\n  }")
    }
    if !f.revokedTags.isEmpty || includeEmptyRevokedTags {
        entries.append(
            f.revokedTags.isEmpty
                ? "  \"revoked_tags\": []"
                : "  \"revoked_tags\": [\n\(f.revokedTags.map { "    \(q($0))" }.joined(separator: ",\n"))\n  ]"
        )
    }
    if let sha256 = f.sha256 {
        entries.append("  \"sha256\": \(q(sha256))")
    }
    if let size = f.size {
        entries.append("  \"size\": \(size)")
    }
    if let manifestSeq = f.manifestSeq {
        entries.append("  \"manifest_seq\": \(manifestSeq)")
    }
    entries.append("  \"url\": \(q(f.url))")
    entries.append("  \"sig\": \(q(sigB64URL))")
    try ("{\n" + entries.joined(separator: ",\n") + "\n}\n").write(to: fileURL, atomically: true, encoding: .utf8)
    return sigB64URL
}

switch positional.first {
case "--init-keypair":
    let priv = try initKeypair(at: licensePrivPath, label: "LICENSE")
    print("Scheme: \(scheme)")
    print("Paste into SeatStampManager(licensePublicKeyBase64:):")
    print(priv.publicKey.rawRepresentation.base64EncodedString())
    print("Paste into `npx wrangler secret put ED25519_PKCS8_B64`:")
    print(makePKCS8Base64(from: priv.rawRepresentation))
    exit(0)

case "--init-update-keypair":
    let priv = try initKeypair(at: updatePrivPath, label: "UPDATE")
    print("Update scheme: \(updateScheme)")
    print("Paste into SeatStampManager(updatePublicKeyBase64:):")
    print(priv.publicKey.rawRepresentation.base64EncodedString())
    print("Keep this private key offline on your Mac.")
    exit(0)

case "--rotate-keypair":
    guard FileManager.default.fileExists(atPath: licensePrivPath.path) else {
        fail("No LICENSE key to rotate. Run --init-keypair first.")
    }
    let oldPriv = loadKey(at: licensePrivPath, label: "LICENSE")
    let stampFormatter = DateFormatter()
    stampFormatter.locale = Locale(identifier: "en_US_POSIX")
    stampFormatter.timeZone = TimeZone(identifier: "UTC")
    stampFormatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
    let archivedPath = keyDir.appendingPathComponent("ed25519_private.retired-\(stampFormatter.string(from: Date())).key")
    if FileManager.default.fileExists(atPath: archivedPath.path) {
        fail("\(archivedPath.path) already exists. Nothing was changed; try again in a second.")
    }
    do {
        try FileManager.default.moveItem(at: licensePrivPath, to: archivedPath)
    } catch {
        fail("Could not archive \(licensePrivPath.path): \(error.localizedDescription)")
    }
    let newPriv = Curve25519.Signing.PrivateKey()
    // Owner-only mode from the first byte on disk; never replace an existing file.
    umask(0o077)
    do {
        try Data(newPriv.rawRepresentation.base64EncodedString().utf8).write(to: licensePrivPath, options: .withoutOverwriting)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: licensePrivPath.path)
    } catch {
        fail("Could not write the new LICENSE key to \(licensePrivPath.path): \(error.localizedDescription). The old key is at \(archivedPath.path).")
    }
    print("Archived old LICENSE private key to:")
    print(archivedPath.path)
    print("New license public key (SeatStampManager licensePublicKeyBase64):")
    print(newPriv.publicKey.rawRepresentation.base64EncodedString())
    print("Retired license public key (SeatStampManager retiredLicensePublicKeysBase64 and Worker ED25519_RETIRED_PUB_B64):")
    print(oldPriv.publicKey.rawRepresentation.base64EncodedString())
    print("New Cloudflare Worker secret (ED25519_PKCS8_B64):")
    print(makePKCS8Base64(from: newPriv.rawRepresentation))
    print("If you set ED25519_PUB_B64 on the Worker, set it to the new public key or delete it.")
    exit(0)

case "--print-public-and-pkcs8":
    let priv = loadKey(at: licensePrivPath, label: "LICENSE")
    print("License Public Key (licensePublicKeyBase64):")
    print(priv.publicKey.rawRepresentation.base64EncodedString())
    print("Cloudflare Worker secret (ED25519_PKCS8_B64):")
    print(makePKCS8Base64(from: priv.rawRepresentation))
    exit(0)

case "--print-update-public":
    let priv = loadKey(at: updatePrivPath, label: "UPDATE")
    print(priv.publicKey.rawRepresentation.base64EncodedString())
    exit(0)

case "--tag-for-key":
    guard positional.count >= 2 else {
        fail("Usage: --tag-for-key <purchaseKey> [--key-hash-domain <domain>]")
    }
    let rawKey = positional[1].trimmingCharacters(in: .whitespacesAndNewlines)
    guard !rawKey.isEmpty else { fail("purchaseKey must not be empty.") }
    if rawKey.contains("@") {
        fail("Do not pass an email address; pass a purchase key such as cs_live_... or a store UUID.")
    }
    print(LicenseTicket.deriveOrderTag(forPurchaseKey: rawKey, domain: keyHashDomain))
    exit(0)

case "--revoke-key":
    guard positional.count >= 3 else {
        fail("Usage: --revoke-key <purchaseKeyOrOrdTag> <manifestPath> [--key-hash-domain <domain>]")
    }
    let priv = loadKey(at: updatePrivPath, label: "UPDATE")
    let tagToRevoke = resolveOrderTagInput(positional[1], domain: keyHashDomain)
    let targetPath = positional[2]
    let fileURL = URL(fileURLWithPath: targetPath)
    guard let rawData = try? Data(contentsOf: fileURL),
          let json = (try? JSONSerialization.jsonObject(with: rawData)) as? [String: Any] else {
        fail("Could not parse manifest JSON at \(targetPath).")
    }
    let parsedFields: UpdateManifest.Fields
    switch UpdateManifest.fields(from: json) {
    case .success(let p): parsedFields = p
    case .failure(let e): fail("Manifest invalid: \(e)")
    }
    var mergedRevoked = Set(parsedFields.revokedTags)
    mergedRevoked.insert(tagToRevoke)
    let updatedFields = UpdateManifest.Fields(
        version: parsedFields.version,
        url: parsedFields.url,
        summary: parsedFields.summary,
        notes: parsedFields.notes,
        summaryI18n: parsedFields.summaryI18n,
        notesI18n: parsedFields.notesI18n,
        revokedTags: Array(mergedRevoked).sorted(),
        sha256: parsedFields.sha256,
        size: parsedFields.size,
        manifestSeq: (seqFlag || parsedFields.manifestSeq != nil) ? nextManifestSeq(after: parsedFields.manifestSeq) : nil,
        signature: nil
    )
    let sigB64URL = try signAndWriteManifest(
        fields: updatedFields,
        includeEmptyNotes: json["notes"] != nil,
        includeEmptyRevokedTags: true,
        to: fileURL,
        priv: priv,
        scheme: updateScheme
    )
    let revokeSeqLabel = updatedFields.manifestSeq.map { ", manifest_seq: \($0)" } ?? ""
    print("Revoked \(tagToRevoke) in \(targetPath) (total revoked_tags: \(updatedFields.revokedTags.count), scheme: \(updateScheme)\(revokeSeqLabel)) -> sig: \(sigB64URL)")
    exit(0)

case "--unrevoke-key":
    guard positional.count >= 3 else {
        fail("Usage: --unrevoke-key <purchaseKeyOrOrdTag> <manifestPath> [--key-hash-domain <domain>]")
    }
    let priv = loadKey(at: updatePrivPath, label: "UPDATE")
    let tagToRestore = resolveOrderTagInput(positional[1], domain: keyHashDomain)
    let targetPath = positional[2]
    let fileURL = URL(fileURLWithPath: targetPath)
    guard let rawData = try? Data(contentsOf: fileURL),
          let json = (try? JSONSerialization.jsonObject(with: rawData)) as? [String: Any] else {
        fail("Could not parse manifest JSON at \(targetPath).")
    }
    let parsedFields: UpdateManifest.Fields
    switch UpdateManifest.fields(from: json) {
    case .success(let p): parsedFields = p
    case .failure(let e): fail("Manifest invalid: \(e)")
    }
    var remainingRevoked = Set(parsedFields.revokedTags)
    guard remainingRevoked.remove(tagToRestore) != nil else {
        fail("Tag \(tagToRestore) is not in revoked_tags.")
    }
    // Clients remove a tag only on a higher sequence, so always sign a new manifest_seq.
    let updatedFields = UpdateManifest.Fields(
        version: parsedFields.version,
        url: parsedFields.url,
        summary: parsedFields.summary,
        notes: parsedFields.notes,
        summaryI18n: parsedFields.summaryI18n,
        notesI18n: parsedFields.notesI18n,
        revokedTags: Array(remainingRevoked).sorted(),
        sha256: parsedFields.sha256,
        size: parsedFields.size,
        manifestSeq: nextManifestSeq(after: parsedFields.manifestSeq),
        signature: nil
    )
    _ = try signAndWriteManifest(
        fields: updatedFields,
        includeEmptyNotes: json["notes"] != nil,
        includeEmptyRevokedTags: true,
        to: fileURL,
        priv: priv,
        scheme: updateScheme
    )
    print("Unrevoked \(tagToRestore) in \(targetPath) (total revoked_tags: \(updatedFields.revokedTags.count), manifest_seq: \(updatedFields.manifestSeq ?? 0))")
    exit(0)

case "--sign-manifest":
    let priv = loadKey(at: updatePrivPath, label: "UPDATE")
    let targetPath = positional.count >= 2 ? positional[1] : "version.json"
    let fileURL = URL(fileURLWithPath: targetPath)
    guard let rawData = try? Data(contentsOf: fileURL),
          let json = (try? JSONSerialization.jsonObject(with: rawData)) as? [String: Any] else {
        fail("Could not parse manifest JSON at \(targetPath).")
    }
    let parsedForSigning: UpdateManifest.Fields
    switch UpdateManifest.fields(from: json) {
    case .success(let parsed): parsedForSigning = parsed
    case .failure(let e): fail("Manifest invalid: \(e)")
    }
    var signSha256 = parsedForSigning.sha256
    var signSize = parsedForSigning.size
    if let artifact = artifactPath {
        let digest = artifactDigest(at: artifact)
        signSha256 = digest.sha256
        signSize = digest.size
    } else if parsedForSigning.sha256 != nil {
        fail("This manifest carries sha256; pass --artifact <file> for the new download, or remove sha256 and size.")
    }
    let useSeq = seqFlag || artifactPath != nil || parsedForSigning.manifestSeq != nil
    let f = UpdateManifest.Fields(
        version: parsedForSigning.version,
        url: parsedForSigning.url,
        summary: parsedForSigning.summary,
        notes: parsedForSigning.notes,
        summaryI18n: parsedForSigning.summaryI18n,
        notesI18n: parsedForSigning.notesI18n,
        revokedTags: parsedForSigning.revokedTags,
        sha256: signSha256,
        size: signSize,
        manifestSeq: useSeq ? nextManifestSeq(after: parsedForSigning.manifestSeq) : nil,
        signature: nil
    )
    let sigB64URL = try signAndWriteManifest(
        fields: f,
        includeEmptyNotes: json["notes"] != nil,
        includeEmptyRevokedTags: json["revoked_tags"] != nil,
        to: fileURL,
        priv: priv,
        scheme: updateScheme
    )
    let signSeqLabel = f.manifestSeq.map { ", manifest_seq \($0)" } ?? ""
    print("Signed \(targetPath) (version \(f.version), scheme \(updateScheme)\(signSeqLabel)) -> sig: \(sigB64URL)")
    exit(0)

case "--verify-manifest":
    guard positional.count >= 3 else {
        fail("Usage: --verify-manifest <path> <updatePublicKeyBase64> [expectedVersion] [--url-prefix https://...]")
    }
    let fileURL = URL(fileURLWithPath: positional[1])
    guard let pubData = Data(base64Encoded: positional[2]), pubData.count == 32,
          let pubKey = try? Curve25519.Signing.PublicKey(rawRepresentation: pubData) else {
        fail("updatePublicKeyBase64 is not a valid 32-byte Ed25519 public key.")
    }
    guard let rawData = try? Data(contentsOf: fileURL),
          let json = (try? JSONSerialization.jsonObject(with: rawData)) as? [String: Any] else {
        fail("Could not parse manifest JSON at \(positional[1]).")
    }
    guard case .success(let f) = UpdateManifest.fields(from: json) else { fail("Manifest is missing required fields.") }
    guard let parsedURL = URL(string: f.url),
          parsedURL.scheme?.lowercased() == "https",
          !parsedURL.pathComponents.contains("..") else {
        fail("Manifest url must use https:// and must not contain '..' segments.")
    }
    if let requiredPrefix = urlPrefixGuard, !f.url.hasPrefix(requiredPrefix) {
        fail("Manifest url '\(f.url)' does not start with '\(requiredPrefix)'.")
    }
    if positional.count >= 4, positional[3] != f.version {
        fail("Manifest version '\(f.version)' != expected '\(positional[3])'.")
    }
    guard UpdateManifest.verify(f, scheme: updateScheme, publicKey: pubKey) else {
        fail("Manifest signature does NOT verify with the provided update public key (scheme: \(updateScheme)).")
    }
    if let artifact = artifactPath {
        let digest = artifactDigest(at: artifact)
        guard f.sha256 == digest.sha256, f.size == nil || f.size == digest.size else {
            fail("Artifact does not match the manifest sha256 or size.")
        }
    }
    let shaLabel = f.sha256.map { String($0.prefix(12)) } ?? "none"
    print("\(positional[1]) OK: version \(f.version), signature verified (\(updateScheme), revoked_tags: \(f.revokedTags.count), sha256: \(shaLabel))")
    exit(0)

case "--mint":
    let mintUsage = "Usage: --mint <purchaseKeyOrOrdTag> (--seat <16-hex> | --universal)"
    guard positional.count >= 2 else { fail(mintUsage) }
    guard positional.count == 2 else {
        fail("--mint takes exactly one purchase key or ORD- tag. \(mintUsage)")
    }
    guard (mintSeatArg != nil) != universalFlag else {
        fail("Pass exactly one of --seat <16-hex> or --universal. \(mintUsage)")
    }
    let mintTag = resolveOrderTagInput(positional[1], domain: keyHashDomain)
    guard mintTag.dropFirst(4).count <= 64 else {
        fail("An ORD- tag must have at most 64 characters after ORD-.")
    }
    var mintSeat: String? = nil
    if let rawSeat = mintSeatArg {
        let cleaned = rawSeat.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard cleaned.utf8.count == 16, cleaned.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else {
            fail("Seat hash '\(cleaned)' must be 16 lowercase hex characters.")
        }
        mintSeat = cleaned
    }
    let priv = loadKey(at: licensePrivPath, label: "LICENSE")
    if mintSeat == nil {
        fputs("Warning: minting a universal ticket (valid on any Mac, cannot be revoked by watermark). Pass --seat <16-hex> to bind it.\n", stderr)
    }
    let payload = LicenseTicket.canonicalPayload(scheme: scheme, tag: mintTag, issued: Int64(Date().timeIntervalSince1970), seat: mintSeat)
    let signature = try priv.signature(for: Data(payload.utf8))
    print(LicenseTicket.encode(payload: payload, signature: signature, prefix: ticketPrefix))
    exit(0)

case "--erase-key":
    guard positional.count == 2 else {
        fail("Usage: SEATSTAMP_ADMIN_TOKEN=... license-tool --erase-key <purchaseKey> --endpoint <https URL>")
    }
    let eraseKey = positional[1].trimmingCharacters(in: .whitespacesAndNewlines)
    guard eraseKey.count >= 16, eraseKey.count <= 256 else {
        fail("The purchase key must be 16 to 256 characters long.")
    }
    guard let endpointString = endpointArg?.trimmingCharacters(in: .whitespacesAndNewlines),
          let endpointURL = URL(string: endpointString),
          endpointURL.scheme?.lowercased() == "https",
          endpointURL.host?.isEmpty == false else {
        fail("--erase-key needs --endpoint with an https URL (e.g. https://activate.myapp.com).")
    }
    // The token is read only from the environment, never from argv, and is never printed.
    let adminToken = (ProcessInfo.processInfo.environment["SEATSTAMP_ADMIN_TOKEN"] ?? "")
        .trimmingCharacters(in: .whitespacesAndNewlines)
    guard adminToken.count >= 32 else {
        fail("Set the environment variable SEATSTAMP_ADMIN_TOKEN to the Worker's ADMIN_TOKEN (at least 32 characters).")
    }
    var eraseRequest = URLRequest(url: endpointURL, timeoutInterval: 15)
    eraseRequest.httpMethod = "POST"
    eraseRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
    eraseRequest.httpBody = try? JSONSerialization.data(withJSONObject: [
        "action": "erase", "key": eraseKey, "adminToken": adminToken,
    ])
    let eraseConfig = URLSessionConfiguration.ephemeral
    eraseConfig.timeoutIntervalForRequest = 15
    eraseConfig.timeoutIntervalForResource = 15
    let eraseSession = URLSession(configuration: eraseConfig)
    let eraseDone = DispatchSemaphore(value: 0)
    var eraseStatus = 0
    var eraseData = Data()
    var eraseError: Error?
    eraseSession.dataTask(with: eraseRequest) { data, response, error in
        eraseStatus = (response as? HTTPURLResponse)?.statusCode ?? 0
        eraseData = data ?? Data()
        eraseError = error
        eraseDone.signal()
    }.resume()
    eraseDone.wait()
    if let eraseError {
        fail("Request failed: \(eraseError.localizedDescription)")
    }
    let eraseJSON = (try? JSONSerialization.jsonObject(with: eraseData)) as? [String: Any]
    if eraseStatus == 200 {
        let erased = (eraseJSON?["erased"] as? Bool) ?? false
        print("Erased: \(erased)")
        exit(0)
    }
    let errorField = (eraseJSON?["error"] as? String) ?? "unknown"
    fputs("Error: HTTP \(eraseStatus) \(errorField)\n", stderr)
    exit(1)

case nil:
    fputs(usageText + "\n", stderr)
    exit(2)

default:
    let first = positional.first ?? ""
    if !first.hasPrefix("--") {
        fail("Minting needs an explicit command: --mint <purchaseKeyOrOrdTag> --seat <16-hex>.")
    }
    fail("Unknown option '\(first)'. Run license-tool --help.")
}
