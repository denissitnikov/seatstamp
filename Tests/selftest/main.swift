// selftest: unit and state-machine tests without XCTest (runs on macOS Command Line Tools).
// Run: `swift run selftest`

import AppKit
import Combine
import CryptoKit
import Foundation
import SeatStamp

var passed = 0
var failures = 0

func check(_ cond: @autoclosure () -> Bool, _ name: String, file: StaticString = #file, line: UInt = #line) {
    if cond() {
        passed += 1
        print("  ok   \(name)")
    } else {
        failures += 1
        print("  FAIL \(name)  (\(file):\(line))")
    }
}

func section(_ title: String) {
    print("\n== \(title)")
}

let repoRoot: String = {
    if CommandLine.arguments.count > 1 { return CommandLine.arguments[1] }
    var dir = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    for _ in 0..<6 {
        if FileManager.default.fileExists(atPath: dir.appendingPathComponent("Package.swift").path),
           FileManager.default.fileExists(atPath: dir.appendingPathComponent("fixtures/golden-vectors.json").path) {
            return dir.path
        }
        dir = dir.deletingLastPathComponent()
    }
    return FileManager.default.currentDirectoryPath
}()

// MARK: - 1. VersionCompare

section("VersionCompare")
check(VersionCompare.isVersion("1.1", newerThan: "1.0.9"), "1.1 > 1.0.9")
check(VersionCompare.isVersion("1.10", newerThan: "1.9"), "1.10 > 1.9")
check(VersionCompare.isVersion("2", newerThan: "1.9.9"), "2 > 1.9.9")
check(!VersionCompare.isVersion("1.0", newerThan: "1.0.0"), "1.0 == 1.0.0")
check(VersionCompare.isVersion("1.2-beta", newerThan: "1.1+42"), "pre-release/build suffixes ignored")
check(!VersionCompare.isVersion("1.0", newerThan: "1.0"), "equal is not newer")
check(VersionCompare.formattedDisplayVersion("1.0.0") == "1.0", "display 1.0.0 -> 1.0")
check(VersionCompare.formattedDisplayVersion("1.0.3") == "1.0.3", "display 1.0.3 preserves non-zero patch")
check(VersionCompare.formattedDisplayVersion("1.10.0") == "1.10", "display 1.10.0 -> 1.10")
check(VersionCompare.formattedDisplayVersion("garbage") == "1.0", "display garbage -> 1.0")
check(VersionCompare.formattedDisplayVersion("3") == "3.0", "display 3 -> 3.0")
check(VersionCompare.isValidVersionString("1.2.3-beta.1"), "valid semver accepted")
check(!VersionCompare.isValidVersionString("1.foo"), "non-numeric version segment rejected")

// MARK: - 2. LicenseTicket

section("LicenseTicket")
let signer = Curve25519.Signing.PrivateKey()
let pub = signer.publicKey
let otherPub = Curve25519.Signing.PrivateKey().publicKey
let seat = TrialSeal.seatCode(hardwareUUID: "11111111-2222-3333-4444-555555555555", domain: "com.example.acme.seat.v1|")
check(seat.count == 16 && seat.allSatisfy { $0.isHexDigit }, "seat code is 16 hex chars")
check(seat == TrialSeal.seatCode(hardwareUUID: "11111111-2222-3333-4444-555555555555", domain: "com.example.acme.seat.v1|"), "seat code is deterministic")
check(seat != TrialSeal.seatCode(hardwareUUID: "11111111-2222-3333-4444-555555555555", domain: "com.example.other.seat.v1|"), "domain separates seat codes")

func mint(scheme: String = "ACME-V1", prefix: String = "LK1-", tag: String = "ORD-1", issued: Int64 = 1_760_000_000, seat: String?) -> String {
    let payload = LicenseTicket.canonicalPayload(scheme: scheme, tag: tag, issued: issued, seat: seat)
    let sig = try! signer.signature(for: Data(payload.utf8))
    return LicenseTicket.encode(payload: payload, signature: sig, prefix: prefix)
}

let bound = mint(seat: seat)
let universal = mint(seat: nil)

check({
    if case .success(let p) = LicenseTicket.verify(bound, scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat) {
        return p.boundSeat == seat && p.tag == "ORD-1"
    }
    return false
}(), "seat-bound ticket verifies on its Mac")
check(LicenseTicket.canonicalPayload(scheme: "ACME-V1", tag: "8821", issued: 1_760_000_000, seat: seat).contains("|ORD-8821|"), "canonicalPayload normalizes missing ORD- prefix")
check({
    if case .success(let p) = LicenseTicket.verify(bound, scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat.uppercased()) {
        return p.boundSeat == seat
    }
    return false
}(), "seat match is case-insensitive")
check(LicenseTicket.verify(bound, scheme: "ACME-V1", publicKey: pub, expectedSeatCode: "0000000000000000") == .failure(.seatMismatch), "seat-bound ticket refused on another Mac")
check(LicenseTicket.verify(bound, scheme: "OTHER-V1", publicKey: pub, expectedSeatCode: seat) == .failure(.badPayload), "wrong scheme rejected as badPayload")
check(LicenseTicket.verify(bound, scheme: "ACME-V1", prefix: "CUSTOM-", publicKey: pub, expectedSeatCode: seat) == .failure(.malformed), "wrong prefix rejected as malformed")
check({
    if case .success(let p) = LicenseTicket.verify(universal, scheme: "ACME-V1", publicKey: pub, expectedSeatCode: "anything") {
        return p.boundSeat == nil
    }
    return false
}(), "universal ticket verifies anywhere")
do {
    let trailingPipePayload = "ACME-V1|ORD-1|1760000000|"
    let sig = try! signer.signature(for: Data(trailingPipePayload.utf8))
    let trailingPipeTicket = LicenseTicket.encode(payload: trailingPipePayload, signature: sig)
    check(LicenseTicket.verify(trailingPipeTicket, scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat) == .failure(.badPayload), "4-field payload with empty 4th field is rejected as badPayload")
}
check(LicenseTicket.verify(bound, scheme: "ACME-V1", publicKey: otherPub, expectedSeatCode: seat) == .failure(.badSignature), "wrong public key -> badSignature")
check(LicenseTicket.verify("LK1-notaticket", scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat) == .failure(.malformed), "malformed -> malformed")
check(LicenseTicket.verify(String(bound.dropFirst(4)), scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat) == .failure(.malformed), "missing prefix -> malformed")
check(LicenseTicket.verify(bound + "x", scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat) != .success(LicenseTicket.Payload(tag: "ORD-1", issued: 1_760_000_000, boundSeat: seat)), "tampered signature fails")

do {
    let payload = LicenseTicket.canonicalPayload(scheme: "ACME-V1", tag: "ORD-1", issued: 1_760_000_000, seat: seat)
    let sig = try! signer.signature(for: Data(payload.utf8))
    let forged = LicenseTicket.encode(payload: payload.replacingOccurrences(of: "ORD-1", with: "ORD-2"), signature: sig)
    check(LicenseTicket.verify(forged, scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat) == .failure(.badSignature), "payload tamper -> badSignature")
}

check(LicenseTicket.verify(mint(issued: 1_000, seat: seat), scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat) == .failure(.badPayload), "issued below floor -> badPayload")
check(LicenseTicket.verify(mint(issued: 9_999_999_999, seat: seat), scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat) == .failure(.badPayload), "issued above ceiling -> badPayload")
check(LicenseTicket.verify(bound, scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat, revokedBefore: 1_760_000_001) == .failure(.revoked), "seat-bound issued before watermark -> revoked")
check({
    if case .success = LicenseTicket.verify(bound, scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat, revokedBefore: 1_760_000_000) { return true }
    return false
}(), "issued == watermark is accepted")
check({
    if case .success = LicenseTicket.verify(mint(issued: 1_760_000_500, seat: seat), scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat, revokedBefore: 1_760_000_001) { return true }
    return false
}(), "fresh ticket after watermark is accepted")
check({
    if case .success = LicenseTicket.verify(universal, scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat, revokedBefore: 9_000_000_000) { return true }
    return false
}(), "universal ticket ignores watermark")

// Order tag derivation + offline revokedOrderTags checks
let derivedOrd = LicenseTicket.deriveOrderTag(forPurchaseKey: "  cs_live_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8 \n")
check(derivedOrd.hasPrefix("ORD-") && derivedOrd.count == 20, "deriveOrderTag returns ORD- + 16 uppercase hex chars")
check(derivedOrd == LicenseTicket.deriveOrderTag(forPurchaseKey: "cs_live_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"), "deriveOrderTag trims whitespace deterministically")
check(derivedOrd != LicenseTicket.deriveOrderTag(forPurchaseKey: "cs_live_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8", domain: "other-domain|"), "deriveOrderTag respects domain separation")
check(LicenseTicket.canonicalOrderTag("  a1b2c3d4 ") == "ORD-A1B2C3D4", "canonicalOrderTag normalizes bare hex")
check(LicenseTicket.canonicalOrderTag("ord-a1b2c3d4e5f60718") == "ORD-A1B2C3D4E5F60718", "canonicalOrderTag normalizes lowercase ord- prefix")
check(LicenseTicket.canonicalOrderTag("   ") == nil && LicenseTicket.canonicalOrderTag("ORD-") == nil, "canonicalOrderTag rejects empty tag")

check(LicenseTicket.verify(bound, scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat, revokedOrderTags: ["ORD-1"]) == .failure(.revoked), "seat-bound ticket in revokedOrderTags -> .revoked")
check(LicenseTicket.verify(bound, scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat, revokedOrderTags: ["  ord-1 "]) == .failure(.revoked), "revokedOrderTags matches case-insensitively with whitespace")
check(LicenseTicket.verify(bound, scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat, revokedOrderTags: ["1"]) == .failure(.revoked), "revokedOrderTags matches bare tag without ORD- prefix")
check(LicenseTicket.verify(universal, scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat, revokedOrderTags: ["ord-1"]) == .failure(.revoked), "universal ticket in revokedOrderTags -> .revoked")
check({
    if case .success = LicenseTicket.verify(bound, scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat, revokedOrderTags: ["ORD-2", ""]) { return true }
    return false
}(), "non-matching revokedOrderTags allows valid ticket")
do {
    let bound16 = mint(tag: "ORD-7A1F5F1C321BD5D5", seat: seat)
    check({
        if case .success(let p) = LicenseTicket.verify(bound16, scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat, revokedOrderTags: ["ORD-1"]) {
            return p.tag == "ORD-7A1F5F1C321BD5D5"
        }
        return false
    }(), "16-hex ORD- ticket verifies alongside 8-hex tickets")
    check(LicenseTicket.verify(bound16, scheme: "ACME-V1", publicKey: pub, expectedSeatCode: seat, revokedOrderTags: ["7a1f5f1c321bd5d5"]) == .failure(.revoked), "16-hex ORD- ticket revoked by bare lowercase hex")
}

check(LicenseTicket.base64URLDecode("YQ") == Data("a".utf8), "base64url pad 2")
check(LicenseTicket.base64URLDecode("YWI") == Data("ab".utf8), "base64url pad 1")
check(LicenseTicket.base64URLDecode("YWJj") == Data("abc".utf8), "base64url pad 0")

// MARK: - 3. TrialSeal

section("TrialSeal")
let sealKey = TrialSeal.hmacKey(hardwareUUID: "11111111-2222-3333-4444-555555555555", domain: "com.example.acme.trial-seal.v1|")
let otherSealKey = TrialSeal.hmacKey(hardwareUUID: "99999999-2222-3333-4444-555555555555", domain: "com.example.acme.trial-seal.v1|")
let sealV2 = TrialSeal.make(first: 1_760_000_000, high: 1_760_100_000, revokedBefore: 1_760_050_000, key: sealKey)
check(TrialSeal.verify(sealV2, key: sealKey) == TrialSeal.Parsed(first: 1_760_000_000, high: 1_760_100_000, revokedBefore: 1_760_050_000), "v2 round-trip")
check(TrialSeal.verify(sealV2, key: otherSealKey) == nil, "v2 wrong hardware key rejected")
check(TrialSeal.verify(sealV2.replacingOccurrences(of: "1760000000", with: "1770000000"), key: sealKey) == nil, "v2 tamper rejected")
do {
    let msg = "TV1|1760000000|1760100000"
    let mac = HMAC<SHA256>.authenticationCode(for: Data(msg.utf8), using: sealKey)
    let v1 = "\(msg)|\(LicenseTicket.base64URLEncode(Data(mac)))"
    check(TrialSeal.verify(v1, key: sealKey) == TrialSeal.Parsed(first: 1_760_000_000, high: 1_760_100_000, revokedBefore: 0), "TV1 seal without a revokedBefore field is accepted")
}
check(TrialSeal.verify("TV3|1|2|3|4|xx", key: sealKey) == nil, "unknown seal version rejected")

// MARK: - 4. Shared Golden Vectors (Swift <-> Node/WebCrypto)

section("Golden Vectors (fixtures/golden-vectors.json)")
do {
    let fixtureURL = URL(fileURLWithPath: repoRoot).appendingPathComponent("fixtures/golden-vectors.json")
    let raw = try Data(contentsOf: fixtureURL)
    let root = try JSONSerialization.jsonObject(with: raw) as! [String: Any]

    let licObj = root["licenseTestKey"] as! [String: String]
    let updObj = root["updateTestKey"] as! [String: String]
    let hwObj = root["hardwareDerivation"] as! [String: Any]
    let tObj = root["ticket"] as! [String: Any]
    let mObj = root["manifest"] as! [String: Any]

    let licPub = try Curve25519.Signing.PublicKey(rawRepresentation: Data(base64Encoded: licObj["publicKeyBase64"]!)!)
    let updPub = try Curve25519.Signing.PublicKey(rawRepresentation: Data(base64Encoded: updObj["publicKeyBase64"]!)!)

    let derivedSeat = TrialSeal.seatCode(
        hardwareUUID: hwObj["hardwareUUID"] as! String,
        domain: hwObj["seatDomain"] as! String
    )
    check(derivedSeat == (hwObj["expectedSeatCode"] as! String), "golden seatCode matches Node SHA-256")

    let derivedSealKey = TrialSeal.hmacKey(
        hardwareUUID: hwObj["hardwareUUID"] as! String,
        domain: hwObj["trialSealDomain"] as! String
    )
    let derivedSeal = TrialSeal.make(
        first: Int64(hwObj["first"] as! Int),
        high: Int64(hwObj["high"] as! Int),
        revokedBefore: Int64(hwObj["revokedBefore"] as! Int),
        key: derivedSealKey
    )
    check(derivedSeal == (hwObj["expectedSeal"] as! String), "golden TrialSeal matches Node HMAC-SHA256")

    let verifyTicket = LicenseTicket.verify(
        tObj["encoded"] as! String,
        scheme: tObj["scheme"] as! String,
        prefix: tObj["prefix"] as! String,
        publicKey: licPub,
        expectedSeatCode: derivedSeat
    )
    check(
        verifyTicket == .success(LicenseTicket.Payload(
            tag: tObj["tag"] as! String,
            issued: Int64(tObj["issued"] as! Int),
            boundSeat: tObj["seat"] as? String
        )),
        "golden LK1- ticket minted by WebCrypto verifies in CryptoKit"
    )

    check(UpdateManifest.derivedScheme(fromLicenseScheme: "ACME-V1") == "ACME-UPDATE-V1", "derived update scheme strips -V1 cleanly")

    let canon = UpdateManifest.canonicalSigningData(
        scheme: mObj["scheme"] as! String,
        version: mObj["version"] as! String,
        url: mObj["url"] as! String,
        summary: mObj["summary"] as! String,
        notes: mObj["notes"] as! [String],
        summaryI18n: mObj["summaryI18n"] as! [String: String],
        notesI18n: mObj["notesI18n"] as! [String: [String]]
    )
    check(String(data: canon, encoding: .utf8) == (mObj["canonicalUTF8"] as! String), "golden manifest canonical bytes match")
    let fields = UpdateManifest.Fields(
        version: mObj["version"] as! String,
        url: mObj["url"] as! String,
        summary: mObj["summary"] as! String,
        notes: mObj["notes"] as! [String],
        summaryI18n: mObj["summaryI18n"] as! [String: String],
        notesI18n: mObj["notesI18n"] as! [String: [String]],
        signature: (mObj["signatureBase64URL"] as! String)
    )
    check(UpdateManifest.verify(fields, scheme: mObj["scheme"] as! String, publicKey: updPub), "golden manifest signature verifies")
    check(!UpdateManifest.verify(fields, scheme: "WRONG-UPDATE-V1", publicKey: updPub), "manifest wrong scheme fails")
    check(UpdateManifest.fields(from: ["version": "1.0", "url": "https://x", "summary": "s", "notes": "oops"]) == .failure(.badNotes), "typed notes check")

    // Golden orderTagDerivation vector (Swift <-> Worker parity)
    let otdObj = root["orderTagDerivation"] as! [String: String]
    let otdInput = Data((otdObj["domain"]! + otdObj["purchaseKey"]!).utf8)
    let otdHash = SHA256.hash(data: otdInput).map { String(format: "%02x", $0) }.joined()
    check(otdHash == otdObj["expectedKeyHash"]!, "golden orderTagDerivation SHA-256 matches")
    let otdTag = LicenseTicket.deriveOrderTag(
        forPurchaseKey: "  \(otdObj["purchaseKey"]!)\n",
        domain: otdObj["domain"]!
    )
    check(otdTag == otdObj["expectedOrderTag"]!, "golden deriveOrderTag matches Node Worker ORD-<16-hex>")

    // Golden manifestWithRevokedTags vector + backward-compatibility & tamper checks
    let mrObj = root["manifestWithRevokedTags"] as! [String: Any]
    let mrCanon = UpdateManifest.canonicalSigningData(
        scheme: mrObj["scheme"] as! String,
        version: mrObj["version"] as! String,
        url: mrObj["url"] as! String,
        summary: mrObj["summary"] as! String,
        notes: mrObj["notes"] as! [String],
        summaryI18n: mrObj["summaryI18n"] as! [String: String],
        notesI18n: mrObj["notesI18n"] as! [String: [String]],
        revokedTags: ["42a9f01c", "ORD-0011223344556677", "ord-42A9F01C"]
    )
    check(String(data: mrCanon, encoding: .utf8) == (mrObj["canonicalUTF8"] as! String), "golden manifestWithRevokedTags canonical bytes match (sorted + deduplicated)")
    let mrParsed = UpdateManifest.fields(from: [
        "version": mrObj["version"] as! String,
        "url": mrObj["url"] as! String,
        "summary": mrObj["summary"] as! String,
        "notes": mrObj["notes"] as! [String],
        "summary_i18n": mrObj["summaryI18n"] as! [String: String],
        "notes_i18n": mrObj["notesI18n"] as! [String: [String]],
        "revoked_tags": ["ord-42a9f01c", "0011223344556677", "ORD-42A9F01C"],
        "sig": mrObj["signatureBase64URL"] as! String
    ])
    if case .success(let mrFields) = mrParsed {
        check(mrFields.revokedTags == ["ORD-0011223344556677", "ORD-42A9F01C"], "fields(from:) normalizes, deduplicates, and sorts revoked_tags")
        check(UpdateManifest.verify(mrFields, scheme: mrObj["scheme"] as! String, publicKey: updPub), "golden manifestWithRevokedTags signature verifies")
        let strippedFields = UpdateManifest.Fields(
            version: mrFields.version,
            url: mrFields.url,
            summary: mrFields.summary,
            notes: mrFields.notes,
            summaryI18n: mrFields.summaryI18n,
            notesI18n: mrFields.notesI18n,
            revokedTags: [],
            signature: mrFields.signature
        )
        check(!UpdateManifest.verify(strippedFields, scheme: mrObj["scheme"] as! String, publicKey: updPub), "stripping revoked_tags invalidates manifest signature")
        let tamperedFields = UpdateManifest.Fields(
            version: mrFields.version,
            url: mrFields.url,
            summary: mrFields.summary,
            notes: mrFields.notes,
            summaryI18n: mrFields.summaryI18n,
            notesI18n: mrFields.notesI18n,
            revokedTags: ["ORD-0011223344556677"],
            signature: mrFields.signature
        )
        check(!UpdateManifest.verify(tamperedFields, scheme: mrObj["scheme"] as! String, publicKey: updPub), "removing one tag from revoked_tags invalidates manifest signature")
    } else {
        check(false, "manifestWithRevokedTags failed to parse: \(mrParsed)")
    }
    check(UpdateManifest.fields(from: ["version": "1.0", "url": "https://x", "summary": "s", "revoked_tags": "ORD-1"]) == .failure(.badRevokedTags), "non-array revoked_tags rejected as badRevokedTags")
    check(UpdateManifest.fields(from: ["version": "1.0", "url": "https://x", "summary": "s", "revoked_tags": [123]]) == .failure(.badRevokedTags), "non-string element in revoked_tags rejected as badRevokedTags")
    check(UpdateManifest.fields(from: ["version": "1.0", "url": "https://x", "summary": "s", "revoked_tags": ["   "]]) == .failure(.badRevokedTags), "empty element in revoked_tags rejected as badRevokedTags")
    check(UpdateManifest.fields(from: ["version": "1.0", "url": "https://x", "summary": "s", "revoked_tags": ["ORD-"]]) == .failure(.badRevokedTags), "bare ORD- element in revoked_tags rejected as badRevokedTags")

    // Golden manifestWithArtifact vector: signed sha256 + size of the download
    let maObj = root["manifestWithArtifact"] as! [String: Any]
    let maSha = maObj["sha256"] as! String
    let maSize = Int64(maObj["size"] as! Int)
    let maCanon = UpdateManifest.canonicalSigningData(
        scheme: maObj["scheme"] as! String,
        version: maObj["version"] as! String,
        url: maObj["url"] as! String,
        summary: maObj["summary"] as! String,
        notes: maObj["notes"] as! [String],
        summaryI18n: maObj["summaryI18n"] as! [String: String],
        notesI18n: maObj["notesI18n"] as! [String: [String]],
        revokedTags: maObj["revokedTags"] as! [String],
        sha256: maSha,
        size: maSize
    )
    check(String(data: maCanon, encoding: .utf8) == (maObj["canonicalUTF8"] as! String), "golden manifestWithArtifact canonical bytes match")
    func artifactFields(sha256: String?, size: Int64?) -> UpdateManifest.Fields {
        UpdateManifest.Fields(
            version: maObj["version"] as! String,
            url: maObj["url"] as! String,
            summary: maObj["summary"] as! String,
            notes: maObj["notes"] as! [String],
            summaryI18n: maObj["summaryI18n"] as! [String: String],
            notesI18n: maObj["notesI18n"] as! [String: [String]],
            revokedTags: maObj["revokedTags"] as! [String],
            sha256: sha256,
            size: size,
            signature: (maObj["signatureBase64URL"] as! String)
        )
    }
    let maScheme = maObj["scheme"] as! String
    check(UpdateManifest.verify(artifactFields(sha256: maSha, size: maSize), scheme: maScheme, publicKey: updPub), "golden manifestWithArtifact signature verifies")
    check(UpdateManifest.verify(artifactFields(sha256: maSha.uppercased(), size: maSize), scheme: maScheme, publicKey: updPub), "upper-case sha256 is signed as lower case")
    let flippedSha = (maSha.first == "0" ? "1" : "0") + maSha.dropFirst()
    check(!UpdateManifest.verify(artifactFields(sha256: flippedSha, size: maSize), scheme: maScheme, publicKey: updPub), "changing one hex digit of sha256 invalidates manifest signature")
    check(!UpdateManifest.verify(artifactFields(sha256: maSha, size: maSize + 1), scheme: maScheme, publicKey: updPub), "changing size invalidates manifest signature")
    check(!UpdateManifest.verify(artifactFields(sha256: nil, size: nil), scheme: maScheme, publicKey: updPub), "dropping sha256 and size invalidates manifest signature")
    check(UpdateManifest.verify(fields, scheme: mObj["scheme"] as! String, publicKey: updPub), "golden manifest still verifies next to the artifact vector")

    // fields(from:) validation of sha256 and size
    let baseManifest: [String: Any] = ["version": "1.0", "url": "https://x", "summary": "s"]
    func withExtra(_ extra: [String: Any]) -> [String: Any] { baseManifest.merging(extra) { _, new in new } }
    if case .success(let upperFields) = UpdateManifest.fields(from: withExtra(["sha256": maSha.uppercased(), "size": 34])) {
        check(upperFields.sha256 == maSha && upperFields.size == 34, "fields(from:) stores an upper-case sha256 in lower case and reads size")
    } else {
        check(false, "fields(from:) rejected a valid upper-case sha256")
    }
    check(UpdateManifest.fields(from: withExtra(["sha256": String(maSha.dropLast())])) == .failure(.badSha256), "63 hex characters rejected as badSha256")
    check(UpdateManifest.fields(from: withExtra(["sha256": maSha, "size": "34"])) == .failure(.badSize), "string size rejected as badSize")
    check(UpdateManifest.fields(from: withExtra(["sha256": maSha, "size": 1.5])) == .failure(.badSize), "fractional size rejected as badSize")
    check(UpdateManifest.fields(from: withExtra(["sha256": maSha, "size": 0])) == .failure(.badSize), "zero size rejected as badSize")
    check(UpdateManifest.fields(from: withExtra(["sha256": maSha, "size": true])) == .failure(.badSize), "boolean size rejected as badSize")
    check(UpdateManifest.fields(from: withExtra(["size": 34])) == .failure(.badSize), "size without sha256 rejected as badSize")

    // Golden manifestWithSequence vector: signed manifest_seq after the artifact lines
    let msObj = root["manifestWithSequence"] as! [String: Any]
    let msSeq = Int64(msObj["manifestSeq"] as! Int)
    let msCanon = UpdateManifest.canonicalSigningData(
        scheme: msObj["scheme"] as! String,
        version: msObj["version"] as! String,
        url: msObj["url"] as! String,
        summary: msObj["summary"] as! String,
        notes: msObj["notes"] as! [String],
        summaryI18n: msObj["summaryI18n"] as! [String: String],
        notesI18n: msObj["notesI18n"] as! [String: [String]],
        revokedTags: msObj["revokedTags"] as! [String],
        sha256: msObj["sha256"] as? String,
        size: Int64(msObj["size"] as! Int),
        manifestSeq: msSeq
    )
    check(String(data: msCanon, encoding: .utf8) == (msObj["canonicalUTF8"] as! String), "golden manifestWithSequence canonical bytes match")
    let msParsed = UpdateManifest.fields(from: [
        "version": msObj["version"] as! String,
        "url": msObj["url"] as! String,
        "summary": msObj["summary"] as! String,
        "notes": msObj["notes"] as! [String],
        "sha256": msObj["sha256"] as! String,
        "size": msObj["size"] as! Int,
        "manifest_seq": msObj["manifestSeq"] as! Int,
        "sig": msObj["signatureBase64URL"] as! String
    ])
    if case .success(let msFields) = msParsed {
        check(msFields.manifestSeq == msSeq, "fields(from:) reads manifest_seq")
        check(UpdateManifest.verify(msFields, scheme: msObj["scheme"] as! String, publicKey: updPub), "golden manifestWithSequence signature verifies")
    } else {
        check(false, "manifestWithSequence failed to parse: \(msParsed)")
    }
    check(UpdateManifest.fields(from: withExtra(["manifest_seq": "10"])) == .failure(.badManifestSeq), "string manifest_seq rejected as badManifestSeq")
    check(UpdateManifest.fields(from: withExtra(["manifest_seq": 0])) == .failure(.badManifestSeq), "zero manifest_seq rejected as badManifestSeq")
    check(UpdateManifest.fields(from: withExtra(["manifest_seq": false])) == .failure(.badManifestSeq), "boolean manifest_seq rejected as badManifestSeq")
} catch {
    check(false, "golden-vectors.json failed to parse: \(error)")
}

// MARK: - 5. SeatStampManager State Machine

section("SeatStampManager Manager")
do {
    let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent("seatstamp-selftest-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: tmpDir) }
    let suiteName = "com.example.selftest.\(UUID().uuidString)"
    let suite = UserDefaults(suiteName: suiteName)!
    defer { suite.removePersistentDomain(forName: suiteName) }

    let anchor1 = tmpDir.appendingPathComponent("appSupport/.vault_seal")
    let anchor2 = tmpDir.appendingPathComponent("caches/.vault_seal")
    let vaultFile = tmpDir.appendingPathComponent("appSupport/.license_vault")

    var fakeNow: Int64 = 1_760_000_000
    let fakeHW = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    let licKey = Curve25519.Signing.PrivateKey()
    let updKey = Curve25519.Signing.PrivateKey()
    let licPubB64 = licKey.publicKey.rawRepresentation.base64EncodedString()
    let updPubB64 = updKey.publicKey.rawRepresentation.base64EncodedString()

    func makeKit(revokedOrderTags: Set<String> = []) -> SeatStampManager {
        SeatStampManager(
            scheme: "TESTAPP-V1",
            licensePublicKeyBase64: licPubB64,
            updatePublicKeyBase64: updPubB64,
            trialLengthDays: 30,
            maxSeats: 2,
            bundleID: "com.example.testapp",
            revokedOrderTags: revokedOrderTags,
            testingOverrides: .init(
                defaults: suite,
                fileAnchorURLs: [anchor1, anchor2],
                vaultFileURL: vaultFile,
                hardwareUUID: fakeHW,
                useKeychain: false,
                healSynchronously: true,
                now: { Date(timeIntervalSince1970: TimeInterval(fakeNow)) }
            )
        )
    }

    let kit1 = makeKit()
    check(!kit1.isLicensed, "fresh install starts unlicensed")
    check(kit1.trialDaysRemaining == 30, "fresh install has 30 trial days")
    check(kit1.verifyGateAccess(), "gate open during active trial")
    check(FileManager.default.fileExists(atPath: anchor1.path) && FileManager.default.fileExists(atPath: anchor2.path), "both file anchors created")

    // Advance 10 days, bump monotonic clock, then delete UserDefaults + anchor1 -> anchor2 preserves elapsed trial
    fakeNow += 10 * 86_400
    kit1.refreshMonotonicClockIfNeeded()
    kit1.refreshMonotonicClockIfNeeded()
    suite.removeObject(forKey: "seatStampTrialSealV2")
    try? FileManager.default.removeItem(at: anchor1)

    let kit2 = makeKit()
    check(kit2.trialDaysRemaining == 20, "surviving file anchor prevents trial reset (20 days left)")
    check(FileManager.default.fileExists(atPath: anchor1.path), "deleted file anchor self-healed")

    // Roll clock backwards by 9 days -> highWaterEpoch prevents gaining trial days back
    kit2.refreshMonotonicClockIfNeeded()
    let savedNow = fakeNow
    fakeNow -= 9 * 86_400
    check(kit2.trialDaysRemaining == 20, "clock rollback cannot extend trial")
    fakeNow = savedNow

    // Future transient clock jump (+365 days) during one launch -> capped to +7 days on next normal launch
    fakeNow += 365 * 86_400
    let jumped = makeKit()
    jumped.refreshMonotonicClockIfNeeded()
    fakeNow = savedNow
    let recovered = makeKit()
    check(recovered.trialDaysRemaining >= 13 && !recovered.isTrialExpired, "+7-day skew cap prevents wrong future clock from bricking trial")

    // Expire trial (advance past day 30)
    fakeNow = 1_760_000_000 + 31 * 86_400
    let expiredKit = makeKit()
    check(expiredKit.isTrialExpired && !expiredKit.verifyGateAccess(), "expired trial closes gate")

    // Mint a seat-bound ticket for this Mac (even with issued slightly ahead of fakeNow) and activate
    let payload1 = LicenseTicket.canonicalPayload(scheme: "TESTAPP-V1", tag: "ORD-9001", issued: fakeNow + 2, seat: expiredKit.deviceSeatCode)
    let sig1 = try licKey.signature(for: Data(payload1.utf8))
    let seatTicket1 = LicenseTicket.encode(payload: payload1, signature: sig1)

    check(expiredKit.activateOfflineTicket(seatTicket1, parentSeatKey: "cs_live_parentKeyExample000000000001", seatsUsed: 1, maxSeats: 2), "seat-bound ticket activates offline")
    check(expiredKit.isLicensed && expiredKit.verifyGateAccess(), "gate opens once licensed")
    check(expiredKit.orderTag == "ORD-9001", "orderTag populated from ticket")
    check(expiredKit.maskedKey == "••••-000001", "maskedKey displays parent key suffix")
    check(expiredKit.shareableLicenseKey == "cs_live_parentKeyExample000000000001", "shareableLicenseKey returns parent purchase key")

    // Migration Assistant simulation: copy .license_vault to a new Mac (separate anchors/defaults, new hardwareUUID)
    let mac2Vault = tmpDir.appendingPathComponent("mac2/.license_vault")
    try FileManager.default.createDirectory(at: mac2Vault.deletingLastPathComponent(), withIntermediateDirectories: true)
    try FileManager.default.copyItem(at: vaultFile, to: mac2Vault)
    let migratedMac = SeatStampManager(
        scheme: "TESTAPP-V1",
        licensePublicKeyBase64: licPubB64,
        updatePublicKeyBase64: updPubB64,
        trialLengthDays: 30,
        maxSeats: 2,
        bundleID: "com.example.testapp",
        testingOverrides: .init(
            defaults: suite,
            fileAnchorURLs: [tmpDir.appendingPathComponent("mac2/.vault_seal")],
            vaultFileURL: mac2Vault,
            hardwareUUID: "99999999-bbbb-cccc-dddd-eeeeeeeeeeee",
            useKeychain: false,
            healSynchronously: false,
            now: { Date(timeIntervalSince1970: TimeInterval(fakeNow)) }
        )
    )
    check(!migratedMac.isLicensed, "migrated vault does not unlock new hardware UUID without re-activating")
    check(migratedMac.shareableLicenseKey == "cs_live_parentKeyExample000000000001", "migrated vault preserves parentKey for 1-click Seat #2 activation")

    // Relaunch on original Mac preserves license
    let relaunched = makeKit()
    check(relaunched.isLicensed && relaunched.verifyGateAccess(), "license persists across relaunch")

    // Deactivate in the SAME second (even when ticket.issued was fakeNow + 2) -> must reject re-pasting seatTicket1
    relaunched.deactivate()
    check(!relaunched.isLicensed && !relaunched.verifyGateAccess(), "deactivate immediately locks expired Mac")
    check(!relaunched.activateOfflineTicket(seatTicket1), "re-pasting deactivated seat ticket fails even in same second / clock skew")
    check(!relaunched.activateOfflineTicket(seatTicket1, parentSeatKey: "cs_live_parentKeyExample000000000001"), "deactivated seat ticket is rejected even when it arrives with a parent key (server response)")

    // Server-issued fresh ticket (issued > seatTicket1.issued) activates cleanly while keeping seatTicket1 revoked
    fakeNow += 10
    let payload2 = LicenseTicket.canonicalPayload(scheme: "TESTAPP-V1", tag: "ORD-9001", issued: fakeNow, seat: relaunched.deviceSeatCode)
    let sig2 = try licKey.signature(for: Data(payload2.utf8))
    let seatTicket2 = LicenseTicket.encode(payload: payload2, signature: sig2)
    check(relaunched.activateOfflineTicket(seatTicket2, parentSeatKey: "cs_live_parentKeyExample000000000001", seatsUsed: 1, maxSeats: 2, serverRevokedBefore: fakeNow - 5), "server-issued fresh ticket activates")
    let relaunchedAfterServerTicket = makeKit()
    check(!relaunchedAfterServerTicket.activateOfflineTicket(seatTicket1, parentSeatKey: "cs_live_parentKeyExample000000000001"), "sealed watermark is not lowered by a server ticket: old ticket stays rejected after relaunch")
    check(!relaunched.activateOfflineTicket(seatTicket1), "old pre-deactivation ticket remains rejected after server re-activation")

    // UpdateChecker ingestion test
    let updater = UpdateChecker(
        kit: relaunched,
        manifestURL: URL(string: "https://testapp.example/version.json")!,
        trustedDownloadHosts: ["testapp.example"],
        currentVersion: "1.0.0",
        defaults: suite,
        languageCodeProvider: { "ja" }
    )
    let mUrl = "https://testapp.example/download/TestApp-1.2.1.dmg"
    let mCanon = UpdateManifest.canonicalSigningData(
        scheme: "TESTAPP-UPDATE-V1",
        version: "1.2.1",
        url: mUrl,
        summary: "Faster startup",
        notes: ["Note 1"],
        summaryI18n: ["ja": "高速化"],
        notesI18n: [:]
    )
    let mSig = LicenseTicket.base64URLEncode(try updKey.signature(for: mCanon))
    let manifestJSON: [String: Any] = [
        "version": "1.2.1",
        "url": mUrl,
        "summary": "Faster startup",
        "summary_i18n": ["ja": "高速化"],
        "notes": ["Note 1"],
        "sig": mSig
    ]
    let mData = try JSONSerialization.data(withJSONObject: manifestJSON)
    check(updater.ingest(data: mData), "signed manifest ingested")
    check(updater.availableUpdate?.version == "1.2.1" && updater.availableUpdate?.rawVersion == "1.2.1", "patch version preserved in display version")
    check(updater.availableUpdate?.summary == "高速化", "localized summary selected")

    // Path traversal (`/download/../other/TestApp.dmg`) must be rejected even on trusted host
    let travUrl = "https://testapp.example/download/../other/TestApp-1.3.dmg"
    let travCanon = UpdateManifest.canonicalSigningData(
        scheme: "TESTAPP-UPDATE-V1",
        version: "1.3.0",
        url: travUrl,
        summary: "Traversal",
        notes: [],
        summaryI18n: [:],
        notesI18n: [:]
    )
    let travSig = LicenseTicket.base64URLEncode(try updKey.signature(for: travCanon))
    let travData = try JSONSerialization.data(withJSONObject: [
        "version": "1.3.0", "url": travUrl, "summary": "Traversal", "sig": travSig
    ])
    check(!updater.ingest(data: travData), "path traversal in manifest download URL rejected")

    // Untrusted download host must be rejected even if signed
    let evilUrl = "https://evil.example/download/TestApp-1.3.dmg"
    let evilCanon = UpdateManifest.canonicalSigningData(
        scheme: "TESTAPP-UPDATE-V1",
        version: "1.3.0",
        url: evilUrl,
        summary: "Evil",
        notes: [],
        summaryI18n: [:],
        notesI18n: [:]
    )
    let evilSig = LicenseTicket.base64URLEncode(try updKey.signature(for: evilCanon))
    let evilData = try JSONSerialization.data(withJSONObject: [
        "version": "1.3.0", "url": evilUrl, "summary": "Evil", "sig": evilSig
    ])
    check(!updater.ingest(data: evilData), "untrusted download host rejected even with valid signature")

    updater.dismissCurrentUpdate()
    check(updater.availableUpdate == nil, "dismiss clears availableUpdate")
    check(updater.ingest(data: mData) && updater.availableUpdate == nil, "dismissed version stays snoozed")

    // Offline revokedOrderTags on SeatStampManager.init + re-purchase on same Mac
    let seatBeforeRevoke = relaunched.deviceSeatCode
    let revokedBootKit = makeKit(revokedOrderTags: ["9001"])
    check(!revokedBootKit.isLicensed && !revokedBootKit.verifyGateAccess(), "stored ticket whose tag is in revokedOrderTags boots unlicensed")
    check(revokedBootKit.deviceSeatCode == seatBeforeRevoke, "revoking order tag does not alter deviceSeatCode")
    check(!revokedBootKit.activateOfflineTicket(seatTicket2), "re-pasting revoked seat-bound ticket rejected by SeatStampManager")
    let univRevokedPayload = LicenseTicket.canonicalPayload(scheme: "TESTAPP-V1", tag: "ORD-9001", issued: fakeNow + 5, seat: nil)
    let univRevokedTicket = LicenseTicket.encode(payload: univRevokedPayload, signature: try licKey.signature(for: Data(univRevokedPayload.utf8)))
    check(!revokedBootKit.activateOfflineTicket(univRevokedTicket), "universal ticket with revoked tag rejected by SeatStampManager")

    // Re-purchasing a fresh order (ORD-NEW16HEX00000001) on the same Mac succeeds cleanly
    fakeNow += 20
    let newOrdPayload = LicenseTicket.canonicalPayload(scheme: "TESTAPP-V1", tag: "ORD-NEW16HEX00000001", issued: fakeNow, seat: revokedBootKit.deviceSeatCode)
    let newOrdTicket = LicenseTicket.encode(payload: newOrdPayload, signature: try licKey.signature(for: Data(newOrdPayload.utf8)))
    check(revokedBootKit.activateOfflineTicket(newOrdTicket, parentSeatKey: "cs_live_repurchasedOrderKey0000000002", seatsUsed: 1, maxSeats: 2), "re-purchased order ticket activates on same Mac after ORD-9001 revocation")
    check(revokedBootKit.isLicensed && revokedBootKit.verifyGateAccess() && revokedBootKit.orderTag == "ORD-NEW16HEX00000001", "re-purchased order unlocks gate with new orderTag")

    // UpdateChecker .suppressUpdates (default): hides update for revoked orderTag while keeping installed binary licensed
    let suppressUpdater = UpdateChecker(
        kit: revokedBootKit,
        manifestURL: URL(string: "https://testapp.example/version.json")!,
        trustedDownloadHosts: ["testapp.example"],
        currentVersion: "1.0.0",
        defaults: suite
    )
    let v14Url = "https://testapp.example/download/TestApp-1.4.0.dmg"
    func makeSignedManifestData(version: String, url: String, revokedTags: [String]) throws -> Data {
        let canon = UpdateManifest.canonicalSigningData(
            scheme: "TESTAPP-UPDATE-V1",
            version: version,
            url: url,
            summary: "Update \(version)",
            notes: ["Fixes"],
            summaryI18n: [:],
            notesI18n: [:],
            revokedTags: revokedTags
        )
        let sig = LicenseTicket.base64URLEncode(try updKey.signature(for: canon))
        var obj: [String: Any] = [
            "version": version,
            "url": url,
            "summary": "Update \(version)",
            "notes": ["Fixes"],
            "sig": sig
        ]
        if !revokedTags.isEmpty {
            obj["revoked_tags"] = revokedTags
        }
        return try JSONSerialization.data(withJSONObject: obj)
    }

    let otherRevokedManifest = try makeSignedManifestData(version: "1.4.0", url: v14Url, revokedTags: ["ORD-SOMEONEELSE00001"])
    check(suppressUpdater.ingest(data: otherRevokedManifest) && suppressUpdater.availableUpdate?.version == "1.4", "manifest revoking unrelated tag still surfaces update to valid buyer")

    let selfRevokedManifest = try makeSignedManifestData(version: "1.4.0", url: v14Url, revokedTags: ["new16hex00000001"])
    check(suppressUpdater.ingest(data: selfRevokedManifest), "suppressUpdates ingests signed manifest with matching revoked_tags")
    check(suppressUpdater.availableUpdate == nil, "suppressUpdates hides update banner when kit.orderTag is in revoked_tags")
    check(revokedBootKit.isLicensed && revokedBootKit.verifyGateAccess(), "suppressUpdates leaves current installed binary licensed")

    // UpdateChecker .revokeLocalLicense: deactivates local license AND persists revoked tag in vault across offline relaunches
    let hardRevokeUpdater = UpdateChecker(
        kit: revokedBootKit,
        manifestURL: URL(string: "https://testapp.example/version.json")!,
        trustedDownloadHosts: ["testapp.example"],
        revocationBehavior: .revokeLocalLicense,
        currentVersion: "1.0.0",
        defaults: suite
    )
    check(hardRevokeUpdater.ingest(data: selfRevokedManifest), "revokeLocalLicense ingests signed manifest")
    check(!revokedBootKit.isLicensed && !revokedBootKit.verifyGateAccess() && hardRevokeUpdater.availableUpdate == nil, "revokeLocalLicense immediately revokes local license and clears update")
    check(revokedBootKit.revokedOrderTags.contains("ORD-NEW16HEX00000001"), "revokeLocalLicense records revoked tag in SeatStampManager")

    // Offline relaunch (new SeatStampManager with empty static revokedOrderTags) still remembers the vault-persisted revoked tag
    let offlineRelaunchKit = makeKit()
    check(!offlineRelaunchKit.isLicensed && offlineRelaunchKit.revokedOrderTags.contains("ORD-NEW16HEX00000001"), "persisted revoked tag in .license_vault survives offline relaunch")
    check(!offlineRelaunchKit.activateOfflineTicket(newOrdTicket), "re-pasting ticket for manifest-revoked order fails offline after relaunch")

    // Re-purchasing a 3rd order on the same Mac still works cleanly
    fakeNow += 20
    let thirdOrdPayload = LicenseTicket.canonicalPayload(scheme: "TESTAPP-V1", tag: "ORD-REPURCHASE000002", issued: fakeNow, seat: offlineRelaunchKit.deviceSeatCode)
    let thirdOrdTicket = LicenseTicket.encode(payload: thirdOrdPayload, signature: try licKey.signature(for: Data(thirdOrdPayload.utf8)))
    check(offlineRelaunchKit.activateOfflineTicket(thirdOrdTicket, parentSeatKey: "cs_live_repurchasedOrderKey0000000003", seatsUsed: 1, maxSeats: 2), "second re-purchase activates cleanly after .revokeLocalLicense")
    check(offlineRelaunchKit.isLicensed && offlineRelaunchKit.orderTag == "ORD-REPURCHASE000002", "second re-purchase unlocks Mac")

    // Kits with their own vault, anchors, and defaults suite, for manifest sequence and revocation tests.
    var isolatedSuiteNames: [String] = []
    defer { for name in isolatedSuiteNames { UserDefaults.standard.removePersistentDomain(forName: name) } }
    var isolatedSuites: [String: UserDefaults] = [:]
    func isolatedSuite(_ name: String) -> UserDefaults {
        if let existing = isolatedSuites[name] { return existing }
        let suiteName = "com.example.selftest.isolated.\(name).\(UUID().uuidString)"
        isolatedSuiteNames.append(suiteName)
        let created = UserDefaults(suiteName: suiteName)!
        isolatedSuites[name] = created
        return created
    }
    func isolatedVault(_ name: String) -> URL { tmpDir.appendingPathComponent("isolated-\(name)/appSupport/.license_vault") }
    func makeIsolatedKit(_ name: String, revokedOrderTags: Set<String> = []) -> SeatStampManager {
        SeatStampManager(
            scheme: "TESTAPP-V1",
            licensePublicKeyBase64: licPubB64,
            updatePublicKeyBase64: updPubB64,
            trialLengthDays: 30,
            maxSeats: 2,
            bundleID: "com.example.testapp",
            revokedOrderTags: revokedOrderTags,
            testingOverrides: .init(
                defaults: isolatedSuite(name),
                fileAnchorURLs: [
                    tmpDir.appendingPathComponent("isolated-\(name)/appSupport/.vault_seal"),
                    tmpDir.appendingPathComponent("isolated-\(name)/caches/.vault_seal")
                ],
                vaultFileURL: isolatedVault(name),
                hardwareUUID: fakeHW,
                useKeychain: false,
                healSynchronously: true,
                now: { Date(timeIntervalSince1970: TimeInterval(fakeNow)) }
            )
        )
    }
    func makeIsolatedUpdater(_ name: String, kit: SeatStampManager, behavior: UpdateChecker.RevocationBehavior = .suppressUpdates) -> UpdateChecker {
        UpdateChecker(
            kit: kit,
            manifestURL: URL(string: "https://testapp.example/version.json")!,
            trustedDownloadHosts: ["testapp.example"],
            revocationBehavior: behavior,
            currentVersion: "1.0.0",
            defaults: isolatedSuite(name)
        )
    }
    func makeSequencedManifest(version: String, revokedTags: [String] = [], seq: Int64?) throws -> [String: Any] {
        let url = "https://testapp.example/download/TestApp-\(version).dmg"
        let canon = UpdateManifest.canonicalSigningData(
            scheme: "TESTAPP-UPDATE-V1",
            version: version,
            url: url,
            summary: "Update \(version)",
            notes: [],
            summaryI18n: [:],
            notesI18n: [:],
            revokedTags: revokedTags,
            manifestSeq: seq
        )
        var obj: [String: Any] = [
            "version": version,
            "url": url,
            "summary": "Update \(version)",
            "sig": LicenseTicket.base64URLEncode(try updKey.signature(for: canon))
        ]
        if !revokedTags.isEmpty { obj["revoked_tags"] = revokedTags }
        if let seq = seq { obj["manifest_seq"] = seq }
        return obj
    }
    func manifestData(_ obj: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: obj) }
    func seqData(version: String, revokedTags: [String] = [], seq: Int64?) -> Data {
        (try? manifestData(makeSequencedManifest(version: version, revokedTags: revokedTags, seq: seq))) ?? Data()
    }
    func mintSeatTicket(tag: String, issued: Int64, seat: String?) throws -> String {
        let payload = LicenseTicket.canonicalPayload(scheme: "TESTAPP-V1", tag: tag, issued: issued, seat: seat)
        return LicenseTicket.encode(payload: payload, signature: try licKey.signature(for: Data(payload.utf8)))
    }

    // Signed manifest_seq: a replayed lower sequence is rejected and changes nothing.
    let seqKit = makeIsolatedKit("seq")
    let seqUpdater = makeIsolatedUpdater("seq", kit: seqKit)
    var tamperedSeq = try makeSequencedManifest(version: "2.0.5", seq: 5)
    tamperedSeq["manifest_seq"] = 6
    check(!seqUpdater.ingest(data: (try? manifestData(tamperedSeq)) ?? Data()), "changing manifest_seq in a signed manifest makes ingest return false")
    check(seqKit.highestManifestSequence == 0, "a manifest with a broken signature does not store its sequence")
    check(seqUpdater.ingest(data: seqData(version: "2.1.0", seq: 10)), "manifest with manifest_seq 10 ingests")
    let updateAtSeq10 = seqUpdater.availableUpdate
    check(updateAtSeq10?.rawVersion == "2.1.0", "manifest with manifest_seq 10 sets availableUpdate")
    check(!seqUpdater.ingest(data: seqData(version: "2.2.0", seq: 9)), "a lower manifest_seq (9 after 10) is rejected as a replay")
    check(seqUpdater.availableUpdate == updateAtSeq10, "a replayed manifest leaves availableUpdate unchanged")
    check(seqUpdater.ingest(data: seqData(version: "2.1.0", seq: 10)), "the same manifest_seq 10 is accepted again")
    check(!seqUpdater.ingest(data: seqData(version: "2.2.0", seq: nil)), "a manifest without manifest_seq is rejected once a sequenced one was accepted")
    check(makeIsolatedKit("seq").highestManifestSequence == 10, "a new SeatStampManager on the same vault reports highestManifestSequence 10")
    let freshSeqKit = makeIsolatedKit("seqfresh")
    check(makeIsolatedUpdater("seqfresh", kit: freshSeqKit).ingest(data: seqData(version: "2.2.0", seq: nil)),
          "a fresh kit still accepts a manifest without manifest_seq")

    // A manifest revocation of a seat-bound ticket advances the sealed watermark, so deleting .license_vault
    // and pasting the old ticket back does not work.
    fakeNow += 30
    let sealKit = makeIsolatedKit("sealrevoke")
    let sealTicket = try mintSeatTicket(tag: "ORD-5EA1ED0000000001", issued: fakeNow, seat: sealKit.deviceSeatCode)
    check(sealKit.activateOfflineTicket(sealTicket, parentSeatKey: "cs_live_sealedRevocationKey000000000004", seatsUsed: 1, maxSeats: 2), "seat-bound ticket activates on the watermark test kit")
    let sealUpdater = makeIsolatedUpdater("sealrevoke", kit: sealKit, behavior: .revokeLocalLicense)
    check(sealUpdater.ingest(data: seqData(version: "2.3.0", revokedTags: ["ORD-5EA1ED0000000001"], seq: nil)), "revoking manifest ingests on the watermark test kit")
    check(!sealKit.isLicensed, "revokeLocalLicense revokes the active seat-bound ticket")
    try? FileManager.default.removeItem(at: isolatedVault("sealrevoke"))
    let sealRelaunch = makeIsolatedKit("sealrevoke")
    check(!sealRelaunch.activateOfflineTicket(sealTicket), "a manifest-revoked seat-bound ticket cannot be pasted back after .license_vault is deleted")

    // A corrected sequenced manifest undoes a manifest revocation; the purchase key survives for a one-click re-activation.
    fakeNow += 30
    let unrevokeKit = makeIsolatedKit("unrevoke")
    let unrevokeKey = "cs_live_unrevokeMistakeKey00000000000005"
    let unrevokeTag = "ORD-0DD5E1F000000001"
    let unrevokeTicket = try mintSeatTicket(tag: unrevokeTag, issued: fakeNow, seat: unrevokeKit.deviceSeatCode)
    check(unrevokeKit.activateOfflineTicket(unrevokeTicket, parentSeatKey: unrevokeKey, seatsUsed: 1, maxSeats: 2), "seat-bound ticket activates on the un-revoke test kit")
    let unrevokeUpdater = makeIsolatedUpdater("unrevoke", kit: unrevokeKit, behavior: .revokeLocalLicense)
    check(unrevokeUpdater.ingest(data: seqData(version: "2.4.0", revokedTags: [unrevokeTag], seq: 5)), "manifest_seq 5 listing the active tag ingests")
    check(!unrevokeKit.isLicensed, "manifest_seq 5 revokes the active ticket")
    check(unrevokeKit.shareableLicenseKey == unrevokeKey, "a manifest revocation keeps the purchase key")
    check(unrevokeUpdater.ingest(data: seqData(version: "2.4.1", seq: 6)), "manifest_seq 6 without the tag ingests")
    check(!unrevokeKit.revokedOrderTags.contains(unrevokeTag), "a newer sequenced manifest without the tag removes it from the revoked set")
    fakeNow += 10
    let unrevokeTicket2 = try mintSeatTicket(tag: unrevokeTag, issued: fakeNow, seat: unrevokeKit.deviceSeatCode)
    check(unrevokeKit.activateOfflineTicket(unrevokeTicket2, parentSeatKey: unrevokeKey), "a new ticket for the un-revoked tag (later issued) activates")
    check(!unrevokeUpdater.ingest(data: seqData(version: "2.4.0", revokedTags: [unrevokeTag], seq: 5)), "replaying manifest_seq 5 after 6 is rejected")
    check(!unrevokeKit.revokedOrderTags.contains(unrevokeTag) && unrevokeKit.isLicensed, "a replayed revocation leaves the tag absent and the kit licensed")
    check(!makeIsolatedKit("unrevoke").revokedOrderTags.contains(unrevokeTag), "the un-revoked tag stays absent after relaunch")

    let staticTag = "ORD-57A71C0000000001"
    let staticKit = makeIsolatedKit("statictag", revokedOrderTags: [staticTag])
    let staticUpdater = makeIsolatedUpdater("statictag", kit: staticKit, behavior: .revokeLocalLicense)
    check(staticUpdater.ingest(data: seqData(version: "2.4.0", revokedTags: [staticTag], seq: 7)), "sequenced manifest listing a static tag ingests")
    check(staticUpdater.ingest(data: seqData(version: "2.4.1", seq: 8)), "newer sequenced manifest without the static tag ingests")
    check(staticKit.revokedOrderTags.contains(staticTag), "a tag passed to init(revokedOrderTags:) stays revoked after a sequenced manifest that does not list it")

    let addOnlyKit = makeIsolatedKit("addonly")
    let addOnlyUpdater = makeIsolatedUpdater("addonly", kit: addOnlyKit, behavior: .revokeLocalLicense)
    check(addOnlyUpdater.ingest(data: seqData(version: "2.4.0", revokedTags: ["ORD-ADD0000000000001"], seq: nil))
          && addOnlyUpdater.ingest(data: seqData(version: "2.4.0", revokedTags: ["ORD-ADD0000000000002"], seq: nil)),
          "unsequenced manifests ingest on a fresh kit")
    check(addOnlyKit.revokedOrderTags.isSuperset(of: ["ORD-ADD0000000000001", "ORD-ADD0000000000002"]), "manifests without a sequence still only add tags")

    addOnlyKit.replaceManifestRevokedOrderTags(["ORD-ADD0000000000002"])
    check(addOnlyKit.revokedOrderTags == ["ORD-ADD0000000000002"], "replaceManifestRevokedOrderTags replaces the stored set")
    addOnlyKit.replaceManifestRevokedOrderTags([String]())
    check(addOnlyKit.revokedOrderTags.isEmpty, "replaceManifestRevokedOrderTags with an empty list clears the stored set")

    // Sealed trial clock: a launch with the clock rolled back never lowers `first` or `high`, and a far-future
    // clock advances `high` by at most 7 days per launch and per hour of running.
    let clockRoot = FileManager.default.temporaryDirectory.appendingPathComponent("seatstamp-clock-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: clockRoot) }
    var clockSuiteNames: [String] = []
    defer { for name in clockSuiteNames { UserDefaults.standard.removePersistentDomain(forName: name) } }
    var clockNow: Int64 = 1_770_000_000
    let clockT0 = clockNow
    var clockSuites: [String: UserDefaults] = [:]
    func clockAnchor(_ name: String) -> URL { clockRoot.appendingPathComponent("\(name)/.vault_seal") }
    func makeClockKit(_ name: String) -> SeatStampManager {
        let defaults: UserDefaults
        if let existing = clockSuites[name] {
            defaults = existing
        } else {
            let suiteName = "com.example.selftest.clock.\(name).\(UUID().uuidString)"
            clockSuiteNames.append(suiteName)
            defaults = UserDefaults(suiteName: suiteName)!
            clockSuites[name] = defaults
        }
        return SeatStampManager(
            scheme: "TESTAPP-V1",
            licensePublicKeyBase64: licPubB64,
            trialLengthDays: 30,
            bundleID: "com.example.testapp",
            testingOverrides: .init(
                defaults: defaults,
                fileAnchorURLs: [clockAnchor(name)],
                vaultFileURL: clockRoot.appendingPathComponent("\(name)/.license_vault"),
                hardwareUUID: fakeHW,
                useKeychain: false,
                healSynchronously: true,
                now: { Date(timeIntervalSince1970: TimeInterval(clockNow)) }
            )
        )
    }
    func clockAnchorText(_ name: String) -> String {
        (try? String(contentsOf: clockAnchor(name), encoding: .utf8)) ?? ""
    }

    _ = makeClockKit("rollback")
    for i in 1...5 {
        clockNow = clockT0 + Int64(i) * 7 * 86_400
        _ = makeClockKit("rollback")
    }
    clockNow = clockT0
    let anchorBeforeRollback = clockAnchorText("rollback")
    let rolledBack = makeClockKit("rollback")
    check(rolledBack.isTrialExpired && !rolledBack.verifyGateAccess() && rolledBack.trialDaysRemaining == 0, "expired trial stays expired after a launch with the clock rolled back")
    check(!anchorBeforeRollback.isEmpty && clockAnchorText("rollback") == anchorBeforeRollback, "a launch with the clock rolled back does not rewrite the anchors")
    let rolledBackAgain = makeClockKit("rollback")
    check(rolledBackAgain.isTrialExpired && !rolledBackAgain.verifyGateAccess() && rolledBackAgain.trialDaysRemaining == 0
          && clockAnchorText("rollback") == anchorBeforeRollback, "a second rolled-back launch keeps the trial expired and the anchors unchanged")

    clockNow = clockT0 - 10 * 86_400
    let earlyClock = makeClockKit("rollback")
    check(Int64(earlyClock.firstLaunchDate.timeIntervalSince1970) == clockT0, "a launch with the clock before the sealed first launch does not lower first")

    clockNow = clockT0
    _ = makeClockKit("forward")
    clockNow = clockT0 + 365 * 86_400
    let farFuture = makeClockKit("forward")
    farFuture.refreshMonotonicClockIfNeeded()
    farFuture.refreshMonotonicClockIfNeeded()
    farFuture.refreshMonotonicClockIfNeeded()
    clockNow = clockT0
    check(makeClockKit("forward").trialDaysRemaining == 23, "a launch under a far-future clock costs at most 7 trial days, however often refresh is called")
    clockNow = clockT0 + 365 * 86_400
    let farFutureRunning = makeClockKit("forward")
    clockNow += 3_600
    farFutureRunning.refreshMonotonicClockIfNeeded()
    clockNow = clockT0
    check(farFutureRunning.trialDaysRemaining == 9, "an hour of running under a far-future clock advances high by at most 7 more days")
} catch {
    check(false, "SeatStampManager state-machine test threw: \(error)")
}

// MARK: - 5a. Default-Browser Checkout Handoff (beginBrowserCheckout, resumePendingCheckoutIfNeeded, deep-link race, cancel)

final class MockCheckoutURLProtocol: URLProtocol {
    enum Reply {
        case now(Int, [String: Any])
        /// Park the request; the test releases it later via `releaseHeld(...)`. Never blocks the loader thread.
        case hold
    }

    static let lock = NSLock()
    static var handler: ((URLRequest, Data) -> Reply)?
    private static var held: [MockCheckoutURLProtocol] = []

    static func setHandler(_ h: @escaping (URLRequest, Data) -> Reply) {
        lock.lock(); handler = h; lock.unlock()
    }

    /// Simple handler form for tests that always answer immediately.
    static func setImmediateHandler(_ h: @escaping (URLRequest, Data) -> (Int, [String: Any])) {
        setHandler { req, body in
            let (s, j) = h(req, body)
            return .now(s, j)
        }
    }

    static var heldCount: Int {
        lock.lock(); defer { lock.unlock() }
        return held.count
    }

    /// Responds to every parked request with the given status/body.
    static func releaseHeld(status: Int, body: [String: Any]) {
        lock.lock()
        let batch = held
        held.removeAll()
        lock.unlock()
        for p in batch { p.respond(status: status, jsonObj: body) }
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        var bodyData = request.httpBody ?? Data()
        if bodyData.isEmpty, let stream = request.httpBodyStream {
            stream.open()
            var buf = [UInt8](repeating: 0, count: 1024)
            while stream.hasBytesAvailable {
                let n = stream.read(&buf, maxLength: buf.count)
                if n > 0 { bodyData.append(buf, count: n) } else { break }
            }
            stream.close()
        }
        Self.lock.lock()
        let h = Self.handler
        Self.lock.unlock()
        switch h?(request, bodyData) ?? .now(500, ["error": "unconfigured"]) {
        case .now(let status, let jsonObj):
            respond(status: status, jsonObj: jsonObj)
        case .hold:
            Self.lock.lock()
            Self.held.append(self)
            Self.lock.unlock()
        }
    }

    private func respond(status: Int, jsonObj: [String: Any]) {
        let respData = (try? JSONSerialization.data(withJSONObject: jsonObj)) ?? Data()
        let resp = HTTPURLResponse(
            url: request.url ?? URL(string: "https://activate.testapp.example/")!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: respData)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

/// Thread-safe counters for assertions driven from the URLSession loader thread.
final class TestCounters {
    private let lock = NSLock()
    private var ints: [String: Int] = [:]
    private var strings: [String: String] = [:]
    private var flags: [String: Bool] = [:]

    func bump(_ key: String) { lock.lock(); ints[key, default: 0] += 1; lock.unlock() }
    func int(_ key: String) -> Int { lock.lock(); defer { lock.unlock() }; return ints[key] ?? 0 }
    func set(_ key: String, _ value: String) { lock.lock(); strings[key] = value; lock.unlock() }
    func string(_ key: String) -> String { lock.lock(); defer { lock.unlock() }; return strings[key] ?? "" }
    func flag(_ key: String) { lock.lock(); flags[key] = true; lock.unlock() }
    func isSet(_ key: String) -> Bool { lock.lock(); defer { lock.unlock() }; return flags[key] ?? false }
}

func pumpMainRunLoop(until timeout: TimeInterval = 1.0, condition: () -> Bool) {
    let deadline = Date().addingTimeInterval(timeout)
    while !condition() && Date() < deadline {
        RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.005))
    }
}

section("Default-Browser Checkout Handoff")
do {
    let chkRoot = FileManager.default.temporaryDirectory.appendingPathComponent("seatstamp-checkout-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: chkRoot) }
    let suiteName = "com.example.checkout.\(UUID().uuidString)"
    let suite = UserDefaults(suiteName: suiteName)!
    defer { suite.removePersistentDomain(forName: suiteName) }

    var fakeNow: Int64 = 1_760_500_000
    let fakeHW = "12121212-3434-5656-7878-909090909090"
    let licKey = Curve25519.Signing.PrivateKey()
    let licPubB64 = licKey.publicKey.rawRepresentation.base64EncodedString()
    let paymentLink = URL(string: "https://buy.stripe.com/test_usd")!
    let endpoint = URL(string: "https://activate.testapp.example")!

    let mockCfg = URLSessionConfiguration.ephemeral
    mockCfg.protocolClasses = [MockCheckoutURLProtocol.self]
    let mockSession = URLSession(configuration: mockCfg)

    // Each sub-test gets its own vault directory so an async deactivate from one kit can never rewrite another's vault.
    func makeCheckoutKit(vault: String, pollInterval: TimeInterval = 0.015, autoResume: Bool = true, endpoints: [URL]? = nil, defaults: UserDefaults? = nil) -> SeatStampManager {
        let dir = chkRoot.appendingPathComponent(vault, isDirectory: true)
        return SeatStampManager(
            scheme: "TESTAPP-V1",
            licensePublicKeyBase64: licPubB64,
            activationEndpoints: endpoints ?? [endpoint],
            trialLengthDays: 30,
            maxSeats: 2,
            bundleID: "com.example.testapp",
            testingOverrides: .init(
                defaults: defaults ?? suite,
                fileAnchorURLs: [dir.appendingPathComponent(".vault_seal")],
                vaultFileURL: dir.appendingPathComponent(".license_vault"),
                hardwareUUID: fakeHW,
                useKeychain: false,
                healSynchronously: true,
                now: { Date(timeIntervalSince1970: TimeInterval(fakeNow)) },
                urlSession: mockSession,
                checkoutPollInterval: pollInterval,
                autoResumePendingCheckout: autoResume
            )
        )
    }
    func seatTicket(tag: String, issued: Int64, seat: String) throws -> String {
        let payload = LicenseTicket.canonicalPayload(scheme: "TESTAPP-V1", tag: tag, issued: issued, seat: seat)
        return LicenseTicket.encode(payload: payload, signature: try licKey.signature(for: Data(payload.utf8)))
    }
    func activatedBody(key: String, ticket: String) -> [String: Any] {
        ["status": "activated", "key": key, "ticket": ticket, "seatsUsed": 1, "maxSeats": 2, "revokedBefore": 0]
    }
    func json(_ body: Data) -> [String: Any] {
        (try? JSONSerialization.jsonObject(with: body) as? [String: Any]) ?? [:]
    }
    func handoffToken(in url: URL) -> String {
        URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "client_reference_id" })?.value ?? ""
    }
    let seatCode = TrialSeal.seatCode(hardwareUUID: fakeHW, domain: "com.example.testapp.seat.v1|")

    // 1) checkoutURL(for:handoffToken:) preserves existing query params and works with RegionalPricing.checkoutURL(for:)
    let kitURL = makeCheckoutKit(vault: "s1")
    let links = RegionalPricing.PaymentLinks(usd: URL(string: "https://buy.stripe.com/test_usd?prefilled_promo_code=LAUNCH50&client_reference_id=old")!)
    let tokenSample = SeatStampManager.generateHandoffToken()
    check(tokenSample.hasPrefix("chk_") && tokenSample.count == 36 && tokenSample.dropFirst(4).allSatisfy { $0.isHexDigit && !$0.isUppercase }, "generateHandoffToken produces chk_<32 lowercase hex>")
    check(SeatStampManager.generateHandoffToken() != tokenSample, "generateHandoffToken is random")
    let tagged = kitURL.checkoutURL(for: RegionalPricing.checkoutURL(for: links), handoffToken: tokenSample)
    let taggedItems = URLComponents(url: tagged, resolvingAgainstBaseURL: false)!.queryItems ?? []
    check(taggedItems.first(where: { $0.name == "prefilled_promo_code" })?.value == "LAUNCH50", "checkoutURL preserves existing query parameters")
    check(taggedItems.filter({ $0.name == "client_reference_id" }).count == 1, "checkoutURL replaces existing client_reference_id without duplicating")
    check(handoffToken(in: tagged) == tokenSample, "checkoutURL sets client_reference_id to handoffToken")

    // 2) End-to-end: 202 pending -> 200 activated flips isLicensed, clears isAwaitingBrowserCheckout, stores shareableLicenseKey
    let c2 = TestCounters()
    let sessionKey2 = "cs_live_browserCheckoutAutoClaim0000001"
    let ticket2 = try seatTicket(tag: "ORD-AUTO000000000001", issued: fakeNow, seat: seatCode)
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        let j = json(body)
        guard (j["action"] as? String) == "claim_checkout" else { return (400, ["error": "unexpected"]) }
        c2.bump("claims")
        c2.set("handoff", (j["handoff"] as? String) ?? "")
        return c2.int("claims") == 1 ? (202, ["status": "pending"]) : (200, activatedBody(key: sessionKey2, ticket: ticket2))
    }
    var openedURL: URL?
    var outcome2: SeatStampManager.ActivationOutcome?
    let returnedURL = kitURL.beginBrowserCheckout(paymentLink: paymentLink, openURL: { openedURL = $0 }, onOutcome: { outcome2 = $0 })
    check(openedURL == returnedURL && kitURL.isAwaitingBrowserCheckout, "beginBrowserCheckout opens tagged URL and sets isAwaitingBrowserCheckout = true")
    pumpMainRunLoop(until: 5.0) { kitURL.isLicensed }
    check(c2.int("claims") >= 2, "beginBrowserCheckout polled pending (202) then activated (200)")
    let sentHandoff = c2.string("handoff")
    check(!sentHandoff.isEmpty && sentHandoff == handoffToken(in: returnedURL), "claim_checkout sends exactly the handoff token embedded in the opened URL")
    check(kitURL.isLicensed && !kitURL.isAwaitingBrowserCheckout, "beginBrowserCheckout unlocks app and clears isAwaitingBrowserCheckout")
    check(kitURL.shareableLicenseKey == sessionKey2, "beginBrowserCheckout saves cs_live_... as shareableLicenseKey for 2nd Mac")
    check(outcome2 == .activated, "beginBrowserCheckout invokes onOutcome(.activated)")
    check(!kitURL.isActivatingOnline, "background claim never sets isActivatingOnline")

    // 3) Quit/relaunch recovery: the exact token persisted by the destroyed kit is what the new kit claims, with fallbackSearch: true
    let c3 = TestCounters()
    MockCheckoutURLProtocol.setImmediateHandler { _, _ in (202, ["status": "pending"]) }
    var kitBeforeQuit: SeatStampManager? = makeCheckoutKit(vault: "s3", pollInterval: 10.0)
    let urlBeforeQuit = kitBeforeQuit!.beginBrowserCheckout(paymentLink: paymentLink, openURL: { _ in })
    let tokenBeforeQuit = handoffToken(in: urlBeforeQuit)
    check(kitBeforeQuit!.isAwaitingBrowserCheckout && !tokenBeforeQuit.isEmpty, "kitBeforeQuit has pending checkout stored in vault")
    kitBeforeQuit = nil

    let sessionKey3 = "cs_live_recoveredOnRelaunchKey000000002"
    fakeNow += 5
    let ticket3 = try seatTicket(tag: "ORD-RECOVER000000002", issued: fakeNow, seat: seatCode)
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        let j = json(body)
        guard (j["action"] as? String) == "claim_checkout" else { return (200, ["ok": true, "revokedBefore": fakeNow]) }
        c3.set("handoff", (j["handoff"] as? String) ?? "")
        if (j["fallbackSearch"] as? Bool) == true { c3.flag("fallback") }
        return (200, activatedBody(key: sessionKey3, ticket: ticket3))
    }
    let relaunched = makeCheckoutKit(vault: "s3", pollInterval: 0.02)
    pumpMainRunLoop(until: 5.0) { relaunched.isLicensed }
    check(c3.string("handoff") == tokenBeforeQuit, "relaunched kit claims the same handoff token that the destroyed kit persisted")
    check(c3.isSet("fallback"), "resumePendingCheckoutIfNeeded sends fallbackSearch: true on relaunch")
    check(relaunched.isLicensed && !relaunched.isAwaitingBrowserCheckout, "interrupted checkout automatically activates on relaunch")
    check(relaunched.shareableLicenseKey == sessionKey3, "recovered checkout preserves cs_live_... parent key")

    // 3b) A pending handoff older than 24h is dropped on init and never claimed
    let c3b = TestCounters()
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        if (json(body)["action"] as? String) == "claim_checkout" { c3b.bump("claims") }
        return (202, ["status": "pending"])
    }
    var staleSeed: SeatStampManager? = makeCheckoutKit(vault: "s3b", pollInterval: 10.0)
    _ = staleSeed!.beginBrowserCheckout(paymentLink: paymentLink, openURL: { _ in })
    staleSeed = nil
    fakeNow += 86_401
    let afterTTL = makeCheckoutKit(vault: "s3b", pollInterval: 0.02)
    pumpMainRunLoop(until: 0.15) { false }
    check(!afterTTL.isAwaitingBrowserCheckout && c3b.int("claims") == 0, "pending handoff older than 24h is discarded on init without any claim")

    // 3c) Between 15m and 24h: one fallback claim fires, but no active polling is resumed
    let c3c = TestCounters()
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        if (json(body)["action"] as? String) == "claim_checkout" { c3c.bump("claims") }
        return (202, ["status": "pending"])
    }
    var lateSeed: SeatStampManager? = makeCheckoutKit(vault: "s3c", pollInterval: 10.0)
    _ = lateSeed!.beginBrowserCheckout(paymentLink: paymentLink, openURL: { _ in })
    lateSeed = nil
    fakeNow += 20 * 60
    let lateKit = makeCheckoutKit(vault: "s3c", pollInterval: 0.02)
    pumpMainRunLoop(until: 5.0) { c3c.int("claims") >= 1 }
    pumpMainRunLoop(until: 0.15) { false }
    check(c3c.int("claims") == 1 && !lateKit.isAwaitingBrowserCheckout, "after the 15-minute active window, relaunch performs exactly one fallback claim and does not resume timer polling")

    // 4) Real race: a claim_checkout is parked server-side while a myapp:// deep link activates.
    //    Deep link must win, cancel polling, and the late 200+ticket from the claim must be ignored.
    let c4 = TestCounters()
    let kit4 = makeCheckoutKit(vault: "s4", pollInterval: 0.02)
    let deepLinkKey = "cs_live_deepLinkWinsRaceSession00000003"
    let lateClaimKey = "cs_live_lateClaimMustBeIgnored000000004"
    fakeNow += 5
    let dlTicket = try seatTicket(tag: "ORD-DEEPLINK00000003", issued: fakeNow, seat: seatCode)
    let lateTicket = try seatTicket(tag: "ORD-LATECLAIM0000004", issued: fakeNow + 1, seat: seatCode)
    MockCheckoutURLProtocol.setHandler { _, body in
        switch json(body)["action"] as? String {
        case "claim_checkout":
            c4.bump("claims")
            return .hold
        case "activate":
            return .now(200, ["ticket": dlTicket, "seatsUsed": 1, "maxSeats": 2, "revokedBefore": 0])
        default:
            return .now(200, ["ok": true, "revokedBefore": fakeNow])
        }
    }
    _ = kit4.beginBrowserCheckout(paymentLink: paymentLink, openURL: { _ in }, onOutcome: { _ in c4.flag("callback") })
    check(kit4.isAwaitingBrowserCheckout, "checkout polling active before deep link arrives")
    pumpMainRunLoop(until: 5.0) { MockCheckoutURLProtocol.heldCount == 1 }
    check(MockCheckoutURLProtocol.heldCount == 1, "a claim_checkout request is in flight (held) when the deep link arrives")

    // Deadlock regression: a Combine subscriber reads a lock-protected property while `isActivatingOnline` is published.
    var sinkObservedTrialDays: Int? = nil
    let sink = kit4.$isActivatingOnline.sink { activating in
        if activating { sinkObservedTrialDays = kit4.trialDaysRemaining }
    }
    var deepLinkOutcome: SeatStampManager.ActivationOutcome?
    kit4.activate(key: deepLinkKey) { deepLinkOutcome = $0 }
    pumpMainRunLoop(until: 5.0) { deepLinkOutcome != nil }
    sink.cancel()
    check(sinkObservedTrialDays != nil, "publishing isActivatingOnline outside stateLock lets subscribers read locked state")
    check(deepLinkOutcome == .activated && kit4.isLicensed, "deep link activate(key:) succeeds while a claim_checkout is in flight")
    check(!kit4.isAwaitingBrowserCheckout && !kit4.isActivatingOnline, "deep link activation cancels isAwaitingBrowserCheckout and resets isActivatingOnline")

    MockCheckoutURLProtocol.releaseHeld(status: 200, body: activatedBody(key: lateClaimKey, ticket: lateTicket))
    pumpMainRunLoop(until: 0.3) { false }
    check(!c4.isSet("callback"), "late claim_checkout response never fires the checkout callback")
    check(kit4.shareableLicenseKey == deepLinkKey && kit4.orderTag == "ORD-DEEPLINK00000003", "late claim response does not overwrite the deep-link license")
    check(c4.int("claims") == 1, "no further claims are issued after the deep link won")

    // 5) cancelBrowserCheckout() stops polling, removes the handoff from the vault, and does not resume on relaunch
    let c5 = TestCounters()
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        if (json(body)["action"] as? String) == "claim_checkout" { c5.bump("claims") }
        return (202, ["status": "pending"])
    }
    let kit5 = makeCheckoutKit(vault: "s5", pollInterval: 0.02)
    _ = kit5.beginBrowserCheckout(paymentLink: paymentLink, openURL: { _ in })
    pumpMainRunLoop(until: 5.0) { c5.int("claims") >= 1 }
    check(kit5.isAwaitingBrowserCheckout, "isAwaitingBrowserCheckout true before cancel")
    kit5.cancelBrowserCheckout()
    check(!kit5.isAwaitingBrowserCheckout, "cancelBrowserCheckout sets isAwaitingBrowserCheckout = false")
    let claimsAtCancel = c5.int("claims")
    pumpMainRunLoop(until: 0.1) { false }
    check(c5.int("claims") == claimsAtCancel, "no claims fire after cancelBrowserCheckout")
    let freshAfterCancel = makeCheckoutKit(vault: "s5", pollInterval: 0.02)
    pumpMainRunLoop(until: 0.1) { false }
    check(!freshAfterCancel.isAwaitingBrowserCheckout && c5.int("claims") == claimsAtCancel, "cancelled checkout is wiped from vault and does not resume on relaunch")

    // 6) 409 seat_limit_reached from claim_checkout maps to .seatLimitReached, stops polling, clears the vault handoff
    let c6 = TestCounters()
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        if (json(body)["action"] as? String) == "claim_checkout" { c6.bump("claims") }
        return (409, ["error": "seat_limit_reached", "maxSeats": 2])
    }
    let kit6 = makeCheckoutKit(vault: "s6", pollInterval: 0.02)
    var outcome6: SeatStampManager.ActivationOutcome?
    _ = kit6.beginBrowserCheckout(paymentLink: paymentLink, openURL: { _ in }, onOutcome: { outcome6 = $0 })
    pumpMainRunLoop(until: 5.0) { outcome6 != nil }
    check(outcome6 == .seatLimitReached && !kit6.isAwaitingBrowserCheckout && !kit6.isLicensed, "409 from claim_checkout -> .seatLimitReached and polling stops")
    let kit6b = makeCheckoutKit(vault: "s6", pollInterval: 0.02)
    pumpMainRunLoop(until: 0.1) { false }
    check(!kit6b.isAwaitingBrowserCheckout && c6.int("claims") == 1, "409 clears the persisted handoff so relaunch does not retry")

    // 6b) 403 handoff_seat_mismatch from claim_checkout stops polling and is reported as .networkError, not .invalidKey
    let c6b = TestCounters()
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        if (json(body)["action"] as? String) == "claim_checkout" { c6b.bump("claims") }
        return (403, ["error": "handoff_seat_mismatch"])
    }
    let kit6c = makeCheckoutKit(vault: "s6c", pollInterval: 0.02)
    var outcome6c: SeatStampManager.ActivationOutcome?
    _ = kit6c.beginBrowserCheckout(paymentLink: paymentLink, openURL: { _ in }, onOutcome: { outcome6c = $0 })
    pumpMainRunLoop(until: 5.0) { outcome6c != nil }
    pumpMainRunLoop(until: 0.1) { false }
    check(outcome6c == .networkError && c6b.int("claims") == 1 && !kit6c.isAwaitingBrowserCheckout, "403 handoff_seat_mismatch from claim_checkout -> .networkError, single request, polling stops")

    // 6d) 409 payment_pending: activate(key:) reports .paymentPending, other 409s stay .seatLimitReached,
    //     and the claim flow keeps polling until the payment settles
    var activate409Error = "payment_pending"
    MockCheckoutURLProtocol.setImmediateHandler { _, _ in (409, ["error": activate409Error]) }
    let kit6d = makeCheckoutKit(vault: "s6d")
    var outcome6d: SeatStampManager.ActivationOutcome?
    kit6d.activate(key: "cs_live_paymentPendingActivate00000006") { outcome6d = $0 }
    pumpMainRunLoop(until: 5.0) { outcome6d != nil }
    check(outcome6d == .paymentPending, "activate(key:) with 409 payment_pending -> .paymentPending")
    activate409Error = "seat_limit_reached"
    outcome6d = nil
    kit6d.activate(key: "cs_live_paymentPendingActivate00000006") { outcome6d = $0 }
    pumpMainRunLoop(until: 5.0) { outcome6d != nil }
    check(outcome6d == .seatLimitReached, "activate(key:) with 409 seat_limit_reached -> .seatLimitReached")

    let c6d = TestCounters()
    let key6d = "cs_live_paymentPendingClaim000000000006"
    fakeNow += 5
    let ticket6d = try seatTicket(tag: "ORD-PENDING000000006", issued: fakeNow, seat: seatCode)
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        guard (json(body)["action"] as? String) == "claim_checkout" else { return (400, ["error": "unexpected"]) }
        c6d.bump("claims")
        return c6d.int("claims") == 1 ? (409, ["error": "payment_pending"]) : (200, activatedBody(key: key6d, ticket: ticket6d))
    }
    let kit6e = makeCheckoutKit(vault: "s6e", pollInterval: 0.02)
    var outcome6e: SeatStampManager.ActivationOutcome?
    _ = kit6e.beginBrowserCheckout(paymentLink: paymentLink, openURL: { _ in }, onOutcome: { outcome6e = $0 })
    pumpMainRunLoop(until: 5.0) { outcome6e != nil }
    check(outcome6e == .activated && kit6e.isLicensed && c6d.int("claims") == 2, "claim answering 409 payment_pending once and then 200 ends activated")

    // 7) Malformed 200 (missing ticket) and unexpected 4xx are terminal, not retried for 15 minutes
    for (status, body, label, expected) in [
        (200, ["status": "activated", "key": "cs_live_malformedNoTicket000000000005"] as [String: Any], "malformed 200 without ticket", SeatStampManager.ActivationOutcome.invalidKey),
        (400, ["error": "invalid_params"] as [String: Any], "unexpected 400", SeatStampManager.ActivationOutcome.networkError),
    ] {
        let c7 = TestCounters()
        MockCheckoutURLProtocol.setImmediateHandler { _, b in
            if (json(b)["action"] as? String) == "claim_checkout" { c7.bump("claims") }
            return (status, body)
        }
        let kit7 = makeCheckoutKit(vault: "s7-\(status)", pollInterval: 0.02)
        var outcome7: SeatStampManager.ActivationOutcome?
        _ = kit7.beginBrowserCheckout(paymentLink: paymentLink, openURL: { _ in }, onOutcome: { outcome7 = $0 })
        pumpMainRunLoop(until: 5.0) { outcome7 != nil }
        pumpMainRunLoop(until: 0.1) { false }
        check(outcome7 == expected && c7.int("claims") == 1 && !kit7.isAwaitingBrowserCheckout, "\(label) from claim_checkout is terminal (.\(expected), single request)")
    }

    // 8) Switching back to the app (didBecomeActive) triggers an immediate claim with fallbackSearch: true
    let c8 = TestCounters()
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        let j = json(body)
        if (j["action"] as? String) == "claim_checkout" {
            c8.bump("claims")
            if (j["fallbackSearch"] as? Bool) == true { c8.bump("fallbackClaims") }
        }
        return (202, ["status": "pending"])
    }
    let kit8 = makeCheckoutKit(vault: "s8", pollInterval: 60.0)
    _ = kit8.beginBrowserCheckout(paymentLink: paymentLink, openURL: { _ in })
    pumpMainRunLoop(until: 0.1) { false }
    check(c8.int("claims") == 0, "with a 60s poll interval no claim has fired yet")
    NotificationCenter.default.post(name: NSApplication.didBecomeActiveNotification, object: nil)
    pumpMainRunLoop(until: 5.0) { c8.int("claims") >= 1 }
    check(c8.int("claims") == 1 && c8.int("fallbackClaims") == 1, "app focus triggers one immediate claim_checkout with fallbackSearch: true")
    kit8.cancelBrowserCheckout()

    // 9) Without activation endpoints, beginBrowserCheckout opens the URL but does not pretend to await a claim
    let kit9 = makeCheckoutKit(vault: "s9", endpoints: [])
    var opened9: URL?
    var outcome9: SeatStampManager.ActivationOutcome?
    let url9 = kit9.beginBrowserCheckout(paymentLink: paymentLink, openURL: { opened9 = $0 }, onOutcome: { outcome9 = $0 })
    check(opened9 == url9 && !handoffToken(in: url9).isEmpty, "beginBrowserCheckout still opens a tagged URL without endpoints")
    check(outcome9 == .unconfigured, "beginBrowserCheckout without endpoints calls onOutcome with .unconfigured")
    check(!kit9.isAwaitingBrowserCheckout, "no activation endpoints -> isAwaitingBrowserCheckout stays false")
    let kit9b = makeCheckoutKit(vault: "s9", endpoints: [])
    check(!kit9b.isAwaitingBrowserCheckout, "no activation endpoints -> nothing is persisted to resume")

    // 9b) Misconfiguration is reported as such, never as a wrong key.
    func activateOutcome(_ kit: SeatStampManager, _ key: String) -> SeatStampManager.ActivationOutcome? {
        var out: SeatStampManager.ActivationOutcome?
        kit.activate(key: key) { out = $0 }
        pumpMainRunLoop(until: 5.0) { out != nil }
        return out
    }
    let c9b = TestCounters()
    var reply9b: (Int, [String: Any]) = (405, [:])
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        if (json(body)["action"] as? String) == "activate" { c9b.bump("activate") }
        return reply9b
    }
    check(activateOutcome(kit9, "cs_live_noEndpointConfigured0000000009b") == .unconfigured, "activate with no endpoints -> .unconfigured")
    let httpKit = makeCheckoutKit(vault: "s9b-http", endpoints: [URL(string: "http://activate.testapp.example")!])
    check(httpKit.rejectedActivationEndpoints == [URL(string: "http://activate.testapp.example")!], "an http:// endpoint is listed in rejectedActivationEndpoints")
    check(activateOutcome(httpKit, "cs_live_httpEndpointRejected00000000009b") == .unconfigured && c9b.int("activate") == 0, "a kit whose only endpoint is http:// -> .unconfigured without a request")
    let kit9c = makeCheckoutKit(vault: "s9c")
    check(kit9c.rejectedActivationEndpoints.isEmpty, "an https endpoint is not rejected")
    for status in [405, 404] {
        reply9b = (status, status == 404 ? ["error": "not_found"] : [:])
        check(activateOutcome(kit9c, "cs_live_wrongEndpointPath000000000009c") == .networkError, "status \(status) from activate -> .networkError")
    }
    reply9b = (403, ["error": "invalid_key"])
    check(activateOutcome(kit9c, "cs_live_reallyInvalidKey00000000000009c") == .invalidKey, "403 invalid_key from activate -> .invalidKey")
    reply9b = (403, ["error": "forbidden_origin"])
    check(activateOutcome(kit9c, "cs_live_unknownForbiddenCode000000009c") == .networkError, "an unknown 403 code from activate -> .networkError")
    let requestsBeforeLongKey = c9b.int("activate")
    check(activateOutcome(kit9c, String(repeating: "k", count: 300)) == .invalidKey && c9b.int("activate") == requestsBeforeLongKey,
          "a 300-character key -> .invalidKey without a request")

    // 10) Email key recovery: looksLikeEmail classification and requestKeyRecovery outcome mapping + failover
    for good in ["a@b.co", "buyer@example.com", "  Mixed.Case+tag@Sub.Example.ORG  ", "x@y.z"] {
        check(SeatStampManager.looksLikeEmail(good), "looksLikeEmail accepts \(good.trimmingCharacters(in: .whitespaces))")
    }
    for bad in ["", "a@b", "@example.com", "user@", "user@example", "user@@example.com", "two words@example.com",
                "user@example.com\nbcc@x.io", "user@.com", "user@example.", "cs_live_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
                "LK1-abc.def", "123e4567-e89b-12d3-a456-426614174000", String(repeating: "a", count: 250) + "@x.io"] {
        check(!SeatStampManager.looksLikeEmail(bad), "looksLikeEmail rejects \(bad.prefix(24).replacingOccurrences(of: "\n", with: "\\n"))")
    }

    let c10 = TestCounters()
    var recoverStatus = 200
    MockCheckoutURLProtocol.setImmediateHandler { req, body in
        let j = json(body)
        guard (j["action"] as? String) == "recover" else { return (400, ["error": "unexpected"]) }
        c10.bump("recover")
        c10.set("email", (j["email"] as? String) ?? "")
        c10.set("host", req.url?.host ?? "")
        if j["seat"] != nil { c10.flag("sentSeat") }
        switch recoverStatus {
        case 200: return (200, ["ok": true])
        case 501: return (501, ["error": "recovery_unconfigured"])
        case 429: return (429, ["error": "rate_limited"])
        case 400: return (400, ["error": "invalid_params"])
        default: return (recoverStatus, ["error": "boom"])
        }
    }
    let kit10 = makeCheckoutKit(vault: "s10")
    func recover(_ email: String) -> SeatStampManager.RecoveryOutcome? {
        var out: SeatStampManager.RecoveryOutcome?
        kit10.requestKeyRecovery(email: email) { out = $0 }
        pumpMainRunLoop(until: 5.0) { out != nil }
        return out
    }

    var sawInFlight = false
    let recoverSink = kit10.$isRequestingKeyRecovery.sink { if $0 { sawInFlight = true } }
    check(recover("  Buyer@Example.com ") == .sent, "200 from recover -> .sent")
    recoverSink.cancel()
    check(sawInFlight && !kit10.isRequestingKeyRecovery, "isRequestingKeyRecovery toggles true during the request and false after")
    check(c10.string("email") == "Buyer@Example.com" && !c10.isSet("sentSeat"), "recover posts the trimmed email as typed, without a seat field")
    check(!kit10.isActivatingOnline && !kit10.isAwaitingBrowserCheckout, "recovery never touches activation or checkout state")

    recoverStatus = 501
    check(recover("buyer@example.com") == .unconfigured, "501 -> .unconfigured")
    recoverStatus = 429
    check(recover("buyer@example.com") == .rateLimited, "429 -> .rateLimited")
    recoverStatus = 400
    check(recover("buyer@example.com") == .invalidEmail, "400 -> .invalidEmail")
    recoverStatus = 503
    check(recover("buyer@example.com") == .networkError, "5xx on the only endpoint -> .networkError")
    let callsBeforeLocal = c10.int("recover")
    check(recover("not-an-email") == .invalidEmail && c10.int("recover") == callsBeforeLocal, "client-side invalid email short-circuits without a network call")

    // Failover: first endpoint 503, second endpoint 200 -> .sent
    recoverStatus = 200
    let failoverKit = makeCheckoutKit(vault: "s10b", endpoints: [URL(string: "https://down.testapp.example")!, endpoint])
    MockCheckoutURLProtocol.setImmediateHandler { req, body in
        if req.url?.host == "down.testapp.example" { return (503, ["error": "down"]) }
        c10.bump("failoverHits")
        return (200, ["ok": true])
    }
    var failoverOutcome: SeatStampManager.RecoveryOutcome?
    failoverKit.requestKeyRecovery(email: "buyer@example.com") { failoverOutcome = $0 }
    pumpMainRunLoop(until: 5.0) { failoverOutcome != nil }
    check(failoverOutcome == .sent && c10.int("failoverHits") == 1, "recovery fails over from a 5xx endpoint to the next one")

    // Nothing about the email is persisted anywhere the SDK writes
    let s10Dir = chkRoot.appendingPathComponent("s10", isDirectory: true)
    let vaultBytes = (try? Data(contentsOf: s10Dir.appendingPathComponent(".license_vault"))) ?? Data()
    let sealBytes = (try? Data(contentsOf: s10Dir.appendingPathComponent(".vault_seal"))) ?? Data()
    let defaultsDump = suite.dictionaryRepresentation().description.lowercased()
    check(!String(decoding: vaultBytes, as: UTF8.self).lowercased().contains("example.com")
          && !String(decoding: sealBytes, as: UTF8.self).lowercased().contains("example.com")
          && !defaultsDump.contains("example.com"), "recovery email is never written to vault, seal, or UserDefaults")
    let noEndpointKit = makeCheckoutKit(vault: "s10c", endpoints: [])
    var noEndpointOutcome: SeatStampManager.RecoveryOutcome?
    noEndpointKit.requestKeyRecovery(email: "buyer@example.com") { noEndpointOutcome = $0 }
    check(noEndpointOutcome == .unconfigured, "no activation endpoints -> .unconfigured synchronously")

    // 11) 429 release_limit on deactivate is terminal: the queued deactivation is dropped, the purchase key stays
    //     available, and seatReleaseBlockedUntil is published.
    let suite11Name = "com.example.checkout.release.\(UUID().uuidString)"
    let suite11 = UserDefaults(suiteName: suite11Name)!
    defer { suite11.removePersistentDomain(forName: suite11Name) }
    let c11 = TestCounters()
    let key11 = "cs_live_releaseLimitClient000000000011"
    fakeNow += 5
    let ticket11 = try seatTicket(tag: "ORD-RELEASE000000011", issued: fakeNow, seat: seatCode)
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        switch json(body)["action"] as? String {
        case "activate":
            return (200, ["ticket": ticket11, "seatsUsed": 1, "maxSeats": 2, "revokedBefore": 0])
        case "deactivate":
            c11.bump("deactivate")
            return (429, ["error": "release_limit", "retryAfterSec": 86_400])
        default:
            return (400, ["error": "unexpected"])
        }
    }
    let kit11 = makeCheckoutKit(vault: "s11", defaults: suite11)
    var outcome11: SeatStampManager.ActivationOutcome?
    kit11.activate(key: key11) { outcome11 = $0 }
    pumpMainRunLoop(until: 5.0) { outcome11 != nil }
    check(outcome11 == .activated && kit11.seatReleaseBlockedUntil == nil, "release_limit setup: kit activates through the mock")
    kit11.deactivate()
    pumpMainRunLoop(until: 5.0) { kit11.seatReleaseBlockedUntil != nil }
    let blockedUntil = kit11.seatReleaseBlockedUntil?.timeIntervalSince1970 ?? 0
    check(abs(blockedUntil - TimeInterval(fakeNow + 86_400)) <= 2, "429 release_limit publishes seatReleaseBlockedUntil about retryAfterSec after now")
    check(kit11.shareableLicenseKey == key11 && !kit11.isLicensed, "429 release_limit keeps the purchase key available for re-activation")
    check(c11.int("deactivate") == 1, "429 release_limit is not retried")
    let kit11b = makeCheckoutKit(vault: "s11", defaults: suite11)
    pumpMainRunLoop(until: 2.5) { false }
    check(c11.int("deactivate") == 1 && kit11b.shareableLicenseKey == key11, "relaunch after release_limit sends no deactivate request and keeps the key")

    // 12) Server responses are checked against the sealed watermark and never lower it.
    let suite12Name = "com.example.checkout.watermark.\(UUID().uuidString)"
    let suite12 = UserDefaults(suiteName: suite12Name)!
    defer { suite12.removePersistentDomain(forName: suite12Name) }
    let c12 = TestCounters()
    let key12 = "cs_live_watermarkReplay0000000000000012"
    fakeNow += 5
    let oldTicket12 = try seatTicket(tag: "ORD-WATERMARK0000012", issued: fakeNow, seat: seatCode)
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        let j = json(body)
        switch j["action"] as? String {
        case "activate":
            c12.bump("activate")
            if let n = j["minIssued"] as? NSNumber { c12.set("minIssued", n.stringValue) } else { c12.set("minIssued", "absent") }
            return (200, ["ticket": oldTicket12, "seatsUsed": 1, "maxSeats": 2, "revokedBefore": 0])
        case "claim_checkout":
            c12.bump("claims")
            return (200, activatedBody(key: key12, ticket: oldTicket12))
        default:
            return (200, ["ok": true, "revokedBefore": fakeNow])
        }
    }
    let kit12 = makeCheckoutKit(vault: "s12", defaults: suite12)
    var outcome12: SeatStampManager.ActivationOutcome?
    kit12.activate(key: key12) { outcome12 = $0 }
    pumpMainRunLoop(until: 5.0) { outcome12 != nil }
    check(outcome12 == .activated && c12.string("minIssued") == "absent", "a fresh kit sends no minIssued field")
    kit12.deactivate()
    outcome12 = nil
    kit12.activate(key: key12) { outcome12 = $0 }
    pumpMainRunLoop(until: 5.0) { outcome12 != nil }
    let sentMinIssued = Int64(c12.string("minIssued")) ?? 0
    check(outcome12 == .clockSkew && !kit12.isLicensed, "an old ticket in a 200 response after Deactivate -> .clockSkew and the kit stays unlicensed")
    check(sentMinIssued > fakeNow, "activate sends a numeric minIssued above the released ticket's issued")

    var outcome12c: SeatStampManager.ActivationOutcome?
    _ = kit12.beginBrowserCheckout(paymentLink: paymentLink, openURL: { _ in }, onOutcome: { outcome12c = $0 })
    pumpMainRunLoop(until: 5.0) { outcome12c != nil }
    pumpMainRunLoop(until: 0.1) { false }
    check(outcome12c == .clockSkew && !kit12.isLicensed && !kit12.isAwaitingBrowserCheckout && c12.int("claims") == 1, "claim_checkout with an old ticket -> .clockSkew and polling stops")

    // 13) A Deactivate with the clock far ahead writes a cutoff that a server ticket can still reach.
    let suite13Name = "com.example.checkout.skew.\(UUID().uuidString)"
    let suite13 = UserDefaults(suiteName: suite13Name)!
    defer { suite13.removePersistentDomain(forName: suite13Name) }
    let key13 = "cs_live_deactivateClockAhead0000000013"
    fakeNow += 5
    let baseNow13 = fakeNow
    let first13 = try seatTicket(tag: "ORD-CLOCKAHEAD000013", issued: baseNow13, seat: seatCode)
    let ahead13 = try seatTicket(tag: "ORD-CLOCKAHEAD000013", issued: baseNow13 + 366 * 86_400, seat: seatCode)
    var reply13 = first13
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        switch json(body)["action"] as? String {
        case "activate": return (200, ["ticket": reply13, "seatsUsed": 1, "maxSeats": 2, "revokedBefore": 0])
        default: return (200, ["ok": true, "revokedBefore": baseNow13])
        }
    }
    let kit13 = makeCheckoutKit(vault: "s13", defaults: suite13)
    var outcome13: SeatStampManager.ActivationOutcome?
    kit13.activate(key: key13) { outcome13 = $0 }
    pumpMainRunLoop(until: 5.0) { outcome13 != nil }
    check(outcome13 == .activated, "clock-ahead setup: kit activates")
    fakeNow = baseNow13 + 2 * 365 * 86_400
    kit13.deactivate()
    fakeNow = baseNow13
    reply13 = ahead13
    outcome13 = nil
    kit13.activate(key: key13) { outcome13 = $0 }
    pumpMainRunLoop(until: 5.0) { outcome13 != nil }
    check(outcome13 == .activated && kit13.isLicensed, "after Deactivate with the clock 2 years ahead, a ticket issued 366 days ahead still activates")
    pumpMainRunLoop(until: 0.2) { false }

    // 14) 500 signing_error on deactivate is not terminal: the queued deactivation survives a relaunch.
    let suite14Name = "com.example.checkout.signing.\(UUID().uuidString)"
    let suite14 = UserDefaults(suiteName: suite14Name)!
    defer { suite14.removePersistentDomain(forName: suite14Name) }
    let c14 = TestCounters()
    let key14 = "cs_live_signingErrorKeepsQueue000000014"
    fakeNow += 5
    let ticket14 = try seatTicket(tag: "ORD-SIGNING000000014", issued: fakeNow, seat: seatCode)
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        let j = json(body)
        switch j["action"] as? String {
        case "activate":
            return (200, ["ticket": ticket14, "seatsUsed": 1, "maxSeats": 2, "revokedBefore": 0])
        case "deactivate":
            if (j["key"] as? String) == key14 { c14.bump("deactivate") }
            return (500, ["error": "signing_error"])
        default:
            return (400, ["error": "unexpected"])
        }
    }
    let kit14 = makeCheckoutKit(vault: "s14", defaults: suite14)
    var outcome14: SeatStampManager.ActivationOutcome?
    kit14.activate(key: key14) { outcome14 = $0 }
    pumpMainRunLoop(until: 5.0) { outcome14 != nil }
    kit14.deactivate()
    pumpMainRunLoop(until: 5.0) { c14.int("deactivate") >= 1 }
    pumpMainRunLoop(until: 0.1) { false }
    check(outcome14 == .activated && c14.int("deactivate") == 1, "500 signing_error setup: one deactivate request was answered with 500")
    let kit14b = makeCheckoutKit(vault: "s14", defaults: suite14)
    pumpMainRunLoop(until: 3.0) { c14.int("deactivate") >= 2 }
    check(c14.int("deactivate") >= 2 && !kit14b.isLicensed, "after 500 signing_error a relaunched kit sends the queued deactivate again")
} catch {
    check(false, "Default-Browser Checkout Handoff test threw: \(error)")
}

// MARK: - 5a1. License key rotation (retired license keys and silent re-activation)

section("License key rotation")
do {
    let rotRoot = FileManager.default.temporaryDirectory.appendingPathComponent("seatstamp-rotation-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: rotRoot) }
    var rotSuiteNames: [String] = []
    defer { for name in rotSuiteNames { UserDefaults.standard.removePersistentDomain(forName: name) } }
    var rotSuites: [String: UserDefaults] = [:]
    func rotSuite(_ name: String) -> UserDefaults {
        if let existing = rotSuites[name] { return existing }
        let suiteName = "com.example.selftest.rotation.\(name).\(UUID().uuidString)"
        rotSuiteNames.append(suiteName)
        let created = UserDefaults(suiteName: suiteName)!
        rotSuites[name] = created
        return created
    }

    var rotNow: Int64 = 1_765_000_000
    let rotHW = "13131313-2424-3535-4646-575757575757"
    let k1 = Curve25519.Signing.PrivateKey()
    let k2 = Curve25519.Signing.PrivateKey()
    let k1B64 = k1.publicKey.rawRepresentation.base64EncodedString()
    let k2B64 = k2.publicKey.rawRepresentation.base64EncodedString()
    let rotEndpoint = URL(string: "https://activate.testapp.example")!
    let rotCfg = URLSessionConfiguration.ephemeral
    rotCfg.protocolClasses = [MockCheckoutURLProtocol.self]
    let rotSession = URLSession(configuration: rotCfg)
    let rotSeat = TrialSeal.seatCode(hardwareUUID: rotHW, domain: "com.example.testapp.seat.v1|")

    func makeRotKit(_ name: String, current: String, retired: [String] = [], endpoints: [URL] = [rotEndpoint]) -> SeatStampManager {
        let dir = rotRoot.appendingPathComponent(name, isDirectory: true)
        return SeatStampManager(
            scheme: "TESTAPP-V1",
            licensePublicKeyBase64: current,
            retiredLicensePublicKeysBase64: retired,
            activationEndpoints: endpoints,
            trialLengthDays: 30,
            maxSeats: 2,
            bundleID: "com.example.testapp",
            testingOverrides: .init(
                defaults: rotSuite(name),
                fileAnchorURLs: [dir.appendingPathComponent(".vault_seal")],
                vaultFileURL: dir.appendingPathComponent(".license_vault"),
                hardwareUUID: rotHW,
                useKeychain: false,
                healSynchronously: true,
                now: { Date(timeIntervalSince1970: TimeInterval(rotNow)) },
                urlSession: rotSession,
                retiredKeyRetryInterval: 0.02
            )
        )
    }
    func rotTicket(_ key: Curve25519.Signing.PrivateKey, tag: String, issued: Int64, seat: String?) throws -> String {
        let payload = LicenseTicket.canonicalPayload(scheme: "TESTAPP-V1", tag: tag, issued: issued, seat: seat)
        return LicenseTicket.encode(payload: payload, signature: try key.signature(for: Data(payload.utf8)))
    }
    /// Writes a K1 ticket and a purchase key into the vault `name` through a kit that trusts K1.
    func seedK1Vault(_ name: String, purchaseKey: String, tag: String) throws -> String {
        let ticket = try rotTicket(k1, tag: tag, issued: rotNow, seat: rotSeat)
        let seeder = makeRotKit(name, current: k1B64, endpoints: [])
        check(seeder.activateOfflineTicket(ticket, parentSeatKey: purchaseKey), "rotation setup '\(name)': K1 ticket activates under K1")
        return ticket
    }
    func rotJSON(_ body: Data) -> [String: Any] {
        (try? JSONSerialization.jsonObject(with: body) as? [String: Any]) ?? [:]
    }

    // (a) The background re-activation installs a K2 ticket on the same seat.
    rotNow += 10
    let keyA = "cs_live_rotationReactivate00000000000a1"
    _ = try seedK1Vault("a", purchaseKey: keyA, tag: "ORD-R0TA000000000001")
    rotNow += 10
    let ticketK2A = try rotTicket(k2, tag: "ORD-R0TA000000000001", issued: rotNow, seat: rotSeat)
    let ca = TestCounters()
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        let j = rotJSON(body)
        guard (j["action"] as? String) == "activate", (j["key"] as? String) == keyA else { return (400, ["error": "unexpected"]) }
        ca.bump("activate")
        if (j["seat"] as? String) == rotSeat { ca.flag("seat") }
        return (200, ["ticket": ticketK2A, "seatsUsed": 1, "maxSeats": 2, "revokedBefore": 0])
    }
    let kitA = makeRotKit("a", current: k2B64, retired: [k1B64])
    check(kitA.isLicensed && kitA.licenseNeedsReactivation && kitA.retiredKeyGraceEndsAt != nil, "a K1 ticket under a K2 kit with K1 retired starts licensed and needs re-activation")
    pumpMainRunLoop(until: 5.0) { !kitA.licenseNeedsReactivation }
    check(ca.int("activate") == 1 && ca.isSet("seat"), "the re-activation posts activate once with the stored purchase key and this seat")
    check(kitA.isLicensed && !kitA.licenseNeedsReactivation && kitA.retiredKeyGraceEndsAt == nil, "(a) a K2 ticket from the server ends the grace period")
    check(makeRotKit("a", current: k2B64, endpoints: []).isLicensed, "(a) a kit with K2 and no retired keys is licensed after the re-activation")

    // (b) Server unreachable: licensed during the grace period, unlicensed after it, purchase key kept.
    rotNow += 10
    let keyB = "cs_live_rotationGraceExpiry0000000000b1"
    _ = try seedK1Vault("b", purchaseKey: keyB, tag: "ORD-R0TB000000000001")
    let cb = TestCounters()
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        if (rotJSON(body)["key"] as? String) == keyB { cb.bump("activate") }
        return (503, ["error": "down"])
    }
    let kitB = makeRotKit("b", current: k2B64, retired: [k1B64])
    pumpMainRunLoop(until: 5.0) { cb.int("activate") >= 2 }
    check(cb.int("activate") >= 2, "a 503 answer is retried")
    check(kitB.isLicensed && kitB.licenseNeedsReactivation, "(b) a 503 answer keeps the kit licensed with licenseNeedsReactivation")
    rotNow += 31 * 86_400
    let kitB2 = makeRotKit("b", current: k2B64, retired: [k1B64])
    check(!kitB2.isLicensed && !kitB2.licenseNeedsReactivation, "(b) past 30 days a new kit starts unlicensed")
    check(kitB2.shareableLicenseKey == keyB, "(b) the purchase key is kept after the grace period")
    pumpMainRunLoop(until: 0.2) { false }
    check(!kitB.isLicensed, "the running kit drops the ticket once the grace period is over")

    // (c) 403 invalid_key drops the license at once.
    rotNow += 10
    let keyC = "cs_live_rotationInvalidKey000000000000c1"
    _ = try seedK1Vault("c", purchaseKey: keyC, tag: "ORD-R0TC000000000001")
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        (rotJSON(body)["key"] as? String) == keyC ? (403, ["error": "invalid_key"]) : (503, ["error": "down"])
    }
    let kitC = makeRotKit("c", current: k2B64, retired: [k1B64])
    check(kitC.isLicensed, "(c) setup: licensed during grace before the answer")
    pumpMainRunLoop(until: 5.0) { !kitC.isLicensed }
    check(!kitC.isLicensed && !kitC.licenseNeedsReactivation, "(c) 403 invalid_key drops the license after pumping")

    // (d) A K1 ticket never activates on a K2 kit, even with K1 retired.
    rotNow += 10
    let freshK1 = try rotTicket(k1, tag: "ORD-R0TD000000000001", issued: rotNow, seat: rotSeat)
    let kitD = makeRotKit("d", current: k2B64, retired: [k1B64], endpoints: [])
    check(!kitD.activateOfflineTicket(freshK1), "(d) activateOfflineTicket refuses a ticket signed by a retired key")
    check(!kitD.activateOfflineTicket(freshK1, parentSeatKey: "cs_live_rotationServerResponse00000000d1"), "a server response signed by a retired key is refused")

    // (e) Without the retired list a K1 vault starts unlicensed.
    rotNow += 10
    _ = try seedK1Vault("e", purchaseKey: "cs_live_rotationNoRetiredList0000000000e1", tag: "ORD-R0TE000000000001")
    check(!makeRotKit("e", current: k2B64, endpoints: []).isLicensed, "(e) a K2 kit without retired keys starts unlicensed on a K1 vault")

    // (f) A revocation of an unrelated tag during grace keeps the license.
    rotNow += 10
    _ = try seedK1Vault("f", purchaseKey: "cs_live_rotationUnrelatedRevoke00000000f1", tag: "ORD-R0TF000000000001")
    let kitF = makeRotKit("f", current: k2B64, retired: [k1B64], endpoints: [])
    kitF.recordRevokedOrderTags(["ORD-UNRELATED"])
    check(kitF.isLicensed && kitF.licenseNeedsReactivation, "(f) recordRevokedOrderTags of an unrelated tag keeps a grace-period license")
    kitF.recordRevokedOrderTags(["ORD-R0TF000000000001"])
    check(!kitF.isLicensed && !kitF.licenseNeedsReactivation, "revoking the tag of a grace-period ticket drops it")

    // (g) With the trial expired, the gate closes at the deadline without a relaunch.
    rotNow += 10
    _ = makeRotKit("g", current: k1B64, endpoints: [])
    rotNow += 40 * 86_400
    _ = try seedK1Vault("g", purchaseKey: "cs_live_rotationGateDeadline00000000g1", tag: "ORD-R0TG000000000001")
    let kitG = makeRotKit("g", current: k2B64, retired: [k1B64], endpoints: [])
    check(kitG.isTrialExpired == false && kitG.verifyGateAccess(), "(g) setup: the gate is open during grace")
    rotNow += 30 * 86_400 + 1
    check(!kitG.verifyGateAccess(), "(g) verifyGateAccess closes once the clock passes the grace deadline")
    kitG.refreshMonotonicClockIfNeeded()
    check(!kitG.isLicensed && kitG.orderTag.isEmpty && kitG.maskedKey.isEmpty, "refreshMonotonicClockIfNeeded drops the ticket after the deadline")
} catch {
    check(false, "License key rotation test threw: \(error)")
}

// MARK: - 5a1b. Queued deactivation (retry while running, survive a new activation)

section("Queued deactivation")
do {
    let qRoot = FileManager.default.temporaryDirectory.appendingPathComponent("seatstamp-queue-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: qRoot) }
    var qSuiteNames: [String] = []
    defer { for name in qSuiteNames { UserDefaults.standard.removePersistentDomain(forName: name) } }
    var qSuites: [String: UserDefaults] = [:]
    func qSuite(_ name: String) -> UserDefaults {
        if let existing = qSuites[name] { return existing }
        let suiteName = "com.example.selftest.queue.\(name).\(UUID().uuidString)"
        qSuiteNames.append(suiteName)
        let created = UserDefaults(suiteName: suiteName)!
        qSuites[name] = created
        return created
    }

    var qNow: Int64 = 1_766_000_000
    let qHW = "35353535-4646-5757-6868-797979797979"
    let qLic = Curve25519.Signing.PrivateKey()
    let qPubB64 = qLic.publicKey.rawRepresentation.base64EncodedString()
    let qEndpoint = URL(string: "https://activate.testapp.example")!
    let qCfg = URLSessionConfiguration.ephemeral
    qCfg.protocolClasses = [MockCheckoutURLProtocol.self]
    let qSession = URLSession(configuration: qCfg)
    let qSeat = TrialSeal.seatCode(hardwareUUID: qHW, domain: "com.example.testapp.seat.v1|")

    func qVaultURL(_ name: String) -> URL { qRoot.appendingPathComponent("\(name)/.license_vault") }
    func makeQKit(_ name: String, retry: TimeInterval = 0.02, endpoints: [URL] = [qEndpoint]) -> SeatStampManager {
        let dir = qRoot.appendingPathComponent(name, isDirectory: true)
        return SeatStampManager(
            scheme: "TESTAPP-V1",
            licensePublicKeyBase64: qPubB64,
            activationEndpoints: endpoints,
            trialLengthDays: 30,
            maxSeats: 2,
            bundleID: "com.example.testapp",
            testingOverrides: .init(
                defaults: qSuite(name),
                fileAnchorURLs: [dir.appendingPathComponent(".vault_seal")],
                vaultFileURL: qVaultURL(name),
                hardwareUUID: qHW,
                useKeychain: false,
                healSynchronously: true,
                now: { Date(timeIntervalSince1970: TimeInterval(qNow)) },
                urlSession: qSession,
                deactivationRetryInterval: retry
            )
        )
    }
    func qTicket(tag: String, seat: String?) throws -> String {
        qNow += 5
        let payload = LicenseTicket.canonicalPayload(scheme: "TESTAPP-V1", tag: tag, issued: qNow, seat: seat)
        return LicenseTicket.encode(payload: payload, signature: try qLic.signature(for: Data(payload.utf8)))
    }
    func qJSON(_ body: Data) -> [String: Any] {
        (try? JSONSerialization.jsonObject(with: body) as? [String: Any]) ?? [:]
    }

    // One mock for the whole section: activate answers with the ticket registered for the key; deactivate answers
    // with the current status and logs every request per key, plus the order of the ones answered with 200.
    let qc = TestCounters()
    var qTickets: [String: String] = [:]
    var deactReply: (Int, [String: Any]) = (503, ["error": "down"])
    MockCheckoutURLProtocol.setImmediateHandler { _, body in
        let j = qJSON(body)
        let key = (j["key"] as? String) ?? ""
        switch j["action"] as? String {
        case "activate":
            guard let ticket = qTickets[key] else { return (403, ["error": "invalid_key"]) }
            return (200, ["ticket": ticket, "seatsUsed": 1, "maxSeats": 2, "revokedBefore": 0])
        case "deactivate":
            qc.bump("deact:\(key)")
            if (j["seat"] as? String) == qSeat { qc.flag("seat:\(key)") }
            if let t = j["ticket"] as? String, t.hasPrefix("LK1-") { qc.flag("ticket:\(key)") }
            let reply = deactReply
            if reply.0 == 200 { qc.set("order", qc.string("order") + key + ";") }
            return reply
        default:
            return (400, ["error": "unexpected"])
        }
    }
    func qActivate(_ kit: SeatStampManager, _ key: String) -> SeatStampManager.ActivationOutcome? {
        var outcome: SeatStampManager.ActivationOutcome?
        kit.activate(key: key) { outcome = $0 }
        pumpMainRunLoop(until: 5.0) { outcome != nil }
        return outcome
    }
    func deacts(_ key: String) -> Int { qc.int("deact:\(key)") }

    // (a) The deactivate request carries key, seat, and ticket.
    let keyQA = "cs_live_queueCarriesFields0000000000qa1"
    qTickets[keyQA] = try qTicket(tag: "ORD-QA00000000000001", seat: qSeat)
    deactReply = (200, ["ok": true, "revokedBefore": qNow])
    let kitQA = makeQKit("a")
    check(qActivate(kitQA, keyQA) == .activated, "queue (a) setup: activated")
    kitQA.deactivate()
    pumpMainRunLoop(until: 5.0) { deacts(keyQA) >= 1 }
    check(deacts(keyQA) == 1 && qc.isSet("seat:\(keyQA)") && qc.isSet("ticket:\(keyQA)"), "(a) the deactivate request carries key, seat, and ticket")

    // (b) 503 then 200: the retry delivers it in the same session; a relaunch sends nothing.
    let keyQB = "cs_live_queueRetriesUntilOk0000000000qb1"
    qTickets[keyQB] = try qTicket(tag: "ORD-QB00000000000001", seat: qSeat)
    let kitQB = makeQKit("b")
    check(qActivate(kitQB, keyQB) == .activated, "queue (b) setup: activated")
    deactReply = (503, ["error": "down"])
    kitQB.deactivate()
    pumpMainRunLoop(until: 5.0) { deacts(keyQB) >= 2 }
    check(deacts(keyQB) >= 2, "(b) a 503 answer is retried while the app runs")
    deactReply = (200, ["ok": true, "revokedBefore": qNow])
    pumpMainRunLoop(until: 5.0) { qc.string("order").contains(keyQB) }
    check(qc.string("order").contains(keyQB), "(b) the retry delivers the deactivation in the same session")
    pumpMainRunLoop(until: 0.1) { false }
    let afterB = deacts(keyQB)
    _ = makeQKit("b")
    pumpMainRunLoop(until: 0.3) { false }
    check(deacts(keyQB) == afterB, "(b) a new kit on that vault sends nothing")

    // (c) 403 invalid_ticket removes the entry after one request.
    let keyQC = "cs_live_queueInvalidTicketDrops00000qc1"
    qTickets[keyQC] = try qTicket(tag: "ORD-QC00000000000001", seat: qSeat)
    let kitQC = makeQKit("c")
    check(qActivate(kitQC, keyQC) == .activated, "queue (c) setup: activated")
    deactReply = (403, ["error": "invalid_ticket"])
    kitQC.deactivate()
    pumpMainRunLoop(until: 5.0) { deacts(keyQC) >= 1 }
    pumpMainRunLoop(until: 0.3) { false }
    check(deacts(keyQC) == 1, "(c) 403 invalid_ticket removes the entry after one request")

    // (d) 500 signing_error keeps the entry and retries.
    let keyQD = "cs_live_queueSigningErrorRetries0000qd1"
    qTickets[keyQD] = try qTicket(tag: "ORD-QD00000000000001", seat: qSeat)
    let kitQD = makeQKit("d")
    check(qActivate(kitQD, keyQD) == .activated, "queue (d) setup: activated")
    deactReply = (500, ["error": "signing_error"])
    kitQD.deactivate()
    pumpMainRunLoop(until: 5.0) { deacts(keyQD) >= 3 }
    check(deacts(keyQD) >= 3, "(d) 500 signing_error keeps the entry and retries")
    deactReply = (200, ["ok": true, "revokedBefore": qNow])
    pumpMainRunLoop(until: 5.0) { qc.string("order").contains(keyQD) }

    // (e) A queued deactivation for key A survives the activation of key B.
    let keyQEA = "cs_live_queueSurvivesOtherKeyA00000qea1"
    let keyQEB = "cs_live_queueSurvivesOtherKeyB00000qeb1"
    qTickets[keyQEA] = try qTicket(tag: "ORD-QEA0000000000001", seat: qSeat)
    let kitQE = makeQKit("e")
    check(qActivate(kitQE, keyQEA) == .activated, "queue (e) setup: key A activated")
    deactReply = (503, ["error": "down"])
    kitQE.deactivate()
    pumpMainRunLoop(until: 5.0) { deacts(keyQEA) >= 1 }
    qTickets[keyQEB] = try qTicket(tag: "ORD-QEB0000000000001", seat: qSeat)
    check(qActivate(kitQE, keyQEB) == .activated && kitQE.isLicensed, "(e) key B activates while A's deactivation is queued")
    deactReply = (200, ["ok": true, "revokedBefore": qNow])
    pumpMainRunLoop(until: 5.0) { qc.string("order").contains(keyQEA) }
    check(qc.string("order").contains(keyQEA), "(e) the deactivation for key A still arrives after key B was activated")
    check(kitQE.isLicensed && kitQE.orderTag == "ORD-QEB0000000000001", "(e) the kit stays licensed with key B")

    // (f) Re-activating the same purchase cancels its queued deactivation.
    let keyQF = "cs_live_queueSamePurchaseCancels0000qf1"
    qTickets[keyQF] = try qTicket(tag: "ORD-QF00000000000001", seat: qSeat)
    let kitQF = makeQKit("f")
    check(qActivate(kitQF, keyQF) == .activated, "queue (f) setup: activated")
    deactReply = (503, ["error": "down"])
    kitQF.deactivate()
    pumpMainRunLoop(until: 5.0) { deacts(keyQF) >= 1 }
    qTickets[keyQF] = try qTicket(tag: "ORD-QF00000000000001", seat: qSeat)
    check(qActivate(kitQF, keyQF) == .activated, "(f) the same key activates again")
    let afterF = deacts(keyQF)
    deactReply = (200, ["ok": true, "revokedBefore": qNow])
    pumpMainRunLoop(until: 0.4) { false }
    check(deacts(keyQF) == afterF && kitQF.isLicensed, "(f) no deactivate for the re-activated key is sent afterwards")

    // (g) Becoming the active app triggers a flush.
    let keyQG = "cs_live_queueFlushOnAppFocus000000000qg1"
    qTickets[keyQG] = try qTicket(tag: "ORD-QG00000000000001", seat: qSeat)
    let kitQG = makeQKit("g", retry: 60)
    check(qActivate(kitQG, keyQG) == .activated, "queue (g) setup: activated")
    deactReply = (503, ["error": "down"])
    kitQG.deactivate()
    pumpMainRunLoop(until: 5.0) { deacts(keyQG) >= 1 }
    pumpMainRunLoop(until: 0.2) { false }
    check(deacts(keyQG) == 1, "(g) with a 60 s retry no second request has been sent yet")
    NotificationCenter.default.post(name: NSApplication.didBecomeActiveNotification, object: nil)
    pumpMainRunLoop(until: 5.0) { deacts(keyQG) >= 2 }
    check(deacts(keyQG) == 2, "(g) NSApplication.didBecomeActiveNotification triggers a flush")
    deactReply = (200, ["ok": true, "revokedBefore": qNow])
    NotificationCenter.default.post(name: NSApplication.didBecomeActiveNotification, object: nil)
    pumpMainRunLoop(until: 5.0) { qc.string("order").contains(keyQG) }

    // (h) Two queued deactivations are delivered in order.
    let keyQHA = "cs_live_queueTwoInOrderKeyA000000000qha1"
    let keyQHB = "cs_live_queueTwoInOrderKeyB000000000qhb1"
    qTickets[keyQHA] = try qTicket(tag: "ORD-QHA0000000000001", seat: qSeat)
    let kitQH = makeQKit("h")
    deactReply = (503, ["error": "down"])
    check(qActivate(kitQH, keyQHA) == .activated, "queue (h) setup: key A activated")
    kitQH.deactivate()
    pumpMainRunLoop(until: 5.0) { deacts(keyQHA) >= 1 }
    qTickets[keyQHB] = try qTicket(tag: "ORD-QHB0000000000001", seat: qSeat)
    check(qActivate(kitQH, keyQHB) == .activated, "queue (h) setup: key B activated")
    kitQH.deactivate()
    pumpMainRunLoop(until: 5.0) { deacts(keyQHB) >= 1 }
    qc.set("order", "")
    deactReply = (200, ["ok": true, "revokedBefore": qNow])
    pumpMainRunLoop(until: 5.0) { qc.string("order").contains(keyQHB) }
    check(qc.string("order") == "\(keyQHA);\(keyQHB);", "(h) both queued deactivations arrive after recovery, A first")

    // shareableLicenseKey never returns a ticket bound to this Mac.
    let kitShare = makeQKit("share", endpoints: [])
    let boundShare = try qTicket(tag: "ORD-SHARE00000000001", seat: qSeat)
    check(kitShare.activateOfflineTicket(boundShare) && kitShare.shareableLicenseKey == nil,
          "shareableLicenseKey is nil for a seat-bound ticket activated without a purchase key")
    let universalShare = try qTicket(tag: "ORD-SHARE00000000002", seat: nil)
    check(kitShare.activateOfflineTicket(universalShare) && kitShare.shareableLicenseKey == universalShare, "shareableLicenseKey returns a universal ticket")
    check(makeQKit("share", endpoints: []).shareableLicenseKey == universalShare, "shareableLicenseKey returns a universal ticket after relaunch")
    let parentShare = try qTicket(tag: "ORD-SHARE00000000003", seat: qSeat)
    check(kitShare.activateOfflineTicket(parentShare, parentSeatKey: "cs_live_shareableParentKey00000000000s1")
          && kitShare.shareableLicenseKey == "cs_live_shareableParentKey00000000000s1", "shareableLicenseKey returns the purchase key when one exists")
} catch {
    check(false, "Queued deactivation test threw: \(error)")
}

// MARK: - 5a2. Verified update download (downloadAndVerifyUpdate)

/// Answers every request with a fixed status and body; counts requests.
final class MockDownloadURLProtocol: URLProtocol {
    static let lock = NSLock()
    private static var status = 200
    private static var body = Data()
    private static var count = 0

    static func configure(status: Int, body: Data) {
        lock.lock(); self.status = status; self.body = body; lock.unlock()
    }

    static var requestCount: Int {
        lock.lock(); defer { lock.unlock() }
        return count
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()
        Self.count += 1
        let status = Self.status
        let body = Self.body
        Self.lock.unlock()
        let resp = HTTPURLResponse(
            url: request.url ?? URL(string: "https://testapp.example/")!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/octet-stream", "Content-Length": String(body.count)]
        )!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

section("Verified update download")
do {
    let dlRoot = FileManager.default.temporaryDirectory.appendingPathComponent("seatstamp-download-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: dlRoot) }
    try FileManager.default.createDirectory(at: dlRoot, withIntermediateDirectories: true)
    let dlSuiteName = "com.example.selftest.download.\(UUID().uuidString)"
    let dlSuite = UserDefaults(suiteName: dlSuiteName)!
    defer { dlSuite.removePersistentDomain(forName: dlSuiteName) }

    let dlLicKey = Curve25519.Signing.PrivateKey()
    let dlUpdKey = Curve25519.Signing.PrivateKey()
    let dlKit = SeatStampManager(
        scheme: "DLTEST-V1",
        licensePublicKeyBase64: dlLicKey.publicKey.rawRepresentation.base64EncodedString(),
        updatePublicKeyBase64: dlUpdKey.publicKey.rawRepresentation.base64EncodedString(),
        bundleID: "com.example.dltest",
        testingOverrides: .init(
            defaults: dlSuite,
            fileAnchorURLs: [dlRoot.appendingPathComponent("anchors/.vault_seal")],
            vaultFileURL: dlRoot.appendingPathComponent("anchors/.license_vault")
        )
    )
    let dlCfg = URLSessionConfiguration.ephemeral
    dlCfg.protocolClasses = [MockDownloadURLProtocol.self]
    let dlSession = URLSession(configuration: dlCfg)

    let dlURL = "https://testapp.example/download/TestApp-2.0.0.dmg"
    let dlBytes = Data((0..<5000).map { UInt8(truncatingIfNeeded: $0 &* 7) })
    let dlSha = SHA256.hash(data: dlBytes).map { String(format: "%02x", $0) }.joined()

    func signedArtifactManifest(sha256: String?, size: Int64?) throws -> Data {
        let canon = UpdateManifest.canonicalSigningData(
            scheme: "DLTEST-UPDATE-V1", version: "2.0.0", url: dlURL, summary: "Two", notes: [],
            summaryI18n: [:], notesI18n: [:], sha256: sha256, size: size
        )
        var obj: [String: Any] = [
            "version": "2.0.0", "url": dlURL, "summary": "Two",
            "sig": LicenseTicket.base64URLEncode(try dlUpdKey.signature(for: canon))
        ]
        if let sha256 = sha256 { obj["sha256"] = sha256 }
        if let size = size { obj["size"] = size }
        return try JSONSerialization.data(withJSONObject: obj)
    }

    func makeDownloadChecker(_ name: String, manifest: Data) -> (UpdateChecker, URL) {
        let dir = dlRoot.appendingPathComponent(name, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let checker = UpdateChecker(
            kit: dlKit,
            manifestURL: URL(string: "https://testapp.example/version.json")!,
            trustedDownloadHosts: ["testapp.example"],
            currentVersion: "1.0.0",
            defaults: dlSuite,
            urlSession: dlSession,
            downloadDirectory: dir
        )
        check(checker.ingest(data: manifest), "download test manifest '\(name)' ingests")
        return (checker, dir)
    }

    func runDownload(_ checker: UpdateChecker, openURL: ((URL) -> Void)? = nil) -> UpdateChecker.DownloadOutcome? {
        var outcome: UpdateChecker.DownloadOutcome?
        checker.downloadAndVerifyUpdate(openURL: openURL) { outcome = $0 }
        pumpMainRunLoop(until: 10.0) { outcome != nil }
        return outcome
    }

    func dirContents(_ dir: URL) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
    }

    let goodManifest = try signedArtifactManifest(sha256: dlSha, size: Int64(dlBytes.count))

    MockDownloadURLProtocol.configure(status: 200, body: dlBytes)
    let (okChecker, okDir) = makeDownloadChecker("ok", manifest: goodManifest)
    check(okChecker.availableUpdate?.sha256 == dlSha && okChecker.availableUpdate?.size == Int64(dlBytes.count), "AvailableUpdate carries the signed sha256 and size")
    let okOutcome = runDownload(okChecker)
    if case .verified(let savedURL)? = okOutcome {
        check(savedURL.lastPathComponent == "TestApp-2.0.0.dmg" && savedURL.deletingLastPathComponent().standardizedFileURL.path == okDir.standardizedFileURL.path,
              "verified download is saved under the URL's file name in downloadDirectory")
        check((try? Data(contentsOf: savedURL)) == dlBytes, "verified download has the served bytes")
        let qLen = getxattr(savedURL.path, "com.apple.quarantine", nil, 0, 0, 0)
        check(qLen > 0, "verified download carries com.apple.quarantine")
    } else {
        check(false, "correct bytes give .verified (got \(String(describing: okOutcome)))")
    }
    let secondOutcome = runDownload(okChecker)
    if case .verified(let secondURL)? = secondOutcome {
        check(secondURL.lastPathComponent == "TestApp-2.0.0 (2).dmg", "a second verified download gets a ' (2)' name")
    } else {
        check(false, "second download gives .verified (got \(String(describing: secondOutcome)))")
    }

    var tampered = dlBytes
    tampered[42] ^= 0xFF
    MockDownloadURLProtocol.configure(status: 200, body: tampered)
    let (badChecker, badDir) = makeDownloadChecker("tampered", manifest: goodManifest)
    check(runDownload(badChecker) == .hashMismatch, "one changed byte gives .hashMismatch")
    check(dirContents(badDir).isEmpty, "a mismatching download leaves no file in downloadDirectory")

    MockDownloadURLProtocol.configure(status: 200, body: dlBytes)
    let (sizeChecker, sizeDir) = makeDownloadChecker("size", manifest: try signedArtifactManifest(sha256: dlSha, size: Int64(dlBytes.count + 1)))
    check(runDownload(sizeChecker) == .hashMismatch, "a wrong signed size gives .hashMismatch")
    check(dirContents(sizeDir).isEmpty, "a size mismatch leaves no file in downloadDirectory")

    MockDownloadURLProtocol.configure(status: 404, body: Data("not found".utf8))
    let (missingChecker, missingDir) = makeDownloadChecker("missing", manifest: goodManifest)
    check(runDownload(missingChecker) == .failed, "HTTP 404 gives .failed")
    check(dirContents(missingDir).isEmpty, "HTTP 404 leaves no file in downloadDirectory")

    let requestsBeforeBrowser = MockDownloadURLProtocol.requestCount
    let (plainChecker, _) = makeDownloadChecker("plain", manifest: try signedArtifactManifest(sha256: nil, size: nil))
    var openedURLs: [URL] = []
    check(runDownload(plainChecker, openURL: { openedURLs.append($0) }) == .openedInBrowser, "a manifest without sha256 gives .openedInBrowser")
    check(openedURLs == [URL(string: dlURL)!], "a manifest without sha256 calls the injected openURL once with the signed URL")
    check(MockDownloadURLProtocol.requestCount == requestsBeforeBrowser, "a manifest without sha256 downloads nothing")

    let noUpdateChecker = UpdateChecker(
        kit: dlKit,
        manifestURL: URL(string: "https://testapp.example/version.json")!,
        currentVersion: "1.0.0",
        defaults: dlSuite,
        urlSession: dlSession,
        downloadDirectory: dlRoot
    )
    check(runDownload(noUpdateChecker) == .failed, "no available update gives .failed")
} catch {
    check(false, "Verified update download test threw: \(error)")
}

// MARK: - 5a3. UpdateChecker scheduling (backoff after failed checks)

section("UpdateChecker scheduling")
do {
    let schedRoot = FileManager.default.temporaryDirectory.appendingPathComponent("seatstamp-sched-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: schedRoot) }
    var schedSuiteNames: [String] = []
    defer { for name in schedSuiteNames { UserDefaults.standard.removePersistentDomain(forName: name) } }
    func makeSchedSuite() -> UserDefaults {
        let name = "com.example.selftest.sched.\(UUID().uuidString)"
        schedSuiteNames.append(name)
        return UserDefaults(suiteName: name)!
    }

    let schedUpdKey = Curve25519.Signing.PrivateKey()
    let schedKitSuite = makeSchedSuite()
    let schedKit = SeatStampManager(
        scheme: "SCHED-V1",
        licensePublicKeyBase64: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation.base64EncodedString(),
        updatePublicKeyBase64: schedUpdKey.publicKey.rawRepresentation.base64EncodedString(),
        bundleID: "com.example.sched",
        testingOverrides: .init(
            defaults: schedKitSuite,
            fileAnchorURLs: [schedRoot.appendingPathComponent("anchors/.vault_seal")],
            vaultFileURL: schedRoot.appendingPathComponent("anchors/.license_vault")
        )
    )
    let schedCfg = URLSessionConfiguration.ephemeral
    schedCfg.protocolClasses = [MockCheckoutURLProtocol.self]
    let schedSession = URLSession(configuration: schedCfg)

    func signedSchedManifest(validSignature: Bool) throws -> [String: Any] {
        let url = "https://testapp.example/download/Sched-2.0.0.dmg"
        let canon = UpdateManifest.canonicalSigningData(
            scheme: "SCHED-UPDATE-V1", version: "2.0.0", url: url, summary: "Sched", notes: [],
            summaryI18n: [:], notesI18n: [:]
        )
        var sig = try schedUpdKey.signature(for: canon)
        if !validSignature { sig[0] ^= 0x01 }
        return ["version": "2.0.0", "url": url, "summary": "Sched", "sig": LicenseTicket.base64URLEncode(sig)]
    }

    let schedCounters = TestCounters()
    var schedReply: (Int, [String: Any]) = (404, ["error": "not_found"])
    MockCheckoutURLProtocol.setImmediateHandler { _, _ in
        schedCounters.bump("manifest")
        return schedReply
    }

    func makeSchedChecker(_ defaults: UserDefaults, recheckInterval: TimeInterval = 7 * 24 * 60 * 60) -> UpdateChecker {
        UpdateChecker(
            kit: schedKit,
            manifestURL: URL(string: "https://testapp.example/version.json")!,
            trustedDownloadHosts: ["testapp.example"],
            recheckInterval: recheckInterval,
            currentVersion: "1.0.0",
            defaults: defaults,
            urlSession: schedSession
        )
    }
    func runCheckNow(_ checker: UpdateChecker) {
        var done = false
        checker.checkNow { done = true }
        pumpMainRunLoop(until: 5.0) { done }
    }
    func secondsUntilNextCheck(_ checker: UpdateChecker) -> TimeInterval {
        (checker.nextCheckDate ?? .distantPast).timeIntervalSinceNow
    }

    let weekSuite = makeSchedSuite()
    let weekChecker = makeSchedChecker(weekSuite)
    check(weekChecker.nextCheckDate.map { abs($0.timeIntervalSinceNow) < 10 } ?? false, "with no attempt yet, nextCheckDate is now")

    schedReply = (404, ["error": "not_found"])
    runCheckNow(weekChecker)
    check(abs(secondsUntilNextCheck(weekChecker) - 3600) < 10, "after one failed check (404) the next check is about 1 hour away")
    let requestsAfterFailure = schedCounters.int("manifest")
    weekChecker.checkIfDue()
    pumpMainRunLoop(until: 0.3) { false }
    check(schedCounters.int("manifest") == requestsAfterFailure, "checkIfDue right after a failed check sends no request")

    runCheckNow(weekChecker)
    check(abs(secondsUntilNextCheck(weekChecker) - 7200) < 10, "after a second failed check the next check is about 2 hours away")
    check(abs((makeSchedChecker(weekSuite).nextCheckDate ?? .distantPast).timeIntervalSinceNow - 7200) < 10, "the backoff survives a relaunch")

    let shortSuite = makeSchedSuite()
    let shortChecker = makeSchedChecker(shortSuite, recheckInterval: 7200)
    runCheckNow(shortChecker)
    runCheckNow(shortChecker)
    runCheckNow(shortChecker)
    check(abs(secondsUntilNextCheck(shortChecker) - 7200) < 10, "with recheckInterval 7200 a third failed check stays at 7200 seconds")

    schedReply = (200, try signedSchedManifest(validSignature: true))
    runCheckNow(weekChecker)
    check(weekChecker.availableUpdate?.rawVersion == "2.0.0", "a valid signed manifest is ingested by checkNow")
    check(weekSuite.integer(forKey: "seatStampUpdateFailureCount") == 0, "a successful check resets the failure count to 0")
    check(abs(secondsUntilNextCheck(weekChecker) - 7 * 24 * 60 * 60) < 10, "after a successful check the next check is about recheckInterval away")

    schedReply = (200, try signedSchedManifest(validSignature: false))
    let badSigSuite = makeSchedSuite()
    let badSigChecker = makeSchedChecker(badSigSuite)
    runCheckNow(badSigChecker)
    check(badSigSuite.integer(forKey: "seatStampUpdateFailureCount") == 1 && abs(secondsUntilNextCheck(badSigChecker) - 3600) < 10,
          "a manifest with a bad signature counts as a failed check")

    weekChecker.autoCheckForUpdates = false
    check(weekChecker.nextCheckDate == nil, "nextCheckDate is nil when automatic checks are off")
} catch {
    check(false, "UpdateChecker scheduling test threw: \(error)")
}

// MARK: - 5b. license-tool CLI (--tag-for-key, --revoke-key, --sign-manifest, --verify-manifest)

section("license-tool CLI")
do {
    let cliTmp = FileManager.default.temporaryDirectory.appendingPathComponent("seatstamp-cli-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: cliTmp) }
    try FileManager.default.createDirectory(at: cliTmp, withIntermediateDirectories: true)

    let execDir = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
    let toolURL = execDir.appendingPathComponent("license-tool")

    func runTool(_ args: [String], env: [String: String] = [:]) throws -> (Int32, String) {
        let proc = Process()
        proc.executableURL = toolURL
        proc.arguments = args
        var mergedEnv = ProcessInfo.processInfo.environment
        for (k, v) in env { mergedEnv[k] = v }
        proc.environment = mergedEnv
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        try proc.run()
        proc.waitUntilExit()
        let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return (proc.terminationStatus, out.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    if FileManager.default.isExecutableFile(atPath: toolURL.path) {
        let fixtureURL = URL(fileURLWithPath: repoRoot).appendingPathComponent("fixtures/golden-vectors.json")
        let root = try JSONSerialization.jsonObject(with: Data(contentsOf: fixtureURL)) as! [String: Any]
        let otdObj = root["orderTagDerivation"] as! [String: String]
        let updObj = root["updateTestKey"] as! [String: String]

        // 1) --tag-for-key matches golden vector
        let (code1, out1) = try runTool([
            "--key-hash-domain", otdObj["domain"]!,
            "--tag-for-key", otdObj["purchaseKey"]!
        ])
        check(code1 == 0 && out1 == otdObj["expectedOrderTag"]!, "license-tool --tag-for-key matches golden expectedOrderTag")

        // 2) --revoke-key derives ORD-<16-hex> from purchase key, normalizes direct ORD- tags, deduplicates, and re-signs
        let privKeyFile = cliTmp.appendingPathComponent("ed25519_update_private.key")
        let updSeedB64 = Data(base64Encoded: updObj["pkcs8Base64"]!)!.suffix(32).base64EncodedString()
        try updSeedB64.write(to: privKeyFile, atomically: true, encoding: .utf8)

        let manifestFile = cliTmp.appendingPathComponent("version.json")
        let initialManifest = """
        {
          "version": "1.2.0",
          "url": "https://cdn.example.com/MyApp-1.2.0.dmg",
          "summary": "Release 1.2",
          "notes": ["Fix A"]
        }
        """
        try initialManifest.write(to: manifestFile, atomically: true, encoding: .utf8)

        let (code2, _) = try runTool([
            "--scheme", "EXAMPLEAPP-V1",
            "--key-dir", cliTmp.path,
            "--key-hash-domain", otdObj["domain"]!,
            "--revoke-key", otdObj["purchaseKey"]!,
            manifestFile.path
        ])
        check(code2 == 0, "license-tool --revoke-key with purchase key exits 0")

        // Run --revoke-key again with same key + a direct 8-hex tag -> idempotent deduplication + sorted output
        let (code3, _) = try runTool([
            "--scheme", "EXAMPLEAPP-V1",
            "--key-dir", cliTmp.path,
            "--revoke-key", "ord-42a9f01c",
            manifestFile.path
        ])
        let (code3Dup, _) = try runTool([
            "--scheme", "EXAMPLEAPP-V1",
            "--key-dir", cliTmp.path,
            "--key-hash-domain", otdObj["domain"]!,
            "--revoke-key", otdObj["purchaseKey"]!,
            manifestFile.path
        ])
        check(code3 == 0 && code3Dup == 0, "license-tool --revoke-key is idempotent on duplicate runs")

        // 3) Re-running --sign-manifest preserves existing revoked_tags
        let (code4, _) = try runTool([
            "--scheme", "EXAMPLEAPP-V1",
            "--key-dir", cliTmp.path,
            "--sign-manifest", manifestFile.path
        ])
        let (code5, _) = try runTool([
            "--scheme", "EXAMPLEAPP-V1",
            "--verify-manifest", manifestFile.path,
            updObj["publicKeyBase64"]!
        ])
        let signedJSON = try JSONSerialization.jsonObject(with: Data(contentsOf: manifestFile)) as! [String: Any]
        let savedRevoked = signedJSON["revoked_tags"] as? [String] ?? []
        check(code4 == 0 && code5 == 0 && savedRevoked == ["ORD-42A9F01C", otdObj["expectedOrderTag"]!], "license-tool --sign-manifest preserves sorted revoked_tags and --verify-manifest succeeds")

        // 4) --artifact binds the download's SHA-256 and size into a separate manifest
        let artifactFile = cliTmp.appendingPathComponent("MyApp-2.0.0.dmg")
        let artifactBytes = Data((0..<3000).map { UInt8(truncatingIfNeeded: $0 &* 31) })
        try artifactBytes.write(to: artifactFile)
        let expectedArtifactSha = SHA256.hash(data: artifactBytes).map { String(format: "%02x", $0) }.joined()
        let artifactManifest = cliTmp.appendingPathComponent("version.json")
        try """
        {
          "version": "2.0.0",
          "url": "https://cdn.example.com/download/MyApp-2.0.0.dmg",
          "summary": "Release 2.0"
        }
        """.write(to: artifactManifest, atomically: true, encoding: .utf8)
        let (codeA1, _) = try runTool([
            "--scheme", "EXAMPLEAPP-V1", "--key-dir", cliTmp.path,
            "--sign-manifest", artifactManifest.path, "--artifact", artifactFile.path
        ])
        let artifactJSON = try JSONSerialization.jsonObject(with: Data(contentsOf: artifactManifest)) as! [String: Any]
        check(codeA1 == 0 && artifactJSON["sha256"] as? String == expectedArtifactSha && (artifactJSON["size"] as? NSNumber)?.int64Value == Int64(artifactBytes.count),
              "license-tool --sign-manifest --artifact writes the sha256 and size of the file")
        let (codeA2, _) = try runTool([
            "--scheme", "EXAMPLEAPP-V1", "--verify-manifest", artifactManifest.path, updObj["publicKeyBase64"]!,
            "--artifact", artifactFile.path
        ])
        check(codeA2 == 0, "license-tool --verify-manifest --artifact accepts the matching file")
        var alteredBytes = artifactBytes
        alteredBytes[100] ^= 0x01
        let alteredFile = cliTmp.appendingPathComponent("MyApp-2.0.0-altered.dmg")
        try alteredBytes.write(to: alteredFile)
        let (codeA3, _) = try runTool([
            "--scheme", "EXAMPLEAPP-V1", "--verify-manifest", artifactManifest.path, updObj["publicKeyBase64"]!,
            "--artifact", alteredFile.path
        ])
        check(codeA3 != 0, "license-tool --verify-manifest --artifact rejects a file with one changed byte")
        let beforeResign = try Data(contentsOf: artifactManifest)
        let (codeA4, _) = try runTool([
            "--scheme", "EXAMPLEAPP-V1", "--key-dir", cliTmp.path, "--sign-manifest", artifactManifest.path
        ])
        let afterRefusedResign = try Data(contentsOf: artifactManifest)
        check(codeA4 != 0 && afterRefusedResign == beforeResign, "license-tool --sign-manifest without --artifact refuses a manifest that carries sha256 and leaves it unchanged")
        let (codeA5, _) = try runTool([
            "--scheme", "EXAMPLEAPP-V1", "--key-dir", cliTmp.path, "--revoke-key", "ORD-42A9F01C", artifactManifest.path
        ])
        let revokedArtifactJSON = try JSONSerialization.jsonObject(with: Data(contentsOf: artifactManifest)) as! [String: Any]
        check(codeA5 == 0 && revokedArtifactJSON["sha256"] as? String == expectedArtifactSha
              && (revokedArtifactJSON["size"] as? NSNumber)?.int64Value == Int64(artifactBytes.count),
              "license-tool --revoke-key keeps sha256 and size")

        // 5) --seq writes a signed manifest_seq at or above the current unix time, and every re-sign raises it
        let seqManifest = cliTmp.appendingPathComponent("version-seq.json")
        try """
        {
          "version": "2.0.1",
          "url": "https://cdn.example.com/download/MyApp-2.0.1.dmg",
          "summary": "Sequenced"
        }
        """.write(to: seqManifest, atomically: true, encoding: .utf8)
        func readSeq() throws -> Int64? {
            let obj = try JSONSerialization.jsonObject(with: Data(contentsOf: seqManifest)) as! [String: Any]
            return (obj["manifest_seq"] as? NSNumber)?.int64Value
        }
        let beforeSeqSign = Int64(Date().timeIntervalSince1970)
        let (codeS1, _) = try runTool(["--scheme", "EXAMPLEAPP-V1", "--key-dir", cliTmp.path, "--sign-manifest", seqManifest.path, "--seq"])
        let seq1 = try readSeq() ?? 0
        check(codeS1 == 0 && seq1 >= beforeSeqSign, "license-tool --sign-manifest --seq writes manifest_seq at or above the current unix time")
        let (codeS2, _) = try runTool(["--scheme", "EXAMPLEAPP-V1", "--key-dir", cliTmp.path, "--sign-manifest", seqManifest.path])
        let seq2 = try readSeq() ?? 0
        check(codeS2 == 0 && seq2 > seq1, "signing a manifest that carries manifest_seq again writes a strictly higher value")
        let (codeS3, _) = try runTool(["--scheme", "EXAMPLEAPP-V1", "--key-dir", cliTmp.path, "--revoke-key", "ORD-42A9F01C", seqManifest.path])
        let seq3 = try readSeq() ?? 0
        let (codeS4, _) = try runTool(["--scheme", "EXAMPLEAPP-V1", "--verify-manifest", seqManifest.path, updObj["publicKeyBase64"]!])
        check(codeS3 == 0 && seq3 > seq2 && codeS4 == 0, "license-tool --revoke-key raises manifest_seq again and the manifest still verifies")

        // 6) --unrevoke-key removes a tag, raises manifest_seq, and re-signs
        let unrevokeManifest = cliTmp.appendingPathComponent("version-unrevoke.json")
        try """
        {
          "version": "2.0.2",
          "url": "https://cdn.example.com/download/MyApp-2.0.2.dmg",
          "summary": "Unrevoke"
        }
        """.write(to: unrevokeManifest, atomically: true, encoding: .utf8)
        func readManifest(_ url: URL) throws -> [String: Any] {
            try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        }
        let (codeU1, _) = try runTool(["--scheme", "EXAMPLEAPP-V1", "--key-dir", cliTmp.path, "--revoke-key", "ORD-42A9F01C", unrevokeManifest.path])
        let afterRevoke = try readManifest(unrevokeManifest)
        let seqAfterRevoke = (afterRevoke["manifest_seq"] as? NSNumber)?.int64Value ?? 0
        let (codeU2, _) = try runTool(["--scheme", "EXAMPLEAPP-V1", "--key-dir", cliTmp.path, "--unrevoke-key", "ORD-42A9F01C", unrevokeManifest.path])
        let afterUnrevoke = try readManifest(unrevokeManifest)
        let seqAfterUnrevoke = (afterUnrevoke["manifest_seq"] as? NSNumber)?.int64Value ?? 0
        let (codeU3, _) = try runTool(["--scheme", "EXAMPLEAPP-V1", "--verify-manifest", unrevokeManifest.path, updObj["publicKeyBase64"]!])
        check(codeU1 == 0 && (afterRevoke["revoked_tags"] as? [String]) == ["ORD-42A9F01C"], "license-tool --revoke-key X adds X")
        check(codeU2 == 0 && ((afterUnrevoke["revoked_tags"] as? [String]) ?? []).isEmpty && seqAfterUnrevoke > seqAfterRevoke && codeU3 == 0,
              "license-tool --unrevoke-key X removes X, raises manifest_seq, and the manifest verifies")
        let (codeU4, _) = try runTool(["--scheme", "EXAMPLEAPP-V1", "--key-dir", cliTmp.path, "--unrevoke-key", "ORD-42A9F01C", unrevokeManifest.path])
        check(codeU4 != 0, "license-tool --unrevoke-key for an absent tag exits non-zero")

        // 7) --rotate-keypair archives the old LICENSE key and writes a new one
        let rotateDir = cliTmp.appendingPathComponent("rotate", isDirectory: true)
        let (codeR0, _) = try runTool(["--scheme", "EXAMPLEAPP-V1", "--key-dir", rotateDir.path, "--rotate-keypair"])
        check(codeR0 != 0, "license-tool --rotate-keypair without a LICENSE key exits non-zero")
        let (codeR1, outR1) = try runTool(["--scheme", "EXAMPLEAPP-V1", "--key-dir", rotateDir.path, "--init-keypair"])
        let licenseKeyFile = rotateDir.appendingPathComponent("ed25519_private.key")
        let oldKeyText = (try? String(contentsOf: licenseKeyFile, encoding: .utf8)) ?? ""
        let initLines = outR1.components(separatedBy: "\n")
        let oldPub = initLines.firstIndex(of: "Paste into SeatStampManager(licensePublicKeyBase64:):").flatMap { $0 + 1 < initLines.count ? initLines[$0 + 1] : nil } ?? ""
        let (codeR2, outR2) = try runTool(["--scheme", "EXAMPLEAPP-V1", "--key-dir", rotateDir.path, "--rotate-keypair"])
        let rotatedNames = ((try? FileManager.default.contentsOfDirectory(atPath: rotateDir.path)) ?? [])
            .filter { $0.hasPrefix("ed25519_private.retired-") && $0.hasSuffix(".key") }
        let archivedText = rotatedNames.first.flatMap { try? String(contentsOf: rotateDir.appendingPathComponent($0), encoding: .utf8) } ?? ""
        let newKeyText = (try? String(contentsOf: licenseKeyFile, encoding: .utf8)) ?? ""
        let outLines = outR2.components(separatedBy: "\n")
        func valueAfter(_ label: String) -> String {
            guard let i = outLines.firstIndex(of: label), i + 1 < outLines.count else { return "" }
            return outLines[i + 1]
        }
        let newPubPrinted = valueAfter("New license public key (SeatStampManager licensePublicKeyBase64):")
        let retiredPubPrinted = valueAfter("Retired license public key (SeatStampManager retiredLicensePublicKeysBase64 and Worker ED25519_RETIRED_PUB_B64):")
        check(codeR1 == 0 && codeR2 == 0, "license-tool --rotate-keypair exits 0 after --init-keypair")
        check(rotatedNames.count == 1 && !oldKeyText.isEmpty && archivedText == oldKeyText, "--rotate-keypair leaves exactly one retired key file with the old key content")
        check(!newKeyText.isEmpty && newKeyText != oldKeyText, "--rotate-keypair writes a new ed25519_private.key with different content")
        check(!oldPub.isEmpty && retiredPubPrinted == oldPub && !newPubPrinted.isEmpty && newPubPrinted != oldPub, "--rotate-keypair prints the new and the retired public keys")
        let keyPerms = (try? FileManager.default.attributesOfItem(atPath: licenseKeyFile.path)[.posixPermissions] as? NSNumber)?.intValue ?? 0
        check(keyPerms == 0o600, "the rotated LICENSE key file has mode 0600")

        // 8) Minting needs --mint with --seat or --universal; tags for purchase keys are derived
        let licObj = root["licenseTestKey"] as! [String: String]
        let tObj = root["ticket"] as! [String: Any]
        let licSeedB64 = Data(base64Encoded: licObj["pkcs8Base64"]!)!.suffix(32).base64EncodedString()
        try licSeedB64.write(to: cliTmp.appendingPathComponent("ed25519_private.key"), atomically: true, encoding: .utf8)
        let goldenLicPub = try Curve25519.Signing.PublicKey(rawRepresentation: Data(base64Encoded: licObj["publicKeyBase64"]!)!)
        let mintScheme = tObj["scheme"] as! String
        let goldenSeat = tObj["seat"] as! String
        let mintBase = ["--scheme", mintScheme, "--key-dir", cliTmp.path, "--key-hash-domain", otdObj["domain"]!]
        func mintedTicket(_ out: String) -> String? {
            out.components(separatedBy: "\n").first { $0.hasPrefix("LK1-") }
        }
        func verifyMinted(_ ticket: String?, seat: String) -> LicenseTicket.Payload? {
            guard let ticket = ticket,
                  case .success(let p) = LicenseTicket.verify(ticket, scheme: mintScheme, publicKey: goldenLicPub, expectedSeatCode: seat) else { return nil }
            return p
        }
        let (codeM1, outM1) = try runTool(mintBase + ["--print-update-pub"])
        check(codeM1 != 0 && !outM1.contains("LK1-"), "(a) a mistyped command exits non-zero and prints no ticket")
        let (codeM2, outM2) = try runTool(mintBase)
        check(codeM2 == 2 && !outM2.contains("LK1-"), "(b) no command exits with status 2 and prints no ticket")
        let (codeM3, outM3) = try runTool(mintBase + ["ORD-8821", "0123456789abcdef"])
        check(codeM3 != 0 && !outM3.contains("LK1-"), "(c) the old positional mint form exits non-zero")
        let (codeM4, outM4) = try runTool(mintBase + ["--mint", otdObj["purchaseKey"]!, "--seat", goldenSeat])
        let payloadM4 = verifyMinted(mintedTicket(outM4), seat: goldenSeat)
        check(codeM4 == 0 && payloadM4?.boundSeat == goldenSeat && payloadM4?.tag == otdObj["expectedOrderTag"]!,
              "(d) --mint <purchaseKey> --seat mints a seat-bound ticket with the derived tag")
        let (codeM5, outM5) = try runTool(mintBase + ["--mint", "ORD-8821", "--universal"])
        let payloadM5 = verifyMinted(mintedTicket(outM5), seat: "0000000000000000")
        check(codeM5 == 0 && payloadM5 != nil && payloadM5?.boundSeat == nil && payloadM5?.tag == "ORD-8821",
              "(e) --mint ORD-8821 --universal mints a universal ticket")
        let (codeM6, outM6) = try runTool(mintBase + ["--mint", "ORD-8821"])
        let (codeM7, outM7) = try runTool(mintBase + ["--mint", "ORD-8821", "--seat", goldenSeat, "--universal"])
        check(codeM6 != 0 && codeM7 != 0 && !outM6.contains("LK1-") && !outM7.contains("LK1-"),
              "(f) --mint without --seat or --universal, or with both, exits non-zero")

        // --erase-key never sends a request without a token or to a non-https endpoint
        let (codeE1, outE1) = try runTool(
            ["--erase-key", "cs_live_eraseKeyCliProbe000000000000000", "--endpoint", "https://example.invalid"],
            env: ["SEATSTAMP_ADMIN_TOKEN": ""]
        )
        check(codeE1 != 0 && outE1.contains("SEATSTAMP_ADMIN_TOKEN"),
              "--erase-key without SEATSTAMP_ADMIN_TOKEN exits non-zero and names the variable")
        let (codeE2, outE2) = try runTool(
            ["--erase-key", "cs_live_eraseKeyCliProbe000000000000000", "--endpoint", "http://example.invalid"],
            env: ["SEATSTAMP_ADMIN_TOKEN": String(repeating: "t", count: 40)]
        )
        check(codeE2 != 0 && !outE2.contains(String(repeating: "t", count: 40)), "--erase-key refuses an http endpoint and never prints the token")
    } else {
        check(false, "license-tool binary not found next to selftest; run swift build first")
    }
} catch {
    check(false, "license-tool CLI test threw: \(error)")
}

// MARK: - 6. RegionalPricing

section("RegionalPricing")
do {
    let links = RegionalPricing.PaymentLinks(
        usd: URL(string: "https://buy.stripe.com/test_usd")!,
        eur: URL(string: "https://buy.stripe.com/test_eur")!,
        jpy: URL(string: "https://buy.stripe.com/test_jpy")!,
        cny: URL(string: "https://buy.stripe.com/test_cny")!,
        twd: URL(string: "https://buy.stripe.com/test_twd")!,
        krw: URL(string: "https://buy.stripe.com/test_krw")!,
        inr: URL(string: "https://buy.stripe.com/test_inr")!
    )
    check(RegionalPricing.resolveTier(regionCode: "US", currencyCode: "USD", gmtOffsetSeconds: -28_800, timeZoneIdentifier: "America/Los_Angeles", links: links) == .usd, "US -> USD")
    check(RegionalPricing.resolveTier(regionCode: "DE", currencyCode: "EUR", gmtOffsetSeconds: 3_600, timeZoneIdentifier: "Europe/Berlin", links: links) == .eur, "DE -> EUR")
    check(RegionalPricing.resolveTier(regionCode: "JP", currencyCode: "JPY", gmtOffsetSeconds: 32_400, timeZoneIdentifier: "Asia/Tokyo", links: links) == .jpy, "JP + JST -> JPY")
    check(RegionalPricing.resolveTier(regionCode: "JP", currencyCode: "JPY", gmtOffsetSeconds: -28_800, timeZoneIdentifier: "America/Los_Angeles", links: links) == .usd, "JP region in US timezone -> USD")
    check(RegionalPricing.resolveTier(regionCode: "IN", currencyCode: "INR", gmtOffsetSeconds: 19_800, timeZoneIdentifier: "Asia/Kolkata", links: links) == .inr, "IN + IST -> INR")
    check(RegionalPricing.resolveTier(regionCode: "IN", currencyCode: "INR", gmtOffsetSeconds: 0, timeZoneIdentifier: "UTC", links: links) == .usd, "IN region in UTC -> USD")
    check(RegionalPricing.resolveTier(regionCode: "CN", currencyCode: "CNY", gmtOffsetSeconds: 28_800, timeZoneIdentifier: "Asia/Shanghai", links: links) == .cny, "CN + UTC+8 -> CNY")
    check(RegionalPricing.resolveTier(regionCode: "TW", currencyCode: "TWD", gmtOffsetSeconds: 28_800, timeZoneIdentifier: "Asia/Taipei", links: links) == .twd, "TW -> TWD")
    check(RegionalPricing.resolveTier(regionCode: "KR", currencyCode: "KRW", gmtOffsetSeconds: 32_400, timeZoneIdentifier: "Asia/Seoul", links: links) == .krw, "KR -> KRW")
    // Region alone selects these tiers (no time-zone check); pinned so the docs stay true.
    check(RegionalPricing.resolveTier(regionCode: "TW", currencyCode: "TWD", gmtOffsetSeconds: -28_800, timeZoneIdentifier: "America/Los_Angeles", links: links) == .twd, "TW region in US timezone -> TWD")
    check(RegionalPricing.resolveTier(regionCode: "KR", currencyCode: "KRW", gmtOffsetSeconds: 0, timeZoneIdentifier: "UTC", links: links) == .krw, "KR region in UTC -> KRW")
    check(RegionalPricing.resolveTier(regionCode: "US", currencyCode: "EUR", gmtOffsetSeconds: -28_800, timeZoneIdentifier: "America/Los_Angeles", links: links) == .eur, "US region with EUR currency -> EUR")
}

// MARK: - 7. Repository Hygiene Guard

section("Repository Hygiene")
do {
    // Scans `root` for key files and dashes. Hidden files are included; build, VCS, and tool directories are
    // skipped at any depth.
    func scanRepositoryHygiene(root: URL) -> (keyFiles: [String], dashFiles: [String]) {
        let skippedDirectories: Set<String> = [".git", ".build", ".swiftpm", ".wrangler", "node_modules", "DerivedData"]
        let textExtensions: Set<String> = ["md", "swift", "js", "mjs", "jsonc", "json", "yml", "yaml", "example", "html", "css"]
        let emDash = String(Character(Unicode.Scalar(0x2014)!))
        let enDash = String(Character(Unicode.Scalar(0x2013)!))
        let rootPath = root.resolvingSymlinksInPath().path
        let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: []
        )
        var keyFiles: [String] = []
        var dashFiles: [String] = []
        while let url = enumerator?.nextObject() as? URL {
            let isDirectory = (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false
            if isDirectory {
                if skippedDirectories.contains(url.lastPathComponent) {
                    enumerator?.skipDescendants()
                }
                continue
            }
            let rel = url.resolvingSymlinksInPath().path.replacingOccurrences(of: rootPath + "/", with: "")
            let ext = url.pathExtension.lowercased()
            if ext == "key" || ext == "pem" || ext == "pkcs8" {
                keyFiles.append(rel)
            }
            if textExtensions.contains(ext),
               let text = try? String(contentsOf: url, encoding: .utf8),
               (text.contains(emDash) || text.contains(enDash)) {
                dashFiles.append(rel)
            }
        }
        return (keyFiles, dashFiles)
    }

    // The scan sees hidden files and skips `.git`.
    let probeRoot = FileManager.default.temporaryDirectory.appendingPathComponent("seatstamp-hygiene-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: probeRoot) }
    let probeDash = "a" + String(Character(Unicode.Scalar(0x2013)!)) + "b\n"
    try FileManager.default.createDirectory(at: probeRoot.appendingPathComponent(".git", isDirectory: true), withIntermediateDirectories: true)
    try probeDash.write(to: probeRoot.appendingPathComponent(".hygiene-probe.md"), atomically: true, encoding: .utf8)
    try probeDash.write(to: probeRoot.appendingPathComponent(".git/ignored-probe.md"), atomically: true, encoding: .utf8)
    let probe = scanRepositoryHygiene(root: probeRoot)
    check(probe.dashFiles == [".hygiene-probe.md"], "hygiene scan finds a dash in a hidden file and skips .git (\(probe.dashFiles))")

    let result = scanRepositoryHygiene(root: URL(fileURLWithPath: repoRoot, isDirectory: true))
    check(result.keyFiles.isEmpty, "no .key/.pem/.pkcs8 files present in repo (\(result.keyFiles.joined(separator: ", ")))")
    check(result.dashFiles.isEmpty, "zero em-dashes or en-dashes across repo (\(result.dashFiles.joined(separator: ", ")))")
} catch {
    check(false, "repository hygiene scan threw: \(error)")
}

print("")
if failures == 0 {
    print("selftest: ALL \(passed) CHECKS PASSED")
    exit(0)
} else {
    print("selftest: \(failures) FAILURE(S) (\(passed) passed)")
    exit(1)
}
