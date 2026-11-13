import AppKit
import Combine
import CryptoKit
import Foundation
import IOKit
import Security

/// Offline Ed25519 seat license and HMAC trial manager for macOS apps.
public final class SeatStampManager: ObservableObject, @unchecked Sendable {
    public enum ActivationOutcome: Equatable, Sendable {
        case activated
        case seatLimitReached
        case networkError
        case invalidKey
        case unconfigured
        case paymentPending
        case clockSkew
    }

    /// Result of `requestKeyRecovery(email:)`. `.sent` means the Worker accepted the request; it is returned
    /// whether or not the email matches a purchase, so it cannot be used to enumerate buyers.
    public enum RecoveryOutcome: Equatable, Sendable {
        case sent
        case unconfigured
        case rateLimited
        case invalidEmail
        case networkError
    }

    public struct TestingOverrides {
        public var defaults: UserDefaults
        public var fileAnchorURLs: [URL]
        public var vaultFileURL: URL
        public var hardwareUUID: String
        public var useKeychain: Bool
        public var healSynchronously: Bool
        public var now: () -> Date
        public var urlSession: URLSession?
        public var checkoutPollInterval: TimeInterval?
        public var autoResumePendingCheckout: Bool
        /// Replaces the retry delay and the 2-second start delay of the retired-key re-activation.
        public var retiredKeyRetryInterval: TimeInterval?
        /// Replaces the queued-deactivation retry delay and the 2-second flush delay at launch.
        public var deactivationRetryInterval: TimeInterval?

        public init(
            defaults: UserDefaults,
            fileAnchorURLs: [URL],
            vaultFileURL: URL,
            hardwareUUID: String = "11111111-2222-3333-4444-555555555555",
            useKeychain: Bool = false,
            healSynchronously: Bool = true,
            now: @escaping () -> Date = Date.init,
            urlSession: URLSession? = nil,
            checkoutPollInterval: TimeInterval? = nil,
            autoResumePendingCheckout: Bool = true,
            retiredKeyRetryInterval: TimeInterval? = nil,
            deactivationRetryInterval: TimeInterval? = nil
        ) {
            self.defaults = defaults
            self.fileAnchorURLs = fileAnchorURLs
            self.vaultFileURL = vaultFileURL
            self.hardwareUUID = hardwareUUID
            self.useKeychain = useKeychain
            self.healSynchronously = healSynchronously
            self.now = now
            self.urlSession = urlSession
            self.checkoutPollInterval = checkoutPollInterval
            self.autoResumePendingCheckout = autoResumePendingCheckout
            self.retiredKeyRetryInterval = retiredKeyRetryInterval
            self.deactivationRetryInterval = deactivationRetryInterval
        }
    }

    private enum TicketInstallResult {
        case installed
        case rejected
        case belowWatermark
    }

    /// A seat release that still has to reach the server.
    private struct PendingDeactivation: Codable, Equatable {
        var key: String
        var ticket: String?
    }

    private static let maxPendingDeactivations = 4

    private struct StoredLicenseVault: Codable {
        var token: String?
        var parentKey: String?
        var seatsUsed: Int?
        var maxSeats: Int?
        var revokedOrderTags: [String]?
        var pendingCheckoutHandoff: String?
        var pendingCheckoutStartedEpoch: Int64?
        var manifestSeq: Int64?
        var retiredKeyGraceStartEpoch: Int64?
        var pendingDeactivations: [PendingDeactivation]?
    }

    // MARK: - Public Configuration

    public let scheme: String
    public let ticketPrefix: String
    public let updateScheme: String
    public let activationEndpoints: [URL]
    /// Endpoints passed to `init` that were dropped because they do not use https.
    public let rejectedActivationEndpoints: [URL]
    public let trialLengthDays: Int
    public let configuredMaxSeats: Int
    public let bundleID: String
    public let enforceTrialGate: Bool

    internal let licensePublicKey: Curve25519.Signing.PublicKey?
    /// Retired license keys from `init(retiredLicensePublicKeysBase64:)`. They only keep an already stored ticket
    /// alive for the grace period; they never accept a new activation.
    private let retiredLicensePublicKeys: [Curve25519.Signing.PublicKey]
    private let retiredKeyGraceDays: Int
    internal let updatePublicKey: Curve25519.Signing.PublicKey?

    // MARK: - Published State

    @Published public private(set) var isLicensed: Bool
    /// Displays `••••-<last6>` of the parent purchase key when present, or the ticket's `ORD-...` tag.
    @Published public private(set) var maskedKey: String
    /// The verified ticket's `ORD-...` order tag (`""` when unlicensed).
    @Published public private(set) var orderTag: String = ""
    @Published public private(set) var seatsUsed: Int = 1
    @Published public private(set) var maxSeats: Int = 2
    @Published public private(set) var isActivatingOnline: Bool = false
    /// True while waiting for a default-browser Stripe checkout (`beginBrowserCheckout`) to complete in the background.
    @Published public private(set) var isAwaitingBrowserCheckout: Bool = false
    /// True while a `requestKeyRecovery(email:)` request is in flight.
    @Published public private(set) var isRequestingKeyRecovery: Bool = false
    /// Set when the server refused to free this Mac's seat because the purchase's yearly release budget is used up
    /// (`429 release_limit`). The seat stays assigned and the purchase key stays available for re-activation.
    /// In memory only; never persisted.
    @Published public private(set) var seatReleaseBlockedUntil: Date?
    /// True while the stored ticket verifies only under a retired license key. The kit stays licensed until
    /// `retiredKeyGraceEndsAt` and re-activates in the background with the stored purchase key.
    @Published public private(set) var licenseNeedsReactivation: Bool = false

    /// End of the retired-key grace period, or nil outside it.
    public var retiredKeyGraceEndsAt: Date? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return retiredKeyGraceDeadlineEpoch.map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }

    /// 16-hex prefix of `SHA256(seatHashDomain + IOPlatformUUID)`.
    public let deviceSeatCode: String
    public let firstLaunchDate: Date

    // MARK: - Internal State

    private static let checkoutHandoffTTLSeconds: Int64 = 24 * 60 * 60
    private static let checkoutFastPollWindowSeconds: Int64 = 3 * 60
    private static let checkoutMaxActivePollWindowSeconds: Int64 = 15 * 60
    private static let checkoutFastPollInterval: TimeInterval = 3.0
    private static let checkoutSlowPollInterval: TimeInterval = 10.0

    private let stateLock = NSLock()
    private let persistenceQueue = DispatchQueue(label: "com.seatstamp.persistence", qos: .utility)
    private let trialHMACKey: SymmetricKey
    private let canUseKeychainAnchor: Bool
    private let defaults: UserDefaults
    private let anchorURLs: [URL]
    private let vaultURL: URL?
    private let keychainService: String
    private let defaultsSealKey = "seatStampTrialSealV2"
    private let keychainTrialAccount = "trial_seal_v2"
    private let keychainLicenseAccount = "license_vault_v2"
    private let healSynchronously: Bool
    private let nowProvider: () -> Date
    private let networkSession: URLSession
    private let checkoutPollIntervalOverride: TimeInterval?

    private var firstLaunchEpoch: Int64
    private var highWaterEpoch: Int64
    /// Clock reading at launch or at the last `refreshMonotonicClockIfNeeded()` advance (in memory only, not sealed).
    private var lastClockAdvanceEpoch: Int64 = 0
    /// Seat-bound tickets with `issued < seatRevokedBeforeEpoch` are rejected offline.
    private var seatRevokedBeforeEpoch: Int64 = 0
    /// Effective revoked set: `staticRevokedOrderTags` plus `persistedRevokedOrderTags`.
    private var revokedOrderTagsSet: Set<String>
    /// Tags passed to `init(revokedOrderTags:)`; permanent for this build.
    private let staticRevokedOrderTags: Set<String>
    /// Tags from signed manifests, stored in `.license_vault`. Mirrors the newest manifest that carries a `manifest_seq`.
    private var persistedRevokedOrderTags: Set<String>
    /// Highest signed `manifest_seq` accepted from an update manifest (0 when none).
    private var highestManifestSeq: Int64 = 0
    private var sealGeneration: UInt64 = 0
    private var storedTokenCache: String?
    private var storedTokenVerified: Bool = false
    private var storedParentKeyCache: String?
    /// Queued seat releases, oldest first (at most `maxPendingDeactivations`).
    private var pendingDeactivations: [PendingDeactivation] = []
    private var deactivationFlushInFlight: Bool = false
    private var deactivationFlushEntry: PendingDeactivation?
    /// Work waiting for the in-flight flush to finish (an activation of the same key).
    private var deactivationFlushWaiters: [() -> Void] = []
    private var deactivationRetryAttempt: Int = 0
    private var deactivationRetryTimer: DispatchSourceTimer?
    private var deactivationFocusObserver: NSObjectProtocol?
    private let deactivationRetryOverride: TimeInterval?
    /// The purchase key that received `429 release_limit`; `seatReleaseBlockedUntil` clears only on a 200 for it.
    private var releaseLimitKey: String?
    /// True when the stored ticket is bound to this Mac's seat.
    private var storedTokenIsSeatBound: Bool = false
    private var pendingCheckoutHandoffCache: String?
    private var pendingCheckoutStartedEpochCache: Int64?
    private var checkoutPollTimer: DispatchSourceTimer?
    private var checkoutFocusObserver: NSObjectProtocol?
    private var checkoutOutcomeCallback: ((ActivationOutcome) -> Void)?
    private var checkoutPollGeneration: UInt64 = 0
    private var checkoutPollAttemptCount: Int = 0
    private var isClaimCheckInFlight: Bool = false
    private var activationInFlight: Bool = false
    private var recoveryInFlight: Bool = false
    private var activationRequestID: UInt64 = 0
    /// Start of the retired-key grace period, stored in `.license_vault` (nil when the ticket uses the current key).
    private var retiredKeyGraceStartEpoch: Int64?
    /// `retiredKeyGraceStartEpoch + retiredKeyGraceDays * 86_400`, in memory only.
    private var retiredKeyGraceDeadlineEpoch: Int64?
    private let retiredKeyRetryOverride: TimeInterval?
    private var retiredKeyRetryDelay: TimeInterval = 60
    private var retiredKeyRetryTimer: DispatchSourceTimer?

    /// Result of `acceptManifestSequence(_:)`.
    public enum ManifestSequenceResult: Equatable, Sendable {
        /// Lower than the highest accepted sequence: the manifest is an old one served again.
        case replay
        /// Equal to the highest accepted sequence.
        case same
        /// Higher than the highest accepted sequence; it is now stored.
        case newer
    }

    /// Highest signed `manifest_seq` this kit has accepted (0 when none), persisted in `.license_vault`.
    public var highestManifestSequence: Int64 {
        stateLock.lock()
        defer { stateLock.unlock() }
        return highestManifestSeq
    }

    /// Currently active set of canonical uppercase `"ORD-..."` tags refused offline.
    public var revokedOrderTags: Set<String> {
        stateLock.lock()
        defer { stateLock.unlock() }
        return revokedOrderTagsSet
    }

    public var trialDaysRemaining: Int {
        stateLock.lock()
        let first = firstLaunchEpoch
        let high = highWaterEpoch
        stateLock.unlock()
        let nowClamped = max(LicenseTicket.minReasonableEpoch, Int64(nowProvider().timeIntervalSince1970))
        let effectiveNow = max(nowClamped, high)
        let elapsedSeconds = max(0, effectiveNow - first)
        let elapsedDays = Int(elapsedSeconds / 86_400)
        return max(0, trialLengthDays - elapsedDays)
    }

    public var isTrialExpired: Bool {
        !isLicensed && trialDaysRemaining == 0
    }

    /// Returns the parent purchase key (`cs_live_...`), or a universal offline ticket when no purchase key is stored,
    /// so the user can copy it for a second Mac or re-activate after Migration Assistant / Time Machine.
    /// Never returns a ticket bound to this Mac (it fails on any other Mac); that case returns nil.
    public var shareableLicenseKey: String? {
        stateLock.lock()
        defer { stateLock.unlock() }
        if let parent = storedParentKeyCache, !parent.isEmpty {
            return parent
        }
        if let token = storedTokenCache, !token.isEmpty, !storedTokenIsSeatBound {
            return token
        }
        return nil
    }

    public static var displayAppVersion: String {
        let raw = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
        return VersionCompare.formattedDisplayVersion(raw)
    }

    // MARK: - Init

    public init(
        scheme: String,
        ticketPrefix: String = LicenseTicket.defaultPrefix,
        licensePublicKeyBase64: String,
        retiredLicensePublicKeysBase64: [String] = [],
        retiredKeyGraceDays: Int = 30,
        updatePublicKeyBase64: String? = nil,
        updateScheme: String? = nil,
        activationEndpoints: [URL] = [],
        trialLengthDays: Int = 30,
        maxSeats: Int = 2,
        bundleID: String? = nil,
        seatHashDomain: String? = nil,
        trialSealDomain: String? = nil,
        revokedOrderTags: Set<String> = [],
        enforceTrialGate: Bool = true,
        testingOverrides: TestingOverrides? = nil
    ) {
        let resolvedBundleID = (bundleID?.trimmingCharacters(in: .whitespacesAndNewlines)).flatMap { $0.isEmpty ? nil : $0 }
            ?? Bundle.main.bundleIdentifier
            ?? "com.example.myapp"

        self.scheme = scheme
        self.ticketPrefix = ticketPrefix
        self.updateScheme = updateScheme ?? UpdateManifest.derivedScheme(fromLicenseScheme: scheme)
        self.activationEndpoints = activationEndpoints.filter { $0.scheme?.lowercased() == "https" }
        self.rejectedActivationEndpoints = activationEndpoints.filter { $0.scheme?.lowercased() != "https" }
        if !self.rejectedActivationEndpoints.isEmpty, testingOverrides == nil {
            assertionFailure("SeatStampManager: activationEndpoints must use https")
        }
        self.trialLengthDays = max(0, trialLengthDays)
        self.configuredMaxSeats = max(1, maxSeats)
        self.bundleID = resolvedBundleID
        self.enforceTrialGate = enforceTrialGate

        self.licensePublicKey = Self.decodePublicKey(base64: licensePublicKeyBase64)
        let decodedRetiredKeys = retiredLicensePublicKeysBase64.compactMap(Self.decodePublicKey(base64:))
        self.retiredLicensePublicKeys = decodedRetiredKeys
        let resolvedGraceDays = min(365, max(1, retiredKeyGraceDays))
        self.retiredKeyGraceDays = resolvedGraceDays
        self.retiredKeyRetryOverride = testingOverrides?.retiredKeyRetryInterval
        self.deactivationRetryOverride = testingOverrides?.deactivationRetryInterval
        self.updatePublicKey = updatePublicKeyBase64.flatMap(Self.decodePublicKey(base64:))

        let resolvedNow = testingOverrides?.now ?? Date.init
        self.nowProvider = resolvedNow
        self.healSynchronously = testingOverrides?.healSynchronously ?? false

        let hwUUID = testingOverrides?.hardwareUUID ?? Self.readHardwareUUID(fallbackNamespace: resolvedBundleID)
        let resolvedSeatDomain = seatHashDomain ?? "\(resolvedBundleID).seat.v1|"
        let resolvedSealDomain = trialSealDomain ?? "\(resolvedBundleID).trial-seal.v1|"

        self.deviceSeatCode = TrialSeal.seatCode(hardwareUUID: hwUUID, domain: resolvedSeatDomain)
        let hmacKey = TrialSeal.hmacKey(hardwareUUID: hwUUID, domain: resolvedSealDomain)
        self.trialHMACKey = hmacKey

        let useKeychain = testingOverrides?.useKeychain ?? Self.hasStableDeveloperTeamID()
        self.canUseKeychainAnchor = useKeychain
        self.keychainService = "\(resolvedBundleID).license-vault"
        self.defaults = testingOverrides?.defaults ?? .standard
        self.anchorURLs = testingOverrides?.fileAnchorURLs ?? Self.defaultFileAnchorURLs(bundleID: resolvedBundleID)
        self.vaultURL = testingOverrides?.vaultFileURL ?? Self.defaultLicenseVaultFileURL(bundleID: resolvedBundleID)

        let appName = (Bundle.main.infoDictionary?["CFBundleName"] as? String) ?? resolvedBundleID
        if let customSession = testingOverrides?.urlSession {
            self.networkSession = customSession
        } else {
            let cfg = URLSessionConfiguration.ephemeral
            cfg.tlsMinimumSupportedProtocolVersion = .TLSv13
            cfg.httpCookieAcceptPolicy = .never
            cfg.httpShouldSetCookies = false
            cfg.urlCache = nil
            cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            cfg.httpAdditionalHeaders = ["User-Agent": "\(appName)/\(Self.displayAppVersion)"]
            self.networkSession = URLSession(configuration: cfg)
        }
        self.checkoutPollIntervalOverride = testingOverrides?.checkoutPollInterval

        let nowEpoch = max(LicenseTicket.minReasonableEpoch, Int64(resolvedNow().timeIntervalSince1970))
        var validFirsts: [Int64] = []
        var validHighs: [Int64] = []
        var validRevoked: [Int64] = []
        var anchorBlobs: [String] = []

        if let dSeal = self.defaults.string(forKey: self.defaultsSealKey) {
            anchorBlobs.append(dSeal)
        }
        for url in self.anchorURLs {
            if let fSeal = try? String(contentsOf: url, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines) {
                anchorBlobs.append(fSeal)
            }
        }
        if useKeychain, let kSeal = Self.readKeychainString(service: self.keychainService, account: self.keychainTrialAccount) {
            anchorBlobs.append(kSeal)
        }

        for blob in anchorBlobs {
            if let parsed = TrialSeal.verify(blob, key: hmacKey) {
                let clampedFirst = min(LicenseTicket.maxReasonableEpoch, max(LicenseTicket.minReasonableEpoch, parsed.first))
                let clampedHigh = min(LicenseTicket.maxReasonableEpoch, max(clampedFirst, parsed.high))
                validFirsts.append(clampedFirst)
                validHighs.append(clampedHigh)
                validRevoked.append(min(LicenseTicket.maxReasonableEpoch, max(0, parsed.revokedBefore)))
            }
        }

        let resolvedFirst = validFirsts.min() ?? nowEpoch
        // Never lower a sealed high-water mark. Advance it by at most 7 days per launch so a wrong future clock costs at most 7 trial days.
        let maxHighAhead: Int64 = 7 * 86_400
        let storedHigh = validHighs.max() ?? nowEpoch
        let resolvedHigh = max(storedHigh, min(nowEpoch, storedHigh + maxHighAhead))
        let resolvedRevoked = validRevoked.max() ?? 0

        self.firstLaunchEpoch = resolvedFirst
        self.highWaterEpoch = resolvedHigh
        self.lastClockAdvanceEpoch = nowEpoch
        self.seatRevokedBeforeEpoch = resolvedRevoked
        self.firstLaunchDate = Date(timeIntervalSince1970: TimeInterval(resolvedFirst))

        let freshSeal = TrialSeal.make(first: resolvedFirst, high: resolvedHigh, revokedBefore: resolvedRevoked, key: hmacKey)
        let expectedAnchorCount = 1 + self.anchorURLs.count + (useKeychain ? 1 : 0)
        let allAnchorsFresh = anchorBlobs.count == expectedAnchorCount && anchorBlobs.allSatisfy { $0 == freshSeal }

        let vault = Self.loadLicenseVault(
            vaultURL: self.vaultURL,
            useKeychain: useKeychain,
            keychainService: self.keychainService,
            keychainAccount: self.keychainLicenseAccount
        )
        let vaultRevoked = LicenseTicket.normalizeOrderTagSet(vault.revokedOrderTags ?? [])
        let staticRevoked = LicenseTicket.normalizeOrderTagSet(revokedOrderTags)
        let mergedRevoked = staticRevoked.union(vaultRevoked)
        self.staticRevokedOrderTags = staticRevoked
        self.persistedRevokedOrderTags = vaultRevoked
        self.revokedOrderTagsSet = mergedRevoked
        self.highestManifestSeq = max(0, vault.manifestSeq ?? 0)

        // Preserve parentKey even if the ticket fails .seatMismatch after Migration Assistant to a new Mac.
        self.storedParentKeyCache = vault.parentKey
        let loadedQueue = (vault.pendingDeactivations ?? []).filter { !$0.key.isEmpty }
        self.pendingDeactivations = Array(loadedQueue.suffix(Self.maxPendingDeactivations))

        // A ticket that verifies only under a retired key keeps the kit licensed until the grace deadline.
        var startupPayload: LicenseTicket.Payload?
        var startupGraceStart: Int64?
        var startupGraceDeadline: Int64?
        var droppedExpiredGraceTicket = false
        let clockNow = max(nowEpoch, resolvedHigh)
        if let storedToken = vault.token,
           let verified = Self.verifyStoredTicket(
               storedToken,
               scheme: scheme,
               prefix: ticketPrefix,
               currentKey: self.licensePublicKey,
               retiredKeys: decodedRetiredKeys,
               seatCode: self.deviceSeatCode,
               revokedBefore: resolvedRevoked,
               revokedOrderTags: mergedRevoked
           ) {
            if verified.usedRetiredKey {
                let start = vault.retiredKeyGraceStartEpoch ?? clockNow
                let deadline = start + Int64(resolvedGraceDays) * 86_400
                if clockNow < deadline {
                    startupPayload = verified.payload
                    startupGraceStart = start
                    startupGraceDeadline = deadline
                } else {
                    droppedExpiredGraceTicket = true
                }
            } else {
                startupPayload = verified.payload
            }
        }
        self.retiredKeyGraceStartEpoch = startupGraceStart
        self.retiredKeyGraceDeadlineEpoch = startupGraceDeadline

        if let storedToken = vault.token, let payload = startupPayload {
            self.isLicensed = true
            self.licenseNeedsReactivation = startupGraceDeadline != nil
            self.orderTag = payload.tag
            self.maskedKey = Self.formatMaskedKey(parentKey: vault.parentKey, orderTag: payload.tag)
            self.seatsUsed = max(1, vault.seatsUsed ?? 1)
            self.maxSeats = max(self.seatsUsed, vault.maxSeats ?? self.configuredMaxSeats)
            self.storedTokenCache = storedToken
            self.storedTokenVerified = true
            self.storedTokenIsSeatBound = payload.boundSeat != nil
            self.pendingCheckoutHandoffCache = nil
            self.pendingCheckoutStartedEpochCache = nil
        } else {
            self.isLicensed = false
            self.orderTag = ""
            self.maskedKey = ""
            self.seatsUsed = 1
            self.maxSeats = self.configuredMaxSeats
            self.storedTokenCache = nil
            self.storedTokenVerified = false
            if let handoff = vault.pendingCheckoutHandoff,
               Self.isValidHandoffToken(handoff),
               let started = vault.pendingCheckoutStartedEpoch,
               nowEpoch - started < Self.checkoutHandoffTTLSeconds {
                self.pendingCheckoutHandoffCache = handoff
                self.pendingCheckoutStartedEpochCache = max(LicenseTicket.minReasonableEpoch, min(nowEpoch, started))
            } else {
                self.pendingCheckoutHandoffCache = nil
                self.pendingCheckoutStartedEpochCache = nil
            }
        }

        if !allAnchorsFresh {
            if self.healSynchronously {
                Self.persistSealToAllAnchors(
                    freshSeal,
                    defaults: self.defaults,
                    defaultsKey: self.defaultsSealKey,
                    fileURLs: self.anchorURLs,
                    useKeychain: useKeychain,
                    keychainService: self.keychainService,
                    keychainAccount: self.keychainTrialAccount
                )
            } else {
                persistenceQueue.asyncAfter(deadline: .now() + 1.5) { [weak self] in
                    guard let self = self else { return }
                    self.stateLock.lock()
                    let shouldWriteInitial = (self.sealGeneration == 0)
                    self.stateLock.unlock()
                    guard shouldWriteInitial else { return }
                    Self.persistSealToAllAnchors(
                        freshSeal,
                        defaults: self.defaults,
                        defaultsKey: self.defaultsSealKey,
                        fileURLs: self.anchorURLs,
                        useKeychain: useKeychain,
                        keychainService: self.keychainService,
                        keychainAccount: self.keychainTrialAccount
                    )
                }
            }
        }

        if !self.pendingDeactivations.isEmpty {
            DispatchQueue.main.asyncAfter(deadline: .now() + (self.deactivationRetryOverride ?? 2.0)) { [weak self] in
                self?.flushPendingDeactivationIfNeeded()
            }
        }

        if droppedExpiredGraceTicket || startupGraceStart != vault.retiredKeyGraceStartEpoch {
            // Persist a new grace start, a cleared one, or the drop of a ticket whose grace period ended.
            persistCurrentVault()
        }
        if startupGraceDeadline != nil,
           !(self.storedParentKeyCache ?? "").isEmpty,
           !self.activationEndpoints.isEmpty {
            scheduleRetiredKeyReactivation(after: self.retiredKeyRetryOverride ?? 2.0)
        }

        if !self.isLicensed,
           self.pendingCheckoutHandoffCache != nil,
           !self.activationEndpoints.isEmpty,
           testingOverrides?.autoResumePendingCheckout ?? true {
            self.resumePendingCheckoutIfNeeded()
        }
    }

    deinit {
        retiredKeyRetryTimer?.cancel()
        retiredKeyRetryTimer = nil
        deactivationRetryTimer?.cancel()
        deactivationRetryTimer = nil
        if let obs = deactivationFocusObserver {
            NotificationCenter.default.removeObserver(obs)
            deactivationFocusObserver = nil
        }
        checkoutPollTimer?.cancel()
        checkoutPollTimer = nil
        if let obs = checkoutFocusObserver {
            NotificationCenter.default.removeObserver(obs)
            checkoutFocusObserver = nil
        }
    }

    // MARK: - Trial Gate & Monotonic Clock

    /// Reads in-memory state only; does not touch disk or Keychain.
    @inline(__always)
    public func verifyGateAccess() -> Bool {
        if !enforceTrialGate {
            return true
        }
        stateLock.lock()
        var verified = storedTokenVerified && storedTokenCache != nil
        let first = firstLaunchEpoch
        let high = highWaterEpoch
        let graceDeadline = retiredKeyGraceDeadlineEpoch
        stateLock.unlock()
        let nowClamped = max(LicenseTicket.minReasonableEpoch, Int64(nowProvider().timeIntervalSince1970))
        let effectiveNow = max(nowClamped, high)
        if verified, let deadline = graceDeadline, effectiveNow >= deadline {
            // A ticket kept alive by a retired key counts only until the grace deadline.
            verified = false
        }
        if verified {
            return true
        }
        let elapsedSeconds = max(0, effectiveNow - first)
        return elapsedSeconds < Int64(trialLengthDays) * 86_400
    }

    /// Updates `highWaterEpoch` on disk at most once per hour.
    public func refreshMonotonicClockIfNeeded() {
        expireRetiredKeyGraceIfNeeded()
        let nowEpoch = max(LicenseTicket.minReasonableEpoch, Int64(nowProvider().timeIntervalSince1970))
        stateLock.lock()
        guard nowEpoch - max(highWaterEpoch, lastClockAdvanceEpoch) >= 3_600 else {
            stateLock.unlock()
            return
        }
        let maxReasonableAdvance = highWaterEpoch + 7 * 86_400
        highWaterEpoch = min(nowEpoch, maxReasonableAdvance)
        lastClockAdvanceEpoch = nowEpoch
        stateLock.unlock()
        persistSeal()
    }

    // MARK: - Retired License Keys

    /// Verifies a stored ticket with the current key first and, only when that fails with `.badSignature`, with each
    /// retired key in order. Use it for a ticket that is already stored, never for a new activation.
    private static func verifyStoredTicket(
        _ token: String,
        scheme: String,
        prefix: String,
        currentKey: Curve25519.Signing.PublicKey?,
        retiredKeys: [Curve25519.Signing.PublicKey],
        seatCode: String,
        revokedBefore: Int64,
        revokedOrderTags: Set<String>
    ) -> (payload: LicenseTicket.Payload, usedRetiredKey: Bool)? {
        guard let currentKey = currentKey else { return nil }
        switch LicenseTicket.verify(
            token,
            scheme: scheme,
            prefix: prefix,
            publicKey: currentKey,
            expectedSeatCode: seatCode,
            revokedBefore: revokedBefore,
            revokedOrderTags: revokedOrderTags
        ) {
        case .success(let payload):
            return (payload, false)
        case .failure(.badSignature):
            break
        case .failure:
            return nil
        }
        for key in retiredKeys {
            if case .success(let payload) = LicenseTicket.verify(
                token,
                scheme: scheme,
                prefix: prefix,
                publicKey: key,
                expectedSeatCode: seatCode,
                revokedBefore: revokedBefore,
                revokedOrderTags: revokedOrderTags
            ) {
                return (payload, true)
            }
        }
        return nil
    }

    private func verifyStoredTicket(
        _ token: String,
        revokedBefore: Int64,
        revokedOrderTags: Set<String>
    ) -> (payload: LicenseTicket.Payload, usedRetiredKey: Bool)? {
        Self.verifyStoredTicket(
            token,
            scheme: scheme,
            prefix: ticketPrefix,
            currentKey: licensePublicKey,
            retiredKeys: retiredLicensePublicKeys,
            seatCode: deviceSeatCode,
            revokedBefore: revokedBefore,
            revokedOrderTags: revokedOrderTags
        )
    }

    /// Clears the retired-key grace state. Callers must hold `stateLock`.
    private func clearRetiredKeyGraceLocked() {
        retiredKeyGraceStartEpoch = nil
        retiredKeyGraceDeadlineEpoch = nil
        retiredKeyRetryTimer?.cancel()
        retiredKeyRetryTimer = nil
        retiredKeyRetryDelay = 60
    }

    /// Drops a ticket kept alive by a retired key once the grace deadline has passed.
    private func expireRetiredKeyGraceIfNeeded() {
        let nowEpoch = max(LicenseTicket.minReasonableEpoch, Int64(nowProvider().timeIntervalSince1970))
        stateLock.lock()
        guard let deadline = retiredKeyGraceDeadlineEpoch, max(nowEpoch, highWaterEpoch) >= deadline else {
            stateLock.unlock()
            return
        }
        stateLock.unlock()
        dropRetiredKeyLicense()
    }

    /// Drops the stored ticket and the grace state; keeps the purchase key so the buyer can activate again.
    private func dropRetiredKeyLicense() {
        stateLock.lock()
        storedTokenCache = nil
        storedTokenVerified = false
        clearRetiredKeyGraceLocked()
        stateLock.unlock()
        self.orderTag = ""
        self.maskedKey = ""
        self.isLicensed = false
        self.licenseNeedsReactivation = false
        persistCurrentVault()
    }

    private func scheduleRetiredKeyReactivation(after delay: TimeInterval) {
        stateLock.lock()
        retiredKeyRetryTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + max(0.005, delay))
        timer.setEventHandler { [weak self] in
            self?.attemptRetiredKeyReactivation()
        }
        retiredKeyRetryTimer = timer
        stateLock.unlock()
        timer.resume()
    }

    /// Schedules the next silent re-activation: 60 s, doubling up to 21600 s (or the testing override).
    private func scheduleRetiredKeyRetry() {
        stateLock.lock()
        let delay = retiredKeyRetryOverride ?? retiredKeyRetryDelay
        retiredKeyRetryDelay = min(21_600, retiredKeyRetryDelay * 2)
        stateLock.unlock()
        scheduleRetiredKeyReactivation(after: delay)
    }

    /// Re-activates a ticket kept alive by a retired key with the stored purchase key on the same seat.
    private func attemptRetiredKeyReactivation() {
        expireRetiredKeyGraceIfNeeded()
        let endpoints = activationEndpoints
        stateLock.lock()
        retiredKeyRetryTimer = nil
        guard retiredKeyGraceDeadlineEpoch != nil,
              storedTokenCache != nil,
              let purchaseKey = storedParentKeyCache, !purchaseKey.isEmpty,
              !endpoints.isEmpty else {
            stateLock.unlock()
            return
        }
        if activationInFlight {
            stateLock.unlock()
            return
        }
        activationInFlight = true
        activationRequestID &+= 1
        let reqID = activationRequestID
        let watermark = seatRevokedBeforeEpoch
        stateLock.unlock()

        var body: [String: Any] = [
            "action": "activate",
            "key": purchaseKey,
            "seat": deviceSeatCode
        ]
        if watermark > 0 {
            body["minIssued"] = NSNumber(value: watermark)
        }
        let payloadData = try? JSONSerialization.data(withJSONObject: body)

        func attempt(at index: Int) {
            var req = URLRequest(url: endpoints[index])
            req.httpMethod = "POST"
            req.timeoutInterval = 8.0
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = payloadData

            networkSession.dataTask(with: req) { [weak self] data, response, error in
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    let status = (response as? HTTPURLResponse)?.statusCode ?? 0
                    let shouldFailover = (error != nil && response == nil) || status == 0 || status == 404 || status >= 500
                    if shouldFailover, index + 1 < endpoints.count {
                        self.stateLock.lock()
                        let current = self.activationRequestID == reqID
                        self.stateLock.unlock()
                        if current {
                            attempt(at: index + 1)
                        }
                        return
                    }
                    self.stateLock.lock()
                    guard self.activationRequestID == reqID else {
                        // Superseded (for example by Deactivate or a user activation), which owns the flag now.
                        self.stateLock.unlock()
                        return
                    }
                    self.activationInFlight = false
                    self.stateLock.unlock()

                    let json = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
                    if status == 403, (json?["error"] as? String) == "invalid_key" {
                        self.dropRetiredKeyLicense()
                        return
                    }
                    if status == 200, let ticket = json?["ticket"] as? String {
                        let result = self.installTicket(
                            ticket,
                            parentSeatKey: purchaseKey,
                            seatsUsed: (json?["seatsUsed"] as? Int) ?? 1,
                            maxSeats: (json?["maxSeats"] as? Int) ?? self.configuredMaxSeats,
                            serverRevokedBefore: (json?["revokedBefore"] as? NSNumber)?.int64Value ?? 0
                        )
                        if result == .installed {
                            return
                        }
                    }
                    self.scheduleRetiredKeyRetry()
                }
            }.resume()
        }

        attempt(at: 0)
    }

    /// Merges newly revoked `"ORD-..."` tags (for example from a signed `version.json` manifest under `.revokeLocalLicense`),
    /// persists them in `.license_vault`, and revokes the currently active ticket in memory if its tag matches.
    /// Revoking a seat-bound ticket also advances the sealed watermark past its `issued`, so the ticket stays
    /// rejected after `.license_vault` is deleted. Add-only: never removes a tag.
    public func recordRevokedOrderTags<S: Sequence>(_ tags: S) where S.Element == String {
        let incoming = LicenseTicket.normalizeOrderTagSet(tags)
        guard !incoming.isEmpty else { return }
        _ = applyRevocationState(sequence: nil, checkSequence: false, tags: incoming, tagStep: .add)
    }

    /// Replaces the manifest-derived revoked tags with `tags` (an empty sequence clears them), then revokes the active
    /// ticket if its tag is still listed. Tags passed to `init(revokedOrderTags:)` stay revoked.
    public func replaceManifestRevokedOrderTags<S: Sequence>(_ tags: S) where S.Element == String {
        _ = applyRevocationState(
            sequence: nil,
            checkSequence: false,
            tags: LicenseTicket.normalizeOrderTagSet(tags),
            tagStep: .replace
        )
    }

    /// Stores a signed manifest sequence when it is higher than the highest accepted one.
    /// A nil sequence counts as 0. A lower sequence returns `.replay` and changes nothing.
    public func acceptManifestSequence(_ sequence: Int64?) -> ManifestSequenceResult {
        applyRevocationState(sequence: sequence, checkSequence: true, tags: [], tagStep: .none)
    }

    /// Applies a verified manifest with one vault write: the sequence step, then (when `mirror` is true) the tag step.
    /// On `.newer` with a non-nil sequence the stored tags are replaced by `revokedTags` (also when it is empty);
    /// in every other accepted case tags are only added. Returns `.replay` without changing anything.
    internal func applyVerifiedManifest(sequence: Int64?, revokedTags: [String], mirror: Bool) -> ManifestSequenceResult {
        applyRevocationState(
            sequence: sequence,
            checkSequence: true,
            tags: LicenseTicket.normalizeOrderTagSet(revokedTags),
            tagStep: mirror ? .mirror : .none
        )
    }

    private enum RevokedTagStep {
        case none
        case add
        case replace
        /// Replace on a newer non-nil sequence, add otherwise.
        case mirror
    }

    private func applyRevocationState(
        sequence: Int64?,
        checkSequence: Bool,
        tags: Set<String>,
        tagStep: RevokedTagStep
    ) -> ManifestSequenceResult {
        stateLock.lock()
        var result: ManifestSequenceResult = .same
        var changed = false
        if checkSequence {
            let incoming = max(0, sequence ?? 0)
            if incoming < highestManifestSeq {
                stateLock.unlock()
                return .replay
            }
            if incoming > highestManifestSeq {
                highestManifestSeq = incoming
                result = .newer
                changed = true
            }
        }
        let beforePersisted = persistedRevokedOrderTags
        switch tagStep {
        case .none:
            break
        case .add:
            persistedRevokedOrderTags.formUnion(tags)
        case .replace:
            persistedRevokedOrderTags = tags
        case .mirror:
            if result == .newer, sequence != nil {
                persistedRevokedOrderTags = tags
            } else {
                persistedRevokedOrderTags.formUnion(tags)
            }
        }
        if persistedRevokedOrderTags != beforePersisted {
            changed = true
        }
        revokedOrderTagsSet = staticRevokedOrderTags.union(persistedRevokedOrderTags)
        let revocation = tagStep == .none ? ActiveTicketRevocation() : revokeActiveTicketIfListedLocked()
        stateLock.unlock()

        finishActiveTicketRevocation(revocation)
        if changed || revocation.revoked {
            persistCurrentVault()
        }
        return result
    }

    private struct ActiveTicketRevocation {
        var revoked = false
        var watermarkRaised = false
    }

    /// Drops the active ticket when its tag is in the effective revoked set. For a seat-bound ticket the watermark
    /// moves to `issued + 1` (never lowered). Call with `stateLock` held, then `finishActiveTicketRevocation` after unlocking.
    private func revokeActiveTicketIfListedLocked() -> ActiveTicketRevocation {
        var out = ActiveTicketRevocation()
        guard storedTokenVerified,
              let token = storedTokenCache else { return out }
        switch verifyStoredTicket(token, revokedBefore: 0, revokedOrderTags: []) {
        case .some(let verified):
            let payload = verified.payload
            guard let tag = LicenseTicket.canonicalOrderTag(payload.tag), revokedOrderTagsSet.contains(tag) else {
                return out
            }
            out.revoked = true
            if payload.boundSeat != nil {
                let floor = payload.issued + 1
                if floor > seatRevokedBeforeEpoch {
                    seatRevokedBeforeEpoch = floor
                    out.watermarkRaised = true
                }
            }
        case .none:
            out.revoked = true
        }
        clearRetiredKeyGraceLocked()
        // Keep `storedParentKeyCache`: a buyer revoked by mistake re-activates with one click after a corrected manifest.
        storedTokenCache = nil
        storedTokenVerified = false
        return out
    }

    /// Publishes a revocation made by `revokeActiveTicketIfListedLocked` and seals a raised watermark. Call without the lock.
    private func finishActiveTicketRevocation(_ revocation: ActiveTicketRevocation) {
        if revocation.revoked {
            self.isLicensed = false
            self.orderTag = ""
            self.maskedKey = ""
            self.licenseNeedsReactivation = false
        }
        if revocation.watermarkRaised {
            persistSeal()
        }
    }

    // MARK: - Activation & Deactivation

    public func activate(key rawKey: String, completion: @escaping (ActivationOutcome) -> Void) {
        let cleaned = rawKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleaned.isEmpty, cleaned.count <= 512 else {
            completion(.invalidKey)
            return
        }

        if activateOfflineTicket(cleaned) {
            completion(.activated)
            return
        }
        if !ticketPrefix.isEmpty, cleaned.uppercased().hasPrefix(ticketPrefix.uppercased()) {
            completion(.invalidKey)
            return
        }

        let endpoints = activationEndpoints
        guard !endpoints.isEmpty else {
            completion(.unconfigured)
            return
        }
        // The Worker refuses keys longer than 256 characters; a garbage paste never reaches the status mapping.
        guard cleaned.count <= 256 else {
            completion(.invalidKey)
            return
        }

        // A release of this same key may be on the wire: wait for its answer, or the server could process the two
        // requests in either order and free the seat of a Mac that stays licensed.
        stateLock.lock()
        if deactivationFlushInFlight, deactivationFlushEntry?.key == cleaned {
            deactivationFlushWaiters.append { [weak self] in
                guard let self = self else {
                    completion(.networkError)
                    return
                }
                self.activate(key: rawKey, completion: completion)
            }
            stateLock.unlock()
            return
        }
        let releaseOtherKey = pendingDeactivations.contains { $0.key != cleaned }
        stateLock.unlock()
        if releaseOtherKey {
            flushPendingDeactivationIfNeeded()
        }

        stateLock.lock()
        if activationInFlight {
            stateLock.unlock()
            completion(.networkError)
            return
        }
        activationInFlight = true
        activationRequestID &+= 1
        let reqID = activationRequestID
        let watermark = seatRevokedBeforeEpoch
        stateLock.unlock()
        // Publish outside the lock: `objectWillChange` fires synchronously and subscribers may read locked properties.
        isActivatingOnline = true

        var activateBody: [String: Any] = [
            "action": "activate",
            "key": cleaned,
            "seat": deviceSeatCode
        ]
        if watermark > 0 {
            activateBody["minIssued"] = NSNumber(value: watermark)
        }
        let payloadData = try? JSONSerialization.data(withJSONObject: activateBody)

        func attemptActivation(at index: Int) {
            var req = URLRequest(url: endpoints[index])
            req.httpMethod = "POST"
            req.timeoutInterval = 8.0
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = payloadData

            networkSession.dataTask(with: req) { [weak self] data, response, error in
                DispatchQueue.main.async {
                    guard let self = self else {
                        completion(.networkError)
                        return
                    }
                    self.stateLock.lock()
                    guard self.activationRequestID == reqID else {
                        self.stateLock.unlock()
                        completion(.networkError)
                        return
                    }
                    let status = (response as? HTTPURLResponse)?.statusCode ?? 0
                    let shouldFailover = (error != nil && response == nil) || status == 0 || status == 404 || status >= 500
                    if shouldFailover, index + 1 < endpoints.count {
                        self.stateLock.unlock()
                        attemptActivation(at: index + 1)
                        return
                    }
                    self.activationInFlight = false
                    self.stateLock.unlock()
                    self.isActivatingOnline = false

                    if error != nil && response == nil {
                        completion(.networkError)
                        return
                    }
                    if status == 409 {
                        let errorCode = data
                            .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
                            .flatMap { $0["error"] as? String }
                        completion(errorCode == "payment_pending" ? .paymentPending : .seatLimitReached)
                        return
                    }
                    if status == 429 || status >= 500 || status == 0 {
                        completion(.networkError)
                        return
                    }
                    if (400..<500).contains(status) {
                        // Only a definite answer about the key is a wrong key. Any other 4xx (a path in the endpoint
                        // URL, a proxy, an unknown code) is a setup or transport problem.
                        let errorCode = data
                            .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
                            .flatMap { $0["error"] as? String }
                        let isKeyAnswer = status == 403 && (errorCode == "invalid_key" || errorCode == "payment_disputed")
                        completion(isKeyAnswer ? .invalidKey : .networkError)
                        return
                    }
                    guard status == 200,
                          let data = data,
                          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                          let ticket = json["ticket"] as? String else {
                        completion(.invalidKey)
                        return
                    }
                    let serverRevoked = (json["revokedBefore"] as? NSNumber)?.int64Value ?? 0
                    switch self.installTicket(
                        ticket,
                        parentSeatKey: cleaned,
                        seatsUsed: (json["seatsUsed"] as? Int) ?? 1,
                        maxSeats: (json["maxSeats"] as? Int) ?? self.configuredMaxSeats,
                        serverRevokedBefore: serverRevoked
                    ) {
                    case .installed:
                        completion(.activated)
                    case .belowWatermark:
                        completion(.clockSkew)
                    case .rejected:
                        completion(.invalidKey)
                    }
                }
            }.resume()
        }

        attemptActivation(at: 0)
    }

    @MainActor
    public func activate(key rawKey: String) async -> ActivationOutcome {
        await withCheckedContinuation { continuation in
            activate(key: rawKey) { outcome in
                continuation.resume(returning: outcome)
            }
        }
    }

    @discardableResult
    public func activateOfflineTicket(
        _ rawTicket: String,
        parentSeatKey: String? = nil,
        seatsUsed: Int = 1,
        maxSeats: Int? = nil,
        serverRevokedBefore: Int64 = 0
    ) -> Bool {
        installTicket(
            rawTicket,
            parentSeatKey: parentSeatKey,
            seatsUsed: seatsUsed,
            maxSeats: maxSeats,
            serverRevokedBefore: serverRevokedBefore
        ) == .installed
    }

    private func installTicket(
        _ rawTicket: String,
        parentSeatKey: String?,
        seatsUsed: Int,
        maxSeats: Int?,
        serverRevokedBefore: Int64
    ) -> TicketInstallResult {
        guard let pubKey = licensePublicKey else { return .rejected }
        let cleaned = rawTicket.trimmingCharacters(in: .whitespacesAndNewlines)
        let isServerIssued = (parentSeatKey?.isEmpty == false)

        stateLock.lock()
        let currentWatermark = seatRevokedBeforeEpoch
        let currentRevokedTags = revokedOrderTagsSet
        stateLock.unlock()

        let payload: LicenseTicket.Payload
        switch LicenseTicket.verify(
            cleaned,
            scheme: scheme,
            prefix: ticketPrefix,
            publicKey: pubKey,
            expectedSeatCode: deviceSeatCode,
            revokedBefore: currentWatermark,
            revokedOrderTags: currentRevokedTags
        ) {
        case .success(let verified):
            payload = verified
        case .failure(.revoked) where isServerIssued:
            // A correctly signed server ticket that fails only on the sealed watermark points at a clock
            // disagreement (or a replayed response), not at a bad key.
            if case .success = LicenseTicket.verify(
                cleaned,
                scheme: scheme,
                prefix: ticketPrefix,
                publicKey: pubKey,
                expectedSeatCode: deviceSeatCode,
                revokedBefore: 0,
                revokedOrderTags: currentRevokedTags
            ) {
                return .belowWatermark
            }
            return .rejected
        case .failure:
            return .rejected
        }

        stateLock.lock()
        if isServerIssued {
            // Never lower the watermark. `serverRevokedBefore` is unsigned response data, so it may raise the
            // watermark only up to the verified ticket's `issued` timestamp.
            seatRevokedBeforeEpoch = max(seatRevokedBeforeEpoch, min(max(0, serverRevokedBefore), payload.issued))
        }
        let resolvedParent: String?
        if let parentSeatKey = parentSeatKey, !parentSeatKey.isEmpty {
            storedParentKeyCache = parentSeatKey
            resolvedParent = parentSeatKey
        } else {
            resolvedParent = storedParentKeyCache
        }
        storedTokenCache = cleaned
        storedTokenVerified = true
        storedTokenIsSeatBound = payload.boundSeat != nil
        // The same purchase is in use on this Mac again, so its queued release must not be sent. A queued release of
        // another purchase still has to reach the server.
        let newTag = LicenseTicket.canonicalOrderTag(payload.tag)
        pendingDeactivations.removeAll { entry in
            if let parentSeatKey = parentSeatKey, !parentSeatKey.isEmpty, entry.key == parentSeatKey {
                return true
            }
            guard let entryTicket = entry.ticket,
                  let entryPayload = verifyStoredTicket(entryTicket, revokedBefore: 0, revokedOrderTags: [])?.payload else {
                return false
            }
            return newTag != nil && LicenseTicket.canonicalOrderTag(entryPayload.tag) == newTag
        }
        pendingCheckoutHandoffCache = nil
        pendingCheckoutStartedEpochCache = nil
        checkoutOutcomeCallback = nil
        stopActiveCheckoutPollingLocked()
        // A ticket under the current key ends any retired-key grace period.
        clearRetiredKeyGraceLocked()
        let used = max(1, seatsUsed)
        let cap = max(used, maxSeats ?? configuredMaxSeats)
        stateLock.unlock()

        self.isAwaitingBrowserCheckout = false
        self.licenseNeedsReactivation = false
        self.isLicensed = true
        self.orderTag = payload.tag
        self.maskedKey = Self.formatMaskedKey(parentKey: resolvedParent, orderTag: payload.tag)
        self.seatsUsed = used
        self.maxSeats = cap

        if isServerIssued {
            persistSeal()
        }
        persistCurrentVault()
        flushPendingDeactivationIfNeeded()
        return .installed
    }

    public func deactivate() {
        let nowEpoch = max(LicenseTicket.minReasonableEpoch, Int64(nowProvider().timeIntervalSince1970))

        stateLock.lock()
        activationRequestID &+= 1
        let parentKey = storedParentKeyCache
        let releasedTicket = storedTokenCache
        var releasedIssued: Int64 = 0
        if let ticket = releasedTicket,
           let verified = verifyStoredTicket(ticket, revokedBefore: 0, revokedOrderTags: []) {
            releasedIssued = verified.payload.issued
        }
        // Advance strictly past the released ticket's `issued` timestamp (+1s) so re-pasting the just-deactivated
        // ticket fails even within the same wall-clock second. Follow the clock, but never more than 365 days past
        // the released ticket, so the cutoff stays below what the Worker can mint (now + 366 days at most).
        let clockFloor = max(nowEpoch, highWaterEpoch)
        let floor: Int64
        if releasedIssued > 0 {
            floor = max(releasedIssued, min(clockFloor, releasedIssued + 365 * 86_400)) + 1
        } else {
            floor = clockFloor + 1
        }
        seatRevokedBeforeEpoch = max(seatRevokedBeforeEpoch, floor)
        storedTokenCache = nil
        storedTokenVerified = false
        storedParentKeyCache = nil
        if let parentKey = parentKey {
            pendingDeactivations.append(PendingDeactivation(key: parentKey, ticket: releasedTicket))
            if pendingDeactivations.count > Self.maxPendingDeactivations {
                pendingDeactivations.removeFirst(pendingDeactivations.count - Self.maxPendingDeactivations)
            }
        }
        pendingCheckoutHandoffCache = nil
        pendingCheckoutStartedEpochCache = nil
        checkoutOutcomeCallback = nil
        activationInFlight = false
        stopActiveCheckoutPollingLocked()
        clearRetiredKeyGraceLocked()
        stateLock.unlock()

        self.isAwaitingBrowserCheckout = false
        self.isActivatingOnline = false
        self.licenseNeedsReactivation = false
        self.isLicensed = false
        self.orderTag = ""
        self.maskedKey = ""

        persistSeal()
        persistCurrentVault()
        flushPendingDeactivationIfNeeded()
    }

    // MARK: - Email Key Recovery

    /// Heuristic used by the unified license field: true for `name@domain.tld`, false for `cs_live_...`,
    /// store UUIDs, and `LK1-` tickets. Mirrors the Worker's `normalizeRecoveryEmail` shape check.
    public static func looksLikeEmail(_ input: String) -> Bool {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count >= 3, trimmed.count <= 254 else { return false }
        guard !trimmed.contains(where: { $0.isWhitespace || $0.isNewline || ($0.asciiValue.map { $0 < 0x21 || $0 == 0x7f } ?? false) }) else { return false }
        let parts = trimmed.split(separator: "@", omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty else { return false }
        let domain = parts[1]
        guard let dot = domain.firstIndex(of: "."), dot != domain.startIndex, domain.index(after: dot) != domain.endIndex else { return false }
        return domain.last != "."
    }

    /// Asks the Worker to email every `cs_live_...` key tied to `email`. The address is sent once over TLS and is
    /// never written to disk, `UserDefaults`, or Keychain by this SDK.
    public func requestKeyRecovery(email rawEmail: String, completion: @escaping (RecoveryOutcome) -> Void) {
        let trimmed = rawEmail.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.looksLikeEmail(trimmed) else {
            completion(.invalidEmail)
            return
        }
        let endpoints = activationEndpoints
        guard !endpoints.isEmpty else {
            completion(.unconfigured)
            return
        }

        stateLock.lock()
        if recoveryInFlight {
            stateLock.unlock()
            completion(.networkError)
            return
        }
        recoveryInFlight = true
        stateLock.unlock()
        isRequestingKeyRecovery = true

        let payloadData = try? JSONSerialization.data(withJSONObject: ["action": "recover", "email": trimmed])

        func finish(_ outcome: RecoveryOutcome) {
            stateLock.lock()
            recoveryInFlight = false
            stateLock.unlock()
            isRequestingKeyRecovery = false
            completion(outcome)
        }

        func attempt(at index: Int) {
            var req = URLRequest(url: endpoints[index])
            req.httpMethod = "POST"
            req.timeoutInterval = 8.0
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = payloadData

            networkSession.dataTask(with: req) { [weak self] _, response, error in
                DispatchQueue.main.async {
                    guard self != nil else {
                        completion(.networkError)
                        return
                    }
                    let status = (response as? HTTPURLResponse)?.statusCode ?? 0
                    let shouldFailover = (error != nil && response == nil) || status == 0 || status == 404 || status >= 500
                    if shouldFailover, index + 1 < endpoints.count {
                        attempt(at: index + 1)
                        return
                    }
                    switch status {
                    case 200: finish(.sent)
                    case 501: finish(.unconfigured)
                    case 429: finish(.rateLimited)
                    case 400: finish(.invalidEmail)
                    default: finish(.networkError)
                    }
                }
            }.resume()
        }

        attempt(at: 0)
    }

    @MainActor
    public func requestKeyRecovery(email: String) async -> RecoveryOutcome {
        await withCheckedContinuation { continuation in
            requestKeyRecovery(email: email) { outcome in
                continuation.resume(returning: outcome)
            }
        }
    }

    // MARK: - Default-Browser Checkout Handoff (`client_reference_id`)

    /// Generates a cryptographically random `"chk_<32 lowercase hex>"` handoff token (128 bits).
    public static func generateHandoffToken() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status != errSecSuccess {
            var rng = SystemRandomNumberGenerator()
            for i in 0..<bytes.count {
                bytes[i] = UInt8.random(in: 0...255, using: &rng)
            }
        }
        return "chk_" + bytes.map { String(format: "%02x", $0) }.joined()
    }

    internal static func isValidHandoffToken(_ raw: String) -> Bool {
        guard raw.hasPrefix("chk_"), raw.utf8.count == 36 else { return false }
        for c in raw.dropFirst(4) {
            let isLowerHex = (c >= "0" && c <= "9") || (c >= "a" && c <= "f")
            if !isLowerHex { return false }
        }
        return true
    }

    /// Appends or replaces `client_reference_id=<handoffToken>` on a Stripe Payment Link while preserving existing query parameters.
    @discardableResult
    public func checkoutURL(for paymentLink: URL, handoffToken: String) -> URL {
        guard var comps = URLComponents(url: paymentLink, resolvingAgainstBaseURL: false) else {
            return paymentLink
        }
        var items = (comps.queryItems ?? []).filter { $0.name != "client_reference_id" }
        items.append(URLQueryItem(name: "client_reference_id", value: handoffToken))
        comps.queryItems = items
        return comps.url ?? paymentLink
    }

    /// Opens `paymentLink` tagged with a 128-bit `client_reference_id` in the user's default browser
    /// and starts background claim polling + app-focus observation so the Mac app activates automatically.
    /// Without `activationEndpoints` the tagged URL is still opened, nothing is persisted or polled, and `onOutcome`
    /// receives `.unconfigured` at once.
    @discardableResult
    public func beginBrowserCheckout(
        paymentLink: URL,
        openURL: ((URL) -> Void)? = nil,
        onOutcome: ((ActivationOutcome) -> Void)? = nil
    ) -> URL {
        let handoff = Self.generateHandoffToken()
        let taggedURL = checkoutURL(for: paymentLink, handoffToken: handoff)
        let open = openURL ?? { NSWorkspace.shared.open($0) }

        guard !activationEndpoints.isEmpty else {
            open(taggedURL)
            onOutcome?(.unconfigured)
            return taggedURL
        }

        let nowEpoch = max(LicenseTicket.minReasonableEpoch, Int64(nowProvider().timeIntervalSince1970))
        stateLock.lock()
        let gen = stopActiveCheckoutPollingLocked()
        pendingCheckoutHandoffCache = handoff
        pendingCheckoutStartedEpochCache = nowEpoch
        checkoutOutcomeCallback = onOutcome
        checkoutPollAttemptCount = 0
        installCheckoutFocusObserverLocked(generation: gen)
        stateLock.unlock()

        self.isAwaitingBrowserCheckout = true
        persistCurrentVault()
        open(taggedURL)
        scheduleNextCheckoutPollTick(generation: gen)
        return taggedURL
    }

    /// Cancels active browser checkout polling and clears the pending handoff token from memory and `.license_vault`.
    public func cancelBrowserCheckout() {
        stateLock.lock()
        _ = stopActiveCheckoutPollingLocked()
        pendingCheckoutHandoffCache = nil
        pendingCheckoutStartedEpochCache = nil
        checkoutOutcomeCallback = nil
        stateLock.unlock()

        self.isAwaitingBrowserCheckout = false
        persistCurrentVault()
    }

    /// If unlicensed and an unexpired (`< 24h`) `pendingCheckoutHandoff` exists in `.license_vault`,
    /// performs a claim check (`fallbackSearch: true`) and resumes bounded polling if still within the 15-minute active window.
    public func resumePendingCheckoutIfNeeded(onOutcome: ((ActivationOutcome) -> Void)? = nil) {
        guard !activationEndpoints.isEmpty else { return }
        let nowEpoch = max(LicenseTicket.minReasonableEpoch, Int64(nowProvider().timeIntervalSince1970))

        stateLock.lock()
        guard !storedTokenVerified,
              let handoff = pendingCheckoutHandoffCache,
              Self.isValidHandoffToken(handoff),
              let started = pendingCheckoutStartedEpochCache else {
            stateLock.unlock()
            return
        }
        let elapsed = max(0, nowEpoch - started)
        if elapsed >= Self.checkoutHandoffTTLSeconds {
            stateLock.unlock()
            cancelBrowserCheckout()
            return
        }
        if let onOutcome = onOutcome {
            checkoutOutcomeCallback = onOutcome
        }
        let gen = stopActiveCheckoutPollingLocked()
        checkoutPollAttemptCount = 0
        let withinActiveWindow = elapsed < Self.checkoutMaxActivePollWindowSeconds
        if withinActiveWindow {
            installCheckoutFocusObserverLocked(generation: gen)
        }
        stateLock.unlock()

        if withinActiveWindow {
            self.isAwaitingBrowserCheckout = true
            scheduleNextCheckoutPollTick(generation: gen)
        }
        performCheckoutClaimCheck(generation: gen, forceFallbackSearch: true)
    }

    /// Invalidates every outstanding timer, observer, and in-flight claim, and returns the new generation.
    /// Callers must hold `stateLock`.
    @discardableResult
    private func stopActiveCheckoutPollingLocked() -> UInt64 {
        checkoutPollGeneration &+= 1
        isClaimCheckInFlight = false
        tearDownCheckoutTimerAndObserverLocked()
        return checkoutPollGeneration
    }

    /// Callers must hold `stateLock`.
    private func tearDownCheckoutTimerAndObserverLocked() {
        checkoutPollTimer?.cancel()
        checkoutPollTimer = nil
        if let obs = checkoutFocusObserver {
            NotificationCenter.default.removeObserver(obs)
            checkoutFocusObserver = nil
        }
    }

    /// Callers must hold `stateLock` and have just bumped to `generation`, so no stale observer can be registered.
    private func installCheckoutFocusObserverLocked(generation: UInt64) {
        if let existing = checkoutFocusObserver {
            NotificationCenter.default.removeObserver(existing)
        }
        checkoutFocusObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.performCheckoutClaimCheck(generation: generation, forceFallbackSearch: true)
        }
    }

    private func scheduleNextCheckoutPollTick(generation: UInt64) {
        let nowEpoch = max(LicenseTicket.minReasonableEpoch, Int64(nowProvider().timeIntervalSince1970))
        stateLock.lock()
        guard checkoutPollGeneration == generation,
              !storedTokenVerified,
              pendingCheckoutHandoffCache != nil,
              let started = pendingCheckoutStartedEpochCache else {
            stateLock.unlock()
            return
        }
        let elapsed = max(0, nowEpoch - started)
        if elapsed >= Self.checkoutMaxActivePollWindowSeconds {
            // Active window over: stop timers and focus wakeups but keep the vault handoff for relaunch recovery.
            tearDownCheckoutTimerAndObserverLocked()
            stateLock.unlock()
            self.isAwaitingBrowserCheckout = false
            return
        }
        checkoutPollTimer?.cancel()
        let interval: TimeInterval = checkoutPollIntervalOverride
            ?? (elapsed < Self.checkoutFastPollWindowSeconds ? Self.checkoutFastPollInterval : Self.checkoutSlowPollInterval)
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + max(0.005, interval))
        timer.setEventHandler { [weak self] in
            self?.performCheckoutClaimCheck(generation: generation, forceFallbackSearch: false)
        }
        checkoutPollTimer = timer
        stateLock.unlock()
        timer.resume()
    }

    private func performCheckoutClaimCheck(generation: UInt64, forceFallbackSearch: Bool) {
        let endpoints = activationEndpoints
        guard !endpoints.isEmpty else { return }

        stateLock.lock()
        guard checkoutPollGeneration == generation,
              !storedTokenVerified,
              !isClaimCheckInFlight,
              let handoff = pendingCheckoutHandoffCache,
              Self.isValidHandoffToken(handoff) else {
            stateLock.unlock()
            return
        }
        isClaimCheckInFlight = true
        checkoutPollAttemptCount += 1
        let useFallbackSearch = forceFallbackSearch || (checkoutPollAttemptCount % 5 == 0)
        let watermark = seatRevokedBeforeEpoch
        stateLock.unlock()

        var claimBody: [String: Any] = [
            "action": "claim_checkout",
            "handoff": handoff,
            "seat": deviceSeatCode,
            "fallbackSearch": useFallbackSearch
        ]
        if watermark > 0 {
            claimBody["minIssued"] = NSNumber(value: watermark)
        }
        let payloadData = try? JSONSerialization.data(withJSONObject: claimBody)

        func attemptClaim(at index: Int) {
            var req = URLRequest(url: endpoints[index])
            req.httpMethod = "POST"
            req.timeoutInterval = 8.0
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = payloadData

            networkSession.dataTask(with: req) { [weak self] data, response, error in
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    let status = (response as? HTTPURLResponse)?.statusCode ?? 0
                    let shouldFailover = (error != nil && response == nil) || status == 0 || status == 404 || status >= 500
                    if shouldFailover, index + 1 < endpoints.count {
                        attemptClaim(at: index + 1)
                        return
                    }

                    self.stateLock.lock()
                    // Only this generation may clear its own in-flight flag; a stale completion must not unblock a newer one.
                    guard self.checkoutPollGeneration == generation else {
                        self.stateLock.unlock()
                        return
                    }
                    self.isClaimCheckInFlight = false
                    guard !self.storedTokenVerified, self.pendingCheckoutHandoffCache == handoff else {
                        self.stateLock.unlock()
                        return
                    }
                    let callback = self.checkoutOutcomeCallback
                    self.stateLock.unlock()

                    self.handleClaimResponse(status: status, data: data, generation: generation, callback: callback)
                }
            }.resume()
        }

        attemptClaim(at: 0)
    }

    private func handleClaimResponse(
        status: Int,
        data: Data?,
        generation: UInt64,
        callback: ((ActivationOutcome) -> Void)?
    ) {
        func finish(_ outcome: ActivationOutcome) {
            cancelBrowserCheckout()
            callback?(outcome)
        }
        let errorCode: String? = data
            .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            .flatMap { $0["error"] as? String }
        switch status {
        case 202:
            scheduleNextCheckoutPollTick(generation: generation)
        case 200:
            guard let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let key = json["key"] as? String, !key.isEmpty,
                  let ticket = json["ticket"] as? String, !ticket.isEmpty else {
                finish(.invalidKey)
                return
            }
            switch installTicket(
                ticket,
                parentSeatKey: key,
                seatsUsed: (json["seatsUsed"] as? Int) ?? 1,
                maxSeats: (json["maxSeats"] as? Int) ?? configuredMaxSeats,
                serverRevokedBefore: (json["revokedBefore"] as? NSNumber)?.int64Value ?? 0
            ) {
            case .installed:
                // installTicket already cleared the handoff and stopped polling.
                callback?(.activated)
            case .belowWatermark:
                finish(.clockSkew)
            case .rejected:
                finish(.invalidKey)
            }
        case 409 where errorCode == "payment_pending":
            // The checkout session is open or the payment has not settled yet: keep polling inside the window.
            scheduleNextCheckoutPollTick(generation: generation)
        case 409:
            finish(.seatLimitReached)
        case 429:
            scheduleNextCheckoutPollTick(generation: generation)
        case 403 where errorCode == "handoff_seat_mismatch":
            // Another seat code polled this handoff first. Stop polling; the key is still on the thank-you page.
            finish(.networkError)
        case 403 where errorCode == "invalid_key" || errorCode == "payment_disputed":
            finish(.invalidKey)
        case 400..<500:
            // Any other client error (400 invalid_params, 404 for a path in the endpoint URL, ...) is a setup or
            // transport problem, not a wrong key. All are terminal; retrying cannot help.
            finish(.networkError)
        default:
            // Transport error or 5xx: keep polling until the active window expires.
            scheduleNextCheckoutPollTick(generation: generation)
        }
    }

    // MARK: - Persistence & Keychain

    /// Sends the oldest queued seat release. Terminal answers remove it and move on to the next entry; any other
    /// answer keeps it and arms a retry (30 s doubling up to 1 hour) plus an app-focus trigger.
    private func flushPendingDeactivationIfNeeded() {
        let endpoints = activationEndpoints
        stateLock.lock()
        if pendingDeactivations.isEmpty {
            tearDownDeactivationRetryLocked()
            stateLock.unlock()
            return
        }
        if endpoints.isEmpty {
            // A kit without endpoints can never deliver a release; drop the queue.
            pendingDeactivations.removeAll()
            tearDownDeactivationRetryLocked()
            stateLock.unlock()
            persistCurrentVault()
            return
        }
        if deactivationFlushInFlight {
            stateLock.unlock()
            return
        }
        if activationInFlight {
            // Do not race an activation; try again later so the entry is not forgotten if the activation fails.
            armDeactivationRetryLocked(advanceBackoff: false)
            stateLock.unlock()
            return
        }
        let entry = pendingDeactivations[0]
        deactivationFlushInFlight = true
        deactivationFlushEntry = entry
        deactivationRetryTimer?.cancel()
        deactivationRetryTimer = nil
        installDeactivationFocusObserverLocked()
        stateLock.unlock()

        var body: [String: Any] = [
            "action": "deactivate",
            "key": entry.key,
            "seat": deviceSeatCode
        ]
        if let ticket = entry.ticket, !ticket.isEmpty {
            body["ticket"] = ticket
        }
        let payloadData = try? JSONSerialization.data(withJSONObject: body)

        func attemptDeactivation(at index: Int) {
            var req = URLRequest(url: endpoints[index])
            req.httpMethod = "POST"
            req.timeoutInterval = 6.0
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = payloadData
            networkSession.dataTask(with: req) { [weak self] data, response, error in
                DispatchQueue.main.async {
                    let status = (response as? HTTPURLResponse)?.statusCode ?? 0
                    let shouldFailover = (error != nil && response == nil) || status == 0 || status == 404 || status >= 500
                    if shouldFailover, index + 1 < endpoints.count {
                        attemptDeactivation(at: index + 1)
                        return
                    }
                    let json: [String: Any]? = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
                    self?.handleDeactivationResult(entry: entry, status: status, json: json)
                }
            }.resume()
        }

        attemptDeactivation(at: 0)
    }

    /// Runs on the main queue.
    private func handleDeactivationResult(entry: PendingDeactivation, status: Int, json: [String: Any]?) {
        let errorCode = json?["error"] as? String
        let retryAfterSec = (json?["retryAfterSec"] as? NSNumber)?.int64Value
        let isReleaseLimit = (status == 429 && errorCode == "release_limit")
        let isTerminal = (status == 200)
            || isReleaseLimit
            || (status == 400 && errorCode == "ticket_required")
            || (status == 403 && (errorCode == "invalid_ticket" || errorCode == "invalid_key"))
            || (status == 404 && errorCode == "unknown_key")

        stateLock.lock()
        deactivationFlushInFlight = false
        deactivationFlushEntry = nil
        let waiters = deactivationFlushWaiters
        deactivationFlushWaiters = []
        var clearBlockedDate = false
        var flushNext = false
        if isTerminal {
            if let index = pendingDeactivations.firstIndex(of: entry) {
                pendingDeactivations.remove(at: index)
            }
            deactivationRetryAttempt = 0
            if isReleaseLimit {
                releaseLimitKey = entry.key
                if storedTokenCache == nil, storedParentKeyCache == nil {
                    // The seat is still assigned on the server, so let the user activate this Mac again.
                    storedParentKeyCache = entry.key
                }
            } else if status == 200, releaseLimitKey == entry.key {
                releaseLimitKey = nil
                clearBlockedDate = true
            }
            flushNext = !pendingDeactivations.isEmpty
            if !flushNext {
                tearDownDeactivationRetryLocked()
            }
        } else {
            armDeactivationRetryLocked(advanceBackoff: true)
        }
        stateLock.unlock()

        if isReleaseLimit {
            let wait = min(max(retryAfterSec ?? 365 * 86_400, 1), 366 * 86_400)
            seatReleaseBlockedUntil = nowProvider().addingTimeInterval(TimeInterval(wait))
        } else if clearBlockedDate {
            seatReleaseBlockedUntil = nil
        }
        if isTerminal {
            persistCurrentVault()
        }
        for waiter in waiters {
            waiter()
        }
        if flushNext {
            flushPendingDeactivationIfNeeded()
        }
    }

    /// Arms the one-shot retry timer: `min(3600, 30 * 2^attempt)` seconds, or the testing override.
    /// Callers must hold `stateLock`.
    private func armDeactivationRetryLocked(advanceBackoff: Bool) {
        let exponent = min(deactivationRetryAttempt, 7)
        let delay = deactivationRetryOverride ?? min(3600, 30 * pow(2.0, Double(exponent)))
        if advanceBackoff {
            deactivationRetryAttempt += 1
        }
        deactivationRetryTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + max(0.005, delay))
        timer.setEventHandler { [weak self] in
            self?.flushPendingDeactivationIfNeeded()
        }
        deactivationRetryTimer = timer
        installDeactivationFocusObserverLocked()
        timer.resume()
    }

    /// Callers must hold `stateLock`.
    private func installDeactivationFocusObserverLocked() {
        guard deactivationFocusObserver == nil else { return }
        deactivationFocusObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.flushPendingDeactivationIfNeeded()
        }
    }

    /// Callers must hold `stateLock`.
    private func tearDownDeactivationRetryLocked() {
        deactivationRetryTimer?.cancel()
        deactivationRetryTimer = nil
        deactivationRetryAttempt = 0
        if let obs = deactivationFocusObserver {
            NotificationCenter.default.removeObserver(obs)
            deactivationFocusObserver = nil
        }
    }

    private func persistSeal() {
        stateLock.lock()
        sealGeneration &+= 1
        let seal = TrialSeal.make(
            first: firstLaunchEpoch,
            high: highWaterEpoch,
            revokedBefore: seatRevokedBeforeEpoch,
            key: trialHMACKey
        )
        stateLock.unlock()

        let defaultsRef = defaults
        let sealKey = defaultsSealKey
        let urls = anchorURLs
        let useKeychain = canUseKeychainAnchor
        let service = keychainService
        let account = keychainTrialAccount
        if healSynchronously {
            Self.persistSealToAllAnchors(
                seal,
                defaults: defaultsRef,
                defaultsKey: sealKey,
                fileURLs: urls,
                useKeychain: useKeychain,
                keychainService: service,
                keychainAccount: account
            )
        } else {
            persistenceQueue.async {
                Self.persistSealToAllAnchors(
                    seal,
                    defaults: defaultsRef,
                    defaultsKey: sealKey,
                    fileURLs: urls,
                    useKeychain: useKeychain,
                    keychainService: service,
                    keychainAccount: account
                )
            }
        }
    }

    private func persistCurrentVault() {
        stateLock.lock()
        let savedRevoked = persistedRevokedOrderTags.isEmpty ? nil : persistedRevokedOrderTags.sorted()
        let hasActiveHandoff = (storedTokenCache == nil && pendingCheckoutHandoffCache != nil)
        let vault = StoredLicenseVault(
            token: storedTokenCache,
            parentKey: storedParentKeyCache,
            seatsUsed: storedTokenCache != nil ? seatsUsed : nil,
            maxSeats: storedTokenCache != nil ? maxSeats : nil,
            revokedOrderTags: savedRevoked,
            pendingCheckoutHandoff: hasActiveHandoff ? pendingCheckoutHandoffCache : nil,
            pendingCheckoutStartedEpoch: hasActiveHandoff ? pendingCheckoutStartedEpochCache : nil,
            manifestSeq: highestManifestSeq > 0 ? highestManifestSeq : nil,
            retiredKeyGraceStartEpoch: storedTokenCache != nil ? retiredKeyGraceStartEpoch : nil,
            pendingDeactivations: pendingDeactivations.isEmpty ? nil : pendingDeactivations
        )
        stateLock.unlock()

        let url = vaultURL
        let useKeychain = canUseKeychainAnchor
        let service = keychainService
        let account = keychainLicenseAccount
        if healSynchronously {
            Self.saveLicenseVault(
                vault,
                vaultURL: url,
                useKeychain: useKeychain,
                keychainService: service,
                keychainAccount: account
            )
        } else {
            persistenceQueue.async {
                Self.saveLicenseVault(
                    vault,
                    vaultURL: url,
                    useKeychain: useKeychain,
                    keychainService: service,
                    keychainAccount: account
                )
            }
        }
    }

    internal static func decodePublicKey(base64: String) -> Curve25519.Signing.PublicKey? {
        let trimmed = base64.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = Data(base64Encoded: trimmed), data.count == 32 else { return nil }
        return try? Curve25519.Signing.PublicKey(rawRepresentation: data)
    }

    private static func formatMaskedKey(parentKey: String?, orderTag: String) -> String {
        if let parent = parentKey, !parent.isEmpty {
            return "••••-\(parent.suffix(6))"
        }
        return orderTag
    }

    private static func defaultLicenseVaultFileURL(bundleID: String) -> URL? {
        guard let appSup = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        return appSup.appendingPathComponent(bundleID, isDirectory: true).appendingPathComponent(".license_vault")
    }

    private static func defaultFileAnchorURLs(bundleID: String) -> [URL] {
        let fm = FileManager.default
        var urls: [URL] = []
        if let appSup = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
            urls.append(appSup.appendingPathComponent(bundleID, isDirectory: true).appendingPathComponent(".vault_seal"))
        }
        if let caches = fm.urls(for: .cachesDirectory, in: .userDomainMask).first {
            urls.append(caches.appendingPathComponent(bundleID, isDirectory: true).appendingPathComponent(".vault_seal"))
        }
        return urls
    }

    private static func loadLicenseVault(
        vaultURL: URL?,
        useKeychain: Bool,
        keychainService: String,
        keychainAccount: String
    ) -> StoredLicenseVault {
        if useKeychain,
           let kStr = readKeychainString(service: keychainService, account: keychainAccount),
           let kData = kStr.data(using: .utf8),
           let decoded = try? JSONDecoder().decode(StoredLicenseVault.self, from: kData) {
            return decoded
        }
        if let url = vaultURL,
           let data = try? Data(contentsOf: url),
           let decoded = try? JSONDecoder().decode(StoredLicenseVault.self, from: data) {
            return decoded
        }
        return StoredLicenseVault(token: nil, parentKey: nil)
    }

    private static func saveLicenseVault(
        _ vault: StoredLicenseVault,
        vaultURL: URL?,
        useKeychain: Bool,
        keychainService: String,
        keychainAccount: String
    ) {
        let fm = FileManager.default
        let hasRevokedTags = !(vault.revokedOrderTags?.isEmpty ?? true)
        let hasPendingCheckout = !(vault.pendingCheckoutHandoff?.isEmpty ?? true)
        let isEmpty = (
            vault.token == nil &&
            vault.parentKey == nil &&
            (vault.pendingDeactivations?.isEmpty ?? true) &&
            !hasRevokedTags &&
            !hasPendingCheckout &&
            vault.manifestSeq == nil
        )
        if isEmpty {
            if let url = vaultURL {
                try? fm.removeItem(at: url)
            }
            if useKeychain {
                deleteKeychainItem(service: keychainService, account: keychainAccount)
            }
            return
        }
        guard let encoded = try? JSONEncoder().encode(vault) else { return }
        if let url = vaultURL {
            let dir = url.deletingLastPathComponent()
            try? fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try? encoded.write(to: url, options: .atomic)
            try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            // Note: `.license_vault` is NOT excluded from backup so `parentKey` carries across Migration Assistant / Time Machine
            // to a new Mac (while the old Mac's seat-bound `token` is rejected on the new hardware UUID).
        }
        if useKeychain, let jsonStr = String(data: encoded, encoding: .utf8) {
            writeKeychainString(jsonStr, service: keychainService, account: keychainAccount)
        }
    }

    private static func persistSealToAllAnchors(
        _ seal: String,
        defaults: UserDefaults,
        defaultsKey: String,
        fileURLs: [URL],
        useKeychain: Bool,
        keychainService: String,
        keychainAccount: String
    ) {
        defaults.set(seal, forKey: defaultsKey)
        let fm = FileManager.default
        let data = Data(seal.utf8)
        for url in fileURLs {
            let dir = url.deletingLastPathComponent()
            try? fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try? data.write(to: url, options: .atomic)
            try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            var rv = URLResourceValues()
            rv.isExcludedFromBackup = true
            var mutableURL = url
            try? mutableURL.setResourceValues(rv)
        }
        if useKeychain {
            writeKeychainString(seal, service: keychainService, account: keychainAccount)
        }
    }

    private static func readKeychainString(service: String, account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess,
              let data = item as? Data,
              let str = String(data: data, encoding: .utf8) else {
            return nil
        }
        return str
    }

    private static func writeKeychainString(_ value: String, service: String, account: String) {
        guard let data = value.data(using: .utf8) else { return }
        let matchQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let updateStatus = SecItemUpdate(matchQuery as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecItemNotFound {
            var addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account
            ]
            for (k, v) in attributes { addQuery[k] = v }
            _ = SecItemAdd(addQuery as CFDictionary, nil)
        } else if updateStatus == errSecAuthFailed || updateStatus == errSecInteractionNotAllowed {
            deleteKeychainItem(service: service, account: account)
            var addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account
            ]
            for (k, v) in attributes { addQuery[k] = v }
            _ = SecItemAdd(addQuery as CFDictionary, nil)
        }
    }

    private static func deleteKeychainItem(service: String, account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        _ = SecItemDelete(query as CFDictionary)
    }

    /// Ad-hoc signed builds change code identity on every rebuild, which triggers macOS Keychain password prompts.
    /// Only use the Keychain anchor when the running binary passes `SecCodeCheckValidity` with a non-empty Team ID.
    public static func hasStableDeveloperTeamID() -> Bool {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess,
              let selfCode = code,
              SecCodeCheckValidity(selfCode, [], nil) == errSecSuccess else {
            return false
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(selfCode, [], &staticCode) == errSecSuccess, let sCode = staticCode else { return false }
        var infoCF: CFDictionary?
        let flags = SecCSFlags(rawValue: UInt32(kSecCSSigningInformation))
        guard SecCodeCopySigningInformation(sCode, flags, &infoCF) == errSecSuccess,
              let info = infoCF as? [String: Any],
              let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String,
              !teamID.isEmpty else {
            return false
        }
        return true
    }

    private static func readHardwareUUID(fallbackNamespace: String) -> String {
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        guard service != IO_OBJECT_NULL else { return "\(fallbackNamespace)-fallback-hw" }
        defer { IOObjectRelease(service) }
        if let uuid = IORegistryEntryCreateCFProperty(service, kIOPlatformUUIDKey as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? String,
           !uuid.isEmpty {
            return uuid
        }
        return "\(fallbackNamespace)-fallback-hw"
    }
}
