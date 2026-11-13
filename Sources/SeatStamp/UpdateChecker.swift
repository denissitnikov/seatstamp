import AppKit
import Combine
import CryptoKit
import Foundation

/// Release metadata verified from a signed `version.json` manifest.
public struct AvailableUpdate: Equatable, Sendable {
    public let version: String
    public let rawVersion: String
    public let summary: String
    public let notes: [String]
    public let url: URL
    /// Lower-case hex SHA-256 of the download from the signed manifest, or nil when the manifest does not bind the file.
    public let sha256: String?
    /// Byte size of the download from the signed manifest.
    public let size: Int64?

    public init(
        version: String,
        rawVersion: String? = nil,
        summary: String,
        notes: [String],
        url: URL,
        sha256: String? = nil,
        size: Int64? = nil
    ) {
        self.version = version
        self.rawVersion = rawVersion ?? version
        self.summary = summary
        self.notes = notes
        self.url = url
        self.sha256 = sha256?.lowercased()
        self.size = size
    }
}

/// Checks a remote `version.json` manifest signed with the offline update key configured on `SeatStampManager`.
/// When the manifest carries a signed `sha256`, `downloadAndVerifyUpdate` downloads the file, checks its hash and size,
/// sets the quarantine attribute, and reveals it in Finder; otherwise it opens the download URL in the browser.
/// Never opens, mounts, or runs a downloaded file, and does not patch binaries in place.
public final class UpdateChecker: ObservableObject {
    public enum RevocationBehavior: Equatable, Sendable {
        /// Hides update notifications when the active license's order tag is listed in `revoked_tags`, leaving the installed app untouched.
        case suppressUpdates
        /// Revokes the active local license (`isLicensed = false`) and persists the revoked tag when listed in a signed manifest.
        case revokeLocalLicense
    }

    public enum DownloadOutcome: Equatable, Sendable {
        /// Saved; SHA-256 and size match the signed manifest, and the quarantine attribute is set.
        case verified(URL)
        /// The manifest has no `sha256`: the download URL was opened in the browser.
        case openedInBrowser
        /// The hash or size differs from the signed manifest; the file was deleted.
        case hashMismatch
        /// No update, a download already running, a network error, an HTTP status other than 200,
        /// or the quarantine attribute could not be set.
        case failed
    }

    @Published public private(set) var availableUpdate: AvailableUpdate?

    /// When false, `UpdateChecker` makes no background network requests.
    @Published public var autoCheckForUpdates: Bool {
        didSet {
            guard autoCheckForUpdates != oldValue else { return }
            defaults.set(autoCheckForUpdates, forKey: autoCheckKey)
            if autoCheckForUpdates {
                checkIfDue()
                armNextCheckTimer()
            } else {
                recheckTimer?.invalidate()
                recheckTimer = nil
                inFlight?.cancel()
                inFlight = nil
            }
        }
    }

    public let manifestURL: URL
    public let trustedDownloadHosts: Set<String>
    public let requiredPathPrefix: String
    public let fallbackWebsiteURL: URL?
    public let recheckInterval: TimeInterval
    public let revocationBehavior: RevocationBehavior

    private let kit: SeatStampManager
    private let currentRawVersion: String
    private let defaults: UserDefaults
    private let languageCodeProvider: () -> String
    private let session: URLSession
    private let downloadSession: URLSession
    private let downloadDirectory: URL?
    private let appName: String

    private static let launchDelay: TimeInterval = 4.0
    private static let maxManifestBytes = 64 * 1024
    private static let maxUnsizedDownloadBytes: Int64 = 4 * 1024 * 1024 * 1024
    private static let hashChunkBytes = 1024 * 1024

    private let dismissedVersionKey = "seatStampDismissedUpdateVersion"
    private let lastCheckEpochKey = "seatStampUpdateLastCheckEpoch"
    /// Time of the last completed attempt, successful or not.
    private let lastAttemptEpochKey = "seatStampUpdateLastAttemptEpoch"
    /// Consecutive failed attempts, capped at `maxFailureCount`.
    private let failureCountKey = "seatStampUpdateFailureCount"
    private static let maxFailureCount = 16
    private static let firstRetryInterval: TimeInterval = 60 * 60
    private let autoCheckKey = "seatStampAutoCheckForUpdates"

    private var recheckTimer: Timer?
    private var inFlight: URLSessionDataTask?
    private var hasScheduledLaunchCheck = false
    private var downloadInFlight = false

    public init(
        kit: SeatStampManager,
        manifestURL: URL,
        trustedDownloadHosts: Set<String>? = nil,
        requiredPathPrefix: String = "/download/",
        fallbackWebsiteURL: URL? = nil,
        recheckInterval: TimeInterval = 7 * 24 * 60 * 60,
        revocationBehavior: RevocationBehavior = .suppressUpdates,
        currentVersion: String? = nil,
        defaults: UserDefaults = .standard,
        languageCodeProvider: @escaping () -> String = {
            Locale.preferredLanguages.first.map { String($0.prefix(2)) } ?? "en"
        },
        urlSession: URLSession? = nil,
        downloadDirectory: URL? = nil
    ) {
        self.kit = kit
        self.manifestURL = manifestURL
        if let hosts = trustedDownloadHosts, !hosts.isEmpty {
            self.trustedDownloadHosts = Set(hosts.map { $0.lowercased() })
        } else if let host = manifestURL.host?.lowercased() {
            self.trustedDownloadHosts = [host]
        } else {
            self.trustedDownloadHosts = []
        }
        self.requiredPathPrefix = requiredPathPrefix
        self.fallbackWebsiteURL = fallbackWebsiteURL
        self.recheckInterval = max(60, recheckInterval)
        self.revocationBehavior = revocationBehavior
        self.currentRawVersion = (currentVersion
            ?? (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String)
            ?? "1.0").trimmingCharacters(in: .whitespacesAndNewlines)
        self.defaults = defaults
        self.languageCodeProvider = languageCodeProvider
        self.autoCheckForUpdates = defaults.object(forKey: autoCheckKey) as? Bool ?? true

        let appName = (Bundle.main.infoDictionary?["CFBundleName"] as? String) ?? kit.bundleID
        self.appName = appName
        self.downloadDirectory = downloadDirectory
        if let injected = urlSession {
            self.session = injected
            self.downloadSession = injected
        } else {
            func baseConfiguration() -> URLSessionConfiguration {
                let cfg = URLSessionConfiguration.ephemeral
                cfg.tlsMinimumSupportedProtocolVersion = .TLSv13
                cfg.httpCookieAcceptPolicy = .never
                cfg.httpShouldSetCookies = false
                cfg.urlCache = nil
                cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
                cfg.httpAdditionalHeaders = ["User-Agent": "\(appName)/\(SeatStampManager.displayAppVersion)"]
                return cfg
            }
            let cfg = baseConfiguration()
            cfg.timeoutIntervalForRequest = 10
            cfg.waitsForConnectivity = true
            cfg.timeoutIntervalForResource = 60
            self.session = URLSession(configuration: cfg)

            let dlCfg = baseConfiguration()
            dlCfg.timeoutIntervalForRequest = 60
            dlCfg.timeoutIntervalForResource = 3600
            dlCfg.waitsForConnectivity = false
            self.downloadSession = URLSession(configuration: dlCfg)
        }
    }

    public func scheduleLaunchCheck() {
        guard !hasScheduledLaunchCheck else { return }
        hasScheduledLaunchCheck = true
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.launchDelay) { [weak self] in
            guard let self = self, self.autoCheckForUpdates else { return }
            self.checkIfDue()
            self.armNextCheckTimer()
        }
    }

    /// When the next automatic check is due: nil when automatic checks are off, now when no attempt was ever made.
    /// After a failed check the wait is 1 hour, then 2, 4, and so on, up to `recheckInterval`.
    public var nextCheckDate: Date? {
        guard autoCheckForUpdates else { return nil }
        let ref = referenceEpoch()
        guard ref > 0 else { return Date() }
        return Date(timeIntervalSince1970: ref + waitInterval())
    }

    public func checkIfDue() {
        guard autoCheckForUpdates else { return }
        let now = Date().timeIntervalSince1970
        let ref = referenceEpoch()
        guard ref <= 0 || now < ref || (now - ref) >= waitInterval() else { return }
        performCheck(force: false)
    }

    /// `recheckInterval` after a success; after `n` consecutive failures `min(recheckInterval, 1 h * 2^(n - 1))`.
    private func waitInterval() -> TimeInterval {
        let failures = min(Self.maxFailureCount, max(0, defaults.integer(forKey: failureCountKey)))
        guard failures >= 1 else { return recheckInterval }
        return min(recheckInterval, Self.firstRetryInterval * pow(2, Double(failures - 1)))
    }

    /// The later of the last successful check and the last attempt.
    private func referenceEpoch() -> TimeInterval {
        max(defaults.double(forKey: lastCheckEpochKey), defaults.double(forKey: lastAttemptEpochKey))
    }

    public func checkNow(openDownloadIfAvailable: Bool = false, completion: (() -> Void)? = nil) {
        performCheck(force: true) { [weak self] in
            guard let self = self else { completion?(); return }
            if openDownloadIfAvailable {
                if let update = self.availableUpdate {
                    if update.sha256 != nil {
                        self.downloadAndVerifyUpdate { _ in }
                    } else {
                        NSWorkspace.shared.open(update.url)
                    }
                } else if let site = self.fallbackWebsiteURL {
                    NSWorkspace.shared.open(site)
                }
            }
            completion?()
        }
    }

    public func dismissCurrentUpdate() {
        if let v = availableUpdate?.rawVersion {
            defaults.set(v, forKey: dismissedVersionKey)
        }
        availableUpdate = nil
    }

    @discardableResult
    public func ingest(data: Data) -> Bool {
        guard let pubKey = kit.updatePublicKey,
              data.count <= Self.maxManifestBytes,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let rawVersionField = json["version"] as? String,
              let rawURLField = json["url"] as? String else {
            return false
        }
        let rawVersion = rawVersionField.trimmingCharacters(in: .whitespacesAndNewlines)
        let urlString = rawURLField.trimmingCharacters(in: .whitespacesAndNewlines)
        guard VersionCompare.isValidVersionString(rawVersion),
              let url = URL(string: urlString),
              url.scheme?.lowercased() == "https",
              let host = url.host?.lowercased(), trustedDownloadHosts.contains(host),
              !url.pathComponents.contains(".."),
              requiredPathPrefix.isEmpty || url.standardized.path.hasPrefix(requiredPathPrefix),
              case .success(let f) = UpdateManifest.fields(from: json),
              f.version == rawVersion, f.url == urlString,
              UpdateManifest.verify(f, scheme: kit.updateScheme, publicKey: pubKey) else {
            return false
        }

        // Read before applying the manifest: applying it can revoke the active ticket and clear `kit.isLicensed`.
        let activeTagIsRevoked: Bool = {
            guard kit.isLicensed,
                  let currentTag = LicenseTicket.canonicalOrderTag(kit.orderTag) else {
                return false
            }
            return f.revokedTags.contains(currentTag)
        }()

        // A signed sequence lower than the highest one accepted means an older manifest is being served again.
        // Under `.revokeLocalLicense` the stored revoked set mirrors the newest sequenced manifest.
        guard kit.applyVerifiedManifest(
            sequence: f.manifestSeq,
            revokedTags: f.revokedTags,
            mirror: revocationBehavior == .revokeLocalLicense
        ) != .replay else {
            return false
        }
        if activeTagIsRevoked {
            availableUpdate = nil
            return true
        }

        guard VersionCompare.isVersion(rawVersion, newerThan: currentRawVersion) else {
            availableUpdate = nil
            return true
        }
        let dismissed = defaults.string(forKey: dismissedVersionKey) ?? ""
        guard rawVersion != dismissed else {
            availableUpdate = nil
            return true
        }

        let langKey = languageCodeProvider()
        let summary = (f.summaryI18n[langKey]).flatMap { $0.isEmpty ? nil : $0 } ?? f.summary
        let notes = (f.notesI18n[langKey]).flatMap { $0.isEmpty ? nil : $0 } ?? f.notes

        let update = AvailableUpdate(
            version: VersionCompare.formattedDisplayVersion(rawVersion),
            rawVersion: rawVersion,
            summary: String(summary.prefix(140)),
            notes: notes.prefix(3).map { String($0.prefix(120)) },
            url: url,
            sha256: f.sha256,
            size: f.size
        )
        if availableUpdate != update {
            availableUpdate = update
        }
        return true
    }

    /// Downloads the available update and keeps it only when its SHA-256 and size match the signed manifest.
    /// A manifest without `sha256` opens the download URL instead (`openURL`, default `NSWorkspace.shared.open`).
    /// Every `completion` call happens on the main queue. Never opens, mounts, or runs the downloaded file.
    public func downloadAndVerifyUpdate(openURL: ((URL) -> Void)? = nil, completion: @escaping (DownloadOutcome) -> Void) {
        let finish: (DownloadOutcome) -> Void = { outcome in
            if Thread.isMainThread {
                completion(outcome)
            } else {
                DispatchQueue.main.async { completion(outcome) }
            }
        }
        guard let update = availableUpdate, !downloadInFlight else {
            finish(.failed)
            return
        }
        guard let expectedSha = update.sha256 else {
            if let openURL = openURL {
                openURL(update.url)
            } else {
                NSWorkspace.shared.open(update.url)
            }
            finish(.openedInBrowser)
            return
        }
        downloadInFlight = true
        let trustedHosts = trustedDownloadHosts
        let explicitDirectory = downloadDirectory
        let agentName = appName
        let done: (DownloadOutcome) -> Void = { [weak self] outcome in
            DispatchQueue.main.async {
                self?.downloadInFlight = false
                completion(outcome)
            }
        }
        let task = downloadSession.downloadTask(with: update.url) { tempURL, response, error in
            let fm = FileManager.default
            guard error == nil,
                  let tempURL = tempURL,
                  let http = response as? HTTPURLResponse,
                  http.statusCode == 200,
                  let finalURL = http.url ?? response?.url,
                  finalURL.scheme?.lowercased() == "https",
                  let finalHost = finalURL.host?.lowercased(),
                  trustedHosts.contains(finalHost) else {
                done(.failed)
                return
            }
            // URLSession deletes `tempURL` when this handler returns: move it to a private staging file first.
            let staging = fm.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            do {
                try fm.moveItem(at: tempURL, to: staging)
            } catch {
                done(.failed)
                return
            }
            let outcome = Self.verifyAndSave(
                staging: staging,
                update: update,
                expectedSha: expectedSha,
                directory: explicitDirectory,
                agentName: agentName
            )
            if case .verified(let savedURL) = outcome, explicitDirectory == nil {
                DispatchQueue.main.async {
                    NSWorkspace.shared.activateFileViewerSelecting([savedURL])
                }
            }
            done(outcome)
        }
        task.resume()
    }

    /// Checks size and SHA-256 of the staging file, moves it into the download folder, and sets the quarantine attribute.
    /// Deletes the staging file on every path that does not move it.
    private static func verifyAndSave(
        staging: URL,
        update: AvailableUpdate,
        expectedSha: String,
        directory: URL?,
        agentName: String
    ) -> DownloadOutcome {
        let fm = FileManager.default
        var moved = false
        defer {
            if !moved { try? fm.removeItem(at: staging) }
        }
        guard let attrs = try? fm.attributesOfItem(atPath: staging.path),
              let byteCount = (attrs[.size] as? NSNumber)?.int64Value else {
            return .failed
        }
        if let expectedSize = update.size {
            guard byteCount == expectedSize else { return .hashMismatch }
        } else {
            guard byteCount <= maxUnsizedDownloadBytes else { return .hashMismatch }
        }
        guard let actualSha = sha256Hex(ofFileAt: staging) else { return .failed }
        guard actualSha == expectedSha.lowercased() else { return .hashMismatch }

        guard let folder = directory ?? fm.urls(for: .downloadsDirectory, in: .userDomainMask).first else {
            return .failed
        }
        try? fm.createDirectory(at: folder, withIntermediateDirectories: true)
        let rawName = update.url.lastPathComponent
        let fileName = (rawName.isEmpty || rawName == "/") ? "update" : rawName
        let saved = uniqueDestination(in: folder, fileName: fileName)
        do {
            try fm.moveItem(at: staging, to: saved)
        } catch {
            return .failed
        }
        moved = true
        guard setQuarantine(on: saved, sourceURL: update.url, agentName: agentName) else {
            try? fm.removeItem(at: saved)
            return .failed
        }
        return .verified(saved)
    }

    private static func sha256Hex(ofFileAt url: URL) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let next: Data?
            do {
                next = try handle.read(upToCount: hashChunkBytes)
            } catch {
                return nil
            }
            guard let chunk = next, !chunk.isEmpty else { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// `Name.dmg`, then `Name (2).dmg`, `Name (3).dmg`, and so on.
    private static func uniqueDestination(in folder: URL, fileName: String) -> URL {
        let fm = FileManager.default
        let first = folder.appendingPathComponent(fileName)
        guard fm.fileExists(atPath: first.path) else { return first }
        let ext = (fileName as NSString).pathExtension
        let base = (fileName as NSString).deletingPathExtension
        var n = 2
        while true {
            let candidate = folder.appendingPathComponent(ext.isEmpty ? "\(base) (\(n))" : "\(base) (\(n)).\(ext)")
            if !fm.fileExists(atPath: candidate.path) { return candidate }
            n += 1
        }
    }

    /// Files downloaded with `URLSession` get no quarantine attribute unless the app is sandboxed or declares
    /// `LSFileQuarantineEnabled`, so set it explicitly and read it back.
    private static func setQuarantine(on fileURL: URL, sourceURL: URL, agentName: String) -> Bool {
        let attrName = "com.apple.quarantine"
        func hasAttribute() -> Bool {
            getxattr(fileURL.path, attrName, nil, 0, 0, 0) > 0
        }
        var target = fileURL
        var values = URLResourceValues()
        values.quarantineProperties = [
            kLSQuarantineAgentNameKey as String: agentName,
            kLSQuarantineTypeKey as String: kLSQuarantineTypeOtherDownload as String,
            kLSQuarantineDataURLKey as String: sourceURL
        ]
        try? target.setResourceValues(values)
        if hasAttribute() { return true }
        let stamp = String(Int64(Date().timeIntervalSince1970), radix: 16)
        let value = "0081;\(stamp);\(agentName);"
        let bytes = Array(value.utf8)
        _ = bytes.withUnsafeBufferPointer { buf in
            setxattr(fileURL.path, attrName, buf.baseAddress, buf.count, 0, 0)
        }
        return hasAttribute()
    }

    private func armNextCheckTimer() {
        recheckTimer?.invalidate()
        let ref = referenceEpoch()
        let now = Date().timeIntervalSince1970
        let due = (ref > 0 && now >= ref) ? max(60, ref + waitInterval() - now) : waitInterval()
        let timer = Timer(timeInterval: due, repeats: false) { [weak self] _ in
            self?.checkIfDue()
            self?.armNextCheckTimer()
        }
        timer.tolerance = 60 * 60
        RunLoop.main.add(timer, forMode: .common)
        recheckTimer = timer
    }

    /// Records a completed attempt: a success resets the failure count, anything else adds one (capped).
    private func recordAttempt(succeeded: Bool) {
        let now = Date().timeIntervalSince1970
        defaults.set(now, forKey: lastAttemptEpochKey)
        if succeeded {
            defaults.set(now, forKey: lastCheckEpochKey)
            defaults.set(0, forKey: failureCountKey)
        } else {
            let failures = max(0, defaults.integer(forKey: failureCountKey))
            defaults.set(min(Self.maxFailureCount, failures + 1), forKey: failureCountKey)
        }
    }

    private func performCheck(force: Bool, completion: (() -> Void)? = nil) {
        guard inFlight == nil, force || autoCheckForUpdates else { completion?(); return }
        var req = URLRequest(url: manifestURL)
        req.httpMethod = "GET"
        req.setValue("application/json", forHTTPHeaderField: "Accept")

        let task = session.dataTask(with: req) { [weak self] data, response, error in
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.inFlight = nil
                if let urlError = error as? URLError, urlError.code == .cancelled {
                    completion?()
                    return
                }
                let http = response as? HTTPURLResponse
                let status = http?.statusCode ?? 0
                let announced = http?.expectedContentLength ?? -1
                var succeeded = false
                if error == nil,
                   status == 200,
                   let data = data,
                   announced <= Self.maxManifestBytes,
                   data.count <= Self.maxManifestBytes {
                    succeeded = self.ingest(data: data)
                }
                self.recordAttempt(succeeded: succeeded)
                if self.autoCheckForUpdates {
                    self.armNextCheckTimer()
                }
                completion?()
            }
        }
        inFlight = task
        task.resume()
    }
}
