import AppKit
import CryptoKit
import SeatStamp
import SwiftUI

/// Minimal SwiftUI menu-bar app demonstrating `SeatStampManager`.
///
/// Run from terminal:
///   cd example && swift run
///
/// Uses the deterministic test keypair from `../fixtures/golden-vectors.json` so you can mint a real
/// `LK1-` seat ticket locally and test Activate, Copy Key, Deactivate, and watermark rejection
/// without deploying a Worker first. Replace `licensePublicKeyBase64` and `activationEndpoints` in your app.
@main
struct ExampleMenuBarApp: App {
    @StateObject private var kit = SeatStampManager(
        scheme: "EXAMPLE-V1",
        // Deterministic test public key from fixtures/golden-vectors.json (replace in production)
        licensePublicKeyBase64: "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=",
        activationEndpoints: [
            // URL(string: "https://activate.myapp.com")!
        ],
        trialLengthDays: 30,
        maxSeats: 2,
        bundleID: "com.example.samplebar"
    )

    var body: some Scene {
        MenuBarExtra("SampleBar", systemImage: kit.isLicensed ? "checkmark.seal.fill" : "key.fill") {
            LicensePopoverView(kit: kit)
        }
        .menuBarExtraStyle(.window)
    }
}

final class DemoUIState: ObservableObject {
    @Published var keyInput: String = ""
    @Published var statusMessage: String = ""
    @Published var proActionCount: Int = 0
    /// The last ticket from "Fill Demo Seat Ticket". `shareableLicenseKey` is nil for a seat-bound ticket without a
    /// purchase key, so the watermark demo keeps its own copy.
    @Published var lastDemoTicket: String = ""
}

struct LicensePopoverView: View {
    @ObservedObject var kit: SeatStampManager
    @StateObject private var ui = DemoUIState()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("SampleBar")
                    .font(.headline)
                Spacer()
                statusBadge
            }

            Divider()

            HStack {
                Button("Run Pro Action") {
                    kit.refreshMonotonicClockIfNeeded()
                    if kit.verifyGateAccess() {
                        ui.proActionCount += 1
                        ui.statusMessage = "Pro action ran (\(ui.proActionCount)x)."
                    } else {
                        ui.statusMessage = "Trial expired. Enter a license key to unlock."
                    }
                }
                .buttonStyle(.borderedProminent)

                Spacer()
                // Full 16-hex seat code, selectable for `license-tool --mint ... --seat <code>`.
                Text("Seat ID: \(kit.deviceSeatCode)")
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .foregroundStyle(.secondary)
            }

            Divider()

            if kit.isLicensed {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Licensed (\(kit.maskedKey)) · Seat \(kit.seatsUsed) of \(kit.maxSeats)")
                        .font(.subheadline.weight(.medium))

                    HStack(spacing: 8) {
                        if let shareable = kit.shareableLicenseKey {
                            Button("Copy Key for 2nd Mac") {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(shareable, forType: .string)
                                ui.statusMessage = "Copied key to clipboard."
                            }
                        }
                        Button("Deactivate This Mac") {
                            let oldKey = kit.shareableLicenseKey ?? ui.lastDemoTicket
                            kit.deactivate()
                            ui.keyInput = oldKey
                            ui.statusMessage = "Seat released. Try clicking Activate on that same offline ticket: the local watermark refuses it."
                        }
                    }
                }
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        Button(kit.isAwaitingBrowserCheckout ? "Waiting for Browser..." : "Buy License") {
                            let taggedURL = kit.beginBrowserCheckout(
                                paymentLink: URL(string: "https://buy.stripe.com/test_example")!,
                                openURL: { url in
                                    ui.statusMessage = "Opened browser checkout (\(url.lastPathComponent)). App will auto-activate once paid."
                                },
                                onOutcome: { outcome in
                                    if outcome == .activated {
                                        ui.statusMessage = "Auto-activated from browser checkout."
                                    } else if outcome == .unconfigured {
                                        ui.statusMessage = "Activation is not set up in this build."
                                    }
                                }
                            )
                            _ = taggedURL
                        }
                        if kit.isAwaitingBrowserCheckout {
                            Button("Cancel") {
                                kit.cancelBrowserCheckout()
                                ui.statusMessage = "Browser checkout cancelled."
                            }
                        }
                    }

                    TextField("Paste cs_live_... key, LK1-... ticket, or your purchase email", text: $ui.keyInput)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.caption, design: .monospaced))

                    HStack(spacing: 8) {
                        if SeatStampManager.looksLikeEmail(ui.keyInput) {
                            // Lost key: the same field accepts the purchase email and asks the Worker to email the key back.
                            Button(kit.isRequestingKeyRecovery ? "Sending..." : "Email Key") {
                                Task {
                                    switch await kit.requestKeyRecovery(email: ui.keyInput) {
                                    case .sent:
                                        ui.statusMessage = "If that email bought a license, a message with the key and a one-click link is on its way."
                                    case .unconfigured:
                                        ui.statusMessage = "Key recovery is not enabled on this activation server."
                                    case .rateLimited:
                                        ui.statusMessage = "Too many requests. Try again in a few minutes."
                                    case .invalidEmail:
                                        ui.statusMessage = "That does not look like a valid email address."
                                    case .networkError:
                                        ui.statusMessage = "Could not reach activation server. Check your connection."
                                    }
                                }
                            }
                            .disabled(kit.isRequestingKeyRecovery)
                        } else {
                            Button(kit.isActivatingOnline ? "Activating..." : "Activate") {
                                Task {
                                    let outcome = await kit.activate(key: ui.keyInput)
                                    switch outcome {
                                    case .activated:
                                        ui.keyInput = ""
                                        ui.statusMessage = "Activated and verified offline with CryptoKit."
                                    case .seatLimitReached:
                                        ui.statusMessage = "All \(kit.maxSeats) Mac seats are in use. Deactivate another Mac first."
                                    case .networkError:
                                        ui.statusMessage = "Could not reach activation server. Check your connection."
                                    case .invalidKey:
                                        ui.statusMessage = "Invalid, wrong-Mac, or previously deactivated license key."
                                    case .paymentPending:
                                        ui.statusMessage = "Payment is still processing. Try again in a minute."
                                    case .clockSkew:
                                        ui.statusMessage = "The license server and this Mac disagree about the time. Check the date and time, then try again."
                                    case .unconfigured:
                                        ui.statusMessage = "Activation is not set up in this build."
                                    }
                                }
                            }
                            .disabled(kit.isActivatingOnline || ui.keyInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                        }

                        Button("Fill Demo Seat Ticket") {
                            ui.keyInput = Self.mintDemoTicket(forSeat: kit.deviceSeatCode)
                            ui.lastDemoTicket = ui.keyInput
                            ui.statusMessage = "Demo LK1- ticket minted for seat \(kit.deviceSeatCode). Click Activate."
                        }
                    }
                }
            }

            if !ui.statusMessage.isEmpty {
                Text(ui.statusMessage)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Divider()

            HStack {
                Spacer()
                Button("Quit") { NSApplication.shared.terminate(nil) }
                    .buttonStyle(.plain)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(14)
        .frame(width: 360)
        // Pre-fill incoming `samplebar://activate?key=cs_live_...` links when unlicensed rather than auto-submitting.
        .onOpenURL { url in
            guard !kit.isLicensed,
                  url.scheme?.lowercased() == "samplebar",
                  url.host?.lowercased() == "activate",
                  let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
                  let key = comps.queryItems?.first(where: { $0.name == "key" })?.value else {
                return
            }
            ui.keyInput = String(key.prefix(256))
            ui.statusMessage = "License key pre-filled from link. Click Activate."
        }
    }

    @ViewBuilder
    private var statusBadge: some View {
        if kit.isLicensed {
            Text("PRO")
                .font(.caption2.bold())
                .padding(.horizontal, 7)
                .padding(.vertical, 2)
                .background(Color.green.opacity(0.2), in: Capsule())
        } else if kit.isTrialExpired {
            Text("Trial Expired")
                .font(.caption2.bold())
                .padding(.horizontal, 7)
                .padding(.vertical, 2)
                .background(Color.red.opacity(0.2), in: Capsule())
        } else {
            Text("\(kit.trialDaysRemaining)d trial")
                .font(.caption2.bold())
                .padding(.horizontal, 7)
                .padding(.vertical, 2)
                .background(Color.orange.opacity(0.2), in: Capsule())
        }
    }

    /// Demo helper using the test seed `0x00..0x1f` from `fixtures/golden-vectors.json`.
    /// Do not ship a private signing seed inside a real client binary.
    private static func mintDemoTicket(forSeat seatCode: String) -> String {
        let demoSeed = Data((0..<32).map(UInt8.init))
        let priv = try! Curve25519.Signing.PrivateKey(rawRepresentation: demoSeed)
        let payload = LicenseTicket.canonicalPayload(
            scheme: "EXAMPLE-V1",
            tag: "ORD-DEMO01",
            issued: Int64(Date().timeIntervalSince1970),
            seat: seatCode
        )
        let sig = try! priv.signature(for: Data(payload.utf8))
        return LicenseTicket.encode(payload: payload, signature: sig)
    }
}
