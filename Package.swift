// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "seatstamp",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "SeatStamp", targets: ["SeatStamp"]),
        .executable(name: "license-tool", targets: ["license-tool"])
    ],
    targets: [
        // Offline Ed25519 seat-ticket verification, hardware-bound HMAC trial seals,
        // signed update-manifest verification, and ObservableObject managers for macOS apps.
        .target(
            name: "SeatStamp",
            path: "Sources/SeatStamp",
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("IOKit"),
                .linkedFramework("Security")
            ]
        ),
        // `swift run license-tool`: Ed25519 keypair management (separate license & offline update keys),
        // seat-ticket minting, and signing/verifying version.json manifests.
        .executableTarget(
            name: "license-tool",
            dependencies: ["SeatStamp"],
            path: "Sources/license-tool"
        ),
        // `swift run selftest`: XCTest-free test suite (runs on Command Line Tools without full Xcode).
        .executableTarget(
            name: "selftest",
            dependencies: ["SeatStamp", "license-tool"],
            path: "Tests/selftest"
        )
    ]
)
