// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "ExampleMenuBarApp",
    platforms: [
        .macOS(.v13)
    ],
    dependencies: [
        .package(path: "..")
    ],
    targets: [
        .executableTarget(
            name: "ExampleMenuBarApp",
            dependencies: [
                .product(name: "SeatStamp", package: "seatstamp")
            ],
            path: "Sources/ExampleMenuBarApp"
        )
    ]
)
