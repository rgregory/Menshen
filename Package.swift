// swift-tools-version: 6.0
import Foundation
import PackageDescription

// With only the Command Line Tools installed, the Swift Build backend intermittently omits the
// plugin path for Swift Testing's macros ("plugin for module 'TestingMacros' not found").
// Point the compiler at it explicitly when that toolchain layout is present.
let cltTestingPlugins = "/Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing"
let testSettings: [SwiftSetting] = FileManager.default.fileExists(atPath: cltTestingPlugins)
    ? [.unsafeFlags(["-plugin-path", cltTestingPlugins])]
    : []

let package = Package(
    name: "menshen",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "menshen", targets: ["menshen"]),
    ],
    targets: [
        .executableTarget(name: "menshen", dependencies: ["MenshenCore"]),
        .target(name: "MenshenCore"),
        .testTarget(
            name: "MenshenCoreTests",
            dependencies: ["MenshenCore"],
            resources: [.copy("Fixtures")],
            swiftSettings: testSettings
        ),
    ]
)
