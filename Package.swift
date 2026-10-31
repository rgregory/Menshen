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

// The AppKit/SwiftUI targets use the Swift 5 language mode to keep UI code free of concurrency
// annotations; the core library stays in strict Swift 6.
let uiSettings: [SwiftSetting] = [.swiftLanguageMode(.v5)]

let package = Package(
    name: "menshen",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "menshen", targets: ["menshen"]),
        .executable(name: "menshen-launch", targets: ["menshen-launch"]),
        .executable(name: "MenshenApp", targets: ["MenshenApp"]),
        // For apps built on Menshen's sandboxing, such as Shentu (../shentu).
        .library(name: "MenshenCore", targets: ["MenshenCore"]),
    ],
    targets: [
        .executableTarget(name: "menshen", dependencies: ["MenshenCore"]),
        .executableTarget(name: "menshen-launch", dependencies: ["MenshenCore"], swiftSettings: uiSettings),
        .executableTarget(name: "MenshenApp", dependencies: ["MenshenCore"], swiftSettings: uiSettings),
        .target(name: "MenshenCore"),
        .testTarget(
            name: "MenshenCoreTests",
            // menshen-launch is listed so it is built before the launcher integration test runs.
            dependencies: ["MenshenCore", "menshen-launch"],
            resources: [.copy("Fixtures")],
            swiftSettings: testSettings
        ),
    ]
)
