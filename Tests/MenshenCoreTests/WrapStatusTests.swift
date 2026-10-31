import Foundation
import Security
import Testing
@testable import MenshenCore

/// "Can Menshen wrap this app?" — decided from the signature alone, quickly.
@Suite(.serialized) struct WrapStatusTests {
    @Test func statusComesFromTheSignature() throws {
        let d = try DummyApps()
        defer { d.cleanUp() }
        #expect(WrapStatus.check(d.app) == .wrappable)

        // The same app, signed with the App Sandbox entitlement.
        let ents = d.root + "/sandbox.entitlements"
        try PropertyListSerialization.data(fromPropertyList: ["com.apple.security.app-sandbox": true], format: .xml, options: 0)
            .write(to: URL(fileURLWithPath: ents))
        #expect(Swap.run("/usr/bin/codesign", ["-s", "-", "--force", "--entitlements", ents, d.app]) == 0)
        #expect(WrapStatus.check(d.app) == .alreadySandboxed)
        #expect(WrapStatus.check(d.app).badge == "Already sandboxed")

        #expect(WrapStatus.check("/System/Applications/Books.app") == .appleApp, "Apple first, though Books is also sandboxed")
        if case .unavailable = WrapStatus.check(d.root + "/missing.app") {} else { Issue.record("a missing app is unavailable") }
        #expect(WrapStatus.wrappable.problem(name: "X") == nil)
    }

    /// The quick Apple check skips re-hashing files; it must give the same answer as the full one.
    @Test func quickAppleCheckMatchesTheFullCheck() throws {
        let d = try DummyApps()
        defer { d.cleanUp() }
        var requirement: SecRequirement?
        SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement)
        for path in ["/System/Applications/Books.app", "/System/Applications/Calculator.app", d.app] {
            var code: SecStaticCode?
            SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code)
            let full = SecStaticCodeCheckValidity(code!, [], requirement) == errSecSuccess
            #expect(SigningInfo.read(URL(fileURLWithPath: path)).isAppleAnchor == full, "\(path)")
        }
    }
}
