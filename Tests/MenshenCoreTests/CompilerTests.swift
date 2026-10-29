import Foundation
import Testing
@testable import MenshenCore

@Suite struct CompilerTests {
    let env = testEnvironment()

    func sampleConfig() -> MenshenConfig {
        Learn.build(target: fooTarget, events: [
            allow("file-read-data", "/Applications/Foo.app/Contents/Info.plist"),
            allow("file-read-data", "\(testHome)/.ssh/id_rsa"),
            allow("network-outbound", "remote:*:443"),
            allow("process-exec*", "/bin/sh"),
            allow("mach-lookup", "com.apple.windowserver.active"),
            allow("file-write-data", "\(testHome)/Documents/report \"q\".txt"),
        ], environment: env)
    }

    @Test func layoutPutsHardeningAfterLearned() throws {
        let text = ProfileCompiler(environment: env).compile(sampleConfig())
        let lines = text.split(separator: "\n").map(String.init)
        let deny = try #require(lines.firstIndex(of: "(deny default)"))
        let lastLearned = try #require(lines.lastIndex { $0.contains("; L-") })
        let firstHardening = try #require(lines.firstIndex { $0.contains("; H-") })
        let fileLink = try #require(lines.firstIndex(of: "(deny file-link)"))
        #expect(deny < lastLearned && lastLearned < firstHardening && firstHardening < fileLink)
        #expect(text.contains("(deny file-read* file-write* (subpath \"\(testHome)/.ssh\"))  ; H-ssh FLAGGED"))
        #expect(text.contains("(allow network-outbound (remote ip \"*:443\") (with report))"))
        #expect(text.contains("(allow process-exec* (literal \"/bin/sh\") (with report))"))
        #expect(text.contains("(allow mach-lookup (global-name \"com.apple.windowserver.active\"))  ;"))
        #expect(text.contains("(subpath \"\(testHome)/Documents\") (with report))"))
        #expect(!text.contains("~/"), "home paths are expanded at compile time")
        #expect(text.contains("(allow user-preference-read user-preference-write (preference-domain \"com.example.foo\"))"))
        #expect(lines.contains("(allow mach-lookup (global-name-prefix \"com.apple.\"))"))
        #expect(lines.contains("(allow user-preference-read (preference-domain-prefix \"com.apple.\") (preference-domain \"kCFPreferencesAnyApplication\") (preference-domain \"pbs\"))"))
    }

    @Test func loggingTogglesControlReports() {
        var config = sampleConfig()
        config.logging.network = false
        config.logging.exec = false
        let text = ProfileCompiler(environment: env).compile(config)
        #expect(text.contains("(allow network-outbound (remote ip \"*:443\"))  ;"))
        #expect(text.contains("(allow process-exec* (literal \"/bin/sh\"))  ;"))
    }

    @Test func quotesAreEscaped() {
        let c = ProfileCompiler(environment: env)
        #expect(c.quote("a\"b\\c") == "\"a\\\"b\\\\c\"")
    }

    @Test func generatedProfileLoadsInTheKernel() {
        let text = ProfileCompiler(environment: env).compile(sampleConfig())
        #expect(ProfileCompiler.validate(text) == nil)
    }

    @Test func validateRejectsBrokenProfiles() {
        #expect(ProfileCompiler.validate("(version 1)(allow no-such-operation)") != nil)
        #expect(ProfileCompiler.validate("(version 1)(allow network-outbound (remote ip \"1.2.3.4:443\"))") != nil)
    }

    @Test func keepEditsCarriesActionsAndLogging() throws {
        let original = sampleConfig()
        var edited = original
        let i = try #require(edited.hardening.firstIndex { $0.id == "H-ssh" })
        edited.hardening[i].action = .allow
        edited.rules[0].action = .deny
        edited.logging.exec = false
        var regenerated = sampleConfig()
        regenerated.keepEdits(from: edited)
        #expect(regenerated.hardening.first { $0.id == "H-ssh" }?.action == .allow)
        #expect(regenerated.rules[0].action == .deny)
        #expect(regenerated.logging.exec == false)
    }

    @Test func configRoundTrips() throws {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("menshen-\(UUID()).json")
        defer { try? FileManager.default.removeItem(at: url) }
        let config = sampleConfig()
        try config.write(to: url)
        let loaded = try MenshenConfig.load(url)
        #expect(loaded.rules == config.rules)
        #expect(loaded.hardening == config.hardening)
        #expect(loaded.target == config.target)
    }
}

/// The compiled layout relies on "later matching rule wins". Prove it against the real kernel.
@Suite struct SeatbeltOrderingTests {
    func touch(_ path: String, profile: String) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
        p.arguments = ["-p", profile, "/usr/bin/touch", path]
        p.standardError = FileHandle.nullDevice
        try? p.run()
        p.waitUntilExit()
        return p.terminationStatus
    }

    @Test func laterRuleWins() throws {
        let dir = realPath(NSTemporaryDirectory()) + "/menshen-order-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir + "/sub", withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let base = "(version 1)(deny default)(import \"system.sb\")(allow process-exec)(allow file-read*)"
        let allowThenDeny = base + "(allow file-write* (subpath \"\(dir)\"))(deny file-write* (subpath \"\(dir)/sub\"))"
        let denyThenAllow = base + "(deny file-write* (subpath \"\(dir)/sub\"))(allow file-write* (subpath \"\(dir)\"))"
        #expect(touch(dir + "/a", profile: allowThenDeny) == 0)
        #expect(touch(dir + "/sub/b", profile: allowThenDeny) != 0, "a later deny overrides an earlier broader allow")
        #expect(touch(dir + "/sub/c", profile: denyThenAllow) == 0, "a later allow overrides an earlier deny")
    }
}
