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
        var config = sampleConfig()
        config.addCustom(.read, fileTypes: ["mp4"])
        let text = ProfileCompiler(environment: env).compile(config)
        let lines = text.split(separator: "\n").map(String.init)
        let deny = try #require(lines.firstIndex(of: "(deny default)"))
        let learned = try #require(lines.firstIndex(of: ";; --- learned"))
        let yours = try #require(lines.firstIndex { $0.hasPrefix(";; --- your rules") })
        let hardening = try #require(lines.firstIndex { $0.hasPrefix(";; --- hardening") })
        let fileLink = try #require(lines.firstIndex(of: "(deny file-link)"))
        #expect(deny < learned && learned < yours && yours < hardening && hardening < fileLink)
        #expect(text.contains("(allow network-outbound (remote ip \"*:443\") (with report))"))
        #expect(text.contains("(allow process-exec* (literal \"/bin/sh\") (with report))"))
        #expect(text.contains("(subpath \"\(testHome)/Documents\") (with report))"))
        #expect(text.contains("(allow file-read* (regex #\"\\.([mM][pP]4)$\"))"))
        #expect(!text.contains("~/"), "home paths are expanded at compile time")
        #expect(text.contains("(allow user-preference-read user-preference-write (preference-domain \"com.example.foo\"))"))
        #expect(lines.contains("(allow mach-lookup (global-name-prefix \"com.apple.\"))"))
    }

    /// Simple, auditable output: grouped statements, no per-rule comments, nothing redundant.
    @Test func outputIsCompact() throws {
        let text = ProfileCompiler(environment: env).compile(sampleConfig())
        let lines = text.split(separator: "\n").map(String.init)
        #expect(!text.contains("; L-") && !text.contains("; H-") && !text.contains("seen="), "IDs and counts stay in the JSON")
        #expect(!text.contains("com.apple.windowserver.active"), "covered by the always-on com.apple. prefix")
        #expect(lines.filter { $0.hasPrefix("(deny file-read* file-write*") }.count == 1, "one statement for all protected locations")
        #expect(text.contains("(deny file-read* file-write*\n    (subpath \"\(testHome)/.ssh\")\n    (subpath \"\(testHome)/.aws\")"))
        #expect(lines.contains("(allow file-read-metadata)"))
        #expect(lines.filter { $0.hasPrefix(";") }.count <= 6, "only a header and section titles")
    }

    /// Merging must never widen anything: every rule's filter is still present with its action.
    @Test func compactingKeepsEveryRule() {
        let config = sampleConfig()
        let compiler = ProfileCompiler(environment: env)
        let text = compiler.compile(config)
        for rule in config.rules + config.hardening where !compiler.coveredByAlwaysOn(rule, config) {
            if let filter = compiler.filterText(rule.filter) {
                #expect(text.contains(filter), "missing \(rule.id): \(filter)")
            }
        }
        #expect(!text.contains("(allow default"), "nothing is ever opened up wholesale")
    }

    @Test func switchedOffLearnedRuleWinsInItsSection() throws {
        var config = sampleConfig()
        let i = try #require(config.rules.firstIndex { $0.filter.value == "/Applications/Foo.app" })
        config.rules[i].action = .deny
        config.rules[i].operations = ["file-write*"]
        let text = ProfileCompiler(environment: env).compile(config)
        let allowAt = try #require(text.range(of: "(allow file-read*"))
        let denyAt = try #require(text.range(of: "(deny file-write* (subpath \"/Applications/Foo.app\"))"))
        #expect(allowAt.lowerBound < denyAt.lowerBound, "denies come after the section's allows")
    }

    @Test func loggingTogglesControlReports() {
        var config = sampleConfig()
        config.logging.network = false
        config.logging.exec = false
        let text = ProfileCompiler(environment: env).compile(config)
        #expect(text.contains("(allow network-outbound (remote ip \"*:443\"))"))
        #expect(!text.contains("(remote ip \"*:443\") (with report)"))
        #expect(text.contains("(allow process-exec* (literal \"/bin/sh\"))"))
    }

    @Test func fileTypesParseSafely() throws {
        #expect(try MenshenConfig.fileExtensions("*.mp4, .MKV mov;mp4") == ["mp4", "mkv", "mov"])
        #expect(throws: MenshenError.self) { try MenshenConfig.fileExtensions("mp4\")(allow default") }
        #expect(throws: MenshenError.self) { try MenshenConfig.fileExtensions("  ") }
        #expect(ProfileCompiler.caseInsensitive("mp4,mkv") == "[mM][pP]4|[mM][kK][vV]")
    }

    @Test func yourRulesAddAndRemove() throws {
        var config = sampleConfig()
        let rule = config.addCustom(.readWrite, folder: "\(testHome)/Movies", environment: env)
        #expect(rule.id.hasPrefix("C-"))
        #expect(rule.source == .custom && rule.operations == ["file-read*", "file-write*"])
        let again = config.addCustom(.readWrite, folder: "\(testHome)/Movies", environment: env)
        #expect(again.id == rule.id, "no duplicates")
        #expect(config.rules.filter { $0.id == rule.id }.count == 1)
        let types = config.addCustom(.read, fileTypes: ["mp4", "mkv"])
        #expect(RuleText.describe(types) == "Read all .mp4, .mkv files")
        let removed = config.removeCustom(rule.id)
        #expect(removed)
        let learnedID = try #require(config.rules.first { $0.source == .learned }?.id)
        let removedLearned = config.removeCustom(learnedID)
        #expect(!removedLearned, "learned rules can only be switched off")
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

    @Test func rebasedMovesOwnBundleRulesOnly() throws {
        let config = Learn.build(target: fooTarget, events: [
            allow("file-read-data", "/Applications/Foo.app/Contents/Info.plist"),
            allow("file-read-data", "/Applications/Foobar.app/x"),
            allow("mach-lookup", "com.apple.x"),
        ], environment: env)
        let moved = config.rebased(to: "/Applications/.Foo.menshen.app")
        #expect(moved.target.path == "/Applications/.Foo.menshen.app")
        #expect(moved.target.executable == "/Applications/.Foo.menshen.app/Contents/MacOS/Foo")
        #expect(moved.rules.contains { $0.filter.value == "/Applications/.Foo.menshen.app" })
        #expect(!moved.rules.contains { $0.filter.value == "/Applications/Foo.app" })
        #expect(moved.rules.contains { $0.filter.value == "/Applications" || $0.filter.value == "/Applications/Foobar.app/x" },
                "a sibling app with the same prefix must not move")
        #expect(moved.rules.map(\.id) == config.rules.map(\.id), "IDs stay stable so edits are kept")
        let text = ProfileCompiler(environment: env).compile(moved)
        #expect(text.contains("(allow process-exec* (subpath \"/Applications/.Foo.menshen.app\")"))
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

/// "Your rules" against the real kernel: file types anywhere, any letter case, and hardening still wins.
@Suite final class FileTypeRuleTests {
    let dir = "/private/tmp/menshen-ft-\(UUID().uuidString)"
    deinit { try? FileManager.default.removeItem(atPath: dir) }

    func cat(_ file: String, _ profile: String) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
        p.arguments = ["-p", profile, "/bin/cat", file]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try? p.run()
        p.waitUntilExit()
        return p.terminationStatus
    }

    @Test func fileTypesAreReadableAnywhereButProtectedPlacesStayBlocked() throws {
        let home = dir + "/home"
        try FileManager.default.createDirectory(atPath: home + "/.ssh", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: dir + "/media", withIntermediateDirectories: true)
        for f in ["media/clip.MP4", "media/notes.txt", "home/.ssh/key.mp4"] {
            try "x".write(toFile: "\(dir)/\(f)", atomically: true, encoding: .utf8)
        }
        let env = MenshenEnvironment(home: home, dataRoot: URL(fileURLWithPath: dir), logsRoot: URL(fileURLWithPath: dir),
                                     userTempRoot: nil)
        var config = Learn.build(target: try ResolvedTarget.resolve("/bin/cat"), events: [], environment: env)
        let control = ProfileCompiler(environment: env).compile(config)
        config.addCustom(.read, fileTypes: ["mp4"])
        let profile = ProfileCompiler(environment: env).compile(config)

        #expect(cat("\(dir)/media/clip.MP4", control) != 0, "control: not readable without the rule")
        #expect(cat("\(dir)/media/clip.MP4", profile) == 0, "readable in any folder, any letter case")
        #expect(cat("\(dir)/media/notes.txt", profile) != 0, "other types stay blocked")
        #expect(cat("\(home)/.ssh/key.mp4", profile) != 0, "hardening still wins over your rules")
    }
}
