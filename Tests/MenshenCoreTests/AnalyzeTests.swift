import Foundation
import Testing
@testable import MenshenCore

/// `analyze` builds a config from the app on disk, with no learn run behind it (ADR-012).
@Suite struct AnalyzeTests {
    let env = testEnvironment()

    func build(_ facts: BundleFacts = BundleFacts()) -> MenshenConfig {
        Analyze.build(target: fooTarget, environment: env, facts: facts).config
    }

    func rule(_ config: MenshenConfig, _ ops: [String], _ kind: FilterKind, _ value: String?) -> Rule? {
        config.rules.first { $0.operations == ops && $0.filter == Filter(kind, value) }
    }

    @Test func baselineIsMarkedAsAnalyzedNotLearned() {
        let c = build()
        #expect(c.analysis != nil)
        #expect(c.learning.runs == 0 && c.learning.events == 0 && c.learning.captures.isEmpty)
        #expect(c.learning.warnings.contains(Analyze.caveat))
        #expect(c.rules.allSatisfy { $0.source == .baseline })
        #expect(c.rules.allSatisfy { $0.id.hasPrefix("B-") })
    }

    @Test func systemAndOwnDataAreAllowed() {
        let c = build()
        #expect(rule(c, ["file-read*", "file-map-executable"], .subpath, "/System") != nil)
        #expect(rule(c, ["file-read*", "file-map-executable"], .subpath, "/usr") != nil)
        // Its own data folders, including ones macOS hasn't created yet.
        #expect(rule(c, ["file-read*", "file-write*"], .subpath, "~/Library/Application Support/com.example.foo") != nil)
        #expect(rule(c, ["file-read*", "file-write*"], .subpath, "~/Library/Preferences/com.example.foo.plist") != nil)
        #expect(rule(c, ["file-read*", "file-write*"], .subpath, "$DARWIN/C/com.example.foo") != nil)
        // Never a write rule for the app's own bundle: every profile already reads and runs it.
        #expect(!c.rules.contains { ($0.filter.value ?? "").hasPrefix("/Applications/Foo.app")
            && $0.operations.contains("file-write*") })
        // Nothing of yours: no Documents, Desktop or home-wide rule.
        #expect(!c.rules.contains { ["~", "~/Documents", "~/Desktop", "/"].contains($0.filter.value ?? "") })
    }

    @Test func nothingIsAllowedOutWithoutEvidence() {
        let c = build()
        let network = c.rules.first { $0.operations == ["network-outbound"] }
        #expect(network?.action == .deny)
        #expect(c.rules.first { $0.operations == ["network-bind", "network-inbound"] }?.action == .deny)
        #expect(c.rules.first { $0.operations == ["process-exec*"] }?.action == .deny)
        #expect(c.rules.first { $0.operations == ["iokit-open-user-client"] }?.action == .deny)
    }

    @Test func networkIsAllowedOnlyWithEvidenceFromTheBundle() {
        var facts = BundleFacts()
        facts.networkEvidence = ["the network client entitlement"]
        facts.serverEvidence = ["Bonjour services in Info.plist"]
        let c = build(facts)
        let out = c.rules.first { $0.operations == ["network-outbound"] }
        #expect(out?.action == .allow)
        #expect(out?.category == .network)   // reported, so it shows in the enforce log
        #expect(c.rules.first { $0.operations == ["network-bind", "network-inbound"] }?.action == .allow)
    }

    @Test func declaredFileKindsBecomeOneReadRule() {
        var facts = BundleFacts()
        facts.documentTypes = Analyze.cleanExtensions(["MP4", ".mkv", "mov", "mp4"])
        let c = build(facts)
        let types = c.rules.first { $0.filter.kind == .fileTypes }
        #expect(types?.action == .allow)
        #expect(types?.operations == ["file-read*"])
        #expect(types?.filter.value == "mkv,mov,mp4")
    }

    /// A declaration never hands out key material, however the app words it.
    @Test func credentialsAreNeverGrantedByADeclaration() {
        let cleaned = Analyze.cleanExtensions(["pem", "key", "p12", "kdbx", "env", "txt", "bad ext",
                                               "waytoolongextensionname"])
        #expect(cleaned == ["txt"])
    }

    @Test func hardeningIsAppliedWithoutHavingRunTheApp() {
        let c = build()
        let denied = c.hardening.filter { $0.action == .deny }
        #expect(denied.count > 50)
        #expect(c.hardening.contains { $0.id == "H-ssh" && $0.action == .deny })
        #expect(c.hardening.contains { $0.id == "H-sock-containers" && $0.action == .deny })
        #expect(c.hardening.allSatisfy { $0.flagged != true })   // nothing was watched, so nothing is flagged
        #expect(c.hardening.first { $0.id == "H-ssh" }?.note?.hasSuffix(Hardening.notRunNote) == true)
    }

    /// The compiled profile keeps the layering: baseline first, protections last and winning.
    @Test func compiledProfileDeniesSensitiveLocations() {
        var facts = BundleFacts()
        facts.networkEvidence = ["the network client entitlement"]
        let text = SBPLCompiler(environment: env).compile(build(facts))
        #expect(text.contains(";; --- baseline (analyzed from the app bundle, not from watching it run)"))
        let hardening = text.range(of: ";; --- hardening")
        let ssh = text.range(of: "/.ssh")
        #expect(hardening != nil && ssh != nil && hardening!.lowerBound < ssh!.lowerBound)
        #expect(text.contains("(allow network-outbound"))
    }

    /// End to end on a real (dummy) app: the profile loads, re-analyzing keeps a backup, and a
    /// learned config is never thrown away by an analysis.
    @Test func analyzeWritesAConfigAndNeverOverwritesALearnedOne() throws {
        let d = try DummyApps()
        defer { d.cleanUp() }
        let result = try Analyze.run(target: d.app, environment: d.env)
        #expect(result.config.analysis != nil)
        #expect(result.config.target.bundleId == d.bundleId)
        #expect(FileManager.default.fileExists(atPath: result.configURL.path))
        #expect(result.config.rules.contains { $0.filter.kind == .fileTypes })   // it declares plain text
        #expect(try MenshenConfig.load(result.configURL).analysis != nil)

        let again = try Analyze.run(target: d.app, environment: d.env)
        #expect(again.backupURL != nil)

        try d.writeConfig()
        #expect(throws: MenshenError.self) { try Analyze.run(target: d.app, environment: d.env) }
        #expect(try MenshenConfig.load(result.configURL).learning.runs == 1)
    }

    /// --force replaces a learned config, but keeps its captures so Rebuild undoes it.
    @Test func forcedAnalyzeKeepsTheLearnCapturesSoRebuildUndoesIt() throws {
        let d = try DummyApps()
        defer { d.cleanUp() }
        let capture = d.env.learnDir(try ResolvedTarget.resolve(d.app).identity.key)
            .appendingPathComponent("20261118-120000.ndjson")
        try FileManager.default.ensureDirectory(capture.deletingLastPathComponent())
        let event = SandboxEvent(process: "Dummy", pid: 1, verdict: .allow, operation: "file-read-data",
                                 target: "/usr/share/dict/words", count: 1)
        try Data((String(decoding: try JSONEncoder().encode(event), as: UTF8.self) + "\n").utf8).write(to: capture)

        var learned = Learn.build(target: try ResolvedTarget.resolve(d.app), events: [event],
                                  environment: d.env, runs: 1, captures: [capture.path])
        learned.addCustom(.read, fileTypes: ["mp4"])
        let url = d.env.configURL(learned.target.key)
        try learned.save(to: url)

        let forced = try Analyze.run(target: d.app, force: true, environment: d.env)
        #expect(forced.config.analysis != nil)
        #expect(forced.config.learning.captures == [capture.path])
        #expect(forced.backupURL != nil)
        #expect(forced.config.rules.contains { $0.source == .custom })   // your rules survive
        #expect(!forced.config.rules.contains { $0.source == .learned })

        let (rebuilt, _) = try Learn.rebuild(configURL: url, environment: d.env)
        #expect(rebuilt.analysis == nil)
        #expect(rebuilt.learning.runs == 1)
        #expect(rebuilt.rules.contains { $0.source == .learned })
    }
}
