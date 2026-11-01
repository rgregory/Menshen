import Foundation
import Testing
@testable import MenshenCore

extension KernelTests {
    /// The always-on Apple service/preference rules (ADR-004) against the real kernel, launchd and
    /// cfprefsd. A control profile without those two lines proves the probe can fail.
    @Suite final class PlatformRuleTests {
        let dir: String
        let probe: String

        deinit { try? FileManager.default.removeItem(atPath: dir) }

        init() throws {
            dir = "/private/tmp/menshen-baseline-\(UUID().uuidString)"
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            probe = dir + "/platformprobe"
            let source = try #require(Bundle.module.url(forResource: "platformprobe", withExtension: "c", subdirectory: "Fixtures"))
            let cc = Process()
            cc.executableURL = URL(fileURLWithPath: "/usr/bin/cc")
            cc.arguments = ["-o", probe, source.path, "-framework", "CoreFoundation"]
            try cc.run()
            cc.waitUntilExit()
            try #require(cc.terminationStatus == 0, "cc failed to build platformprobe")
        }

        func compiled() throws -> String {
            let target = try ResolvedTarget.resolve(probe)
            let config = Learn.build(target: target, events: [], environment: .current())
            return SBPLCompiler(environment: .current()).compile(config)
        }

        /// Same base as a compiled profile, without the Apple service/preference lines.
        var control: String {
            """
            (version 1)(deny default)(import "system.sb")(allow file-read-metadata)
            (allow file-read* file-map-executable (literal "\(probe)"))(allow process-exec* (literal "\(probe)"))
            """
        }

        func run(_ sbplText: String, _ args: [String]) throws -> Int32 {
            let profile = dir + "/p-\(UUID().uuidString).sb"
            try sbplText.write(toFile: profile, atomically: true, encoding: .utf8)
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
            p.arguments = ["-f", profile, probe] + args
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            try p.run()
            p.waitUntilExit()
            return p.terminationStatus
        }

        @Test func appleServicesAndPreferencesAreReachable() throws {
            let profile = try compiled()
            #expect(try run(profile, ["pref", "-"]) == 0, "the global preference domain is readable")
            #expect(try run(profile, ["mach", "com.apple.pasteboard.1"]) == 0, "Apple mach services are reachable")
            #expect(try run(profile, ["mach", "org.example.not-apple"]) != 0, "non-Apple services are not covered")
        }

        /// Risky Apple services are denied for every app, though `com.apple.*` is allowed. The
        /// control (the same profile with that protection switched to allow) reaches each one, so
        /// the name is real on this Mac and the deny is what blocks it.
        @Test func riskyAppleServicesAreDenied() throws {
            let target = try ResolvedTarget.resolve(probe)
            let config = Learn.build(target: target, events: [], environment: .current())
            let compiler = SBPLCompiler(environment: .current())
            let profile = compiler.compile(config)
            for service in Hardening.services {
                var open = config
                let i = try #require(open.hardening.firstIndex { $0.id == service.id })
                open.hardening[i].action = .allow
                #expect(try run(compiler.compile(open), ["mach", service.name]) == 0, "\(service.name) exists and is reachable")
                #expect(try run(profile, ["mach", service.name]) != 0, "\(service.name) is denied")
            }
        }

        /// The assertions above must be able to fail: without the two lines, the same calls are blocked.
        @Test func controlProfileBlocksThem() throws {
            #expect(try run(control, ["pref", "-"]) != 0)
            #expect(try run(control, ["mach", "com.apple.pasteboard.1"]) != 0)
        }
    }
}

extension KernelTests {
    /// Learn → enforce against a real binary, the real kernel and the real log stream.
    @Suite(.serialized) final class IntegrationTests {
        let base: String
        let home: String
        let probe: String
        let env: MenshenEnvironment
        let port = "45917"

        deinit { try? FileManager.default.removeItem(atPath: base) }

        init() throws {
            // Outside the user temp root on purpose: that folder is an anchor and would allow everything.
            base = "/private/tmp/menshen-it-\(UUID().uuidString)"
            home = base + "/home"
            let fm = FileManager.default
            for dir in ["bin", "allowed", "other", "home/.ssh", "home/Library/LaunchAgents", "data"] {
                try fm.createDirectory(atPath: "\(base)/\(dir)", withIntermediateDirectories: true)
            }
            try "hi\n".write(toFile: base + "/input.txt", atomically: true, encoding: .utf8)
            try "key\n".write(toFile: home + "/.ssh/id_test", atomically: true, encoding: .utf8)
            probe = base + "/bin/probe"
            let source = try #require(Bundle.module.url(forResource: "probe", withExtension: "c", subdirectory: "Fixtures"))
            let cc = Process()
            cc.executableURL = URL(fileURLWithPath: "/usr/bin/cc")
            cc.arguments = ["-o", probe, source.path]
            try cc.run()
            cc.waitUntilExit()
            try #require(cc.terminationStatus == 0, "cc failed to build the probe")
            env = MenshenEnvironment(home: home, dataRoot: URL(fileURLWithPath: base + "/data"),
                                     logsRoot: URL(fileURLWithPath: base + "/data/logs"),
                                     userTempRoot: MenshenEnvironment.current().userTempRoot)
        }

        func learn() throws -> LearnSummary {
            var options = LearnOptions(target: probe)
            options.arguments = ["learn", base, home, port]
            return try Learn.run(options, environment: env)
        }

        func enforce() throws -> (EnforceSummary, [EnforceRecord]) {
            // Undo the learn run's side effects so enforce has to create them again.
            try? FileManager.default.removeItem(atPath: base + "/allowed/out.txt")
            try? FileManager.default.removeItem(atPath: home + "/Library/LaunchAgents/evil.plist")
            var options = EnforceOptions(target: probe)
            options.arguments = ["enforce", base, home, port]
            let summary = try Enforce.run(options, environment: env)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let records = try String(contentsOf: summary.logURL, encoding: .utf8).split(separator: "\n")
                .map { try decoder.decode(EnforceRecord.self, from: Data($0.utf8)) }
            return (summary, records)
        }

        func exists(_ path: String) -> Bool { FileManager.default.fileExists(atPath: path) }

        @Test func learnThenEnforce() throws {
            let learned = try learn()
            let config = learned.config
            let flagged = Set(config.hardening.filter { $0.flagged == true }.map(\.id))
            #expect(flagged == ["H-ssh", "H-user-launchagents"])
            #expect(config.rules.contains { $0.operations == ["file-read*"] && $0.filter == Filter(.literal, base + "/input.txt") })
            #expect(config.rules.contains { $0.operations == ["process-exec*"] && $0.filter.value == "/bin/echo" && $0.category == .exec })
            #expect(config.rules.contains { $0.operations == ["network-outbound"] && $0.filter.value == "*:\(port)" })
            #expect(!config.rules.contains { ($0.filter.value ?? "").contains(".ssh") })

            let (summary, records) = try enforce()
            #expect(summary.drained)
            // Learned behavior still works…
            #expect(exists(base + "/allowed/out.txt"))
            // …hardening and the baseline block the rest.
            #expect(!exists(home + "/Library/LaunchAgents/evil.plist"))
            #expect(!exists(base + "/other/new.txt"))

            let denied = records.filter { $0.verdict == .deny }
            let diagnosis = "records \(records.count), denials \(summary.denials), drained \(summary.drained), notices \(summary.streamNotices), status \(summary.outcome.status), log \(summary.logURL.path)"
            #expect(denied.contains { $0.target.hasSuffix("/other/new.txt") && $0.category == "denied" }, "\(diagnosis)")
            #expect(denied.contains { $0.target.hasSuffix("/LaunchAgents/evil.plist") })
            #expect(denied.contains { $0.target.hasSuffix("/.ssh/id_test") && $0.operation.hasPrefix("file-read") })
            #expect(records.contains { $0.verdict == .allow && $0.category == "exec" && $0.target == "/bin/echo" })
            #expect(records.contains { $0.verdict == .allow && $0.category == "network" })
            #expect(records.contains { $0.verdict == .allow && $0.category == "read" && $0.target.hasSuffix("/input.txt") },
                    "activity logging reports ordinary reads for the live dashboard")
            #expect(!denied.contains { $0.target.hasSuffix("/allowed/out.txt") })
        }

        /// Profiles override what was learned: the probe's learned connect, launch and write are
        /// blocked, its learned read still works.
        @Test func profilesRestrictWhatWasLearned() throws {
            let learned = try learn()
            var config = learned.config
            config.profiles = [.offline, .noLaunch, .tempOnly]
            try config.write(to: learned.configURL)

            let (_, records) = try enforce()
            let denied = records.filter { $0.verdict == .deny }
            #expect(denied.contains { $0.operation.hasPrefix("network-outbound") }, "offline")
            #expect(denied.contains { $0.operation.hasPrefix("process-exec") && $0.target == "/bin/echo" }, "no other programs")
            #expect(denied.contains { $0.target.hasSuffix("/allowed/out.txt") }, "temp-only blocks even learned writes")
            #expect(!exists(base + "/allowed/out.txt"))
            #expect(records.contains { $0.verdict == .allow && $0.target.hasSuffix("/input.txt") }, "reads still work")
        }

        /// Background priority and limits wrap the launch; the app still runs and is still tracked.
        @Test func backgroundPriorityStillRunsAndIsTracked() throws {
            let learned = try learn()
            var config = learned.config
            config.profiles = [.background]
            config.limits = ResourceLimits(cpuSeconds: 60, memoryMB: 512)
            try config.write(to: learned.configURL)

            let (summary, records) = try enforce()
            #expect(summary.outcome.status == 0)
            #expect(exists(base + "/allowed/out.txt"))
            #expect(records.contains { $0.target.hasSuffix("/input.txt") }, "reports from the wrapped launch are attributed")
        }

        /// The assertions above must be able to fail: flip one learned rule and watch it bite.
        @Test func flippedLearnedRuleIsEnforced() throws {
            let learned = try learn()
            var config = learned.config
            let i = try #require(config.rules.firstIndex { $0.operations == ["file-write*"] && ($0.filter.value ?? "").hasSuffix("/allowed/out.txt") })
            config.rules[i].action = .deny
            try config.write(to: learned.configURL)

            let (_, records) = try enforce()
            #expect(!exists(base + "/allowed/out.txt"))
            #expect(records.contains { $0.verdict == .deny && $0.target.hasSuffix("/allowed/out.txt") })
        }

        @Test func changedBinaryIsRefused() throws {
            _ = try learn()
            // Rebuild the probe with different code: same path, new cdhash.
            let cc = Process()
            cc.executableURL = URL(fileURLWithPath: "/bin/sh")
            cc.arguments = ["-c", "printf 'int main(void){return 3;}' | /usr/bin/cc -x c -o '\(probe)' -"]
            try cc.run()
            cc.waitUntilExit()
            var options = EnforceOptions(target: probe)
            options.arguments = ["enforce", base, home, port]
            #expect(throws: MenshenError.self) { try Enforce.run(options, environment: env) }
        }
    }
}
