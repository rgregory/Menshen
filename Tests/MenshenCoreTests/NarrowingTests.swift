import Foundation
import Testing
@testable import MenshenCore

extension KernelTests {
    /// Learned rules stay as narrow as what the kernel reported: the app's own folders in the
    /// Darwin folder (not every app's caches), and the names of the shared memory, Mach services
    /// and sysctls it used. Checked by the kernel, each with a control that succeeds without the
    /// restriction.
    @Suite final class NarrowingTests {
        let dir = "/private/tmp/menshen-narrow-\(UUID().uuidString)"
        let tag = UUID().uuidString.prefix(8)
        var cleanup: [String] = []
        deinit {
            for path in cleanup + [dir] { try? FileManager.default.removeItem(atPath: path) }
        }

        /// Runs `command` under `profile` and returns what it printed, or nil if it failed.
        func run(_ profile: String, _ command: [String]) -> String? {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
            p.arguments = ["-p", profile] + command
            let out = Pipe()
            p.standardOutput = out
            p.standardError = FileHandle.nullDevice
            guard (try? p.run()) != nil else { return nil }
            let text = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            p.waitUntilExit()
            return p.terminationStatus == 0 ? text : nil
        }

        func environment(userTempRoot: String?) -> MenshenEnvironment {
            MenshenEnvironment(home: dir + "/home", dataRoot: URL(fileURLWithPath: dir), logsRoot: URL(fileURLWithPath: dir),
                               userTempRoot: userTempRoot)
        }

        @Test func darwinFolderGivesOnlyTheAppsOwnCaches() throws {
            let root = try #require(MenshenEnvironment.current().userTempRoot)
            let own = "\(root)/C/cat.menshen-test-\(tag)"  // named after the app (/bin/cat), so it owns it
            let other = "\(root)/C/com.example.other-\(tag)"
            let temp = "\(root)/T/menshen-test-\(tag)"
            for folder in [own, other, temp] {
                try FileManager.default.createDirectory(atPath: folder, withIntermediateDirectories: true)
                try "x".write(toFile: folder + "/f", atomically: true, encoding: .utf8)
                cleanup.append(folder)
            }
            let env = environment(userTempRoot: root)
            let config = Learn.build(target: try ResolvedTarget.resolve("/bin/cat"),
                                     events: [allow("file-write-data", own + "/f")], environment: env)
            #expect(!config.anchors.contains(root), "the Darwin folder itself is not the app's")
            let profile = SBPLCompiler(environment: env).compile(config)

            #expect(run(profile, ["/bin/cat", own + "/f"]) == "x", "its own cache folder")
            #expect(run(profile, ["/bin/cat", temp + "/f"]) == "x", "the shared temp folder")
            #expect(run(profile, ["/bin/cat", other + "/f"]) == nil, "another app's caches stay closed")

            var wide = config  // control: the whole Darwin folder, as learned before
            wide.rules.append(Rule(action: .allow, operations: ["file-read*", "file-write*"], filter: Filter(.subpath, root),
                                   source: .learned))
            #expect(run(SBPLCompiler(environment: env).compile(wide), ["/bin/cat", other + "/f"]) == "x")
        }

        @Test func namedSharedMemoryRegistrationAndSysctlWrites() throws {
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            let probePath = dir + "/nameprobe"
            let source = try #require(Bundle.module.url(forResource: "nameprobe", withExtension: "c", subdirectory: "Fixtures"))
            let cc = Process()
            cc.executableURL = URL(fileURLWithPath: "/usr/bin/clang")
            cc.arguments = ["-O0", "-o", probePath, source.path]
            try cc.run()
            cc.waitUntilExit()
            try #require(cc.terminationStatus == 0)

            let good = "menshen.good-\(tag)", other = "menshen.other-\(tag)"
            let events = ["write-create", "read-data", "write-data", "write-unlink"].map { allow("ipc-posix-shm-\($0)", good) }
                + [allow("mach-register", good), allow("sysctl-write", "kern.grade_cputype")]
            let env = environment(userTempRoot: nil)
            let config = Learn.build(target: try ResolvedTarget.resolve(probePath), events: events, environment: env)
            let profile = SBPLCompiler(environment: env).compile(config)
            func probe(_ what: String, _ name: String, _ profile: String) -> String? {
                run(profile, [probePath, what, name])?.trimmingCharacters(in: .whitespacesAndNewlines)
            }

            #expect(probe("shm", good, profile) == "ok", "the shared memory it created while learning")
            #expect(probe("shm", other, profile) == nil, "other shared memory names")
            #expect(probe("global", good, profile) == "ok", "the service name it registered")
            #expect(probe("global", other, profile) == nil, "other service names in the login session")
            #expect(probe("reg", other, profile) == "ok", "per-pid names: system.sb allows them all")
            #expect(probe("sysctl", "kern.tcsm_enable", profile) == nil, "a sysctl it never wrote")

            // Controls: the same operations pass with the filter-less rules learning used to write,
            // and a learned sysctl name passes.
            var wide = config
            wide.rules.removeAll { ["mach-register", "sysctl-write"].contains($0.operations[0]) || $0.operations[0].hasPrefix("ipc-posix") }
            for op in ["ipc-posix-shm-write-create", "ipc-posix-shm-read-data", "ipc-posix-shm-write-data",
                       "ipc-posix-shm-write-unlink", "mach-register", "sysctl-write"] {
                wide.rules.append(Rule(action: .allow, operations: [op], filter: .any, source: .learned))
            }
            let wideProfile = SBPLCompiler(environment: env).compile(wide)
            #expect(probe("shm", other, wideProfile) == "ok")
            #expect(probe("global", other, wideProfile) == "ok")
            #expect(probe("sysctl", "kern.tcsm_enable", wideProfile) == "ok")
            let tcsm = Learn.build(target: try ResolvedTarget.resolve(probePath), events: [allow("sysctl-write", "kern.tcsm_enable")],
                                   environment: env)
            #expect(probe("sysctl", "kern.tcsm_enable", SBPLCompiler(environment: env).compile(tcsm)) == "ok")
        }

        @Test func tempOnlyAllowsSharedTempAndOwnCachesNotEveryApps() throws {
            let env = testEnvironment(data: dir)
            var config = Learn.build(target: fooTarget,
                                     events: [allow("file-write-data", "/private/var/folders/aa/bb/C/com.example.foo/x")],
                                     environment: env)
            config.profiles = [.tempOnly]
            let profile = SBPLCompiler(environment: env).compile(config)
            let section = try #require(profile.components(separatedBy: ";; --- profiles").last)
            #expect(section.contains("(subpath \"/private/var/folders/aa/bb/T\")"))
            #expect(section.contains("(subpath \"/private/var/folders/aa/bb/C/com.example.foo\")"))
            #expect(!section.contains("(subpath \"/private/var/folders/aa/bb\")"))
        }

        @Test func rebuildRegeneratesFromCapturesAndKeepsYourChoices() throws {
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            let env = testEnvironment(data: dir)
            let capture = URL(fileURLWithPath: dir + "/run1.ndjson")
            let writer = try NDJSONWriter(capture)
            for event in [allow("mach-register", "com.apple.axserver (per-pid)"),
                          allow("file-write-data", "/private/var/folders/aa/bb/C/com.example.foo/x"),
                          allow("network-outbound", "remote:*:443")] { writer.write(event) }
            writer.close()

            // A config as learning used to write it: the whole Darwin folder, a filter-less register.
            var old = Learn.build(target: fooTarget, events: try readCapture(capture), environment: env, captures: [capture.path])
            old.rules.removeAll { $0.operations == ["mach-register"] }
            old.rules.append(Rule(action: .allow, operations: ["mach-register"], filter: .any, source: .learned))
            old.rules.append(Rule(action: .allow, operations: ["file-read*", "file-write*"],
                                  filter: Filter(.subpath, "/private/var/folders/aa/bb"), source: .learned))
            old.anchors.append("/private/var/folders/aa/bb")
            old.addCustom(.read, fileTypes: ["mp4"])
            old.profiles = [.offline]
            old.logging.activity = false
            let https = try #require(old.rules.firstIndex { $0.operations == ["network-outbound"] })
            old.rules[https].action = .deny
            let url = env.configURL("com.example.foo")
            try old.write(to: url)

            let (config, backup) = try Learn.rebuild(configURL: url, environment: env)
            #expect(backup != nil)
            #expect(try MenshenConfig.load(url).rules == config.rules, "saved")
            #expect(!config.rules.contains { $0.filter.value == "/private/var/folders/aa/bb" })
            #expect(!config.anchors.contains("/private/var/folders/aa/bb"))
            #expect(config.rules.contains { $0.operations == ["mach-register"] && $0.filter == Filter(.localName, "com.apple.axserver") })
            #expect(!config.rules.contains { $0.operations == ["mach-register"] && $0.filter == .any })
            #expect(config.rules.contains { $0.source == .custom && $0.filter == Filter(.fileTypes, "mp4") }, "your rules")
            #expect(config.profiles == [.offline])
            #expect(config.logging.activity == false)
            #expect(config.rules.first { $0.operations == ["network-outbound"] }?.action == .deny, "rules you switched off")
        }

        @Test func rebuildRefusesWhenACaptureIsMissing() throws {
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            let env = testEnvironment(data: dir)
            let config = Learn.build(target: fooTarget, events: [allow("network-outbound", "remote:*:443")], environment: env,
                                     captures: [dir + "/gone.ndjson"])
            let url = env.configURL("com.example.foo")
            try config.write(to: url)
            let before = try Data(contentsOf: url)
            #expect(throws: MenshenError.self) { try Learn.rebuild(configURL: url, environment: env) }
            #expect(try Data(contentsOf: url) == before, "the config is left as it was")
        }
    }
}
