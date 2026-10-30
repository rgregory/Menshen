import Foundation
import Testing
@testable import MenshenCore

@Suite final class ProfileTests {
    let dir = "/private/tmp/menshen-tpl-\(UUID().uuidString)"
    deinit { try? FileManager.default.removeItem(atPath: dir) }

    let env = testEnvironment()

    @Test func olderConfigsWithoutProfilesLoad() throws {
        let config = Learn.build(target: fooTarget, events: [], environment: env)
        var json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(config)) as! [String: Any]
        json["profiles"] = nil
        json["limits"] = nil
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .deferredToDate
        let loaded = try decoder.decode(MenshenConfig.self, from: JSONSerialization.data(withJSONObject: json))
        #expect(loaded.profiles == nil && loaded.limits == nil)
    }

    @Test func launchWrapsInPlace() throws {
        var config = Learn.build(target: fooTarget, events: [], environment: env)
        config.profiles = [.background, .tempOnly]
        config.limits = ResourceLimits(cpuSeconds: 30, memoryMB: 256)
        let e = MenshenEnvironment(home: testHome, dataRoot: URL(fileURLWithPath: dir), logsRoot: URL(fileURLWithPath: dir),
                                   userTempRoot: nil)
        let launch = try Enforce.launchOptions(config, environment: e)
        #expect(launch.wrapper == ["/bin/sh", "-c", "ulimit -t 30; exec \"$@\"", "sh",
                                   "/usr/sbin/taskpolicy", "-c", "background", "-d", "throttle"])
        #expect(launch.inner == ["/usr/sbin/taskpolicy", "-m", "256"], "the memory limit must be applied inside the sandbox")
        #expect(launch.environment["TMPDIR"] == e.privateTemp("com.example.foo").path + "/")
        let argv = Runner.command(profile: URL(fileURLWithPath: "/p.sb"), executable: "/a", arguments: ["x"], launch: launch)
        #expect(Array(argv.suffix(8)) == ["/usr/bin/sandbox-exec", "-f", "/p.sb", "/usr/sbin/taskpolicy", "-m", "256", "/a", "x"])
    }

    @Test func summaryReflectsProfiles() {
        var config = Learn.build(target: fooTarget, events: [
            allow("network-outbound", "remote:*:443"),
            allow("process-exec*", "/bin/sh"),
            allow("file-write-data", "\(testHome)/Documents/a.txt"),
        ], environment: env)
        config.profiles = [.offline, .noLaunch, .tempOnly]
        let s = AccessSummary.make(config, environment: env)
        #expect(!s.network.contains { $0.title.contains("443") }, "learned network no longer applies")
        #expect(s.network.contains { $0.access == "blocked" })
        #expect(s.launches.map(\.access) == ["blocked"])
        #expect(!s.files.contains { $0.access.contains("write") && $0.title != "Writes" })
    }

    /// The CPU budget is enforced by the kernel: a busy loop is stopped with SIGXCPU.
    @Test func cpuLimitStopsABusyLoop() throws {
        let profile = URL(fileURLWithPath: dir + "/all.sb")
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try "(version 1)(allow default)".write(to: profile, atomically: true, encoding: .utf8)
        var config = Learn.build(target: fooTarget, events: [], environment: env)
        config.limits = ResourceLimits(cpuSeconds: 1)
        let launch = try Enforce.launchOptions(config, environment: env)
        let started = Date()
        let outcome = try Runner.run(profile: profile, executable: "/bin/sh", arguments: ["-c", "while :; do :; done"],
                                     duration: 20, forwardSignals: false, launch: launch, onLaunch: { _ in }, tick: {})
        #expect(outcome.wasSignaled && outcome.status == SIGXCPU, "status \(outcome.status)")
        #expect(!outcome.stoppedByMenshen && Date().timeIntervalSince(started) < 10)
    }

    /// The memory limit is enforced too: a 300 MiB allocation under a 50 MiB limit is killed.
    @Test func memoryLimitKillsAnOverAllocation() throws {
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let source = dir + "/eat.c"
        try """
            #include <stdlib.h>
            #include <string.h>
            int main(void) { for (int i = 0; i < 30; i++) { char *p = malloc(10 << 20); memset(p, 1, 10 << 20); } return 0; }
            """.write(toFile: source, atomically: true, encoding: .utf8)
        #expect(Swap.run("/usr/bin/cc", ["-o", dir + "/eat", source]) == 0)
        let profile = URL(fileURLWithPath: dir + "/all.sb")
        try "(version 1)(allow default)".write(to: profile, atomically: true, encoding: .utf8)
        var config = Learn.build(target: fooTarget, events: [], environment: env)
        config.limits = ResourceLimits(memoryMB: 50)
        let limited = try Runner.run(profile: profile, executable: dir + "/eat", arguments: [], duration: 20, forwardSignals: false,
                                     launch: try Enforce.launchOptions(config, environment: env), onLaunch: { _ in }, tick: {})
        let free = try Runner.run(profile: profile, executable: dir + "/eat", arguments: [], duration: 20, forwardSignals: false,
                                  launch: LaunchOptions(), onLaunch: { _ in }, tick: {})
        #expect(free.status == 0 && !free.wasSignaled, "control: runs fine without the limit")
        #expect(limited.wasSignaled && limited.status == SIGKILL)
    }
}

/// The sanity set: secrets by name anywhere in home, even inside folders you allowed.
@Suite final class SanitySetTests {
    let dir = "/private/tmp/menshen-sanity-\(UUID().uuidString)"
    deinit { try? FileManager.default.removeItem(atPath: dir) }

    @Test func secretsByNameAreProtected() throws {
        let home = dir + "/home"
        let h = Hardening(environment: MenshenEnvironment(home: home, dataRoot: URL(fileURLWithPath: dir),
                                                           logsRoot: URL(fileURLWithPath: dir), userTempRoot: nil),
                          ownAnchors: [])
        for (path, id) in [("proj/.env", "H-env-files"), ("proj/.env.local", "H-env-files"), ("Downloads/server.key", "H-key-files"),
                           ("certs/a.p12", "H-key-files"), ("backup/id_ed25519", "H-ssh-keys-anywhere"),
                           (".git-credentials", "H-git-credentials"), (".npmrc", "H-npmrc"),
                           ("Library/Application Support/Slack/x", "H-slack"), ("Library/Calendars/c", "H-calendars")] {
            #expect(h.entry(for: "\(home)/\(path)", isWrite: false)?.id == id, "\(path)")
        }
        #expect(h.entry(for: "\(home)/proj/readme.txt", isWrite: false) == nil)
        #expect(h.entry(for: "\(home)/proj/environment.md", isWrite: false) == nil, "only .env names, not 'env' anywhere")
    }

    @Test func envFilesBlockedEvenInAnAllowedFolder() throws {
        let home = dir + "/home"
        try FileManager.default.createDirectory(atPath: home + "/proj", withIntermediateDirectories: true)
        try "SECRET=1".write(toFile: home + "/proj/.env", atomically: true, encoding: .utf8)
        try "hi".write(toFile: home + "/proj/readme.txt", atomically: true, encoding: .utf8)
        let env = MenshenEnvironment(home: home, dataRoot: URL(fileURLWithPath: dir), logsRoot: URL(fileURLWithPath: dir),
                                     userTempRoot: nil)
        var config = Learn.build(target: try ResolvedTarget.resolve("/bin/cat"), events: [], environment: env)
        config.addCustom(.read, folder: home + "/proj", environment: env)
        let profile = SBPLCompiler(environment: env).compile(config)
        func cat(_ f: String) -> Int32 {
            Swap.run("/usr/bin/sandbox-exec", ["-p", profile, "/bin/cat", f])
        }
        #expect(cat(home + "/proj/readme.txt") == 0, "the folder you allowed is readable")
        #expect(cat(home + "/proj/.env") != 0, "but not the .env inside it")
    }

    /// Configs learned before a protection existed still get it when compiled.
    @Test func olderConfigsGetNewProtections() {
        let env = testEnvironment()
        var config = Learn.build(target: fooTarget, events: [], environment: env)
        config.hardening.removeAll { $0.id == "H-npmrc" || $0.id == "H-env-files" }
        let text = SBPLCompiler(environment: env).compile(config)
        #expect(text.contains("(subpath \"\(testHome)/.npmrc\")"))
        #expect(text.contains(#"(regex #"/\.env(\.[^/]*)?$")"#))
    }
}
