import Foundation
import Testing
@testable import MenshenCore

/// The read side the GUI is built on.
@Suite final class LibraryTests {
    let root = "/private/tmp/menshen-lib-\(UUID().uuidString)"
    let env: MenshenEnvironment

    init() {
        env = MenshenEnvironment(home: testHome, dataRoot: URL(fileURLWithPath: root + "/data"),
                                 logsRoot: URL(fileURLWithPath: root + "/logs"), userTempRoot: nil)
    }

    deinit { try? FileManager.default.removeItem(atPath: root) }

    @Test func listsConfiguredAppsButNotBackups() throws {
        let config = Learn.build(target: fooTarget, events: [allow("file-read-data", "\(testHome)/.ssh/id_rsa")],
                                 environment: env)
        let url = env.configURL(fooTarget.identity.key)
        try config.save(to: url)
        let backup = try #require(try config.save(to: url), "second save keeps a backup")
        #expect(FileManager.default.fileExists(atPath: backup.path))

        let apps = Library.apps(env)
        #expect(apps.count == 1)
        #expect(apps[0].id == "com.example.foo")
        #expect(apps[0].flagged.map(\.id) == ["H-ssh"])
        #expect(apps[0].swap == nil)
        #expect(apps[0].appPath == "/Applications/Foo.app")
    }

    @Test func sessionsAreCountedAndNewestFirst() throws {
        let key = fooTarget.identity.key
        let learnDir = env.learnDir(key)
        let logsDir = env.logsDir(key)
        try FileManager.default.ensureDirectory(learnDir)
        try FileManager.default.ensureDirectory(logsDir)

        let capture = try NDJSONWriter(learnDir.appendingPathComponent("20261029-100000.ndjson"))
        capture.write(allow("file-read-data", "/x", count: 3))
        capture.write(SandboxEvent(process: "Foo", pid: 1, verdict: .deny, operation: "file-write-data", target: "/y"))
        capture.close()

        let log = try NDJSONWriter(logsDir.appendingPathComponent("20261029-110000.jsonl"))
        for verdict in [Verdict.deny, .deny, .allow] {
            log.write(EnforceRecord(ts: Date(), runId: "r", pid: 1, process: "Foo", verdict: verdict,
                                    operation: "file-write-create", target: "/z", category: "denied", count: 1))
        }
        log.close()

        let sessions = Library.sessions(key, env)
        #expect(sessions.map(\.kind) == [.enforce, .learn], "newest first")
        #expect(sessions[0].events == 3 && sessions[0].denials == 2)
        #expect(sessions[1].events == 4 && sessions[1].denials == 1)
        #expect(Library.records(sessions[0].url).count == 3)
        #expect(Library.captureEvents(sessions[1].url).count == 2)
    }

    @Test func forgetMovesEverythingForTheAppToTheTrash() throws {
        let key = fooTarget.identity.key
        let fm = FileManager.default
        let config = Learn.build(target: fooTarget, events: [], environment: env)
        try config.save(to: env.configURL(key))
        try config.save(to: env.configURL(key))                       // second save leaves a backup
        try fm.ensureDirectory(env.learnDir(key))
        try "x".write(to: env.learnDir(key).appendingPathComponent("a.ndjson"), atomically: true, encoding: .utf8)
        try fm.ensureDirectory(env.logsDir(key))
        try "x".write(to: env.logsDir(key).appendingPathComponent("b.jsonl"), atomically: true, encoding: .utf8)
        try fm.ensureDirectory(env.privateTemp(key))
        let other = env.configURL("com.example.other")
        try config.save(to: other)                                    // another app's config must survive

        #expect(Library.files(for: key, env).count == 5)
        let trashed = try Library.forget(key, env)
        defer { trashed.forEach { try? fm.removeItem(at: $0) } }      // don't leave test files in the user's Trash
        #expect(trashed.count == 5)
        #expect(Library.files(for: key, env).isEmpty)
        #expect(fm.fileExists(atPath: other.path))
        #expect(Library.apps(env).map(\.configURL.lastPathComponent) == ["com.example.other.json"], "only the other app is left")
    }

    @Test func forgetRefusesWhileReplaced() throws {
        let key = fooTarget.identity.key
        try Learn.build(target: fooTarget, events: [], environment: env).save(to: env.configURL(key))
        try Swap.saveRecords([SwapRecord(key: key, appPath: "/Applications/Foo.app",
                                         hiddenPath: "/Applications/.Foo.menshen.app", cdhash: nil, date: Date())], env)
        #expect(throws: MenshenError.self) { try Library.forget(key, env) }
        #expect(FileManager.default.fileExists(atPath: env.configURL(key).path), "nothing moved")
    }

    @Test func forgetWithNothingStoredSaysSo() {
        #expect(throws: MenshenError.self) { try Library.forget("com.example.nothing", env) }
    }
}
