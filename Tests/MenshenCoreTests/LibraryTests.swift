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
}
