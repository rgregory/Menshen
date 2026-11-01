import Foundation
import Testing
@testable import MenshenCore

@Suite struct ActivityTests {
    let env = testEnvironment()

    @Test func olderConfigsWithoutActivityStillLoad() throws {
        let json = #"{"denials": false, "network": true, "exec": true, "writeOutside": true}"#
        let logging = try JSONDecoder().decode(LoggingSettings.self, from: Data(json.utf8))
        #expect(logging.activity, "missing settings take their defaults")
        #expect(!logging.denials, "present settings are kept")
        #expect(try JSONDecoder().decode(LoggingSettings.self, from: Data("{}".utf8)) == LoggingSettings())
    }

    @Test func activityIsReportedButSystemReadsStayQuiet() {
        let config = Learn.build(target: fooTarget, events: [
            allow("file-read-data", "/System/Library/Fonts/A.ttf"),
            allow("file-read-data", "\(testHome)/Music/song.mp3"),
            allow("mach-lookup", "org.example.helper"),
        ], environment: env)
        let text = SBPLCompiler(environment: env).compile(config)
        #expect(text.contains("(allow file-read* (subpath \"/System\"))\n"), "system reads: no report")
        #expect(text.contains("(subpath (home \"/Music\")) (with report))"))
        #expect(text.contains("(allow mach-lookup (global-name \"org.example.helper\") (with report))"))
        #expect(text.contains("(allow mach-lookup (global-name-prefix \"com.apple.\") (with report))"))

        var quiet = config
        quiet.logging.activity = false
        let off = SBPLCompiler(environment: env).compile(quiet)
        #expect(!off.contains("Music\") (with report)"), "activity off: reads are not reported")
        #expect(off.contains("(allow mach-lookup (global-name-prefix \"com.apple.\"))\n"))
    }

    @Test func recordsAreGroupedForTheDashboard() {
        func r(_ verdict: Verdict, _ op: String, _ target: String, _ category: String, _ count: Int = 1) -> EnforceRecord {
            EnforceRecord(ts: Date(), runId: "r", pid: 1, process: "Foo", verdict: verdict, operation: op,
                          target: target, category: category, count: count)
        }
        let a = ActivitySummary.make([
            r(.allow, "network-outbound", "remote:*:443", "network", 3),
            r(.allow, "network-outbound", "/private/var/run/syslog", "network"),
            r(.allow, "file-read-data", "~/Music/a.mp3", "read", 2),
            r(.allow, "file-write-create", "~/Music/b.mp3", "write-outside"),
            r(.allow, "process-exec*", "/bin/sh", "exec"),
            r(.allow, "mach-lookup", "com.example.render (xpc)", "service"),
            r(.deny, "file-write-create", "~/Library/LaunchAgents/x.plist", "denied"),
        ])
        #expect(a.total == 10 && a.blocked == 1)
        #expect(a.network.first?.label == "port 443 (HTTPS)" && a.network.first?.count == 3)
        #expect(a.network.contains { $0.label == "the system log" })
        #expect(a.disk.first?.label == "~/Music" && a.disk.first?.detail == "read & write" && a.disk.first?.count == 3)
        #expect(a.launches.first?.label == "sh")
        #expect(a.services.first?.label == "com.example.render")
        #expect(a.blockedTop.first?.label == "Write ~/Library/LaunchAgents/x.plist")
    }

    /// A blocked connection is still network activity (seen live: "1 blocked, 0 network").
    @Test func blockedConnectionsCountAsNetwork() {
        let records = [
            EnforceRecord(ts: Date(), runId: "r", pid: 1, process: "VLC", verdict: .deny, operation: "network-outbound",
                          target: "remote:*:9", category: "denied", count: 2),
            EnforceRecord(ts: Date(), runId: "r", pid: 1, process: "VLC", verdict: .deny, operation: "process-exec*",
                          target: "/bin/sh", category: "denied", count: 1),
        ]
        let s = ActivitySummary.make(records)
        #expect(s.blocked == 3)
        #expect(s.counts["network"] == 2 && s.counts["exec"] == 1)
        #expect(s.network.first?.detail == "blocked")
        #expect(s.launches.first?.label == "sh")
    }

    @Test func writesInOwnFoldersAreNotOutside() {
        let event = SandboxEvent(process: "Foo", pid: 1, verdict: .allow, operation: "file-write-data",
                                 target: "\(testHome)/Library/Caches/foo/x")
        #expect(EnforceRecord.category(for: event, ownFolders: ["\(testHome)/Library/Caches/foo"]) == "write")
        #expect(EnforceRecord.category(for: event, ownFolders: []) == "write-outside")
    }

    @Test func followerReadsOnlyCompleteNewLines() throws {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("menshen-follow-\(UUID()).jsonl")
        defer { try? FileManager.default.removeItem(at: url) }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        func line(_ target: String) throws -> Data {
            try encoder.encode(EnforceRecord(ts: Date(timeIntervalSince1970: 0), runId: "r", pid: 1, process: "p",
                                             verdict: .allow, operation: "file-read-data", target: target,
                                             category: "read", count: 1)) + Data([0x0A])
        }
        let first = try line("/a"), second = try line("/b")
        try (first + second.prefix(10)).write(to: url)           // second line only half written
        let follower = LogFollower(url: url)
        #expect(follower.poll().map(\.target) == ["/a"])
        let handle = try FileHandle(forWritingTo: url)
        try handle.seekToEnd()
        handle.write(second.dropFirst(10))
        try handle.close()
        #expect(follower.poll().map(\.target) == ["/b"], "the rest of the line arrives later")
        #expect(follower.poll().isEmpty)
    }

    @Test func socketsReadPlainly() {
        func rule(_ path: String) -> Rule {
            Rule(action: .allow, operations: ["network-outbound"], filter: Filter(.literal, path), source: .learned)
        }
        #expect(RuleText.describe(rule("/private/var/run/syslog")) == "Write to the system log")
        #expect(RuleText.describe(rule("/private/var/run/mDNSResponder")) == "Look up host names (DNS)")
        #expect(RuleText.describe(rule("/tmp/x.sock")) == "Talk to local socket /tmp/x.sock")
    }
}
