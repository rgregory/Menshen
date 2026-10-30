import Foundation
import Testing
@testable import MenshenCore

@Suite struct SummaryTests {
    let env = testEnvironment()

    func summary(_ events: [SandboxEvent]) -> AccessSummary {
        AccessSummary.make(Learn.build(target: fooTarget, events: events, environment: env), environment: env)
    }

    @Test func groupsFilesByOwner() throws {
        let s = summary([
            allow("file-read-data", "/Applications/Foo.app/Contents/Info.plist"),
            allow("file-write-data", "\(testHome)/Library/Application Support/Foo/db"),
            allow("file-read-data", "\(testHome)/Movies/clip.mov"),
            allow("file-read-data", "/System/Library/Fonts/A.ttf"),
            allow("file-read-data", "/usr/lib/libz.dylib"),
            allow("file-write-data", "/dev/null"),
            allow("file-write-data", "\(testHome)/notes.txt"),
        ])
        let titles = s.files.map(\.title)
        #expect(titles == ["The app itself", "Its own data", "~/Movies", "System files", "Devices", "Other locations"])
        let own = try #require(s.files.first { $0.title == "Its own data" })
        #expect(own.access == "read & write")
        #expect(own.detail.contains("~/Library/Application Support/Foo"))
        #expect(s.files.first { $0.title == "System files" }?.detail == "/System, /usr")
        #expect(s.files.first { $0.title == "Other locations" }?.detail == "~/notes.txt")
    }

    @Test func networkLaunchesAndServicesInPlainWords() {
        let s = summary([
            allow("network-outbound", "remote:*:443"),
            allow("network-outbound", "/private/var/run/mDNSResponder"),
            allow("process-exec*", "/bin/sh"),
            allow("process-exec*", "/Applications/Foo.app/Contents/MacOS/Helper"),
            allow("mach-lookup", "org.example.helper"),
            allow("mach-lookup", "com.apple.windowserver.active"),
        ])
        #expect(Set(s.network.map(\.title)) == ["Connect out to port 443 (HTTPS)", "Look up host names (DNS)"])
        #expect(s.launches.map(\.title) == ["sh"], "its own helpers are not listed as launches")
        #expect(s.services.contains { $0.title == "Other services" && $0.detail == "org.example.helper" })
        #expect(s.services.contains { $0.title == "Its own settings" && $0.detail == "com.example.foo" })
    }

    @Test func sensitiveListsFlaggedFirst() {
        let s = summary([allow("file-read-data", "\(testHome)/.ssh/id_rsa")])
        #expect(s.sensitive.first?.title == "SSH keys and config")
        #expect(s.sensitive.first?.access == "blocked")
        #expect(s.sensitive.first?.flagged == true)
        #expect(s.protectedCount > 30)
    }

    @Test func ruleTextIsReadable() {
        #expect(RuleText.describe(Rule(action: .allow, operations: ["file-read*", "file-write*"],
                                       filter: Filter(.subpath, "~/Library/Caches/foo"), source: .learned))
                == "Read & write ~/Library/Caches/foo")
        #expect(RuleText.object(Filter(.local, "localhost:8080")) == "port 8080 (HTTP alt) on this Mac")
        #expect(RuleText.access(["process-exec*"]) == "run")
        #expect(RuleText.verb(["sysctl-read"]) == "Read system information")
    }
}
