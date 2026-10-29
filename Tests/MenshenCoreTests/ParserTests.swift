import Foundation
import Testing
@testable import MenshenCore

@Suite struct ParserTests {
    @Test func allowWithTarget() throws {
        let e = try #require(ReportParser.parse("Sandbox: VLC(81047) allow mach-lookup com.apple.system.notification_center"))
        #expect(e == SandboxEvent(process: "VLC", pid: 81047, verdict: .allow, operation: "mach-lookup",
                                  target: "com.apple.system.notification_center"))
    }

    @Test func denyWithPathContainingSpaces() throws {
        let e = try #require(ReportParser.parse("Sandbox: probe(80083) deny(1) file-write-create /Users/x/Library/Application Support/a b.txt"))
        #expect(e.verdict == .deny)
        #expect(e.operation == "file-write-create")
        #expect(e.target == "/Users/x/Library/Application Support/a b.txt")
    }

    @Test func processNameWithSpacesAndParens() throws {
        let e = try #require(ReportParser.parse("Sandbox: Google Chrome Helper (Renderer)(1234) allow process-fork"))
        #expect(e.process == "Google Chrome Helper (Renderer)")
        #expect(e.pid == 1234)
        #expect(e.operation == "process-fork")
        #expect(e.target == "")
    }

    @Test func duplicateReportsCarryTheirCount() throws {
        let e = try #require(ReportParser.parse("317 duplicate reports for Sandbox: Messages(45083) deny(1) syscall-unix 186"))
        #expect(e.count == 317)
        #expect(e.process == "Messages")
        #expect(e.operation == "syscall-unix")
        #expect(e.target == "186")
        #expect(ReportParser.parse("1 duplicate report for Sandbox: a(1) allow sysctl-read kern.x")?.count == 1)
    }

    @Test func ignoresNonReports() {
        #expect(ReportParser.parse("Sandbox apply: sandbox-exec[83948] <bytes>") == nil)
        #expect(ReportParser.parse("networkd_settings_read_from_file Sandbox is preventing this process") == nil)
        #expect(ReportParser.parse("Sandbox: weird line without verdict") == nil)
    }

    @Test func onlyFirstLineCounts() throws {
        let e = try #require(ReportParser.parse("Sandbox: Messages(45083) deny(1) syscall-unix 186\nsyscall-unix-denied"))
        #expect(e.target == "186")
    }

    /// Real lines captured from VLC on macOS 27.0.1 (user name scrubbed).
    @Test func parsesEveryCapturedLine() throws {
        let url = try #require(Bundle.module.url(forResource: "vlc-report-lines", withExtension: "txt", subdirectory: "Fixtures"))
        let lines = try String(contentsOf: url, encoding: .utf8).split(separator: "\n").map(String.init)
        #expect(lines.count > 200)
        for line in lines {
            let event = ReportParser.parse(line)
            #expect(event != nil, "failed to parse: \(line)")
            if line.hasPrefix("Sandbox: VLC(") {
                #expect(event?.process == "VLC")
                #expect(event?.pid == 81047)
            }
        }
        let network = lines.compactMap(ReportParser.parse).first { $0.operation == "network-outbound" }
        #expect(network?.target == "remote:*:443")
    }
}
