import Foundation
import Testing
@testable import MenshenCore

/// The Restricted Sandbox, checked by the kernel. escapeprobe plays a dropped, unlearned app
/// trying to reach things; a control run under `(allow default)` proves every step can succeed.
@Suite final class RestrictedTests {
    let dir = "/private/tmp/menshen-restricted-\(UUID().uuidString)"
    var home: String { dir + "/home" }
    deinit { try? FileManager.default.removeItem(atPath: dir) }

    func env() -> MenshenEnvironment {
        MenshenEnvironment(home: home, dataRoot: URL(fileURLWithPath: dir + "/data"),
                           logsRoot: URL(fileURLWithPath: dir + "/logs"), userTempRoot: nil)
    }

    /// Builds the probe and a home with a work folder (read & write), a reference folder
    /// (read only), a private document and a .env inside the work folder.
    func setUp() throws -> String {
        let fm = FileManager.default
        for d in ["/bin", "/home/Work", "/home/Reference", "/home/Documents"] {
            try fm.createDirectory(atPath: dir + d, withIntermediateDirectories: true)
        }
        for f in ["Reference/book.pdf", "Documents/private.txt", "Work/.env", "Work/notes.txt"] {
            try "x".write(toFile: "\(home)/\(f)", atomically: true, encoding: .utf8)
        }
        let probe = dir + "/bin/escapeprobe"
        let source = try #require(Bundle.module.url(forResource: "escapeprobe", withExtension: "c", subdirectory: "Fixtures"))
        #expect(Swap.run("/usr/bin/cc", ["-o", probe, source.path]) == 0)
        return probe
    }

    func run(_ profile: String, _ probe: String, _ args: [String]) throws -> [String: Bool] {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
        p.arguments = ["-p", profile, probe] + args
        let out = Pipe()
        p.standardOutput = out
        try p.run()
        p.waitUntilExit()
        var result: [String: Bool] = [:]
        for line in String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self).split(separator: "\n") {
            let parts = line.split(separator: " ")
            result[String(parts[0])] = parts[1] == "ok"
        }
        return result
    }

    /// A listening socket on localhost; returns (fd, port).
    func listener() -> (Int32, String) {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        var addr = sockaddr_in(sin_len: UInt8(MemoryLayout<sockaddr_in>.size), sin_family: sa_family_t(AF_INET),
                               sin_port: 0, sin_addr: in_addr(s_addr: inet_addr("127.0.0.1")), sin_zero: (0, 0, 0, 0, 0, 0, 0, 0))
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) } }
        listen(fd, 4)
        _ = withUnsafeMutablePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        return (fd, String(UInt16(bigEndian: addr.sin_port)))
    }

    @Test func onlyWhatYouChose() throws {
        let probe = try setUp()
        let (fd, port) = listener()
        defer { close(fd) }
        // escapeprobe <document> <box-folder> <secret-in-home> <outside-file> <port>
        let args = ["\(home)/Reference/book.pdf", "\(home)/Work", "\(home)/Documents/private.txt",
                    "\(home)/Documents/dropped.txt", port]
        let control = try run("(version 1)(allow default)", probe, args)
        #expect(control.count == 7 && control.values.allSatisfy { $0 }, "control: every step works unsandboxed \(control)")
        try FileManager.default.removeItem(atPath: "\(home)/Documents/dropped.txt")

        let box = RestrictedSandbox(readWrite: ["~/Work"], readOnly: ["~/Reference"])
        let profile = SBPLCompiler(environment: env()).restrictedProfile(try ResolvedTarget.resolve(probe), box)
        #expect(SBPLCompiler.validate(profile) == nil)
        let r = try run(profile, probe, args)
        #expect(r["read-document"] == true, "read-only folder is readable")
        #expect(r["write-box"] == true, "read & write folder is writable")
        #expect(r["read-home"] == false, "the rest of home is not readable")
        #expect(r["write-outside"] == false, "nor writable")
        #expect(r["connect"] == false, "no network")
        #expect(r["exec"] == false, "no other programs")

        // Same settings with bash as the app, for checks the probe doesn't make. Not /bin/sh: it's
        // a shim that starts bash, which "no other programs" blocks, so every check would fail.
        let shProfile = SBPLCompiler(environment: env()).restrictedProfile(try ResolvedTarget.resolve("/bin/bash"), box)
        func boxedSh(_ command: String) -> Int32 {
            Swap.run("/usr/bin/sandbox-exec", ["-p", shProfile, "/bin/bash", "-c", command])
        }
        let scratch = "/private/tmp/menshen-restricted-ok-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: scratch) }
        #expect(boxedSh("echo x > \(scratch) && { read -r l; [ \"$l\" = x ]; } < '\(home)/Work/notes.txt'") == 0,
                "control: the shell runs, writes temp and reads a folder you chose")
        #expect(boxedSh("echo x > '\(home)/Reference/new.txt'") != 0, "read-only folder is not writable")
        #expect(boxedSh("{ read -r l; [ \"$l\" = x ]; } < '\(home)/Work/.env'") != 0, "secrets stay blocked inside a folder you chose")
    }

    @Test func togglesOpenWhatTheySay() throws {
        let probe = try setUp()
        let (fd, port) = listener()
        defer { close(fd) }
        let args = ["\(home)/Reference/book.pdf", "\(home)/Work", "\(home)/Documents/private.txt",
                    "\(home)/Documents/dropped.txt", port]
        let box = RestrictedSandbox(network: true, otherPrograms: true, readWrite: ["~/Work"])
        let profile = SBPLCompiler(environment: env()).restrictedProfile(try ResolvedTarget.resolve(probe), box)
        let r = try run(profile, probe, args)
        #expect(r["connect"] == true)
        #expect(r["exec"] == true)
        #expect(r["read-home"] == false, "home stays closed")
    }

    /// The real path (log tap, launch, drain): what the app was blocked from ends up in the log.
    @Test func blockedAttemptsAreLogged() throws {
        let probe = try setUp()
        let (fd, port) = listener()
        defer { close(fd) }
        var options = EnforceOptions(target: probe)
        options.arguments = ["\(home)/Reference/book.pdf", "\(home)/Work", "\(home)/Documents/private.txt",
                             "\(home)/Documents/dropped.txt", port, "3"]
        let box = RestrictedSandbox(readWrite: ["~/Work"], readOnly: ["~/Reference"])
        // Each blocked step is tried 3 times: the kernel drops some reports under load (finding
        // 25), so a single attempt makes this test about the kernel, not about Menshen.
        let summary = try Enforce.runRestricted(options, sandbox: box, environment: env())
        let denied = Library.records(summary.logURL).filter { $0.verdict == .deny }
        let detail = "status \(summary.outcome.status) drained \(summary.drained) notices \(summary.streamNotices) records \(Library.records(summary.logURL).count)"
        #expect(denied.contains { $0.target.hasSuffix("/Documents/private.txt") }, "\(denied.map(\.target)) \(detail)")
        #expect(denied.contains { $0.operation.hasPrefix("network-outbound") })
        #expect(denied.contains { $0.operation.hasPrefix("process-exec") })
    }

    @Test func settingsRoundTrip() throws {
        let box = RestrictedSandbox(network: true, readWrite: ["~/Work"], readOnly: ["~/Music"])
        try box.save(env())
        #expect(RestrictedSandbox.load(env()) == box)
        #expect(RestrictedSandbox.load(MenshenEnvironment(home: home, dataRoot: URL(fileURLWithPath: dir + "/none"),
                                                          logsRoot: URL(fileURLWithPath: dir), userTempRoot: nil))
                == RestrictedSandbox(), "strict defaults when nothing is saved")
    }
}
