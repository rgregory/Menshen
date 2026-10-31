import Foundation
import Testing
@testable import MenshenCore

extension KernelTests {
    /// The Restricted Sandbox, checked by the kernel. escapeprobe plays a dropped, unlearned app
    /// trying to reach things; a control run under `(allow default)` proves every step can succeed.
    @Suite final class RestrictedTests {
        let dir = "/private/tmp/menshen-restricted-\(UUID().uuidString)"
        let tag = UUID().uuidString.prefix(8)
        var cleanup: [String] = []
        var drives: [String] = []
        var home: String { dir + "/home" }
        deinit {
            for drive in drives { Swap.run("/usr/bin/hdiutil", ["detach", drive, "-force"]) }
            for path in cleanup + [dir] { try? FileManager.default.removeItem(atPath: path) }
        }

        func env(userTempRoot: String? = nil) -> MenshenEnvironment {
            MenshenEnvironment(home: home, dataRoot: URL(fileURLWithPath: dir + "/data"),
                               logsRoot: URL(fileURLWithPath: dir + "/logs"), userTempRoot: userTempRoot)
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

        /// The Darwin folder holds every app's caches: the app writes to the shared temp and its own
        /// cache folders, never another app's (ADR-007, as for learned profiles).
        @Test func darwinFolderGivesOnlyTheAppsOwnCaches() throws {
            let root = try #require(MenshenEnvironment.current().userTempRoot)
            let id = "com.example.menshen-test-\(tag)"
            let own = ["\(root)/C/\(id)", "\(root)/0/\(id)"]
            let other = "\(root)/C/com.example.other-\(tag)"
            let temp = "\(root)/T/menshen-test-\(tag)"
            for folder in own + [other, temp] {
                cleanup.append(folder)
                try FileManager.default.createDirectory(atPath: folder, withIntermediateDirectories: true)
            }
            var app = try ResolvedTarget.resolve("/bin/bash")
            app.identity.bundleId = id  // bash playing an app whose caches are named after its bundle ID
            let compiler = SBPLCompiler(environment: env(userTempRoot: root))
            let profile = compiler.restrictedProfile(app, RestrictedSandbox())
            func writes(_ folder: String, _ profile: String) -> Bool {
                Swap.run("/usr/bin/sandbox-exec", ["-p", profile, "/bin/bash", "-c", "echo x > '\(folder)/f'"]) == 0
            }

            #expect(writes(own[0], profile), "its own cache folder")
            #expect(writes(own[1], profile), "its own 0 folder")
            #expect(writes(temp, profile), "the shared temp folder")
            #expect(!writes(other, profile), "another app's caches stay closed")
            #expect(!writes(own[0], compiler.restrictedProfile(app, RestrictedSandbox(ownData: false))), "no own data, no caches")

            // Control: the whole Darwin folder, as the temp allow had it before.
            let narrow = "(subpath \"\(root)/T\")"
            try #require(profile.contains(narrow))
            #expect(writes(other, profile.replacingOccurrences(of: narrow, with: "(subpath \"\(root)\")")))
        }

        /// A real external drive: a small disk image, mounted under /Volumes like a USB stick.
        func mountDrive() throws -> String {
            let image = dir + "/drive.dmg", name = "MenshenTest-\(tag)"
            #expect(Swap.run("/usr/bin/hdiutil", ["create", "-quiet", "-size", "4m", "-fs", "HFS+", "-volname", name, image]) == 0)
            #expect(Swap.run("/usr/bin/hdiutil", ["attach", "-quiet", "-nobrowse", image]) == 0)
            let mount = "/Volumes/" + name
            try #require(FileManager.default.fileExists(atPath: mount))
            drives.append(mount)
            return mount
        }

        /// Reads limited to file types in home and on drives, and writes only to the run's own
        /// temp folder (the options Shentu offers). Every must-fail check has a must-succeed one
        /// in the same profile, and turning each option off makes its must-fail check succeed.
        @Test func fileTypesDrivesAndRunTemp() throws {
            _ = try setUp()
            let drive = try mountDrive()
            let fm = FileManager.default
            try fm.createDirectory(atPath: home + "/Movies", withIntermediateDirectories: true)
            for file in ["\(home)/Movies/clip.mp4", "\(drive)/clip.mp4", "\(drive)/notes.txt"] {
                try "x".write(toFile: file, atomically: true, encoding: .utf8)
            }
            let scratch = dir + "/run-temp"
            try fm.createDirectory(atPath: scratch, withIntermediateDirectories: true)
            let bash = try ResolvedTarget.resolve("/bin/bash")
            let compiler = SBPLCompiler(environment: env())
            let box = RestrictedSandbox(ownData: false, readFileTypes: FileCategory.media.extensions,
                                        limitDrives: true, ephemeralTemp: true)
            func profile(_ box: RestrictedSandbox) -> String { compiler.restrictedProfile(bash, box, scratch: scratch) }
            func ok(_ command: String, _ profile: String) -> Bool {
                Swap.run("/usr/bin/sandbox-exec", ["-p", profile, "/bin/bash", "-c", command]) == 0
            }
            func reads(_ file: String) -> String { "{ read -r l; [ \"$l\" = x ]; } < '\(file)'" }
            func writes(_ file: String) -> String { "echo x > '\(file)'" }
            let strict = profile(box)
            #expect(SBPLCompiler.validate(strict) == nil)

            // Must succeed: the chosen type in home and on the drive, and the run's temp folder.
            #expect(ok(reads("\(home)/Movies/clip.mp4"), strict), "a media file in home")
            #expect(ok(reads("\(drive)/clip.mp4"), strict), "a media file on the drive")
            #expect(ok(writes("\(scratch)/f"), strict), "the run's temp folder")
            // Must fail: other types, and writes anywhere else.
            #expect(!ok(reads("\(home)/Documents/private.txt"), strict), "another type in home")
            #expect(!ok(reads("\(drive)/notes.txt"), strict), "another type on the drive")
            #expect(!ok(writes("\(dir)/outside.txt"), strict), "the shared temp")
            #expect(!ok(writes("\(home)/Movies/new.mp4"), strict), "home, even a chosen type")
            #expect(!ok(writes("\(drive)/new.mp4"), strict), "the drive")
            // Folder listings (bash's glob, as /bin/ls is another program): needed to find the files.
            func lists(_ folder: String) -> String { "shopt -s nullglob; f=('\(folder)'/*); [ ${#f[@]} -gt 0 ]" }
            #expect(ok(lists(drive), strict), "folders on the drive are listable")
            #expect(ok(lists(home + "/Documents"), strict), "folders in home are listable")
            #expect(!ok(lists(home + "/Documents"), profile(RestrictedSandbox(ownData: false))), "not without file types")

            // Each option off: its must-fail check now succeeds (or its must-succeed one fails).
            var off = box
            off.limitDrives = false
            #expect(ok(reads("\(drive)/notes.txt"), profile(off)), "drives open without limitDrives")
            off = box
            off.ephemeralTemp = false
            #expect(ok(writes("\(dir)/outside.txt"), profile(off)), "shared temp open without ephemeralTemp")
            off = box
            off.readFileTypes = []
            #expect(!ok(reads("\(home)/Movies/clip.mp4"), profile(off)), "no types, no media in home")
        }

        /// Settings are written by cfprefsd, not the app, so the file-write deny can't stop them:
        /// with own data off, the preference write itself is denied.
        @Test func noOwnDataMeansNoSavedSettings() throws {
            try FileManager.default.createDirectory(atPath: dir + "/bin", withIntermediateDirectories: true)
            let probe = dir + "/bin/prefprobe"
            let source = try #require(Bundle.module.url(forResource: "prefprobe", withExtension: "c", subdirectory: "Fixtures"))
            #expect(Swap.run("/usr/bin/cc", ["-o", probe, source.path, "-framework", "CoreFoundation"]) == 0)
            let compiler = SBPLCompiler(environment: env())
            let target = try ResolvedTarget.resolve(probe)
            func saves(_ box: RestrictedSandbox) -> Bool {
                let domain = "com.example.menshen-pref-\(tag)-\(box.ownData)"
                defer {
                    Swap.run("/usr/bin/defaults", ["delete", domain])
                    try? FileManager.default.removeItem(atPath: NSHomeDirectory() + "/Library/Preferences/\(domain).plist")
                }
                let saved = Swap.run("/usr/bin/sandbox-exec", ["-p", compiler.restrictedProfile(target, box), probe, domain]) == 0
                return saved && Swap.run("/usr/bin/defaults", ["read", domain, "probe"]) == 0
            }
            #expect(!saves(RestrictedSandbox(ownData: false)), "own data off: nothing saved")
            #expect(saves(RestrictedSandbox(ownData: true)), "control: own data on saves settings")
        }

        @Test func oldSettingsStillLoad() throws {
            let old = #"{"network":true,"otherPrograms":false,"ownData":false,"readOnly":[],"readWrite":["~/Work"]}"#
            let box = try JSONDecoder().decode(RestrictedSandbox.self, from: Data(old.utf8))
            #expect(box == RestrictedSandbox(network: true, ownData: false, readWrite: ["~/Work"]))
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
}
