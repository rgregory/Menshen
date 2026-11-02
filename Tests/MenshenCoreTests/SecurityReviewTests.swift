import Foundation
import Testing
@testable import MenshenCore

/// Fixes from the 2026-11-02 security review: hardening re-allow order (H-1), Menshen's own
/// files (self-protection), and regex-literal filters checked on load (H-4).
@Suite struct SecurityReviewTests {
    let env = testEnvironment()

    func config(anchors: [String] = []) -> MenshenConfig {
        var c = Learn.build(target: fooTarget, events: [], environment: env)
        c.anchors += anchors
        c.hardening = Hardening(environment: env, ownAnchors: c.anchors.map(env.expand)).rules(hits: [:])
        return c
    }

    @Test func ownGroupContainerIsReallowedAfterTheDeny() throws {
        let text = SBPLCompiler(environment: env).compile(config(anchors: ["~/Library/Group Containers/TEAM123.group.foo"]))
        let lines = text.split(separator: "\n").map(String.init)
        let deny = try #require(lines.firstIndex { $0.contains("(subpath (home \"/Library/Group Containers\"))") })
        let allow = try #require(lines.firstIndex { $0.contains("(home \"/Library/Group Containers/TEAM123.group.foo\")") })
        #expect(lines[allow].hasPrefix("(allow file-read* file-write*"))
        #expect(deny < allow, "the re-allow must come after the deny it refines")
    }

    @Test func secretPatternsStayLastAndSwitchedOnPatternsStayFirst() throws {
        var c = config()
        let i = try #require(c.hardening.firstIndex { $0.id == "H-env-files" })
        c.hardening[i].action = .allow
        let lines = SBPLCompiler(environment: env).compile(c).split(separator: "\n").map(String.init)
        let ssh = try #require(lines.firstIndex { $0.contains("(subpath (home \"/.ssh\"))") })
        let envAllow = try #require(lines.firstIndex { $0.contains("\\.env") })
        let keyDeny = try #require(lines.firstIndex { $0.contains("pem|key") })
        #expect(envAllow < ssh, "a switched-on pattern can't open files inside a protected folder")
        #expect(ssh < keyDeny, "pattern denies win over folder allows")
    }

    @Test func menshenFilesAreDeniedLastAndAlways() throws {
        var c = config()
        let data = realPath("/tmp/menshen-unit")
        c.rules.append(Rule(action: .allow, operations: ["file-read*", "file-write*"],
                            filter: Filter(.subpath, data), source: .custom))
        let text = SBPLCompiler(environment: env).compile(c)
        let deny = try #require(text.range(of: "(deny file-read* file-write* (subpath \"\(data)\"))"))
        let custom = try #require(text.range(of: "(subpath \"\(data)\")"))
        #expect(custom.lowerBound < deny.lowerBound, "nothing in the config comes after it")
        #expect(!c.hardening.contains { $0.filter.value?.contains("menshen-unit") == true }, "not stored in the config")
    }

    @Test func tempOnlyKeepsItsPrivateTemp() {
        var c = config()
        c.profiles = [.tempOnly]
        let text = SBPLCompiler(environment: env).compile(c)
        #expect(text.contains("(allow file-read* file-write* (subpath \"\(realPath("/tmp/menshen-unit"))/temp/com.example.foo\"))"))
    }

    @Test func dataRootHoldingHomeIsNotDenied() {
        let e = MenshenEnvironment(home: "/tmp/x/home", dataRoot: URL(fileURLWithPath: "/tmp/x"),
                                   logsRoot: URL(fileURLWithPath: "/tmp/x"), userTempRoot: nil)
        let c = Learn.build(target: fooTarget, events: [], environment: e)
        #expect(SBPLCompiler(environment: e).selfProtection(c).isEmpty)
    }

    // MARK: Regex filters on load

    func roundTrip(_ edit: (inout MenshenConfig) -> Void) throws -> MenshenConfig {
        var c = config()
        edit(&c)
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("menshen-load-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        try c.write(to: url)
        return try MenshenConfig.load(url)
    }

    @Test(arguments: [".*", "9)\" (subpath \"/", "mp4|.*", "p.df", "", "mp4,"])
    func badFileTypesAreRefusedOnLoad(_ value: String) {
        #expect(throws: MenshenError.self) {
            _ = try roundTrip { $0.rules.append(Rule(action: .allow, operations: ["file-read*"],
                                                     filter: Filter(.fileTypes, value), source: .custom)) }
        }
        #expect(SBPLCompiler(environment: env).filterText(Filter(.fileTypes, value)) == SBPLCompiler.matchesNothing)
    }

    @Test func goodFileTypesLoad() throws {
        let c = try roundTrip { $0.addCustom(.read, fileTypes: ["mp4", "mkv"]) }
        #expect(c.rules.contains { $0.filter == Filter(.fileTypes, "mp4,mkv") })
    }

    @Test func unknownNamePatternIsRefused() {
        #expect(throws: MenshenError.self) {
            _ = try roundTrip { $0.rules.append(Rule(action: .allow, operations: ["file-read*"],
                                                     filter: Filter(.homePattern, ".*"), source: .custom)) }
        }
    }

    @Test func olderBuiltInPatternIsUpdated() throws {
        let c = try roundTrip { c in
            let i = c.hardening.firstIndex { $0.id == "H-key-files" }!
            c.hardening[i].filter.value = #"\.(pem|key)$"#
        }
        let current = Hardening.entries.first { $0.id == "H-key-files" }!.pattern
        #expect(c.hardening.first { $0.id == "H-key-files" }?.filter.value == current)
    }
}

/// The same fixes against the real kernel.
@Suite final class SecurityReviewKernelTests {
    let dir = realPath("/private/tmp") + "/menshen-sr-\(UUID().uuidString)"
    deinit { try? FileManager.default.removeItem(atPath: dir) }

    func run(_ args: [String], _ profile: String) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
        p.arguments = ["-p", profile] + args
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try? p.run()
        p.waitUntilExit()
        return p.terminationStatus
    }

    func write(_ path: String) throws {
        try FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try "x".write(toFile: path, atomically: true, encoding: .utf8)
    }

    @Test func ownGroupContainerReadableOthersNot() throws {
        let home = dir + "/home"
        let mine = home + "/Library/Group Containers/TEAM.group.mine/data"
        let theirs = home + "/Library/Group Containers/OTHER.group.theirs/data"
        try write(mine); try write(theirs)
        let env = MenshenEnvironment(home: home, dataRoot: URL(fileURLWithPath: dir + "/data"),
                                     logsRoot: URL(fileURLWithPath: dir + "/logs"), userTempRoot: nil)
        var config = Learn.build(target: try ResolvedTarget.resolve("/bin/cat"), events: [], environment: env)
        config.anchors.append("~/Library/Group Containers/TEAM.group.mine")
        config.rules.append(Rule(action: .allow, operations: ["file-read*"], filter: Filter(.subpath, "~"), source: .learned))
        config.hardening = Hardening(environment: env, ownAnchors: config.anchors.map(env.expand)).rules(hits: [:])
        let profile = SBPLCompiler(environment: env).compile(config)
        #expect(SBPLCompiler.validate(profile) == nil)
        #expect(run(["/bin/cat", mine], profile) == 0, "the app's own group container")
        #expect(run(["/bin/cat", theirs], profile) != 0, "another app's group container")
    }

    @Test func menshenDataUnreachableEvenWhenAllowed() throws {
        let home = dir + "/home"
        let data = dir + "/data"
        try write(home + "/file")
        try write(data + "/profiles/x.json")
        try write(dir + "/logs/x/run.jsonl")
        let env = MenshenEnvironment(home: home, dataRoot: URL(fileURLWithPath: data),
                                     logsRoot: URL(fileURLWithPath: dir + "/logs"), userTempRoot: nil)
        var config = Learn.build(target: try ResolvedTarget.resolve("/bin/cat"), events: [], environment: env)
        config.rules.append(Rule(action: .allow, operations: ["file-read*", "file-write*"],
                                 filter: Filter(.subpath, dir), source: .custom))
        let profile = SBPLCompiler(environment: env).compile(config)
        #expect(SBPLCompiler.validate(profile) == nil)
        #expect(run(["/bin/cat", home + "/file"], profile) == 0, "control: the allow works elsewhere")
        #expect(run(["/bin/cat", data + "/profiles/x.json"], profile) != 0, "config not readable")
        #expect(run(["/bin/cat", dir + "/logs/x/run.jsonl"], profile) != 0, "logs not readable")
        let tee = profile + "\n(allow process-exec* file-read* file-map-executable (literal \"/usr/bin/tee\"))\n"
        #expect(run(["/usr/bin/tee", home + "/out"], tee) == 0, "control: writing elsewhere works")
        #expect(run(["/usr/bin/tee", data + "/profiles/x.json"], tee) != 0, "config not writable")
        #expect(run(["/usr/bin/tee", data + "/profiles/new.json"], tee) != 0, "no new files in the data folder")
    }
}

/// H-2: an app named "Google Earth" owns its folder inside "Google", never all of "Google".
@Suite struct VendorFolderTests {
    let env = testEnvironment()
    let earth = ResolvedTarget(
        identity: TargetIdentity(path: "/Applications/Google Earth.app",
                                 executable: "/Applications/Google Earth.app/Contents/MacOS/Google Earth",
                                 name: "Google Earth", bundleId: "com.google.GoogleEarthPro", teamId: "EQHXZ8M8AV",
                                 signingId: "com.google.GoogleEarthPro", cdhash: "abcd"),
        bundlePath: "/Applications/Google Earth.app", isAppleSigned: false, hasAppSandbox: false)
    var support: String { testHome + "/Library/Application Support" }

    func build(_ events: [SandboxEvent]) -> MenshenConfig {
        Learn.build(target: earth, events: events, environment: env)
    }

    @Test func touchingChromeDoesNotOwnTheVendorFolder() {
        let c = build([allow("file-read-data", support + "/Google/Chrome/Default/Cookies")])
        #expect(!c.anchors.contains("~/Library/Application Support/Google"))
        #expect(!c.anchors.contains { $0.hasPrefix("~/Library/Application Support/Google/Chrome") })
        #expect(c.hardening.first { $0.id == "H-chrome" }?.flagged == true, "Chrome access is flagged, not own data")
    }

    @Test(arguments: ["Earth", "Google Earth", "com.google.GoogleEarthPro"])
    func ownFolderInsideTheVendorIsOwned(_ folder: String) {
        let c = build([allow("file-write-data", support + "/Google/\(folder)/db.sqlite")])
        #expect(c.anchors == c.anchors.filter { !$0.hasSuffix("/Google") })
        #expect(c.anchors.contains("~/Library/Application Support/Google/\(folder)"))
    }

    @Test func siblingProductIsNotOwned() {
        let c = build([allow("file-write-data", support + "/Google/Drive/x")])
        #expect(!c.anchors.contains { $0.contains("Application Support/Google") })
    }

    @Test func groupContainerWithoutTeamPrefix() {
        let c = build([allow("file-read-data", testHome + "/Library/Group Containers/group.com.google.GoogleEarthPro/x")])
        #expect(c.anchors.contains("~/Library/Group Containers/group.com.google.GoogleEarthPro"))
    }
}

/// M-1: runs that start in the same second get separate logs.
@Suite struct LogFileTests {
    @Test func sameSecondRunsGetTheirOwnLog() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("menshen-log-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let (a, urlA) = try NDJSONWriter.create(in: dir, stem: "20261102-130000", ext: "jsonl")
        let (b, urlB) = try NDJSONWriter.create(in: dir, stem: "20261102-130000", ext: "jsonl")
        a.write(["run": "a", "line": "first and longer"])
        b.write(["run": "b"])
        a.close(); b.close()
        #expect(urlA.lastPathComponent == "20261102-130000.jsonl")
        #expect(urlB.lastPathComponent == "20261102-130000-2.jsonl")
        #expect(try String(contentsOf: urlA, encoding: .utf8).contains("\"a\""))
        #expect(!(try String(contentsOf: urlA, encoding: .utf8).contains("\"b\"")))
        #expect(Library.date(of: urlB) == Library.date(of: urlA), "the suffix doesn't hide the run's time")
    }

    @Test func unreadableConfigsAreReported() throws {
        let root = NSTemporaryDirectory() + "menshen-unread-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: root) }
        let env = testEnvironment(data: root)
        var c = Learn.build(target: fooTarget, events: [], environment: env)
        c.rules.append(Rule(action: .allow, operations: ["file-read*"], filter: Filter(.fileTypes, ".*"), source: .custom))
        try c.write(to: env.configURL(c.target.key))
        #expect(Library.apps(env).isEmpty)
        #expect(Library.unreadableConfigs(env).count == 1)
    }
}

/// M-2 (key squatting), capture paths, and the smaller review items.
@Suite struct RemainingReviewTests {
    let env = testEnvironment()
    let url = URL(fileURLWithPath: "/tmp/x.json")

    func identity(path: String, team: String?) -> TargetIdentity {
        TargetIdentity(path: path, executable: path + "/Contents/MacOS/Foo", name: "Foo", bundleId: "com.example.foo",
                       teamId: team, signingId: "com.example.foo", cdhash: "abcd")
    }

    @Test func differentTeamSameIDIsRefused() {
        #expect(throws: MenshenError.self) {
            try Learn.checkSameApp(identity(path: "/Applications/Foo.app", team: "TEAM123"),
                                   identity(path: "/Applications/Foo.app", team: "EVIL"),
                                   normalPath: "/Applications/Foo.app", configURL: url)
        }
    }

    @Test func otherAppStillPresentIsRefused() {
        // "/bin" exists, so the stored app is "still there".
        #expect(throws: MenshenError.self) {
            try Learn.checkSameApp(identity(path: "/bin", team: nil), identity(path: "/tmp/Squatter.app", team: nil),
                                   normalPath: "/tmp/Squatter.app", configURL: url)
        }
    }

    @Test func sameAppOrMovedAppIsFine() throws {
        try Learn.checkSameApp(identity(path: "/Applications/Foo.app", team: "TEAM123"),
                               identity(path: "/Applications/Foo.app", team: "TEAM123"),
                               normalPath: "/Applications/Foo.app", configURL: url)
        try Learn.checkSameApp(identity(path: "/Applications/Gone-\(UUID()).app", team: "TEAM123"),
                               identity(path: "/Applications/Foo.app", team: "TEAM123"),
                               normalPath: "/Applications/Foo.app", configURL: url)
        // Replaced: the stored path is the launcher's, the app runs from the hidden original.
        try Learn.checkSameApp(identity(path: "/bin", team: nil), identity(path: "/.bin.menshen.app", team: nil),
                               normalPath: "/bin", configURL: url)
    }


    @Test func photosLibrariesAnywhereAreProtected() {
        let h = Hardening(environment: env, ownAnchors: [])
        #expect(h.entry(for: testHome + "/Pictures/Trip.photoslibrary/database/Photos.sqlite", isWrite: false)?.id == "H-photos-libraries")
        #expect(h.entry(for: testHome + "/Pictures/notes.photoslibrary.txt", isWrite: false) == nil)
    }

    @Test func networkRulesSayAnyHost() {
        let rule = Rule(action: .allow, operations: ["network-outbound"], filter: Filter(.remote, "*:443"), source: .learned)
        #expect(RuleText.describe(rule) == "Connect out to port 443 (HTTPS), any host")
        let local = Rule(action: .allow, operations: ["network-outbound"], filter: Filter(.remote, "localhost:8080"), source: .learned)
        #expect(RuleText.describe(local) == "Connect out to port 8080 (HTTP alt) on this Mac")
    }

    @Test func sharedTempIsNotShownAsOwnData() {
        let config = Learn.build(target: fooTarget, events: [
            allow("file-write-data", "/private/var/folders/aa/bb/T/tmp123"),
        ], environment: env)
        let s = AccessSummary.make(config, environment: env)
        #expect(s.files.contains { $0.title == "Shared temp folder" })
        #expect(!s.files.contains { $0.title == "Its own data" && $0.detail.contains("$DARWIN/T") })
    }
}
