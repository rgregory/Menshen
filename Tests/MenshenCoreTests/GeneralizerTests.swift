import Foundation
import Testing
@testable import MenshenCore

let testHome = "/Users/test"

func testEnvironment(home: String = testHome, data: String = "/tmp/menshen-unit") -> MenshenEnvironment {
    MenshenEnvironment(home: home, dataRoot: URL(fileURLWithPath: data),
                       logsRoot: URL(fileURLWithPath: data + "/logs"), userTempRoot: "/private/var/folders/aa/bb")
}

let fooTarget = ResolvedTarget(
    identity: TargetIdentity(path: "/Applications/Foo.app", executable: "/Applications/Foo.app/Contents/MacOS/Foo",
                             name: "Foo", bundleId: "com.example.foo", teamId: "TEAM123",
                             signingId: "com.example.foo", cdhash: "abcd"),
    bundlePath: "/Applications/Foo.app", isAppleSigned: false, hasAppSandbox: false)

func allow(_ op: String, _ target: String, count: Int = 1) -> SandboxEvent {
    SandboxEvent(process: "Foo", pid: 42, verdict: .allow, operation: op, target: target, count: count)
}

@Suite struct GeneralizerTests {
    let env = testEnvironment()

    func build(_ events: [SandboxEvent]) -> MenshenConfig {
        Learn.build(target: fooTarget, events: events, environment: env)
    }

    func learned(_ config: MenshenConfig, _ op: String, _ kind: FilterKind, _ value: String) -> Rule? {
        config.rules.first { $0.operations == [op] && $0.filter == Filter(kind, value) }
    }

    @Test func bundleAndOwnLibraryFoldersBecomeAnchors() throws {
        let c = build([
            allow("file-read-data", "/Applications/Foo.app/Contents/Resources/a.png"),
            allow("file-read-data", "/Applications/Foo.app/Contents/Info.plist"),
            allow("file-write-create", "\(testHome)/Library/Application Support/Foo/db.sqlite"),
            allow("file-write-data", "\(testHome)/Library/Caches/com.example.foo/x"),
            allow("file-write-data", "/private/var/folders/aa/bb/T/tmp123"),
        ])
        #expect(learned(c, "file-read*", .subpath, "/Applications/Foo.app")?.seen == 2)
        #expect(!c.rules.contains { $0.operations.contains("file-write*") && $0.filter.value == "/Applications/Foo.app" },
                "the bundle is never writable")
        let support = try #require(ownFolder(c, "~/Library/Application Support/Foo"))
        #expect(support.category == nil, "writes to the app's own folders are not 'outside'")
        #expect(support.seen == 1)
        #expect(ownFolder(c, "~/Library/Caches/com.example.foo") != nil)
        #expect(ownFolder(c, "/private/var/folders/aa/bb/T") != nil)
        #expect(c.anchors.contains("~/Library/Application Support/Foo"))
    }

    /// The Darwin folder holds every app's caches: the app owns the shared temp and only its own
    /// folders in C and 0. Writes to another app's caches are learned exactly and reported.
    @Test func darwinFolderOwnsOnlyTempAndTheAppsCaches() throws {
        let c = build([
            allow("file-write-data", "/private/var/folders/aa/bb/C/com.example.foo/com.apple.metal/x"),
            allow("file-read-data", "/private/var/folders/aa/bb/0/com.example.foo/y"),
            allow("file-write-data", "/private/var/folders/aa/bb/C/com.other.app/z"),
        ])
        #expect(ownFolder(c, "/private/var/folders/aa/bb/C/com.example.foo")?.seen == 1)
        #expect(ownFolder(c, "/private/var/folders/aa/bb/0/com.example.foo") != nil)
        #expect(ownFolder(c, "/private/var/folders/aa/bb") == nil, "not the whole Darwin folder")
        #expect(!c.anchors.contains("/private/var/folders/aa/bb"))
        let other = try #require(learned(c, "file-write*", .literal, "/private/var/folders/aa/bb/C/com.other.app/z"))
        #expect(other.category == .writeOutside)
    }

    @Test func registrationsSharedMemoryAndSysctlWritesKeepTheirNames() {
        let c = build([
            allow("mach-register", "com.apple.axserver (per-pid)"),
            allow("mach-register", "com.example.foo.helper"),
            allow("ipc-posix-shm-write-create", "com.apple.AppleDatabaseChanged"),
            allow("ipc-posix-sem-open", "foo.lock"),
            allow("sysctl-write", "kern.tcsm_enable"),
        ])
        #expect(learned(c, "mach-register", .localName, "com.apple.axserver") != nil)
        #expect(learned(c, "mach-register", .globalName, "com.example.foo.helper") != nil)
        #expect(learned(c, "ipc-posix-shm-write-create", .ipcPosixName, "com.apple.AppleDatabaseChanged") != nil)
        #expect(learned(c, "ipc-posix-sem-open", .ipcPosixName, "foo.lock") != nil)
        #expect(learned(c, "sysctl-write", .sysctlName, "kern.tcsm_enable") != nil)
        #expect(!c.rules.contains { $0.filter == .any && $0.operations.contains { $0 == "mach-register" || $0 == "sysctl-write" || $0.hasPrefix("ipc-posix") } })
        let profile = SBPLCompiler(environment: env).compile(c)
        #expect(profile.contains("(ipc-posix-name \"com.apple.AppleDatabaseChanged\")"))
        #expect(profile.contains("(sysctl-name \"kern.tcsm_enable\")"))
        #expect(profile.contains("(global-name \"com.example.foo.helper\")"))
        #expect(!profile.contains("com.apple.axserver"), "per-pid registrations are already allowed by system.sb")
    }

    func ownFolder(_ c: MenshenConfig, _ path: String) -> Rule? {
        c.rules.first { $0.operations == ["file-read*", "file-write*"] && $0.filter == Filter(.subpath, path) }
    }

    /// Apps often write state only at quit, when the kernel drops reports, so an own folder
    /// that was only read during learning must still be writable.
    @Test func ownFoldersAreFullyWritableEvenIfOnlyRead() throws {
        let c = build([allow("file-read-data", "\(testHome)/Library/Preferences/com.example.foo/rc")])
        let rule = try #require(ownFolder(c, "~/Library/Preferences/com.example.foo"))
        #expect(rule.seen == 1)
        #expect(ownFolder(c, "/private/var/folders/aa/bb/T")?.seen == 0, "the shared temp folder is always owned")
    }

    @Test func sensitiveAccessIsFlaggedAndNotLearned() throws {
        let c = build([
            allow("file-read-data", "\(testHome)/.ssh/id_rsa"),
            allow("file-write-create", "\(testHome)/Library/LaunchAgents/com.evil.plist"),
            allow("file-read-data", "\(testHome)/Library/LaunchAgents/com.other.plist"),
            allow("appleevent-send", "com.apple.finder"),
            allow("process-exec*", "/usr/bin/osascript"),
        ])
        let ssh = try #require(c.hardening.first { $0.id == "H-ssh" })
        #expect(ssh.action == .deny)
        #expect(ssh.flagged == true)
        #expect(ssh.note?.contains("~/.ssh/id_rsa") == true)
        #expect(c.hardening.first { $0.id == "H-user-launchagents" }?.flagged == true)
        #expect(c.hardening.first { $0.id == "H-apple-events" }?.flagged == true)
        #expect(c.hardening.first { $0.id == "H-osascript" }?.flagged == true)
        #expect(c.hardening.first { $0.id == "H-aws" }?.flagged == nil, "untouched entries are not flagged")
        // Nothing sensitive leaks into learned allows; reading a launch agent is not sensitive.
        #expect(!c.rules.contains { ($0.filter.value ?? "").contains(".ssh") })
        #expect(!c.rules.contains { ($0.filter.value ?? "").contains("com.evil") })
        #expect(learned(c, "file-read*", .literal, "~/Library/LaunchAgents/com.other.plist") != nil)
        #expect(!c.rules.contains { $0.operations == ["process-exec*"] && $0.filter.value == "/usr/bin/osascript" })
    }

    @Test func ownGroupContainerIsReallowedAfterTheDeny() throws {
        let c = build([allow("file-write-data", "\(testHome)/Library/Group Containers/TEAM123.shared/data")])
        let ids = c.hardening.map(\.id)
        let deny = try #require(ids.firstIndex(of: "H-group-containers"))
        let own = try #require(c.hardening.firstIndex { $0.action == .allow && $0.filter.value == "~/Library/Group Containers/TEAM123.shared" })
        #expect(own > deny, "the re-allow must come after the deny so it wins")
        #expect(c.hardening[deny].flagged == nil)
    }

    @Test func browsersKeepTheirOwnProfile() throws {
        var chrome = fooTarget
        chrome.identity.name = "Google Chrome"
        chrome.identity.bundleId = "com.google.Chrome"
        let c = Learn.build(target: chrome, events: [
            allow("file-read-data", "\(testHome)/Library/Application Support/Google/Chrome/Default/Cookies"),
        ], environment: env)
        let rule = try #require(c.hardening.first { $0.id == "H-chrome" })
        #expect(rule.action == .allow)
        #expect(c.hardening.first { $0.id == "H-firefox" }?.action == .deny)
    }

    @Test func namedResourcesStayExact() {
        let c = build([
            allow("mach-lookup", "com.apple.windowserver.active"),
            allow("mach-lookup", "com.apple.coredrag (per-pid)"),
            allow("mach-lookup", "com.example.renderer (xpc)"),
            allow("user-preference-read", "com.apple.hitoolbox"),
            allow("iokit-open-user-client", "IOSurfaceRootUserClient"),
            allow("network-outbound", "remote:*:443"),
            allow("network-outbound", "/private/var/run/mDNSResponder"),
            allow("network-bind", "local:*:8080"),
            allow("sysctl-read", "kern.osproductversion", count: 7),
        ])
        #expect(learned(c, "mach-lookup", .globalName, "com.apple.windowserver.active") != nil)
        #expect(learned(c, "mach-lookup", .localName, "com.apple.coredrag") != nil)
        #expect(learned(c, "mach-lookup", .xpcServiceName, "com.example.renderer") != nil, "(xpc) lookups are XPC services")
        #expect(learned(c, "user-preference-read", .preferenceDomain, "com.apple.hitoolbox") != nil)
        #expect(learned(c, "iokit-open-user-client", .iokitUserClientClass, "IOSurfaceRootUserClient") != nil)
        #expect(learned(c, "network-outbound", .remote, "*:443")?.category == .network)
        #expect(learned(c, "network-outbound", .literal, "/private/var/run/mDNSResponder")?.category == nil)
        #expect(learned(c, "network-bind", .local, "*:8080")?.category == .network)
        #expect(c.rules.first { $0.operations == ["sysctl-read"] }?.filter == .any)
        #expect(c.rules.first { $0.operations == ["sysctl-read"] }?.seen == 7)
    }

    @Test func manyFilesInOneFolderCollapse() {
        let events = (1...5).map { allow("file-write-create", "\(testHome)/Projects/out/file\($0).txt") }
            + [allow("file-write-create", "\(testHome)/notes.txt")]
        let c = build(events)
        let folder = learned(c, "file-write*", .subpath, "~/Projects/out")
        #expect(folder?.seen == 5)
        #expect(folder?.category == .writeOutside)
        #expect(learned(c, "file-write*", .literal, "~/notes.txt") != nil, "a single file in ~ stays literal")
        #expect(!c.rules.contains { $0.filter.kind == .subpath && $0.filter.value == "~" })
    }

    @Test func systemReadsCollapseButSystemWritesDoNot() {
        let c = build([
            allow("file-read-data", "/usr/lib/libfoo.dylib"),
            allow("file-read-data", "/System/Library/Fonts/A.ttf"),
            allow("file-write-data", "/Library/Application Support/Foo Shared/state"),
            allow("file-write-data", "/dev/null"),
        ])
        #expect(learned(c, "file-read*", .subpath, "/usr") != nil)
        #expect(learned(c, "file-read*", .subpath, "/System") != nil)
        #expect(learned(c, "file-write*", .literal, "/Library/Application Support/Foo Shared/state")?.category == .writeOutside)
        #expect(learned(c, "file-write*", .literal, "/dev/null")?.category == nil)
    }

    @Test func targetPathForms() {
        #expect(Generalizer.path(from: "/a b/c") == "/a b/c")
        #expect(Generalizer.path(from: "path:/a b/c xattr:com.apple.decmpfs") == "/a b/c")
        #expect(Generalizer.path(from: "path:/dev/dtracehelper ioctl-command:(_IO \"h\" 4)") == "/dev/dtracehelper")
        #expect(Generalizer.path(from: "target:/Applications/VLC.app extension-class:com.apple.app-sandbox.read") == "/Applications/VLC.app")
        #expect(Generalizer.path(from: "com.apple.foo") == nil)
    }

    @Test func ruleIDsAreStable() {
        let events = [allow("file-read-data", "/usr/lib/a"), allow("mach-lookup", "com.apple.x")]
        #expect(build(events).rules.map(\.id) == build(events).rules.map(\.id))
        #expect(Set(build(events).rules.map(\.id)).count == build(events).rules.count, "no ID collisions")
    }

    @Test func learnModeDenialsBecomeAWarningNotRules() {
        let denied = SandboxEvent(process: "Foo", pid: 42, verdict: .deny, operation: "file-read-data", target: "/x")
        let c = build([denied])
        #expect(!c.rules.contains { $0.filter.value == "/x" })
        #expect(c.rules.allSatisfy { $0.seen == 0 }, "only the always-owned temp folder, nothing learned")
        #expect(c.learning.warnings.contains { $0.contains("denied even in learn mode") })
    }
}
