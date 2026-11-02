import Foundation
import Testing
@testable import MenshenCore

/// A throwaway "Applications" folder with a signed dummy app, so swap tests never touch real apps.
struct DummyApps {
    let root: String
    let apps: String
    let app: String
    let env: MenshenEnvironment
    let bundleId = "dev.menshen.test.dummy"

    init() throws {
        root = "/private/tmp/menshen-swap-\(UUID().uuidString)"
        apps = root + "/Applications"
        app = apps + "/Dummy.app"
        let fm = FileManager.default
        try fm.createDirectory(atPath: app + "/Contents/MacOS", withIntermediateDirectories: true)
        try fm.createDirectory(atPath: app + "/Contents/Resources", withIntermediateDirectories: true)
        try Data("icon".utf8).write(to: URL(fileURLWithPath: app + "/Contents/Resources/Dummy.icns"))
        let info: [String: Any] = [
            "CFBundleIdentifier": bundleId, "CFBundleExecutable": "Dummy", "CFBundleName": "Dummy",
            "CFBundlePackageType": "APPL", "CFBundleIconFile": "Dummy", "CFBundleShortVersionString": "1.0",
            "CFBundleDocumentTypes": [["CFBundleTypeName": "Text", "CFBundleTypeRole": "Viewer",
                                       "LSItemContentTypes": ["public.plain-text"]]],
        ]
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
            .write(to: URL(fileURLWithPath: app + "/Contents/Info.plist"))
        let source = try #require(Bundle.module.url(forResource: "dummyapp", withExtension: "c", subdirectory: "Fixtures"))
        try #require(Swap.run("/usr/bin/cc", ["-o", app + "/Contents/MacOS/Dummy", source.path]) == 0)
        try #require(Swap.run("/usr/bin/codesign", ["-s", "-", "--force", app]) == 0)
        env = MenshenEnvironment(home: NSHomeDirectory(), dataRoot: URL(fileURLWithPath: root + "/data"),
                                 logsRoot: URL(fileURLWithPath: root + "/data/logs"),
                                 userTempRoot: MenshenEnvironment.current().userTempRoot)
    }

    /// The launcher stub SwiftPM built into the products folder that holds this test bundle
    /// (the resource bundle may be nested inside the .xctest, so walk up).
    var stub: URL {
        var dir = Bundle.module.bundleURL.deletingLastPathComponent()
        for _ in 0..<6 {
            let candidate = dir.appendingPathComponent(Swap.launcherExecutable)
            if FileManager.default.isExecutableFile(atPath: candidate.path) { return candidate }
            dir = dir.deletingLastPathComponent()
        }
        return dir.appendingPathComponent("menshen-launch-not-found")
    }

    func writeConfig() throws {
        let target = try ResolvedTarget.resolve(app)
        // One learned rule: Replace refuses a config with none (it would never start).
        let events = [SandboxEvent(process: "x", pid: 1, verdict: .allow, operation: "file-read-data",
                                   target: "/usr/share/dict/words", count: 1)]
        try Learn.build(target: target, events: events, environment: env).write(to: env.configURL(target.identity.key))
    }

    func cleanUp() { try? FileManager.default.removeItem(atPath: root) }
}

extension KernelTests {
    @Suite(.serialized) struct SwapTests {
        let d: DummyApps
        let fm = FileManager.default

        init() throws { d = try DummyApps() }

        @Test func replaceThenRestoreRoundTrips() throws {
            defer { d.cleanUp() }
            try d.writeConfig()
            let before = try #require(ResolvedTarget.signingCdhash(d.app))
            #expect(fm.isExecutableFile(atPath: d.stub.path), "menshen-launch should be built next to the tests")

            let record = try Swap.replace(d.app, stub: d.stub, environment: d.env)
            let hidden = d.apps + "/.Dummy.menshen.app"
            #expect(record.hiddenPath == hidden)
            #expect(record.cdhash == before)
            // The original was renamed, not modified.
            #expect(ResolvedTarget.signingCdhash(hidden) == before)
            #expect(Swap.codesignVerifies(hidden))
            // The launcher took its place, with the original's name, icon and document types.
            let info = try #require(NSDictionary(contentsOfFile: d.app + "/Contents/Info.plist") as? [String: Any])
            #expect(info["CFBundleIdentifier"] as? String == "dev.menshen.launcher.\(d.bundleId)")
            #expect(info["CFBundleName"] as? String == "Dummy")
            #expect(info["LSUIElement"] as? Bool == true)
            #expect((info["CFBundleDocumentTypes"] as? [Any])?.count == 1)
            #expect(Swap.launcherInfo(d.app)?["original"] == hidden)
            #expect(fm.fileExists(atPath: d.app + "/Contents/Resources/Dummy.icns"))
            #expect(fm.isExecutableFile(atPath: d.app + "/Contents/MacOS/menshen-launch"))
            #expect(Swap.codesignVerifies(d.app))
            #expect(Swap.records(d.env) == [record])

            let result = try Swap.restore(d.bundleId, environment: d.env)
            #expect(result.signatureValid)
            #expect(!result.cdhashChanged)
            #expect(ResolvedTarget.signingCdhash(d.app) == before)
            #expect(!Swap.isLauncher(d.app))
            #expect(!fm.fileExists(atPath: hidden))
            #expect(Swap.records(d.env).isEmpty)
            let leftovers = try fm.contentsOfDirectory(atPath: d.apps)
            #expect(leftovers == ["Dummy.app"], "no hidden or half-removed bundles left behind")
        }

        @Test func refusesWithoutConfigAndWhenAlreadyReplaced() throws {
            defer { d.cleanUp() }
            #expect(throws: MenshenError.self) { try Swap.replace(d.app, stub: d.stub, environment: d.env) }
            #expect(!Swap.isLauncher(d.app) && !fm.fileExists(atPath: Swap.hiddenPath(for: d.app)), "nothing moved")

            try d.writeConfig()
            try Swap.replace(d.app, stub: d.stub, environment: d.env)
            #expect(throws: MenshenError.self) { try Swap.replace(d.app, stub: d.stub, environment: d.env) }
            try Swap.restore(d.app, environment: d.env)
        }

        /// If building the launcher fails halfway, the original must end up exactly where it was.
        @Test func failedLauncherBuildRollsBack() throws {
            defer { d.cleanUp() }
            try d.writeConfig()
            let before = try #require(ResolvedTarget.signingCdhash(d.app))
            // An execute-only stub passes the up-front checks but can't be copied, so the launcher
            // build fails after the original has already been renamed.
            let stub = d.root + "/unreadable-stub"
            try FileManager.default.copyItem(at: d.stub, to: URL(fileURLWithPath: stub))
            chmod(stub, 0o111)

            do {
                try Swap.replace(d.app, stub: URL(fileURLWithPath: stub), environment: d.env)
                Issue.record("replace should have failed")
            } catch {
                // Must be the rollback path, not an earlier refusal (which would prove nothing).
                #expect("\(error)".contains("building the launcher failed"), "got: \(error)")
                #expect("\(error)".contains("original is back in place"))
            }
            #expect(!Swap.isLauncher(d.app))
            #expect(ResolvedTarget.signingCdhash(d.app) == before)
            #expect(!fm.fileExists(atPath: Swap.hiddenPath(for: d.app)))
            #expect(Swap.records(d.env).isEmpty)
        }

        /// Pointing commands at a replaced app's normal path (now the launcher) must reach the app's
        /// own config, and learning through it must store the normal path, never the hidden one.
        @Test func launcherPathMeansTheOriginalApp() throws {
            defer { d.cleanUp() }
            let doc = d.root + "/doc.txt"
            try "x".write(toFile: doc, atomically: true, encoding: .utf8)
            var learn = LearnOptions(target: d.app)
            learn.arguments = [doc]
            _ = try Learn.run(learn, environment: d.env)
            let configURL = d.env.configURL(d.bundleId)
            var config = try MenshenConfig.load(configURL)
            config.addCustom(.read, fileTypes: ["mp4"])
            try config.save(to: configURL)

            try Swap.replace(d.app, stub: d.stub, environment: d.env)
            defer { _ = try? Swap.restore(d.bundleId, environment: d.env) }
            #expect(try Enforce.locateConfig(EnforceOptions(target: d.app), environment: d.env).0 == configURL)

            learn.merge = true   // merges a capture from before the swap with one from the hidden original
            _ = try Learn.run(learn, environment: d.env)
            let relearned = try MenshenConfig.load(configURL)
            #expect(relearned.target.path == d.app)
            #expect(relearned.learning.runs == 2)
            let json = try String(contentsOf: configURL, encoding: .utf8)
            #expect(!json.contains(".menshen.app"), "no rule may point at the hidden location")
            #expect(relearned.rules.contains { $0.source == .custom }, "your rules survive re-learning")
        }

        @Test func restoreNeverDeletesSomethingThatIsntItsLauncher() throws {
            defer { d.cleanUp() }
            try d.writeConfig()
            let record = try Swap.replace(d.app, stub: d.stub, environment: d.env)
            // Someone replaced our launcher with something else.
            try fm.removeItem(atPath: d.app)
            try fm.createDirectory(atPath: d.app + "/Contents", withIntermediateDirectories: true)

            #expect(throws: MenshenError.self) { try Swap.restore(d.bundleId, environment: d.env) }
            #expect(fm.fileExists(atPath: d.app + "/Contents"), "not deleted")
            #expect(fm.fileExists(atPath: record.hiddenPath), "original still safe")
        }
    }
}

extension KernelTests {
    /// The launcher end to end: LaunchServices opens it with a document, it runs the hidden original
    /// under enforce with that document, and the enforce log shows the unlearned write was denied.
    @Suite(.serialized) struct LauncherTests {
        @Test func launcherRunsTheOriginalUnderEnforce() throws {
            let d = try DummyApps()
            defer { d.cleanUp() }
            let doc = d.root + "/docs/a.txt"
            try FileManager.default.createDirectory(atPath: d.root + "/docs", withIntermediateDirectories: true)
            try "hello\n".write(toFile: doc, atomically: true, encoding: .utf8)

            var learn = LearnOptions(target: d.app)
            learn.arguments = [doc]
            _ = try Learn.run(learn, environment: d.env)
            try FileManager.default.removeItem(atPath: doc + ".out")

            try Swap.replace(d.app, stub: d.stub, environment: d.env)
            defer { _ = try? Swap.restore(d.bundleId, environment: d.env) }

            let open = Process()
            open.executableURL = URL(fileURLWithPath: "/usr/bin/open")
            open.arguments = ["-W", "-a", d.app, doc]
            try open.run()
            let deadline = Date().addingTimeInterval(60)
            while open.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.2) }
            if open.isRunning { open.terminate() }
            #expect(open.terminationStatus == 0)

            #expect(FileManager.default.fileExists(atPath: doc + ".out"), "the original ran with the forwarded document")
            let logs = Library.sessions(d.bundleId, d.env).filter { $0.kind == .enforce }
            let log = try #require(logs.first, "the launcher wrote an enforce log")
            let records = Library.records(log.url)
            #expect(records.contains { $0.verdict == .deny && $0.target.contains("/docs/unlearned-") })
            #expect(!records.contains { $0.verdict == .deny && $0.target.hasSuffix("a.txt.out") })
        }
    }
}
