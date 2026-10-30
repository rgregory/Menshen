import Darwin
import Foundation

/// A replaced app: the launcher sits at `appPath`, the untouched original at `hiddenPath`.
public struct SwapRecord: Codable, Equatable, Sendable {
    public var key: String
    public var appPath: String
    public var hiddenPath: String
    public var cdhash: String?
    public var date: Date
}

public struct RestoreResult: Sendable {
    public var record: SwapRecord
    public var signatureValid: Bool
    /// The original changed while replaced (e.g. its own updater ran).
    public var cdhashChanged: Bool
}

/// Replaces an app with a launcher that runs it under `enforce`, and puts it back (ADR-005).
///
/// The original is only ever *renamed* within its own folder (`VLC.app` → `.VLC.menshen.app`):
/// its contents and signature are untouched, and a same-folder rename needs no write access to
/// the bundle itself. Every step rolls back on failure. The only thing Menshen deletes is its
/// own launcher, recognized by the `MenshenLauncher` key in its Info.plist.
public enum Swap {
    public static let markerKey = "MenshenLauncher"
    public static let launcherExecutable = "menshen-launch"
    static let lsregister = "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister"

    /// `/Applications/VLC.app` → `/Applications/.VLC.menshen.app`
    public static func hiddenPath(for appPath: String) -> String {
        let url = URL(fileURLWithPath: appPath)
        let name = url.deletingPathExtension().lastPathComponent
        return url.deletingLastPathComponent().appendingPathComponent(".\(name).menshen.app").path
    }

    /// The app a path really means: for a Menshen launcher, its hidden original; otherwise the path itself.
    public static func resolveOriginal(_ path: String) -> String {
        launcherInfo(realPath(path))?["original"] ?? path
    }

    public static func isLauncher(_ path: String) -> Bool {
        launcherInfo(path) != nil
    }

    /// The `MenshenLauncher` dictionary of a launcher bundle.
    public static func launcherInfo(_ path: String) -> [String: String]? {
        let info = NSDictionary(contentsOfFile: path + "/Contents/Info.plist")
        return info?[markerKey] as? [String: String]
    }

    /// The launcher stub next to the running executable, or in `../Resources` inside an app bundle.
    public static func defaultStub() -> URL? {
        guard let exe = Bundle.main.executableURL?.resolvingSymlinksInPath() else { return nil }
        let dir = exe.deletingLastPathComponent()
        return [dir.appendingPathComponent(launcherExecutable),
                dir.deletingLastPathComponent().appendingPathComponent("Resources/\(launcherExecutable)")]
            .first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }

    // MARK: - Registry

    public static func records(_ environment: MenshenEnvironment) -> [SwapRecord] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let data = try? Data(contentsOf: environment.swapsURL) else { return [] }
        return (try? decoder.decode([SwapRecord].self, from: data)) ?? []
    }

    static func saveRecords(_ records: [SwapRecord], _ environment: MenshenEnvironment) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        try FileManager.default.ensureDirectory(environment.dataRoot)
        try encoder.encode(records).write(to: environment.swapsURL, options: .atomic)
    }

    // MARK: - Replace

    @discardableResult
    public static func replace(_ path: String, stub: URL, environment: MenshenEnvironment) throws -> SwapRecord {
        let fm = FileManager.default
        let appPath = realPath(path)
        if isLauncher(appPath) {
            throw MenshenError.refused("\(appPath) is already a Menshen launcher")
        }
        let target = try ResolvedTarget.resolve(appPath)
        guard let bundle = target.bundlePath else {
            throw MenshenError.usage("only .app bundles can be replaced")
        }
        try target.preflight()
        let name = target.identity.name
        let key = target.identity.key
        let configURL = environment.configURL(key)
        guard fm.fileExists(atPath: configURL.path) else {
            throw MenshenError.refused("\(name) has no config yet. Learn it first.")
        }
        guard runningPIDs(inside: bundle).isEmpty else {
            throw MenshenError.refused("\(name) is running. Quit it first.")
        }
        guard codesignVerifies(bundle) else {
            throw MenshenError.refused("\(name)'s code signature doesn't verify, so Menshen won't touch it.")
        }
        guard fm.isExecutableFile(atPath: stub.path) else {
            throw MenshenError.failed("launcher stub missing at \(stub.path)")
        }
        let hidden = hiddenPath(for: bundle)
        guard !fm.fileExists(atPath: hidden) else {
            throw MenshenError.refused("\(hidden) already exists; resolve that first.")
        }

        do {
            try fm.moveItem(atPath: bundle, toPath: hidden)
        } catch {
            throw explainMove(error, name: name)
        }
        do {
            try buildLauncher(at: bundle, original: hidden, key: key, configURL: configURL,
                              stub: stub, environment: environment)
        } catch {
            // Whatever is at `bundle` now was created by us a moment ago.
            try? fm.removeItem(atPath: bundle)
            do {
                try fm.moveItem(atPath: hidden, toPath: bundle)
            } catch {
                throw MenshenError.failed("building the launcher failed AND moving the original back failed. The original is safe at \(hidden); rename it back to \(bundle).")
            }
            throw MenshenError.failed("building the launcher failed (\(error)); the original is back in place.")
        }

        register([bundle, hidden])
        // Whole seconds: the registry stores ISO-8601 dates, which drop fractions.
        let now = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        let record = SwapRecord(key: key, appPath: bundle, hiddenPath: hidden,
                                cdhash: target.identity.cdhash, date: now)
        try saveRecords(records(environment).filter { $0.key != key } + [record], environment)
        return record
    }

    static func buildLauncher(at path: String, original: String, key: String, configURL: URL,
                              stub: URL, environment: MenshenEnvironment) throws {
        let fm = FileManager.default
        let contents = path + "/Contents"
        try fm.createDirectory(atPath: contents + "/MacOS", withIntermediateDirectories: true)
        try fm.createDirectory(atPath: contents + "/Resources", withIntermediateDirectories: true)
        try fm.copyItem(atPath: stub.path, toPath: contents + "/MacOS/" + launcherExecutable)

        let source = (NSDictionary(contentsOfFile: original + "/Contents/Info.plist") as? [String: Any]) ?? [:]
        var info: [String: Any] = [:]
        for k in ["CFBundleName", "CFBundleDisplayName", "CFBundleIconFile", "CFBundleIconName",
                  "CFBundleDocumentTypes", "CFBundleURLTypes", "CFBundleShortVersionString", "CFBundleVersion"] {
            info[k] = source[k]
        }
        info["CFBundleIdentifier"] = "dev.menshen.launcher.\(key)"
        info["CFBundleExecutable"] = launcherExecutable
        info["CFBundlePackageType"] = "APPL"
        info["CFBundleInfoDictionaryVersion"] = "6.0"
        info["LSUIElement"] = true
        info["NSPrincipalClass"] = "NSApplication"
        info[markerKey] = [
            "key": key,
            "original": original,
            "config": configURL.path,
            "dataRoot": environment.dataRoot.path,
            "logsRoot": environment.logsRoot.path,
        ]
        if let icon = source["CFBundleIconFile"] as? String {
            let file = icon.hasSuffix(".icns") ? icon : icon + ".icns"
            let from = original + "/Contents/Resources/" + file
            if fm.fileExists(atPath: from) { try fm.copyItem(atPath: from, toPath: contents + "/Resources/" + file) }
        }
        let assets = original + "/Contents/Resources/Assets.car"
        if source["CFBundleIconName"] != nil, fm.fileExists(atPath: assets) {
            try fm.copyItem(atPath: assets, toPath: contents + "/Resources/Assets.car")
        }
        let data = try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
        try data.write(to: URL(fileURLWithPath: contents + "/Info.plist"))
        guard run("/usr/bin/codesign", ["-s", "-", "--force", path]) == 0 else {
            throw MenshenError.failed("ad hoc signing of the launcher failed")
        }
    }

    // MARK: - Restore

    /// `keyOrPath` is a config key (bundle ID) or the app's normal path.
    @discardableResult
    public static func restore(_ keyOrPath: String, environment: MenshenEnvironment) throws -> RestoreResult {
        let fm = FileManager.default
        let all = records(environment)
        var record = all.first { $0.key == keyOrPath || $0.appPath == keyOrPath || $0.appPath == realPath(keyOrPath) }
        if record == nil, let marker = launcherInfo(realPath(keyOrPath)), let original = marker["original"] {
            // Not in the registry (e.g. it was lost); the launcher itself knows where the original is.
            record = SwapRecord(key: marker["key"] ?? keyOrPath, appPath: realPath(keyOrPath),
                                hiddenPath: original, cdhash: nil, date: Date())
        }
        guard let record else { throw MenshenError.usage("\(keyOrPath) isn't replaced") }
        guard isLauncher(record.appPath) else {
            throw MenshenError.refused("\(record.appPath) isn't a Menshen launcher, so Menshen won't remove it")
        }
        guard fm.fileExists(atPath: record.hiddenPath) else {
            throw MenshenError.refused("the original isn't at \(record.hiddenPath)")
        }
        guard runningPIDs(inside: record.appPath).isEmpty, runningPIDs(inside: record.hiddenPath).isEmpty else {
            throw MenshenError.refused("the app is running. Quit it first.")
        }

        // Launcher aside → original back → delete launcher. Undo the first step if the second fails.
        let aside = URL(fileURLWithPath: record.appPath).deletingLastPathComponent()
            .appendingPathComponent(".menshen-removing-\(UUID().uuidString).app").path
        try fm.moveItem(atPath: record.appPath, toPath: aside)
        do {
            try fm.moveItem(atPath: record.hiddenPath, toPath: record.appPath)
        } catch {
            try? fm.moveItem(atPath: aside, toPath: record.appPath)
            throw explainMove(error, name: URL(fileURLWithPath: record.appPath).lastPathComponent)
        }
        try? fm.removeItem(atPath: aside)

        register([record.appPath])
        try saveRecords(all.filter { $0.key != record.key }, environment)
        let now = ResolvedTarget.signingCdhash(record.appPath)
        return RestoreResult(record: record, signatureValid: codesignVerifies(record.appPath),
                             cdhashChanged: record.cdhash != nil && now != record.cdhash)
    }

    // MARK: - Helpers

    static func explainMove(_ error: Error, name: String) -> MenshenError {
        let posix = ((error as NSError).userInfo[NSUnderlyingErrorKey] as? NSError)?.code
        if posix == Int(EPERM) || posix == Int(EACCES) || (error as NSError).code == NSFileWriteNoPermissionError {
            return .refused("macOS blocked moving \(name). Allow Menshen (or your terminal) under System Settings → Privacy & Security → App Management, then try again.")
        }
        return .failed("moving \(name) failed: \(error.localizedDescription)")
    }

    static func codesignVerifies(_ path: String) -> Bool {
        run("/usr/bin/codesign", ["--verify", "--strict", path]) == 0
    }

    /// Best effort: tell LaunchServices about the new bundle locations.
    static func register(_ paths: [String]) {
        for path in paths { _ = run(lsregister, ["-f", path]) }
    }

    @discardableResult
    static func run(_ tool: String, _ args: [String]) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return -1 }
        p.waitUntilExit()
        return p.terminationStatus
    }

    /// Processes whose executable lives inside `path` (i.e. the app is running).
    static func runningPIDs(inside path: String) -> [pid_t] {
        let prefix = path.hasSuffix("/") ? path : path + "/"
        let capacity = Int(proc_listallpids(nil, 0)) + 64
        var pids = [pid_t](repeating: 0, count: capacity)
        let n = Int(proc_listallpids(&pids, Int32(capacity * MemoryLayout<pid_t>.stride)))
        var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        return pids.prefix(max(n, 0)).filter { pid in
            guard pid > 0, proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return false }
            let bytes = buffer.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }
            return String(decoding: bytes, as: UTF8.self).hasPrefix(prefix)
        }
    }
}
