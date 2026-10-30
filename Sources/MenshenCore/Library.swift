import Foundation

/// An app Menshen has a config for.
public struct AppEntry: Identifiable, Sendable {
    public var id: String { config.target.key }
    public var config: MenshenConfig
    public var configURL: URL
    public var swap: SwapRecord?

    public var flagged: [Rule] { config.hardening.filter { $0.flagged == true } }
    /// Where the real app is right now: the hidden original while it's replaced.
    public var appPath: String { swap?.hiddenPath ?? config.target.path }
}

/// One learn or enforce run on disk.
public struct SessionInfo: Identifiable, Sendable {
    public enum Kind: String, Sendable {
        case learn
        case enforce
    }

    public var id: String { url.path }
    public var kind: Kind
    public var url: URL
    public var date: Date
    public var events: Int
    public var denials: Int
}

/// Read-side view of Menshen's folders, for the GUI.
public enum Library {
    public static func apps(_ environment: MenshenEnvironment) -> [AppEntry] {
        let swaps = Swap.records(environment)
        let files = (try? FileManager.default.contentsOfDirectory(
            at: environment.profilesDir, includingPropertiesForKeys: nil)) ?? []
        return files
            .filter { $0.pathExtension == "json" && !$0.lastPathComponent.contains(".bak-") }
            .compactMap { url in
                guard let config = try? MenshenConfig.load(url) else { return nil }
                return AppEntry(config: config, configURL: url,
                                swap: swaps.first { $0.key == config.target.key })
            }
            .sorted { $0.config.target.name.localizedCaseInsensitiveCompare($1.config.target.name) == .orderedAscending }
    }

    /// Learn captures and enforce logs for one app, newest first.
    public static func sessions(_ key: String, _ environment: MenshenEnvironment) -> [SessionInfo] {
        var result: [SessionInfo] = []
        for (dir, ext, kind) in [(environment.learnDir(key), "ndjson", SessionInfo.Kind.learn),
                                 (environment.logsDir(key), "jsonl", .enforce)] {
            let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
            for url in files where url.pathExtension == ext {
                let (events, denials) = kind == .learn ? countCapture(url) : countLog(url)
                result.append(SessionInfo(kind: kind, url: url, date: date(of: url),
                                          events: events, denials: denials))
            }
        }
        return result.sorted { $0.date > $1.date }
    }

    public static func records(_ url: URL) -> [EnforceRecord] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return lines(url).compactMap { try? decoder.decode(EnforceRecord.self, from: Data($0.utf8)) }
    }

    public static func captureEvents(_ url: URL) -> [SandboxEvent] {
        (try? readCapture(url)) ?? []
    }

    /// Everything Menshen keeps for an app: its config, compiled profile, backups, learning
    /// captures, enforce logs and private temp folder. The app itself is never part of it.
    public static func files(for key: String, _ environment: MenshenEnvironment) -> [URL] {
        let fm = FileManager.default
        let profiles = (try? fm.contentsOfDirectory(at: environment.profilesDir, includingPropertiesForKeys: nil)) ?? []
        let configFiles = profiles.filter { url in
            let name = url.lastPathComponent
            return name == "\(key).json" || name == "\(key).sb" || name.hasPrefix("\(key).bak-")
        }
        let folders = [environment.learnDir(key), environment.logsDir(key), environment.privateTemp(key)]
        return (configFiles + folders).filter { fm.fileExists(atPath: $0.path) }.sorted { $0.path < $1.path }
    }

    /// Moves everything Menshen keeps for an app to the Trash (recoverable). Refuses while the
    /// app is replaced, since its launcher still points at this config; restore it first.
    /// Returns where each item ended up in the Trash.
    @discardableResult
    public static func forget(_ key: String, _ environment: MenshenEnvironment) throws -> [URL] {
        if let swap = Swap.records(environment).first(where: { $0.key == key }) {
            throw MenshenError.refused("\(swap.appPath) is replaced by a Menshen launcher. Restore it first.")
        }
        let items = files(for: key, environment)
        guard !items.isEmpty else { throw MenshenError.usage("Menshen keeps nothing for \(key)") }
        var trashed: [URL] = []
        for url in items {
            var result: NSURL?
            try FileManager.default.trashItem(at: url, resultingItemURL: &result)
            if let result { trashed.append(result as URL) }
        }
        return trashed
    }

    // MARK: -

    static func countCapture(_ url: URL) -> (Int, Int) {
        let events = captureEvents(url)
        return (events.reduce(0) { $0 + $1.count }, events.filter { $0.verdict == .deny }.reduce(0) { $0 + $1.count })
    }

    static func countLog(_ url: URL) -> (Int, Int) {
        let records = records(url)
        return (records.reduce(0) { $0 + $1.count }, records.filter { $0.verdict == .deny }.reduce(0) { $0 + $1.count })
    }

    static func lines(_ url: URL) -> [Substring] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return text.split(separator: "\n")
    }

    /// Session files are named by `fileStamp()`; fall back to the file's modification date.
    static func date(of url: URL) -> Date {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyyMMdd-HHmmss"
        if let d = f.date(from: url.deletingPathExtension().lastPathComponent) { return d }
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? .distantPast
    }
}
