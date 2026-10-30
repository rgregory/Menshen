import Foundation

public struct LearnOptions: Sendable {
    public var target: String
    public var arguments: [String] = []
    public var duration: TimeInterval?
    public var merge = false
    public var configPath: URL?
    public var control = SessionControl(forwardSignals: true)
    /// Every captured report, as it arrives (for live UIs). Called on a background queue.
    public var onEvent: (@Sendable (SandboxEvent) -> Void)?

    public init(target: String) { self.target = target }
}

public struct LearnSummary: Sendable {
    public var configURL: URL
    public var captureURL: URL
    public var backupURL: URL?
    public var config: MenshenConfig
    public var eventsThisRun: Int
    public var processes: Set<String>
    public var outcome: Runner.Outcome
}

public struct EnforceOptions: Sendable {
    /// An app, binary, or config JSON.
    public var target: String
    public var arguments: [String] = []
    public var configPath: URL?
    public var allowChanged = false
    public var duration: TimeInterval?
    public var control = SessionControl(forwardSignals: true)
    /// Every logged record, as it arrives (for live UIs). Called on a background queue.
    public var onRecord: (@Sendable (EnforceRecord) -> Void)?

    public init(target: String) { self.target = target }
}

public struct EnforceSummary: Sendable {
    public var logURL: URL
    public var profileURL: URL
    public var denials: Int
    public var uniqueDenials: Int
    public var reportedAllows: [String: Int]
    public var outcome: Runner.Outcome
    public var drained: Bool
    public var streamNotices: Int
}

public enum Learn {
    public static func run(
        _ options: LearnOptions,
        environment: MenshenEnvironment = .current(),
        say: @escaping @Sendable (String) -> Void = { _ in }
    ) throws -> LearnSummary {
        let target = try ResolvedTarget.resolve(options.target)
        try target.preflight()
        let key = target.identity.key
        let fm = FileManager.default
        let learnDir = environment.learnDir(key)
        try fm.ensureDirectory(learnDir)
        let configURL = options.configPath ?? environment.configURL(key)

        let profile = learnDir.appendingPathComponent("learn.sb")
        try ProfileCompiler.learnProfile.write(to: profile, atomically: true, encoding: .utf8)
        let onEvent = options.onEvent
        let captureURL = learnDir.appendingPathComponent("\(fileStamp()).ndjson")
        let capture = try NDJSONWriter(captureURL)
        defer { capture.close() }

        say("learning \(target.identity.name) (\(target.identity.executable)). Use the app normally, then quit it\(options.duration.map { " or wait \(Int($0))s" } ?? "").")
        let result = try Session.run(
            profile: profile, target: target, arguments: options.arguments,
            duration: options.duration, environment: environment, control: options.control,
            onEvent: { event in
                capture.write(event)
                onEvent?(event)
            }
        )
        capture.close()

        var warnings: [String] = []
        if result.events.isEmpty {
            warnings.append("No reports were captured from the app. The config would be empty; check that the app actually ran.")
        }
        if !result.drained {
            warnings.append("The log stream never confirmed it had caught up after the app exited; the last reports may be missing.")
        }
        if result.streamNotices > 0 {
            warnings.append("log stream reported \(result.streamNotices) non-log notice(s), possibly dropped messages. Consider another learn run with --merge.")
        }
        warnings.append("Child processes that exit within milliseconds may be under-reported by the kernel. Exercise features more than once, or re-run with --merge.")

        let previous = fm.fileExists(atPath: configURL.path) ? try? MenshenConfig.load(configURL) : nil
        var captures = [captureURL.path]
        var runs = 1
        if options.merge, let previous {
            captures = previous.learning.captures + captures
            runs = previous.learning.runs + 1
        }
        var events: [SandboxEvent] = []
        for path in captures {
            events += (try? readCapture(URL(fileURLWithPath: path))) ?? []
        }

        var config = build(target: target, events: events, environment: environment,
                           runs: runs, captures: captures, warnings: warnings)
        // Learning a replaced app runs its hidden original; store the app's normal location so
        // the config stays valid after Restore.
        if let swap = Swap.records(environment).first(where: { $0.hiddenPath == target.identity.path }) {
            config = config.rebased(to: swap.appPath)
        }
        if let previous, options.merge {
            config.keepEdits(from: previous)
        }
        let backupURL = try config.save(to: configURL)
        return LearnSummary(configURL: configURL, captureURL: captureURL, backupURL: backupURL, config: config,
                            eventsThisRun: result.events.count, processes: result.processes,
                            outcome: result.outcome)
    }

    /// Pure: events → config. Used by `learn` and by tests.
    public static func build(
        target: ResolvedTarget, events: [SandboxEvent], environment: MenshenEnvironment,
        runs: Int = 1, captures: [String] = [], warnings: [String] = []
    ) -> MenshenConfig {
        let generalizer = Generalizer(environment: environment, target: target.identity, bundlePath: target.bundlePath)
        let output = generalizer.generalize(events)
        let hardening = Hardening(environment: environment, ownAnchors: output.anchors.map(environment.expand))
        return MenshenConfig(
            schemaVersion: 1,
            generatedBy: "menshen \(menshenVersion)",
            generatedAt: Date(),
            target: target.identity,
            anchors: output.anchors,
            learning: LearningInfo(runs: runs, events: events.reduce(0) { $0 + $1.count },
                                   captures: captures, warnings: warnings + output.warnings),
            logging: LoggingSettings(),
            rules: output.rules,
            hardening: hardening.rules(hits: output.hits)
        )
    }
}

public enum Enforce {
    /// Finds the config: an explicit path, a .json target, or the default for the target's key.
    public static func locateConfig(_ options: EnforceOptions, environment: MenshenEnvironment) throws -> (URL, MenshenConfig) {
        let url: URL
        if let explicit = options.configPath {
            url = explicit
        } else if options.target.hasSuffix(".json") {
            url = URL(fileURLWithPath: options.target)
        } else {
            url = environment.configURL(try ResolvedTarget.resolve(options.target).identity.key)
        }
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw MenshenError.usage("no config at \(url.path). Run `menshen learn \(options.target)` first.")
        }
        return (url, try MenshenConfig.load(url))
    }

    public static func run(
        _ options: EnforceOptions,
        environment: MenshenEnvironment = .current(),
        say: @escaping @Sendable (String) -> Void = { _ in }
    ) throws -> EnforceSummary {
        let (configURL, stored) = try locateConfig(options, environment: environment)
        let targetPath = options.target.hasSuffix(".json") ? stored.target.path : options.target
        let target = try ResolvedTarget.resolve(targetPath)
        try target.preflight()
        try checkIdentity(expected: stored.target, actual: target.identity, allowChanged: options.allowChanged, say: say)
        // A replaced app runs from its hidden location; its own-bundle rules must follow it.
        let config = stored.rebased(to: target.identity.path)

        let text = ProfileCompiler(environment: environment).compile(config, source: configURL.path)
        if let error = ProfileCompiler.validate(text) {
            throw MenshenError.failed("the compiled profile doesn't load:\n\(error)")
        }
        let profileURL = configURL.deletingPathExtension().appendingPathExtension("sb")
        try text.write(to: profileURL, atomically: true, encoding: .utf8)

        let runId = UUID().uuidString
        let logURL = environment.logsDir(config.target.key).appendingPathComponent("\(fileStamp()).jsonl")
        let log = try NDJSONWriter(logURL)
        defer { log.close() }
        let tally = Tally()
        let logging = config.logging
        let onRecord = options.onRecord

        say("enforcing \(configURL.path) on \(target.identity.name). Log: \(logURL.path)")
        let result = try Session.run(
            profile: profileURL, target: target, arguments: options.arguments,
            duration: options.duration, environment: environment, control: options.control,
            onEvent: { event in
                if event.verdict == .deny && !logging.denials { return }
                let record = EnforceRecord(
                    ts: Date(), runId: runId, pid: event.pid, process: event.process,
                    verdict: event.verdict, operation: event.operation,
                    target: environment.abbreviate(event.target),
                    category: EnforceRecord.category(for: event), count: event.count)
                log.write(record)
                onRecord?(record)
                if tally.add(record) {
                    say("DENY \(record.operation) \(record.target)  [\(record.process) \(record.pid)]")
                }
            }
        )
        return EnforceSummary(
            logURL: logURL, profileURL: profileURL, denials: tally.denials, uniqueDenials: tally.unique,
            reportedAllows: tally.allows, outcome: result.outcome, drained: result.drained,
            streamNotices: result.streamNotices
        )
    }

    static func checkIdentity(expected: TargetIdentity, actual: TargetIdentity, allowChanged: Bool,
                              say: (String) -> Void) throws {
        var changes: [String] = []
        if expected.teamId != actual.teamId { changes.append("team ID \(expected.teamId ?? "none") → \(actual.teamId ?? "none")") }
        if expected.signingId != actual.signingId { changes.append("signing ID \(expected.signingId ?? "none") → \(actual.signingId ?? "none")") }
        if expected.cdhash != actual.cdhash { changes.append("code hash changed (updated or rebuilt)") }
        guard !changes.isEmpty else { return }
        let message = "\(actual.name) isn't the binary this config was learned from: " + changes.joined(separator: "; ")
        if allowChanged {
            say("warning: \(message). Continuing because of --allow-changed.")
        } else {
            throw MenshenError.refused("\(message). Re-run `menshen learn` (add --merge to keep your edits), or pass --allow-changed.")
        }
    }
}

/// Counts enforce events and decides which denials are new enough to print.
private final class Tally: @unchecked Sendable {
    private let lock = NSLock()
    private var seen: Set<String> = []
    private(set) var denials = 0
    private(set) var allows: [String: Int] = [:]
    var unique: Int { lock.withLock { seen.count } }

    /// Returns true for the first occurrence of each distinct denial.
    func add(_ record: EnforceRecord) -> Bool {
        lock.withLock {
            if record.verdict == .allow {
                allows[record.category, default: 0] += record.count
                return false
            }
            denials += record.count
            return seen.insert("\(record.operation) \(record.target)").inserted
        }
    }
}
