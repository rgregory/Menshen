import CryptoKit
import Foundation

public let menshenVersion = "0.2.0"

public enum RuleAction: String, Codable, Sendable {
    case allow
    case deny
}

public enum RuleSource: String, Codable, Sendable {
    case learned
    case hardening
    /// Added by the user (e.g. "read all .mp4 files"). Kept when the app is re-learned.
    case custom
}

/// Risky allows that are compiled `(with report)` so they show up in the enforce log.
public enum ReportCategory: String, Codable, Sendable {
    case network
    case exec
    case writeOutside = "write-outside"
}

public enum FilterKind: String, Codable, Sendable {
    case any
    case subpath
    case literal
    case globalName = "global-name"
    /// An XPC service, reported by the kernel as "mach-lookup <name> (xpc)".
    case xpcServiceName = "xpc-service-name"
    case localName = "local-name"
    case remote
    case local
    case preferenceDomain = "preference-domain"
    case iokitUserClientClass = "iokit-user-client-class"
    /// Comma-separated file extensions ("mp4,mkv"), matched anywhere, in any letter case.
    case fileTypes = "file-types"
}

public struct Filter: Codable, Hashable, Sendable {
    public var kind: FilterKind
    /// Paths are stored with `~` for the home directory and expanded at compile time.
    public var value: String?

    public init(_ kind: FilterKind, _ value: String? = nil) {
        self.kind = kind
        self.value = value
    }

    public static let any = Filter(.any)
}

public struct Rule: Codable, Equatable, Identifiable, Sendable {
    public var id: String
    public var action: RuleAction
    public var operations: [String]
    public var filter: Filter
    public var source: RuleSource
    public var category: ReportCategory?
    /// Reports seen during learning that this rule covers.
    public var seen: Int
    /// True when learning saw the app do something this hardening rule denies.
    public var flagged: Bool?
    /// Set for category presets ("media", "documents"), so they read as names, not long lists.
    public var label: String?
    public var note: String?

    public init(
        id: String? = nil, action: RuleAction, operations: [String], filter: Filter,
        source: RuleSource, category: ReportCategory? = nil, seen: Int = 0,
        flagged: Bool? = nil, note: String? = nil
    ) {
        self.action = action
        self.operations = operations
        self.filter = filter
        self.source = source
        self.category = category
        self.seen = seen
        self.flagged = flagged
        self.note = note
        self.id = id ?? Rule.contentID(action: action, operations: operations, filter: filter)
    }

    /// Stable ID from the rule's content, so regenerating a config keeps the user's edits.
    static func contentID(action: RuleAction, operations: [String], filter: Filter) -> String {
        let text = "\(action.rawValue)|\(operations.joined(separator: ","))|\(filter.kind.rawValue)|\(filter.value ?? "")"
        let digest = SHA256.hash(data: Data(text.utf8))
        return "L-" + digest.prefix(4).map { String(format: "%02x", $0) }.joined()
    }
}

public struct LoggingSettings: Codable, Equatable, Sendable {
    public var denials = true
    public var network = true
    public var exec = true
    public var writeOutside = true

    public init() {}

    func reports(_ category: ReportCategory) -> Bool {
        switch category {
        case .network: return network
        case .exec: return exec
        case .writeOutside: return writeOutside
        }
    }
}

public struct LearningInfo: Codable, Equatable, Sendable {
    public var runs: Int
    public var events: Int
    /// Raw NDJSON captures this config was generated from (kept so it can be regenerated).
    public var captures: [String]
    public var warnings: [String]
}

public struct MenshenConfig: Codable, Equatable, Sendable {
    public var schemaVersion: Int
    public var generatedBy: String
    public var generatedAt: Date
    public var target: TargetIdentity
    /// Folders the app owns (its bundle, its Library folders, the user temp root). Writes
    /// elsewhere count as `write-outside`.
    public var anchors: [String]
    public var learning: LearningInfo
    public var logging: LoggingSettings
    /// Learned from observed behavior. Compiled before `hardening`.
    public var rules: [Rule]
    /// Built-in sensitive rules. Compiled last, so they win over broader learned allows.
    public var hardening: [Rule]

    public static func load(_ url: URL) throws -> MenshenConfig {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode(MenshenConfig.self, from: Data(contentsOf: url))
        } catch {
            throw MenshenError.failed("can't read config \(url.path): \(error)")
        }
    }

    public func write(to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        try FileManager.default.ensureDirectory(url.deletingLastPathComponent())
        try encoder.encode(self).write(to: url, options: .atomic)
    }

    /// The same config for the app at another location (a replaced app runs from its hidden
    /// `.Name.menshen.app`): the target and every rule inside the old bundle move with it.
    public func rebased(to newPath: String) -> MenshenConfig {
        let old = target.path
        guard old != newPath else { return self }
        func move(_ path: String) -> String {
            path == old ? newPath : path.hasPrefix(old + "/") ? newPath + path.dropFirst(old.count) : path
        }
        var copy = self
        copy.target.path = newPath
        copy.target.executable = move(target.executable)
        copy.anchors = anchors.map(move)
        for i in copy.rules.indices { copy.rules[i].filter.value = copy.rules[i].filter.value.map(move) }
        for i in copy.hardening.indices { copy.hardening[i].filter.value = copy.hardening[i].filter.value.map(move) }
        return copy
    }

    /// Writes the config, first keeping any previous version as `<name>.bak-<stamp>.json`.
    /// Returns the backup's URL, if there was a previous version.
    @discardableResult
    public func save(to url: URL) throws -> URL? {
        var backup: URL?
        if FileManager.default.fileExists(atPath: url.path) {
            let copy = url.deletingPathExtension().appendingPathExtension("bak-\(fileStamp()).json")
            try? FileManager.default.removeItem(at: copy)
            try FileManager.default.copyItem(at: url, to: copy)
            backup = copy
        }
        try write(to: url)
        return backup
    }

    /// Carries the user's edits (actions, logging toggles) from `previous` into a regenerated config.
    public mutating func keepEdits(from previous: MenshenConfig) {
        logging = previous.logging
        let actions = Dictionary((previous.rules + previous.hardening).map { ($0.id, $0.action) },
                                 uniquingKeysWith: { first, _ in first })
        for i in rules.indices { if let a = actions[rules[i].id] { rules[i].action = a } }
        for i in hardening.indices { if let a = actions[hardening[i].id] { hardening[i].action = a } }
    }
}

// MARK: - Your rules (broad permissions added by the user)

public enum CustomAccess: String, CaseIterable, Sendable {
    case read = "Read"
    case readWrite = "Read & write"

    var operations: [String] { self == .read ? ["file-read*"] : ["file-read*", "file-write*"] }
}

extension MenshenConfig {
    /// "*.mp4, .mkv mov" → ["mp4", "mkv", "mov"]. Extensions are letters and digits only, so they
    /// can be compiled into an SBPL regex safely.
    public static func fileExtensions(_ text: String) throws -> [String] {
        let words = text.split(whereSeparator: { " ,;".contains($0) }).map { word -> String in
            var w = Substring(word)
            if w.hasPrefix("*") { w = w.dropFirst() }
            if w.hasPrefix(".") { w = w.dropFirst() }
            return w.lowercased()
        }
        guard !words.isEmpty else { throw MenshenError.usage("no file types given (e.g. mp4 mkv)") }
        for w in words where w.isEmpty || w.count > 16 || !w.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) {
            throw MenshenError.usage("\"\(w)\" isn't a file type; use letters and digits, like mp4 or mkv")
        }
        var seen = Set<String>()
        return words.filter { seen.insert($0).inserted }
    }

    /// Allows reading (or reading and writing) every file with these extensions, anywhere.
    /// Hardening still wins: a matching file in ~/.ssh stays blocked.
    @discardableResult
    public mutating func addCustom(_ access: CustomAccess, fileTypes: [String]) -> Rule {
        add(Rule(action: .allow, operations: access.operations,
                 filter: Filter(.fileTypes, fileTypes.joined(separator: ",")), source: .custom,
                 note: "Added by you."))
    }

    /// Allows reading (or reading and writing) every file macOS puts in a category, anywhere.
    @discardableResult
    public mutating func addCustom(_ access: CustomAccess, category: FileCategory) -> Rule {
        var rule = Rule(action: .allow, operations: access.operations,
                        filter: Filter(.fileTypes, category.extensions.joined(separator: ",")), source: .custom,
                        note: "Added by you: \(category.title).")
        rule.label = category.rawValue
        return add(rule)
    }

    /// Allows reading (or reading and writing) everything inside a folder.
    @discardableResult
    public mutating func addCustom(_ access: CustomAccess, folder: String, environment: MenshenEnvironment) -> Rule {
        let path = environment.abbreviate(realPath(environment.expand(folder)))
        return add(Rule(action: .allow, operations: access.operations, filter: Filter(.subpath, path),
                        source: .custom, category: access == .readWrite ? .writeOutside : nil,
                        note: "Added by you."))
    }

    /// Removes one of your rules. Learned and hardening rules can only be switched off, not removed.
    @discardableResult
    public mutating func removeCustom(_ id: String) -> Bool {
        let before = rules.count
        rules.removeAll { $0.id == id && $0.source == .custom }
        return rules.count < before
    }

    private mutating func add(_ rule: Rule) -> Rule {
        var rule = rule
        rule.id = "C-" + rule.id.dropFirst(2)
        if let existing = rules.first(where: { $0.id == rule.id }) { return existing }
        rules.append(rule)
        return rule
    }
}
