import Foundation

/// The Restricted Sandbox: one set of restrictions you choose once, applied to any app you drop
/// on Menshen, with no learning. Everything is allowed except what is switched off here, and
/// the sanity set (secrets, other apps' data, persistence) is always blocked.
public struct RestrictedSandbox: Codable, Equatable, Sendable {
    /// Internet and local-network connections. Local sockets (logging, DNS) always work.
    public var network = false
    /// Starting other programs. The app's own helpers inside its bundle always work.
    public var otherPrograms = false
    /// The app's own folders in ~/Library (settings, caches, saved state), guessed from its
    /// bundle ID and name. Off means it can't keep anything between runs.
    public var ownData = true
    /// The only places outside temp folders it can write, and the only places in your home
    /// folder it can read.
    public var readWrite: [String] = []
    /// Readable, never writable.
    public var readOnly: [String] = []

    public init(network: Bool = false, otherPrograms: Bool = false, ownData: Bool = true,
                readWrite: [String] = [], readOnly: [String] = []) {
        self.network = network
        self.otherPrograms = otherPrograms
        self.ownData = ownData
        self.readWrite = readWrite
        self.readOnly = readOnly
    }

    public static func url(_ environment: MenshenEnvironment) -> URL {
        environment.dataRoot.appendingPathComponent("restricted-sandbox.json")
    }

    /// The saved settings, or the strict defaults if none are saved.
    public static func load(_ environment: MenshenEnvironment) -> RestrictedSandbox {
        guard let data = try? Data(contentsOf: url(environment)) else { return RestrictedSandbox() }
        return (try? JSONDecoder().decode(RestrictedSandbox.self, from: data)) ?? RestrictedSandbox()
    }

    public func save(_ environment: MenshenEnvironment) throws {
        try FileManager.default.ensureDirectory(environment.dataRoot)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(self).write(to: Self.url(environment), options: .atomic)
    }

    /// One-line summary for the UI and the CLI.
    public var summary: String {
        var parts = [network ? "network on" : "no network"]
        parts.append(readWrite.isEmpty ? "writes only to temp" : "writes to \(readWrite.count) folder\(readWrite.count == 1 ? "" : "s")")
        if !readOnly.isEmpty { parts.append("reads \(readOnly.count) more") }
        if !otherPrograms { parts.append("no other programs") }
        if !ownData { parts.append("no saved data") }
        return parts.joined(separator: " · ")
    }

    /// The app's own folders under ~/Library, by bundle ID and by name.
    static func ownFolders(_ target: TargetIdentity, home: String) -> [String] {
        let lib = home + "/Library"
        var names = [target.name]
        if let id = target.bundleId { names.insert(id, at: 0) }
        var folders: [String] = []
        for name in names {
            folders += ["\(lib)/Application Support/\(name)", "\(lib)/Caches/\(name)", "\(lib)/Logs/\(name)"]
        }
        if let id = target.bundleId {
            folders += ["\(lib)/Containers/\(id)", "\(lib)/HTTPStorages/\(id)", "\(lib)/WebKit/\(id)",
                        "\(lib)/Saved Application State/\(id).savedState", "\(lib)/Preferences/\(id).plist"]
        }
        return folders
    }
}

extension SBPLCompiler {
    /// Operation families a normal app uses. Left out on purpose: boot-arg-set,
    /// opendirectory-user-modify and fs-snapshot*; anything not listed is denied and logged.
    static let restrictedBase = [
        "file*", "ipc*", "iokit*", "mach*", "network*", "process*", "signal", "sysctl*", "system*",
        "user-preference*", "nvram*", "job-creation", "lsopen", "pseudo-tty", "dynamic-code-generation",
        "darwin-notification-post", "distributed-notification-post", "authorization-right-obtain",
        "hid-control", "appleevent-send", "syscall*", "generic-issue-extension", "socket-ioctl",
        "device*", "qtn-user",
    ]

    /// The Restricted Sandbox profile. Starts by allowing everything an app normally does, so any
    /// app runs without learning, then takes away: the network, your home folder (except the folders you chose and
    /// the app's own), writes outside temp and your read & write folders, other programs. The
    /// sanity set comes last so it wins. Every deny carries a filter: a filter-less deny only
    /// would only set the operation's default (ADR-003).
    public func restrictedProfile(_ target: ResolvedTarget, _ box: RestrictedSandbox) -> String {
        let t = target.identity
        let home = environment.home
        let rw = box.readWrite.map(environment.expand).map(realPath)
        let ro = box.readOnly.map(environment.expand).map(realPath)
        let own = box.ownData ? RestrictedSandbox.ownFolders(t, home: home) : []
        func subpaths(_ paths: [String]) -> [String] { paths.map { "(subpath \(quote($0)))" } }
        let ownBundle = t.path == t.executable ? "(literal \(quote(t.executable)))" : "(subpath \(quote(t.path)))"

        var out = [
            ";; Menshen Restricted Sandbox for \(t.name)\(t.bundleId.map { " (\($0))" } ?? ""): \(box.summary).",
            "(version 1)",
            "(deny default)",
            "(import \"system.sb\")",
            ";; everything an app normally does, as explicit allows: under (allow default) the kernel",
            ";; enforces the denies below but never logs them (tested), so nothing would show up.",
            "(allow \(Self.restrictedBase.joined(separator: " ")))",
        ]
        if !box.network {
            out += ["", ";; no network",
                    "(deny network-outbound (remote ip))",
                    "(deny network-bind network-inbound (local ip))"]
        }
        // Order: no writes anywhere, then temp; then nothing in home (whatever the earlier lines
        // allowed); then only your folders and the app's own. Allows use the same wildcard
        // `file-read*` as the sanity set's denies: a rule naming a specific operation
        // (file-read-data) beats a wildcard one whatever the order, so it would have re-opened
        // .env files in your folders (tested). File names in home stay visible: many apps stop
        // working without file-read-metadata.
        let temp = [environment.userTempRoot, "/private/tmp"].compactMap { $0 } + ["/dev"]
        out += ["", ";; writes: only temp folders and your read & write folders",
                "(deny file-write* (subpath \"/\"))",
                statement("allow", ["file-write*"], subpaths(temp), report: false),
                ";; your home folder: only the folders you chose\(box.ownData ? " and the app's own data" : "")",
                "(deny file-read* file-write* (subpath \(quote(home))))",
                "(allow file-read-metadata (subpath \(quote(home))))"]
        if !(rw + own).isEmpty {
            out.append(statement("allow", ["file-write*"], subpaths(rw + own), report: false))
        }
        let readable = [t.path] + rw + ro + own + [home + "/Library/Fonts"]
        out.append(statement("allow", ["file-read*"], subpaths(readable), report: false))
        if !box.otherPrograms {
            out += ["", ";; no other programs",
                    "(deny process-exec* (subpath \"/\"))",
                    "(allow process-exec* \(ownBundle))"]
        }
        let anchors = own + rw
        let rules = Hardening(environment: environment, ownAnchors: anchors).rules(hits: [:])
        out += ["", ";; sanity set (last, so it wins)"] + statements(rules, logging: LoggingSettings())
        out.append("(deny file-link (subpath \"/\"))")
        return out.joined(separator: "\n") + "\n"
    }
}
