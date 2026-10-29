import Foundation

/// Built-in rules that protect credentials, other apps' data and persistence locations.
/// They are always compiled last, so they override broader learned allows (ADR-003).
public struct Hardening: Sendable {
    public enum Protection: Sendable {
        /// Deny reading and writing (credential stores, other apps' data).
        case readWrite
        /// Deny writing only (persistence locations; reading them is harmless).
        case write
    }

    public struct Entry: Sendable {
        public var id: String
        public var title: String
        public var path: String
        public var protection: Protection
    }

    public struct Hit: Sendable {
        public var count = 0
        public var example = ""
    }

    public static let entries: [Entry] = [
        Entry(id: "H-ssh", title: "SSH keys and config", path: "~/.ssh", protection: .readWrite),
        Entry(id: "H-aws", title: "AWS credentials", path: "~/.aws", protection: .readWrite),
        Entry(id: "H-gnupg", title: "GnuPG keyrings", path: "~/.gnupg", protection: .readWrite),
        Entry(id: "H-kube", title: "Kubernetes credentials", path: "~/.kube", protection: .readWrite),
        Entry(id: "H-gh", title: "GitHub CLI token", path: "~/.config/gh", protection: .readWrite),
        Entry(id: "H-gcloud", title: "Google Cloud credentials", path: "~/.config/gcloud", protection: .readWrite),
        Entry(id: "H-netrc", title: ".netrc passwords", path: "~/.netrc", protection: .readWrite),
        Entry(id: "H-docker", title: "Docker registry auth", path: "~/.docker/config.json", protection: .readWrite),
        Entry(id: "H-keychains", title: "User keychains", path: "~/Library/Keychains", protection: .readWrite),
        Entry(id: "H-system-keychains", title: "System keychains", path: "/Library/Keychains", protection: .readWrite),
        Entry(id: "H-cookies", title: "Other apps' cookies", path: "~/Library/Cookies", protection: .readWrite),
        Entry(id: "H-safari", title: "Safari data", path: "~/Library/Safari", protection: .readWrite),
        Entry(id: "H-messages", title: "Messages history", path: "~/Library/Messages", protection: .readWrite),
        Entry(id: "H-mail", title: "Mail data", path: "~/Library/Mail", protection: .readWrite),
        Entry(id: "H-containers", title: "Other apps' sandbox containers", path: "~/Library/Containers", protection: .readWrite),
        Entry(id: "H-group-containers", title: "Other apps' group containers", path: "~/Library/Group Containers", protection: .readWrite),
        Entry(id: "H-chrome", title: "Chrome profile", path: "~/Library/Application Support/Google/Chrome", protection: .readWrite),
        Entry(id: "H-firefox", title: "Firefox profile", path: "~/Library/Application Support/Firefox", protection: .readWrite),
        Entry(id: "H-edge", title: "Edge profile", path: "~/Library/Application Support/Microsoft Edge", protection: .readWrite),
        Entry(id: "H-brave", title: "Brave profile", path: "~/Library/Application Support/BraveSoftware", protection: .readWrite),
        Entry(id: "H-arc", title: "Arc profile", path: "~/Library/Application Support/Arc", protection: .readWrite),
        Entry(id: "H-zsh-history", title: "zsh history", path: "~/.zsh_history", protection: .readWrite),
        Entry(id: "H-zsh-sessions", title: "zsh session history", path: "~/.zsh_sessions", protection: .readWrite),
        Entry(id: "H-bash-history", title: "bash history", path: "~/.bash_history", protection: .readWrite),
        Entry(id: "H-user-launchagents", title: "User launch agents (persistence)", path: "~/Library/LaunchAgents", protection: .write),
        Entry(id: "H-launchagents", title: "System launch agents (persistence)", path: "/Library/LaunchAgents", protection: .write),
        Entry(id: "H-launchdaemons", title: "Launch daemons (persistence)", path: "/Library/LaunchDaemons", protection: .write),
        Entry(id: "H-zshrc", title: "~/.zshrc (persistence)", path: "~/.zshrc", protection: .write),
        Entry(id: "H-zprofile", title: "~/.zprofile (persistence)", path: "~/.zprofile", protection: .write),
        Entry(id: "H-zshenv", title: "~/.zshenv (persistence)", path: "~/.zshenv", protection: .write),
        Entry(id: "H-zlogin", title: "~/.zlogin (persistence)", path: "~/.zlogin", protection: .write),
        Entry(id: "H-bashrc", title: "~/.bashrc (persistence)", path: "~/.bashrc", protection: .write),
        Entry(id: "H-bash-profile", title: "~/.bash_profile (persistence)", path: "~/.bash_profile", protection: .write),
        Entry(id: "H-profile", title: "~/.profile (persistence)", path: "~/.profile", protection: .write),
    ]

    public static let appleEventsID = "H-apple-events"
    public static let osascriptID = "H-osascript"
    public static let osascriptPath = "/usr/bin/osascript"

    let environment: MenshenEnvironment
    /// Absolute paths of folders the app owns. Sensitive entries never block the app's own data.
    let ownAnchors: [String]

    public init(environment: MenshenEnvironment, ownAnchors: [String]) {
        self.environment = environment
        self.ownAnchors = ownAnchors
    }

    /// The entry that protects `path` for this kind of access, or nil if the access isn't sensitive.
    public func entry(for path: String, isWrite: Bool) -> Entry? {
        if ownAnchors.contains(where: { path.isWithin($0) }) { return nil }
        return Self.entries.first { entry in
            guard isWrite || entry.protection == .readWrite else { return false }
            return path.isWithin(environment.expand(entry.path))
        }
    }

    /// Compiles the overlay. `hits` maps entry IDs to what learning saw (flag-and-deny).
    public func rules(hits: [String: Hit]) -> [Rule] {
        var rules: [Rule] = []
        for entry in Self.entries {
            let full = environment.expand(entry.path)
            let operations = entry.protection == .readWrite ? ["file-read*", "file-write*"] : ["file-write*"]
            let filter = Filter(.subpath, entry.path)
            if let owner = ownAnchors.first(where: { full.isWithin($0) }) {
                rules.append(Rule(id: entry.id, action: .allow, operations: operations, filter: filter,
                                  source: .hardening,
                                  note: "\(entry.title): inside the app's own folder \(environment.abbreviate(owner)), so allowed."))
                continue
            }
            rules.append(Rule(id: entry.id, action: .deny, operations: operations, filter: filter,
                              source: .hardening, seen: hits[entry.id]?.count ?? 0,
                              flagged: hits[entry.id] == nil ? nil : true,
                              note: note(entry.title, hits[entry.id])))
            // The deny above would also block the app's own folder inside it (e.g. its own
            // group container), so re-allow exactly that folder right after.
            for own in ownAnchors where own.isWithin(full) && own != full {
                let ownFilter = Filter(.subpath, environment.abbreviate(own))
                let hash = Rule.contentID(action: .allow, operations: operations, filter: ownFilter).dropFirst(2)
                rules.append(Rule(id: "H-own-\(hash)", action: .allow, operations: operations, filter: ownFilter,
                                  source: .hardening, note: "The app's own data inside \(entry.path)."))
            }
        }
        rules.append(Rule(id: Self.appleEventsID, action: .deny, operations: ["appleevent-send"], filter: .any,
                          source: .hardening, seen: hits[Self.appleEventsID]?.count ?? 0,
                          flagged: hits[Self.appleEventsID] == nil ? nil : true,
                          note: note("Sending Apple Events to other apps", hits[Self.appleEventsID])))
        rules.append(Rule(id: Self.osascriptID, action: .deny, operations: ["process-exec*"],
                          filter: Filter(.literal, Self.osascriptPath), source: .hardening,
                          seen: hits[Self.osascriptID]?.count ?? 0,
                          flagged: hits[Self.osascriptID] == nil ? nil : true,
                          note: note("Running AppleScript via osascript", hits[Self.osascriptID])))
        return rules
    }

    private func note(_ title: String, _ hit: Hit?) -> String {
        guard let hit else { return "\(title). Not seen during learning." }
        return "\(title). FLAGGED: seen \(hit.count)× during learning (e.g. \(hit.example)). Denied by default; set action to \"allow\" to permit."
    }
}

extension String {
    /// True if self equals `root` or lies underneath it.
    func isWithin(_ root: String) -> Bool {
        self == root || hasPrefix(root.hasSuffix("/") ? root : root + "/")
    }
}
