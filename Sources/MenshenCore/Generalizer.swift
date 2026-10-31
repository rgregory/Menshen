import Foundation

/// Turns learned reports into reviewable rules: paths collapse onto the folders they belong to,
/// named resources (mach services, preference domains, IOKit classes, ports) stay exact.
public struct Generalizer {
    public struct Output {
        public var rules: [Rule]
        public var anchors: [String]
        public var hits: [String: Hardening.Hit]
        public var warnings: [String]
    }

    enum OpClass { case read, write, exec, other }

    /// Areas of ~/Library where an app keeps its own folder.
    static let libraryAreas = [
        "Application Support", "Caches", "Preferences", "Saved Application State", "HTTPStorages",
        "WebKit", "Logs", "Cookies", "Containers", "Group Containers",
    ]
    /// Read-only system locations collapsed to one subpath rule each.
    static let systemReadRoots = [
        "/System", "/usr", "/bin", "/sbin", "/Library", "/Applications", "/private/etc",
        "/private/var/db", "/opt/homebrew",
    ]
    static let contentRoots = ["Documents", "Desktop", "Downloads", "Movies", "Music", "Pictures", "Public"]
    /// A folder with at least this many learned files of one kind becomes a single subpath rule.
    static let collapseThreshold = 4

    let environment: MenshenEnvironment
    let target: TargetIdentity
    let bundlePath: String?

    public init(environment: MenshenEnvironment, target: TargetIdentity, bundlePath: String?) {
        self.environment = environment
        self.target = target
        self.bundlePath = bundlePath
    }

    public func generalize(_ events: [SandboxEvent]) -> Output {
        let allowed = events.filter { $0.verdict == .allow }
        let anchors = ownAnchors(allowed)
        let hardening = Hardening(environment: environment, ownAnchors: anchors)
        var hits: [String: Hardening.Hit] = [:]
        var warnings: [String] = []
        var merged: [Key: Accum] = [:]

        func record(_ ops: [String], _ filter: Filter, _ category: ReportCategory?, _ count: Int) {
            let key = Key(operations: ops, filter: filter)
            merged[key, default: Accum()].seen += count
            if let category { merged[key]!.category = category }
        }
        func hit(_ id: String, _ event: SandboxEvent) {
            hits[id, default: Hardening.Hit()].count += event.count
            if hits[id]!.example.isEmpty {
                hits[id]!.example = "\(event.operation) \(environment.abbreviate(event.target))"
            }
        }

        // The app owns these folders outright: full read/write, not just the operations that
        // happened to be seen (apps often write their state only at quit, when reports get lost).
        let bundleAnchor = bundlePath ?? target.executable
        let ownFolders = anchors.filter { $0 != bundleAnchor }
        for folder in ownFolders {
            record(["file-read*", "file-write*"], Filter(.subpath, environment.abbreviate(folder)), nil, 0)
        }

        let denied = events.filter { $0.verdict == .deny }.reduce(0) { $0 + $1.count }
        if denied > 0 {
            warnings.append("\(denied) report(s) were denied even in learn mode (the system denies some operations to every process); they are not turned into rules.")
        }

        for event in allowed {
            let op = event.operation
            if op == "appleevent-send" { hit(Hardening.appleEventsID, event); continue }
            if op.hasPrefix("process-exec") {
                guard let path = Self.path(from: event.target) else { record([op], .any, .exec, event.count); continue }
                if path == Hardening.osascriptPath { hit(Hardening.osascriptID, event); continue }
                if let entry = hardening.entry(for: path, isWrite: false) { hit(entry.id, event); continue }
                let filter = anchors.first(where: { path.isWithin($0) }).map { Filter(.subpath, environment.abbreviate($0)) }
                    ?? Filter(.literal, environment.abbreviate(path))
                record(["process-exec*"], filter, .exec, event.count)
                continue
            }
            if op.hasPrefix("file-") {
                guard let (group, cls) = Self.fileGroup(op) else {
                    if op == "file-link" { warnings.append("The app made hard links; Menshen always denies file-link.") }
                    continue
                }
                guard let path = Self.path(from: event.target) else { record([group], .any, nil, event.count); continue }
                if (group == "file-read*" || group == "file-write*"),
                   let folder = ownFolders.first(where: { path.isWithin($0) }) {
                    record(["file-read*", "file-write*"], Filter(.subpath, environment.abbreviate(folder)), nil, event.count)
                    continue
                }
                if let entry = hardening.entry(for: path, isWrite: cls == .write) { hit(entry.id, event); continue }
                let (filter, category) = classify(path, cls, anchors)
                record([group], filter, category, event.count)
                continue
            }
            if op.hasPrefix("network-") {
                let (filter, category) = Self.networkFilter(op, event.target)
                record([op], filter, category, event.count)
                continue
            }
            switch op {
            case "mach-lookup", "mach-register":
                var name = event.target
                var kind = FilterKind.globalName
                if name.hasSuffix(" (per-pid)") {
                    name = String(name.dropLast(" (per-pid)".count))
                    kind = .localName
                } else if name.hasSuffix(" (xpc)") {
                    name = String(name.dropLast(" (xpc)".count))
                    kind = .xpcServiceName
                }
                record([op], name.isEmpty ? .any : Filter(kind, name), nil, event.count)
            case "user-preference-read", "user-preference-write":
                record([op], event.target.isEmpty ? .any : Filter(.preferenceDomain, event.target), nil, event.count)
            case "iokit-open-user-client":
                record([op], event.target.isEmpty ? .any : Filter(.iokitUserClientClass, event.target), nil, event.count)
            case "sysctl-write":
                record([op], event.target.isEmpty ? .any : Filter(.sysctlName, event.target), nil, event.count)
            case _ where op.hasPrefix("ipc-posix-"):  // shared memory and semaphores
                record([op], event.target.isEmpty ? .any : Filter(.ipcPosixName, event.target), nil, event.count)
            case "signal":
                continue  // always-on rule: signals only within the sandbox
            default:
                record([op], .any, nil, event.count)  // sysctl-read, system-info, process-fork, …
            }
        }

        let rules = collapse(merged).map { key, accum in
            Rule(action: .allow, operations: key.operations, filter: key.filter, source: .learned,
                 category: accum.category, seen: accum.seen)
        }.sorted { ($0.operations[0], $0.filter.value ?? "") < ($1.operations[0], $1.filter.value ?? "") }

        return Output(rules: rules, anchors: anchors.map(environment.abbreviate), hits: hits, warnings: warnings)
    }

    // MARK: - Paths

    struct Key: Hashable {
        var operations: [String]
        var filter: Filter
    }

    struct Accum {
        var seen = 0
        var category: ReportCategory?
    }

    /// Folders the app owns: its bundle (or executable), the shared user temp folder, and any
    /// folder named after it that it actually touched in a ~/Library area or in the Darwin
    /// caches (`…/C`, `…/0`). Never the whole Darwin folder: that is every app's caches.
    func ownAnchors(_ events: [SandboxEvent]) -> [String] {
        var anchors: Set<String> = [bundlePath ?? target.executable]
        if let temp = environment.userTempDir { anchors.insert(temp) }
        let areas = Self.libraryAreas.map { environment.home + "/Library/" + $0 } + environment.userAppAreas
        for event in events where event.operation.hasPrefix("file-") || event.operation.hasPrefix("process-exec") {
            guard let path = Self.path(from: event.target),
                  let area = areas.first(where: { path.hasPrefix($0 + "/") }),
                  let name = path.dropFirst(area.count + 1).split(separator: "/").first,
                  owns(String(name)) else { continue }
            anchors.insert(area + "/" + name)
        }
        return anchors.sorted()
    }

    /// Whether a folder/file name under a ~/Library area belongs to this app.
    func owns(_ component: String) -> Bool {
        let c = component.lowercased()
        let names = [target.name, target.bundleId, target.signingId,
                     (target.executable as NSString).lastPathComponent].compactMap { $0?.lowercased() }
        for name in names where !name.isEmpty {
            if c == name || c.hasPrefix(name + ".") { return true }
        }
        if let team = target.teamId?.lowercased(), c.hasPrefix(team + ".") { return true }
        // Vendor folders such as "Google" for "Google Chrome".
        let words = target.name.split(separator: " ")
        if words.count > 1, let first = words.first, first.count >= 4, c == first.lowercased() { return true }
        return false
    }

    func classify(_ path: String, _ cls: OpClass, _ anchors: [String]) -> (Filter, ReportCategory?) {
        let write = cls == .write
        if let anchor = anchors.first(where: { path.isWithin($0) }) {
            return (Filter(.subpath, environment.abbreviate(anchor)), nil)
        }
        if path.hasPrefix("/dev/") {
            return (Filter(.literal, path), nil)
        }
        for root in Self.contentRoots {
            let full = environment.home + "/" + root
            if path.isWithin(full) {
                return (Filter(.subpath, environment.abbreviate(full)), write ? .writeOutside : nil)
            }
        }
        if !write, let root = Self.systemReadRoots.first(where: { path.isWithin($0) }) {
            return (Filter(.subpath, root), nil)
        }
        return (Filter(.literal, environment.abbreviate(path)), write ? .writeOutside : nil)
    }

    /// Replaces many literals in one folder with a subpath rule for that folder.
    func collapse(_ merged: [Key: Accum]) -> [(key: Key, value: Accum)] {
        var result = merged
        let literals = merged.filter { $0.key.filter.kind == .literal && $0.key.filter.value != nil }
        let groups = Dictionary(grouping: literals) { entry in
            "\(entry.key.operations.joined(separator: " "))\u{0}\((entry.key.filter.value! as NSString).deletingLastPathComponent)"
        }
        for (_, members) in groups where members.count >= Self.collapseThreshold {
            let first = members[0].key
            let parent = (first.filter.value! as NSString).deletingLastPathComponent
            let depth = environment.expand(parent).split(separator: "/").count
            guard parent != "~", depth >= 2, !parent.hasPrefix("/dev") else { continue }
            var accum = Accum()
            for member in members {
                result.removeValue(forKey: member.key)
                accum.seen += member.value.seen
                accum.category = accum.category ?? member.value.category
            }
            let key = Key(operations: first.operations, filter: Filter(.subpath, parent))
            result[key, default: Accum()].seen += accum.seen
            if let c = accum.category { result[key]!.category = c }
        }
        return result.map { ($0.key, $0.value) }
    }

    // MARK: - Report targets

    /// Reads, writes and other file operations, grouped the way they are written in SBPL.
    static func fileGroup(_ op: String) -> (String, OpClass)? {
        switch op {
        case "file-read-metadata", "file-link": return nil  // always-on allow / always-on deny
        case "file-read-data", "file-read-xattr", "file-read*": return ("file-read*", .read)
        case "file-map-executable": return ("file-map-executable", .read)
        case "file-issue-extension": return ("file-issue-extension", .read)
        case "file-ioctl": return ("file-ioctl", .other)
        default:
            if op.hasPrefix("file-write") { return ("file-write*", .write) }
            return (op, .other)
        }
    }

    /// Extracts the path from targets like `/a/b`, `path:/a/b xattr:x`, `target:/a extension-class:c`.
    static func path(from target: String) -> String? {
        if target.hasPrefix("/") { return target }
        for (prefix, terminators) in [("path:", [" xattr:", " ioctl-command:"]), ("target:", [" extension-class:"])] {
            guard target.hasPrefix(prefix) else { continue }
            var body = Substring(target.dropFirst(prefix.count))
            for t in terminators {
                if let r = body.range(of: t, options: .backwards) { body = body[..<r.lowerBound] }
            }
            return body.hasPrefix("/") ? String(body) : nil
        }
        return nil
    }

    /// SBPL only allows `*` or `localhost` as the host, so keep the port and drop the address.
    static func networkFilter(_ op: String, _ target: String) -> (Filter, ReportCategory?) {
        if target.hasPrefix("/") { return (Filter(.literal, target), nil) }  // unix socket (e.g. mDNSResponder)
        for (prefix, kind) in [("remote:", FilterKind.remote), ("local:", FilterKind.local)] {
            guard target.hasPrefix(prefix) else { continue }
            let address = target.dropFirst(prefix.count)
            guard let colon = address.lastIndex(of: ":") else { break }
            let host = address[..<colon]
            let port = address[address.index(after: colon)...]
            let h = host == "localhost" || host == "127.0.0.1" || host == "::1" ? "localhost" : "*"
            return (Filter(kind, "\(h):\(port)"), .network)
        }
        return (.any, .network)
    }
}
