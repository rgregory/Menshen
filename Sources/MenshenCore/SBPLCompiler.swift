import Foundation

/// Config → SBPL. Order matters: SBPL lets later matching rules override earlier ones, so the
/// layout is base → always-on → learned → your rules → hardening → final denies (ADR-003).
public struct SBPLCompiler {
    public static let learnProfile = """
        (version 1)
        ;; Menshen learn mode: allow everything, report every operation to the kernel log.
        (allow default (with report))

        """

    let environment: MenshenEnvironment

    public init(environment: MenshenEnvironment) {
        self.environment = environment
    }

    /// Compact SBPL: rules with the same action, operations and logging are merged into one
    /// statement, and learned rules already covered by an always-on rule are left out. The JSON
    /// config keeps every rule with its ID and counts; this file is only what the kernel needs.
    public func compile(_ stored: MenshenConfig, source: String? = nil) -> String {
        let config = withCurrentProtections(stored)
        let t = config.target
        var out = [
            ";; Menshen profile for \(t.name)\(t.bundleId.map { " (\($0))" } ?? "")\(source.map { ", from \($0)" } ?? ""). Edit the JSON, not this file.",
            "(version 1)",
            "(deny default)",
            "(import \"system.sb\")",
        ]
        out += definitions()
        out += [
            "",
            ";; --- always on",
            "(allow file-read-metadata)",
        ]
        let own = t.path == t.executable ? "(literal \(path(t.executable)))" : "(subpath \(path(t.path)))"
        out.append("(allow file-read* file-map-executable \(own))")
        let profiles = Set(config.profiles ?? [])
        if !profiles.contains(.noLaunch) {  // otherwise the no-launch section allows it, after its deny
            out.append("(allow process-exec* \(own)\(config.logging.exec ? " (with report)" : ""))")
        }
        out.append("(allow signal (target same-sandbox))")
        if config.limits?.memoryMB != nil {
            // The memory limit is applied by taskpolicy inside the sandbox, right before the app.
            out.append("(allow file-read* file-map-executable process-exec* (literal \"/usr/sbin/taskpolicy\"))")
        }
        // launchd and cfprefsd check these in user space, so learning can't see them (ADR-004):
        // the app's own preferences, plus Apple system services and preferences.
        if let domain = t.bundleId {
            out.append("(allow user-preference-read user-preference-write (preference-domain \(quote(domain))))")
        }
        out.append("(allow mach-lookup (global-name-prefix \"com.apple.\")\(config.logging.activity ? " (with report)" : ""))")
        out.append(statement("allow", ["user-preference-read"], ["(preference-domain-prefix \"com.apple.\")",
                   "(preference-domain \"kCFPreferencesAnyApplication\")", "(preference-domain \"pbs\")"], report: false))

        let learned = withoutShadowed(config.rules.filter { $0.source != .custom && !coveredByAlwaysOn($0, config) }, config)
        let yours = withoutShadowed(config.rules.filter { $0.source == .custom }, config)
        for (title, rules) in [(";; --- learned", learned),
                               (";; --- your rules (before hardening, so protected locations stay blocked)", yours)] where !rules.isEmpty {
            out.append("")
            out.append(title)
            out += statements(rules, logging: config.logging, config: config)
        }
        out += profileSection(config, own: own)
        out.append("")
        out.append(";; --- hardening (last, so it wins)")
        out += hardeningStatements(config.hardening, logging: config.logging, config: config)
        out += selfProtection(config)
        out.append("(deny file-link)")
        out.append("")
        return out.joined(separator: "\n")
    }

    /// Profiles restrict what was learned, so they come after learned and your rules. Order
    /// inside matters here: a blanket deny, then the narrow allow that survives it. The blanket
    /// denies carry `(subpath "/")`: a deny with no filter only sets the operation's default and
    /// loses to any filtered allow, whatever the order (tested).
    func profileSection(_ config: MenshenConfig, own: String) -> [String] {
        let profiles = Set(config.profiles ?? [])
        guard !profiles.subtracting([.background]).isEmpty else { return [] }
        let names = Profile.allCases.filter { profiles.contains($0) && $0 != .background }.map(\.rawValue)
        var out = ["", ";; --- profiles: \(names.joined(separator: ", "))"]
        if profiles.contains(.offline) {
            out.append("(deny network-outbound (remote ip))")
            out.append("(deny network-bind network-inbound (local ip))")
        }
        if profiles.contains(.tempOnly) {
            out.append("(deny file-write* (subpath \"/\"))")
            // Shared temp plus the app's own Darwin cache folders, never every app's caches.
            var places = [environment.privateTemp(config.target.key).path]
            if let temp = environment.userTempDir { places.append(temp) }
            places += config.anchors.map(environment.expand)
                .filter { anchor in environment.userAppAreas.contains { anchor.hasPrefix($0 + "/") } }
            out.append(statement("allow", ["file-write*"], places.map { "(subpath \(path($0)))" } + devWrites(config), report: false))
        }
        if profiles.contains(.noLaunch) {
            out.append("(deny process-exec* (subpath \"/\"))")
            let taskpolicy = config.limits?.memoryMB != nil ? " (literal \"/usr/sbin/taskpolicy\")" : ""
            out.append("(allow process-exec* \(own)\(taskpolicy)\(config.logging.exec ? " (with report)" : ""))")
            // Apps, documents and links opened through LaunchServices run outside the sandbox.
            // lsopen is checked with no path, so no filter matches it and this deny has none;
            // it wins because learned lsopen allows have no filter either (finding 30).
            out.append("(deny lsopen)")
        }
        return out
    }

    /// Device files a temp-only app may still write: the usual sinks, its terminal, and any
    /// other device learning saw it write. Not all of /dev.
    func devWrites(_ config: MenshenConfig) -> [String] {
        var out = Self.devSinks.map { "(literal \(quote($0)))" } + ["(subpath \"/dev/fd\")", "(regex #\"^/dev/ttys[0-9]+$\")"]
        for rule in config.rules where rule.action == .allow && rule.operations.contains(where: { $0.hasPrefix("file-write") }) {
            guard rule.filter.kind == .literal || rule.filter.kind == .subpath, let raw = rule.filter.value else { continue }
            let path = environment.expand(raw)
            guard path.hasPrefix("/dev/"), !Self.devSinks.contains(path), !path.isWithin("/dev/fd"),
                  let text = filterText(rule.filter), !out.contains(text) else { continue }
            out.append(text)
        }
        return out
    }

    static let matchesNothing = "(literal \"/dev/null/menshen-invalid-rule\")"

    static let devSinks = ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/tty", "/dev/dtracehelper"]

    /// Leaves out the parts of learned and your allows that a profile's blanket deny cancels
    /// anyway, so the compiled file shows only what is really allowed. The kernel enforces the
    /// same thing either way; the JSON keeps every rule.
    /// - Temp-only: every write (the profile re-allows temp, the app's caches and devices).
    /// - No other programs: every launch (the profile re-allows the app itself).
    /// - Offline: IP network rules (local sockets are untouched).
    func withoutShadowed(_ rules: [Rule], _ config: MenshenConfig) -> [Rule] {
        let profiles = Set(config.profiles ?? [])
        guard !profiles.subtracting([.background]).isEmpty else { return rules }
        return rules.compactMap { rule in
            guard rule.action == .allow else { return rule }
            var ops = rule.operations
            if profiles.contains(.tempOnly) { ops.removeAll { $0.hasPrefix("file-write") } }
            if profiles.contains(.noLaunch) { ops.removeAll { $0 == "process-exec*" } }
            if profiles.contains(.offline), rule.filter.kind == .remote || rule.filter.kind == .local {
                ops.removeAll { $0.hasPrefix("network") }
            }
            if ops.isEmpty { return nil }
            var copy = rule
            copy.operations = ops
            return copy
        }
    }

    /// Every profile gets every current protection: ones added to Menshen after a config was
    /// learned are appended (as deny), so nobody has to re-learn to pick them up.
    func withCurrentProtections(_ config: MenshenConfig) -> MenshenConfig {
        let have = Set(config.hardening.map(\.id))
        let current = Hardening(environment: environment, ownAnchors: config.anchors.map(environment.expand)).rules(hits: [:])
        let missing = current.filter { !have.contains($0.id) }
        guard !missing.isEmpty else { return config }
        var copy = config
        copy.hardening += missing
        return copy
    }

    /// The hardening section in layers, because the order inside it matters (later wins):
    /// 1. name patterns you switched to allow (e.g. .env files), so a protected folder still
    ///    blocks them inside it (a .env in ~/.ssh stays blocked);
    /// 2. denies on protected folders and files;
    /// 3. folder allows: the app's own data inside a protected folder (`H-own-…`), entries
    ///    inside the app's own folder, and folders you switched to allow. After the denies so
    ///    they actually win; sorting every allow first made the own-data re-allows dead;
    /// 4. denies on secrets matched by name (.env, key files), so no re-allowed folder opens
    ///    them again.
    func hardeningStatements(_ rules: [Rule], logging: LoggingSettings, config: MenshenConfig) -> [String] {
        let pattern = { (r: Rule) in r.filter.kind == .homePattern }
        let layers = [rules.filter { $0.action == .allow && pattern($0) },
                      rules.filter { $0.action == .deny && !pattern($0) },
                      rules.filter { $0.action == .allow && !pattern($0) },
                      rules.filter { $0.action == .deny && pattern($0) }]
        return layers.flatMap { statements($0, logging: logging, config: config) }
    }

    /// Menshen's own state, which no wrapped app may touch: its configs, captures, swap
    /// registry and logs (read and write), and every launcher bundle and other replaced
    /// app's hidden original (write). Otherwise a confined app could rewrite its own profile,
    /// or swap a launcher, and be free on the next launch. Not stored in the config, so it
    /// can't be switched off or edited away; compiled after hardening, so nothing overrides it.
    /// A root that contains the home folder or the app itself (a test setup, an odd
    /// MENSHEN_DATA) is skipped rather than blocking everything.
    func selfProtection(_ config: MenshenConfig) -> [String] {
        let target = config.target.path
        func usable(_ root: String) -> Bool {
            root != "/" && !environment.home.isWithin(root) && !target.isWithin(root)
        }
        let roots = [environment.dataRoot.path, environment.logsRoot.path].map(realPath)
        var readWrite: [String] = []
        for root in roots where usable(root) && !readWrite.contains(where: { root.isWithin($0) }) {
            readWrite.append(root)
        }
        var writeOnly: [String] = []
        for record in Swap.records(environment) {
            writeOnly.append(record.appPath)
            if record.hiddenPath != target { writeOnly.append(record.hiddenPath) }
        }
        writeOnly = writeOnly.filter { p in usable(p) && !readWrite.contains { p.isWithin($0) } }
        guard !readWrite.isEmpty || !writeOnly.isEmpty else { return [] }
        var out = ["", ";; --- Menshen's own files (always, can't be switched off)"]
        if !readWrite.isEmpty {
            out.append(statement("deny", ["file-read*", "file-write*"], readWrite.map { "(subpath \(path($0)))" }, report: false))
        }
        if !writeOnly.isEmpty {
            out.append(statement("deny", ["file-write*"], writeOnly.map { "(subpath \(path($0)))" }, report: false))
        }
        // Temp-only exports a private TMPDIR inside the data folder; that one folder stays usable.
        if Set(config.profiles ?? []).contains(.tempOnly) {
            let temp = realPath(environment.dataRoot.path) + "/temp/" + config.target.key
            if readWrite.contains(where: { temp.isWithin($0) }) {
                out.append(statement("allow", ["file-read*", "file-write*"], ["(subpath \(path(temp)))"], report: false))
            }
        }
        return out
    }

    /// Merges rules into as few statements as possible without changing what they permit.
    /// Within a section, allows come first and denies after, so a rule you switched off wins
    /// over the section's allows.
    func statements(_ rules: [Rule], logging: LoggingSettings, config: MenshenConfig? = nil) -> [String] {
        struct Key: Hashable {
            var action: RuleAction
            var operations: [String]
            var report: Bool
        }
        var keys: [Key] = []
        var filters: [Key: [String]] = [:]
        for rule in rules {
            let report = rule.action == .allow && (rule.category.map(logging.reports) == true
                || (logging.activity && config.map { watched(rule, $0) } == true))
            let key = Key(action: rule.action, operations: rule.operations, report: report)
            if filters[key] == nil { keys.append(key) }
            var list = filters[key, default: []]
            if let filter = filterText(rule.filter) {
                if !list.contains(filter) { list.append(filter) }
            }
            filters[key] = list
        }
        var out: [String] = []
        for action in [RuleAction.allow, .deny] {
            // Operation-wide rules (no filter, not reported) collapse into one line.
            let bare = keys.filter { $0.action == action && !$0.report && filters[$0]!.isEmpty }
            let ops = bare.flatMap(\.operations).reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }
            if !ops.isEmpty { out.append(statement(action.rawValue, ops.sorted(), [], report: false)) }
            for key in keys where key.action == action && !(bare.contains(key)) {
                out.append(statement(action.rawValue, key.operations, filters[key]!, report: key.report))
            }
        }
        return out
    }

    /// Activity worth showing on the live dashboard that no specific switch covers: file access
    /// outside system files and the app itself, local sockets, services and devices. System-file reads would be thousands of
    /// uninteresting lines, so they stay quiet.
    func watched(_ rule: Rule, _ config: MenshenConfig) -> Bool {
        // Network, launches and outside writes have their own logging switches; activity covers the rest.
        if rule.category != nil { return false }
        let ops = Set(rule.operations)
        let interesting = ops.contains { op in
            op.hasPrefix("file-read") || op.hasPrefix("file-write") || op == "file-map-executable"
                || op.hasPrefix("network") || op == "process-exec*" || op == "mach-lookup" || op.hasPrefix("iokit")
        }
        guard interesting else { return false }
        guard let value = rule.filter.value, rule.filter.kind == .subpath || rule.filter.kind == .literal else { return true }
        let path = environment.expand(value)
        if path == "/" || path.hasPrefix("/dev/") || path.isWithin(config.target.path) { return false }
        let systemRead = Generalizer.systemReadRoots.contains { path.isWithin($0) } && !ops.contains("file-write*")
        return !systemRead
    }

    /// `(allow ops filter)` on one line, or one filter per line when there are several.
    func statement(_ action: String, _ operations: [String], _ filters: [String], report: Bool) -> String {
        let head = "(\(action) \(operations.joined(separator: " "))"
        let tail = report ? " (with report))" : ")"
        if filters.count <= 1 { return head + (filters.first.map { " \($0)" } ?? "") + tail }
        return head + filters.map { "\n    \($0)" }.joined() + tail
    }

    /// Learned allows that an always-on rule or system.sb already grants (Apple services and
    /// preferences, per-pid registrations, the app's own preferences and bundle), so they add
    /// nothing to the profile.
    func coveredByAlwaysOn(_ rule: Rule, _ config: MenshenConfig) -> Bool {
        guard rule.action == .allow, let value = rule.filter.value else { return false }
        let ops = Set(rule.operations)
        switch rule.filter.kind {
        case .globalName:
            return ops == ["mach-lookup"] && value.hasPrefix("com.apple.")
        case .localName:
            return ops == ["mach-register"]  // system.sb allows every per-pid registration
        case .preferenceDomain:
            return ops == ["user-preference-read"]
                && (value.hasPrefix("com.apple.") || ["kCFPreferencesAnyApplication", "pbs", config.target.bundleId].contains(value))
        case .subpath, .literal:
            let path = environment.expand(value)
            let own = config.target.path
            let inside = path == own || path.hasPrefix(own + "/")
            let reportsMatch = !ops.contains("process-exec*") || (rule.category == .exec) == config.logging.exec
            return inside && reportsMatch && ops.isSubset(of: ["file-read*", "file-map-executable", "process-exec*"])
        default:
            return false
        }
    }

    func filterText(_ filter: Filter) -> String? {
        guard let raw = filter.value else { return nil }
        let value = environment.expand(raw)
        switch filter.kind {
        case .any: return nil
        case .subpath: return "(subpath \(path(value)))"
        case .literal: return "(literal \(path(value)))"
        case .globalName: return "(global-name \(quote(value)))"
        case .xpcServiceName: return "(xpc-service-name \(quote(value)))"
        case .localName: return "(local-name \(quote(value)))"
        case .remote: return "(remote ip \(quote(value)))"
        case .local: return "(local ip \(quote(value)))"
        case .preferenceDomain: return "(preference-domain \(quote(value)))"
        case .iokitUserClientClass: return "(iokit-user-client-class \(quote(value)))"
        case .ipcPosixName: return "(ipc-posix-name \(quote(value)))"
        case .sysctlName: return "(sysctl-name \(quote(value)))"
        // Regex literals can't be escaped like strings, so only checked values get in
        // (MenshenConfig.load refuses others; this guard covers configs built in code).
        // An unchecked value compiles to a path that matches nothing, never to no filter.
        case .homePattern:
            guard MenshenConfig.isSafePattern(raw) else { return Self.matchesNothing }
            return "(require-all (subpath home-dir) (regex #\"\(raw)\"))"
        case .fileTypes:
            guard MenshenConfig.isFileTypeList(raw) else { return Self.matchesNothing }
            return "(regex #\"\\.(\(Self.caseInsensitive(raw)))$\")"
        }
    }

    /// The two machine-specific roots, named once at the top so the rules read the same on
    /// every Mac: `(home "/Library/Caches/x")`, `(darwin "/C/org.example.app")`. The Darwin
    /// folder (`/private/var/folders/xx/yyyy`) is the per-user temp and cache root.
    func definitions() -> [String] {
        var out = ["", ";; --- this Mac",
                   "(define home-dir \(quote(environment.home)))",
                   "(define (home p) (string-append home-dir p))"]
        if let root = environment.userTempRoot {
            out.append("(define darwin-dir \(quote(root)))")
            out.append("(define (darwin p) (string-append darwin-dir p))")
        }
        return out
    }

    /// A path for a filter, written relative to the home or Darwin folder when it's inside one.
    func path(_ p: String) -> String {
        if let root = environment.userTempRoot {
            if p == root { return "darwin-dir" }
            if p.hasPrefix(root + "/") { return "(darwin \(quote(String(p.dropFirst(root.count)))))" }
        }
        if p == environment.home { return "home-dir" }
        if p.hasPrefix(environment.home + "/") { return "(home \(quote(String(p.dropFirst(environment.home.count)))))" }
        return quote(p)
    }

    func quote(_ s: String) -> String {
        "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    /// Asks the kernel to load the profile (plus permission to exec /usr/bin/true) and run true.
    /// Returns nil on success, or sandbox-exec's error text.
    public static func validate(_ sbplText: String) -> String? {
        let probe = sbplText + "\n(allow process-exec* (literal \"/usr/bin/true\"))\n"
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
        task.arguments = ["-p", probe, "/usr/bin/true"]
        let err = Pipe()
        task.standardError = err
        task.standardOutput = FileHandle.nullDevice
        do { try task.run() } catch { return "can't run sandbox-exec: \(error)" }
        task.waitUntilExit()
        let text = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        return task.terminationStatus == 0 ? nil : (text.isEmpty ? "exit \(task.terminationStatus)" : text)
    }
}

extension SBPLCompiler {
    /// "mp4,mkv" → "mp4|MP4|mkv|MKV": readable in an audit. SBPL regexes have no
    /// case-insensitive flag (`(?i)` silently matches nothing), but on macOS's default
    /// case-insensitive volumes any mix of case matches anyway (tested). Extensions are validated
    /// to letters and digits when the rule is created.
    static func caseInsensitive(_ extensions: String) -> String {
        extensions.split(separator: ",").flatMap { ext -> [String] in
            let lower = ext.lowercased(), upper = ext.uppercased()
            return lower == upper ? [lower] : [lower, upper]
        }.joined(separator: "|")
    }
}
