import Foundation

/// Plain-language wording for rules, so people don't have to read SBPL.
public enum RuleText {
    static let ports: [String: String] = [
        "80": "HTTP", "443": "HTTPS", "53": "DNS", "22": "SSH", "25": "SMTP", "587": "SMTP",
        "993": "IMAP", "8080": "HTTP alt", "5353": "Bonjour",
    ]

    /// "Read & write", "Run programs in", "Connect out to", …
    public static func verb(_ operations: [String]) -> String {
        let ops = Set(operations)
        if ops.contains("file-read*") && ops.contains("file-write*") { return "Read & write" }
        guard let op = operations.first else { return "" }
        switch op {
        case "file-read*": return "Read"
        case "file-write*": return "Write"
        case "process-exec*": return "Run"
        case "file-map-executable": return "Load code from"
        case "file-ioctl": return "Control device"
        case "file-issue-extension": return "Share access to"
        case "mach-lookup": return "Talk to service"
        case "mach-register": return "Offer services"
        case "network-outbound": return "Connect out to"
        case "network-bind", "network-inbound": return "Listen on"
        case "user-preference-read": return "Read settings of"
        case "user-preference-write": return "Change settings of"
        case "iokit-open-user-client": return "Use hardware interface"
        case "sysctl-read", "system-info": return "Read system information"
        case "sysctl-write": return "Change system settings"
        case "process-fork": return "Start child processes"
        case "appleevent-send": return "Send Apple Events"
        default:
            if op.hasPrefix("ipc-posix") { return "Use shared memory" }
            if op.hasPrefix("mach-") { return "Use system services" }
            return op
        }
    }

    /// Short access word for a table column: read, write, read & write, run, connect, …
    public static func access(_ operations: [String]) -> String {
        let ops = Set(operations)
        if ops.contains("file-read*") && ops.contains("file-write*") { return "read & write" }
        if ops.contains("file-write*") { return "write" }
        if ops.contains("file-read*") || ops.contains("file-map-executable") { return "read" }
        if ops.contains("process-exec*") { return "run" }
        if ops.contains("network-outbound") { return "connect" }
        if ops.contains("network-bind") || ops.contains("network-inbound") { return "listen" }
        return "use"
    }

    /// "port 443 (HTTPS)" for network addresses, the path or name otherwise.
    public static func object(_ filter: Filter) -> String {
        guard let value = filter.value else { return "" }
        switch filter.kind {
        case .fileTypes:
            return "all " + value.split(separator: ",").map { ".\($0)" }.joined(separator: ", ") + " files"
        case .remote, .local:
            let port = String(value.split(separator: ":").last ?? "")
            let host = value.hasPrefix("localhost") ? " on this Mac" : ""
            return "port \(port)" + (ports[port].map { " (\($0))" } ?? "") + host
        default:
            return value
        }
    }

    /// Names for well-known local sockets apps "connect" to.
    public static func socketName(_ path: String) -> String? {
        switch path {
        case "/private/var/run/mDNSResponder", "/var/run/mDNSResponder": return "DNS lookups"
        case "/private/var/run/syslog", "/var/run/syslog": return "the system log"
        default: return nil
        }
    }

    public static func describe(_ rule: Rule) -> String {
        if let label = rule.label, let category = FileCategory(rawValue: label) {
            return "\(verb(rule.operations)) all \(category.noun)"
        }
        let object = object(rule.filter)
        if rule.operations == ["network-outbound"], rule.filter.kind == .literal, let path = rule.filter.value {
            switch socketName(path) {
            case "DNS lookups": return "Look up host names (DNS)"
            case "the system log": return "Write to the system log"
            default: return "Talk to local socket \(path)"
            }
        }
        return object.isEmpty ? verb(rule.operations) : "\(verb(rule.operations)) \(object)"
    }
}

/// What an app is allowed to do, grouped for the dashboard.
public struct AccessSummary: Sendable {
    public struct Item: Identifiable, Sendable {
        public var id: String { title + detail }
        public var title: String
        public var detail: String
        public var access: String
        public var flagged = false
    }

    public var files: [Item] = []
    public var network: [Item] = []
    public var launches: [Item] = []
    public var services: [Item] = []
    public var sensitive: [Item] = []
    /// Active templates and resource limits.
    public var restrictions: [Item] = []
    /// Hardening rules that deny something (protected locations and behaviors).
    public var protectedCount = 0

    static let systemRoots: Set<String> = Set(Generalizer.systemReadRoots)
    static let fileOps: Set<String> = ["file-read*", "file-write*", "file-map-executable", "file-ioctl", "file-issue-extension"]

    public static func make(_ config: MenshenConfig, environment: MenshenEnvironment) -> AccessSummary {
        var s = AccessSummary()
        let allowed = config.rules.filter { $0.action == .allow }
        let bundle = config.target.path
        let anchors = Set(config.anchors.map(environment.expand))

        // Files: group by what owns the location.
        var groups: [String: (detail: Set<String>, ops: Set<String>, order: Int)] = [:]
        func add(_ title: String, _ detail: String, _ ops: [String], _ order: Int) {
            var g = groups[title] ?? ([], [], order)
            if !detail.isEmpty { g.detail.insert(detail) }
            g.ops.formUnion(ops)
            groups[title] = g
        }
        for rule in allowed where !Set(rule.operations).isDisjoint(with: fileOps) {
            if rule.filter.kind == .fileTypes {
                let types = (rule.filter.value ?? "").split(separator: ",").map { ".\($0)" }
                if let label = rule.label, let category = FileCategory(rawValue: label) {
                    let shown = types.prefix(6).joined(separator: ", ") + (types.count > 6 ? " +\(types.count - 6) more" : "")
                    add("All \(category.noun)", "anywhere (added by you): \(shown)", rule.operations, 3)
                } else {
                    add("All " + types.joined(separator: ", ") + " files", "anywhere (added by you)", rule.operations, 3)
                }
                continue
            }
            guard let raw = rule.filter.value else { add("Any file", "", rule.operations, 9); continue }
            let path = environment.expand(raw)
            let short = environment.abbreviate(path)
            if path.isWithin(bundle) {
                add("The app itself", "", rule.operations, 0)
            } else if let anchor = anchors.first(where: { path.isWithin($0) }) {
                add("Its own data", environment.abbreviate(anchor), rule.operations, 1)
            } else if path.hasPrefix("/dev/") || path == "/dev" {
                add("Devices", short, rule.operations, 6)
            } else if Generalizer.contentRoots.contains(where: { path.isWithin(environment.home + "/" + $0) }) {
                add(short, "", rule.operations, 2)
            } else if systemRoots.contains(where: { path.isWithin($0) }) || path == "/" {
                add("System files", short, rule.operations, 5)
            } else {
                add("Other locations", short, rule.operations, 7)
            }
        }
        s.files = groups.sorted { ($0.value.order, $0.key) < ($1.value.order, $1.key) }.map { title, g in
            let shown = g.detail.sorted()
            let detail = shown.count > 4 ? shown.prefix(4).joined(separator: ", ") + " +\(shown.count - 4) more"
                                         : shown.joined(separator: ", ")
            return Item(title: title, detail: detail, access: RuleText.access(Array(g.ops)))
        }

        // Network.
        for rule in allowed where rule.operations.contains(where: { $0.hasPrefix("network-") }) {
            s.network.append(Item(title: RuleText.describe(rule), detail: "", access: RuleText.access(rule.operations)))
        }

        // Programs it may launch (beyond its own bundle).
        for rule in allowed where rule.operations.contains("process-exec*") {
            guard let raw = rule.filter.value, !environment.expand(raw).isWithin(bundle) else { continue }
            s.launches.append(Item(title: (raw as NSString).lastPathComponent,
                                   detail: environment.abbreviate(environment.expand(raw)), access: "run"))
        }

        // Services and settings: always-on platform access plus anything learned beyond it (ADR-004).
        s.services.append(Item(title: "Apple system services", detail: "always allowed", access: "use"))
        s.services.append(Item(title: "Apple & global settings", detail: "always allowed", access: "read"))
        if let id = config.target.bundleId {
            s.services.append(Item(title: "Its own settings", detail: id, access: "read & write"))
        }
        let otherServices = allowed.filter {
            $0.operations == ["mach-lookup"] && !($0.filter.value ?? "").hasPrefix("com.apple.")
        }.compactMap(\.filter.value)
        if !otherServices.isEmpty {
            s.services.append(Item(title: "Other services", detail: otherServices.sorted().joined(separator: ", "), access: "use"))
        }
        let hardware = allowed.filter { $0.operations == ["iokit-open-user-client"] }.count
        if hardware > 0 {
            s.services.append(Item(title: "Hardware interfaces", detail: "\(hardware) learned", access: "use"))
        }

        // Sensitive: what hardening blocks, flagged first.
        let hardening = config.hardening
        s.protectedCount = hardening.filter { $0.action == .deny }.count
        for rule in hardening where rule.flagged == true || (rule.action == .allow && rule.id.hasPrefix("H-") && !rule.id.hasPrefix("H-own")) {
            let title = rule.note?.components(separatedBy: ".").first ?? rule.id
            let state = rule.action == .deny ? "blocked" : "allowed"
            let detail = rule.flagged == true ? "tried during learning (\(rule.seen)×)" : "allowed by you or as its own data"
            s.sensitive.append(Item(title: title, detail: detail, access: state, flagged: rule.flagged == true))
        }
        s.sensitive.sort { $0.flagged && !$1.flagged }
        s.applyTemplates(config)
        return s
    }

    /// Templates override learned allows, so the summary must say what really applies.
    mutating func applyTemplates(_ config: MenshenConfig) {
        let templates = Set(config.templates ?? [])
        if templates.contains(.offline) {
            network = network.filter { $0.title.contains("DNS") || $0.title.contains("system log") || $0.title.contains("local socket") }
            network.append(Item(title: "All internet and local-network connections", detail: "Offline template", access: "blocked"))
        }
        if templates.contains(.tempOnly) {
            files = files.compactMap { item in
                var item = item
                if item.access == "write" { return nil }
                if item.access == "read & write" { item.access = "read" }
                return item
            }
            files.append(Item(title: "Writes", detail: "temp folders only (Temp-only template)", access: "write"))
        }
        if templates.contains(.noLaunch) {
            launches = [Item(title: "Other programs", detail: "No other programs template", access: "blocked")]
        }
        for template in Template.allCases where templates.contains(template) {
            restrictions.append(Item(title: template.title, detail: template.explanation, access: "on"))
        }
        if let seconds = config.limits?.cpuSeconds {
            restrictions.append(Item(title: "CPU time limit", detail: "stopped after \(seconds) s of CPU time", access: "limit"))
        }
        if let mb = config.limits?.memoryMB {
            restrictions.append(Item(title: "Memory limit", detail: "killed above \(mb) MiB", access: "limit"))
        }
    }
}
