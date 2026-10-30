import Foundation

/// What a running (or finished) enforce session did, grouped for the live dashboard.
public struct ActivitySummary: Sendable {
    public struct Entry: Identifiable, Sendable {
        public var id: String { label }
        public var label: String
        public var detail: String
        public var count: Int
    }

    public var total = 0
    public var blocked = 0
    public var counts: [String: Int] = [:]
    public var network: [Entry] = []
    public var disk: [Entry] = []
    public var launches: [Entry] = []
    public var services: [Entry] = []
    public var devices: [Entry] = []
    public var blockedTop: [Entry] = []

    public static func make(_ records: [EnforceRecord], limit: Int = 6) -> ActivitySummary {
        var s = ActivitySummary()
        var network = Group(), disk = Group(), launches = Group(), services = Group(), devices = Group(), blocked = Group()
        for r in records {
            s.total += r.count
            s.counts[r.category, default: 0] += r.count
            if r.verdict == .deny {
                s.blocked += r.count
                blocked.add("\(RuleText.verb([group(r.operation)])) \(r.target)", "", r.count)
                continue
            }
            switch r.category {
            case "network":
                network.add(networkLabel(r.target), r.operation.hasPrefix("network-outbound") ? "connect" : "listen", r.count)
            case "exec":
                let path = Generalizer.path(from: r.target) ?? r.target
                launches.add((path as NSString).lastPathComponent, path, r.count)
            case "service":
                services.add(serviceName(r.target), "", r.count)
            case "device":
                devices.add(r.target, "", r.count)
            case "read", "write", "write-outside":
                let path = Generalizer.path(from: r.target) ?? r.target
                let folder = (path as NSString).deletingLastPathComponent
                disk.add(folder.isEmpty ? path : folder, r.category == "read" ? "read" : "write", r.count)
            default:
                break
            }
        }
        s.network = network.top(limit)
        s.disk = disk.top(limit)
        s.launches = launches.top(limit)
        s.services = services.top(limit)
        s.devices = devices.top(limit)
        s.blockedTop = blocked.top(limit)
        return s
    }

    /// "port 443 (HTTPS)", "DNS lookups", "the system log", or the socket path.
    static func networkLabel(_ target: String) -> String {
        for (prefix, kind) in [("remote:", FilterKind.remote), ("local:", FilterKind.local)] where target.hasPrefix(prefix) {
            let address = String(target.dropFirst(prefix.count))
            let host = address.hasPrefix("localhost") || address.hasPrefix("127.") ? "localhost" : "*"
            let port = address.split(separator: ":").last.map(String.init) ?? ""
            return RuleText.object(Filter(kind, "\(host):\(port)"))
        }
        return RuleText.socketName(target) ?? target
    }

    static func serviceName(_ target: String) -> String {
        for suffix in [" (xpc)", " (per-pid)"] where target.hasSuffix(suffix) {
            return String(target.dropLast(suffix.count))
        }
        return target
    }

    /// Kernel operation names (file-write-create) → the rule groups RuleText knows (file-write*).
    static func group(_ op: String) -> String {
        if op.hasPrefix("file-write") { return "file-write*" }
        if op.hasPrefix("file-read") { return "file-read*" }
        if op.hasPrefix("process-exec") { return "process-exec*" }
        return op
    }

    struct Group {
        var counts: [String: Int] = [:]
        var details: [String: Set<String>] = [:]

        mutating func add(_ label: String, _ detail: String, _ count: Int) {
            counts[label, default: 0] += count
            if !detail.isEmpty { details[label, default: []].insert(detail) }
        }

        func top(_ n: Int) -> [Entry] {
            counts.sorted { ($0.value, $1.key) > ($1.value, $0.key) }.prefix(n).map { label, count in
                let d = details[label] ?? []
                let detail = d == ["read", "write"] ? "read & write" : d.sorted().joined(separator: ", ")
                return Entry(label: label, detail: detail, count: count)
            }
        }
    }
}

/// Follows an enforce log as it grows (for sessions run by a launcher, outside the GUI).
public final class LogFollower: @unchecked Sendable {
    public let url: URL
    private var offset: UInt64 = 0
    private var partial = Data()
    private let decoder: JSONDecoder

    public init(url: URL) {
        self.url = url
        decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
    }

    /// Records appended since the last call. A half-written last line is kept for next time.
    public func poll() -> [EnforceRecord] {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return [] }
        defer { try? handle.close() }
        try? handle.seek(toOffset: offset)
        let data = handle.readDataToEndOfFile()
        offset += UInt64(data.count)
        partial.append(data)
        guard let lastNewline = partial.lastIndex(of: 0x0A) else { return [] }
        let complete = partial[partial.startIndex...lastNewline]
        partial = Data(partial[partial.index(after: lastNewline)...])
        return complete.split(separator: 0x0A).compactMap { try? decoder.decode(EnforceRecord.self, from: Data($0)) }
    }
}
