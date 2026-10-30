import AppKit
import Foundation
import MenshenCore
import Observation
import UniformTypeIdentifiers

enum DetailTab: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard"
    case session = "Session"
    case history = "History"
    case config = "Config"
    var id: String { rawValue }
}

enum RowFilter: String, CaseIterable, Identifiable {
    case all = "All"
    case denied = "Denied"
    case network = "Network"
    case exec = "Exec"
    case writes = "Writes outside"
    var id: String { rawValue }

    func matches(_ row: EventRow) -> Bool {
        switch self {
        case .all: return true
        case .denied: return row.verdict == .deny
        case .network: return row.category == "network" || row.operation.hasPrefix("network")
        case .exec: return row.category == "exec" || row.operation.hasPrefix("process-exec")
        case .writes: return row.category == "write-outside"
        }
    }
}

enum RuleFilter: String, CaseIterable, Identifiable {
    case all = "All"
    case flagged = "Flagged"
    case learned = "Learned"
    case hardening = "Hardening"
    case yours = "Yours"
    var id: String { rawValue }
}

/// An app in the sidebar: either configured (learned) or just added.
struct AppItem: Identifiable {
    let id: String
    let name: String
    /// Where the real app is right now (the hidden original while replaced).
    let appPath: String
    let entry: AppEntry?
}

/// All GUI state. Mutated on the main thread only.
@Observable
final class AppStore {
    let environment = MenshenEnvironment.current()
    @ObservationIgnored let stub = Swap.defaultStub()

    var entries: [AppEntry] = []
    var added: [AppItem] = []
    private(set) var selection: String?
    var tab: DetailTab = .dashboard
    var message: String?

    // Session tab
    var sessions: [String: LiveSession] = [:]
    var learnSeconds = ""
    var learnMerge = true

    // Dashboard: the most-blocked attempts from the newest enforce run
    var lastBlocked: [BlockedSummary] = []
    var lastEnforce: Date?

    // History tab
    var history: [SessionInfo] = []
    private(set) var historySelection: String?
    var historyRows: [EventRow] = []
    var historyFilter: RowFilter = .all
    var historySearch = ""

    // Config tab: unsaved edits per app, so switching apps doesn't lose them
    var drafts: [String: MenshenConfig] = [:]
    var ruleFilter: RuleFilter = .all
    var ruleSearch = ""
    var profileText: String?

    // Add Permission sheet
    var addingPermission = false
    var newAccess: CustomAccess = .read
    var newIsFolder = false
    var newValue = ""

    // Replace / Restore confirmation
    var confirmingReplace = false
    var confirmingRestore = false

    init() {
        refresh()
    }

    var items: [AppItem] {
        entries.map { AppItem(id: $0.id, name: $0.config.target.name, appPath: $0.appPath, entry: $0) }
            + added.filter { a in !entries.contains { $0.id == a.id } }
    }

    var selectedItem: AppItem? { items.first { $0.id == selection } }

    func refresh() {
        entries = Library.apps(environment)
        added.removeAll { a in entries.contains { $0.id == a.id } }
        if let key = selection {
            history = Library.sessions(key, environment)
            let newest = history.first { $0.kind == .enforce }
            lastEnforce = newest?.date
            lastBlocked = newest.map { BlockedSummary.top(Library.records($0.url)) } ?? []
            if let entry = entries.first(where: { $0.id == key }), drafts[key] == nil {
                drafts[key] = entry.config
            }
        }
    }

    func select(_ key: String?) {
        guard key != selection else { return }
        selection = key
        historySelection = nil
        historyRows = []
        profileText = nil
        refresh()
    }

    // MARK: - Adding apps

    func pickApp() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.application]
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        panel.allowsMultipleSelection = true
        guard panel.runModal() == .OK else { return }
        panel.urls.forEach(add)
    }

    func add(_ url: URL) {
        do {
            let target = try ResolvedTarget.resolve(url.path)
            let key = target.identity.key
            if !items.contains(where: { $0.id == key }) {
                added.append(AppItem(id: key, name: target.identity.name, appPath: target.identity.path, entry: nil))
            }
            select(key)
            tab = .dashboard
        } catch {
            message = "\(error)"
        }
    }

    /// nil if the app can be wrapped, otherwise the reason it can't.
    func preflightProblem(_ item: AppItem) -> String? {
        do {
            try ResolvedTarget.resolve(item.appPath).preflight()
            return nil
        } catch {
            return "\(error)"
        }
    }

    // MARK: - Sessions

    func learn(_ item: AppItem) {
        let session = LiveSession(kind: .learn, appName: item.name)
        var options = LearnOptions(target: item.appPath)
        options.duration = Double(learnSeconds.trimmingCharacters(in: .whitespaces))
        options.merge = learnMerge && item.entry != nil
        options.control = SessionControl(forwardSignals: false, stop: session.stop)
        options.onEvent = { session.add($0) }
        let env = environment
        sessions[item.id] = session
        session.start({ session in
            let s = try Learn.run(options, environment: env, say: { session.setStatus($0) })
            let flagged = s.config.hardening.filter { $0.flagged == true }.count
            return "Learned \(s.eventsThisRun) reports → \(s.config.rules.count) rules; \(flagged) flagged."
        }, onFinish: { [weak self] in self?.sessionEnded(item.id) })
        tab = .session
    }

    func enforce(_ item: AppItem) {
        guard let entry = item.entry else { return }
        let session = LiveSession(kind: .enforce, appName: item.name)
        var options = EnforceOptions(target: item.appPath)
        options.configPath = entry.configURL
        options.control = SessionControl(forwardSignals: false, stop: session.stop)
        options.onRecord = { session.add($0) }
        let env = environment
        sessions[item.id] = session
        session.start({ session in
            let s = try Enforce.run(options, environment: env, say: { session.setStatus($0) })
            return "\(s.denials) denial(s), \(s.uniqueDenials) distinct. Log: \(s.logURL.lastPathComponent)"
        }, onFinish: { [weak self] in self?.sessionEnded(item.id) })
        tab = .session
    }

    func stop(_ key: String) {
        sessions[key]?.stop.stop()
    }

    private func sessionEnded(_ key: String) {
        // A learn run rewrites the config on disk; pick that up unless the user has unsaved edits.
        if let entry = entries.first(where: { $0.id == key }), drafts[key] == entry.config {
            drafts[key] = nil
        }
        refresh()
    }

    // MARK: - Replace / Restore

    func replace(_ item: AppItem) {
        guard let stub else {
            message = "The launcher stub (menshen-launch) isn't bundled with this build of Menshen."
            return
        }
        do {
            let record = try Swap.replace(item.appPath, stub: stub, environment: environment)
            message = "\(item.name) is replaced. Opening it from the Dock, Finder or Spotlight now runs it under Menshen.\n\nOriginal (untouched): \(record.hiddenPath)"
        } catch {
            message = "\(error)"
        }
        refresh()
    }

    func restore(_ item: AppItem) {
        do {
            let result = try Swap.restore(item.id, environment: environment)
            var text = "\(item.name) is restored to \(result.record.appPath)."
            if !result.signatureValid { text += "\n\nWarning: its code signature does not verify." }
            if result.cdhashChanged { text += "\n\nThe app changed while it was replaced (probably updated); re-learn it before enforcing." }
            message = text
        } catch {
            message = "\(error)"
        }
        refresh()
    }

    // MARK: - History

    func selectHistory(_ id: String?) {
        historySelection = id
        guard let id, let info = history.first(where: { $0.id == id }) else {
            historyRows = []
            return
        }
        switch info.kind {
        case .enforce:
            historyRows = Library.records(info.url).enumerated().map { i, r in
                EventRow(id: i, time: r.ts, verdict: r.verdict, category: r.category, operation: r.operation,
                         target: r.target, process: r.process, count: r.count)
            }
        case .learn:
            historyRows = Library.captureEvents(info.url).enumerated().map { i, e in
                EventRow(id: i, time: nil, verdict: e.verdict, category: e.verdict == .deny ? "denied" : "observed",
                         operation: e.operation, target: environment.abbreviate(e.target), process: e.process, count: e.count)
            }
        }
    }

    var filteredHistory: [EventRow] {
        let search = historySearch.lowercased()
        return historyRows.filter { row in
            historyFilter.matches(row) && (search.isEmpty || row.target.lowercased().contains(search)
                || row.operation.contains(search) || row.process.lowercased().contains(search))
        }
    }

    // MARK: - Config

    func isDirty(_ key: String) -> Bool {
        guard let draft = drafts[key], let entry = entries.first(where: { $0.id == key }) else { return false }
        return draft != entry.config
    }

    func rules(_ key: String) -> [Rule] {
        guard let draft = drafts[key] else { return [] }
        let all = draft.rules + draft.hardening
        let search = ruleSearch.lowercased()
        return all.filter { rule in
            let kept: Bool
            switch ruleFilter {
            case .all: kept = true
            case .flagged: kept = rule.flagged == true
            case .learned: kept = rule.source == .learned
            case .hardening: kept = rule.source == .hardening
            case .yours: kept = rule.source == .custom
            }
            return kept && (search.isEmpty || rule.id.lowercased().contains(search)
                || (rule.filter.value ?? "").lowercased().contains(search)
                || rule.operations.joined(separator: " ").contains(search))
        }
    }

    func setAction(_ key: String, ruleID: String, allow: Bool) {
        guard var draft = drafts[key] else { return }
        let action: RuleAction = allow ? .allow : .deny
        if let i = draft.rules.firstIndex(where: { $0.id == ruleID }) { draft.rules[i].action = action }
        if let i = draft.hardening.firstIndex(where: { $0.id == ruleID }) { draft.hardening[i].action = action }
        drafts[key] = draft
    }

    func save(_ key: String) {
        guard let draft = drafts[key], let entry = entries.first(where: { $0.id == key }) else { return }
        do {
            try draft.save(to: entry.configURL)
            refresh()
        } catch {
            message = "Couldn't save: \(error)"
        }
    }

    func revert(_ key: String) {
        drafts[key] = entries.first { $0.id == key }?.config
    }

    func addPermission(_ key: String) {
        guard var draft = drafts[key] else { return }
        do {
            if newIsFolder {
                guard !newValue.isEmpty else { throw MenshenError.usage("choose a folder") }
                draft.addCustom(newAccess, folder: newValue, environment: environment)
            } else {
                draft.addCustom(newAccess, fileTypes: try MenshenConfig.fileExtensions(newValue))
            }
            drafts[key] = draft
            addingPermission = false
            newValue = ""
        } catch {
            message = "\(error)"
        }
    }

    func removeCustom(_ key: String, ruleID: String) {
        drafts[key]?.removeCustom(ruleID)
    }

    func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        if panel.runModal() == .OK, let url = panel.url { newValue = url.path }
    }

    func showProfile(_ key: String) {
        guard let draft = drafts[key] else { return }
        profileText = ProfileCompiler(environment: environment).compile(draft)
    }
}
