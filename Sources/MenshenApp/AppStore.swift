import AppKit
import Foundation
import MenshenCore
import Observation
import UniformTypeIdentifiers

enum DetailTab: String, CaseIterable, Identifiable {
    case overview = "Overview"
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

enum PermissionKind: String, CaseIterable, Identifiable {
    case category = "Category"
    case fileTypes = "File types"
    case folder = "A folder"
    var id: String { rawValue }
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
    @ObservationIgnored private var statusCache: [String: (stamp: Date?, status: WrapStatus)] = [:]

    var entries: [AppEntry] = []
    var added: [AppItem] = []
    private(set) var selection: String?
    var tab: DetailTab = .overview
    /// Which smart list the Overview shows (picked in the sidebar).
    var scope: SidebarScope = .overview
    var message: String?
    /// Unreadable configs already reported, so a refresh doesn't alert about them again.
    @ObservationIgnored private var reportedUnreadable: Set<String> = []

    // Session tab
    var sessions: [String: LiveSession] = [:]
    var learnSeconds = ""
    var learnMerge = true

    // Dashboard: the most-blocked attempts from the newest enforce run
    var lastRecords: [EnforceRecord] = []
    var lastEnforce: Date?
    @ObservationIgnored private var followers: [String: LogFollower] = [:]
    @ObservationIgnored private var watchTimer: Timer?

    // History tab
    var history: [SessionInfo] = []

    // Overview: each learned app's newest enforce run, summarized (cached per log file)
    var overview: [String: (date: Date, activity: ActivitySummary)] = [:]
    @ObservationIgnored private var overviewCache: [String: (stamp: Date?, activity: ActivitySummary)] = [:]
    private(set) var historySelection: String?
    var historyRows: [EventRow] = []
    var historyFilter: RowFilter = .all
    var historySearch = ""

    // Config tab: unsaved edits per app, so switching apps doesn't lose them
    var drafts: [String: MenshenConfig] = [:]
    var ruleFilter: RuleFilter = .all
    var ruleSearch = ""
    var sbplText: String?

    // Add Permission sheet
    var addingPermission = false
    /// Opened from the Dashboard: the new permission is saved at once, not added to Config's draft.
    var permissionAppliesNow = false
    var newAccess: CustomAccess = .read
    var newKind: PermissionKind = .category
    var newCategory: FileCategory = .media
    var newValue = ""

    /// The app waiting for "Remove from Menshen" confirmation.
    var removing: AppItem?

    // Replace / Restore confirmation
    var confirmingReplace = false
    var confirmingRestore = false

    init() {
        refresh()
        watchTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.watchReplacedApps() }
    }

    var items: [AppItem] {
        entries.map { AppItem(id: $0.id, name: $0.config.target.name, appPath: $0.appPath, entry: $0) }
            + added.filter { a in !entries.contains { $0.id == a.id } }
    }

    var selectedItem: AppItem? { items.first { $0.id == selection } }

    func refresh() {
        entries = Library.apps(environment)
        let unreadable = Library.unreadableConfigs(environment).filter { !reportedUnreadable.contains($0.url.path) }
        if !unreadable.isEmpty, message == nil {
            reportedUnreadable.formUnion(unreadable.map(\.url.path))
            message = "These configs didn't load, so their apps aren't listed. If you didn't edit them, something else did.\n\n"
                + unreadable.map { "\($0.url.lastPathComponent): \($0.reason)" }.joined(separator: "\n\n")
        }
        refreshOverview()
        added.removeAll { a in entries.contains { $0.id == a.id } }
        if let key = selection {
            history = Library.sessions(key, environment)
            let newest = history.first { $0.kind == .enforce }
            lastEnforce = newest?.date
            lastRecords = newest.map { Library.records($0.url) } ?? []
            if let entry = entries.first(where: { $0.id == key }), drafts[key] == nil {
                drafts[key] = entry.config
            }
        }
    }

    /// The newest enforce run of every learned app. Logs are re-read only when they change.
    private func refreshOverview() {
        var result: [String: (date: Date, activity: ActivitySummary)] = [:]
        for entry in entries {
            guard let newest = Library.sessions(entry.id, environment).first(where: { $0.kind == .enforce }) else { continue }
            let stamp = (try? FileManager.default.attributesOfItem(atPath: newest.url.path))?[.modificationDate] as? Date
            let activity: ActivitySummary
            if let cached = overviewCache[newest.url.path], cached.stamp == stamp {
                activity = cached.activity
            } else {
                activity = ActivitySummary.make(Library.records(newest.url))
                overviewCache[newest.url.path] = (stamp, activity)
            }
            result[entry.id] = (newest.date, activity)
        }
        overview = result
    }

    /// Opens one app's Dashboard (from the Overview).
    func open(_ item: AppItem) {
        select(item.id)
        tab = .dashboard
    }

    /// Shows one of the sidebar's smart lists.
    func showScope(_ scope: SidebarScope) {
        self.scope = scope
        tab = .overview
    }

    func select(_ key: String?) {
        // Picking an app while the Overview is showing opens that app.
        if key != nil && tab == .overview { tab = .dashboard }
        guard key != selection else { return }
        selection = key
        historySelection = nil
        historyRows = []
        sbplText = nil
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
            // A replaced app's launcher stands for the hidden original.
            let target = try ResolvedTarget.resolve(Swap.resolveOriginal(url.path))
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

    /// Whether Menshen can wrap the app, checked once per app and kept until the app changes on
    /// disk (views ask on every redraw, which during a live session is several times a second).
    func wrapStatus(_ item: AppItem) -> WrapStatus {
        let stamp = Self.modificationStamp(item.appPath)
        if let cached = statusCache[item.appPath], cached.stamp == stamp { return cached.status }
        let status = WrapStatus.check(item.appPath)
        statusCache[item.appPath] = (stamp, status)
        return status
    }

    /// nil if the app can be wrapped, otherwise the reason it can't.
    func preflightProblem(_ item: AppItem) -> String? {
        wrapStatus(item).problem(name: item.name)
    }

    /// Changes when the app is updated or replaced: its Info.plist (bundles) or the file itself.
    static func modificationStamp(_ path: String) -> Date? {
        let plist = path + "/Contents/Info.plist"
        let target = FileManager.default.fileExists(atPath: plist) ? plist : path
        return (try? FileManager.default.attributesOfItem(atPath: target))?[.modificationDate] as? Date
    }

    // MARK: - Removing apps

    /// Takes the app off the list. A learned app's Menshen data goes to the Trash (the app
    /// itself is untouched); a replaced or running app is refused.
    func remove(_ item: AppItem) {
        if sessions[item.id]?.running == true {
            message = "\(item.name) is running under Menshen. Stop it first."
            return
        }
        if item.entry != nil {
            do {
                try Library.forget(item.id, environment)
            } catch {
                message = "\(error)"
                return
            }
        }
        added.removeAll { $0.id == item.id }
        sessions[item.id] = nil
        drafts[item.id] = nil
        if selection == item.id { select(nil) }
        refresh()
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
        if sessions[key]?.external == true, let swap = entries.first(where: { $0.id == key })?.swap {
            let hidden = swap.hiddenPath
            Swap.runningPIDs(inside: hidden).forEach { kill($0, SIGTERM) }
            // Like the CLI: whatever ignores SIGTERM gets SIGKILL after 5 s.
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                Swap.runningPIDs(inside: hidden).forEach { kill($0, SIGKILL) }
            }
            return
        }
        sessions[key]?.stop.stop()
    }

    /// A replaced app opened from the Dock/Finder runs under its launcher, not under Menshen.
    /// Notice it and follow the launcher's enforce log so the dashboard is live for it too.
    private func watchReplacedApps() {
        for entry in entries {
            guard let swap = entry.swap else { continue }
            let running = !Swap.runningPIDs(inside: swap.hiddenPath).isEmpty
            let session = sessions[entry.id]
            if running, session?.running != true {
                let logs = Library.sessions(entry.id, environment).filter { $0.kind == .enforce }
                guard let newest = logs.first, Date().timeIntervalSince(newest.date) < 120 else { continue }
                let live = LiveSession(kind: .enforce, appName: entry.config.target.name)
                live.external = true
                live.startExternal()
                sessions[entry.id] = live
                followers[entry.id] = LogFollower(url: newest.url)
            }
            if let live = sessions[entry.id], live.external, live.running, let follower = followers[entry.id] {
                live.addFollowed(follower.poll())
                if !running {
                    live.endExternal()
                    followers[entry.id] = nil
                    refresh()
                }
            }
        }
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
        // Same check the CLI makes: don't save a config whose profile the kernel won't load.
        if let error = SBPLCompiler.validate(SBPLCompiler(environment: environment).compile(draft)) {
            message = "Not saved: the profile wouldn't load.\n\n\(error)"
            return
        }
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
        let kind = newKind, access = newAccess, category = newCategory, value = newValue, env = environment
        do {
            let types = kind == .fileTypes ? try MenshenConfig.fileExtensions(value) : []
            if kind == .folder && value.isEmpty { throw MenshenError.usage("choose a folder") }
            let change: (inout MenshenConfig) -> Void = { config in
                switch kind {
                case .category: config.addCustom(access, category: category)
                case .fileTypes: config.addCustom(access, fileTypes: types)
                case .folder: config.addCustom(access, folder: value, environment: env)
                }
            }
            if permissionAppliesNow {
                update(key, change)
            } else {
                guard var draft = drafts[key] else { return }
                change(&draft)
                drafts[key] = draft
            }
            addingPermission = false
            permissionAppliesNow = false
            newValue = ""
        } catch {
            message = "\(error)"
        }
    }

    /// Lets the app read every file of a kind (as macOS classifies them), or stops it, right away.
    func applyCategory(_ key: String, _ category: FileCategory, on: Bool) {
        update(key) { config in
            if on {
                config.addCustom(.read, category: category)
            } else {
                config.rules.removeAll { $0.source == .custom && $0.label == category.rawValue }
            }
        }
    }

    /// Removes one of your rules right away (from the Dashboard).
    func removeRuleNow(_ key: String, ruleID: String) {
        update(key) { $0.removeCustom(ruleID) }
    }

    /// Turns a profile on or off for an app right away (saved with a backup of the previous config).
    func applyProfile(_ key: String, _ profile: Profile, on: Bool) {
        update(key) { config in
            var set = Set(config.profiles ?? [])
            if on { set.insert(profile) } else { set.remove(profile) }
            config.profiles = set.isEmpty ? nil : Profile.allCases.filter { set.contains($0) }
        }
    }

    /// Sets a hard limit right away; empty or zero clears it.
    func applyLimit(_ key: String, _ path: WritableKeyPath<ResourceLimits, Int?>, _ text: String) {
        update(key) { config in
            var limits = config.limits ?? ResourceLimits()
            limits[keyPath: path] = Int(text.trimmingCharacters(in: .whitespaces)).flatMap { $0 > 0 ? $0 : nil }
            config.limits = limits.cpuSeconds == nil && limits.memoryMB == nil ? nil : limits
        }
    }

    /// Changes the saved config and mirrors the same change into any unsaved Config edits, so
    /// a later Save can't undo it.
    private func update(_ key: String, _ change: (inout MenshenConfig) -> Void) {
        guard let entry = entries.first(where: { $0.id == key }) else { return }
        var config = entry.config
        change(&config)
        do {
            try config.save(to: entry.configURL)
        } catch {
            message = "Couldn't save: \(error)"
            return
        }
        if var draft = drafts[key] {
            change(&draft)
            drafts[key] = draft
        }
        refresh()
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

    /// Regenerates the whole profile on every click: re-reads the config from disk (picking up
    /// Dashboard toggles, CLI edits and rebuilds), re-detects the environment, and compiles from
    /// scratch with the current protections. Unsaved Config edits are kept and included.
    func showSandboxRules(_ key: String) {
        let before = entries.first { $0.id == key }?.config
        refresh()
        guard let entry = entries.first(where: { $0.id == key }) else { return }
        if drafts[key] == nil || drafts[key] == before { drafts[key] = entry.config }
        guard let draft = drafts[key] else { return }
        let source = (isDirty(key) ? "\(entry.configURL.path) with unsaved edits" : entry.configURL.path)
            + ", generated \(Date().formatted(date: .omitted, time: .standard))"
        sbplText = SBPLCompiler(environment: MenshenEnvironment.current()).compile(draft, source: source)
    }
}
