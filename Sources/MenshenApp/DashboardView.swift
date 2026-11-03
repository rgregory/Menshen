import MenshenCore
import SwiftUI

/// The per-app summary: what the app may access, what it was blocked from, and its status.
struct DashboardView: View {
    let store: AppStore
    let item: AppItem

    var body: some View {
        let session = store.sessions[item.id]
        let problem = store.preflightProblem(item)
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                StatusStrip(store: store, item: item, session: session, problem: problem)
                if let session, session.kind == .enforce {
                    ActivityPanel(title: session.running ? "Live activity" : "This run", live: session.running,
                                  records: session.records)
                } else if !store.lastRecords.isEmpty, let date = store.lastEnforce {
                    ActivityPanel(title: "Last run · \(date.formatted(date: .abbreviated, time: .shortened))",
                                  live: false, records: store.lastRecords)
                }
                if let entry = item.entry {
                    AccessSummaryView(summary: AccessSummary.make(entry.config, environment: store.environment))
                } else {
                    GroupBox {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Menshen hasn't learned \(item.name) yet.").font(.headline)
                            Text("Learning runs it with everything allowed and records what it does. Use it normally, then quit it. Menshen then writes a config that blocks everything else, plus sensitive locations even if the app touched them.")
                                .foregroundStyle(.secondary)
                            Button("Learn \(item.name)") { store.learn(item) }
                                .disabled(problem != nil || session?.running == true)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(6)
                    }
                }
            }
            .padding()
        }
    }
}

/// Top line: protection state, live counters while a session runs, quick actions.
struct StatusStrip: View {
    let store: AppStore
    let item: AppItem
    let session: LiveSession?
    let problem: String?

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            if let session, session.running {
                Circle().fill(session.kind == .enforce ? Color.green : Color.blue).frame(width: 10, height: 10)
                TimelineView(.periodic(from: session.startedAt, by: 1)) { context in
                    Text("\(session.kind.rawValue) · \(elapsed(since: session.startedAt, now: context.date))")
                        .font(.headline)
                }
                if session.kind == .learn {     // enforce runs show their counters in the app header
                    Divider().frame(height: 24)
                    Metric(value: session.total, label: "events")
                    Metric(value: session.denied, label: "blocked", color: session.denied > 0 ? .red : .primary)
                }
                Spacer()
                Button("Stop \(item.name)", role: .destructive) { store.stop(item.id) }
            } else {
                Image(systemName: stateIcon).foregroundStyle(stateColor).font(.title2)
                VStack(alignment: .leading, spacing: 2) {
                    Text(stateTitle).font(.headline)
                    Text(stateDetail).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                }
                Spacer()
                if problem == nil {
                    Button("Learn") { store.learn(item) }
                    if let entry = item.entry {
                        ReplaceButton(store: store, item: item, entry: entry)
                    }
                    Button("Enforce") { store.enforce(item) }
                        .buttonStyle(.borderedProminent)
                        .disabled(item.entry == nil)
                }
            }
        }
        .padding(12)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
    }

    var stateIcon: String {
        if problem != nil { return "xmark.octagon" }
        if item.entry?.swap != nil { return "checkmark.shield.fill" }
        return item.entry == nil ? "questionmark.diamond" : "shield.lefthalf.filled"
    }

    var stateColor: Color {
        if problem != nil { return .red }
        return item.entry?.swap != nil ? .green : (item.entry == nil ? .secondary : .blue)
    }

    var stateTitle: String {
        if problem != nil { return "Can't be protected" }
        if item.entry?.swap != nil { return "Protected whenever it's opened" }
        return item.entry == nil ? "Not learned yet" : "Learned, not running"
    }

    var stateDetail: String {
        if let problem { return problem }
        if let entry = item.entry {
            let c = entry.config
            let identity = "Team \(c.target.teamId ?? "none") · code hash \(String((c.target.cdhash ?? "none").prefix(12)))"
            if let swap = entry.swap {
                return "Opening it from the Dock, Finder or Spotlight runs it under Menshen. Original (untouched): \(swap.hiddenPath). \(identity)"
            }
            return "Learned from \(c.learning.events) reports over \(c.learning.runs) run\(c.learning.runs == 1 ? "" : "s"). Replace it to protect it however it's opened, or Enforce to run it protected now. \(identity)"
        }
        return item.appPath
    }

    func elapsed(since start: Date, now: Date) -> String {
        let s = max(0, Int(now.timeIntervalSince(start)))
        return s < 60 ? "\(s)s" : s < 3600 ? "\(s / 60) min \(s % 60)s" : "\(s / 3600) h \(s % 3600 / 60) min"
    }
}

struct Metric: View {
    let value: Int
    let label: String
    var color: Color = .primary

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("\(value)").font(.title3.monospacedDigit().bold()).foregroundStyle(color)
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
        .lineLimit(1)
        .fixedSize()
    }
}

/// What the app may do, Things-style: files on the left, everything else on the right, each
/// section a light card of one-line rows. A detail that doesn't fit is in the row's tooltip.
struct AccessSummaryView: View {
    let summary: AccessSummary

    var body: some View {
        HStack(alignment: .top, spacing: 24) {
            AccessSection(title: "Files", items: summary.files, empty: "No file access learned")
                .frame(maxWidth: .infinity, alignment: .top)
            VStack(alignment: .leading, spacing: 0) {
                AccessSection(title: "Network", items: summary.network, empty: "No network access",
                              footer: "Everything else is blocked.")
                AccessSection(title: "Launches", items: summary.launches, empty: "Only runs itself")
                AccessSection(title: "Services & settings", items: summary.services, empty: "None")
                AccessSection(title: "Sensitive", items: summary.sensitive, empty: "Nothing touched while learning",
                              footer: "\(summary.protectedCount) locations and behaviors protected.")
            }
            .frame(maxWidth: .infinity, alignment: .top)
        }
    }
}

/// A section heading over one card of rows, hairlines between them.
struct AccessSection: View {
    let title: String
    let items: [AccessSummary.Item]
    let empty: String
    var footer: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ThingsSection(title: title, count: items.isEmpty ? nil : items.count)
            VStack(alignment: .leading, spacing: 0) {
                if items.isEmpty {
                    Text(empty).foregroundStyle(.secondary).padding(.vertical, 7)
                }
                ForEach(Array(items.enumerated()), id: \.element.id) { index, item in
                    if index > 0 { Divider() }
                    AccessRow(item: item)
                }
            }
            .padding(.horizontal, 10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.primary.opacity(0.07)))
            if let footer {
                Text(footer).font(.caption).foregroundStyle(.tertiary).padding(.top, 4).padding(.leading, 2)
            }
        }
    }
}

/// One line: flag, title, detail (truncated in the middle), access badge.
struct AccessRow: View {
    let item: AccessSummary.Item

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            if item.flagged { Image(systemName: "flag.fill").font(.caption).foregroundStyle(.orange) }
            Text(item.title).lineLimit(1).layoutPriority(1)
            Text(item.detail).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            Spacer(minLength: 4)
            AccessBadge(text: item.access)
        }
        .padding(.vertical, 6)
        .help(item.detail.isEmpty ? item.title : "\(item.title)\n\(item.detail)")
    }
}

struct AccessBadge: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }

    var color: Color {
        switch text {
        case "blocked": return .red
        case "allowed": return .orange
        case "read & write", "write": return .purple
        case "run", "connect", "listen": return .blue
        case "on", "limit": return .green
        default: return .secondary
        }
    }
}

/// Replace… or Restore…, with the confirmation that says exactly what moves where.
struct ReplaceButton: View {
    let store: AppStore
    let item: AppItem
    let entry: AppEntry

    var body: some View {
        Group {
            if entry.swap != nil {
                Button("Restore…") { store.confirmingRestore = true }
                    .help("Remove Menshen's launcher and put the original app back")
            } else {
                Button("Replace…") { store.confirmingReplace = true }
                    .help("Put a launcher in its place so it always runs under Menshen, however it's opened")
            }
        }
        .confirmationDialog("Replace \(item.name)?", isPresented: Bindable(store).confirmingReplace) {
            Button("Replace") { store.replace(item) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("""
                Menshen will rename \(item.appPath) to \(Swap.hiddenPath(for: item.appPath)) without changing \
                its contents, and put a launcher with the same name and icon in its place. You can Restore at any time.
                While replaced, the app's own updater may not work, and macOS may ask you to allow Menshen \
                under App Management.
                """)
        }
        .confirmationDialog("Restore \(item.name)?", isPresented: Bindable(store).confirmingRestore) {
            Button("Restore") { store.restore(item) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Menshen will remove its launcher and move the original app back. Quit the app first.")
        }
    }
}

/// What the app is doing (live) or did (last run): network, disk, launches, services, blocked.
struct ActivityPanel: View {
    let title: String
    let live: Bool
    let records: [EnforceRecord]

    var body: some View {
        let a = ActivitySummary.make(records)
        // The counters are in the app header; here only tiles with something in them, and one
        // line for the rest.
        let tiles: [(String, String, [ActivitySummary.Entry], String, Color)] = [
            ("Blocked", "hand.raised", a.blockedTop, "nothing blocked", .red),
            ("Network", "network", a.network, "no network activity", .accentColor),
            ("Disk", "internaldrive", a.disk, "no file activity outside system files", .accentColor),
            ("Launches", "terminal", a.launches, "no other programs", .accentColor),
            ("Services", "gearshape.2", a.services, "no service lookups", .accentColor),
            ("Devices", "cpu", a.devices, "no devices", .accentColor),
        ]
        let quiet = tiles.filter { $0.2.isEmpty }.map(\.3)
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 240), spacing: 10, alignment: .top)],
                          alignment: .leading, spacing: 10) {
                    ForEach(tiles.filter { !$0.2.isEmpty }, id: \.0) { t in
                        ActivityTile(title: t.0, systemImage: t.1, entries: t.2, empty: "", tint: t.4)
                    }
                }
                if !quiet.isEmpty {
                    Text(quiet.joined(separator: " · ").prefix(1).uppercased() + quiet.joined(separator: " · ").dropFirst() + ".")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if !records.isEmpty {
                    Divider()
                    Text("Recent").font(.caption.bold()).foregroundStyle(.secondary)
                    ForEach(Array(records.suffix(8).reversed().enumerated()), id: \.offset) { _, r in
                        HStack(alignment: .firstTextBaseline, spacing: 10) {
                            Text(r.ts.formatted(date: .omitted, time: .standard))
                                .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                                .frame(width: 70, alignment: .leading)
                            AccessBadge(text: r.verdict == .deny ? "blocked" : r.category)
                                .frame(width: 100, alignment: .leading)
                            Text(r.target).font(.caption).lineLimit(1).truncationMode(.middle)
                            Spacer()
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(4)
        } label: {
            HStack(spacing: 6) {
                if live { Circle().fill(.green).frame(width: 8, height: 8) }
                Label(title, systemImage: "waveform.path.ecg").font(.headline)
            }
        }
    }
}

struct ActivityTile: View {
    let title: String
    let systemImage: String
    let entries: [ActivitySummary.Entry]
    let empty: String
    var tint: Color = .accentColor

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(title, systemImage: systemImage).font(.subheadline.bold())
            if entries.isEmpty {
                Text(empty).font(.caption).foregroundStyle(.secondary)
            }
            ForEach(entries) { e in
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(e.label).font(.caption).lineLimit(1).truncationMode(.middle)
                        .help(e.detail.hasPrefix("/") || e.detail.hasPrefix("$") ? e.detail : e.label)
                    Spacer(minLength: 6)
                    // Paths are in the tooltip; only short details (read, blocked, connect) show.
                    if !e.detail.isEmpty && !e.detail.hasPrefix("/") && !e.detail.hasPrefix("$") {
                        Text(e.detail).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                    }
                    Text("\(e.count)").font(.caption.monospacedDigit().bold()).foregroundStyle(tint)
                }
            }
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }
}

/// Profiles: one-click restrictions on top of what the app learned, applied immediately.
struct ProfilesCard: View {
    let store: AppStore
    let entry: AppEntry

    var body: some View {
        let active = Set(entry.config.profiles ?? [])
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                // Text on the left, every switch in one column on the right.
                ForEach(Profile.allCases, id: \.self) { profile in
                    HStack(alignment: .center, spacing: 16) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(profile.title)
                            Text(profile.explanation).font(.caption).foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 0)
                        Toggle(profile.title, isOn: Binding(get: { active.contains(profile) },
                                                            set: { store.applyProfile(entry.id, profile, on: $0) }))
                            .toggleStyle(.switch)
                            .labelsHidden()
                    }
                    if profile != Profile.allCases.last { Divider() }
                }
                Divider()
                HStack {
                    Text("Limits")
                    Spacer(minLength: 16)
                    LimitField(label: "CPU seconds", value: entry.config.limits?.cpuSeconds) {
                        store.applyLimit(entry.id, \.cpuSeconds, $0)
                    }
                    LimitField(label: "Memory MiB", value: entry.config.limits?.memoryMB) {
                        store.applyLimit(entry.id, \.memoryMB, $0)
                    }
                }
                Text("Saves automatically; applies the next time the app runs. Profiles override what was learned; protections stay on.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(4)
        } label: {
            Label("Profiles", systemImage: "slider.horizontal.3").font(.headline)
        }
    }
}

/// Broad read access by kind of file, plus your other rules: `menshen allow` on the Dashboard.
struct FileAccessCard: View {
    let store: AppStore
    let entry: AppEntry

    var body: some View {
        let yours = entry.config.rules.filter { $0.source == .custom }
        let categories = Set(yours.compactMap(\.label))
        let others = yours.filter { $0.label == nil }
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                ForEach(FileCategory.allCases, id: \.self) { category in
                    HStack(alignment: .center, spacing: 16) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(category.title)
                            Text("Read \(category.noun) anywhere, as macOS classifies them.")
                                .font(.caption).foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 0)
                        Toggle(category.title, isOn: Binding(get: { categories.contains(category.rawValue) },
                                                             set: { store.applyCategory(entry.id, category, on: $0) }))
                            .toggleStyle(.switch)
                            .labelsHidden()
                    }
                    Divider()
                }
                ForEach(others) { rule in
                    HStack {
                        Text(RuleText.describe(rule)).lineLimit(1).truncationMode(.middle)
                        Spacer(minLength: 16)
                        Button { store.removeRuleNow(entry.id, ruleID: rule.id) } label: { Image(systemName: "minus.circle") }
                            .buttonStyle(.borderless).help("Remove this rule")
                    }
                }
                VStack(alignment: .leading, spacing: 6) {
                    Button("Add File Types or Folder…") {
                        store.newKind = .fileTypes
                        store.permissionAppliesNow = true
                        store.addingPermission = true
                    }
                    Text("Saves automatically; applies the next time the app runs. Protected files (keys, .env, keychains) stay blocked.").font(.caption).foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(4)
        } label: {
            Label("File access", systemImage: "folder.badge.plus").font(.headline)
        }
        .sheet(isPresented: Binding(get: { store.addingPermission && store.permissionAppliesNow },
                                    set: { if !$0 { store.addingPermission = false; store.permissionAppliesNow = false } })) {
            AddPermissionSheet(store: store, key: entry.id)
        }
    }
}

/// The run's counters, for the app header: live while it runs, otherwise its newest run.
struct RunCounters: View {
    let records: [EnforceRecord]

    var body: some View {
        let a = ActivitySummary.make(records)
        HStack(spacing: 18) {
            Metric(value: a.total, label: "events")
            Metric(value: a.blocked, label: "blocked", color: a.blocked > 0 ? .red : .primary)
            Metric(value: a.counts["network", default: 0], label: "network")
            Metric(value: a.counts["read", default: 0] + a.counts["write", default: 0]
                   + a.counts["write-outside", default: 0], label: "disk")
            Metric(value: a.counts["exec", default: 0], label: "launches")
            Metric(value: a.counts["service", default: 0], label: "services")
        }
    }
}

/// A number field that applies when you press Return or leave it.
struct LimitField: View {
    let label: String
    let value: Int?
    let apply: (String) -> Void

    var body: some View {
        CommitField(label: label, initial: value.map(String.init) ?? "", apply: apply)
            .frame(width: 110)
    }
}

/// An AppKit field that keeps its own text until you press Return or leave it, so typing
/// doesn't save on every keystroke (SwiftUI's @State isn't available with these tools).
private struct CommitField: NSViewRepresentable {
    let label: String
    let initial: String
    let apply: (String) -> Void

    func makeNSView(context: Context) -> NSTextField {
        let field = NSTextField(string: initial)
        field.placeholderString = label
        field.delegate = context.coordinator
        return field
    }

    func updateNSView(_ field: NSTextField, context: Context) {
        if field.currentEditor() == nil { field.stringValue = initial }
        context.coordinator.apply = apply
    }

    func makeCoordinator() -> Coordinator { Coordinator(apply: apply) }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        var apply: (String) -> Void
        init(apply: @escaping (String) -> Void) { self.apply = apply }
        func controlTextDidEndEditing(_ note: Notification) {
            if let field = note.object as? NSTextField { apply(field.stringValue) }
        }
    }
}
