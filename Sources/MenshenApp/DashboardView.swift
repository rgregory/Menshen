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
                    let summary = AccessSummary.make(entry.config, environment: store.environment)
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 320), spacing: 16, alignment: .top)],
                              alignment: .leading, spacing: 16) {
                        Card("Files", systemImage: "folder", items: summary.files,
                             empty: "No file access learned")
                        Card("Network", systemImage: "network", items: summary.network,
                             empty: "No network access", footer: "Everything else is blocked.")
                        Card("Launches", systemImage: "terminal", items: summary.launches,
                             empty: "Only runs itself")
                        Card("Services & settings", systemImage: "gearshape.2", items: summary.services, empty: "")
                        Card("Sensitive", systemImage: "lock.shield", items: summary.sensitive,
                             empty: "Nothing sensitive was touched while learning",
                             footer: "\(summary.protectedCount) sensitive locations and behaviors are protected.")
                        Card("Restrictions", systemImage: "lock", items: summary.restrictions,
                             empty: "No templates. Add them in Config.")
                        ReplaceCard(store: store, item: item, entry: entry, problem: problem)
                    }
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
                Divider().frame(height: 24)
                Metric(value: session.total, label: "events")
                Metric(value: session.denied, label: "blocked", color: session.denied > 0 ? .red : .primary)
                if session.kind == .enforce {
                    Metric(value: session.byCategory["network", default: 0], label: "network")
                    Metric(value: session.byCategory["exec", default: 0], label: "launches")
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
            var text = "Learned from \(c.learning.events) reports over \(c.learning.runs) run\(c.learning.runs == 1 ? "" : "s")."
            if entry.swap == nil { text += " Replace it to protect it however it's opened, or Enforce to run it protected now." }
            return text
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
    }
}

/// A titled card listing summary items: title on the left, access level on the right.
struct Card: View {
    let title: String
    let systemImage: String
    let items: [AccessSummary.Item]
    let empty: String
    var footer: String?

    init(_ title: String, systemImage: String, items: [AccessSummary.Item], empty: String, footer: String? = nil) {
        self.title = title
        self.systemImage = systemImage
        self.items = items
        self.empty = empty
        self.footer = footer
    }

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                if items.isEmpty && !empty.isEmpty {
                    Text(empty).foregroundStyle(.secondary)
                }
                ForEach(items) { item in
                    HStack(alignment: .firstTextBaseline) {
                        VStack(alignment: .leading, spacing: 1) {
                            HStack(spacing: 4) {
                                if item.flagged { Image(systemName: "flag.fill").foregroundStyle(.orange).font(.caption) }
                                Text(item.title)
                            }
                            if !item.detail.isEmpty {
                                Text(item.detail).font(.caption).foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        Spacer(minLength: 8)
                        AccessBadge(text: item.access)
                    }
                }
                if let footer {
                    Text(footer).font(.caption).foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(4)
        } label: {
            Label(title, systemImage: systemImage).font(.headline)
        }
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

struct ReplaceCard: View {
    let store: AppStore
    let item: AppItem
    let entry: AppEntry
    let problem: String?

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                if let swap = entry.swap {
                    Text("Replaced. Opening \(item.name) from the Dock, Finder or Spotlight runs it under Menshen.")
                    Text("Original (untouched): \(swap.hiddenPath)").font(.caption).foregroundStyle(.secondary)
                    Button("Restore Original…") { store.confirmingRestore = true }
                } else {
                    Text("Put a launcher in its place so it always runs under Menshen, however it's opened.")
                        .foregroundStyle(.secondary)
                    Button("Replace \(item.name)…") { store.confirmingReplace = true }
                        .disabled(problem != nil || store.sessions[item.id]?.running == true)
                }
                Divider()
                LabeledContent("Team", value: entry.config.target.teamId ?? "none")
                LabeledContent("Code hash", value: String((entry.config.target.cdhash ?? "none").prefix(12)))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(4)
        } label: {
            Label("Replace", systemImage: "arrow.triangle.swap").font(.headline)
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
        let disk = a.counts["read", default: 0] + a.counts["write", default: 0] + a.counts["write-outside", default: 0]
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 22) {
                    Metric(value: a.total, label: "events")
                    Metric(value: a.blocked, label: "blocked", color: a.blocked > 0 ? .red : .primary)
                    Metric(value: a.counts["network", default: 0], label: "network")
                    Metric(value: disk, label: "disk")
                    Metric(value: a.counts["exec", default: 0], label: "launches")
                    Metric(value: a.counts["service", default: 0], label: "services")
                    Spacer()
                }
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 260), spacing: 12, alignment: .top)],
                          alignment: .leading, spacing: 12) {
                    ActivityTile(title: "Blocked", systemImage: "hand.raised", entries: a.blockedTop,
                                 empty: "Nothing blocked", tint: .red)
                    ActivityTile(title: "Network", systemImage: "network", entries: a.network, empty: "No network activity")
                    ActivityTile(title: "Disk", systemImage: "internaldrive", entries: a.disk,
                                 empty: "No file activity outside system files")
                    ActivityTile(title: "Launches", systemImage: "terminal", entries: a.launches, empty: "No other programs")
                    ActivityTile(title: "Services", systemImage: "gearshape.2", entries: a.services, empty: "No service lookups")
                    if !a.devices.isEmpty {
                        ActivityTile(title: "Devices", systemImage: "cpu", entries: a.devices, empty: "")
                    }
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
        VStack(alignment: .leading, spacing: 6) {
            Label(title, systemImage: systemImage).font(.subheadline.bold())
            if entries.isEmpty {
                Text(empty).font(.caption).foregroundStyle(.secondary)
            }
            ForEach(entries) { e in
                HStack(alignment: .firstTextBaseline) {
                    Text(e.label).font(.caption).lineLimit(1).truncationMode(.middle).help(e.label)
                    Spacer(minLength: 6)
                    if !e.detail.isEmpty { Text(e.detail).font(.caption2).foregroundStyle(.secondary) }
                    Text("\(e.count)").font(.caption.monospacedDigit().bold()).foregroundStyle(tint)
                }
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }
}
