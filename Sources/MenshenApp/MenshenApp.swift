import AppKit
import MenshenCore
import SwiftUI

// UI state lives in @Observable models (AppStore, LiveSession). SwiftUI's own state macros
// (@State) need a compiler plugin the Command Line Tools don't ship, so views take bindings
// from `Bindable(model)` or `Binding(get:set:)` instead.

@main
struct MenshenApp: App {
    private let store = AppStore()

    init() {
        // Also behave like a regular app when started as a bare executable (`swift run`).
        NSApplication.shared.setActivationPolicy(.regular)
        DispatchQueue.main.async { NSApplication.shared.activate(ignoringOtherApps: true) }
    }

    var body: some Scene {
        WindowGroup("Menshen") {
            RootView(store: store)
                .frame(minWidth: 960, minHeight: 600)
        }
        .windowToolbarStyle(.unified(showsTitle: false))
    }
}

struct RootView: View {
    let store: AppStore

    var body: some View {
        NavigationSplitView {
            SidebarView(store: store)
                .navigationSplitViewColumnWidth(min: 220, ideal: 250)
        } detail: {
            Group {
                if store.tab != .overview, let item = store.selectedItem {
                    DetailView(store: store, item: item)
                } else {
                    OverviewView(store: store)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .background(Color(nsColor: .textBackgroundColor))
            .toolbarBackground(.hidden, for: .windowToolbar)
        }
        .alert("Menshen", isPresented: Binding(get: { store.message != nil }, set: { if !$0 { store.message = nil } })) {
            Button("OK") {}
        } message: {
            Text(store.message ?? "")
        }
    }
}

/// Things-style sidebar: smart lists on top (Not Learned set apart like an inbox), then the
/// apps, with Add App at the bottom instead of in the toolbar.
struct SidebarView: View {
    let store: AppStore

    var body: some View {
        List(selection: Binding(get: { store.tab == .overview ? Optional(store.scope.tag) : store.selection },
                                set: { key in
                                    if let scope = SidebarScope.allCases.first(where: { $0.tag == key }) {
                                        store.showScope(scope)
                                    } else {
                                        store.select(key)
                                    }
                                })) {
            ScopeRow(store: store, scope: .unlearned).tag(SidebarScope.unlearned.tag)
            Section {
                ForEach([SidebarScope.overview, .running, .review]) { scope in
                    ScopeRow(store: store, scope: scope).tag(scope.tag)
                }
            }
            Section("Apps") {
                ForEach(store.items) { item in
                    SidebarRow(store: store, item: item).tag(item.id)
                        .contextMenu {
                            Button("Remove from Menshen…", role: .destructive) { store.removing = item }
                        }
                }
            }
        }
        .listStyle(.sidebar)
        .onDeleteCommand { store.removing = store.selectedItem }
        .confirmationDialog(store.removing.map { "Remove \($0.name) from Menshen?" } ?? "",
                            isPresented: Binding(get: { store.removing != nil }, set: { if !$0 { store.removing = nil } }),
                            presenting: store.removing) { item in
            Button("Remove", role: .destructive) { store.remove(item) }
            Button("Cancel", role: .cancel) {}
        } message: { item in
            Text(item.entry == nil
                 ? "It's only listed; Menshen stores nothing for it."
                 : "Its config, learning runs and logs move to the Trash, so you can recover them. The app itself isn't touched.")
        }
        .dropDestination(for: URL.self) { urls, _ in
            urls.filter { $0.pathExtension == "app" }.forEach(store.add)
            return true
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            HStack {
                Button { store.pickApp() } label: { Label("Add App", systemImage: "plus") }
                    .keyboardShortcut("o", modifiers: .command)
                    .help("Add an app to Menshen (⌘O)")
                Spacer()
                Button { store.refresh() } label: { Image(systemName: "arrow.clockwise") }
                    .keyboardShortcut("r", modifiers: .command)
                    .help("Refresh (⌘R)")
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
            .padding(.horizontal, 16).padding(.vertical, 10)
        }
    }
}

/// One app in the sidebar: a single quiet line, with one status mark on the right.
struct SidebarRow: View {
    let store: AppStore
    let item: AppItem

    var body: some View {
        let running = store.sessions[item.id]?.running == true
        HStack(spacing: 8) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: item.appPath))
                .resizable().frame(width: 18, height: 18)
            Text(item.name).lineLimit(1)
                .foregroundStyle(item.entry == nil ? Color.secondary : Color.primary)
            Spacer(minLength: 4)
            if running {
                Circle().fill(.green).frame(width: 7, height: 7)
            } else if let entry = item.entry, !entry.flagged.isEmpty {
                Text("\(entry.flagged.count)").monospacedDigit().foregroundStyle(.orange)
            } else if item.entry == nil, store.wrapStatus(item).badge != nil {
                Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
            }
        }
        .help(summary(running: running))
    }

    func summary(running: Bool) -> String {
        var parts: [String] = []
        if running { parts.append("Running") }
        if let entry = item.entry {
            let runs = entry.config.learning.runs
            parts.append("\(runs) learning run\(runs == 1 ? "" : "s")")
            if !entry.flagged.isEmpty { parts.append("\(entry.flagged.count) flagged") }
            if entry.swap != nil { parts.append("replaced") }
        } else if let problem = store.preflightProblem(item) {
            parts.append(problem)
        } else {
            parts.append("Not learned")
        }
        return parts.joined(separator: " · ")
    }
}

/// An app's page: icon and big title, its tabs as pills underneath, then the tab's content.
struct DetailView: View {
    let store: AppStore
    let item: AppItem

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .center) {
                    ThingsTitle(title: item.name, subtitle: item.entry?.config.target.bundleId ?? item.appPath) {
                        Image(nsImage: NSWorkspace.shared.icon(forFile: item.appPath))
                            .resizable().frame(width: 40, height: 40)
                    }
                    Spacer()
                    if store.tab == .dashboard {
                        let session = store.sessions[item.id]
                        if let session, session.kind == .enforce {
                            RunCounters(records: session.records)
                        } else if !store.lastRecords.isEmpty {
                            RunCounters(records: store.lastRecords)
                        }
                    }
                }
                ThingsTabs(store: store)
            }
            .padding(.horizontal, Things.gutter).padding(.top, 20).padding(.bottom, 10)
            switch store.tab {
            case .dashboard: DashboardView(store: store, item: item)
            case .session: SessionView(store: store, item: item)
            case .history: HistoryView(store: store, item: item)
            case .config: ConfigView(store: store, item: item)
            case .overview: EmptyView()     // shown by RootView instead
            }
        }
    }
}

extension Verdict {
    var color: Color { self == .deny ? .red : .secondary }
}
