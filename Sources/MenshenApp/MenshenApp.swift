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
            .toolbar {
                // In the toolbar, the tabs get their own space and can't be clipped by a narrow window.
                ToolbarItem(placement: .principal) {
                    Picker("View", selection: Bindable(store).tab) {
                        ForEach(DetailTab.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                }
            }
        }
        .alert("Menshen", isPresented: Binding(get: { store.message != nil }, set: { if !$0 { store.message = nil } })) {
            Button("OK") {}
        } message: {
            Text(store.message ?? "")
        }
    }
}

struct SidebarView: View {
    let store: AppStore

    var body: some View {
        List(selection: Binding(get: { store.selection }, set: { store.select($0) })) {
            Section("Apps") {
                ForEach(store.items) { item in
                    SidebarRow(store: store, item: item).tag(item.id)
                        .contextMenu {
                            Button("Remove from Menshen…", role: .destructive) { store.removing = item }
                        }
                }
            }
        }
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
        .toolbar {
            ToolbarItemGroup {
                Button { store.pickApp() } label: { Label("Add App", systemImage: "plus") }
                Button { store.refresh() } label: { Label("Refresh", systemImage: "arrow.clockwise") }
            }
        }
    }
}

struct SidebarRow: View {
    let store: AppStore
    let item: AppItem

    var body: some View {
        HStack(spacing: 8) {
            Image(nsImage: NSWorkspace.shared.icon(forFile: item.appPath))
                .resizable().frame(width: 24, height: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.name).lineLimit(1)
                HStack(spacing: 4) {
                    if let entry = item.entry {
                        Text("\(entry.config.learning.runs) run\(entry.config.learning.runs == 1 ? "" : "s")")
                        if !entry.flagged.isEmpty {
                            Text("· \(entry.flagged.count) flagged").foregroundStyle(.orange)
                        }
                        if entry.swap != nil { Text("· replaced").foregroundStyle(.blue) }
                    } else {
                        if let badge = store.wrapStatus(item).badge {
                            Text(badge).foregroundStyle(.orange)
                                .help(store.preflightProblem(item) ?? "")
                        } else {
                            Text("not learned")
                        }
                    }
                }
                .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if store.sessions[item.id]?.running == true {
                Circle().fill(.green).frame(width: 8, height: 8).help("Running")
            }
        }
    }
}

struct DetailView: View {
    let store: AppStore
    let item: AppItem

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: item.appPath))
                    .resizable().frame(width: 40, height: 40)
                VStack(alignment: .leading) {
                    Text(item.name).font(.title2.bold())
                    Text(item.entry?.config.target.bundleId ?? item.appPath).font(.caption).foregroundStyle(.secondary)
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
            .padding(.horizontal).padding(.vertical, 10)
            Divider()
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
