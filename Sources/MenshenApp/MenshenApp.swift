import AppKit
import MenshenCore
import SwiftUI

// UI state lives in @Observable models (AppStore, LiveSession). SwiftUI's own state macros
// (@State) need a compiler plugin the Command Line Tools don't ship, so views take bindings
// from `Bindable(model)` or `Binding(get:set:)` instead.

/// Files dropped on the Dock icon (or opened with Menshen) arrive here.
final class AppDelegate: NSObject, NSApplicationDelegate {
    var store: AppStore?
    func application(_ application: NSApplication, open urls: [URL]) {
        store?.open(urls)
    }
}

@main
struct MenshenApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
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
                .onAppear { delegate.store = store }
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
            if let item = store.selectedItem {
                DetailView(store: store, item: item)
            } else {
                ContentUnavailableView("No app selected", systemImage: "shield.lefthalf.filled",
                                       description: Text("Add an app with + or drop one here, then learn how it behaves."))
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
        .safeAreaInset(edge: .bottom) { RestrictedDropZone(store: store).padding(10) }
        .sheet(isPresented: Bindable(store).editingRestricted) { RestrictedSettingsView(store: store) }
        .toolbar {
            ToolbarItemGroup {
                Button { store.pickApp() } label: { Label("Add App", systemImage: "plus") }
                Button { store.refresh() } label: { Label("Refresh", systemImage: "arrow.clockwise") }
                Button { store.editingRestricted = true } label: { Label("Restricted Sandbox", systemImage: "lock.square") }
                    .help("Choose what apps dropped on Menshen may do")
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

/// Drop an app here (or on the Dock icon) and it runs in the Restricted Sandbox.
struct RestrictedDropZone: View {
    let store: AppStore

    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: "lock.square.stack").font(.title)
            Text("Drop an app to run it restricted").font(.callout.bold())
            Text(store.restricted.summary).font(.caption).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Settings…") { store.editingRestricted = true }
                .buttonStyle(.link).font(.caption)
        }
        .frame(maxWidth: .infinity)
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 10).strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [5]))
            .foregroundStyle(.secondary))
        .dropDestination(for: URL.self) { urls, _ in
            store.open(urls)
            return urls.contains { $0.pathExtension == "app" }
        }
        .help("Apps dropped here or on Menshen's Dock icon run right away with only the access chosen in Settings. No learning needed.")
    }
}

/// What dropped apps may do.
struct RestrictedSettingsView: View {
    let store: AppStore

    var body: some View {
        let box = Bindable(store)
        VStack(alignment: .leading, spacing: 14) {
            Text("Restricted Sandbox").font(.title2.bold())
            Text("Apps you drop on Menshen run with only this access. Secrets (SSH keys, .env files, keychains, browser and chat data) are always blocked.")
                .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Toggle("Network (internet and local network)", isOn: box.restricted.network)
            Toggle("Start other programs", isOn: box.restricted.otherPrograms)
            Toggle("Keep its own settings and caches in ~/Library", isOn: box.restricted.ownData)
            FolderList(title: "Read & write folders", empty: "None: it can write only to temp folders.",
                       paths: store.restricted.readWrite, add: { store.addRestrictedFolder(writable: true) },
                       remove: { store.restricted.readWrite.remove(at: $0); store.saveRestricted() })
            FolderList(title: "Read-only folders", empty: "None: nothing else in your home folder is readable.",
                       paths: store.restricted.readOnly, add: { store.addRestrictedFolder(writable: false) },
                       remove: { store.restricted.readOnly.remove(at: $0); store.saveRestricted() })
            HStack {
                Text(store.restricted.summary).font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Done") { store.editingRestricted = false }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 520)
        .onChange(of: store.restricted) { store.saveRestricted() }
    }
}

struct FolderList: View {
    let title: String
    let empty: String
    let paths: [String]
    let add: () -> Void
    let remove: (Int) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(title).font(.headline)
                Spacer()
                Button { add() } label: { Image(systemName: "plus") }.buttonStyle(.borderless)
            }
            if paths.isEmpty {
                Text(empty).font(.caption).foregroundStyle(.secondary)
            }
            ForEach(Array(paths.enumerated()), id: \.offset) { i, path in
                HStack {
                    Image(systemName: "folder")
                    Text(path).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Button { remove(i) } label: { Image(systemName: "minus.circle") }.buttonStyle(.borderless)
                }
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
            }
            .padding(.horizontal).padding(.vertical, 10)
            Divider()
            switch store.tab {
            case .dashboard: DashboardView(store: store, item: item)
            case .session: SessionView(store: store, item: item)
            case .history: HistoryView(store: store, item: item)
            case .config: ConfigView(store: store, item: item)
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
}

extension Verdict {
    var color: Color { self == .deny ? .red : .secondary }
}
