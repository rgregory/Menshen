import AppKit
import MenshenCore
import SwiftUI

/// Every learned app on one screen: its newest run (live while running) and quick switches
/// for the big allowances. A switch on means allowed; off applies the matching profile.
struct OverviewView: View {
    let store: AppStore

    var body: some View {
        let learned = store.items.filter { $0.entry != nil }
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                if learned.isEmpty {
                    ContentUnavailableView("No learned apps yet", systemImage: "square.grid.2x2",
                                           description: Text("Learn an app, or drop one on the drop zone to run it restricted."))
                }
                ForEach(learned) { item in
                    OverviewRow(store: store, item: item, entry: item.entry!)
                }
            }
            .padding()
        }
    }
}

struct OverviewRow: View {
    let store: AppStore
    let item: AppItem
    let entry: AppEntry

    var body: some View {
        let session = store.sessions[item.id]
        let live = session?.running == true && session?.kind == .enforce
        let activity = live ? ActivitySummary.make(session!.records) : store.overview[item.id]?.activity
        let profiles = Set(entry.config.profiles ?? [])
        HStack(alignment: .center, spacing: 18) {
            Button { store.open(item) } label: {
                HStack(spacing: 10) {
                    Image(nsImage: NSWorkspace.shared.icon(forFile: item.appPath)).resizable().frame(width: 36, height: 36)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(item.name).font(.headline)
                        Text(status(live: live)).font(.caption).foregroundStyle(live ? .green : .secondary)
                    }
                }
                .frame(width: 210, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("Open \(item.name)'s Dashboard")

            if let a = activity {
                Metric(value: a.total, label: "events")
                Metric(value: a.blocked, label: "blocked", color: a.blocked > 0 ? .red : .primary)
                Metric(value: a.counts["network", default: 0], label: "network")
                Metric(value: a.counts["read", default: 0] + a.counts["write", default: 0]
                       + a.counts["write-outside", default: 0], label: "disk")
                Metric(value: a.counts["exec", default: 0], label: "launches")
                Metric(value: a.counts["service", default: 0], label: "services")
            } else {
                Text("Not run under enforce yet").foregroundStyle(.secondary)
            }
            Spacer(minLength: 12)
            Divider().frame(height: 40)
            VStack(alignment: .trailing, spacing: 4) {
                allowance("Network", blockedBy: .offline, profiles)
                allowance("Write files", blockedBy: .tempOnly, profiles)
                allowance("Other programs", blockedBy: .noLaunch, profiles)
            }
            .frame(width: 170)
        }
        .padding(12)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
    }

    func status(live: Bool) -> String {
        if live { return "Running now" }
        var parts: [String] = []
        if entry.swap != nil { parts.append("Replaced") }
        if let date = store.overview[item.id]?.date {
            parts.append("Last run \(date.formatted(date: .abbreviated, time: .shortened))")
        }
        return parts.isEmpty ? "Learned" : parts.joined(separator: " · ")
    }

    /// On = allowed (the profile that blocks it is off). Saved at once, used from the next run.
    func allowance(_ title: String, blockedBy profile: Profile, _ profiles: Set<Profile>) -> some View {
        HStack(spacing: 8) {
            Text(title).font(.callout)
            Spacer(minLength: 0)
            Toggle(title, isOn: Binding(get: { !profiles.contains(profile) },
                                        set: { store.applyProfile(entry.id, profile, on: !$0) }))
                .toggleStyle(.switch).controlSize(.mini).labelsHidden()
        }
        .help(profile.explanation)
    }
}
