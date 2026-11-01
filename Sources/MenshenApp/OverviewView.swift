import AppKit
import MenshenCore
import SwiftUI

/// Every learned app on one screen with its newest run (live while running). Allowances are
/// changed on each app's Dashboard.
struct OverviewView: View {
    let store: AppStore

    var body: some View {
        let learned = store.items.filter { $0.entry != nil }
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                if learned.isEmpty {
                    ContentUnavailableView("No learned apps yet", systemImage: "square.grid.2x2",
                                           description: Text("Learn an app and it shows up here."))
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
        HStack(alignment: .center, spacing: 16) {
            Button { store.open(item) } label: {
                HStack(spacing: 10) {
                    Image(nsImage: NSWorkspace.shared.icon(forFile: item.appPath)).resizable().frame(width: 32, height: 32)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(item.name).font(.headline)
                        Text(status(live: live)).font(.caption).foregroundStyle(live ? .green : .secondary)
                    }
                    .lineLimit(1)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("Open \(item.name)'s Dashboard")
            .frame(width: 220, alignment: .leading)

            Divider().frame(height: 36)

            // What its newest run did: one evenly spaced line, fewer counts when narrow.
            if let a = activity {
                let disk = a.counts["read", default: 0] + a.counts["write", default: 0] + a.counts["write-outside", default: 0]
                let all: [(Int, String)] = [(a.total, "events"), (a.counts["network", default: 0], "network"), (disk, "disk"),
                                            (a.counts["exec", default: 0], "launches"), (a.counts["service", default: 0], "services")]
                ViewThatFits(in: .horizontal) {
                    stats(blocked: a.blocked, all)
                    stats(blocked: a.blocked, Array(all.prefix(3)))
                    stats(blocked: a.blocked, [])
                }
            } else {
                Text("Not run under enforce yet").font(.callout).foregroundStyle(.secondary)
            }
        }
        .padding(14)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
    }

    func stats(blocked: Int, _ items: [(Int, String)]) -> some View {
        HStack(spacing: 0) {
            Stat(value: blocked, label: "blocked", alert: blocked > 0)
            ForEach(items, id: \.1) { Stat(value: $0.0, label: $0.1) }
        }
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
}

/// One count in the Overview's stat line; columns share the width evenly.
struct Stat: View {
    let value: Int
    let label: String
    var alert = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(value.formatted()).font(.title3.monospacedDigit().weight(.semibold))
                .foregroundStyle(alert ? Color.red : Color.primary)
            Text(label).font(.caption).foregroundStyle(alert ? Color.red : Color.secondary)
        }
        .lineLimit(1)
        .fixedSize()
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
