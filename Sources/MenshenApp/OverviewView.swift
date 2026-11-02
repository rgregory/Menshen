import AppKit
import MenshenCore
import SwiftUI

/// One of the sidebar's smart lists, Things-style: big title, a centered column of rows, and
/// (on the Overview) running apps in their own section. Allowances are changed on each app's
/// Dashboard.
struct OverviewView: View {
    let store: AppStore

    var body: some View {
        let scope = store.scope
        let shown = store.items(in: scope)
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                ThingsTitle(title: scope.rawValue, subtitle: scope.blurb) {
                    Image(systemName: scope.icon)
                        .font(.system(size: 26, weight: .semibold))
                        .foregroundStyle(scope.tint)
                }
                .padding(.bottom, 8)

                if shown.isEmpty {
                    ContentUnavailableView(scope.emptyTitle, systemImage: scope.icon,
                                           description: Text(scope.emptyHint))
                        .padding(.top, 60)
                } else if scope == .overview {
                    let live = shown.filter { store.sessions[$0.id]?.running == true }
                    let rest = shown.filter { store.sessions[$0.id]?.running != true }
                    if !live.isEmpty {
                        ThingsSection(title: "Running now", count: live.count)
                        rows(live)
                    }
                    if !rest.isEmpty {
                        if !live.isEmpty {
                            ThingsSection(title: "Learned", count: rest.count)
                        }
                        rows(rest)
                    }
                } else {
                    rows(shown)
                }
            }
            .padding(.horizontal, Things.gutter).padding(.vertical, 24)
            .frame(maxWidth: Things.column, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder
    func rows(_ items: [AppItem]) -> some View {
        ForEach(items) { item in
            if let entry = item.entry {
                OverviewRow(store: store, item: item, entry: entry)
            } else {
                InboxRow(store: store, item: item)
            }
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
                Spacer(minLength: 0)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.primary.opacity(0.07)))
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
