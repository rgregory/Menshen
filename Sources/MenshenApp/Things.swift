import AppKit
import MenshenCore
import SwiftUI

// Things 3–inspired styling: a quiet sidebar with smart lists on top, big bold titles,
// thin accent-colored section rules, pill tabs instead of a segmented control, and content
// held in a centered reading column.

enum Things {
    static let titleFont = Font.system(size: 26, weight: .bold)
    static let sectionFont = Font.system(size: 13, weight: .semibold)
    /// Width of the centered content column (Overview lists).
    static let column: CGFloat = 760
    static let gutter: CGFloat = 32
}

/// The smart lists at the top of the sidebar (Things' Inbox / Today / Upcoming…).
enum SidebarScope: String, CaseIterable, Identifiable {
    case unlearned = "Not Learned"
    case overview = "Overview"
    case running = "Running"
    case review = "Needs Review"

    var id: String { rawValue }
    /// Sidebar selection tag; app rows use the app's key instead.
    var tag: String { "scope:" + rawValue }

    var icon: String {
        switch self {
        case .unlearned: "tray.fill"
        case .overview: "shield.lefthalf.filled"
        case .running: "play.circle.fill"
        case .review: "flag.fill"
        }
    }

    var tint: Color {
        switch self {
        case .unlearned: .blue
        case .overview: .yellow
        case .running: .green
        case .review: .orange
        }
    }

    var blurb: String {
        switch self {
        case .unlearned: "Added apps waiting for a learning run"
        case .overview: "Every learned app and its newest run"
        case .running: "Apps running under Menshen right now"
        case .review: "Apps with flagged rules to look at"
        }
    }

    var emptyTitle: String {
        switch self {
        case .unlearned: "Nothing waiting"
        case .overview: "No learned apps yet"
        case .running: "Nothing running"
        case .review: "All clear"
        }
    }

    var emptyHint: String {
        switch self {
        case .unlearned: "Add an app with + or drop one on the sidebar."
        case .overview: "Learn an app and it shows up here."
        case .running: "Apps you start through Menshen appear here."
        case .review: "No app has flagged rules."
        }
    }
}

extension AppStore {
    func items(in scope: SidebarScope) -> [AppItem] {
        switch scope {
        case .unlearned: items.filter { $0.entry == nil }
        case .overview: items.filter { $0.entry != nil }
        case .running: items.filter { sessions[$0.id]?.running == true }
        case .review: items.filter { !($0.entry?.flagged.isEmpty ?? true) }
        }
    }
}

/// Icon plus a large bold title, with an optional quiet subtitle.
struct ThingsTitle<Icon: View>: View {
    let title: String
    var subtitle: String? = nil
    @ViewBuilder let icon: Icon

    var body: some View {
        HStack(spacing: 12) {
            icon
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(Things.titleFont).lineLimit(1)
                if let subtitle {
                    Text(subtitle).font(.callout).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle)
                }
            }
        }
    }
}

/// A section heading: accent-colored label over a thin rule, count on the right.
struct ThingsSection: View {
    let title: String
    var count: Int? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(title).font(Things.sectionFont).foregroundStyle(Color.accentColor)
                Spacer()
                if let count {
                    Text("\(count)").font(.caption).monospacedDigit().foregroundStyle(.tertiary)
                }
            }
            Rectangle().fill(Color.accentColor.opacity(0.3)).frame(height: 1)
        }
        .padding(.top, 16).padding(.bottom, 4)
    }
}

/// An app's tabs as quiet pills under its title (replaces the toolbar's segmented control).
struct ThingsTabs: View {
    let store: AppStore

    var body: some View {
        HStack(spacing: 4) {
            ForEach(Array(DetailTab.allCases.filter { $0 != .overview }.enumerated()), id: \.element) { index, tab in
                let on = store.tab == tab
                Button { store.tab = tab } label: {
                    Text(tab.rawValue)
                        .font(.callout.weight(on ? .semibold : .regular))
                        .foregroundStyle(on ? Color.primary : Color.secondary)
                        .padding(.horizontal, 11).padding(.vertical, 4)
                        .background(on ? Color.primary.opacity(0.08) : Color.clear, in: Capsule())
                        .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .keyboardShortcut(KeyEquivalent(Character("\(index + 1)")), modifiers: .command)
            }
        }
    }
}

/// A smart list in the sidebar: tinted icon, name, quiet count.
struct ScopeRow: View {
    let store: AppStore
    let scope: SidebarScope

    var body: some View {
        let n = store.items(in: scope).count
        Label {
            HStack {
                Text(scope.rawValue)
                Spacer(minLength: 4)
                if n > 0 { Text("\(n)").monospacedDigit().foregroundStyle(.tertiary) }
            }
        } icon: {
            Image(systemName: scope.icon).foregroundStyle(scope.tint)
        }
    }
}

/// An added-but-unlearned app in the Not Learned list, styled like an open to-do.
struct InboxRow: View {
    let store: AppStore
    let item: AppItem

    var body: some View {
        Button { store.open(item) } label: {
            HStack(spacing: 10) {
                Image(systemName: "circle").font(.system(size: 15)).foregroundStyle(.tertiary)
                Image(nsImage: NSWorkspace.shared.icon(forFile: item.appPath)).resizable().frame(width: 22, height: 22)
                Text(item.name).lineLimit(1)
                if let badge = store.wrapStatus(item).badge {
                    Text(badge).font(.caption).foregroundStyle(.orange)
                }
                Spacer(minLength: 8)
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
            }
            .padding(.vertical, 7).padding(.horizontal, 8)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(store.preflightProblem(item) ?? "Open \(item.name) to learn what it needs")
    }
}
