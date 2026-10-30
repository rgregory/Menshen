import MenshenCore
import SwiftUI

struct HistoryView: View {
    let store: AppStore
    let item: AppItem

    var body: some View {
        HSplitView {
            List(selection: Binding(get: { store.historySelection }, set: { store.selectHistory($0) })) {
                if store.history.isEmpty {
                    Text("No sessions yet").foregroundStyle(.secondary)
                }
                ForEach(store.history) { s in
                    VStack(alignment: .leading, spacing: 2) {
                        Label(s.kind == .learn ? "Learn" : "Enforce",
                              systemImage: s.kind == .learn ? "eye" : "shield")
                            .bold()
                        Text(s.date.formatted(date: .abbreviated, time: .standard)).font(.caption)
                        Text("\(s.events) events" + (s.denials > 0 ? ", \(s.denials) denied" : ""))
                            .font(.caption)
                            .foregroundStyle(s.denials > 0 ? .red : .secondary)
                    }
                    .tag(s.id)
                }
            }
            .frame(minWidth: 200, idealWidth: 230, maxWidth: 300)

            VStack(alignment: .leading) {
                HStack {
                    Picker("Show", selection: Bindable(store).historyFilter) {
                        ForEach(RowFilter.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .frame(width: 220)
                    TextField("Search target, operation or process", text: Bindable(store).historySearch)
                    if let id = store.historySelection {
                        Button("Show in Finder") {
                            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: id)])
                        }
                    }
                }
                if store.historySelection == nil {
                    Spacer()
                    Text("Choose a session").foregroundStyle(.secondary).frame(maxWidth: .infinity)
                    Spacer()
                } else {
                    let rows = store.filteredHistory
                    Text("\(rows.count) of \(store.historyRows.count) records").font(.caption).foregroundStyle(.secondary)
                    EventTable(rows: rows)
                }
            }
            .padding()
        }
    }
}
