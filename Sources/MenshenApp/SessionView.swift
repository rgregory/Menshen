import MenshenCore
import SwiftUI

struct SessionView: View {
    let store: AppStore
    let item: AppItem

    var body: some View {
        let session = store.sessions[item.id]
        VStack(alignment: .leading, spacing: 12) {
            controls(session)
            if let session {
                counters(session)
                EventTable(rows: session.rows.reversed())
            } else {
                Spacer()
                Text("Learn runs the app with everything allowed and records what it does. Enforce runs it under the config and logs denials and risky actions.")
                    .foregroundStyle(.secondary).frame(maxWidth: 520)
                Spacer()
            }
        }
        .padding()
    }

    @ViewBuilder
    func controls(_ session: LiveSession?) -> some View {
        if let session, session.running {
            HStack {
                ProgressView().controlSize(.small)
                Text("\(session.kind.rawValue) \(session.appName)").bold()
                Text(session.status).foregroundStyle(.secondary).lineLimit(1)
                Spacer()
                Button("Stop \(item.name)", role: .destructive) { store.stop(item.id) }
            }
        } else {
            HStack {
                Button("Learn") { store.learn(item) }
                TextField("seconds (optional)", text: Bindable(store).learnSeconds)
                    .frame(width: 130)
                if item.entry != nil {
                    Toggle("Merge with existing config", isOn: Bindable(store).learnMerge)
                }
                Divider().frame(height: 18)
                Button("Enforce") { store.enforce(item) }
                    .disabled(item.entry == nil)
                Spacer()
                if let (summary, ok) = session?.finished {
                    Label(summary, systemImage: ok ? "checkmark.circle" : "exclamationmark.triangle")
                        .foregroundStyle(ok ? Color.secondary : Color.red)
                        .lineLimit(2)
                }
            }
            .disabled(store.preflightProblem(item) != nil)
        }
    }

    func counters(_ s: LiveSession) -> some View {
        HStack(spacing: 18) {
            stat("Events", s.total)
            stat("Denied", s.denied, color: s.denied > 0 ? .red : .primary)
            if s.kind == .enforce {
                stat("Network", s.byCategory["network", default: 0])
                stat("Exec", s.byCategory["exec", default: 0])
                stat("Writes outside", s.byCategory["write-outside", default: 0])
            }
            Spacer()
            if s.rows.count >= LiveSession.maxRows {
                Text("showing the latest \(LiveSession.maxRows)").font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    func stat(_ label: String, _ value: Int, color: Color = .primary) -> some View {
        VStack(alignment: .leading) {
            Text("\(value)").font(.title3.monospacedDigit()).foregroundStyle(color)
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
    }
}

/// Table shared by the live session and history views.
struct EventTable: View {
    let rows: [EventRow]

    var body: some View {
        Table(rows) {
            TableColumn("Time") { r in
                Text(r.time.map { $0.formatted(date: .omitted, time: .standard) } ?? "")
                    .monospacedDigit()
            }
            .width(min: 70, ideal: 80)
            TableColumn("Verdict") { r in Text(r.verdict.rawValue).foregroundStyle(r.verdict.color) }
                .width(min: 50, ideal: 55)
            TableColumn("Category") { r in Text(r.category) }
                .width(min: 70, ideal: 95)
            TableColumn("Operation") { r in Text(r.operation).font(.system(.body, design: .monospaced)) }
                .width(min: 120, ideal: 170)
            TableColumn("Target") { r in Text(r.target).lineLimit(1).truncationMode(.middle).help(r.target) }
            TableColumn("Process") { r in Text(r.count > 1 ? "\(r.process) ×\(r.count)" : r.process) }
                .width(min: 70, ideal: 100)
        }
    }
}
