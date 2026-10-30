import Foundation
import MenshenCore
import Observation

/// One row of a live or historical event table.
struct EventRow: Identifiable {
    let id: Int
    let time: Date?
    let verdict: Verdict
    let category: String
    let operation: String
    let target: String
    let process: String
    let count: Int
}

/// Collects rows from background threads; the main thread drains it on a timer so a busy app
/// (thousands of reports per second) can't flood the UI.
private final class RowBuffer: @unchecked Sendable {
    private let lock = NSLock()
    private var rows: [EventRow] = []
    private var next = 0

    func add(time: Date?, verdict: Verdict, category: String, operation: String, target: String,
             process: String, count: Int) {
        lock.withLock {
            rows.append(EventRow(id: next, time: time, verdict: verdict, category: category,
                                 operation: operation, target: target, process: process, count: count))
            next += 1
        }
    }

    func drain() -> [EventRow] {
        lock.withLock {
            defer { rows.removeAll(keepingCapacity: true) }
            return rows
        }
    }
}

/// A learn or enforce run started from the GUI.
@Observable
final class LiveSession {
    enum Kind: String {
        case learn = "Learning"
        case enforce = "Enforcing"
    }

    static let maxRows = 5000

    let kind: Kind
    let appName: String
    let startedAt = Date()
    var running = true
    var status = "Starting…"
    var rows: [EventRow] = []
    var total = 0
    var denied = 0
    var byCategory: [String: Int] = [:]
    var finished: (String, Bool)?   // (summary, succeeded)
    /// Enforce records, for the dashboard's activity panel (capped like `rows`).
    var records: [EnforceRecord] = []
    /// Started by a launcher (the app was opened from the Dock/Finder), followed through its log.
    var external = false
    @ObservationIgnored private var pendingRecords: [EnforceRecord] = []
    @ObservationIgnored private let recordLock = NSLock()

    let stop = StopHandle()
    @ObservationIgnored private let buffer = RowBuffer()
    @ObservationIgnored private var timer: Timer?

    init(kind: Kind, appName: String) {
        self.kind = kind
        self.appName = appName
    }

    /// Runs `work` on a background thread; `work` reports rows through `add…` and returns a summary.
    func start(_ work: @escaping (LiveSession) throws -> String, onFinish: @escaping () -> Void) {
        timer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in self?.flush() }
        Thread.detachNewThread {
            let outcome: (String, Bool)
            do {
                outcome = (try work(self), true)
            } catch {
                outcome = ("\(error)", false)
            }
            DispatchQueue.main.async {
                self.flush()
                self.timer?.invalidate()
                self.running = false
                self.finished = outcome
                self.status = outcome.0
                onFinish()
            }
        }
    }

    func setStatus(_ text: String) {
        DispatchQueue.main.async { self.status = text }
    }

    func add(_ event: SandboxEvent) {
        buffer.add(time: Date(), verdict: event.verdict,
                   category: event.verdict == .deny ? "denied" : "observed",
                   operation: event.operation, target: event.target, process: event.process, count: event.count)
    }

    func add(_ record: EnforceRecord) {
        recordLock.withLock { pendingRecords.append(record) }
        buffer.add(time: record.ts, verdict: record.verdict, category: record.category,
                   operation: record.operation, target: record.target, process: record.process, count: record.count)
    }

    /// For external sessions: records read from the launcher's log (main thread).
    func addFollowed(_ new: [EnforceRecord]) {
        new.forEach(add)
        flush()
    }

    /// For external sessions: the app quit.
    func endExternal() {
        flush()
        timer?.invalidate()
        running = false
        finished = ("\(total) events, \(denied) blocked", true)
        status = "Ended"
    }

    func startExternal() {
        status = "Opened normally (through its launcher)"
        timer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in self?.flush() }
    }

    private func flush() {
        let newRecords: [EnforceRecord] = recordLock.withLock {
            defer { pendingRecords.removeAll(keepingCapacity: true) }
            return pendingRecords
        }
        if !newRecords.isEmpty {
            records.append(contentsOf: newRecords)
            if records.count > Self.maxRows { records.removeFirst(records.count - Self.maxRows) }
        }
        let new = buffer.drain()
        guard !new.isEmpty else { return }
        for row in new {
            total += row.count
            if row.verdict == .deny { denied += row.count }
            byCategory[row.category, default: 0] += row.count
        }
        rows.append(contentsOf: new)
        if rows.count > Self.maxRows { rows.removeFirst(rows.count - Self.maxRows) }
    }
}
