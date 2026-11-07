import AppKit
import Carbon
import MenshenCore

/// The executable inside a Menshen launcher bundle (built by `Swap.buildLauncher`). Runs the
/// hidden original app under `enforce`, passing along the documents/URLs it was opened with.
/// It has no Dock icon (LSUIElement) and exits when the app exits.
final class LauncherDelegate: NSObject, NSApplicationDelegate, @unchecked Sendable {
    let original: URL
    let configURL: URL
    let environment: MenshenEnvironment
    // Mutable state is accessed only on the main thread, including Runner callbacks.
    private(set) var pending: [URL] = []
    private var started = false
    private var targetPID: pid_t?
    private var targetApp: NSRunningApplication?
    private var deliveryTimer: Timer?

    init?(_ info: [String: String]) {
        guard let original = info["original"], let config = info["config"],
              let data = info["dataRoot"], let logs = info["logsRoot"] else { return nil }
        self.original = URL(fileURLWithPath: original)
        self.configURL = URL(fileURLWithPath: config)
        self.environment = .current(dataRoot: URL(fileURLWithPath: data), logsRoot: URL(fileURLWithPath: logs))
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        enqueue(urls)
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // LaunchServices delivers the documents the app was opened with right after launch.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.start() }
    }

    /// Dock click while the app is running: bring it forward instead of starting another copy.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        runningApp()?.activate()
        return false
    }

    func enqueue(_ urls: [URL]) {
        pending += urls
        if started { flushPending() }
    }

    func initialArguments() -> [String] {
        started = true
        defer { pending.removeAll() }
        return pending.map { $0.isFileURL ? $0.path : $0.absoluteString }
    }

    func start() {
        var options = EnforceOptions(target: original.path)
        options.arguments = initialArguments()
        options.configPath = configURL
        options.control = SessionControl(forwardSignals: false)
        options.control.onLaunch = { pid in
            DispatchQueue.main.async { self.targetPID = pid; self.flushPending() }
        }
        deliveryTimer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            self?.flushPending()
        }
        let environment = environment
        Thread.detachNewThread {
            var failure: String?
            do {
                _ = try Enforce.run(options, environment: environment)
            } catch let error as MenshenError {
                failure = error.description
            } catch {
                failure = "\(error)"
            }
            DispatchQueue.main.async {
                self.deliveryTimer?.invalidate()
                self.deliveryTimer = nil
                if let failure { self.alert(failure) }
                else if !self.pending.isEmpty {
                    self.alert("The app exited before it could receive: " + self.pending.map(\.absoluteString).joined(separator: ", "))
                }
                NSApp.terminate(nil)
            }
        }
    }

    /// Address events to the exact process spawned by Runner. Unlike NSWorkspace.open,
    /// sending an Apple event cannot start an unprotected replacement if the app exits.
    func flushPending() {
        guard !pending.isEmpty, let app = runningApp(), app.isFinishedLaunching else { return }
        let urls = pending
        pending.removeAll()
        do {
            for url in urls {
                let event = Self.openEvent(url, pid: app.processIdentifier)
                _ = try event.sendEvent(options: [.noReply, .neverInteract], timeout: 1)
            }
        } catch {
            alert("Couldn't deliver the requested documents or URLs to the protected app: \(error)")
        }
    }

    static func openEvent(_ url: URL, pid: pid_t) -> NSAppleEventDescriptor {
        let event = NSAppleEventDescriptor(
            eventClass: url.isFileURL ? AEEventClass(kCoreEventClass) : AEEventClass(kInternetEventClass),
            eventID: url.isFileURL ? AEEventID(kAEOpenDocuments) : AEEventID(kAEGetURL),
            targetDescriptor: NSAppleEventDescriptor(processIdentifier: pid),
            returnID: AEReturnID(kAutoGenerateReturnID), transactionID: AETransactionID(kAnyTransactionID))
        if url.isFileURL {
            let list = NSAppleEventDescriptor.list()
            list.insert(NSAppleEventDescriptor(fileURL: url), at: 1)
            event.setParam(list, forKeyword: AEKeyword(keyDirectObject))
        } else {
            event.setParam(NSAppleEventDescriptor(string: url.absoluteString), forKeyword: AEKeyword(keyDirectObject))
        }
        return event
    }

    func runningApp() -> NSRunningApplication? {
        guard let pid = targetPID else { return nil }
        if targetApp == nil {
            let candidate = NSRunningApplication(processIdentifier: pid)
            if candidate?.bundleURL?.standardizedFileURL.path == original.standardizedFileURL.path {
                targetApp = candidate
            }
        }
        guard let app = targetApp, !app.isTerminated else { return nil }
        return app
    }

    func alert(_ text: String) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Menshen didn't start \(original.deletingPathExtension().lastPathComponent.trimmingCharacters(in: CharacterSet(charactersIn: ".")))"
        alert.informativeText = text + "\n\nOpen Menshen to review or re-learn the app."
        alert.runModal()
    }
}

guard let info = Bundle.main.object(forInfoDictionaryKey: Swap.markerKey) as? [String: String],
      let delegate = LauncherDelegate(info) else {
    FileHandle.standardError.write(Data("menshen-launch: not inside a Menshen launcher bundle\n".utf8))
    exit(64)
}
let app = NSApplication.shared
app.delegate = delegate
app.run()
