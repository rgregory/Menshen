import AppKit
import MenshenCore

/// The executable inside a Menshen launcher bundle (built by `Swap.buildLauncher`). Runs the
/// hidden original app under `enforce`, passing along the documents/URLs it was opened with.
/// It has no Dock icon (LSUIElement) and exits when the app exits.
final class LauncherDelegate: NSObject, NSApplicationDelegate {
    let original: URL
    let configURL: URL
    let environment: MenshenEnvironment
    private var pending: [URL] = []
    private var started = false

    init?(_ info: [String: String]) {
        guard let original = info["original"], let config = info["config"],
              let data = info["dataRoot"], let logs = info["logsRoot"] else { return nil }
        self.original = URL(fileURLWithPath: original)
        self.configURL = URL(fileURLWithPath: config)
        self.environment = .current(dataRoot: URL(fileURLWithPath: data), logsRoot: URL(fileURLWithPath: logs))
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        if started { forward(urls) } else { pending += urls }
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

    func start() {
        started = true
        var options = EnforceOptions(target: original.path)
        options.arguments = pending.map { $0.isFileURL ? $0.path : $0.absoluteString }
        options.configPath = configURL
        options.control = SessionControl(forwardSignals: false)
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
                if let failure { self.alert(failure) }
                NSApp.terminate(nil)
            }
        }
    }

    /// Later opens go to the running (protected) instance. Never launch the original directly:
    /// that would run it unprotected.
    func forward(_ urls: [URL]) {
        guard runningApp() != nil else { return }
        NSWorkspace.shared.open(urls, withApplicationAt: original, configuration: NSWorkspace.OpenConfiguration())
    }

    func runningApp() -> NSRunningApplication? {
        NSWorkspace.shared.runningApplications.first {
            $0.bundleURL?.standardizedFileURL.path == original.standardizedFileURL.path
        }
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
