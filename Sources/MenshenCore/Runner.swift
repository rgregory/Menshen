import Foundation

/// Launches the target under a Seatbelt profile. All launching goes through here so the
/// deprecated `sandbox-exec` can be swapped for another launcher later (ADR-001).
public enum Runner {
    public struct Outcome: Sendable {
        public var status: Int32
        public var wasSignaled: Bool
        public var stoppedByMenshen: Bool
    }

    /// Runs `executable` under `profile`, inheriting stdio. Ctrl-C / SIGTERM to Menshen are
    /// forwarded to the target as SIGTERM so Menshen can finish reading the log afterwards.
    /// `onLaunch` gets the pid (sandbox-exec execs into the target, so it is the target's pid).
    /// `tick` runs every 100 ms while the target is alive.
    public static func run(
        profile: URL,
        executable: String,
        arguments: [String],
        duration: TimeInterval?,
        onLaunch: (pid_t) -> Void,
        tick: @escaping @Sendable () -> Void
    ) throws -> Outcome {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
        child.arguments = ["-f", profile.path, executable] + arguments

        let stopped = StopFlag()
        let queue = DispatchQueue(label: "menshen.runner")
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)
        defer {
            signal(SIGINT, SIG_DFL)
            signal(SIGTERM, SIG_DFL)
        }
        let sources = [SIGINT, SIGTERM].map { sig -> DispatchSourceSignal in
            let source = DispatchSource.makeSignalSource(signal: sig, queue: queue)
            source.setEventHandler { stop(child, stopped) }
            source.resume()
            return source
        }
        defer { sources.forEach { $0.cancel() } }

        try child.run()
        onLaunch(child.processIdentifier)

        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now(), repeating: .milliseconds(100))
        timer.setEventHandler(handler: tick)
        timer.resume()
        defer { timer.cancel() }

        if let duration {
            queue.asyncAfter(deadline: .now() + duration) { stop(child, stopped) }
        }
        child.waitUntilExit()
        return Outcome(
            status: child.terminationStatus,
            wasSignaled: child.terminationReason == .uncaughtSignal,
            stoppedByMenshen: stopped.value
        )
    }

    /// SIGTERM now, SIGKILL if the target is still alive 5 s later.
    private static func stop(_ child: Process, _ flag: StopFlag) {
        guard child.isRunning else { return }
        flag.set()
        let pid = child.processIdentifier
        kill(pid, SIGTERM)
        DispatchQueue.global().asyncAfter(deadline: .now() + 5) {
            if child.isRunning { kill(pid, SIGKILL) }
        }
    }
}

private final class StopFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var stopped = false
    var value: Bool { lock.withLock { stopped } }
    func set() { lock.withLock { stopped = true } }
}
