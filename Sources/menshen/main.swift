import Foundation
import MenshenCore

let usage = """
    menshen \(menshenVersion) — confine a macOS app with Seatbelt.

    USAGE
      menshen learn   <App.app | binary> [--duration 10m] [--merge] [--config PATH] [-- app-args…]
      menshen enforce <App.app | binary | config.json> [--duration 10m] [--config PATH] [--allow-changed] [-- app-args…]
      menshen show    <App.app | binary | config.json> [--config PATH]

    learn    Run the app with everything allowed and every operation reported, then write a
             config: the learned baseline plus hardening (credentials, other apps' data and
             persistence locations are denied even if the app touched them; those are FLAGGED).
    enforce  Run the app under the config. Denials and risky allows (network, process
             launches, writes outside the app's folders) go to a JSONL log.
    show     Print the SBPL profile the config compiles to.

    Configs:  ~/Library/Application Support/Menshen/profiles/<bundle-id>.json
    Logs:     ~/Library/Logs/Menshen/<bundle-id>/<timestamp>.jsonl
    """

func say(_ message: String) {
    FileHandle.standardError.write(Data("menshen: \(message)\n".utf8))
}

struct Parsed {
    var command = ""
    var target: String?
    var appArgs: [String] = []
    var duration: TimeInterval?
    var merge = false
    var allowChanged = false
    var config: URL?
}

func parseDuration(_ text: String) throws -> TimeInterval {
    let units: [Character: Double] = ["s": 1, "m": 60, "h": 3600]
    if let unit = text.last, let mult = units[unit], let n = Double(text.dropLast()), n > 0 { return n * mult }
    if let n = Double(text), n > 0 { return n }
    throw MenshenError.usage("bad --duration \(text) (use e.g. 90s, 10m, 1h)")
}

func parse(_ argv: [String]) throws -> Parsed {
    var p = Parsed()
    var args = argv[...]
    guard let command = args.popFirst() else { throw MenshenError.usage("missing command\n\n\(usage)") }
    p.command = command
    while let arg = args.popFirst() {
        switch arg {
        case "--":
            p.appArgs = Array(args)
            args = []
        case "--duration":
            guard let v = args.popFirst() else { throw MenshenError.usage("--duration needs a value") }
            p.duration = try parseDuration(v)
        case "--config":
            guard let v = args.popFirst() else { throw MenshenError.usage("--config needs a path") }
            p.config = URL(fileURLWithPath: (v as NSString).expandingTildeInPath)
        case "--merge": p.merge = true
        case "--allow-changed": p.allowChanged = true
        default:
            if arg.hasPrefix("--") { throw MenshenError.usage("unknown option \(arg)") }
            guard p.target == nil else { throw MenshenError.usage("unexpected argument \(arg) (put app arguments after --)") }
            p.target = (arg as NSString).expandingTildeInPath
        }
    }
    return p
}

func runLearn(_ p: Parsed, _ target: String) throws -> Int32 {
    var options = LearnOptions(target: target)
    options.arguments = p.appArgs
    options.duration = p.duration
    options.merge = p.merge
    options.configPath = p.config
    let s = try Learn.run(options, say: say)
    let flagged = s.config.hardening.filter { $0.flagged == true }
    say("captured \(s.eventsThisRun) reports from \(s.processes.count) process(es): \(s.processes.sorted().joined(separator: ", "))")
    say("config: \(s.configURL.path)  (\(s.config.rules.count) learned rules, \(s.config.hardening.count) hardening rules, learned over \(s.config.learning.runs) run(s))")
    if let backup = s.backupURL { say("previous config backed up to \(backup.path)") }
    say("raw capture: \(s.captureURL.path)")
    if flagged.isEmpty {
        say("no sensitive access seen.")
    } else {
        say("FLAGGED, denied by default (edit the config to allow):")
        for rule in flagged { say("  \(rule.id): \(rule.note ?? "")") }
    }
    for warning in s.config.learning.warnings { say("note: \(warning)") }
    return 0
}

func runEnforce(_ p: Parsed, _ target: String) throws -> Int32 {
    var options = EnforceOptions(target: target)
    options.arguments = p.appArgs
    options.configPath = p.config
    options.allowChanged = p.allowChanged
    options.duration = p.duration
    let s = try Enforce.run(options, say: say)
    let allows = s.reportedAllows.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " ")
    say("done. \(s.denials) denial(s) (\(s.uniqueDenials) distinct); reported allows: \(allows.isEmpty ? "none" : allows)")
    say("log: \(s.logURL.path)")
    if !s.drained { say("note: the log stream didn't confirm it caught up; the last events may be missing.") }
    if s.streamNotices > 0 { say("note: log stream reported \(s.streamNotices) notice(s), possibly dropped messages.") }
    if s.outcome.stoppedByMenshen { return 0 }
    return s.outcome.wasSignaled ? 128 + s.outcome.status : s.outcome.status
}

func runShow(_ p: Parsed, _ target: String) throws -> Int32 {
    var options = EnforceOptions(target: target)
    options.configPath = p.config
    let env = MenshenEnvironment.current()
    let (url, config) = try Enforce.locateConfig(options, environment: env)
    print(ProfileCompiler(environment: env).compile(config, source: url.path), terminator: "")
    return 0
}

let argv = Array(CommandLine.arguments.dropFirst())
do {
    if argv.isEmpty || ["-h", "--help", "help"].contains(argv[0]) {
        print(usage)
        exit(argv.isEmpty ? 64 : 0)
    }
    if argv[0] == "--version" {
        print("menshen \(menshenVersion)")
        exit(0)
    }
    let p = try parse(argv)
    guard let target = p.target else { throw MenshenError.usage("\(p.command) needs a target\n\n\(usage)") }
    let status: Int32
    switch p.command {
    case "learn": status = try runLearn(p, target)
    case "enforce": status = try runEnforce(p, target)
    case "show": status = try runShow(p, target)
    default: throw MenshenError.usage("unknown command \(p.command)\n\n\(usage)")
    }
    exit(status)
} catch let error as MenshenError {
    say(error.description)
    switch error {
    case .usage: exit(64)
    case .refused: exit(69)
    case .failed: exit(70)
    }
} catch {
    say("error: \(error)")
    exit(70)
}
