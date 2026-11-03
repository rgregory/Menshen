import Foundation
import MenshenCore

let usage = """
    menshen \(menshenVersion) — confine a macOS app with Seatbelt.

    USAGE
      menshen learn   <App.app | binary> [--duration 10m] [--merge] [--config PATH] [-- app-args…]
      menshen enforce <App.app | binary | config.json> [--duration 10m] [--config PATH] [--allow-changed] [-- app-args…]
      menshen rebuild <App.app | binary | config.json> [--config PATH]
      menshen show    <App.app | binary | config.json> [--config PATH]
      menshen allow   <App.app | config.json> [--write] CATEGORY… | TYPES… | FOLDER…   e.g. allow VLC.app media
      menshen allow   <App.app | config.json> --remove RULE-ID
      menshen profile <App.app | config.json> [offline temp-only no-launch] [--cpu-seconds N] [--memory-mb N] [--none]
      menshen forget  <App.app | bundle-id>   move Menshen's data for an app to the Trash
      menshen replace <App.app>       swap the app for a launcher that always runs it under enforce
      menshen restore <App.app | bundle-id>
      menshen swaps                   list replaced apps

    learn    Run the app with everything allowed and every operation reported, then write a
             config: the learned baseline plus hardening (credentials, other apps' data and
             persistence locations are denied even if the app touched them; those are FLAGGED).
    enforce  Run the app under the config. Denials and risky allows (network, process
             launches, writes outside the app's folders) go to a JSONL log.
    rebuild  Regenerate the config from its saved learn captures, without running the app, so
             it picks up improvements in how Menshen turns reports into rules. Keeps your
             rules, profiles, limits and switches. The previous config is backed up.
    show     Print the SBPL profile the config compiles to.
    allow    Add a broad permission of your own: a category as macOS sections file types
             (media, images, documents), some types (mp4 mkv), or a folder (~/Movies).
             Read only unless --write. Protected locations stay blocked.
    profile One-click restrictions on top of what was learned: offline (no network),
             temp-only (writes only to temp folders), no-launch (no other programs).
             Plus hard limits on CPU time and memory. With no names, shows the current ones.
    replace  Rename the app to a hidden .Name.menshen.app (untouched) and put a launcher with
             its name and icon in its place, so Dock/Finder/Spotlight run it under enforce.
    restore  Remove the launcher and put the original back.

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
    var extra: [String] = []
    var write = false
    var remove: String?
    var none = false
    var cpuSeconds: Int?
    var memoryMB: Int?
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
        case "--write": p.write = true
        case "--none": p.none = true
        case "--cpu-seconds", "--memory-mb":
            guard let v = args.popFirst(), let n = Int(v), n > 0 else { throw MenshenError.usage("\(arg) needs a positive number") }
            if arg == "--cpu-seconds" { p.cpuSeconds = n } else { p.memoryMB = n }
        case "--remove":
            guard let v = args.popFirst() else { throw MenshenError.usage("--remove needs a rule ID") }
            p.remove = v
        default:
            if arg.hasPrefix("--") { throw MenshenError.usage("unknown option \(arg)") }
            if p.target != nil, p.command == "allow" || p.command == "profile" {
                p.extra.append(arg)
                continue
            }
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

func runAllow(_ p: Parsed, _ target: String) throws -> Int32 {
    var options = EnforceOptions(target: target)
    options.configPath = p.config
    let env = MenshenEnvironment.current()
    let (url, stored) = try Enforce.locateConfig(options, environment: env)
    var config = stored
    if let id = p.remove {
        guard config.removeCustom(id) else { throw MenshenError.usage("no rule of yours with ID \(id)") }
        try config.save(to: url)
        say("removed \(id). Saved \(url.path)")
        return 0
    }
    guard !p.extra.isEmpty else {
        throw MenshenError.usage("allow needs file types or a folder, e.g.  menshen allow \(target) mp4 mkv")
    }
    // Folders start with /, ~ or ./ ; a category name is a category; anything else is a file type.
    let isFolder = { (s: String) in s.hasPrefix("/") || s.hasPrefix("~") || s.hasPrefix("./") }
    let access: CustomAccess = p.write ? .readWrite : .read
    var added: [Rule] = []
    // Category names (media, images, documents) pick every type macOS puts in that category.
    for category in p.extra.compactMap({ FileCategory(rawValue: $0.lowercased()) }) {
        added.append(config.addCustom(access, category: category))
    }
    let types = p.extra.filter { !isFolder($0) && FileCategory(rawValue: $0.lowercased()) == nil }
    if !types.isEmpty {
        added.append(config.addCustom(access, fileTypes: try MenshenConfig.fileExtensions(types.joined(separator: " "))))
    }
    for folder in p.extra where isFolder(folder) {
        added.append(config.addCustom(access, folder: folder, environment: env))
    }
    if let error = SBPLCompiler.validate(SBPLCompiler(environment: env).compile(config)) {
        throw MenshenError.failed("the new rule doesn't compile, nothing saved:\n\(error)")
    }
    try config.save(to: url)
    for rule in added { say("\(rule.id): \(RuleText.describe(rule))") }
    say("saved \(url.path). Protected locations (like ~/.ssh) stay blocked.")
    return 0
}

func runProfile(_ p: Parsed, _ target: String) throws -> Int32 {
    var options = EnforceOptions(target: target)
    options.configPath = p.config
    let env = MenshenEnvironment.current()
    let (url, stored) = try Enforce.locateConfig(options, environment: env)
    var config = stored
    if p.none {
        config.profiles = nil
        config.limits = nil
    } else if !p.extra.isEmpty || p.cpuSeconds != nil || p.memoryMB != nil {
        if !p.extra.isEmpty {
            config.profiles = try p.extra.map { name in
                guard let t = Profile(rawValue: name.lowercased()) else {
                    throw MenshenError.usage("unknown profile \(name); use \(Profile.allCases.map(\.rawValue).joined(separator: ", "))")
                }
                return t
            }
        }
        if p.cpuSeconds != nil || p.memoryMB != nil {
            var limits = config.limits ?? ResourceLimits()
            if let n = p.cpuSeconds { limits.cpuSeconds = n }
            if let n = p.memoryMB { limits.memoryMB = n }
            config.limits = limits
        }
    } else {
        let names = config.profiles?.map(\.rawValue).joined(separator: ", ") ?? "none"
        print("profiles: \(names)")
        if let l = config.limits { print("limits: cpu \(l.cpuSeconds.map { "\($0)s" } ?? "none"), memory \(l.memoryMB.map { "\($0) MiB" } ?? "none")") }
        return 0
    }
    if let error = SBPLCompiler.validate(SBPLCompiler(environment: env).compile(config)) {
        throw MenshenError.failed("the profile doesn\'t compile with these profiles, nothing saved:\n\(error)")
    }
    try config.save(to: url)
    say("profiles: \(config.profiles?.map(\.rawValue).joined(separator: ", ") ?? "none"). Saved \(url.path)")
    return 0
}

func runForget(_ target: String) throws -> Int32 {
    let env = MenshenEnvironment.current()
    // An app path (or its launcher) → its config key; anything else is taken as the key itself.
    let key = target.contains("/") || target.hasSuffix(".app")
        ? try ResolvedTarget.resolve(Swap.resolveOriginal(target)).identity.key
        : target
    let trashed = try Library.forget(key, env)
    say("moved \(trashed.count) item(s) for \(key) to the Trash. The app itself wasn't touched.")
    return 0
}

func runReplace(_ target: String) throws -> Int32 {
    guard let stub = Swap.defaultStub() else {
        throw MenshenError.failed("can't find the menshen-launch stub next to this binary; build it with `swift build`")
    }
    let r = try Swap.replace(target, stub: stub, environment: .current())
    say("replaced. Launcher: \(r.appPath)   original (untouched): \(r.hiddenPath)")
    return 0
}

func runRestore(_ target: String) throws -> Int32 {
    let r = try Swap.restore(target, environment: .current())
    say("restored \(r.record.appPath). Signature \(r.signatureValid ? "valid" : "DOES NOT VERIFY")\(r.cdhashChanged ? "; the app changed while replaced (updated?)" : "").")
    return r.signatureValid ? 0 : 70
}

func runSwaps() -> Int32 {
    let records = Swap.records(.current())
    if records.isEmpty { print("no replaced apps") }
    for r in records { print("\(r.key)\t\(r.appPath)\t-> \(r.hiddenPath)") }
    return 0
}

func runRebuild(_ p: Parsed, _ target: String) throws -> Int32 {
    var options = EnforceOptions(target: target)
    options.configPath = p.config
    let env = MenshenEnvironment.current()
    let (url, _) = try Enforce.locateConfig(options, environment: env)
    let (config, backup) = try Learn.rebuild(configURL: url, environment: env)
    say("rebuilt \(url.path) from \(config.learning.captures.count) capture(s): \(config.rules.count) rules, \(config.hardening.count) hardening rules")
    if let backup { say("previous config backed up to \(backup.path)") }
    return 0
}

func runShow(_ p: Parsed, _ target: String) throws -> Int32 {
    var options = EnforceOptions(target: target)
    options.configPath = p.config
    let env = MenshenEnvironment.current()
    let (url, config) = try Enforce.locateConfig(options, environment: env)
    print(SBPLCompiler(environment: env).compile(config, source: url.path), terminator: "")
    return 0
}

let argv = Array(CommandLine.arguments.dropFirst())
do {
    if argv.isEmpty || ["-h", "--help", "help"].contains(argv[0]) {
        print(usage)
        exit(argv.isEmpty ? 64 : 0)
    }
    if argv[0] == "swaps" { exit(runSwaps()) }
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
    case "rebuild": status = try runRebuild(p, target)
    case "show": status = try runShow(p, target)
    case "allow": status = try runAllow(p, target)
    case "forget": status = try runForget(target)
    case "profile": status = try runProfile(p, target)
    case "replace": status = try runReplace(target)
    case "restore": status = try runRestore(target)
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
