import Foundation
import Security
import UniformTypeIdentifiers

/// What an app's bundle says about itself, read without running it: the evidence `Analyze`
/// turns into a starting config.
public struct BundleFacts: Sendable, Equatable {
    /// Why Menshen thinks the app talks out to the network (entitlements, Info.plist keys).
    public var networkEvidence: [String] = []
    /// Why it thinks the app listens (the server entitlement, Bonjour services).
    public var serverEvidence: [String] = []
    /// App groups from the entitlements: folders under ~/Library/Group Containers.
    public var appGroups: [String] = []
    /// File extensions the app declares it opens, cleaned and deduped.
    public var documentTypes: [String] = []
    /// It declares it opens any file at all (public.data, public.item, "*"), which says nothing.
    public var opensAnyFile = false
    /// Helpers inside the bundle (XPC services, login items), by name.
    public var helpers: [String] = []
    /// Privacy prompts it declares, by what they ask for ("Camera", "Microphone").
    public var privacyRequests: [String] = []
    /// A Sparkle updater is embedded: it wants the network, and to run its own helpers.
    public var hasSparkle = false

    public init() {}

    /// Reads the signature and Info.plist. Nothing is launched; a bare executable gives
    /// entitlements only.
    public static func read(_ target: ResolvedTarget) -> BundleFacts {
        var facts = BundleFacts()
        let entitlements = Analyze.entitlements(target.identity.path)
        if entitlements["com.apple.security.network.client"] as? Bool == true {
            facts.networkEvidence.append("the network client entitlement")
        }
        if entitlements["com.apple.security.network.server"] as? Bool == true {
            facts.serverEvidence.append("the network server entitlement")
        }
        facts.appGroups = (entitlements["com.apple.security.application-groups"] as? [String]) ?? []
        guard let bundle = target.bundlePath else { return facts }
        let fm = FileManager.default
        if fm.fileExists(atPath: bundle + "/Contents/Frameworks/Sparkle.framework") {
            facts.hasSparkle = true
            facts.networkEvidence.append("an embedded Sparkle updater")
        }
        for dir in ["Contents/XPCServices", "Contents/Library/LoginItems", "Contents/Helpers"] {
            let names = (try? fm.contentsOfDirectory(atPath: bundle + "/" + dir)) ?? []
            facts.helpers += names.filter { !$0.hasPrefix(".") }
        }
        facts.helpers.sort()
        guard let data = fm.contents(atPath: bundle + "/Contents/Info.plist"),
              let info = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil))
                  as? [String: Any]
        else { return facts }
        if info["NSAppTransportSecurity"] != nil {
            facts.networkEvidence.append("App Transport Security settings in Info.plist")
        }
        if info["NSLocalNetworkUsageDescription"] != nil {
            facts.networkEvidence.append("a local-network prompt in Info.plist")
        }
        if let services = info["NSBonjourServices"] as? [String], !services.isEmpty {
            facts.serverEvidence.append("Bonjour services in Info.plist")
        }
        for (key, value) in info where key.hasSuffix("UsageDescription") && value is String {
            let middle = key.hasPrefix("NS") ? key.dropFirst(2) : Substring(key)
            facts.privacyRequests.append(String(middle.dropLast("UsageDescription".count)))
        }
        facts.privacyRequests.sort()
        var types: [String] = []
        for entry in (info["CFBundleDocumentTypes"] as? [[String: Any]]) ?? [] {
            if (entry["CFBundleTypeRole"] as? String) == "None" { continue }
            for ext in (entry["CFBundleTypeExtensions"] as? [String]) ?? [] {
                if ext == "*" { facts.opensAnyFile = true } else { types.append(ext) }
            }
            for uti in (entry["LSItemContentTypes"] as? [String]) ?? [] {
                if Analyze.anyFileTypes.contains(uti) {
                    facts.opensAnyFile = true
                    continue
                }
                if let type = UTType(uti), let extensions = type.tags[.filenameExtension] {
                    types += extensions
                }
            }
        }
        facts.documentTypes = Analyze.cleanExtensions(types)
        return facts
    }
}

/// Builds a starting config from the app on disk, without running it: the access a Mac app
/// needs to start at all, its own data folders, what its bundle declares — and the full
/// hardening overlay, so credentials, other apps' data and persistence locations are denied
/// before the app has ever run (ADR-012).
public enum Analyze {
    public struct Result: Sendable {
        public var config: MenshenConfig
        public var configURL: URL
        public var backupURL: URL?
        /// Plain-language lines about what the bundle showed, for the UI and the CLI.
        public var findings: [String]
    }

    /// Goes in `learning.warnings`, so nobody mistakes a baseline for an observed config.
    public static let caveat = """
        This config was analyzed, not learned: it allows what a Mac app usually needs plus what \
        this app's bundle declares, not what this app actually does. Expect denials; check the \
        enforce log, or learn the app for an exact fit.
        """

    /// Read-only system locations every Mac app loads code and resources from.
    static let systemReads = ["/System", "/usr", "/bin", "/sbin", "/Library", "/private/etc", "/private/var/db"]
    /// Read-only too, but only when they exist (tools installed outside the system).
    static let optionalReads = ["/opt/homebrew"]
    /// Devices that are sinks or sources of bytes, not access to anything of yours.
    static let deviceSinks = ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/tty", "/dev/dtracehelper"]
    /// UTIs that mean "any file at all": a declaration that says nothing about what it opens.
    static let anyFileTypes: Set<String> = ["public.data", "public.item", "public.content", "public.file-url"]
    /// Never granted by a declaration, whatever the app claims: credentials and key material.
    static let neverGranted: Set<String> = [
        "pem", "key", "p12", "pfx", "kdbx", "kdb", "env", "netrc", "gpg", "asc", "ppk", "jks",
        "keystore", "keychain", "agilekeychain", "opvault",
    ]
    /// A longer list than this is a file manager or an archiver claiming the whole disk; the
    /// rest are left out and said so in the findings.
    static let maxDocumentTypes = 60

    /// Analyzes the app and saves its config (backing up any previous one).
    /// Refuses to overwrite a config that was learned unless `force`: that throws real
    /// observations away. Forced, the learn captures are carried over, so `menshen rebuild`
    /// (or the Learn button) brings the learned config back.
    public static func run(
        target path: String, configPath: URL? = nil, force: Bool = false,
        environment: MenshenEnvironment = .current()
    ) throws -> Result {
        let target = try ResolvedTarget.resolve(Swap.resolveOriginal(path))
        try target.preflight()
        let fm = FileManager.default
        let configURL = configPath ?? environment.configURL(target.identity.key)
        let normalPath = Swap.records(environment).first { $0.hiddenPath == target.identity.path }?.appPath
            ?? target.identity.path
        var previous: MenshenConfig?
        if fm.fileExists(atPath: configURL.path) {
            let existing = try MenshenConfig.load(configURL)
            try Learn.checkSameApp(existing.target, target.identity, normalPath: normalPath, configURL: configURL)
            guard existing.learning.runs == 0 || force else {
                throw MenshenError.refused("""
                    \(configURL.lastPathComponent) was learned from \(existing.learning.events) report(s) over \
                    \(existing.learning.runs) run(s); analyzing would throw that away. Pass --force to replace it \
                    anyway (the learn captures are kept, so `menshen rebuild` brings it back), analyze into \
                    another file with --config, or forget the app first.
                    """)
            }
            previous = existing
        }

        let built = build(target: target.moved(to: normalPath), environment: environment)
        var config = built.config
        // Re-analyzing keeps what you added or switched, the way a merged learn run does.
        if let previous {
            let ids = Set(config.rules.map(\.id))
            config.rules += previous.rules.filter { $0.source == .custom && !ids.contains($0.id) }
            config.keepEdits(from: previous) { environment.abbreviate(environment.expand($0)) }
            // Replacing a learned config: keep the captures, so the learned rules can come back
            // with `rebuild` even though this config no longer holds them.
            let captures = previous.learning.captures.filter { fm.fileExists(atPath: $0) }
            if previous.learning.runs > 0 && !captures.isEmpty {
                config.learning.captures = captures
                config.learning.warnings.insert("""
                    This replaced a config learned from \(previous.learning.events) report(s) over \
                    \(previous.learning.runs) run(s). Its captures are kept: `menshen rebuild` puts the \
                    learned rules back, and the previous config was backed up beside this one.
                    """, at: 0)
            }
        }
        if let error = SBPLCompiler.validate(SBPLCompiler(environment: environment)
            .compile(config, configPath: configURL.path)) {
            throw MenshenError.failed("the analyzed profile doesn't load, nothing saved:\n\(error)")
        }
        let backupURL = try config.save(to: configURL)
        return Result(config: config, configURL: configURL, backupURL: backupURL, findings: built.findings)
    }

    /// Pure: an app on disk → a config. Used by `analyze` and by tests (which pass `facts`).
    public static func build(
        target: ResolvedTarget, environment: MenshenEnvironment, facts: BundleFacts? = nil
    ) -> (config: MenshenConfig, findings: [String]) {
        let facts = facts ?? BundleFacts.read(target)
        let ownFolders = Self.anchors(target, facts: facts, environment: environment)
        let bundleAnchor = target.bundlePath ?? target.identity.executable
        var rules: [Rule] = []
        var findings: [String] = []

        func add(_ action: RuleAction, _ operations: [String], _ filter: Filter, _ note: String,
                 category: ReportCategory? = nil) {
            var rule = Rule(action: action, operations: operations, filter: filter, source: .baseline,
                            category: category, note: note)
            rule.id = "B-" + rule.id.dropFirst(2)
            if !rules.contains(where: { $0.id == rule.id }) { rules.append(rule) }
        }

        // 1. The system: read-only, like every learned config ends up with.
        for root in systemReads + optionalReads.filter({ FileManager.default.fileExists(atPath: $0) }) {
            add(.allow, ["file-read*", "file-map-executable"], Filter(.subpath, root),
                "System files, read-only. Frameworks, fonts and settings every app loads.")
        }
        add(.allow, ["file-read*"], Filter(.subpath, "~/Library/Fonts"), "Fonts you installed, read-only.")

        // 2. Its own data. The bundle itself is already allowed (read and run) by every profile.
        for anchor in ownFolders where anchor != bundleAnchor {
            add(.allow, ["file-read*", "file-write*"], Filter(.subpath, environment.abbreviate(anchor)),
                "Its own data.")
        }

        // 3. Plumbing: bytes in and out of devices, and the system questions every app asks.
        for device in deviceSinks {
            add(.allow, ["file-read*", "file-write*", "file-ioctl"], Filter(.literal, device),
                "Device every app uses (\((device as NSString).lastPathComponent)).")
        }
        add(.allow, ["file-read*", "file-write*", "file-ioctl"], Filter(.subpath, "/dev/fd"),
            "Its own open files (/dev/fd).")
        add(.allow, ["sysctl-read"], .any, "Reads system information (sysctl).")
        add(.allow, ["system-info"], .any, "Reads system information.")
        add(.allow, ["process-fork"], .any, "Starts child processes of itself. Running other programs is separate.")
        add(.allow, ["ipc-posix-shm*"], .any, "Shared memory, used by Apple's frameworks.")

        // 4. Switches, off unless the bundle says otherwise: flip one in Config to turn it on.
        // A deny with no filter only sets the operation's default, so these never override the
        // app's own bundle or a narrower allow.
        if facts.networkEvidence.isEmpty {
            add(.deny, ["network-outbound"], .any, """
                Connecting out. Nothing in the bundle says this app needs the network, so it is \
                denied; switch it on here if it does.
                """, category: .network)
        } else {
            add(.allow, ["network-outbound"], .any,
                "Connecting out, from \(list(facts.networkEvidence)).", category: .network)
            findings.append("Talks to the network (\(list(facts.networkEvidence))), so connecting out is allowed and logged.")
        }
        if facts.serverEvidence.isEmpty {
            add(.deny, ["network-bind", "network-inbound"], .any,
                "Listening for connections. Denied; switch it on here if the app needs it.", category: .network)
        } else {
            add(.allow, ["network-bind", "network-inbound"], .any,
                "Listening, from \(list(facts.serverEvidence)).", category: .network)
            findings.append("Listens for connections (\(list(facts.serverEvidence))), so that is allowed and logged.")
        }
        add(.deny, ["process-exec*"], .any, """
            Running other programs. Its own helpers inside the bundle are always allowed; \
            switch this on to let it run anything else.
            """, category: .exec)
        add(.deny, ["iokit-open-user-client"], .any,
            "Talking to hardware drivers directly. Denied; switch it on if the app needs a device.")

        // 5. What it says it opens. Hardening still wins, so a .pem in ~/.ssh stays blocked.
        if !facts.documentTypes.isEmpty {
            let types = Array(facts.documentTypes.prefix(maxDocumentTypes))
            add(.allow, ["file-read*"], Filter(.fileTypes, types.joined(separator: ",")),
                "File kinds the app says it opens (Info.plist). Read-only, anywhere; protected locations stay blocked.")
            let kinds = facts.documentTypes.count
            let shown = types.prefix(6).map { "." + $0 }.joined(separator: " ") + (types.count > 6 ? " …" : "")
            var line = kinds == 1
                ? "Says it opens one kind of file (\(shown)); reading those anywhere is allowed."
                : "Says it opens \(kinds) kinds of file; reading \(types.count) of them anywhere is allowed (\(shown))."
            if facts.documentTypes.count > types.count { line += " The rest were left out; add them in Config if you need them." }
            findings.append(line)
        }
        if facts.opensAnyFile {
            findings.append("It declares it opens any file at all, which says nothing about what it needs, so no file kinds were allowed from that. Add the folders it should reach in Config.")
        }

        if !facts.appGroups.isEmpty {
            findings.append("App groups it shares data with: \(facts.appGroups.joined(separator: ", ")).")
        }
        if !facts.helpers.isEmpty {
            findings.append("Helpers inside the bundle (\(list(facts.helpers.prefix(4).map { $0 }))): already allowed to run, like the app itself.")
        }
        if facts.hasSparkle {
            findings.append("It updates itself with Sparkle, which downloads and runs an installer. Watch the enforce log the first time it checks for updates.")
        }
        if !facts.privacyRequests.isEmpty {
            findings.append("It asks macOS for: \(facts.privacyRequests.joined(separator: ", ")). Those prompts are macOS's, not Menshen's.")
            let sensitive = ["Camera", "Microphone", "AudioCapture", "Location", "LocationWhenInUse",
                             "LocationAlways", "LocationAlwaysAndWhenInUse", "SpeechRecognition"]
            if facts.privacyRequests.contains(where: { sensitive.contains($0) }) {
                findings.append("The camera, capture sessions and your location are denied for every app, so a prompt you granted before doesn't apply here; switch the matching protection to allow if this app needs one. An app that drives CoreAudio directly can still reach the microphone — that service also carries all audio playback.")
            }
            let folders = ["DesktopFolder", "DocumentsFolder", "DownloadsFolder", "NetworkVolumes", "RemovableVolumes"]
            if facts.privacyRequests.contains(where: { folders.contains($0) }) {
                findings.append("It also asks for your Desktop, Documents, Downloads or external volumes. The baseline grants none of them: add the one folder it really needs in Config.")
            }
        }
        if facts.networkEvidence.isEmpty {
            findings.append("Nothing in the bundle says it needs the network, so connecting out is denied. Switch \"Connecting out\" on in Config if it turns out to need it.")
        }

        let hardening = Hardening(environment: environment, ownAnchors: ownFolders)
            .rules(hits: [:], unseen: Hardening.notRunNote)
        findings.append("\(hardening.filter { $0.action == .deny }.count) sensitive locations and behaviors are denied: keys and tokens, keychains, browser and chat data, other apps' sandboxes, your Mail, Messages, Contacts, Calendars and Photos, startup items, and Apple services that install helpers or record the screen.")
        findings.append("Analyzed, not learned: this is what an app of this shape usually needs, not what this app does. Enforce it and read the log, or Learn it for an exact fit.")

        rules.sort { ($0.operations[0], $0.filter.value ?? "") < ($1.operations[0], $1.filter.value ?? "") }
        let config = MenshenConfig(
            schemaVersion: 1,
            generatedBy: "menshen \(menshenVersion)",
            generatedAt: Date(),
            target: target.identity,
            anchors: ownFolders.map(environment.abbreviate),
            learning: LearningInfo(runs: 0, events: 0, captures: [], warnings: [caveat]),
            logging: LoggingSettings(),
            rules: rules,
            hardening: hardening,
            analysis: AnalysisInfo(analyzedAt: Date(), findings: findings)
        )
        return (config, findings)
    }

    /// Folders the app owns, without having watched it: its bundle, the shared temp folder, its
    /// app-group containers, every folder named after it that already exists in a ~/Library area
    /// or the Darwin caches, and the handful macOS creates for an app the first time it runs.
    static func anchors(_ target: ResolvedTarget, facts: BundleFacts,
                        environment: MenshenEnvironment) -> [String] {
        let identity = target.identity
        let generalizer = Generalizer(environment: environment, target: identity, bundlePath: target.bundlePath)
        var anchors: Set<String> = [target.bundlePath ?? identity.executable]
        if let temp = environment.userTempDir { anchors.insert(temp) }
        let home = environment.home
        let areas = Generalizer.libraryAreas.map { home + "/Library/" + $0 } + environment.userAppAreas
        let fm = FileManager.default

        // Already on disk: the app has run before, unconfined.
        for area in areas {
            for name in (try? fm.contentsOfDirectory(atPath: area)) ?? [] {
                if generalizer.owns(name) {
                    anchors.insert(area + "/" + name)
                } else if generalizer.isVendorFolder(name) {
                    for inner in (try? fm.contentsOfDirectory(atPath: area + "/" + name)) ?? []
                    where generalizer.ownsInsideVendor(inner) {
                        anchors.insert(area + "/" + name + "/" + inner)
                    }
                }
            }
        }
        // Not there yet: the places macOS puts an app's own data the first time it needs them.
        if let id = identity.bundleId {
            anchors.formUnion([
                home + "/Library/Application Support/" + id,
                home + "/Library/Caches/" + id,
                home + "/Library/Preferences/" + id + ".plist",
                home + "/Library/Saved Application State/" + id + ".savedState",
                home + "/Library/HTTPStorages/" + id,
                home + "/Library/WebKit/" + id,
            ])
            anchors.formUnion(environment.userAppAreas.map { $0 + "/" + id })
        }
        if !identity.name.isEmpty {
            anchors.insert(home + "/Library/Application Support/" + identity.name)
            anchors.insert(home + "/Library/Logs/" + identity.name)
        }
        for group in facts.appGroups {
            anchors.insert(home + "/Library/Group Containers/" + group)
        }
        return anchors.sorted()
    }

    /// The entitlements the code is signed with, or none for unsigned code.
    static func entitlements(_ path: String) -> [String: Any] {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let code = staticCode else { return [:] }
        var cfInfo: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation)
        guard SecCodeCopySigningInformation(code, flags, &cfInfo) == errSecSuccess,
              let info = cfInfo as? [String: Any] else { return [:] }
        return info[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
    }

    /// "*.MP4", ".mkv" → "mp4", "mkv": lowercased, letters and digits only (so they compile into
    /// a regex safely), credentials dropped, deduped, in a stable order.
    static func cleanExtensions(_ raw: [String]) -> [String] {
        var seen = Set<String>()
        var result: [String] = []
        for item in raw {
            var ext = Substring(item.lowercased())
            if ext.hasPrefix("*") { ext = ext.dropFirst() }
            if ext.hasPrefix(".") { ext = ext.dropFirst() }
            let value = String(ext)
            guard !value.isEmpty, value.count <= 16, !neverGranted.contains(value),
                  value.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }),
                  seen.insert(value).inserted else { continue }
            result.append(value)
        }
        return result.sorted()
    }

    /// "a", "a and b", "a, b and c".
    static func list(_ items: [String]) -> String {
        guard let last = items.last else { return "" }
        if items.count == 1 { return last }
        return items.dropLast().joined(separator: ", ") + " and " + last
    }
}
