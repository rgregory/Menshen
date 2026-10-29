> **Status 2026-10-29:** milestones 1–5 done (v0.1.0; 29 tests green; VLC learn → enforce verified). Open: how to cover user-space-checked operations (see docs/memory/unresolved.md). Deviations from the plan: `--duration` added to enforce; `MENSHEN_DATA` override; the always-on quarantine-xattr rule was dropped (it could stop apps from *setting* quarantine on downloads); the app's own folders get full read/write and its own preference domain is always allowed (learning misses these).

# Menshen v1: Seatbelt learn → harden → enforce CLI

## Context

Menshen should lock down third-party macOS apps from the outside using Seatbelt (the engine underneath App Sandbox). The user wants one CLI with two modes:
- **learn:** run the app normally, record everything it does, and write a config that combines that baseline with built-in hardening.
- **enforce:** run the app under the config and log specific events.

The repo is empty except for `docs/reference/apple-app-sandbox.md`, `docs/CHANGELOG.md`, and `tasks/lessons.md`.

Choices already made with the user: **Swift**, **flag-and-deny** for sensitive access seen during learning, and **logging denials plus risky allows** as JSONL in enforce mode.

### Platform facts this design depends on (all tested on macOS 27.0.1; see the digest)
- `sandbox-exec -p/-f` with custom profiles works. Named `-n` profiles are SIGKILLed.
- `(allow default (with report))` logs **every** operation as a kernel debug line: `Sandbox: VLC(81047) allow mach-lookup com.apple.…`. Denials are logged as error lines: `… deny(1) file-write-create <path>`. **Only a live `/usr/bin/log stream --level debug --predicate 'sender == "Sandbox"'` sees them**; `log show` finds none. No root is needed.
- VLC under report mode: 2,247 events in 5 s, with no dropped-message notices. Target formats include plain paths, `path:… xattr:…`, `remote:*:443`, mach service names, sysctl names, iokit classes, and `target:… extension-class:…`.
- **Can't be wrapped:** apps that already use App Sandbox (`forbidden-sandbox-reinit`, then a SIGTRAP) and Apple's own apps (launch-constraint kill). Preflight must refuse both with a clear reason.
- SBPL network rules only accept `*` or `localhost` as the host, so network policy works at the level of local/remote and port.
- `(deny default)` + `(import "system.sb")` + `(allow process-exec)` + `(allow file-read*)` is a working minimal base.
- `(with report)` is valid only on `allow` rules.

## Approach

A Swift package with **no third-party dependencies**: hand-rolled argument parsing, Foundation `Codable` JSON, Security.framework. It runs `/usr/bin/sandbox-exec` and `/usr/bin/log stream` as child processes. Nothing needs root.

### Commands
```
menshen learn   <App.app | binary> [--duration 10m] [--merge] [--config PATH] [-- app args]
menshen enforce <App.app | binary | config.json> [--config PATH] [--allow-changed] [-- app args]
menshen show    <config.json>        # print the compiled SBPL, for review or a dry run
```
- **learn** runs preflight, then runs the app under `(version 1)(allow default (with report))` while the log tap streams. Learning ends when the app exits or after `--duration`. On Ctrl-C, Menshen sends SIGTERM to the app and drains the log for 2 s. It then:
  - saves the raw events as NDJSON,
  - generalizes them into rules and applies the hardening overlay,
  - writes the config and prints a learn report (counts per category, flagged sensitive items, warnings about dropped log lines).
  `--merge` adds to an existing config instead of replacing it.
- **enforce** loads the config and checks the app's identity (team ID, signing identifier, cdhash). If the app has changed, enforce refuses unless `--allow-changed` is passed, and suggests re-learning. It then compiles the SBPL, writes it next to the config (with a generated-file header), and launches the app. Denials and risky allows go to JSONL, and stderr shows a live denial summary.
- Apps are launched by running `Contents/MacOS/<CFBundleExecutable>` directly, not through `open`, because LaunchServices would re-parent the app outside the sandbox.

### Files (new)
```
Package.swift                      swift-tools 6.x, macOS 27; targets: menshen (exe), MenshenCore (lib), MenshenCoreTests
Sources/menshen/main.swift         subcommand dispatch + flag parsing
Sources/MenshenCore/
  Target.swift          resolve .app → executable, bundle ID; read signing info via SecStaticCode
                        (team ID, identifier, cdhash, entitlements, platform flag); preflight refusals
  Runner.swift          start sandbox-exec -f <profile> -D HOME=… -- exe args; forward signals; wait
  LogTap.swift          start `log stream --style ndjson --level debug --predicate 'sender == "Sandbox"'`
                        before launching the app; stop after a drain period; spot "dropped" notices
  ReportParser.swift    "Sandbox: name(pid) allow|deny(n) op target…" → SandboxEvent; fold
                        "N duplicate reports for …" lines into the event; parse the target sub-fields
  ProcessTree.swift     root pid + descendants via libproc (proc_listchildpids poll + ppid lookup
                        for unknown pids), so other processes' sandbox lines (e.g. mediaremoted) are dropped
  Generalizer.swift     events → rules. Paths collapse to anchor subpaths (app bundle,
                        ~/Library/{Application Support,Caches,Preferences,Saved Application State,HTTPStorages,WebKit}/<id|name>,
                        $TMPDIR, system read roots); mach-lookup/register, sysctl, iokit, prefs stay exact;
                        network → remote ports + local bind ports; process-exec → exact paths
  Hardening.swift       built-in overlay (see below), source-tagged and individually toggleable
  Config.swift          versioned Codable schema: target identity, rules[{id, op, filter, action,
                        source: learned|hardening, seenCount, note}], logging, hardening toggles
  ProfileCompiler.swift config → SBPL: deny default + system.sb base + learned allows (risky ones
                        `(with report)`) + hardening denies **last** (relies on last-match-wins; verified in M3)
  EventLog.swift        JSONL {ts, runId, pid, process, verdict, op, target, category, ruleId?}
Tests/MenshenCoreTests/ parser, generalizer, compiler golden files, config round-trip, Seatbelt integration
Tests/Fixtures/probe.c  test binary: reads a file, writes to an allowed dir, writes to a sensitive dir,
                        runs /bin/echo, connects to localhost
```

### Hardening overlay (flag-and-deny)
- **Sensitive reads.** If the app touched any of these during learning, the config gets a deny rule with `note` = what was seen. The user re-allows it by flipping one `action` field.
  - `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config/{gh,gcloud}`, `~/.netrc`, `~/.docker/config.json`
  - `~/Library/{Keychains,Cookies,Safari,Messages,Mail}`
  - browser profile folders
  - other apps' `~/Library/Containers` and `Group Containers`
  - shell history files
- **Persistence writes:**
  - `~/Library/LaunchAgents`, `/Library/Launch{Agents,Daemons}`
  - shell rc files (`.zshrc`, `.zprofile`, `.bashrc`, `.bash_profile`, `.profile`)
  - `~/.ssh/authorized_keys`
- **Behavior:**
  - `appleevent-send` and running `osascript`: flag-and-deny
  - `network-inbound`: denied unless it was learned
  - `process-exec`: limited to the learned set plus the app bundle
- **Always on, never learned** (taken from App Sandbox's base profile):
  - `(deny file-link)`
  - `signal` only to processes in the same sandbox
  - no removing the `com.apple.quarantine` xattr
- **Risky allows** that get `(with report)` and so appear in the enforce log: `network-outbound`, `process-exec`, and writes outside the app's own anchors.

### Where data lives
- Configs: `~/Library/Application Support/Menshen/profiles/<bundle-id>.json`, with the compiled `<bundle-id>.sb` beside it
- Raw learn captures: `~/Library/Application Support/Menshen/learn/<bundle-id>/<ts>.ndjson`. Kept so configs can be regenerated or merged without re-learning.
- Enforce logs: `~/Library/Logs/Menshen/<bundle-id>/<ts>.jsonl`

## Milestones
1. **Scaffold:**
   - `git init` (no commits unless you ask), `Package.swift`, `.gitignore`, `README.md`
   - `docs/DECISIONS.md` + `docs/memory/decisions/` ADRs (sandbox-exec + log-stream design; Swift with no deps; JSON config)
   - copy this plan to `docs/backlog/menshen-v1.md`
2. **Observe:** Target + preflight, LogTap, ReportParser, ProcessTree, Runner. `menshen learn` writes the raw capture and a summary.
3. **Generate:** Generalizer, Hardening, Config. `learn` writes the config.
4. **Enforce:** ProfileCompiler, `enforce`, `show`, EventLog. Test last-match-wins ordering with a real Seatbelt run before relying on it.
5. **Prove it:** unit tests plus the probe integration test, then a manual end-to-end run on VLC. Update CHANGELOG, the digest's open questions, and memory.

## Verification
- `swift build` and `swift test` pass. The parser fixtures are real captured lines, with `$HOME` scrubbed out.
- **Compiler test:** every generated profile has to load: `sandbox-exec -f <generated.sb> /usr/bin/true` exits 0.
- **Probe integration test:** `learn` the probe, which learns its 4 normal actions and flags the sensitive write as denied. Then `enforce` it: the normal actions succeed, while the sensitive write and a new unlearned write fail with EPERM and appear as `deny` records in the JSONL. The localhost connect and `/bin/echo` appear as risky-allow records.
- **Prove the tests can fail:** flip one learned rule to `deny` and confirm the integration test goes red. Run a positive control for the log tap (one known denial must be captured) before trusting a "no denials" result.
- **Preflight test:** pointing `learn` at Wipr (App Sandbox) and at Calculator (Apple app) refuses with the specific reason, before anything launches.
- **Manual end-to-end:** `menshen learn /Applications/VLC.app --duration 2m` while opening and playing a local file, then `menshen enforce`. Play the same file without new denials, and confirm a write to `~/Library/LaunchAgents` (via the probe pattern) is denied and logged.

## Known limits (written into the README)
- Can't wrap apps that already use App Sandbox or Apple's own apps. Network rules can't name a host.
- Privacy prompts (camera, Full Disk Access, etc.) may name the terminal app instead of the wrapped app.
- `sandbox-exec` and `system.sb` are deprecated or private interfaces. Runner is kept separate so the launcher can be swapped; re-test on every macOS update.
- A baseline only covers what the app did while learning. Rare features show up as denials in the enforce log. A `menshen refine` command to promote reviewed denials is the planned next step, **not in this plan**.
- Threat model: Menshen protects against a compromised *app*, not a compromised *user account*. Configs are user-writable.
