# Menshen

Menshen (門神, the door gods painted on Chinese gates) confines a macOS app with **Seatbelt**, the sandbox engine underneath Apple's App Sandbox, without changing the app.

1. **`menshen learn`** runs the app with everything allowed and every operation reported. From that it writes a config: the learned baseline, plus hardening that denies credential stores, other apps' data and persistence locations, *even if the app touched them while learning* (those rules are **FLAGGED**).
2. **`menshen enforce`** runs the app under a deny-by-default profile compiled from that config. Every denial is logged as JSONL, along with the risky things it was allowed to do: outbound network, process launches, and writes outside the app's own folders.

3. **Replace** swaps an app for a launcher with the same name and icon, so opening it from the Dock, Finder or Spotlight always runs it under enforce. **Restore** puts the original back.

No root needed. Tested on macOS 27.0.1.

## The app

```sh
./scripts/build-app.sh          # builds build/Menshen.app (no Xcode needed)
open build/Menshen.app
```

- **Dashboard:** a plain-language summary of what the selected app may access (files, network, launches, services and settings, sensitive locations), the most-blocked attempts from its last run, and live counters and blocked attempts while it runs.
- **Session:** learn or enforce with a live event table, and Stop.
- **History:** past learn captures and enforce logs, filterable (blocked, network, launches, outside writes) and searchable.
- **Config:** every rule in plain words, with an Allow toggle, flagged rules marked, logging switches, Save (keeps a backup), and Show Profile (the compiled SBPL).

Add apps with **+** or by dropping them on the sidebar.

## Your rules: broad permissions

Learning only allows what the app did. To allow a whole class of files or a folder up front:

```sh
menshen allow /Applications/VLC.app mp4 mkv mov          # read every .mp4/.mkv/.mov anywhere, any letter case
menshen allow /Applications/VLC.app ~/Movies --write     # read and write everything in ~/Movies
menshen allow /Applications/VLC.app --remove C-1a2b3c4d  # remove one of your rules
```

The same is in the app: Config → **Add Permission…**. Your rules come after the learned rules but **before the protections**, so `~/.ssh/key.mp4` stays blocked. They survive re-learning.

## Replacing an app

`menshen replace /Applications/VLC.app` (or **Replace…** in the app):
- renames the app to `/Applications/.VLC.menshen.app`, hidden, in the same folder, with its contents and signature untouched;
- puts a launcher at `/Applications/VLC.app` with VLC's name, icon and document types.

The launcher runs the original under `enforce` with any documents it was opened with, writes the usual log, and exits when VLC quits. `menshen restore org.videolan.vlc` reverses it. `menshen swaps` lists replaced apps. See [ADR-005](docs/memory/decisions/0005-replace-apps-with-a-launcher.md).

## Usage

```sh
swift build -c release
.build/release/menshen learn /Applications/VLC.app            # use the app normally, then quit it
.build/release/menshen show /Applications/VLC.app             # review the compiled SBPL
.build/release/menshen enforce /Applications/VLC.app
```

```
menshen learn   <App.app | binary> [--duration 10m] [--merge] [--config PATH] [-- app-args…]
menshen enforce <App.app | binary | config.json> [--duration 10m] [--config PATH] [--allow-changed] [-- app-args…]
menshen show    <App.app | binary | config.json> [--config PATH]
menshen replace <App.app>
menshen restore <App.app | bundle-id>
menshen swaps
```

- `--merge` adds another learning run to the existing config and keeps your edits. Rule IDs are content hashes, so they stay stable across runs.
- `--allow-changed` runs even though the app's signature changed since learning (team ID, signing ID or cdhash). By default enforce refuses and asks you to re-learn.
- `MENSHEN_DATA=/dir` keeps configs, captures and logs together in one folder.

| What | Where |
|---|---|
| Config (edit this) | `~/Library/Application Support/Menshen/profiles/<bundle-id>.json` |
| Compiled profile (generated) | same folder, `<bundle-id>.sb` |
| Raw learn captures | `~/Library/Application Support/Menshen/learn/<bundle-id>/*.ndjson` |
| Enforce logs | `~/Library/Logs/Menshen/<bundle-id>/<timestamp>.jsonl` |

### Editing a config

Each rule has an `action` (`allow`/`deny`), its `operations`, a `filter`, how often learning `seen` it, and a `note`. To permit something flagged, change its `action` to `"allow"`. `logging` switches the reported categories (`denials`, `network`, `exec`, `writeOutside`) on or off.

The compiled profile is kept short and auditable. Rules with the same action and operations become one statement, and IDs and counts stay in the JSON. Order: deny default + `system.sb` → always-on rules (the app's own bundle, own preferences, Apple services and preferences) → learned rules → your rules → hardening → `(deny file-link)`. Within each section, allows come first and denies after, so a rule you switch off wins. In SBPL a later matching rule wins, which a test checks against the real kernel. So hardening overrides broader learned allows, and a hardening rule you flip to `allow` takes effect.

## How it works

- **Learn** runs `sandbox-exec` with `(allow default (with report))`, which makes the kernel log every operation in SBPL's own vocabulary. Those lines are never saved to the log store, so Menshen reads them from a live `log stream`. It keeps running a sandboxed canary until the canary's denial appears in the stream, and only then launches the app. Lines are filtered to the app's process tree.
- **Generalize:** paths collapse onto what owns them.
  - The bundle is read and exec only.
  - The app's own `~/Library/*/<app>` folders and the per-user temp root get full read/write.
  - Under `~/Documents` and the other content roots, access is granted per root.
  - System locations are read-only.
  - Anything else stays an exact path, and becomes a folder rule once a folder has 4+ files.
  - Mach services, preference domains, IOKit classes and ports stay exact.
- **Hardening** rules are always present. The list is in [`Hardening.swift`](Sources/MenshenCore/Hardening.swift). The app's own data inside a protected folder (its own group container, or a browser's own profile) is re-allowed.

Design records: [`docs/DECISIONS.md`](docs/DECISIONS.md). Platform research: [`docs/reference/apple-app-sandbox.md`](docs/reference/apple-app-sandbox.md).

## Known limits

- **Can't wrap** apps that already use App Sandbox (the kernel refuses a second sandbox and the app crashes) or Apple's own apps (launch constraints). Preflight refuses both.
- **Learning can't see checks made in user space:** mach-service lookups (checked by launchd) and preference reads (checked by cfprefsd) are mostly not reported in learn mode. So every profile always allows `com.apple.*` mach services and Apple/global preference reads ([ADR-004](docs/memory/decisions/0004-allow-apple-services-and-preferences.md)). With those, VLC runs under enforce with 0 denials. A *non-Apple* service the app uses only shows up as a denial in the enforce log.
- **Network rules can't name hosts.** SBPL only accepts `*` or `localhost`, so rules work by port.
- **Reports from processes that exit within milliseconds** of an operation are sometimes dropped by the kernel. In testing, 12 of 20 were kept, versus 20 of 20 when the process stayed alive 300 ms. Enforcement is unaffected; logging and learning of very short-lived helpers are best-effort.
- Privacy prompts (camera, Full Disk Access…) may name the terminal app instead of the wrapped app.
- **A launcher keeps the Menshen version it was made with.** After rebuilding Menshen, refresh a replaced app with Restore and then Replace.
- `sandbox-exec` is deprecated and `system.sb` is a private interface. Re-test after every macOS update.
- **While replaced:** the Dock may show a second icon while the app runs, because the running process belongs to the hidden original. Routing documents and "Open with" to the launcher is best-effort. The app's updater updates the hidden original, after which enforce refuses until the app is re-learned. macOS App Management protection may need to allow Menshen to rename apps.
- Threat model: Menshen protects against a compromised *app*, not a compromised user account. Configs are user-writable.

## Development

Manual QA against VLC, the agreed QA app: [docs/QA.md](docs/QA.md).

```sh
swift build
swift test      # 44 tests, ~4 s: includes real-kernel tests (sandbox-exec + log stream) and a
                #   launcher test that replaces a throwaway dummy app and opens it via LaunchServices
```

The integration test compiles `Tests/MenshenCoreTests/Fixtures/probe.c`, learns it, then enforces it against a fake home folder. The parser fixture holds real kernel report lines captured from VLC.

`Package.swift` passes `-plugin-path` for Swift Testing's macros when only the Command Line Tools are installed. Without it, the default Swift Build backend fails about half of builds with `plugin for module 'TestingMacros' not found`.
