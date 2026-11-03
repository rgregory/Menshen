# Menshen — Overview

The details behind the [README](README.md): what each part of the app does, the command line, how learning and hardening work, and the known limits.

## The app

- **Dashboard:** a **live activity** panel while the app runs: network (by port and socket), disk (by folder, read or write), launches, services, devices and blocked attempts, plus a recent-events feed. It also works for replaced apps opened from the Dock, by following the launcher's log as it grows. When nothing is running, it shows the same for the last run. Below it is a plain-language summary of what the app *may* access.
- **Session:** learn or enforce with a live event table, and Stop.
- **History:** past learn captures and enforce logs, filterable (blocked, network, launches, outside writes) and searchable.
- **Config:** every rule in plain words, with an Allow toggle, flagged rules marked, logging switches, Save (keeps a backup), and Sandbox Rules (the compiled SBPL). **Add Permission…** is where you change what an app may do after learning: profiles, file kinds to read anywhere, your own file types and folders, and limits. Those save right away.

Add apps with **+** or by dropping them on the sidebar. Remove one by right-clicking it (or pressing Delete) and choosing **Remove from Menshen…**: its Menshen data goes to the Trash, and the app itself isn't touched. `menshen forget <app>` does the same.

## Your rules: broad permissions

Learning only allows what the app did. To allow a whole class of files or a folder up front:

```sh
menshen allow /Applications/VLC.app media                # read every media file (video & audio), as macOS classifies them
menshen allow /Applications/VLC.app documents images     # also document and image files
menshen allow /Applications/VLC.app mp4 mkv mov          # or specific types
menshen allow /Applications/VLC.app ~/Movies --write     # read and write everything in ~/Movies
menshen allow /Applications/VLC.app --remove C-1a2b3c4d  # remove one of your rules
```

**Categories** follow macOS's own file-type classification (UTType, what Finder's "Kind" uses), resolved when you add the rule and stored as a plain list in the config. **Media** is movies plus audio; **Images**; **Documents** is PDF, Office, iWork, OpenDocument, ePub and plain or rich text. Code, scripts and config files (json, yaml, sh…) are never "documents", and `.ts` (also TypeScript) and `.key` (also private keys) are left out of the presets.

The same is in the app: Config → **Add Permission…** → **Read anywhere** (hover a kind to see its exact extensions), or **Other files and folders** for types and folders. **Show Sandbox Rules** in Config shows the compiled SBPL. Your rules come after the learned rules but **before the protections**, so `~/.ssh/key.mp4` stays blocked. They survive re-learning.

## Profiles and limits

One-click restrictions on top of what an app learned. In the app: Config → **Add Permission…** → **Profiles** and **Limits**, which apply immediately. Or use `menshen profile`:

```sh
menshen profile /Applications/VLC.app offline no-launch        # no network, no other programs
menshen profile /Applications/VLC.app temp-only --memory-mb 2048 --cpu-seconds 3600
menshen profile /Applications/VLC.app --none                    # clear profiles and limits
```

| Profile | Effect |
|---|---|
| `offline` | No internet or local-network connections, even if learned. Unix sockets aren't IP, so learned ones (logging, DNS) still work; container engines' and SSH agents' are blocked for every app by hardening. |
| `temp-only` | Writes only to temp folders, never your files, even if learned. Command-line tools get a private TMPDIR. Mac apps can only use the shared system temp folder (macOS limitation). |
| `no-launch` | Can't start other programs, only its own helpers. It also can't have macOS open apps, documents or links, so links won't open in your browser. |
| `--cpu-seconds` / `--memory-mb` | Hard limits: stopped after N seconds of CPU time, killed above N MiB. |

The sandbox itself can't cap CPU or memory; those come from `taskpolicy` and `ulimit` at launch. A "max 50% CPU" cap isn't offered: macOS has no such control, and it would need a pause/resume watchdog.

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

Each rule has an `action` (`allow`/`deny`), its `operations`, a `filter`, how often learning `seen` it, and a `note`. To permit something flagged, change its `action` to `"allow"`. `logging` switches the reported categories (`denials`, `network`, `exec`, `writeOutside`) on or off. `activity` (on by default) also reports everyday activity that no other switch covers: reads outside system files, writes inside the app's own folders, local sockets, services and devices. That's what feeds the live dashboard. System-file reads are never reported; they would be thousands of uninteresting lines.

The compiled profile is kept short and auditable. Rules with the same action and operations become one statement, and IDs and counts stay in the JSON. Order: deny default + `system.sb` → always-on rules (the app's own bundle, own preferences, Apple services and preferences) → learned rules → your rules → hardening → `(deny file-link)`. Within each section, allows come first and denies after, so a rule you switch off wins. In SBPL a later matching rule wins, which a test checks against the real kernel. So hardening overrides broader learned allows, and a hardening rule you flip to `allow` takes effect.

## How it works

- **Learn** runs `sandbox-exec` with `(allow default (with report))`, which makes the kernel log every operation in SBPL's own vocabulary. Those lines are never saved to the log store, so Menshen reads them from a live `log stream`. It keeps running a sandboxed canary until the canary's denial appears in the stream, and only then launches the app. Lines are filtered to the app's process tree.
- **Generalize:** paths collapse onto what owns them.
  - The bundle is read and exec only.
  - The app's own `~/Library/*/<app>` folders, its own Darwin cache folders (`/private/var/folders/…/C/<app>`) and the shared temp folder (`…/T`) get full read/write. Other apps' caches don't.
  - Under `~/Documents` and the other content roots, access is granted per root.
  - System locations are read-only.
  - Reads of your own files (on another volume, or in your home outside `~/Library` and hidden folders) become a folder rule once the app read the folder's listing or 2+ files in it, so the next video in `/Volumes/media/Home Videos` plays too. Never a whole volume or your home folder, and hardening still wins inside.
  - Anything else stays an exact path, and becomes a folder rule once a folder has 4+ files.
  - Mach services (looked up or registered), preference domains, IOKit classes, ports, shared-memory names and written sysctls stay exact.
  - `menshen rebuild <app>` regenerates a config from its saved captures, so configs learned earlier pick up these rules without running the app again.
- **Hardening** rules are always present, and older configs pick up new ones automatically when compiled. Besides credential folders, browsers, mail and messages, shell history and startup items, a **sanity set** covers secrets by name anywhere in your home (`.env*`, `*.pem *.key *.p12 *.pfx *.kdbx`, `id_rsa*`/`id_ed25519*`, `.git-credentials`), more credential stores (`.npmrc`, `.pypirc`, `.azure`, `.config/op`, `.password-store`, `.pgpass`…), chat-app sessions (Slack, Discord, Signal, Telegram, WhatsApp) and personal data (Contacts, Calendars, the Photos library). The full list is in [`Hardening.swift`](Sources/MenshenCore/Hardening.swift). The app's own data inside a protected folder (its own group container, or a browser's own profile) is re-allowed.

Design records: [`docs/DECISIONS.md`](docs/DECISIONS.md). Platform research: [`docs/reference/apple-app-sandbox.md`](docs/reference/apple-app-sandbox.md).

## Known limits

- **Can't wrap** apps that already use App Sandbox (the kernel refuses a second sandbox and the app crashes) or Apple's own apps (launch constraints). Preflight refuses both.
- **Learning can't see checks made in user space:** mach-service lookups (checked by launchd) and preference reads (checked by cfprefsd) are mostly not reported in learn mode. So every profile always allows `com.apple.*` mach services and Apple/global preference reads ([ADR-004](docs/memory/decisions/0004-allow-apple-services-and-preferences.md)). With those, VLC runs under enforce with 0 denials. A *non-Apple* service the app uses only shows up as a denial in the enforce log.
- **Logs show what the kernel reports, which isn't always everything.** Blocking never fails, but reports can go missing: when the app blocks and quits within milliseconds, sometimes for no visible reason, and nearly all of them while another process floods sandbox reports (another Menshen learn run, for example). Don't read an empty log as proof that nothing was blocked. ([findings 12, 25, 26](docs/reference/apple-app-sandbox.md))
- **Network rules can't name hosts.** SBPL only accepts `*` or `localhost`, so rules work by port.
- **Reports from processes that exit within milliseconds** of an operation are sometimes dropped by the kernel. In testing, 12 of 20 were kept, versus 20 of 20 when the process stayed alive 300 ms. Enforcement is unaffected; logging and learning of very short-lived helpers are best-effort.
- Privacy prompts (camera, Full Disk Access…) may name the terminal app instead of the wrapped app.
- **A launcher keeps the Menshen version it was made with.** After rebuilding Menshen, refresh a replaced app with Restore and then Replace.
- `sandbox-exec` is deprecated and `system.sb` is a private interface. Re-test after every macOS update.
- **While replaced:** the Dock may show a second icon while the app runs, because the running process belongs to the hidden original. Routing documents and "Open with" to the launcher is best-effort. The app's updater updates the hidden original, after which enforce refuses until the app is re-learned. macOS App Management protection may need to allow Menshen to rename apps.
- **Threat model:** Menshen protects against a compromised *app*, not a compromised user account. A wrapped app can never read or write Menshen's own configs, captures, swap registry or logs, nor write any launcher or another replaced app's original; that block is compiled into every profile and can't be switched off. Other programs running *outside* a sandbox as you can still edit configs and launchers, and Menshen can't detect that: tamper-evident configs need a stable code signature (Developer ID), and the launchers are signed ad hoc.
- **Learn mode protects nothing.** The app runs with everything allowed while it is learned, so learn only apps you'd run unsandboxed anyway, and review the result.
- **Configs are checked on load.** File types must be letters and digits, and name patterns must be Menshen's own; a config that fails is refused (the app shows which and why) rather than compiled.
- **The kernel's sandbox log is visible to every process you run** (`log stream`), so other programs can watch what wrapped apps access or are denied. That's how macOS works, not something Menshen adds.
- **A single write to a folder of your files** (`~/Documents`, `~/Downloads`…) while learning allows writing anywhere in that folder. Such rules are marked "writes outside"; review them.

## Development

Manual QA against VLC, the agreed QA app: [docs/QA.md](docs/QA.md).

```sh
swift build
swift test      # includes real-kernel tests (sandbox-exec + log stream) and a launcher test
                #   that replaces a throwaway dummy app and opens it via LaunchServices
```

The integration test compiles `Tests/MenshenCoreTests/Fixtures/probe.c`, learns it, then enforces it against a fake home folder. The parser fixture holds real kernel report lines captured from VLC.

`Package.swift` passes `-plugin-path` for Swift Testing's macros when only the Command Line Tools are installed. Without it, the default Swift Build backend fails about half of builds with `plugin for module 'TestingMacros' not found`.
