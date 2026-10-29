# Menshen

Menshen (門神, the door gods painted on Chinese gates) confines a macOS app with **Seatbelt**, the sandbox engine underneath Apple's App Sandbox, without changing the app.

1. **`menshen learn`** runs the app with everything allowed and every operation reported. From that it writes a config: the learned baseline, plus hardening that denies credential stores, other apps' data and persistence locations, *even if the app touched them while learning* (those rules are **FLAGGED**).
2. **`menshen enforce`** runs the app under a deny-by-default profile compiled from that config. Every denial is logged as JSONL, along with the risky things it was allowed to do: outbound network, process launches, and writes outside the app's own folders.

No root needed. Tested on macOS 27.0.1.

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

The compiled order is: deny default + `system.sb` → always-on rules (the app's own bundle, own preferences, Apple services and preferences) → learned rules → hardening → `(deny file-link)`. In SBPL a later matching rule wins, which a test checks against the real kernel. So hardening overrides broader learned allows, and a hardening rule you flip to `allow` takes effect.

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
- `sandbox-exec` is deprecated and `system.sb` is a private interface. Re-test after every macOS update.
- Threat model: Menshen protects against a compromised *app*, not a compromised user account. Configs are user-writable.

## Development

```sh
swift build
swift test      # 31 tests; includes real-kernel tests (sandbox-exec + log stream), ~4 s
```

The integration test compiles `Tests/MenshenCoreTests/Fixtures/probe.c`, learns it, then enforces it against a fake home folder. The parser fixture holds real kernel report lines captured from VLC.

`Package.swift` passes `-plugin-path` for Swift Testing's macros when only the Command Line Tools are installed. Without it, the default Swift Build backend fails about half of builds with `plugin for module 'TestingMacros' not found`.
