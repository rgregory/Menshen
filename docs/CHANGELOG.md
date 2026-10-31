# Changelog — Menshen

All notable changes are documented here.

---

## [Unreleased] — 0.2.0

### Added
- **Shentu support (ADR-010):** MenshenCore is now a library product. Three new Restricted Sandbox options, all off by default: reads in home limited to file types (with folder listings), the same limits on external drives (`/Volumes`), and a temp folder made for each run, exported as TMPDIR and deleted afterwards. Kernel test `RestrictedTests.fileTypesDrivesAndRunTemp` uses a real disk image under /Volumes, with must-succeed controls and each option turned off as the mutation. Settings saved by older versions still load (`oldSettingsStillLoad`).
- **Own data off now also blocks saved settings:** cfprefsd wrote them on the app's behalf, past the file-write rules. `RestrictedTests.noOwnDataMeansNoSavedSettings` + `prefprobe` fixture, mutation-checked.
- **Menshen.app**, a native SwiftUI window app built with `scripts/build-app.sh` (no Xcode needed):
  - App icon: the Haiku "Action_Logout" padlock, rendered sharp from its SVG (MIT; `assets/ATTRIBUTION.md`; the license text ships inside the app).
  - **Dashboard:** a plain-language summary per app (files, network, launches, services and settings, sensitive), live counters and blocked attempts while a session runs, and the most-blocked attempts from the last run.
  - **Session:** learn or enforce with a live table, and Stop.
  - **History:** learn captures and enforce logs, with filter and search.
  - **Config:** rules in plain words with Allow toggles, logging switches, Save with backup, and Show Profile.
- **Replace / Restore** (ADR-005): `menshen replace|restore|swaps` and the GUI. The original is renamed to a hidden `.Name.menshen.app` in the same folder (untouched). A launcher (`menshen-launch`) takes its place and runs it under enforce with the opened documents. Every step rolls back on failure, and Menshen deletes only its own launcher.
- MenshenCore:
  - `StopHandle` and `SessionControl` (stop sessions from code; signal forwarding only in the CLI)
  - `onEvent`/`onRecord` live callbacks
  - `Library` (read side)
  - `Swap`
  - `MenshenConfig.save` (with backup) and `rebased(to:)`
  - `AccessSummary` / `RuleText` / `BlockedSummary` (plain-language summaries)
- Tests: 44 in total. They cover swap round trip, refusals, rollback (mutation-checked), never deleting a foreign bundle, the end-to-end launcher via LaunchServices with a dummy app, `Library`, and the summaries.

### Fixed: "No other programs" could be bypassed through LaunchServices
- With `lsopen` learned (Fastpotify has it, to open its login page), a confined app could ask macOS to open another app, a document or a link. The opened app runs outside the sandbox, so a `.command` file could run unconfined in Terminal. The no-launch profile and the Restricted Sandbox's "no other programs" now deny `lsopen` too.
- Cost: under either, links no longer open in the browser. Seatbelt can't tell links from apps (`lsopen` carries no path or URL), so no narrower rule exists. The profile text and the Restricted toggle ("Start other programs and open links") say so.
- Kernel tests (`LSOpenTests`, `lsopenprobe` fixture): the probe opens a self-built dummy app, never a real one. Unsandboxed control, a control profile without the restriction (the dummy starts from launchd, unsandboxed), and a mutation check. ADR-008, reference row 31.

### Changed: learned rules stay as narrow as what the kernel reported
- **Darwin folder:** learning no longer owns the whole per-user `/private/var/folders/xx/yyy`, which holds every app's caches (536 folders on the test Mac). An app owns the shared temp folder (`…/T`) and only its own folders in `…/C` and `…/0`, found the same way as its `~/Library` folders. Writes to another app's caches are learned exactly and reported as writes outside. Temp-only allows the same places.
- **Names kept:** `mach-register`, `ipc-posix-*` (shared memory, semaphores) and `sysctl-write` rules now name what the app used, instead of allowing every name. A filter-less `mach-register` let an app register any service name in your login session; per-pid registrations (AppKit's `com.apple.axserver`, `coredrag`, …) are already allowed by `system.sb`, so they're left out of the profile.
- **`menshen rebuild <app>`** regenerates a config from its saved learn captures without running the app, keeping your rules, profiles, limits, switches and switched-off rules (backed up first; refuses if a capture is missing). Run it on configs learned before this change. A replaced app's launcher can't read rebuilt configs until it's refreshed (Restore, then Replace).
- Kernel tests (`NarrowingTests`, `nameprobe` fixture): another app's cache folder, shared memory, global service registration and sysctl writes are blocked unless learned, each with a control that passes without the restriction; mutation-checked. ADR-007.

### Added: Restricted Sandbox (drop an app to run it confined)
- Choose once what dropped apps may do (sidebar drop zone → Settings…, or the toolbar lock): network on/off, other programs on/off, its own `~/Library` data on/off, **read & write folders** and **read-only folders**. Everything else in your home folder is unreadable, writes go only to those folders and temp, and the sanity set is always blocked, even inside your folders.
- **Drop any app** on Menshen's Dock icon or the drop zone and it runs right away in that sandbox. No learning; blocked attempts are logged and shown live on its Dashboard. Unlearned apps also get **Run Restricted**.
- CLI: `menshen box <App> [--network] [--programs] [--no-own-data] [--rw DIR]… [--ro DIR]… [--save]`.
- The Dashboard counts a blocked connection as network activity and a blocked launch as a launch (they showed only under Blocked, with "0 network").
- **Overview** tab (opens first): every learned app on one screen with its newest run (live while running): events, blocked, network, disk, launches, services. On the right, switches for **Network**, **Write files** and **Other programs** (on = allowed; off turns on Offline, Temp-only or No other programs). Click an app to open its Dashboard.
- Dashboard: **Profiles** and a new **File access** card sit right under the status bar. File access has a switch each for Media, Images and Documents (`menshen allow … media`), your other rules with a remove button, and Add File Types or Folder…; changes save at once. Profile switches line up in one column. **Replace…/Restore…** moved into the status bar, with the team and code hash in its status line.
- Tests: every suite that runs sandboxed processes is nested in a serialized `KernelTests` parent. Concurrent learn runs flooded the kernel's reports and made other tests' logs come up empty (`learnThenEnforce` failed 2–4 runs in 8; now 8 of 8 pass). A full run takes about 15 s instead of 7.
- Kernel tests (`RestrictedTests`): an escape probe as the dropped app, with an unsandboxed control and a mutation check, plus logging through the real session path. ADR-006.
- **Darwin folder:** a dropped app writes to the shared temp folder (`…/T`) and, with its own data on, its own `…/C/<bundle ID>` and `…/0/<bundle ID>`, no longer the whole per-user Darwin folder with every app's caches (as ADR-007 did for learned profiles). Kernel test with a control, mutation-checked.

### Changed: instant "can it be wrapped?" check
- Each app is checked once, from its signature (no launch), and the result is kept until the app changes on disk. The sidebar shows **Already sandboxed** or **Apple app** right away for apps Menshen can't wrap. Previously the check ran on every redraw, several times a second during a live session.
- The Apple-signed check skips re-hashing the bundle: under 1 ms instead of up to ~80 ms, with the same answers (tested against the full check). Replace still runs a full `codesign --verify`.

### Changed: templates are now "profiles"; apps can be removed
- Templates are called **profiles**: a Profiles card on each app's Dashboard applies them immediately (saved with a backup, mirrored into unsaved Config edits), and `menshen profile` replaces `menshen template`. The config key is `profiles`. "Show Profile" became **Show Sandbox Rules**, and `ProfileCompiler` became `SBPLCompiler` in code, so "profile" means one thing.
- **Remove from Menshen** (sidebar right-click or Delete, with confirmation; `menshen forget`): a learned app's config, backups, captures, logs and private temp folder go to the Trash. Refused while the app is replaced.

### Added: templates (now profiles), limits and the sanity set
- **Templates** (`menshen template`, Config switches, a Restrictions card on the Dashboard): offline, temp-only, no-launch, background. They compile after learned and your rules, so they win, and they're kept on re-learn. The dashboard summary reflects them.
- **Hard limits:** CPU seconds (`ulimit -t`, outside the sandbox) and memory MiB (`taskpolicy -m`, applied *inside* the sandbox, since it doesn't survive sandbox-exec). Kernel-tested.
- **Sanity set** added to hardening: secrets by name anywhere in home (regex under the home folder), more credential stores, chat-app sessions, personal data. Older configs get every current protection at compile time.
- **Fixed before it shipped:** blanket template denies without a filter would have lost to learned allows. Seatbelt treats a filter-less rule as the operation's default. They now carry `(subpath "/")`.

### Added: live activity dashboard
- The Dashboard shows live activity while an app runs: network, disk by folder, launches, services, devices and blocked attempts, plus a recent feed. For replaced apps opened from the Dock it follows the launcher's log; otherwise it shows the last run.
- New `logging.activity` (default on; older configs load with it on) reports reads outside system files, own-folder writes, local sockets, services and devices. The specific switches (network, launches, outside writes) still decide their own categories.
- Records now have finer categories: read, write, write-outside, network, exec, service, device, denied.
- Sockets read plainly: "Write to the system log", "Look up host names (DNS)".
- Removed `BlockedSummary`; the activity panel replaces the separate Blocked card.

### Added: category presets
- `menshen allow <app> media | images | documents`, also a Category option in Add Permission.
  - Membership follows macOS's UTType classification and is stored as an auditable extension list.
  - Documents leave out code, scripts and config.
  - `.ts` and `.key` are left out (TypeScript source and private keys).
- Your-rule regexes are now readable (`mp4|MP4`), not character classes. Any case mix still matches on case-insensitive volumes (kernel-tested).

### Added after the first 0.2.0 commit
- **Your rules** (`menshen allow`, Config → Add Permission…): read or read & write every file of some types (`mp4 mkv`, matched in any letter case with a both-cases regex, since SBPL ignores `(?i)`), or a folder. Compiled after learned rules and before hardening, so protected locations still win. Kept on re-learn.
- **Compact, auditable profiles:**
  - same-action, same-operation rules merge into one statement
  - learned entries covered by always-on rules are left out
  - no per-rule comments (they stay in the JSON)
  - within a section, allows come before denies

  The real VLC profile went from 170+ to 97 lines; the permissions are unchanged, and the integration and kernel tests still pass.
- New app icon: an archway (source and license caveat in `assets/ATTRIBUTION.md`).

### Fixed after the first 0.2.0 commit
- Commands given a replaced app's normal path (the launcher) looked up the launcher's own identity. Learn, enforce, show and allow now go to the hidden original and its config.
- Captures recorded while an app was replaced produced rules for the hidden `.Name.menshen.app` path after a Restore and re-learn. Captures are now normalized to the normal path.
- Learned `mach-lookup X (xpc)` reports become `(xpc-service-name "X")`, not a global name with " (xpc)" in it.

### Verified on a real app
- VLC (with the user's OK):
  - replace → open with a document via LaunchServices → VLC ran from the hidden original under the profile (0 denials) → quit → restore gave the identical cdhash, deep codesign OK and a Gatekeeper pass → replaced again.
  - No App Management prompt appeared.

### Fixed
- A replaced app couldn't start: the profile's own-bundle rules pointed at the old location, so `process-exec*` of the hidden original was denied. Configs are now rebased to wherever the app runs, and learning a replaced app stores its normal path. Only the end-to-end launcher test caught this.
- Older test suites left temp folders in `/private/tmp` (71 found); they now clean up.

## [0.1.0]

### Added
- `menshen learn`: runs an app under `(allow default (with report))` and streams the kernel's Seatbelt reports live. A canary proves the stream is live before launch and caught up after exit. Only the app's process tree is kept. The raw capture is saved as NDJSON, and a JSON config is written: learned rules plus hardening.
- `menshen enforce`: compiles the config to a deny-by-default SBPL profile, checks that it loads in the kernel, checks the app's signing identity, and runs the app. Denials and reported risky allows (network, process launches, writes outside the app's folders) go to JSONL, and stderr shows a live denial summary.
- `menshen show`: prints the compiled profile.
- Always-on `com.apple.*` mach services and Apple/global preference reads (ADR-004), because learning can't observe those checks. VLC under enforce: 0 denials.
- Hardening overlay with flag-and-deny: credential stores, other apps' data, browser profiles, shell history, persistence locations, Apple Events, osascript. The app's own data inside a protected folder is re-allowed.
- Preflight refuses apps that already use App Sandbox and Apple-signed apps, each with the specific reason.
- `--merge` (keeps edits via content-hash rule IDs), `--duration`, `--allow-changed`, `MENSHEN_DATA`.
- 31 tests: parser (including real VLC report lines), generalizer, compiler, Seatbelt rule ordering checked against the kernel, and a probe integration test of learn → enforce. Mutation-checked: removing the sensitive-path check or moving hardening before the learned rules makes the tests fail.
- ADRs 001–003, `docs/memory/unresolved.md`.
- `docs/reference/apple-app-sandbox.md`: Apple's App Sandbox docs, read with Seatbelt in mind (landing page plus 8 linked articles, fetched 2026-10-29), `sandbox-exec(1)`, the entitlement → SBPL map, and a macOS 27 test log.
- `tasks/lessons.md`.

### Changed
- Project renamed from Striply to Menshen.
- The digest was first written for an app developer adopting App Sandbox, then rewritten for confining other apps with Seatbelt.

### Fixed (during development)
- Paths were resolved with Foundation's `resolvingSymlinksInPath`, which strips `/private`, so rules for `/private/tmp/...` and the user temp root never matched. Switched to `realpath(3)`.
- Own folders now get full read/write. Apps write state at quit, when kernel reports are often lost, so learning missed those writes and enforce denied them.
- The app's own preference domain is always allowed, because cfprefsd's checks aren't visible to learning.
- Swift Testing macro plugin path pinned for Command Line Tools builds (an intermittent `TestingMacros` build failure).
