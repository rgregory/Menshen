# Changelog — Menshen

All notable changes are documented here.

---

## [Unreleased] — 0.2.0

### Added
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
