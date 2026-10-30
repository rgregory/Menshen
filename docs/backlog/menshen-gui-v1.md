# Menshen.app: GUI + "replace the actual app"

## Context

Menshen v0.1.0 (commit `b82ec47`) is a CLI: `learn` → hardened JSON config → `enforce` with JSONL logs. The user wants a GUI on top of it to manage apps and sessions, and the option to **replace** an app, so that launching it the normal way (Dock, Finder, Spotlight) runs it under Menshen enforcement.

User choices:
- **Swap in a launcher:** the original is set aside untouched and a same-name, same-icon launcher takes its place, with Restore to undo.
- **All four features:** apps overview, live sessions, session history, config editor.
- **A regular window app.**
- **Prefers simple solutions** (from memory).

Constraints found:
- No Xcode, only the Command Line Tools. So: SwiftPM plus a bundling script.
- SwiftUI's `@State` is a macro whose plugin isn't installed. `@Observable`, `NavigationSplitView`, `Table` and `ObservableObject` compile fine (tested), so **no SwiftUI macros**.
- `/Applications` is `root:admin rwx` and the user is an admin.
- Patching an app bundle in place would break its signature, so that's out.

## Approach

### Replace / Restore (MenshenCore `Swap.swift`, also `menshen replace|restore|swaps` in the CLI)

**replace(app):** requires a learned config and an app that passes preflight. The app must not be running.
1. `codesign --verify` the original and record its cdhash.
2. Rename `/Applications/VLC.app` → `/Applications/.VLC.menshen.app`.
   - Hidden, same folder, contents untouched.
   - Same-folder rename needs only write access on `/Applications`, so it works even for root-owned bundles.
   - Keeps the app under `/Applications` for updaters and "move to Applications" checks.
3. Build the launcher at `/Applications/VLC.app`:
   - `Contents/MacOS/<exe>`: a copy of the `menshen-launch` stub.
   - Info.plist: the original's name, icon (.icns copied), `CFBundleDocumentTypes` and `CFBundleURLTypes`, plus `CFBundleIdentifier = dev.menshen.launcher.<id>`, `LSUIElement = YES`, and a `MenshenLauncher` dict {original, config}.
   - Ad hoc `codesign`, then `lsregister -f` both paths.
4. Record the swap in `~/Library/Application Support/Menshen/swaps.json`.

**Each step rolls back on failure. Menshen only ever deletes its own launcher**, identified by the `MenshenLauncher` key.

**restore(app):** check the launcher is ours and nothing is running → delete the launcher → rename the original back → `codesign --verify`. Report if the cdhash changed (the app updated itself meanwhile).

**Launcher (`Sources/menshen-launch`, tiny AppKit, no Dock icon):**
- Collects open-document and URL events for about 0.5 s, then runs `Enforce.run` on the hidden original with the files as arguments, logging as usual.
- Dock click while running: activate the running app.
- Further opens: `NSWorkspace.open(urls, withApplicationAt: original)`, which reaches the running protected instance.
- If enforce refuses (signature changed after an update): show an alert telling the user to re-learn in Menshen.
- Exits when the app exits.

### MenshenCore changes
- `Runner.swift`: add a `StopHandle` (programmatic stop) and a `forwardSignals` flag (CLI on; GUI and launcher off). This removes the global `signal()` clash when the GUI runs several sessions.
- `Modes.swift` / `Session.swift`: options gain `stop` and `onEvent` for live UI.
- New `Library.swift` (read side): configured apps, sessions (learn captures plus enforce logs, with counts), records, and swap state.

### GUI (`Sources/MenshenApp`, SwiftUI with `@Observable`, `NavigationSplitView`)
- **Sidebar:** configured apps, plus "Add App…" (open panel or drag and drop). Badges: can be wrapped / runs learned / flagged count / Replaced.
- **Overview:** identity, preflight result, flagged items, Replace/Restore (with a confirm dialog saying exactly what moves where).
- **Session:** Learn (optional duration) / Enforce / Stop, a live event table (verdict, category, op, target, process) with counters, capped at about 5k rows.
- **History:** learn captures and enforce logs (date, events, denials). Choosing one shows its records with a category filter and search.
- **Config:** rules table (source, action toggle, operations, filter, seen, note) with flagged rules highlighted, logging toggles, Save (writes a `.bak` first), and a "Show profile" sheet with the compiled SBPL.

### Packaging
`scripts/build-app.sh` builds release and assembles `build/Menshen.app` (`Contents/MacOS/Menshen`, launcher stub in `Contents/Resources`, Info.plist) with an ad hoc signature. `build/` gets added to `.gitignore`.

### Files
- **New:**
  - `Sources/MenshenApp/*` (App, `AppStore`, `SessionController`, Views)
  - `Sources/menshen-launch/main.swift`
  - `Sources/MenshenCore/{Swap,Library}.swift`
  - `scripts/build-app.sh`
  - `Tests/MenshenCoreTests/{SwapTests,LibraryTests}.swift` plus a dummy-app fixture
  - ADR-005
- **Modified:** `Package.swift`, `Runner.swift`, `Session.swift`, `Modes.swift`, CLI `main.swift`, README, CHANGELOG.

## Milestones
1. Core: StopHandle and forwardSignals, `Library`, `Swap`, CLI `replace/restore/swaps`, tests.
2. Launcher stub, plus an integration test with a dummy app (no real apps).
3. GUI (four features) and the build script.
4. Verification (below).
5. Docs: ADR-005, README, CHANGELOG, digest/lessons, memory.

## Verification
- **Swap unit tests:** use a temporary "Applications" folder and a dummy bundle. Replace, then check that the launcher plist is right (document types copied, `LSUIElement`, the marker) and that the original was renamed with its signature valid. Restore must give back the same cdhash. Also force a failure partway (launcher path already exists) and confirm the rollback leaves everything as it was. Mutation-check the rollback.
- **Launcher integration test:** swap a dummy app (a C binary that writes a marker and attempts a write that should be denied), `open -W` the launcher, and check that the marker was written and the denial is in the JSONL. Then restore.
- **StopHandle test:** stop a long-running enforced probe; it should exit and the log should be drained.
- `swift test` all green.
- **GUI smoke test:** build Menshen.app and launch **only Menshen itself** (I'll say so first) against `MENSHEN_DATA` test data.
- **Real app:** I'll **ask before** replacing one real app (suggestion: VLC, which already has a config). Launch it from Finder, check the enforce log, Restore, and verify the signature.

## Risks / known limits (README)
- **App Management** privacy permission may stop renaming apps. Detect EPERM and point to System Settings → Privacy & Security → App Management.
- **Second Dock icon:** while the app runs, its process belongs to the hidden original bundle, so the Dock may show a second icon.
- **Default "open with" routing** to the launcher is best-effort.
- **App updates** change the hidden original. Enforce then refuses until re-learned, which is intended and surfaced in an alert.
- **Not supported:** App Sandbox apps and Apple apps. Preflight refuses them, as in the CLI.
