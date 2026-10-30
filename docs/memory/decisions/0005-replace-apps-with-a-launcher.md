# ADR-005: Replace an app by renaming it and putting a launcher in its place

**Status**: Accepted

**Date**: 2026-10-29

## Context

The user wants Menshen to "replace" an app, so that opening it the normal way (Dock, Finder, Spotlight, double-clicking a document) runs it under `enforce`. The user chose "swap in a launcher" over a side-by-side launcher.

## Decision

`Swap.replace` (CLI `menshen replace`, GUI "Replace…"):
1. Requires a learned config, an app that passes preflight, an app that isn't running, and a valid `codesign --verify`.
2. **Renames** `/Applications/VLC.app` → `/Applications/.VLC.menshen.app` (hidden, same folder). Contents are untouched, so the signature, TCC grants and keychain identity all stay valid.
3. Builds a launcher bundle at the original path:
   - executable: the `menshen-launch` stub
   - from the original: name, icon, document types and URL types
   - `LSUIElement`, so it has no Dock icon of its own
   - bundle ID `dev.menshen.launcher.<id>`
   - a `MenshenLauncher` dictionary (original path, config path, data folders)
   - ad hoc signed, then registered with LaunchServices
4. Records the swap in `swaps.json`.

If building the launcher fails, the original is renamed back. `restore` moves the launcher aside, renames the original back, and only then deletes the launcher. It only ever deletes a bundle carrying the `MenshenLauncher` key.

The launcher waits 0.5 s to collect the documents and URLs it was opened with, then runs `Enforce.run` on the hidden original with them as arguments. Later opens are passed to the running protected instance and never launch the original directly. If enforce refuses (e.g. the app updated itself), it shows an alert and exits.

When the app runs from its hidden location, `MenshenConfig.rebased(to:)` moves the config's own-bundle rules to that location. Learning a replaced app stores the normal path.

## Rationale

- Patching the bundle in place would break the developer's signature (Gatekeeper, TCC, keychain) and get undone by updaters.
- A same-folder rename needs only write access to `/Applications` (admin group), even for root-owned bundles. It keeps the app "in /Applications" for updaters and for "move me to Applications" prompts.
- The end-to-end test caught that without rebasing, the profile denied `process-exec*` of the hidden original. Unit tests of the swap alone couldn't have.

## Consequences

- While the app runs, the Dock may show a second icon: the running process belongs to the hidden bundle, while a kept-in-Dock icon points at the launcher.
- Routing documents and default "Open with" handlers to the launcher is best-effort.
- The app's updater updates the hidden original. Enforce then refuses (cdhash changed) until the app is re-learned, which is intended.
- macOS App Management protection may block the rename. Menshen detects EPERM and points to the setting.

## Alternatives Considered

- A side-by-side "VLC (Menshen).app": safest, but the original stays one click away, unprotected.
- Patching the bundle in place: breaks code signing.
- Moving originals to `~/Library/Application Support/Menshen`: needs write access to the bundle itself (to update `..`), so root-owned apps would need admin rights. It also triggers "move to Applications" prompts.
