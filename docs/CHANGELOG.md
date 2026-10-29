# Changelog — Menshen

All notable changes are documented here.

---

## [Unreleased] — 0.1.0

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
