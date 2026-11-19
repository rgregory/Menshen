# ADR-012: Analyze — a baseline config from the app on disk, without running it

**Status**: Accepted

**Date**: 2026-11-18

## Context

Until now the only way to get a config was to learn: run the app with everything allowed, use it, quit it. That is an exact fit, but it has two costs. The app runs unconfined for the length of the learn run (the README says so plainly), and it takes the person's time and attention — several minutes of clicking through features, repeated whenever the app is updated. For an app you have just downloaded and do not trust that far, "run it unconfined first" is the wrong first step, and for an app you only want to open once, learning is more work than the app is worth.

Everything hardening protects is known up front; it needs no observation at all. What an app needs to *start* is also largely the same for every Mac app (system frameworks, its own data folders, the shared temp folder, a handful of devices), and what *this* app declares about itself is sitting in its bundle: entitlements, Info.plist, embedded helpers.

## Decision

`menshen analyze <app>` and the Dashboard's **Analyze** button write a config from the app on disk, with nothing launched. It has four parts:

1. **Sane defaults** — read-only `/System`, `/usr`, `/bin`, `/sbin`, `/Library`, `/private/etc`, `/private/var/db` (and `/opt/homebrew` when present), read-only `~/Library/Fonts`, read/write on the app's own folders, the usual device sinks (`/dev/null`, `/dev/fd`, …), and the system questions every app asks (`sysctl-read`, `system-info`, `process-fork`, `ipc-posix-shm*`). Own folders are the bundle, the shared temp folder, every `~/Library` or Darwin-cache folder already named after the app, the app-group containers from its entitlements, and the handful macOS creates for an app the first time it runs.
2. **Evidence from the bundle** — connecting out is allowed only when something says the app talks to the network (the network client entitlement, App Transport Security or a local-network prompt in Info.plist, an embedded Sparkle updater); listening only with the server entitlement or Bonjour services; and the file kinds the app declares it opens (`CFBundleDocumentTypes`) become one read-only `file-types` rule.
3. **Explicit denials** — connecting out, listening, running other programs and talking to drivers are written as *deny* rules rather than left to the default, so each is one toggle in Config, with a note saying why it is off.
4. **The hardening overlay in full** — every protection, compiled last as always, so credentials, keychains, browser and chat data, other apps' sandboxes, Mail, Messages, Contacts, Calendars, Photos, persistence locations, risky Apple services and escape sockets are denied before the app has ever run. Nothing is FLAGGED, because nothing was watched.

Analyzed rules carry `source: "baseline"` and IDs prefixed `B-`. The config records `analysis` (when, and the plain-language findings) and `learning.runs: 0`, with a warning in `learning.warnings` so nobody mistakes a baseline for an observed config. Analyze refuses to overwrite a config that was learned unless you confirm it (the Dashboard button reads **Analyze…** and asks; the CLI needs `--force`). Forced, it carries the learn captures into the baseline, so `menshen rebuild` puts the learned rules back, and the previous config is backed up as always. Re-analyzing a baseline is fine and keeps your rules, profiles, limits and switches, like `learn --merge`. Learning an analyzed app replaces the baseline outright: observations beat guesses.

## Rationale

The two risks are opposite and both real: a baseline too tight breaks the app, one too loose is security theatre. The split above puts the looseness where it costs least — plumbing and read-only system files — and keeps every path to the user's data, the network and other programs closed until there is either evidence in the bundle or a deliberate toggle. A denied app that fails loudly in the enforce log is recoverable; a quietly over-permissive config is not.

Writing the closed capabilities as `deny` rules rather than relying on `(deny default)` costs nothing at the kernel (an unfiltered deny only sets the operation's default and loses to any filtered allow, reference row 19) and buys the whole UI for free: they are listed, explained and switchable like any other rule.

## Consequences

- An analyzed app will hit denials the first time it does something its bundle never declared. That is the trade: the Dashboard, the CLI and the config's own warning all say to read the enforce log, or to learn the app for an exact fit.
- An app whose bundle declares nothing (most unsigned or hand-rolled apps) gets the plumbing baseline and nothing else.
- A file manager or archiver that claims `public.data` gets no file-kind rule at all; the findings say so.
- `rebuild` has nothing to rebuild from for an analyzed config that never had captures, and says to analyze or learn instead. One that replaced a learned config does, and rebuilding it is the undo.
- Key material is never granted by a declaration: `pem`, `key`, `p12`, `pfx`, `kdbx`, `env`, `netrc` and friends are dropped from the declared types even if the app claims them, and hardening's name patterns block them anyway inside the home folder.

## Alternatives Considered

- **Ship a generic "tight" profile for every app**: no own-data folders, so almost every app breaks at launch; nothing about this app.
- **Allow the network by default**: friendlier, and gives away the capability that matters most. An app that needs it says so in the log on the first run, and it is one toggle.
- **Infer from the Mach-O's linked frameworks** (Network.framework, AVFoundation): weak evidence — frameworks are linked and never used — and easy to defeat. Entitlements and Info.plist are at least the app's own declarations.
- **Learn in the background on first launch** ("observe then tighten"): that is learning, with the same unconfined run, and it hides when the app is unprotected.
