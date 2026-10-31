# ADR-007: Learned rules stay as narrow as what the kernel reported

**Status**: Accepted

**Date**: 2026-10-31

## Context

A hardening review of the learned Fastpotify profile (2026-10-31) found two places where learning granted more than the app used:

- The per-user Darwin folder (`/private/var/folders/xx/yyy`) was learned as one own folder. It holds the shared temp folder `T` and one cache folder per app in `C` (536 on the test Mac). Fastpotify only ever used `C/me.paolino.fastpotify`, but could read and write every app's caches.
- `mach-register`, `ipc-posix-*` and `sysctl-write` were learned without a filter, although every report named what was used. A filter-less `mach-register` let the app register any service name in the login session (`system.sb` refuses that).

The review's other claims were checked and rejected (they're listed in the reference doc, rows 26–29, and the 2026-10-31 session).

## Decision

1. The app owns `T` (the shared temp, as for any unsandboxed app) and only the folders named after it in `C` and `0`, found with the same ownership test as `~/Library/<area>/<app>`. The Temp-only profile allows the same places.
2. These operations keep their names: `mach-register` (global or per-pid, like `mach-lookup`), `ipc-posix-*` (`ipc-posix-name`), `sysctl-write` (`sysctl-name`). `sysctl-read` stays filter-less: reading is low risk and an app reads hundreds.
3. Learned per-pid registrations are left out of the compiled profile, since `system.sb` already allows them all (like learned `com.apple.*` lookups).
4. `menshen rebuild <app>` regenerates a config from its saved captures, so configs learned earlier pick up 1–3 without running the app.

## Rationale

- Each change only removes access the app was never seen using, and each is checked by the kernel with a control (`NarrowingTests`), mutation-checked.
- Rebuilding from captures gives exact names; a compile-time upgrade couldn't recover them from an old config.

## Consequences

- An app that touches its own cache under a different name than its bundle ID, executable or team prefix gets a write-outside rule and reports, not silent access.
- An app that uses a shared-memory name or sysctl not seen while learning is now denied (logged); re-learn with `--merge`.
- Launchers of replaced apps embed the Menshen build they were made with and can't read the new filter kinds: refresh them (Restore, then Replace) after a rebuild.

## Alternatives Considered

- Compile-time upgrade of old configs (as for new hardening): covers the Darwin folder but can't name the other operations.
- Keep `C` whole: simpler, but it's other apps' data.
