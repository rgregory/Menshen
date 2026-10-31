# ADR-006: Restricted Sandbox for apps that haven't been learned

**Status**: Withdrawn (2026-10-31). The feature was removed: `RestrictedSandbox`, `menshen box`, the drop zone and Dock-icon drops are gone. Apps are confined by learning, then enforcing. Kept for the findings in Rationale.

**Date**: 2026-10-31

## Context

Learning first is the strongest protection, but sometimes you want to run an app right now, tightly confined, with restrictions you choose: no network, read & write only in one folder, nothing else in your home folder. A first attempt, a disposable PDF viewer under a hand-written deny-everything profile, was dropped: the goal is any app, not one viewer.

## Decision

One saved set of restrictions (`RestrictedSandbox`, `restricted-sandbox.json`), applied to any app dropped on Menshen's Dock icon or drop zone, or run with `menshen box`. The profile:

1. `(deny default)` + `system.sb`, then explicit allows for every operation family a normal app uses (`restrictedBase`).
2. No network (unless switched on).
3. No writes anywhere, then temp folders, then **nothing in home**, then your read & write folders and the app's own `~/Library` folders.
4. Reads in home: only your folders, the app's own, `~/Library/Fonts`. File names stay visible.
5. No other programs (unless switched on).
6. The sanity set last, so it wins, even inside your folders.

## Rationale

- `(allow default)` is the obvious base, but under it the kernel **enforces explicit denies without logging them** (tested: `blockedAttemptsAreLogged` fails with it). With a deny-default base plus explicit allows, every block is logged.
- Allows use `file-read*`, not `file-read-data`. A rule naming a specific operation beats a wildcard rule whatever the order, so a `file-read-data` allow re-opened `.env` files in your folders (tested).
- The home deny comes after the temp allow. Otherwise a home under a temp root would be writable (caught by the kernel test).

## Consequences

- Unlearned apps run without a learning step. Operations missing from `restrictedBase` are denied and logged, which shows what to add.
- The app's own folders are guessed from its bundle ID and name. Apps that use shared group containers may lose them (the denials show it).
- Seatbelt is not a VM: a kernel exploit can escape any of this.
