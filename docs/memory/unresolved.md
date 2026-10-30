# Unresolved — Menshen

Open questions, deferred items, and known unknowns.

| Date | Item | Context |
|------|------|---------|
| 2026-10-29 | ~~How to cover user-space checks learning can't see~~ | **Resolved by ADR-004**: the user chose to always allow `com.apple.*` services and Apple/global preference reads, kept simple (always-on, not configurable). VLC: 10 → 0 denials. |
| 2026-10-29 | `menshen refine` | Planned next step (not in v1): promote reviewed denials from an enforce log into the config. Still useful for *non-Apple* services, which learning also can't see. |
| 2026-10-29 | Do two `sandbox_init` calls stack for plain processes? | A nested `sandbox-exec` ran without error; whether both policies are actually enforced is untested. |
| 2026-10-29 | Do open/save panels and security-scoped bookmarks work for a wrapped GUI app? | VLC opened a file passed as an argument; it hasn't been tested with the open panel. |
| 2026-10-29 | Which app the privacy prompt names for a wrapped app | Not tested. |
| 2026-10-29 | ~~Replace a real app~~ | **Done with the user's OK on VLC 2026-10-29.** No App Management block. Opened through LaunchServices with a document: the launcher ran VLC from `.VLC.menshen.app` under the profile (reported exec allow, 0 denials). Restore gave back the identical cdhash, deep codesign OK, Gatekeeper accepted, no leftovers. VLC was then replaced again; the user later restored it during their own QA (2026-10-30), so it is currently **not replaced**. Not yet seen: the Dock behavior (VLC isn't in the Dock), and document routing from a Finder double-click. |
| 2026-10-30 | Launchers keep an old copy of Menshen | A launcher embeds the menshen-launch build from the day the app was replaced. After a Menshen update, refresh it with Restore and then Replace. A one-step "refresh launcher" would be nicer. |
| 2026-10-30 | Your rules and the Open panel | A file-type rule lets the app read matching files, but a non-sandboxed app's Open panel may still be unable to *list* folders it has no rule for. Opening files from Finder or by drag and drop works. Not yet tested in VLC. |
| 2026-10-30 | App icon license | The archway image (Pinterest) has an unknown designer and license. Replace it or get permission before distributing. |
| 2026-10-29 | GUI: added-but-unlearned apps aren't remembered | They live in memory only; relaunching Menshen drops them. Persist a small list if this becomes annoying. |
| 2026-10-29 | GUI visual checks | Claude has no Screen Recording permission, so it can't screenshot Menshen; the user checks visually. |
| 2026-10-29 | Project folder rename | The user renamed `projects/striply` → `projects/menshen` mid-session. Claude memory was moved to the new project key. |
