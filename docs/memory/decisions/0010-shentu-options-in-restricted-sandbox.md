# ADR-010: Shentu's launch options live in the Restricted Sandbox

**Status**: Accepted

**Date**: 2026-10-31

(ADR-009 is taken on branch `claude/mystifying-swirles-756dd4`.)

## Context

Shentu (`../shentu`) is a separate app: drop a Mac app on it, pick options in a pop-up, and it runs confined. Its options are network on or off, reads in home and on drives limited to file categories (media, images, documents), writes only to a temp folder made for this run and deleted afterwards, and keeping its settings or not. Most of this already existed in the Restricted Sandbox. The user chose a standalone app, limits on home *and* external drives, strict ephemeral temp (Mac apps' usual temp writes are blocked, since NSTemporaryDirectory ignores TMPDIR), and a "keep its settings" toggle that is off by default.

## Decision

Shentu depends on MenshenCore (a new library product) and adds no sandbox logic of its own. `RestrictedSandbox` gains three fields, all off by default, so Menshen's behavior and saved settings are unchanged:

- `readFileTypes`: extensions readable anywhere in home (and on drives). It reuses `filterText(.fileTypes)`. Folders become listable as well (`vnode-type DIRECTORY`); without that, the app and its in-process Open panel can't find the files it may read.
- `limitDrives`: `/Volumes` gets the same deny, metadata and allow rules as home.
- `ephemeralTemp`: `Enforce.runRestricted` creates a 0700 folder under the per-user T (or `/private/tmp`), exports it as TMPDIR, makes it the only writable place besides `/dev`, and removes it when the app exits.

With own data off, `user-preference-write` is now denied too. cfprefsd writes settings on the app's behalf, past every file-write rule (kernel-tested), so "can't keep anything between runs" wasn't true before. This tightens Menshen's Restricted Sandbox as well.

## Consequences

- Category reads show file and folder names (listing), but not contents.
- Under ephemeral temp, a GUI app's normal temp and cache writes are blocked and logged; some apps may misbehave.
- Other writes made by system services on the app's behalf (Keychain, Photos and so on) aren't covered.

## Alternatives Considered

- Copy the code into Shentu: rejected, the copies would drift.
- A mode inside Menshen.app: the user chose a standalone app.
