# ADR-004: Always allow Apple system services and preference reads

**Status**: Accepted

**Date**: 2026-10-29

## Context

Learn mode can't see mach-service lookups (checked by launchd) or preference reads (checked by cfprefsd), because those checks happen in user space and only *denials* are reported. Adding explicit `(with report)` rules didn't change that (tested). Under enforce, VLC therefore hit 10 distinct denials for Apple system services and Apple/global preference domains.

## Decision

Every compiled profile contains two always-on lines (the user chose "Allow com.apple.\*" and asked for the simple approach):

```
(allow mach-lookup (global-name-prefix "com.apple."))
(allow user-preference-read (preference-domain-prefix "com.apple.") (preference-domain "kCFPreferencesAnyApplication") (preference-domain "pbs"))
```

The app's own preference domain was already always allowed for read and write.

## Rationale

It's simple and robust: VLC went from 10 distinct denials to 0. The filters were tested against the real kernel and cfprefsd with an unentitled probe:
- the `com.apple.` prefix read all 39 keys of `com.apple.universalaccess`;
- a non-matching prefix read 0;
- the global domain needs its own `kCFPreferencesAnyApplication` filter.

`PlatformRuleTests` checks these against a control profile without the two lines.

## Consequences

- A compromised app can reach any Apple mach service. Apple Events (`appleevent-send`) and `osascript` are separate checks that hardening still denies, and privacy-gated services still require the user's privacy consent.
- It can read Apple and global preference domains, but not other vendors' preferences.
- Not configurable per app. Adding a config toggle later is a small change.

## Alternatives Considered

- Seed from App Sandbox's own zero-entitlement baseline in `application.sb`: tighter, but it means parsing a private, auto-generated file.
- A `menshen refine` command that promotes reviewed denials: strictest, but apps break until refined. It's still useful later for non-Apple services.
- Making these editable config rules: built first, then removed for simplicity.
