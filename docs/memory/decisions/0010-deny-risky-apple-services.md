# ADR-010: Deny risky Apple services for every app

**Status**: Accepted

**Date**: 2026-11-01

## Context

ADR-004 allows every `com.apple.` mach service, because learning can't see service lookups (launchd checks them in user space and only denials are reported). So the allow can't be narrowed per app from what was learned. That leaves a compromised app able to reach services no ordinary app needs.

## Decision

Hardening denies a short list of Apple services by name, for every app (`Hardening.services`):

- `com.apple.xpc.smd`: installing privileged helpers (SMJobBless)
- `com.apple.authd`: admin authorization prompts and rights
- `com.apple.installd`: installing packages
- `com.apple.backgroundtaskmanagementagent`: login and background items (persistence)
- `com.apple.replayd`: screen recording
- `com.apple.container.*` (a prefix, added 2026-11-02): Apple's container engine, which can start a container with your home folder mounted. Found in Shentu, where it was reachable even with network off and Unix sockets closed.

They compile into one `(deny mach-lookup (global-name …) …)` in the hardening section, after the always-on prefix allow, so the narrower, later rule wins. Existing configs get them through `withCurrentProtections`.

## Rationale

A general deny list is the only way to tighten ADR-004 without seeing lookups. Each entry is about privilege, persistence or capture, not about how an app normally works.

## Consequences

- An app that really needs one (an installer, a screen recorder) is blocked until you set that protection to allow for it. The block shows in the enforce log; it's never FLAGGED, since learning can't see lookups.
- The clipboard (`com.apple.pasteboard.1`) and the keychain stay allowed: too many normal apps need them.
- `PlatformRuleTests.containerEngineIsDenied` checks the container prefix by comparing launchd's answers (denied by the sandbox vs. unknown or reachable), since the engine needn't be installed.
- `PlatformRuleTests.riskyAppleServicesAreDenied` checks each name against the real launchd: reachable with the protection switched to allow (so the name exists on this Mac), blocked with it on.

## Alternatives Considered

- Narrowing the prefix to learned names: impossible, learning doesn't see them (ADR-004).
- Seeding from App Sandbox's `application.sb`: tighter, but parses a private, generated file.
- Denying the clipboard and keychain too: breaks normal apps by default.
