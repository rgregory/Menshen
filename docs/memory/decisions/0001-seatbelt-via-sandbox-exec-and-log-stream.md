# ADR-001: Enforce with sandbox-exec, observe with a live kernel log stream

**Status**: Accepted

**Date**: 2026-10-29

## Context

Menshen has to confine third-party macOS apps without changing them. It needs two things: a way to apply a Seatbelt policy to a process it launches, and a way to see what that process does, both to learn a baseline and to log denials while enforcing.

## Decision

- **Enforce:** run the target as `/usr/bin/sandbox-exec -f <generated.sb> <executable> [args]`.
- **Learn:** run it under `(version 1)(allow default (with report))`.
- **Observe:** run `/usr/bin/log stream --style ndjson --level debug --predicate 'sender == "Sandbox"'` for the whole run. Parse the kernel's `Sandbox: name(pid) allow|deny(n) op target` lines and keep only those from the target's process tree.
- **Prove the stream is live:** before launch, keep running a sandboxed canary (`touch` denied by its profile) until its denial shows up in the stream. Repeat the canary after the target exits to confirm the stream has caught up.

## Rationale

Tested on macOS 27.0.1 (see `docs/reference/apple-app-sandbox.md`):
- Custom profiles work under `sandbox-exec`. Named `-n` profiles are killed.
- `(with report)` on `allow` produces a kernel debug line for every operation, already in SBPL's own vocabulary, so learning maps straight onto rules.
- Denials produce kernel error lines.
- Neither kind of line is saved to the log store (`log show` finds none). A live stream is the only way to see them.
- No root needed.

## Consequences

- `sandbox-exec` and `sandbox_init` are deprecated, and `system.sb` is a private interface. Launching is kept in `Runner.swift` so the launcher can be swapped, and the platform has to be re-tested on every macOS release.
- Deny reports are **best-effort for processes that exit within milliseconds of a denial** (12 of 20 captured in testing, versus 20 of 20 when the process stayed alive 300 ms longer). Enforcement isn't affected. Learn and enforce reports must say so.
- Apps that already use App Sandbox (`forbidden-sandbox-reinit`) and Apple's own apps (launch constraints) can't be wrapped. Preflight refuses them.

## Alternatives Considered

- **`eslogger` / Endpoint Security:** needs root and Full Disk Access, and its event vocabulary isn't SBPL, so every event would need translating. It stays a fallback.
- **`fs_usage` / `dtrace`:** need root, and SIP limits dtrace. They also don't cover mach-lookup and other IPC.
- **Calling `sandbox_init` from our own launcher:** same deprecation risk, more code. It can replace `sandbox-exec` later behind `Runner`.
