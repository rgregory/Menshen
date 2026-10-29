# ADR-003: Config model, rule order, and flag-and-deny hardening

**Status**: Accepted

**Date**: 2026-10-29

## Context

Learn mode has to turn thousands of observed operations into a policy a person can review. That policy also has to block sensitive behavior even when the app did it while learning.

## Decision

- **Config:** one JSON file per app with the target's identity, `rules` (learned), `hardening` (built-in sensitive rules), and `logging` toggles. Rule IDs come from a hash of the rule's content, so regenerating or merging keeps the user's edits.
- **Compiled order:**
  1. `(deny default)` + `(import "system.sb")` + always-on rules
  2. learned rules
  3. hardening rules

  SBPL's later matches override earlier ones, so a hardening deny beats a broader learned allow, and a hardening rule the user flips to `allow` takes effect.
- **Sensitive access seen while learning** (credentials, other apps' data, persistence locations, Apple Events, osascript) is **flagged and denied**, with a `note` describing what was seen. The user re-allows it by changing `action`.
- **Risky allows** (outbound network, process launches, writes outside the app's own folders) are compiled with `(with report)` so they appear in the enforce log.

## Rationale

The user picked flag-and-deny and logging of denials plus risky allows. Hashed rule IDs make `--merge` safe.

## Consequences

The SBPL order semantics must be confirmed against the real kernel (integration test). Paths are stored with `~` and expanded when compiling, so a config belongs to one user account.

## Alternatives Considered

- Writing SBPL directly as the config: precise, but hard to review and impossible to merge.
- Flag-and-allow, or an interactive review at the end of learning: offered to the user, who declined.
