# ADR-008: "No other programs" also blocks LaunchServices opens

**Status**: Accepted

**Date**: 2026-10-31

## Context

No other programs (the no-launch profile) denied `process-exec*`. Learned configs can still hold a filter-less `lsopen` allow: Fastpotify's does, to open its login page in the browser. The kernel test (reference row 31) showed that with `lsopen` allowed, a confined process can ask LaunchServices to open any app it can read. The app then starts from launchd, outside the sandbox, and the same goes for a URL's handler app. A `.command` file opened this way would run in Terminal unconfined.

## Decision

No other programs adds a filter-less `(deny lsopen)` after the learned rules in the compiled profile. The profile text says that links won't open in the browser.

## Rationale

`lsopen` is checked with no argument, so the kernel can't tell an app from a document or a link, or one URL scheme from another. Path filters never match it, so the usual `(subpath "/")` deny would block nothing. A filter-less deny wins here because learned `lsopen` allows have no filter either (the learner records it without one, and custom rules only cover files).

## Consequences

- Under No other programs, links no longer open in the browser and apps can't open documents in other apps. Turn the profile off for a login that needs the browser.
- Nothing changes for apps without the profile: a learned `lsopen` still works there, as learned.
- If Menshen ever writes a *filtered* `lsopen` allow, this deny would lose to it (row 19). Keep `lsopen` allows filter-less.

## Alternatives Considered

- Allow http/https links only: impossible, because SBPL has no URL-scheme filter and `lsopen` carries no argument.
- `(deny lsopen (subpath "/"))`, like the other blanket denies: tested, it blocks nothing.
- Leave `lsopen` alone and document it: no-launch would keep a known escape.
