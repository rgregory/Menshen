# ADR-009: Reads of your files cover their folder

**Status**: Accepted

**Date**: 2026-10-31

## Context

VLC's learned config listed the videos it played one by one: the folder `/Volumes/media/Home Videos` (its listing) plus two `.MOV` files, each as an exact path. Exact paths only became a folder rule at 4+ files. So the next video in the same folder would be denied, and the config read as a file list rather than a policy. The user asked for folder-level rules ("`/Volumes/media/Home Videos/*`") and a clean, simple config.

## Decision

Learned **reads** in a folder of your own files become one `(subpath folder)` rule once the app read the folder's listing or 2+ files in it. Your own files means a folder inside another volume (`/Volumes/<name>/…`), or one in your home folder outside `~/Library` and hidden folders. Everything else keeps the 4-file threshold, as do all writes. The bundle, own data, content roots and system roots are handled as before.

## Rationale

- The files opened while learning are examples of the user's documents, not the full list. A media player or viewer needs the folder.
- The boundary keeps ADR-007's intent. Other apps' data (`~/Library`) and tool configs (hidden folders) stay exact, and a whole volume or home folder is never granted from two files.
- Hardening comes last and uses the same `file-read*` operation, so secrets inside the folder stay blocked (kernel-tested: `NarrowingTests.readsOfYourFilesCoverTheirFolder`).

## Consequences

- An app gets read access to sibling files it never opened in folders where you opened something. That is the intent. Writes are unchanged.
- The rule is visible in the config and the dashboard summary (the folder shows under Files), not silent.
- Existing configs pick it up with `menshen rebuild <app>`.

## Alternatives Considered

- Treat volumes like content roots (one rule per drive): simpler, but grants a whole drive from one file.
- Lower the threshold for everything, writes included: widens writes and other apps' data.
- The `media` category preset (`menshen allow VLC media`): reads every media file anywhere. That's useful alongside this, but it's a choice you make, not something learned.
