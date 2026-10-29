# Lessons — Menshen

## 2026-10-29 · Pin down the project's purpose before writing an ingest

**What happened:** I was asked to ingest Apple's App Sandbox docs into an empty project. I assumed Menshen was a Mac app that would ship with the sandbox and wrote the digest for an app developer (which entitlements to declare). Menshen actually uses **Seatbelt** (the engine underneath App Sandbox) to confine *other* local apps from the outside. That's a different reader with different questions.

**Rule:** When ingesting a source into a project whose purpose isn't written down anywhere (empty repo, no README or memory), ask one question first: "What will this be used for?" Then write the digest through that lens. A digest written for the wrong reader looks complete and still misses the point.

**How to apply:** Before writing a reference doc, check README / CLAUDE.md / memory for the project's mission. If none of those exist, ask before writing, not after.

## 2026-10-29 · A "nothing found" result needs a positive control

**What happened:** I recorded "custom sandbox-exec profiles don't log denials" as a verified fact. In reality the queries were broken. In zsh, `log` is a shell builtin, so the first `log show` did nothing and its error was hidden by `grep`. Later queries used `log show`, which reads the saved log, and the kernel sandbox lines never get saved. A live `log stream` caught 8 of 8 denials.

**Rule:** Before reporting that something *doesn't* happen, prove the query can find a known-positive case (one line you know exists). Use absolute paths (`/usr/bin/log`) for tools that clash with shell builtins.

**How to apply:** For any negative result, run a positive control alongside it, and only tag it [verified] once the control has hit.

## 2026-10-29 · zsh doesn't word-split unquoted variables

**What happened:** `FILES=$(grep -rl …); perl -pi … $FILES` handed perl the whole newline-separated list as **one** filename ("Can't open …"). Bash would have split it; zsh doesn't.

**Rule:** In this user's shell (zsh), pass file lists with `| tr '\n' '\0' | xargs -0 …` (or `${=VAR}`), never as a bare `$VAR`.

## 2026-10-29 · Fix a flaky build at its cause, not with retries

**What happened:** `swift test` failed about half the time with "plugin for module 'TestingMacros' not found". A retry wrapper didn't help: within one invocation every retry failed. Comparing compiler flags showed the failing builds lacked `-plugin-path …/host/plugins/testing`. Adding that flag in `Package.swift` made 6 of 6 runs pass.

**Rule:** When something is flaky, diff a passing run against a failing one before adding retries. Here the retry script was deleted once the cause was fixed.
