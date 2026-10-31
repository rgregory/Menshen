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

## 2026-10-29 · A failure test must check *which* failure happened

**What happened:** `failedLauncherBuildRollsBack` passed while testing nothing. Replace failed earlier, on a missing stub (and in another version on a signature check), before the rename, so the rollback never ran. `#expect(throws:)` was satisfied by the wrong error.

**Rule:** When testing an error path, assert the error that proves the intended path ran (here "building the launcher failed … original is back in place"), and mutation-check it.

## 2026-10-29 · Unit tests of parts don't prove the whole chain

**What happened:** every swap unit test passed, but a replaced app couldn't start at all: its profile pointed at the old bundle path. Only the end-to-end test (LaunchServices → launcher → enforce → dummy app) caught it.

**Rule:** For a feature that crosses process or OS boundaries, write one real end-to-end test before calling it done.

## 2026-10-29 · Fix a flaky build at its cause, not with retries

**What happened:** `swift test` failed about half the time with "plugin for module 'TestingMacros' not found". A retry wrapper didn't help: within one invocation every retry failed. Comparing compiler flags showed the failing builds lacked `-plugin-path …/host/plugins/testing`. Adding that flag in `Package.swift` made 6 of 6 runs pass.

**Rule:** When something is flaky, diff a passing run against a failing one before adding retries. Here the retry script was deleted once the cause was fixed.

## 2026-10-30 · A profile that reads right can still be enforced differently

**What happened:** The templates wrote `(deny file-write*)` *after* the learned allows, which looks correct if later rules win. The kernel still allowed the learned write. A deny with no filter is only the operation's default, and any filtered allow beats it. Reviewing the profile text would never have caught this; the kernel integration test did.

**Rule:** Every restriction Menshen adds gets a kernel test that runs a real process and checks for EPERM, with a control showing the same action succeeds without the restriction.

## 2026-10-31 · Shell one-liners in tests fail for reasons of their own

**What happened:** In the Restricted Sandbox tests, checks of the form "this should fail" passed for the wrong reason. `/bin/sh` is a shim that starts bash, and "no other programs" blocked that, so every `sh -c …` failed. Then `read l < file` returned 1 only because the test file had no trailing newline. The `.env` check "passed" while `.env` was actually readable. Only a positive control in the same profile (a check that must succeed) exposed both.

**Rule:** Every group of "must fail" kernel checks gets a "must succeed" control in the **same** profile and runner. Check content (`[ "$l" = x ]`), not just exit status.

## 2026-10-31 · Confirm the user's mental model before building the obvious reading

**What happened:** Asked for a "temp-VM" to read an untrusted PDF, I built a dedicated sandboxed PDF viewer. The user wanted something general: drop *any* app on an icon and it runs in a sandbox they configured; the PDF was only an example.

**Rule:** When a request includes an example ("…and a PDF"), ask whether the example *is* the feature or only illustrates it, before building something specific to the example.

## 2026-10-30 · A count of zero can mean the check couldn't look

**What happened:** To confirm a test left nothing in the user's Trash, I ran `ls ~/.Trash | wc -l` and reported 0. In fact `ls` was refused ("Operation not permitted": this session can't list the Trash), so `wc` counted zero lines of nothing. The claim happened to be true, but it was unverified.

**Rule:** Never pipe a check straight into a count. Check the command's own exit status first, and confirm with a positive control (create a known item, see it, remove it) before reporting "none".

## 2026-10-31 · Judge a rule inside the profile it will live in

**What happened:** Reviewing Fastpotify's learned `mach-register`, I tested name filters under a bare `(allow default)` profile and said denying registration would break VoiceOver and drag and drop. Under Menshen's real profile the answer was different: `system.sb`, which every profile imports, already allows every per-pid registration, so that deny would have changed nothing, and the actual hole was *global* registration. The kernel test against the compiled profile caught it.

**Rule:** Before calling a rule risky, necessary or redundant, check what `system.sb` and the always-on rules already grant, and test it in the full compiled profile, not a minimal one.
