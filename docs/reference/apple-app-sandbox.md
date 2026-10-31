# Apple App Sandbox, read for Seatbelt (Menshen)

**Purpose:** Menshen uses **Seatbelt** (`sandbox-exec` / SBPL profiles) to lock down local apps *from the outside*. This digest reads Apple's App Sandbox docs with that goal in mind. App Sandbox is Apple's entitlement-driven layer on top of the same Seatbelt engine.
**Sources:** Apple's [App Sandbox](https://developer.apple.com/documentation/security/app-sandbox) collection and 8 linked pages (fetched 2026-10-29) · the local `sandbox-exec(1)` and `sandbox_init(3)` man pages · Apple's own profiles in `/System/Library/Sandbox/Profiles/` · tests run on this Mac.
**Machine:** macOS 27.0.1 (26A434). Facts tagged **[verified]** were tested here; **[apple-doc]** came from Apple's pages; **[unverified]** still needs a test.

## BLUF

1. **Apple's App Sandbox profile is the reference to crib from.** Every App Sandbox entitlement becomes SBPL rules in `/System/Library/Sandbox/Profiles/application.sb` (995 lines), which imports `appsandbox-common.sb` and `system.sb`. That's Apple's tested rule set for each capability (network, camera, USB, Downloads…). Copy its patterns; don't `import` it directly (see the "Using Apple's profiles" section). **[verified]**
2. **`sandbox-exec` is deprecated but works on macOS 27** for custom profiles (`-p` / `-f`, with `-D` parameters). **[verified]**
3. **Named built-in profiles are dead.** `sandbox-exec -n no-network …` gets SIGKILLed (exit 137) on macOS 27. `sandbox_init(3)` says the `kSBXProfile*` profiles are killed when built against SDK ≥ 27.0. Menshen must ship its own profiles. **[verified]**
4. **Confinement covers every child process.** A shell and everything it launches stay inside. **[verified]**
5. **Denials don't say "sandbox."** File denials show up as `EPERM` (errno 1). A network denial looks like a DNS failure (`curl: (6) Could not resolve host`) because the resolver is blocked before any connection is made. **[verified]**
6. **Seatbelt can report everything an app does, but only to a live stream.** Denials are logged as kernel `Error` lines: `Sandbox: <proc>(pid) deny(1) <op> <target>`. Adding `(with report)` to an `allow` rule logs every allowed operation as a kernel **debug** line. `(allow default (with report))` is therefore a complete learn mode, and it doesn't need root. **Neither kind of line reaches the saved log**, so `log show` finds 0. Only `/usr/bin/log stream --level debug --predicate 'sender == "Sandbox"'` running *during* the run catches them. **[verified]** *(Correction: an earlier version of this note said denials weren't logged. That came from bad queries: zsh's `log` builtin and `log show` reading the saved log.)*
6a. **Two kinds of app can't be wrapped:** Apple's own apps (killed by launch constraints even with no sandbox) and apps that already use App Sandbox (`deny(1) forbidden-sandbox-reinit`, then a SIGTRAP inside `libsecinit`). Third-party apps without App Sandbox (VLC tested) run fine. **[verified]**
6b. **Network rules can't name a host.** SBPL only accepts `*` or `localhost` as the host (`host must be * or localhost in network address`). The finest control is local vs. remote and which port. **[verified]**
7. **The boundary that matters most is `mach-lookup`.** A confined process can ask a system service (via XPC) to act for it, and the service runs with the service's own rights. Apple's guidance to put risky work in a separate XPC service is the same mechanism seen from the other side. **[apple-doc + inference]**

## How App Sandbox is built on Seatbelt **[verified]**

```
application.sb   (App Sandbox base; "auto-generated, private interface, may change")
 ├─ (import "system.sb")             baseline every process needs (dyld, libSystem, …)
 ├─ (import "appsandbox-common.sb")  capability macros: (network-client), (camera), …
 └─ (when (entitlement "com.apple.security.X") (macro))   ← entitlement → rules
```

- The profile reads parameters the App Sandbox runtime supplies: `(param "_HOME")`, `(param "application_bundle_id")`, `(param "application_darwin_user_dir")`. Menshen would have to supply equivalents with `-D`.
- Rules that apply no matter which entitlements an app has (good defaults for Menshen):
  - `(deny default file-link)`: no hard links.
  - `(allow signal (target same-sandbox))`: it can only signal processes in its own sandbox.
  - `(deny file-write-xattr (xattr "com.apple.quarantine"))`: it can't remove the quarantine flag.
  - `(deny file-read-xattr file-write-xattr (xattr-prefix "com.apple.security.private."))`
  - `(deny network-outbound (remote ip "localhost:631"))` and `/private/var/run/cupsd` unless printing is allowed: no CUPS.
  - `(deny network-outbound (literal "/private/var/run/mDNSResponder"))` unless the app has network access: this is why DNS fails first.

### Entitlement → SBPL map (from application.sb / appsandbox-common.sb)

This is Menshen's capability vocabulary. Each row is a switch Menshen could expose.

| Capability | App Sandbox entitlement | What Apple's profile actually allows |
|---|---|---|
| Outbound network | `network.client` | `(network-client)` = `(system-network)` + `(allow network-outbound (remote ip))` + a list of `mach-lookup` services (cfnetwork agents, airportd, NetworkDiagnostic…) + Kerberos config reads |
| Inbound network | `network.server` | `(network-server)` = `(system-network)` + `(allow network-inbound (local ip))` |
| DNS | either network key | lifts the deny on `/private/var/run/mDNSResponder` |
| Camera | `device.camera` | `(camera)` macro (+ WebKit camera support) |
| Microphone | `device.microphone` / `device.audio-input` | `(audio-input)` macro. `(audio-output)` is granted to everyone. |
| USB / HID | `device.usb`, `device.hid` | `iokit-open-user-client` for `IOUSBDeviceUserClientV2`, `IOUSBInterfaceUserClientV3`, `IOHIDLibUserClient` |
| Printing | `print` | `(printing)` + allows CUPS |
| Downloads folder | `files.downloads.read-only` / `-write` | `read-only-and-issue-extensions (home-subpath "/Downloads")` + `process-exec` there |
| User-picked files | `files.user-selected.*` | `mach-lookup com.apple.scopedbookmarksagent.xpc` + sandbox *extensions* issued by the open/save panel (powerbox) |
| Apple Events | `temporary-exception.apple-events` | `(allow appleevent-send (appleevent-destination "<bundle-id>"))`; denied by default |
| Other apps' prefs | `temporary-exception.shared-preference.*` | `user-preference-read/write`; denied by default |

Other entitlement names in the file (for completeness): `device.serial`, `device.firewire`, `device.bluetooth`, `smartcard`, `personal-information.{addressbook,calendars,location}`, `assets.music.*`, `files.bookmarks.{app,document,collection}-scope`, `scripting-targets`, `vm.hypervisor`, `vm.networking`, `network.multipath-tcp`, and several `com.apple.developer.*` keys.

### What App Sandbox always blocks → candidate defaults for Menshen

Apple's list of things a sandboxed app can never do **[apple-doc]**, with the SBPL operation that governs each:

| Blocked behavior | SBPL operation | Source of the op name |
|---|---|---|
| Sending Apple Events to arbitrary apps | `appleevent-send` | verified in application.sb |
| Reading/writing other apps' preferences | `user-preference-read` / `user-preference-write` | verified in application.sb |
| Killing other apps | `signal` (App Sandbox allows only `target same-sandbox`) | verified in application.sb |
| Authorization Services | `authorization-right-obtain` | verified in application.sb |
| Loading kernel extensions | `system-kext-load` | **[unverified]**: not in these files (`system-kext-query` is) |
| Accessibility APIs, network config, simulated input in panels, `userInfo` in distributed notifications | mostly `mach-lookup` to the service behind each one | **[unverified]**: needs per-service mapping |

## Seatbelt behavior tested on this Mac

| # | Test | Result |
|---|---|---|
| 1 | `(allow default)(deny file-write* (subpath (param "LOCK")))` with `-D LOCK=…`, running `sh -c 'touch …; python3 …'` | Writes elsewhere OK. Writes to the locked dir fail in both the shell's child `touch` and in Python: **errno 1 EPERM**. Children inherit the sandbox. |
| 2 | `sandbox-exec -n no-network` and `-n no-internet` | **Exit 137 (SIGKILL).** Named profiles are unusable on macOS 27. |
| 3 | `(allow default)(deny network*)` + `curl https://example.com` | `curl: (6) Could not resolve host`, exit 6. It looks like DNS trouble, not a permission error. |
| 4 | Bare `(version 1)(deny default)` | Can't even start the command: `execvp() … Operation not permitted`, exit 71 |
| 5 | `(deny default)` + `(import "system.sb")(allow process-exec)(allow file-read*)` | Program runs; its write gets EPERM. **This is a working minimal base for deny-by-default profiles.** |
| 6 | `(deny … (with report))` | Profile compile error, exit 65: "report modifier does not apply to deny action". `(with report)` only works on `allow` rules. |
| 7 | `(allow default (with report))` under `log stream --level debug` | Every operation logged at debug level: `Sandbox: striplyprobe(80033) allow file-write-create <path>`, plus sysctl-read, file-ioctl… Nothing in `log show`. |
| 8 | 4 deny styles × 2 runs (plain, deny-default, `(with message …)`, `(with send-signal …)`) under `log stream` | 8 of 8 denials logged as kernel `E` lines. `log show` found 0 a few seconds later. |
| 8a | VLC (third-party, no App Sandbox) under report mode, 5 s | Ran normally. 2,247 allow lines + 517 deny lines (the denials came from *other* processes), 0 dropped-message notices. Op mix: file-read-metadata 1259, file-read-data 481, system-info 279, sysctl-read 77, mach-lookup 67… A few lines came from helper services (`mediaremoted`), so filter by the process tree. |
| 8b | Wipr (App Sandbox app) under report mode | Crashed at launch: `deny(1) forbidden-sandbox-reinit`, then SIGTRAP in `_libsecinit_appsandbox` |
| 8c | Calculator, with and without sandbox-exec | Killed both times: `CODESIGNING` / Launch Constraint Violation. Apple's apps must be started by launchd. |
| 8d | `(remote ip "1.2.3.4:443")` and `"example.com:443"` | Compile error: "host must be * or localhost". `*:443` and `localhost:8080` compile. |
| 9 | A `sandbox-exec` inside an `(allow default)` sandbox, launching another `sandbox-exec` | Exit 0: the nested call didn't fail. Whether the two policies actually *stack* hasn't been tested. |
| 10 | A copy of `/usr/bin/touch` run from another folder | Killed: `CODESIGNING` / **Launch Constraint Violation**. Apple system binaries can only run from their system location. That limit is separate from Seatbelt. |

Use `/usr/bin/log`, not `log`. In zsh, `log` is a shell builtin and quietly does nothing.

### Found while building Menshen (macOS 27.0.1)

| # | Finding | Evidence |
|---|---|---|
| 11 | **Later rules win.** `(allow file-write* (subpath D))(deny file-write* (subpath D/sub))` denies `D/sub/x`; reversing the two rules allows it. | `SeatbeltOrderingTests` (real kernel) |
| 12 | **Deny reports from processes that exit at once are often dropped.** A probe that exits immediately after a denied `open`: 12 of 20 logged. The same probe staying alive 300 ms: 20 of 20. Enforcement held every time (EPERM). | two rounds of 10 + 10 |
| 13 | **Report mode can't see checks made in user space.** VLC's learn run reported only 69 `mach-lookup`s (50 names) and 1–2 `user-preference-read`s. Under enforce it was then denied `com.apple.pbs.fetch_services`, `com.apple.tsm.uiserver`, input-method services, `com.apple.universalaccess` prefs, and more. Adding explicit `(allow mach-lookup (with report))` / `(allow user-preference-read (with report))` didn't change the count (still 69). Launchd and cfprefsd do these checks; they report *denials* but not reported allows. | VLC 12 s run with explicit report rules |
| 14 | **The `log stream --style ndjson` format.** The first line is plain text (`Filtering the log data…`), then one JSON object per line. Kernel Sandbox lines have `processID: 0`, so the pid comes from the message. Allow reports are `messageType: Default`, denials `Error`. | captured stream |
| 15 | **Network reports never include the host:** `remote:*:9` even for `127.0.0.1`. That matches SBPL, which can only say `*` or `localhost`. | `nc` to 127.0.0.1 |
| 16 | **Foundation's `URL.resolvingSymlinksInPath` strips `/private`** (`/private/tmp` → `/tmp`, `/private/var/folders` → `/var/folders`). The kernel matches the real `/private/...` path, so rules built that way never match. Use `realpath(3)`. | Menshen bug, fixed |
| 17 | **VLC end to end.** Learn (20–25 s, playing a silent WAV): about 2,500 reports → 80–85 rules. Enforce: VLC played and shut down cleanly. Distinct denials went from 27 to 10 after giving the app full access to its own folders and preference domain, then to **0** after adding the `com.apple.*` service and preference lines (ADR-004). | `menshen learn/enforce` |
| 19 | **A rule without a filter is only the operation's default.** `(allow file-write* (subpath D))(deny file-write*)` still allows writes in D: the filter-less deny loses to *any* filtered allow, whatever the order. `(deny file-write* (subpath "/"))` makes "later wins" apply again. Menshen's blanket template denies carry `(subpath "/")` for this reason. | `/usr/bin/touch` with three profiles; `TemplateTests` / integration |
| 20 | **Resource limits and sandbox-exec:** `taskpolicy -c background` (priority 4 versus 31) and `ulimit -t` (SIGXCPU) survive `sandbox-exec`. `taskpolicy -m <MiB>` does **not**: a 300 MiB allocation ran fine through `taskpolicy -m 50 sandbox-exec …`, but was killed when taskpolicy ran *inside* the sandbox right before the program (it needs exec and read access to `/usr/sbin/taskpolicy`). Seatbelt itself has no CPU or memory controls. | eat.c, ps, `TemplateTests` |
| 21 | **NSTemporaryDirectory ignores TMPDIR** and always returns the per-user `/var/folders/…/T`. Only App Sandbox containers give Mac apps a private temp folder; command-line tools generally honor TMPDIR. | tmpdir.swift |
| 22 | **Patterns under home:** `(require-all (subpath HOME) (regex #"/\.env(\.[^/]*)?$"))` blocks `.env` and `.env.local` anywhere under HOME, while `readme.txt` next to them stays readable. | `SanitySetTests` |
| 23 | **Under `(allow default)`, explicit denies are enforced but never logged.** Same deny rule, same probe: EPERM every time, but no kernel report; under `(deny default)` the report arrives. `(with report)` is refused on denies ("report modifier does not apply to deny action"). Menshen's Restricted Sandbox therefore starts from `(deny default)` plus explicit allows for each operation family. | `RestrictedTests.blockedAttemptsAreLogged` (failed with allow-default) |
| 24 | **A rule naming a specific operation beats a wildcard one, whatever the order.** `(allow file-read-data (subpath W))` before `(deny file-read* (require-all … .env regex))` still let `W/.env` be read; with `(allow file-read* (subpath W))` the later deny wins. Keep allows and denies on the same operation names when order is meant to decide. | `RestrictedTests.onlyWhatYouChose` |
| 25 | **Kernel deny reports for a real app are not guaranteed.** VLC under the Restricted Sandbox: its startup read of its own `vlcrc` (denied every time, per `sandbox_check`) was reported in 4 of 7 runs and missing in 3, with an identical profile. Network denials from opening a URL were reported every time (3 of 3 runs, CLI and GUI). Enforcement never varied. Treat the log as a record of what *was* reported, not proof that nothing else was blocked. | raw `log stream` next to each run; `sandbox_check` |
| 26 | **`system.sb` allows every per-pid Mach registration** (`(allow mach-register (local-name-prefix ""))`), the kind AppKit makes (`com.apple.axserver`, `com.apple.tsm.portname`, `com.apple.coredrag`). Global registration is refused under it (1100, BOOTSTRAP_NOT_PRIVILEGED) and works with `(global-name "x")` or a filter-less allow. A filter-less `(deny mach-register)` after the import changes nothing: it only sets the default, and Apple's filtered allow wins. | `NarrowingTests` + `nameprobe` (`bootstrap_register2`) |
| 27 | **Name filters are enforced:** `(ipc-posix-name "x")` for `ipc-posix-shm-write-create` (other names EPERM), `(sysctl-name "x")` for `sysctl-write` (`kern.tcsm_enable` is writable without root, so it serves as the control). `system.sb` already allows writing `kern.grade_cputype` and `kern.wq_limit_cooperative_threads`. | `NarrowingTests` |
| 28 | **Network filters take only `*` or `localhost` as the host.** `(local ip "127.0.0.1:47113")` is a compile error ("host must be * or localhost"). And `network-inbound` is checked when the app starts listening, not per connection: with `(allow network-inbound (local ip "localhost:P"))` an app bound to `*:P` still accepted a connection to the Mac's Wi-Fi address, and `(allow network-bind (local ip "localhost:P"))` still let it bind `*:P`. Seatbelt can't keep a listener to loopback peers; that takes the app, the firewall or Little Snitch. | `nc` under `sandbox-exec`, from this Mac to its own LAN address (2026-10-31) |
| 29 | **The per-user Darwin folder is every app's**: `/private/var/folders/xx/yyy/C` held 536 app cache folders and `T` 2,183 entries on this Mac. Its path is stable per user (`getconf DARWIN_USER_DIR`), not per boot. Owning the whole folder let a confined app read and write other apps' caches; Menshen now owns `T` plus the app's own `C/<app>`, `0/<app>`. | `NarrowingTests.darwinFolderGivesOnlyTheAppsOwnCaches` |
| 30 | **Bind reports don't show the address.** A socket bound to `127.0.0.1:P` is reported as `network-bind local:*:P` and `network-inbound local:*:P`, exactly like one bound to `0.0.0.0:P`. A learned `*:P` doesn't mean the app listens on every interface; check with `lsof -nP -iTCP:P` while it runs. | python bind under `(allow default (with report))` + `log stream` (2026-10-31) |
| 31 | **What LaunchServices opens runs outside the sandbox, and `lsopen` can't be filtered.** With `(allow lsopen)` and read access to an app, a confined process opened a self-built dummy app with `LSOpenCFURLRef` even though `process-exec*` was denied. The dummy started from launchd (ppid 1), unsandboxed. Without `lsopen`, or without read access to the item, the call returns -54 (permErr). URLs go through the same check and need no file access: a custom-scheme URL started its handler app the same way. The check carries no argument. `(deny lsopen (subpath "/"))` blocks nothing, path filters on an allow never match, `require-not` always matches, and there is no URL-scheme filter (`url-scheme` is unbound). So it's all or nothing. A filter-less `(deny lsopen)` after the filter-less learned allow blocks it, but a filtered allow placed earlier (even a vacuous `require-not`) still wins, as in row 19. Links can't be let through to the browser while apps are blocked. LaunchServices also ignores URL claims from apps in temp folders (`in-temp-dir` in `lsregister -dump`). | `LSOpenTests` + `lsopenprobe` (mutation-checked); URL case by hand, with the dummy registered outside temp (2026-10-31) |
| 26 | **A flood of sandbox reports from one process starves others' reports, silently.** While a `(allow default (with report))` process ran in a loop, Menshen's enforce integration test lost almost every report from its probe: 1 record, 0 denials, closing canary still arrived, no stream notice. That was 5 of 5 runs, against 5 of 5 passing without the flood. Enforcement held. So a Menshen log can be incomplete while another learn run (or any heavy reporter) is active. | `IntegrationTests` with and without a report flood |
| 18 | **Prefix filters work as named.** `(global-name-prefix "com.apple.")` makes `com.apple.pasteboard.1` reachable, while `org.example.*` stays blocked. `(preference-domain-prefix "com.apple.")` gives an unentitled CoreFoundation probe all 39 keys of `com.apple.universalaccess`; `"org.videolan."` gives 0, and so does no rule. The global domain needs `(preference-domain "kCFPreferencesAnyApplication")`. Unknown filter names are rejected (`unbound variable`). Use an *unentitled* test binary: `/usr/bin/defaults` read the preferences even with no rule. | probe + `PlatformRuleTests` |

## Using Apple's profiles from Menshen

- **Read, don't import.** `application.sb` is marked auto-generated private interface that can change in any OS update. Its rules depend on `(entitlement …)` checks, which look at the *target process's* code-signing entitlements, and on parameters only the App Sandbox runtime passes. Importing it from `sandbox-exec` is **[unverified]** and fragile.
- **`system.sb` is usable** as a base import (test 5). It's still private interface, so pin the macOS version Menshen was tested on and re-test on every OS update.
- **Track drift:** hash `application.sb`, `appsandbox-common.sb`, and `system.sb` on each macOS release, and diff them to see what Apple changed in its capability rules.

## App Sandbox facts that still matter to an outside-in wrapper **[apple-doc]**

- **Seatbelt can't override TCC (privacy permissions).** Camera, mic, contacts, calendars, location, Full Disk Access, and (on macOS 14+) other apps' containers are also gated by the user's privacy prompts. An `allow` in SBPL doesn't skip the prompt. Full Disk Access can only be granted in System Settings. **[unverified for sandbox-exec targets]:** which app the prompt names (often the terminal or launcher that started the process).
- **Other apps' containers (macOS 14+):** they're tied to code signature. Any process, sandboxed or not, that opens another app's container triggers a user prompt. If the user denies it while the target is *launching*, the target fails to launch. That's a failure mode Menshen will see when it wraps App Sandbox apps.
- **User-picked file access depends on the system.** The open/save panel runs in a separate process and *issues sandbox extensions* to the app. Security-scoped bookmarks replay those extensions. **[unverified]:** whether powerbox grants work at all for a GUI app running under `sandbox-exec`. It's likely to be the hardest problem when wrapping GUI apps.
- **Helpers:** children started with `Process` / `fork`+`exec` inherit the sandbox (matches test 1). XPC services, login items, and helper apps run under **their own** policy. Seen from Menshen's side, that's a way out of the wrap unless `mach-lookup` is restricted.
- **EPERM is ambiguous:** SIP and data-protection classes return `EPERM` too, while POSIX permissions and ACLs return `EACCES` (13). An EPERM alone doesn't prove Seatbelt denied it.
- **Finding targets that are already sandboxed:** `codesign -dvvv --entitlements - /path/App.app` (look for `com.apple.security.app-sandbox = true`), or Activity Monitor → View → Columns → Sandbox. **[unverified]:** whether Activity Monitor shows "Yes" for `sandbox-exec` processes.
- **Apple's Console filter** (`type:error` · `subsystem:com.apple.sandbox.reporting` · `category:violation`) is for App Sandbox apps. For our profiles, stream the kernel lines live (`sender == "Sandbox"`; tests 7–8).

## Developer-side material (background only)

Kept short because Menshen isn't shipping a sandboxed app. See the linked pages for details.
- An entitlement catalog of Boolean keys (network, hardware, personal data, user-selected/Downloads/Pictures/Music/Movies files). `files.all` is **deprecated since 10.11**.
- Things a sandboxed app can't do (the list above).
- Containers live at `~/Library/Containers/<bundle-id>`; `container-migration.plist` (`Move`, `MigrateScriptsForApplication`, `Symlink`) moves pre-sandbox files into them.
- An embedded CLI helper must carry exactly `app-sandbox` + `inherit`. `get-task-allow` conflicts with `inherit`, so a sandboxed helper can't be debugged.

## Open questions to test next

1. ~~Where do denials get reported?~~ **Resolved:** a live `log stream` of kernel `Sandbox` lines (tests 7–8). Still open: does `log stream` drop lines under a heavy GUI workload? (VLC had 0 drops in 5 s.)
2. Does a second `sandbox_init` really *stack* for plain processes? ~~App Sandbox apps under `sandbox-exec`~~ **Resolved:** they crash (test 8b).
3. Do open/save panels and security-scoped bookmarks work for GUI apps under `sandbox-exec`?
4. Which TCC client does the prompt name for a wrapped app, and do grants carry over?
5. What's the minimal `mach-lookup` allowlist for a typical CLI tool, and for a typical GUI app?
6. How should `.app` bundles be launched: `sandbox-exec` on `Contents/MacOS/<exe>` versus `open` (LaunchServices re-parents the process, so the sandbox may not follow)?

## Links

- App Sandbox: https://developer.apple.com/documentation/security/app-sandbox
- Protecting user data: https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox
- Accessing files: https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox
- Diagnosing violations: https://developer.apple.com/documentation/security/discovering-and-diagnosing-app-sandbox-violations
- Embedding a CLI helper: https://developer.apple.com/documentation/xcode/embedding-a-helper-tool-in-a-sandboxed-app
- Container migration: https://developer.apple.com/documentation/security/migrating-your-app-s-files-to-its-app-sandbox-container
- Local: `man sandbox-exec`, `man 3 sandbox_init`, `/System/Library/Sandbox/Profiles/{application,appsandbox-common,system,bsd}.sb`

**Refetch tip:** Apple's doc pages render with JavaScript and come back empty from plain fetchers. Use the DocC JSON instead: `https://developer.apple.com/tutorials/data/documentation/<path>.json`
