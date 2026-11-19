# QA — Menshen

Two layers:
- **Automated** (`swift test`): runs on every change, using self-built dummy apps only.
- **Manual QA:** run before a release or after a macOS update, against **VLC**, the agreed QA app.

## 0. Set up (once per build)

```sh
cd ~/sync/projects/menshen
swift test                                   # expect: 145 tests passed
./scripts/build-app.sh                       # builds build/Menshen.app
open build/Menshen.app
alias menshen=~/sync/projects/menshen/build/Menshen.app/Contents/Resources/menshen
```

Keep two windows side by side: the Menshen **Dashboard** for VLC, and Terminal. Have a short media file ready in `~/Movies`.

## 1. Analyze — a config without running VLC

Analyze refuses to overwrite a learned config, so do this against a scratch file and leave VLC's real config alone.

```sh
menshen analyze /Applications/VLC.app --config /tmp/vlc-analyzed.json
menshen show /Applications/VLC.app --config /tmp/vlc-analyzed.json | less
```

**Expect:** VLC never launches. The findings name the file kinds it says it opens, and say the network is denied with no evidence in the bundle. In the profile, `;; --- baseline` comes before `;; --- hardening`, and `~/.ssh`, the keychains and browser profiles are denied at the end.

```sh
menshen enforce /Applications/VLC.app --config /tmp/vlc-analyzed.json
```

**Expect:** VLC opens and plays a file from `~/Movies` (its declared media kinds), and the log shows denials for whatever it does that the bundle never declared. Quit it, read the log, then delete `/tmp/vlc-analyzed.json`.

In the app, Analyze shows only for an app with no config or an analyzed one: add a small app you don't mind breaking with **+**, click **Analyze**, and check the Dashboard says **"Analyzed, not running"** with an **Analysis** panel. **Remove from Menshen…** afterwards.

## 2. Learn

1. Dashboard → **Learn** (or Session → Learn with no seconds set).
2. VLC opens. Do what you normally do: play the file from `~/Movies`, open Preferences, change the volume, quit VLC.
3. **Expect:** the status bar counts events while you work. After you quit, the cards show `~/Movies` under **Files** and **Sensitive** says nothing was touched.

## 3. Enforce from Menshen

1. Dashboard → **Enforce**. Repeat exactly what you did in step 2, then quit.
2. **Expect:** VLC works normally. "Blocked just now" stays empty, or shows only harmless items.

## 4. Prove it blocks (negative test)

Still under **Enforce**, do something you did *not* do while learning:
- Open a media file from `~/Downloads` (or any folder you didn't use in step 2).
- Or VLC → File → Save Playlist… to `~/Desktop`.

**Expect:** VLC can't open or save the file, and Menshen shows it in "Blocked just now" (e.g. `Read ~/Downloads/clip.mp4`). That's the sandbox working.

To allow it, use Config → **Add Permission…** → Category → **Media**, then Save. Run Enforce again: the file now opens. A text or `.json` file from the same folder still doesn't.

## 5. Replaced: launch the normal way

The Dashboard should say **"Protected whenever it's opened."** If it doesn't, click **Replace VLC…**.

1. Open VLC from **Finder** (`/Applications`), then from **Spotlight**, and if you like from the **Dock** (drag VLC there first). Quit after each.
2. Double-click a media file whose default app is VLC.
3. **Expect:** VLC works each time, and each launch adds an **Enforce** run in Menshen → **History**. Note whether the Dock shows a second VLC icon while it runs (a known possibility).

Watch the log live from Terminal if you like:
```sh
tail -f ~/Library/Logs/Menshen/org.videolan.vlc/*.jsonl
```

## 6. Restore and re-replace

1. Quit VLC. Dashboard → **Restore Original…**
2. **Expect:** no warnings in Menshen, and these checks pass:
   ```sh
   menshen swaps                                       # "no replaced apps"
   codesign --verify --deep --strict /Applications/VLC.app && echo signature OK
   spctl --assess --type execute /Applications/VLC.app && echo Gatekeeper OK
   ls -a /Applications | grep -i menshen              # nothing
   ```
3. **Replace VLC…** again if you want it to stay protected.

## 7. Camera, microphone and location (per-app protections)

These three service denials are the one part no test reaches: the names come from Apple's own sandbox profiles, not from a capture on this Mac.

1. Pick an app that uses one (a camera or dictation app; Apple's own apps can't be wrapped). **Analyze** or **Learn** it, then **Enforce** and use that feature.
2. **Expect:** the feature fails, and the log shows a blocked `mach-lookup` of `com.apple.cmio…`, `com.apple.coremedia.capture…` or `com.apple.locationd…`.
   ```sh
   grep -o 'com\.apple\.\(cmio\|coremedia\.capture\|locationd\)[^"]*' ~/Library/Logs/Menshen/*/*.jsonl | sort -u
   ```
   If the feature works and nothing is logged, the service name is wrong and the protection is cosmetic — say so in `docs/memory/unresolved.md`.
3. Config → set that protection to **allow** → the feature works again.
4. **Also check nothing else broke:** an app that only plays audio or video still plays it with the camera protection denied.

## 8. Record the result

Write down the date, the macOS version (`sw_vers -productVersion`), the Menshen version (`menshen --version`), each step's result (pass/fail), and anything unexpected, with a screenshot. Add failures to `docs/memory/unresolved.md` or tell Claude.

## Safety notes
- **Never delete VLC's config while VLC is replaced**; the launcher would refuse to start. Restore first.
- If anything goes wrong mid-swap, the original is always at `/Applications/.VLC.menshen.app`. `menshen restore org.videolan.vlc` puts it back.
- After a VLC update while replaced, Enforce refuses ("isn't the binary this config was learned from"). That's expected: re-learn with Merge on.
