# QA — Menshen

Two layers:
- **Automated** (`swift test`): runs on every change, using self-built dummy apps only.
- **Manual QA:** run before a release or after a macOS update, against **VLC**, the agreed QA app.

## 0. Set up (once per build)

```sh
cd ~/sync/projects/menshen
swift test                                   # expect: 44 tests passed
./scripts/build-app.sh                       # builds build/Menshen.app
open build/Menshen.app
alias menshen=~/sync/projects/menshen/build/Menshen.app/Contents/Resources/menshen
```

Keep two windows side by side: the Menshen **Dashboard** for VLC, and Terminal. Have a short media file ready in `~/Movies`.

## 1. Learn

1. Dashboard → **Learn** (or Session → Learn with no seconds set).
2. VLC opens. Do what you normally do: play the file from `~/Movies`, open Preferences, change the volume, quit VLC.
3. **Expect:** the status bar counts events while you work. After you quit, the cards show `~/Movies` under **Files** and **Sensitive** says nothing was touched.

## 2. Enforce from Menshen

1. Dashboard → **Enforce**. Repeat exactly what you did in step 1, then quit.
2. **Expect:** VLC works normally. "Blocked just now" stays empty, or shows only harmless items.

## 3. Prove it blocks (negative test)

Still under **Enforce**, do something you did *not* do while learning:
- Open a media file from `~/Downloads` (or any folder you didn't use in step 1).
- Or VLC → File → Save Playlist… to `~/Desktop`.

**Expect:** VLC can't open or save the file, and Menshen shows it in "Blocked just now" (e.g. `Read ~/Downloads/clip.mp4`). That's the sandbox working. To allow it, run **Learn** again with "Merge" on while doing that action.

## 4. Replaced: launch the normal way

The Dashboard should say **"Protected whenever it's opened."** If it doesn't, click **Replace VLC…**.

1. Open VLC from **Finder** (`/Applications`), then from **Spotlight**, and if you like from the **Dock** (drag VLC there first). Quit after each.
2. Double-click a media file whose default app is VLC.
3. **Expect:** VLC works each time, and each launch adds an **Enforce** run in Menshen → **History**. Note whether the Dock shows a second VLC icon while it runs (a known possibility).

Watch the log live from Terminal if you like:
```sh
tail -f ~/Library/Logs/Menshen/org.videolan.vlc/*.jsonl
```

## 5. Restore and re-replace

1. Quit VLC. Dashboard → **Restore Original…**
2. **Expect:** no warnings in Menshen, and these checks pass:
   ```sh
   menshen swaps                                       # "no replaced apps"
   codesign --verify --deep --strict /Applications/VLC.app && echo signature OK
   spctl --assess --type execute /Applications/VLC.app && echo Gatekeeper OK
   ls -a /Applications | grep -i menshen              # nothing
   ```
3. **Replace VLC…** again if you want it to stay protected.

## 6. Record the result

Write down the date, the macOS version (`sw_vers -productVersion`), the Menshen version (`menshen --version`), each step's result (pass/fail), and anything unexpected, with a screenshot. Add failures to `docs/memory/unresolved.md` or tell Claude.

## Safety notes
- **Never delete VLC's config while VLC is replaced**; the launcher would refuse to start. Restore first.
- If anything goes wrong mid-swap, the original is always at `/Applications/.VLC.menshen.app`. `menshen restore org.videolan.vlc` puts it back.
- After a VLC update while replaced, Enforce refuses ("isn't the binary this config was learned from"). That's expected: re-learn with Merge on.
