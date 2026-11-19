# Menshen

Menshen (門神, "door god") locks a Mac app inside Seatbelt, the sandbox engine underneath Apple's App Sandbox, using only what the app actually needs.

1. **Analyze** or **Learn.** Analyze reads the app on disk and writes a config without running it: what a Mac app needs to start, its own data folders, the file kinds it says it opens — everything else denied. Learn runs the app once while you use it normally, and records exactly what it does.
2. **Enforce:** run it under a deny-by-default profile built from that. Credentials, other apps' data and startup items stay blocked either way — even if the app touched them while learning.
3. **Replace** (optional): swap the app for a launcher with the same name and icon, so it always runs protected, however you open it. **Restore** puts it back.

No root needed. Tested on macOS 27.0.1.

| Overview | Dashboard |
|---|---|
| ![Overview: every learned app and its newest run](docs/screenshots/overview.png) | ![Dashboard: what the app may access, in plain words](docs/screenshots/dashboard.png) |
| **Config** | **Add Permission** |
| ![Config: every rule with an Allow toggle](docs/screenshots/config.png) | ![Add Permission: profiles, file kinds, your files and folders, limits](docs/screenshots/permissions.png) |

## Get started

```sh
./scripts/build-app.sh          # builds build/Menshen.app (no Xcode needed)
open build/Menshen.app
```

1. Add an app with **+**, or drop it on the sidebar.
2. Click **Analyze** for a config straight away, or **Learn** to use the app the way you normally would and then quit it.
3. Check the **Dashboard**: what it may access, in plain words.
4. Click **Enforce** to run it protected, or **Replace…** to make that permanent.

To change what an app may do after learning, open **Config → Add Permission…**: go offline, allow writes only to temp folders, block other programs, read media or documents anywhere, add your own file types or folders, or set CPU and memory limits.

Prefer the terminal?

```sh
swift build -c release
.build/release/menshen analyze /Applications/VLC.app   # or: learn, and use the app, then quit it
.build/release/menshen enforce /Applications/VLC.app
```

## Good to know

- **Learning protects nothing.** The app runs with everything allowed while it's learned, so learn only apps you trust that far, and review the result. Analyze never runs the app.
- **An analyzed app is a starting point, not a fit.** It allows what an app of that shape usually needs, not what this app does, so expect denials in the enforce log; learn it when you want it exact.
- **Some apps can't be wrapped:** apps that already use App Sandbox, and Apple's own apps. Menshen tells you before it tries.
- **Hardware and location are denied to every app** until you allow them: the camera, the microphone path apps normally use, and Core Location. A permission you granted macOS once doesn't carry into Menshen's sandbox.
- **It guards against a compromised app, not a compromised account.** Other programs running as you can still change Menshen's configs.

More: [Overview](Overview.md) (command line, how it works, all known limits) · [Changelog](docs/CHANGELOG.md) · [Decisions](docs/DECISIONS.md)
