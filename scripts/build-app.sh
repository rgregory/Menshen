#!/bin/sh
# Builds build/Menshen.app from the Swift package (no Xcode needed).
#   Contents/MacOS/Menshen              the GUI
#   Contents/Resources/menshen-launch   stub copied into each launcher when an app is replaced
#   Contents/Resources/menshen          the CLI
set -eu
cd "$(dirname "$0")/.."

if pgrep -f "$PWD/build/Menshen.app/Contents/MacOS/Menshen" >/dev/null; then
    echo "build-app.sh: Menshen is running from build/Menshen.app; it will quit when the bundle is replaced." >&2
fi

swift build -c release --product MenshenApp
swift build -c release --product menshen-launch
swift build -c release --product menshen
BIN=$(swift build -c release --show-bin-path)
VERSION=$(sed -n 's/^public let menshenVersion = "\(.*\)"/\1/p' Sources/MenshenCore/Config.swift)

APP=build/Menshen.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN/MenshenApp" "$APP/Contents/MacOS/Menshen"
cp "$BIN/menshen-launch" "$APP/Contents/Resources/menshen-launch"
cp "$BIN/menshen" "$APP/Contents/Resources/menshen"

# App icon from assets/AppIcon.png: 1024x1024, rendered from assets/AppIcon.svg (Haiku "Action_Logout", MIT —
# see assets/ATTRIBUTION.md), so every size is downscaled and sharp.
ICONSET=build/AppIcon.iconset
rm -rf "$ICONSET"
mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
    sips -z "$s" "$s" assets/AppIcon.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
    sips -z "$((s * 2))" "$((s * 2))" assets/AppIcon.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
cp assets/LICENSE-haiku-icons.txt "$APP/Contents/Resources/"

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key><string>Menshen</string>
    <key>CFBundleIdentifier</key><string>dev.menshen.app</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundleName</key><string>Menshen</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSPrincipalClass</key><string>NSApplication</string>
</dict>
</plist>
EOF

codesign -s - --force "$APP/Contents/Resources/menshen-launch"
codesign -s - --force "$APP/Contents/Resources/menshen"
codesign -s - --force "$APP"
codesign --verify --strict "$APP"
# Re-register so Finder and the Dock don't keep a stale (generic) icon for the rebuilt bundle.
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f "$APP"
echo "built $APP ($VERSION)"
