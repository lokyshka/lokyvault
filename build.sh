#!/bin/bash

rm -rf builds
mkdir builds

# iOS
fyne package -release -name lokyvault -os ios -appID com.lxkyshka.lokyvault -icon /Users/lokyshka/.cache/templ-icon.png
mkdir builds/Payload
mv lokyvault.app builds/Payload/
cd builds || exit
zip -q -r lokyvault.ipa Payload
cd ..
rm -r builds/Payload
echo "iOS app done!"

# android
CGO_LDFLAGS="-fuse-ld=lld" fyne package -release -name lokyvault -os android -appID com.lxkyshka.lokyvault -icon /Users/lokyshka/.cache/templ-icon.png
mv lokyvault.apk builds/lokyvault.apk
echo "android app done!"

# macOS
mkdir -p builds/lokyvault.app/Contents/MacOS
go build -ldflags="-s -w" -o builds/lokyvault.app/Contents/MacOS/lokyvault main.go
cat > builds/lokyvault.app/Contents/Info.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>lokyvault</string>
    <key>CFBundleIdentifier</key>
    <string>com.lxkyshka.lokyvault</string>
    <key>CFBundleName</key>
    <string>lokyvault</string>
    <key>CFBundleDisplayName</key>
    <string>lokyvault</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleSignature</key>
    <string>????</string>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>
EOF
echo "macOS app done!"

# macOS app packing
backg="/Users/lokyshka/.cache/lvault-backg.png"

hdiutil create -quiet -size 50m -fs HFS+ -volname "lokyvault" "builds/temp.dmg"
hdiutil attach -quiet -nobrowse "builds/temp.dmg"

cp -R builds/lokyvault.app "/Volumes/lokyvault"
ln -s /Applications "/Volumes/lokyvault/Applications"
mkdir "/Volumes/lokyvault/.background"
cp "$backg" "/Volumes/lokyvault/.background/background.png"

sleep 1
osascript <<EOF
tell application "Finder"
    set bgfile to (POSIX file "/Volumes/lokyvault/.background/background.png") as alias
    
    tell disk "lokyvault"
        open
        set current view of container window to icon view
        set toolbar visible of container window to false
        set statusbar visible of container window to false
        
        set the bounds of container window to {400, 100, 1060, 500}
        
        set opts to the icon view options of container window
        set arrangement of opts to not arranged
        set icon size of opts to 128
        set background picture of opts to bgfile
        
        set position of item "lokyvault.app" of container window to {160, 200}
        set position of item "Applications" of container window to {500, 200}
        
        close
        open
        update without registering applications
        delay 2
    end tell
end tell
EOF
SetFile -a C "/Volumes/lokyvault"

sync
hdiutil detach -quiet "/Volumes/lokyvault" -force

hdiutil convert -quiet "builds/temp.dmg" -format ULFO -o "builds/lokyvault.dmg"
rm "builds/temp.dmg"
echo "macOS app packing done!"

# windows
export CGO_ENABLED=1
export CC="/Users/lokyshka/.compilers/zig-wrapper.sh"
export CXX="/Users/lokyshka/.compilers/zig-wrapper.sh"
export GOOS=windows
export GOARCH=amd64
go build -ldflags="-s -w -H=windowsgui -extldflags=-Wl,--subsystem,windows" -o builds/lokyvault.exe main.go
echo "windows app done!"
