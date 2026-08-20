#!/bin/bash

# macOS
mkdir -p builds/lokyvault.app/Contents/MacOS
go build -o builds/lokyvault.app/Contents/MacOS/lokyvault main.go
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

# windows
export CGO_ENABLED=1
export CC="/Users/lokyshka/.compilers/zig-wrapper.sh"
export CXX="/Users/lokyshka/.compilers/zig-wrapper.sh"
export GOOS=windows
export GOARCH=amd64
go build -ldflags="-H=windowsgui -extldflags=-Wl,--subsystem,windows" -o builds/lokyvault.exe main.go
echo "windows app done!"
