#!/bin/sh
set -e

basedir="$(realpath "$0" | xargs dirname)"
cd "$basedir"

export CFLAGS= CXXFLAGS= CPPFLAGS= LDFLAGS= RUSTFLAGS=

dx build -p letmein-gui --android --target aarch64-linux-android --release

ANDROID_APP="target/dx/letmein-gui/release/android/app/app"
ANDROID_RES="$ANDROID_APP/src/main/res"

# Fix the generated display name (dx derives it from the binary name "letmein-gui" -> "LetmeinGui").
sed -i 's|<string name="app_name">LetmeinGui</string>|<string name="app_name">Letmein</string>|' \
    "$ANDROID_RES/values/strings.xml"

# dx hardcodes versionCode = 1 in its build.gradle.kts template.  Derive it
# from the Cargo workspace version (major*10000 + minor*100 + patch).
VERSION="$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')"
VER_MAJOR="$(echo "$VERSION" | cut -d. -f1)"
VER_MINOR="$(echo "$VERSION" | cut -d. -f2)"
VER_PATCH="$(echo "$VERSION" | cut -d. -f3)"
VERSION_CODE="$(expr "$VER_MAJOR" \* 10000 + "$VER_MINOR" \* 100 + "$VER_PATCH")"
sed -i "s/versionCode = 1\b/versionCode = $VERSION_CODE/" \
    "$ANDROID_APP/build.gradle.kts"

# dx hardcodes default launcher icons into the Android project and doesn't
# honour [bundle] icon or [android] icon for Android builds.  Work around
# this by overwriting the generated resources and re-running gradle.
cp android/res/drawable/ic_launcher_background.xml         "$ANDROID_RES/drawable/"
cp android/res/drawable-v24/ic_launcher_foreground.xml     "$ANDROID_RES/drawable-v24/"
cp android/res/mipmap-anydpi-v26/ic_launcher.xml           "$ANDROID_RES/mipmap-anydpi-v26/"
cp android/res/mipmap-mdpi/ic_launcher.webp                "$ANDROID_RES/mipmap-mdpi/"
cp android/res/mipmap-hdpi/ic_launcher.webp                "$ANDROID_RES/mipmap-hdpi/"
cp android/res/mipmap-xhdpi/ic_launcher.webp               "$ANDROID_RES/mipmap-xhdpi/"
cp android/res/mipmap-xxhdpi/ic_launcher.webp              "$ANDROID_RES/mipmap-xxhdpi/"
cp android/res/mipmap-xxxhdpi/ic_launcher.webp             "$ANDROID_RES/mipmap-xxxhdpi/"

# Rebuild the release APK with the updated icons.
(
    cd target/dx/letmein-gui/release/android/app
    ./gradlew packageRelease
    ./gradlew bundleRelease
)

cp ./target/dx/letmein-gui/release/android/app/app/build/outputs/apk/release/app-release-unsigned.apk \
   ./letmein-aarch64-unsigned.apk
cp ./target/dx/letmein-gui/release/android/app/app/build/outputs/bundle/release/app-release.aab \
   ./letmein-aarch64.aab
