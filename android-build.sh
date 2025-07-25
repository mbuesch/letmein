#!/bin/sh
# -*- coding: utf-8 -*-

basedir="$(realpath "$0" | xargs dirname)"

. "$basedir/scripts/lib.sh"

export CFLAGS=
export CPPFLAGS=
export CXXFLAGS=
if ! [ -d "$ANDROID_NDK_HOME" ]; then
    export ANDROID_NDK_HOME="$HOME/Android/Sdk/ndk"
fi

platform=28
package=letmein-android
appdir="$basedir/letmein-android-app"

cargo_ndk()
{
    local target="$1"
    local buildsubdir="$2"

    cargo ndk -t "$target" -p "$platform" build -p "$package" --release ||\
        die "cargo ndk $target"
    mkdir -p "$appdir/app/src/main/jniLibs/$target" ||\
        die "mkdir jniLibs/$target"
    cp "$basedir/target/$buildsubdir/release/libletmein_android.so" \
       "$appdir/app/src/main/jniLibs/$target/" ||\
        die "cp .so"
}

cargo_ndk arm64-v8a     aarch64-linux-android
cargo_ndk armeabi-v7a   armv7-linux-androideabi
cargo_ndk x86_64        x86_64-linux-android
cargo_ndk x86           i686-linux-android

# vim: ts=4 sw=4 expandtab
