#!/bin/sh
# -*- coding: utf-8 -*-

basedir="$(realpath "$0" | xargs dirname)"

. "$basedir/scripts/lib.sh"

export CFLAGS=
export CPPFLAGS=
export CXXFLAGS=
export ANDROID_NDK_HOME="$HOME/Android/Sdk/ndk"

cargo_ndk()
{
    local target="$1"
    local platform="$2"
    local package="$3"

    cargo ndk -t "$target" -p "$platform" build -p "$package" --release ||\
        die "cargo ndk $target"

}

platform=28
package=letmein-android
cargo_ndk arm64-v8a "$platform" "$package"
cargo_ndk armeabi-v7a "$platform" "$package"
cargo_ndk x86_64 "$platform" "$package"
cargo_ndk x86 "$platform" "$package"

# vim: ts=4 sw=4 expandtab
