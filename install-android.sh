#!/bin/sh
set -e

basedir="$(realpath "$0" | xargs dirname)"
cd "$basedir"

#adb uninstall ch.bues.letmein 2>/dev/null || true
adb install ./letmein-aarch64.apk
