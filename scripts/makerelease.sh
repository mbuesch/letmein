#!/bin/sh
# -*- coding: utf-8 -*-

srcdir="$(realpath "$0" | xargs dirname)"
srcdir="$srcdir/.."

# Import the makerelease.lib
# https://bues.ch/cgit/misc.git/tree/makerelease.lib
die() { echo "$*"; exit 1; }
for path in $(echo "$PATH" | tr ':' ' '); do
    [ -f "$MAKERELEASE_LIB" ] && break
    MAKERELEASE_LIB="$path/makerelease.lib"
done
[ -f "$MAKERELEASE_LIB" ] && . "$MAKERELEASE_LIB" || die "makerelease.lib not found."

hook_get_version()
{
    version="$(cargo_local_pkg_version letmein)"
}

hook_regression_tests()
{
    default_hook_regression_tests "$@"

    sh "$1"/tests/run-tests.sh
}

project=letmein
conf_upload_packages="letmein-proto letmein-conf letmein-fwproto letmein-systemd letmein-seccomp letmein letmeinfwd letmeind"
makerelease "$@"

# vim: ts=4 sw=4 expandtab
