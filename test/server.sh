#!/bin/sh
# -*- coding: utf-8 -*-

basedir="$(realpath "$0" | xargs dirname)"

info()
{
    echo "--- $*"
}

error()
{
    echo "=== ERROR: $*" >&2
}

warning()
{
    echo "=== WARNING: $*" >&2
}

die()
{
    error "$*"
    exit 1
}

cleanup()
{
    [ -n "$pid_letmeind" ] && kill "$pid_letmeind" 2>/dev/null
    wait
}

cleanup_and_exit()
{
    cleanup
    exit 1
}

trap cleanup_and_exit INT TERM
trap cleanup EXIT

start_letmeind()
{
    echo "Starting letmeind..."
    local binary="$target/letmeind"
    [ -x "$binary" ] || die "letmeind binary $binary not found."
    "$binary" \
        --no-systemd \
        &
    pid_letmeind=$!
}

release="debug"
while [ $# -ge 1 ]; do
    case "$1" in
        --debug|-d)
            release="debug"
            ;;
        --release|-r)
            release="release"
            ;;
        *)
            die "Invalid option: $1"
            ;;
    esac
    shift
done

target="$basedir/../target/$release"
pid_letmeind=
start_letmeind
echo "Up and running."
wait

# vim: ts=4 sw=4 expandtab
