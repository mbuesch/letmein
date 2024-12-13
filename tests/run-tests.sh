#!/bin/sh
# -*- coding: utf-8 -*-

basedir="$(realpath "$0" | xargs dirname)"
basedir="$basedir/.."

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

entry_checks()
{
    [ -d "$target" ] || die "letmein is not built! Run ./build.sh"
}

build_stubs()
{
    info "Building stubs..."
    mkdir -p "$tmpbin" \
        || die "Failed to create tmpbin directory"
    rustc --edition 2021 -o "$tmpbin/nft" "$stubdir/nft.rs" \
        || die "Failed to build nft stub"
}

run_cargo_tests()
{
    info "Running Cargo tests..."
    cd "$basedir" || die "cd failed"
    cargo clippy -- --deny warnings || die "cargo clippy failed"
    cargo clippy --tests -- --deny warnings || die "cargo clippy --tests failed"
    cargo test || die "cargo test failed"
}

run_tcp_tests()
{
    info "### Running test: TCP ###"

    rm -rf "$rundir"
    mkdir -p "$rundir/letmeinfwd" || die "mkdir run"

    local conf="$testdir/conf/tcp.conf"

    info "Starting letmeinfwd..."
    "$target/letmeinfwd" \
        --test-mode \
        --no-systemd \
        --rundir "$rundir" \
        --config "$conf" &
    pid_letmeinfwd=$!

    info "Starting letmeind..."
    "$target/letmeind" \
        --no-systemd \
        --rundir "$rundir" \
        --config "$conf" &
    pid_letmeind=$!

    sleep 1
    check_pidfiles

    info "Knocking..."
    "$target/letmein" \
        --config "$conf" \
        knock \
        --user 12345678 \
        localhost 42 \
        || die "letmein knock failed"

    kill_all_and_wait
}

check_pidfile()
{
    local name="$1"
    local pid="$2"

    if [ -r "$rundir/$name/$name.pid" ]; then
        if [ "$pid" != "$(cat "$rundir/$name/$name.pid")" ]; then
            die "$name: Invalid PID-file."
        fi
    else
        die "$name PID-file is missing. Did $name fail to start?"
    fi
}

check_pidfiles()
{
    check_pidfile letmeinfwd "$pid_letmeinfwd"
    check_pidfile letmeind "$pid_letmeind"
}

kill_all()
{
    kill_letmeind
    kill_letmeinfwd
}

kill_all_and_wait()
{
    kill_all
    wait
}

kill_letmeinfwd()
{
    if [ -n "$pid_letmeinfwd" ]; then
        kill -TERM "$pid_letmeinfwd" >/dev/null 2>&1
        pid_letmeinfwd=
    fi
}

kill_letmeind()
{
    if [ -n "$pid_letmeind" ]; then
        kill -TERM "$pid_letmeind" >/dev/null 2>&1
        pid_letmeind=
    fi
}

cleanup()
{
    kill_all
    if [ -n "$tmpdir" ]; then
        rm -rf "$tmpdir"
        tmpdir=
    fi
}

cleanup_and_exit()
{
    cleanup
    exit 1
}
 
pid_letmeinfwd=
pid_letmeind=

tmpdir="$(mktemp -d --tmpdir=/tmp letmein-test.XXXXXXXXXX)"
[ -d "$tmpdir" ] || die "Failed to create temporary directory"
tmpbin="$tmpdir/bin"
rundir="$tmpdir/run"

target="$basedir/target/debug"
testdir="$basedir/tests"
stubdir="$testdir/stubs"

export PATH="$tmpbin:$PATH"

trap cleanup_and_exit INT TERM
trap cleanup EXIT

entry_checks
info "Temporary directory is: $tmpdir"
build_stubs
run_cargo_tests
run_tcp_tests
info "All tests Ok."

# vim: ts=4 sw=4 expandtab
