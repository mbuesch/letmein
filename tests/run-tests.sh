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

build_project()
{
    info "Building project..."
    cd "$basedir" || die "cd failed"
    ./build.sh || die "Build failed"
}

cargo_clippy()
{
    cargo clippy -- --deny warnings || die "cargo clippy failed"
    cargo clippy --tests -- --deny warnings || die "cargo clippy --tests failed"
}

run_tests()
{
    local test_type="$1"

    info "### Running test: $test_type ###"

    rm -rf "$rundir"
    local conf="$testdir/conf/$test_type.conf"

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

    wait_for_pidfile letmeinfwd "$pid_letmeinfwd"
    wait_for_pidfile letmeind "$pid_letmeind"

    info "Knocking IPv6 + IPv4..."
    "$target/letmein" \
        --verbose \
        --config "$conf" \
        knock \
        --user 12345678 \
        localhost 42 \
        || die "letmein knock failed"

    info "Knocking IPv4..."
    "$target/letmein" \
        --verbose \
        --config "$conf" \
        knock \
        --user 12345678 \
        --ipv4 \
        localhost 42 \
        || die "letmein knock failed"

    info "Knocking IPv6..."
    "$target/letmein" \
        --verbose \
        --config "$conf" \
        knock \
        --user 12345678 \
        --ipv6 \
        localhost 42 \
        || die "letmein knock failed"

    kill_all_and_wait
}

wait_for_pidfile()
{
    local name="$1"
    local pid="$2"

    for i in $(seq 0 29); do
        if [ -r "$rundir/$name/$name.pid" ]; then
            if [ "$pid" != "$(cat "$rundir/$name/$name.pid")" ]; then
                die "$name: Invalid PID-file."
            fi
            return
        fi
        sleep 0.1
    done
    die "$name PID-file is missing. Did $name fail to start?"
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

[ -n "$TMPDIR" ] || export TMPDIR=/tmp
tmpdir="$(mktemp --tmpdir="$TMPDIR" -d letmein-test.XXXXXXXXXX)"
[ -d "$tmpdir" ] || die "Failed to create temporary directory"
rundir="$tmpdir/run"

target="$basedir/target/debug"
testdir="$basedir/tests"
stubdir="$testdir/stubs"

export PATH="$target:$PATH"

trap cleanup_and_exit INT TERM
trap cleanup EXIT

info "Temporary directory is: $tmpdir"
build_project
cargo_clippy
run_tests tcp
run_tests udp
info "All tests Ok."

# vim: ts=4 sw=4 expandtab
