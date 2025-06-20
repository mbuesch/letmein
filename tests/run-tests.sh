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

run_tests_genkey()
{
    info "### Running test: gen-key ###"

    local conf="$testdir/conf/udp.conf"

    local res="$("$target/letmein" --config "$conf"  gen-key  --user 12345678)"

    local user="$(echo "$res" | cut -d'=' -f1 | cut -d' ' -f1)"
    local key="$(echo "$res" | cut -d'=' -f2 | cut -d' ' -f2)"

    [ "$user" = "12345678" ] || die "Got invalid user"
}

run_tests_knock()
{
    local test_type="$1"

    info "### Running test: knock $test_type ###"

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

run_tests_close()
{
    local test_type="$1"

    info "### Running test: close $test_type ###"

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

    # First knock to open the port
    info "First knocking to open the port (IPv4)..."
    "$target/letmein" \
        --verbose \
        --config "$conf" \
        knock \
        --user 12345678 \
        --ipv4 \
        localhost 42 \
        || die "letmein knock failed"

    # Then close the port we just opened
    info "Now closing the port (IPv4)..."
    "$target/letmein" \
        --verbose \
        --config "$conf" \
        close \
        --user 12345678 \
        --ipv4 \
        localhost 42 \
        || die "letmein close failed"

    # Test close for both IPv4 and IPv6
    info "Testing close for IPv6 + IPv4..."
    # First open the port
    "$target/letmein" \
        --verbose \
        --config "$conf" \
        knock \
        --user 12345678 \
        localhost 42 \
        || die "letmein knock failed"
    # Then close it
    "$target/letmein" \
        --verbose \
        --config "$conf" \
        close \
        --user 12345678 \
        localhost 42 \
        || die "letmein close failed"
    
    # Test close for IPv6
    info "Testing close for IPv6..."
    # First open the port
    "$target/letmein" \
        --verbose \
        --config "$conf" \
        knock \
        --user 12345678 \
        --ipv6 \
        localhost 42 \
        || die "letmein knock failed"
    # Then close it
    "$target/letmein" \
        --verbose \
        --config "$conf" \
        close \
        --user 12345678 \
        --ipv6 \
        localhost 42 \
        || die "letmein close failed"
    
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
run_tests_genkey
run_tests_knock tcp
run_tests_knock udp
run_tests_close tcp
run_tests_close udp
info "All tests Ok."

# vim: ts=4 sw=4 expandtab
