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

check_dynlibs()
{
    local bin="$1"
    ldd "$bin" | while read line || die "ldd failed"; do
        printf '%s' "$line" | awk '{ print $1; }' | grep -qe 'linux-vdso\.so' && continue
        printf '%s' "$line" | awk '{ print $1; }' | grep -qe 'libgcc_s\.so' && continue
        printf '%s' "$line" | awk '{ print $1; }' | grep -qe 'libm\.so' && continue
        printf '%s' "$line" | awk '{ print $1; }' | grep -qe 'libc\.so' && continue
        printf '%s' "$line" | awk '{ print $1; }' | grep -qe 'ld-linux-.*\.so' && continue
        printf '%s' "$line" | awk '{ print $1; }' | grep -qe 'ld-android\.so' && continue
        printf '%s' "$line" | awk '{ print $1; }' | grep -qe 'libarmmem-.*\.so' && continue
        printf '%s' "$line" | awk '{ print $1; }' | grep -qe 'libdl\.so' && continue
        die "Found unknown dynamically linked library '$line' in '$bin'"
    done
}

[ -f "$basedir/Cargo.toml" ] || die "basedir sanity check failed"

cd "$basedir" || die "cd basedir failed."
cargo build || die "Cargo build (debug) failed."
cargo test || die "Cargo test failed."
cargo auditable build --release || die "Cargo build (release) failed."
cargo audit bin --deny warnings \
    target/release/letmein \
    target/release/letmeind \
    || die "Cargo audit failed."
check_dynlibs target/release/letmein
check_dynlibs target/release/letmeind

# vim: ts=4 sw=4 expandtab
