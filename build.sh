#!/bin/sh
# -*- coding: utf-8 -*-

basedir="$(realpath "$0" | xargs dirname)"

[ -f "$basedir/Cargo.toml" ] || die "basedir sanity check failed"
. "$basedir/scripts/lib.sh"

release="both"
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

check_dynlibs()
{
    local bin
    local ldd_out

    bin="$1"

    ldd_out="$(ldd "$bin")"
    [ -z "$ldd_out" ] && die "ldd failed"

    printf '%s' "$ldd_out" | while read -r line; do
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

cd "$basedir" || die "cd basedir failed."
export LETMEIN_CONF_PREFIX="/opt/letmein"

packages_args="-p letmein -p letmeind -p letmeinfwd"
packages_release_paths="target/release/letmein target/release/letmeind target/release/letmeinfwd"

# Debug build and test
if [ "$release" = "debug" -o "$release" = "both" ]; then
    cargo build $packages_args || die "Cargo build (debug) failed."
    cargo test $packages_args || die "Cargo test failed."
fi

# Release build
if [ "$release" = "release" -o "$release" = "both" ]; then
    if which cargo-auditable >/dev/null 2>&1; then
        cargo auditable build --release $packages_args \
            || die "Cargo build (release) failed."
        cargo audit --deny warnings bin $packages_release_paths \
            || die "Cargo audit failed."
    else
        cargo build --release $packages_args \
            || die "Cargo build (release) failed."
    fi
    for p in $packages_release_paths; do
        check_dynlibs "$p"
    done
fi

# vim: ts=4 sw=4 expandtab
