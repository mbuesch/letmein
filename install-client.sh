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

do_install()
{
    info "install $*"
    install "$@" || die "Failed install $*"
}

do_chown()
{
    info "chown $*"
    chown "$@" || die "Failed to chown $*"
}

do_chmod()
{
    info "chmod $*"
    chmod "$@" || die "Failed to chmod $*"
}

entry_checks()
{
    [ -d "$target" ] || die "letmein is not built! Run ./build.sh"
    [ "$(id -u)" = "0" ] || die "Must be root to install letmein."
}

install_dirs()
{
    do_install \
        -o root -g root -m 0755 \
        -d /opt/letmein/bin

    do_install \
        -o root -g root -m 0755 \
        -d /opt/letmein/etc
}

install_conf()
{
    if [ -e /opt/letmein/etc/letmein.conf ]; then
        do_chown root:root /opt/letmein/etc/letmein.conf
        do_chmod 0644 /opt/letmein/etc/letmein.conf
    else
        do_install \
            -o root -g root -m 0644 \
            "$basedir/letmein/letmein.conf" \
            /opt/letmein/etc/letmein.conf
    fi
}

install_letmein()
{
    do_install \
        -o root -g root -m 0755 \
        "$target/letmein" \
        /opt/letmein/bin/
}

release="release"
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
target="$basedir/target/$release"

entry_checks
install_dirs
install_conf
install_letmein

# vim: ts=4 sw=4 expandtab
