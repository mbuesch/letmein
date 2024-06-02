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

do_systemctl()
{
    info "systemctl $*"
    systemctl "$@" || die "Failed to systemctl $*"
}

try_systemctl()
{
    info "systemctl $*"
    systemctl "$@" 2>/dev/null
}

entry_checks()
{
    [ -d "$target" ] || die "letmein is not built! Run ./build.sh"
    [ "$(id -u)" = "0" ] || die "Must be root to install letmein."
}

stop_services()
{
    try_systemctl stop letmeind
}

start_services()
{
    do_systemctl start letmeind.socket
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

install_letmeind()
{
    do_install \
        -o root -g root -m 0755 \
        "$target/letmeind" \
        /opt/letmein/bin/

    do_install \
        -o root -g root -m 0644 \
        "$basedir/letmeind/letmeind.service" \
        /etc/systemd/system/

    do_install \
        -o root -g root -m 0644 \
        "$basedir/letmeind/letmeind.socket" \
        /etc/systemd/system/

    if ! [ -e /opt/letmein/etc/letmeind.conf ]; then
        do_install \
            -o root -g root -m 0640 \
            "$basedir/letmeind/letmeind.conf" \
            /opt/letmein/etc/letmeind.conf
    fi

    do_systemctl enable letmeind.service
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
stop_services
install_dirs
install_letmeind
start_services

# vim: ts=4 sw=4 expandtab
