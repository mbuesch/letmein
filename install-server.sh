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

try_systemctl()
{
    info "systemctl $*"
    systemctl "$@" 2>/dev/null
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

    if ! grep -qe '^letmeind:' /etc/passwd; then
        die "The system user 'letmeind' does not exist in /etc/passwd. Please run ./create-user.sh"
    fi
    if ! grep -qe '^letmeind:' /etc/group; then
        die "The system group 'letmeind' does not exist in /etc/group. Please run ./create-user.sh"
    fi
}

stop_services()
{
    try_systemctl stop letmeind.socket
    try_systemctl stop letmeind.service
    try_systemctl stop letmeinfwd.socket
    try_systemctl stop letmeinfwd.service
    try_systemctl disable letmeind.service
    try_systemctl disable letmeind.socket
    try_systemctl disable letmeinfwd.service
    try_systemctl disable letmeinfwd.socket
}

start_services()
{
    do_systemctl start letmeinfwd.socket
    do_systemctl start letmeinfwd.service
    do_systemctl start letmeind.socket
    do_systemctl start letmeind.service
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
    if [ -e /opt/letmein/etc/letmeind.conf ]; then
        do_chown root:letmeind /opt/letmein/etc/letmeind.conf
        do_chmod 0640 /opt/letmein/etc/letmeind.conf
    else
        do_install \
            -o root -g letmeind -m 0640 \
            "$basedir/letmeind/letmeind.conf" \
            /opt/letmein/etc/letmeind.conf
    fi
}

install_letmeinfwd()
{
    do_install \
        -o root -g root -m 0755 \
        "$target/letmeinfwd" \
        /opt/letmein/bin/

    do_install \
        -o root -g root -m 0644 \
        "$basedir/letmeinfwd/letmeinfwd.service" \
        /etc/systemd/system/

    do_install \
        -o root -g root -m 0644 \
        "$basedir/letmeinfwd/letmeinfwd.socket" \
        /etc/systemd/system/

    do_systemctl enable letmeinfwd.socket
    do_systemctl enable letmeinfwd.service
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

    do_systemctl enable letmeind.socket
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
install_conf
install_letmeinfwd
install_letmeind
start_services

# vim: ts=4 sw=4 expandtab
