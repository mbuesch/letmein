#!/bin/sh
# -*- coding: utf-8 -*-

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
    [ "$(id -u)" = "0" ] || die "Must be root to create users."
}

sys_groupadd()
{
    local args="--system"
    info "groupadd $args $*"
    groupadd $args "$@" || die "Failed groupadd"
}

sys_useradd()
{
    local args="--system -s /usr/sbin/nologin -d /nonexistent -M -N"
    info "useradd $args $*"
    useradd $args "$@" || die "Failed useradd"
}

do_usermod()
{
    info "usermod $*"
    usermod "$@" || die "Failed usermod"
}

stop_daemons()
{
    systemctl stop letmeind.socket >/dev/null 2>&1
    systemctl stop letmeind.service >/dev/null 2>&1
    systemctl stop letmeinfwd.socket >/dev/null 2>&1
    systemctl stop letmeinfwd.service >/dev/null 2>&1
}

remove_users()
{
    # Delete all existing users and groups, if any.
    userdel letmeind >/dev/null 2>&1
    groupdel letmeind >/dev/null 2>&1
}

add_users()
{
    sys_groupadd letmeind
    sys_useradd -g letmeind letmeind
}

entry_checks
stop_daemons
remove_users
add_users

# vim: ts=4 sw=4 expandtab
