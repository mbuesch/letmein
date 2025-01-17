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

entry_checks()
{
    [ "$(id -u)" = "0" ] || die "Must be root to restart letmein."
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

entry_checks
stop_services
start_services

# vim: ts=4 sw=4 expandtab
