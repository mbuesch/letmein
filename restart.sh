#!/bin/sh
# -*- coding: utf-8 -*-

basedir="$(realpath "$0" | xargs dirname)"

. "$basedir/scripts/lib.sh"

entry_checks()
{
    [ "$(id -u)" = "0" ] || die "Must be root to restart letmein."
}

entry_checks
stop_services
try_systemctl restart nftables.service
start_services

# vim: ts=4 sw=4 expandtab
