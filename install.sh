#!/bin/sh
# -*- coding: utf-8 -*-

basedir="$(dirname "$(realpath "$0")")"

"$basedir/install-server.sh" || exit 1
"$basedir/install-client.sh" || exit 1

# vim: ts=4 sw=4 expandtab
