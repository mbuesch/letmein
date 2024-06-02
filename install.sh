#!/bin/sh
# -*- coding: utf-8 -*-

basedir="$(realpath "$0" | xargs dirname)"

"$basedir/install-server.sh" || exit 1
"$basedir/install-client.sh" || exit 1

# vim: ts=4 sw=4 expandtab
