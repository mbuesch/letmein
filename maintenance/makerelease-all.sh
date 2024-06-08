#!/bin/sh

basedir="$(realpath "$0" | xargs dirname)"

set -e
"$basedir/makerelease-letmein-conf.sh" "$@"
"$basedir/makerelease-letmein-proto.sh" "$@"
"$basedir/makerelease-letmein-systemd.sh" "$@"
"$basedir/makerelease-letmein.sh" "$@"
"$basedir/makerelease-letmeind.sh" "$@"
