#!/bin/sh

srcdir="$(realpath "$0" | xargs dirname)"
srcdir="$srcdir/.."

# Import the makerelease.lib
# https://bues.ch/cgit/misc.git/tree/makerelease.lib
die() { echo "$*"; exit 1; }
for path in $(echo "$PATH" | tr ':' ' '); do
	[ -f "$MAKERELEASE_LIB" ] && break
	MAKERELEASE_LIB="$path/makerelease.lib"
done
[ -f "$MAKERELEASE_LIB" ] && . "$MAKERELEASE_LIB" || die "makerelease.lib not found."

hook_post_checkout()
{
	local checkout_dir="$1"
	cp "$checkout_dir/README.md" "$checkout_dir/letmein/README.md"
	cp "$checkout_dir/README.md" "$checkout_dir/letmeind/README.md"
}

project=letmeind
conf_package=letmeind
makerelease "$@"
