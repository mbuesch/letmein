# shellcheck shell=sh

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
