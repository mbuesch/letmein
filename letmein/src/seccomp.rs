// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow as ah;
use letmein_conf::Seccomp;

#[cfg(any(target_os = "linux", target_os = "android"))]
use letmein_seccomp::{Action, Allow, Filter, seccomp_supported};

#[cfg(any(target_os = "linux", target_os = "android"))]
const ALLOW_LIST: [Allow; 16] = [
    Allow::Mmap,
    Allow::Mprotect,
    Allow::Open,
    Allow::Read,
    Allow::Write,
    Allow::Ioctl {
        ops: Some(&[libc::FIONREAD as _]),
    },
    Allow::Fcntl {
        ops: Some(&[libc::F_GETFD as _]),
    },
    Allow::Stat,
    Allow::Recv,
    Allow::Send,
    Allow::Listen,
    Allow::Socket {
        afs: Some(&[
            libc::AF_INET as _,
            libc::AF_INET6 as _,
            libc::AF_UNIX as _,
            libc::AF_NETLINK as _,
        ]),
    },
    Allow::TcpConnect,
    Allow::SetSockOpt {
        level_optname: None,
    },
    Allow::Futex,
    Allow::Uname,
];

#[cfg(any(target_os = "linux", target_os = "android"))]
fn do_install_seccomp_rules(seccomp: Seccomp) -> ah::Result<()> {
    use anyhow::Context as _;

    if seccomp == Seccomp::Off {
        // Normal for many client setups - log for audit but do not surface to the user.
        eprintln!(
            "letmein: [INFO] SECCOMP_DISABLED -- \
            Seccomp syscall filter is disabled by configuration"
        );
        return Ok(());
    }

    let action = match seccomp {
        Seccomp::Log => Action::Log,
        Seccomp::Kill => Action::Kill,
        Seccomp::Off => unreachable!(),
    };

    // Install seccomp filter.
    if seccomp_supported() {
        Filter::compile(&ALLOW_LIST, action)
            .context("Compile seccomp filter")?
            .install()
            .context("Install seccomp filter")?;
        // Log for audit; no need to surface to an interactive CLI user on every invocation.
        eprintln!(
            "letmein: [INFO] SECCOMP_ACTIVE mode={seccomp} -- \
            Seccomp syscall filter installed successfully"
        );
    } else {
        // Seccomp was requested but the architecture does not support it.
        // Log for audit AND tell the user - their expected hardening is not in effect.
        eprintln!(
            "letmein: [WARN] SECCOMP_UNAVAILABLE -- \
            WARNING: Seccomp was requested but is not supported on this architecture. \
            Syscall filter not active."
        );
    }

    Ok(())
}

/// Install the `seccomp` rules, if requested.
#[allow(unused_variables)]
pub fn install_seccomp_rules(seccomp: Seccomp) -> ah::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    do_install_seccomp_rules(seccomp)?;

    Ok(())
}

// vim: ts=4 sw=4 expandtab
