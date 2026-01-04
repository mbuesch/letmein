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
use letmein_seccomp::{seccomp_supported, Action, Allow, Filter};

#[cfg(any(target_os = "linux", target_os = "android"))]
const ALLOW_LIST: [Allow; 14] = [
    Allow::Mmap,
    Allow::Mprotect,
    Allow::Open,
    Allow::Read,
    Allow::Write,
    Allow::Fcntl {
        op: Some(libc::F_GETFD as _),
    },
    Allow::Stat,
    Allow::Recv,
    Allow::Send,
    Allow::Listen,
    Allow::TcpConnect,
    Allow::SetSockOpt {
        level_optname: Some((libc::IPPROTO_TCP as _, libc::TCP_NODELAY as _)),
    },
    Allow::Futex,
    Allow::Uname,
];

#[cfg(any(target_os = "linux", target_os = "android"))]
fn do_install_seccomp_rules(seccomp: Seccomp) -> ah::Result<()> {
    use anyhow::Context as _;

    if seccomp == Seccomp::Off {
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
    } else {
        eprintln!(
            "WARNING: Not using seccomp. \
            Letmein does not support seccomp on this architecture, yet."
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
