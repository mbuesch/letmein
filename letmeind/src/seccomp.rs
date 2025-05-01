// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, Context as _};
use letmein_conf::Seccomp;
use letmein_seccomp::{seccomp_supported, Action, Allow, Filter};

const ALLOW_LIST: [Allow; 13] = [
    Allow::Mmap,
    Allow::Mprotect,
    Allow::Read,
    Allow::Write,
    Allow::Fcntl {
        op: Some(libc::F_GETFD as _),
    },
    Allow::Recv,
    Allow::Send,
    Allow::Listen,
    Allow::TcpAccept,
    Allow::UnixConnect,
    Allow::SetSockOpt {
        level_optname: Some((libc::IPPROTO_TCP as _, libc::TCP_NODELAY as _)),
    },
    Allow::Signal,
    Allow::Futex,
];

/// Install the `seccomp` rules, if requested.
pub fn install_seccomp_rules(seccomp: Seccomp) -> ah::Result<()> {
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
        println!("Seccomp mode: {seccomp}");
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

// vim: ts=4 sw=4 expandtab
