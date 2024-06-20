// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! This crate is an abstraction of the `systemd` interfaces needed by `letmein`.

use anyhow::{self as ah, format_err as err, Context as _};
use std::{net::TcpListener, os::fd::FromRawFd as _};

/// Create a new [TcpListener] with the socket provided by systemd.
///
/// All environment variables related to this operation will be cleared.
pub fn tcp_from_systemd() -> ah::Result<Option<TcpListener>> {
    if sd_notify::booted().unwrap_or(false) {
        let mut fds = sd_notify::listen_fds().context("Systemd listen_fds")?;
        if let Some(fd) = fds.next() {
            // SAFETY:
            // The fd from systemd is good and lives for the lifetime of the program.
            return Ok(Some(unsafe { TcpListener::from_raw_fd(fd) }));
        } else {
            return Err(err!(
                "Booted with systemd, but no listen_fds received from systemd."
            ));
        }
    }
    Ok(None)
}

/// Notify ready-status to systemd.
///
/// All environment variables related to this operation will be cleared.
pub fn systemd_notify_ready() -> ah::Result<()> {
    sd_notify::notify(true, &[sd_notify::NotifyState::Ready])?;
    Ok(())
}

// vim: ts=4 sw=4 expandtab
