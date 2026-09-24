// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # letmein-fail2ban
//!
//! This crate provides **ready-to-use fail2ban filter and jail configuration**
//! for the `letmeind` port-knocking daemon.
//!
//! The configuration files are embedded at compile time from the
//! `configs/` directory of this crate and exposed as typed constants.
//! An [`install`] function can write them to the correct locations on a
//! running system.
//!
//! ## Filter files
//!
//! | Constant | File | Jail |
//! |---|---|---|
//! | [`FILTER_ALL`] | `letmeind.conf` | Matches every security event (use for single-jail setups) |
//! | [`FILTER_AUTH`] | `letmeind-auth.conf` | `AUTH_FAILURE`, `UNKNOWN_USER`, `ACCESS_DENIED` |
//! | [`FILTER_ABUSE`] | `letmeind-abuse.conf` | `PROTOCOL_ABUSE` |
//! | [`FILTER_SCAN`] | `letmeind-scan.conf` | `PREAUTH_TIMEOUT`, `CONN_LIMIT_EXCEEDED` |
//! | [`FILTER_PROBE`] | `letmeind-probe.conf` | `UNKNOWN_RESOURCE` |
//!
//! ## Jail file
//!
//! | Constant | File |
//! |---|---|
//! | [`JAIL`] | `letmeind.conf` - four jails: auth, abuse, scan, probe |
//!
//! ## Quick install
//!
//! ```no_run
//! letmein_fail2ban::install(
//!     std::path::Path::new("/etc/fail2ban"),
//!     &letmein_fail2ban::InstallOpts::default(),
//! ).expect("failed to install fail2ban configuration");
//! ```

#![forbid(unsafe_code)]

mod install;

pub use crate::install::{InstallOpts, install};

// ---------------------------------------------------------------------------
// Typed descriptor of a single configuration file to install.
// ---------------------------------------------------------------------------

/// A single fail2ban configuration file to be installed.
#[derive(Debug, Clone, Copy)]
pub struct ConfigFile {
    /// Sub-directory under the fail2ban base directory (e.g. `"filter.d"`).
    pub subdir: &'static str,
    /// File name (e.g. `"letmeind-auth.conf"`).
    pub filename: &'static str,
    /// File content.
    pub content: &'static str,
}

/// All configuration files provided by this crate, in installation order.
pub const CONFIG_FILES: &[ConfigFile] = &[
    /*
    ConfigFile {
        subdir: "filter.d",
        filename: "letmeind.conf",
        content: FILTER_ALL,
    },
    ConfigFile {
        subdir: "filter.d",
        filename: "letmeind-auth.conf",
        content: FILTER_AUTH,
    },
    ConfigFile {
        subdir: "filter.d",
        filename: "letmeind-abuse.conf",
        content: FILTER_ABUSE,
    },
    ConfigFile {
        subdir: "filter.d",
        filename: "letmeind-scan.conf",
        content: FILTER_SCAN,
    },
    ConfigFile {
        subdir: "filter.d",
        filename: "letmeind-probe.conf",
        content: FILTER_PROBE,
    },
    ConfigFile {
        subdir: "jail.d",
        filename: "letmeind.conf",
        content: JAIL,
    },
    */
];

// vim: ts=4 sw=4 expandtab
