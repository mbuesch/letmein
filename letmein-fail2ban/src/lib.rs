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
// Embedded filter configuration files.
// ---------------------------------------------------------------------------

/// Combined filter matching all letmeind security events.
///
/// Suitable for single-jail setups.  For finer-grained control with different
/// `maxretry`/`bantime` per event class use the per-category filters below.
pub const FILTER_ALL: &str = include_str!("../configs/filter.d/letmeind.conf");

/// Filter for authentication failures, unknown users, and access-denied events.
///
/// Intended for the `letmeind-auth` jail.
pub const FILTER_AUTH: &str = include_str!("../configs/filter.d/letmeind-auth.conf");

/// Filter for protocol-abuse events.
///
/// Intended for the `letmeind-abuse` jail.
/// A single occurrence is enough to justify an immediate, long-duration ban.
pub const FILTER_ABUSE: &str = include_str!("../configs/filter.d/letmeind-abuse.conf");

/// Filter for scanner and connection-flood events.
///
/// Intended for the `letmeind-scan` jail.
pub const FILTER_SCAN: &str = include_str!("../configs/filter.d/letmeind-scan.conf");

/// Filter for unknown-resource probe events.
///
/// Intended for the `letmeind-probe` jail.
pub const FILTER_PROBE: &str = include_str!("../configs/filter.d/letmeind-probe.conf");

// ---------------------------------------------------------------------------
// Embedded jail configuration file.
// ---------------------------------------------------------------------------

/// Jail configuration with four jails: auth, abuse, scan, and probe.
///
/// Each jail references the corresponding per-category filter above.
pub const JAIL: &str = include_str!("../configs/jail.d/letmeind.conf");

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
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_files_non_empty() {
        assert!(!FILTER_ALL.is_empty());
        assert!(!FILTER_AUTH.is_empty());
        assert!(!FILTER_ABUSE.is_empty());
        assert!(!FILTER_SCAN.is_empty());
        assert!(!FILTER_PROBE.is_empty());
        assert!(!JAIL.is_empty());
    }

    #[test]
    fn test_config_files_complete() {
        assert_eq!(CONFIG_FILES.len(), 6);
        for f in CONFIG_FILES {
            assert!(!f.subdir.is_empty());
            assert!(!f.filename.is_empty());
            assert!(!f.content.is_empty());
        }
    }

    #[test]
    fn test_filter_all_contains_all_events() {
        // Every banneable event keyword from the logging spec must appear in the combined filter.
        let events = [
            "AUTH_FAILURE",
            "PROTOCOL_ABUSE",
            "PREAUTH_TIMEOUT",
            "POSTAUTH_TIMEOUT",
            "CONN_LIMIT_EXCEEDED",
            "UDP_MALFORMED_PACKET",
            "UDP_QUEUE_OVERFLOW",
            "UNKNOWN_USER",
            "ACCESS_DENIED",
            "UNKNOWN_RESOURCE",
        ];
        for event in events {
            assert!(
                FILTER_ALL.contains(event),
                "FILTER_ALL is missing event keyword: {event}",
            );
        }
    }

    #[test]
    fn test_jail_references_all_filters() {
        // Each per-category filter name must be referenced in the jail file.
        let filters = [
            "letmeind-auth",
            "letmeind-abuse",
            "letmeind-scan",
            "letmeind-probe",
        ];
        for filter in filters {
            assert!(
                JAIL.contains(filter),
                "JAIL config does not reference filter: {filter}",
            );
        }
    }

    #[test]
    fn test_filter_auth_events() {
        // letmeind-auth must cover exactly its documented events and no others from
        // the other jails (to avoid double-banning at wrong thresholds).
        assert!(FILTER_AUTH.contains("AUTH_FAILURE"));
        assert!(FILTER_AUTH.contains("UNKNOWN_USER"));
        assert!(FILTER_AUTH.contains("ACCESS_DENIED"));
        // Must NOT contain events belonging to other jails.
        assert!(!FILTER_AUTH.contains("PROTOCOL_ABUSE"));
        assert!(!FILTER_AUTH.contains("PREAUTH_TIMEOUT"));
        assert!(!FILTER_AUTH.contains("UNKNOWN_RESOURCE"));
    }

    #[test]
    fn test_filter_abuse_events() {
        // letmeind-abuse covers both PROTOCOL_ABUSE severity levels.
        assert!(FILTER_ABUSE.contains("PROTOCOL_ABUSE"));
        // Both [ERROR] and [WARN] variants must be present.
        assert!(FILTER_ABUSE.contains("[ERROR]"));
        assert!(FILTER_ABUSE.contains("[WARN]"));
        // Must NOT bleed into auth events.
        assert!(!FILTER_ABUSE.contains("AUTH_FAILURE"));
    }

    #[test]
    fn test_filter_scan_events() {
        assert!(FILTER_SCAN.contains("PREAUTH_TIMEOUT"));
        assert!(FILTER_SCAN.contains("POSTAUTH_TIMEOUT"));
        assert!(FILTER_SCAN.contains("CONN_LIMIT_EXCEEDED"));
        assert!(FILTER_SCAN.contains("UDP_MALFORMED_PACKET"));
        assert!(FILTER_SCAN.contains("UDP_QUEUE_OVERFLOW"));
        // Must NOT contain auth events.
        assert!(!FILTER_SCAN.contains("AUTH_FAILURE"));
        assert!(!FILTER_SCAN.contains("PROTOCOL_ABUSE"));
    }

    #[test]
    fn test_filter_probe_events() {
        assert!(FILTER_PROBE.contains("UNKNOWN_RESOURCE"));
        // Probe is the least aggressive jail - must not contain high-severity events.
        assert!(!FILTER_PROBE.contains("AUTH_FAILURE"));
        assert!(!FILTER_PROBE.contains("PROTOCOL_ABUSE"));
        assert!(!FILTER_PROBE.contains("PREAUTH_TIMEOUT"));
    }

    #[test]
    fn test_filter_regex_format() {
        // Every failregex line must contain <HOST> (fail2ban's IP placeholder)
        // and end with .*$ so partial-line matches don't silently drop events.
        for (name, content) in [
            ("FILTER_ALL", FILTER_ALL),
            ("FILTER_AUTH", FILTER_AUTH),
            ("FILTER_ABUSE", FILTER_ABUSE),
            ("FILTER_SCAN", FILTER_SCAN),
            ("FILTER_PROBE", FILTER_PROBE),
        ] {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("failregex") {
                    assert!(
                        trimmed.contains("<HOST>"),
                        "{name}: failregex line missing <HOST>: {trimmed}"
                    );
                    assert!(
                        trimmed.ends_with(".*$"),
                        "{name}: failregex line does not end with .*$: {trimmed}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_jail_has_required_fields() {
        // Every jail block must specify enabled, filter, maxretry, findtime, bantime.
        for field in ["enabled", "filter", "maxretry", "findtime", "bantime"] {
            assert!(
                JAIL.contains(field),
                "JAIL config is missing required field: {field}"
            );
        }
    }
}

// vim: ts=4 sw=4 expandtab
