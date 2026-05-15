// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, format_err as err};
use std::net::IpAddr;

#[cfg(feature = "hickory-resolver")]
mod hickory;
#[cfg(feature = "hickory-resolver")]
use hickory as backend;

#[cfg(all(feature = "libc-resolver", not(feature = "hickory-resolver")))]
mod dns_lookup;
#[cfg(all(feature = "libc-resolver", not(feature = "hickory-resolver")))]
use dns_lookup as backend;

#[cfg(not(any(feature = "hickory-resolver", feature = "libc-resolver")))]
compile_error!(
    "At least one resolver backend must be enabled. Enable the 'hickory-resolver' or 'libc-resolver' feature."
);

#[cfg(all(feature = "hickory-resolver", feature = "libc-resolver"))]
#[deprecated(
    note = "Feature 'hickory-resolver' and 'libc-resolver' enabled. Using 'hickory-resolver'."
)]
const WARNING_HICKORY_AND_LIBC_RESOLVER_ENABLED: () = ();
#[cfg(all(feature = "hickory-resolver", feature = "libc-resolver"))]
const _: () = WARNING_HICKORY_AND_LIBC_RESOLVER_ENABLED;

/// Host name resolution target mode.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResMode {
    /// Resolve to IPv6.
    #[default]
    Ipv6,

    /// Resolve to IPv4.
    Ipv4,
}

/// Host name resolution service.
///
/// By `Default` only the system resolver is enabled, but you can enable more DNS services individually.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ResSrv {
    /// Use the resolver from system configuration.
    #[cfg_attr(not(feature = "hickory-resolver"), allow(dead_code))]
    system: bool,

    /// Use Quad9 DNS.
    #[cfg_attr(not(feature = "hickory-resolver"), allow(dead_code))]
    quad9: bool,

    /// Use Google DNS.
    #[cfg_attr(not(feature = "hickory-resolver"), allow(dead_code))]
    google: bool,

    /// Use Cloudflare DNS.
    #[cfg_attr(not(feature = "hickory-resolver"), allow(dead_code))]
    cloudflare: bool,
}

impl Default for ResSrv {
    fn default() -> Self {
        Self {
            system: true,
            quad9: false,
            google: false,
            cloudflare: false,
        }
    }
}

impl ResSrv {
    #[must_use]
    pub fn system(self, enable: bool) -> Self {
        Self {
            system: enable,
            ..self
        }
    }

    #[must_use]
    pub fn quad9(self, enable: bool) -> Self {
        Self {
            quad9: enable,
            ..self
        }
    }

    #[must_use]
    pub fn google(self, enable: bool) -> Self {
        Self {
            google: enable,
            ..self
        }
    }

    #[must_use]
    pub fn cloudflare(self, enable: bool) -> Self {
        Self {
            cloudflare: enable,
            ..self
        }
    }
}

/// Host name resolution encryption.
///
/// By `Default` all encryption modes and unencrypted DNS are enabled, but you can disable them individually.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ResCrypt {
    /// Try DNS over TLS.
    #[cfg_attr(not(feature = "hickory-resolver"), allow(dead_code))]
    tls: bool,

    /// Try DNS over HTTPS.
    #[cfg_attr(not(feature = "hickory-resolver"), allow(dead_code))]
    https: bool,

    /// Try unencrypted DNS.
    #[cfg_attr(not(feature = "hickory-resolver"), allow(dead_code))]
    unencrypted: bool,
}

impl Default for ResCrypt {
    fn default() -> Self {
        Self {
            tls: true,
            https: true,
            unencrypted: true,
        }
    }
}

impl ResCrypt {
    #[must_use]
    pub fn tls(self, enable: bool) -> Self {
        Self {
            tls: enable,
            ..self
        }
    }

    #[must_use]
    pub fn https(self, enable: bool) -> Self {
        Self {
            https: enable,
            ..self
        }
    }

    #[must_use]
    pub fn unencrypted(self, enable: bool) -> Self {
        Self {
            unencrypted: enable,
            ..self
        }
    }
}

/// Host name resolution configuration.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct ResConf {
    /// Resolution mode: IPv4 or IPv6?
    mode: ResMode,

    /// Resolution service.
    #[cfg_attr(not(feature = "hickory-resolver"), allow(dead_code))]
    srv: ResSrv,

    /// Resolution encryption.
    #[cfg_attr(not(feature = "hickory-resolver"), allow(dead_code))]
    crypt: ResCrypt,

    /// Suppress warnings.
    #[cfg_attr(not(feature = "hickory-resolver"), allow(dead_code))]
    suppress_warnings: bool,
}

impl ResConf {
    #[must_use]
    pub fn mode(self, mode: ResMode) -> Self {
        Self { mode, ..self }
    }

    #[must_use]
    pub fn srv(self, srv: ResSrv) -> Self {
        Self { srv, ..self }
    }

    #[must_use]
    pub fn crypt(self, crypt: ResCrypt) -> Self {
        Self { crypt, ..self }
    }

    #[must_use]
    pub fn suppress_warnings(self, suppress_warnings: bool) -> Self {
        Self {
            suppress_warnings,
            ..self
        }
    }
}

/// Check if a string can be parsed into an IPv4 address.
#[must_use]
pub fn is_ipv4_addr(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok_and(|a| a.is_ipv4())
}

/// Check if a string can be parsed into an IPv6 address.
#[must_use]
pub fn is_ipv6_addr(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok_and(|a| a.is_ipv6())
}

/// Resolve a host name into an address.
pub async fn resolve(host: &str, cfg: &ResConf) -> ah::Result<IpAddr> {
    // Try to parse host as an IP address.
    if let Ok(addr) = host.parse::<IpAddr>() {
        match cfg.mode {
            ResMode::Ipv4 if !addr.is_ipv4() => {
                return Err(err!(
                    "Supplied a raw IPv6 address, but resolution mode is set to IPv4"
                ));
            }
            ResMode::Ipv6 if !addr.is_ipv6() => {
                return Err(err!(
                    "Supplied a raw IPv4 address, but resolution mode is set to IPv6"
                ));
            }
            _ => (),
        }
        // It is an IP address. No need for DNS lookup.
        return Ok(addr);
    }

    backend::resolve(host, cfg).await
}

// vim: ts=4 sw=4 expandtab
