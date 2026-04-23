// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, format_err as err};
use hickory_resolver::{
    TokioResolver,
    config::{CLOUDFLARE, GOOGLE, QUAD9, ResolverConfig},
    lookup::Lookup,
    net::runtime::TokioRuntimeProvider,
    proto::rr::{RData, RecordType},
};
use std::net::IpAddr;

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
    system: bool,

    /// Use Quad9 DNS.
    quad9: bool,

    /// Use Google DNS.
    google: bool,

    /// Use Cloudflare DNS.
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
    tls: bool,

    /// Try DNS over HTTPS.
    https: bool,

    /// Try unencrypted DNS.
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
    srv: ResSrv,

    /// Resolution encryption.
    crypt: ResCrypt,

    /// Suppress warnings.
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

/// Determine the DNS record type from the address resolution mode.
fn get_record_type(mode: ResMode) -> (RecordType, &'static str, &'static str) {
    match mode {
        ResMode::Ipv6 => (RecordType::AAAA, "AAAA", "IPv6"),
        ResMode::Ipv4 => (RecordType::A, "A", "IPv4"),
    }
}

/// Return the first address that matches the requested address resolution mode.
fn get_first_result(lookup: &Lookup, host: &str, mode: ResMode) -> ah::Result<IpAddr> {
    for answer in lookup.answers() {
        match (mode, &answer.data) {
            (ResMode::Ipv6, RData::AAAA(addr)) => return Ok(addr.0.into()),
            (ResMode::Ipv4, RData::A(addr)) => return Ok(addr.0.into()),
            _ => (),
        }
    }
    let (_, record_type_str, _) = get_record_type(mode);
    Err(err!(
        "No IP address found for host '{host}'. No '{record_type_str}' record found."
    ))
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

    let (record_type, record_type_str, addr_type_str) = get_record_type(cfg.mode);

    macro_rules! lookup_and_return {
        ($conf:expr) => {
            if let Ok(resolver) =
                TokioResolver::builder_with_config($conf, TokioRuntimeProvider::default()).build()
                && let Ok(lookup) = resolver.lookup(host, record_type).await
            {
                return get_first_result(&lookup, host, cfg.mode);
            }
        };
    }

    if cfg.srv.system {
        if let Ok(builder) = TokioResolver::builder_tokio()
            && let Ok(resolver) = builder.build()
            && let Ok(lookup) = resolver.lookup(host, record_type).await
        {
            return get_first_result(&lookup, host, cfg.mode);
        }

        #[cfg(not(target_os = "android"))]
        let print_warning = true;
        #[cfg(target_os = "android")]
        let print_warning = false;

        if print_warning && !cfg.suppress_warnings {
            #[cfg(target_os = "windows")]
            let os_info = "Is your DNS resolver configured correctly in network settings?";

            #[cfg(not(target_os = "windows"))]
            let os_info = "Is /etc/resolv.conf present and configured correctly?";

            eprintln!(
                "Warning: Could not resolve {addr_type_str} address with the system DNS resolver. \
                 {os_info} \
                 Falling back to other DNS servers."
            );
        }
    }

    if cfg.crypt.tls {
        if cfg.srv.quad9 {
            lookup_and_return!(ResolverConfig::tls(&QUAD9));
        }
        if cfg.srv.google {
            lookup_and_return!(ResolverConfig::tls(&GOOGLE));
        }
        if cfg.srv.cloudflare {
            lookup_and_return!(ResolverConfig::tls(&CLOUDFLARE));
        }
    }

    if cfg.crypt.https {
        if cfg.srv.quad9 {
            lookup_and_return!(ResolverConfig::https(&QUAD9));
        }
        if cfg.srv.google {
            lookup_and_return!(ResolverConfig::https(&GOOGLE));
        }
        if cfg.srv.cloudflare {
            lookup_and_return!(ResolverConfig::https(&CLOUDFLARE));
        }
    }

    if cfg.crypt.unencrypted {
        if cfg.srv.quad9 {
            lookup_and_return!(ResolverConfig::udp_and_tcp(&QUAD9));
        }
        if cfg.srv.google {
            lookup_and_return!(ResolverConfig::udp_and_tcp(&GOOGLE));
        }
        if cfg.srv.cloudflare {
            lookup_and_return!(ResolverConfig::udp_and_tcp(&CLOUDFLARE));
        }
    }

    Err(err!(
        "DNS lookup of host '{host}' failed. No '{record_type_str}' record found."
    ))
}

// vim: ts=4 sw=4 expandtab
