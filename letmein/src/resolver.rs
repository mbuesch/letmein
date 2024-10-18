// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, format_err as err};
use hickory_proto::rr::{record_data::RData, record_type::RecordType};
use hickory_resolver::{config::ResolverConfig, TokioAsyncResolver};
use std::net::IpAddr;

/// Host name resolution target mode.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum ResMode {
    #[default]
    Ipv6,
    Ipv4,
}

/// Check if a string can be parsed into an IPv4 address.
pub fn is_ipv4_addr(host: &str) -> bool {
    host.parse::<IpAddr>().map(|a| a.is_ipv4()).unwrap_or(false)
}

/// Check if a string can be parsed into an IPv6 address.
pub fn is_ipv6_addr(host: &str) -> bool {
    host.parse::<IpAddr>().map(|a| a.is_ipv6()).unwrap_or(false)
}

/// Resolve a host name into an address.
pub async fn resolve(host: &str, mode: ResMode) -> ah::Result<IpAddr> {
    // Try to parse host as an IP address.
    if let Ok(addr) = host.parse::<IpAddr>() {
        match mode {
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

    // Create a DNS resolver.
    let resolver;
    if let Ok(r) = TokioAsyncResolver::tokio_from_system_conf() {
        resolver = r;
    } else {
        eprintln!(
            "Warning: Could not create DNS resolver from system configuration. \
             Is /etc/resolv.conf present? Falling back to Google DNS."
        );
        resolver = TokioAsyncResolver::tokio(ResolverConfig::google(), Default::default());
    }

    // Determine the DNS record type from the address resolution mode.
    let (record_type, record_type_str) = match mode {
        ResMode::Ipv6 => (RecordType::AAAA, "AAAA"),
        ResMode::Ipv4 => (RecordType::A, "A"),
    };

    // Do a DNS lookup of the host.
    let Ok(lookup) = resolver.lookup(host, record_type).await else {
        return Err(err!(
            "DNS lookup of host '{host}' failed. No '{record_type_str}' record found."
        ));
    };

    // Return the first address that matches the requested address resolution mode.
    for addr in lookup {
        match (mode, addr) {
            (ResMode::Ipv6, RData::AAAA(addr)) => return Ok(addr.0.into()),
            (ResMode::Ipv4, RData::A(addr)) => return Ok(addr.0.into()),
            _ => (),
        }
    }
    Err(err!(
        "No IP address found for host '{host}'. No '{record_type_str}' record found."
    ))
}

// vim: ts=4 sw=4 expandtab
