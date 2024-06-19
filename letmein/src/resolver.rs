// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, format_err as err, Context as _};
use hickory_proto::rr::{record_data::RData, record_type::RecordType};
use hickory_resolver::TokioAsyncResolver;
use std::net::IpAddr;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum ResMode {
    #[default]
    Ipv6,
    Ipv4,
}

pub async fn resolve(host: &str, mode: ResMode) -> ah::Result<IpAddr> {
    // Try to parse host as an IP address.
    if let Ok(addr) = host.parse::<IpAddr>() {
        if addr.is_ipv4() && mode != ResMode::Ipv4 {
            return Err(err!(
                "Supplied a raw IPv4 address, but resolution mode is set to IPv6"
            ));
        }
        if addr.is_ipv6() && mode != ResMode::Ipv6 {
            return Err(err!(
                "Supplied a raw IPv6 address, but resolution mode is set to IPv4"
            ));
        }
        return Ok(addr);
    }

    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .context("Create address resolver from system configuration")?;
    let (record_type, record_type_str) = match mode {
        ResMode::Ipv6 => (RecordType::AAAA, "AAAA"),
        ResMode::Ipv4 => (RecordType::A, "A"),
    };

    let Ok(lookup) = resolver.lookup(host, record_type).await else {
        return Err(err!(
            "DNS lookup of host '{host}' failed. No '{record_type_str}' record found."
        ));
    };

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
