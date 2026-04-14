// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::Mutex,
};

/// Rate limiter for incoming connections based on client IP addresses.
pub struct IpLimiter {
    map: Mutex<HashMap<IpAddr, usize>>,
    max_ip_connections: usize,
}

impl IpLimiter {
    /// Create a new `IpLimiter` with the specified maximum number of connections per IP address.
    #[must_use]
    pub fn new(max_ip_connections: usize) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            max_ip_connections,
        }
    }

    /// Normalize an IP address to a rate-limiting key.
    ///
    /// IPv4 addresses are used as-is.
    /// IPv6 addresses are masked to a /56 prefix to prevent evasion by rotating the interface identifier.
    fn rate_limit_key(addr: IpAddr) -> IpAddr {
        match addr {
            IpAddr::V4(_) => addr,
            IpAddr::V6(v6) => {
                IpAddr::V6(v6 & Ipv6Addr::new(0xFFFF, 0xFFFF, 0xFFFF, 0xFF00, 0, 0, 0, 0))
            }
        }
    }

    /// Increment the connection count for the given IP address.
    ///
    /// Returns `true` if the connection should be accepted,
    /// or `false` if it should be rejected.
    #[must_use]
    pub fn request_permit_ok(&self, addr: IpAddr) -> bool {
        let key = Self::rate_limit_key(addr);
        let mut map = self.map.lock().expect("Mutex poisoned");
        let count = map.entry(key).or_insert(0);
        if *count >= self.max_ip_connections {
            false
        } else {
            *count = count.saturating_add(1);
            true
        }
    }

    /// Decrement the connection count for the given IP address.
    pub fn return_permit(&self, addr: IpAddr) {
        let key = Self::rate_limit_key(addr);
        let mut map = self.map.lock().expect("Mutex poisoned");
        if let Some(count) = map.get_mut(&key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&key);
            }
        }
    }
}
