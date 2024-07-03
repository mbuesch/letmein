// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub mod nftables;

use crate::ConfigRef;
use anyhow as ah;
use std::{collections::HashMap, net::IpAddr, time::Instant};

/// Dynamic port/address lease.
struct Lease {
    addr: IpAddr,
    port: u16,
    timeout: Instant,
}

impl Lease {
    /// Create a new lease with maximum timeout.
    pub fn new(conf: &ConfigRef<'_>, addr: IpAddr, port: u16) -> Self {
        let timeout = Instant::now() + conf.nft_timeout();
        Self {
            addr,
            port,
            timeout,
        }
    }

    /// Reset the timeout to maximum.
    pub fn refresh_timeout(&mut self, conf: &ConfigRef<'_>) {
        self.timeout = Instant::now() + conf.nft_timeout();
    }

    /// Check if this lease has timed out.
    pub fn is_timed_out(&self, now: Instant) -> bool {
        now >= self.timeout
    }

    /// Get the IP address of this lease.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// Get the port number of this lease.
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Key in the lease map.
type LeaseId = (IpAddr, u16);

/// A map of [Lease]s.
type LeaseMap = HashMap<LeaseId, Lease>;

/// Prune (remove) all leases that have timed out.
fn prune_all_lease_timeouts(conf: &ConfigRef<'_>, leases: &mut LeaseMap) {
    let now = Instant::now();
    leases.retain(|_, lease| {
        let timed_out = lease.is_timed_out(now);
        if timed_out && conf.debug() {
            println!(
                "firewall: Lease saddr={}, dport={} timed out",
                lease.addr(),
                lease.port()
            );
        }
        !timed_out
    });
}

/// Firewall maintenance operations.
pub trait FirewallMaintain {
    /// Delete all leases from the firewall.
    async fn clear(&mut self, conf: &ConfigRef<'_>) -> ah::Result<()>;

    /// Run periodic maintenance.
    /// This shall be called in regular intervals every couple of seconds.
    /// This operation shall remove all timed-out leases.
    async fn maintain(&mut self, conf: &ConfigRef<'_>) -> ah::Result<()>;

    /// Re-apply all rules to the underlying firewall.
    /// This operation shall remove all timed-out leases.
    async fn reload(&mut self, conf: &ConfigRef<'_>) -> ah::Result<()>;
}

/// Firewall knock-open operations.
pub trait FirewallOpen {
    /// Add a rule to open the specified `port` for the specified `remote_addr`.
    /// This operation shall handle the case where there already is such
    /// a rule present gracefully.
    async fn open_port(
        &mut self,
        conf: &ConfigRef<'_>,
        remote_addr: IpAddr,
        port: u16,
    ) -> ah::Result<()>;
}

// vim: ts=4 sw=4 expandtab
