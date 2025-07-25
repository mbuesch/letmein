// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub mod nftables;

use anyhow as ah;
use letmein_conf::Config;
use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

/// TCP and/or UDP port number.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeasePort {
    /// TCP port.
    Tcp(u16),
    /// UDP port.
    Udp(u16),
    /// TCP + UDP port.
    TcpUdp(u16),
}

impl std::fmt::Display for LeasePort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::Tcp(p) => write!(f, "{p}/TCP"),
            Self::Udp(p) => write!(f, "{p}/UDP"),
            Self::TcpUdp(p) => write!(f, "{p}/TCP+UDP"),
        }
    }
}

/// TCP or UDP port number.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SingleLeasePort {
    /// TCP port.
    Tcp(u16),
    /// UDP port.
    Udp(u16),
}

impl std::fmt::Display for SingleLeasePort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::Tcp(p) => write!(f, "{p}/TCP"),
            Self::Udp(p) => write!(f, "{p}/UDP"),
        }
    }
}

/// Dynamic port/address lease.
#[derive(Clone)]
struct Lease {
    addr: IpAddr,
    port: LeasePort,
    timeout: Instant,
}

impl Lease {
    /// Create a new lease with maximum timeout.
    pub fn new(conf: &Config, addr: IpAddr, port: LeasePort, timeout: Option<Duration>) -> Self {
        // The upper layers must never give us a lease request for the control port.
        assert_ne!(
            conf.port().port,
            match port {
                LeasePort::Tcp(p) => p,
                LeasePort::Udp(p) => p,
                LeasePort::TcpUdp(p) => p,
            }
        );
        let timeout = Instant::now() + timeout.unwrap_or_else(|| conf.nft_timeout());
        Self {
            addr,
            port,
            timeout,
        }
    }

    /// Reset the timeout to maximum.
    pub fn refresh_timeout(&mut self, conf: &Config) {
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
    pub fn port(&self) -> LeasePort {
        self.port
    }
}

impl std::fmt::Display for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "Lease(addr={}, port={})", self.addr(), self.port())
    }
}

/// Key in the lease map.
type LeaseId = (IpAddr, LeasePort);

/// A map of [Lease]s.
type LeaseMap = HashMap<LeaseId, Lease>;

/// Prune (remove) all leases that have timed out.
///
/// Returns a `Vec` of pruned [Lease]s.
/// If no lease timed out, an empty `Vec` is returned.
#[must_use]
fn prune_all_lease_timeouts(conf: &Config, leases: &mut LeaseMap) -> Vec<Lease> {
    let mut pruned = vec![];
    let now = Instant::now();
    leases.retain(|_, lease| {
        let timed_out = lease.is_timed_out(now);
        if timed_out {
            pruned.push(lease.clone());
            if conf.debug() {
                println!("firewall: {lease} timed out");
            }
        }
        !timed_out
    });
    pruned
}

/// Firewall maintenance operations.
pub trait FirewallMaintain {
    /// Delete all leases from the firewall.
    async fn shutdown(&mut self, conf: &Config) -> ah::Result<()>;

    /// Run periodic maintenance.
    /// This shall be called in regular intervals every couple of seconds.
    /// This operation shall remove all timed-out leases.
    async fn maintain(&mut self, conf: &Config) -> ah::Result<()>;
}

/// Firewall knock-open operations.
pub trait FirewallOpen {
    /// Add a rule to open the specified `port` for the specified `remote_addr`.
    /// This operation shall handle the case where there already is such
    /// a rule present gracefully.
    async fn open_port(
        &mut self,
        conf: &Config,
        remote_addr: IpAddr,
        port: LeasePort,
        timeout: Option<Duration>,
    ) -> ah::Result<()>;
}

// vim: ts=4 sw=4 expandtab
