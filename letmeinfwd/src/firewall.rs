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
use letmein_proto::ResourceId;
use std::{collections::HashMap, net::IpAddr, time::Instant};

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

#[derive(Clone)]
enum LeaseType {
    Port { port: LeasePort },
    Jump { targets: FirewallJumpTargets },
}

impl std::fmt::Display for LeaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::Port { port } => {
                write!(f, "Port({port})")
            }
            Self::Jump { targets } => {
                write!(f, "Jump({targets})")
            }
        }
    }
}

/// Dynamic port/address lease.
#[derive(Clone)]
struct Lease {
    addr: IpAddr,
    timeout: Instant,
    type_: LeaseType,
}

impl Lease {
    /// Create a new port-lease with maximum timeout.
    pub fn new_port(conf: &Config, addr: IpAddr, port: LeasePort) -> Self {
        // The upper layers must never give us a lease request for the control port.
        assert_ne!(
            conf.port().port,
            match port {
                LeasePort::Tcp(p) => p,
                LeasePort::Udp(p) => p,
                LeasePort::TcpUdp(p) => p,
            }
        );
        Self::new(conf, addr, LeaseType::Port { port })
    }

    /// Create a new jump-lease with maximum timeout.
    pub fn new_jump(conf: &Config, addr: IpAddr, targets: &FirewallJumpTargets) -> Self {
        Self::new(
            conf,
            addr,
            LeaseType::Jump {
                targets: targets.clone(),
            },
        )
    }

    fn new(conf: &Config, addr: IpAddr, type_: LeaseType) -> Self {
        let timeout = Instant::now() + conf.nft_timeout();
        Self {
            addr,
            timeout,
            type_,
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

    /// Get the lease type.
    pub fn type_(&self) -> &LeaseType {
        &self.type_
    }
}

impl std::fmt::Display for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "Lease(addr={}, {})", self.addr(), self.type_())
    }
}

/// Key in the port lease map.
type PortLeaseId = (IpAddr, LeasePort);

/// A map of port [Lease]s.
type PortLeaseMap = HashMap<PortLeaseId, Lease>;

/// Key in the jump lease map.
type JumpLeaseId = (IpAddr, ResourceId);

/// A map of jump [Lease]s.
type JumpLeaseMap = HashMap<JumpLeaseId, Lease>;

trait LeaseMapOps {
    /// Prune (remove) all leases that have timed out.
    ///
    /// Returns a `Vec` of pruned [Lease]s.
    /// If no lease timed out, an empty `Vec` is returned.
    #[must_use]
    fn prune_timeouts(&mut self, conf: &Config) -> Vec<Lease>;
}

impl<K> LeaseMapOps for HashMap<K, Lease> {
    fn prune_timeouts(&mut self, conf: &Config) -> Vec<Lease> {
        let mut pruned = vec![];
        let now = Instant::now();
        self.retain(|_, lease| {
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

#[derive(Clone, Default)]
pub struct FirewallJumpTargets {
    pub id: ResourceId,
    pub input: Option<String>,
    pub forward: Option<String>,
    pub output: Option<String>,
}

impl std::fmt::Display for FirewallJumpTargets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "id={}", self.id)?;
        if let Some(input) = &self.input {
            write!(f, ", input={input}")?;
        }
        if let Some(forward) = &self.forward {
            write!(f, ", forward={forward}")?;
        }
        if let Some(output) = &self.output {
            write!(f, ", output={output}")?;
        }
        Ok(())
    }
}

/// Firewall action operations.
pub trait FirewallAction {
    /// Add a rule to open the specified `port` for the specified `remote_addr`.
    /// This operation shall handle the case where there already is such
    /// a rule present gracefully.
    async fn open_port(
        &mut self,
        conf: &Config,
        remote_addr: IpAddr,
        port: LeasePort,
    ) -> ah::Result<()>;

    /// Add jump rules to jump to the specified processing rule chains.
    /// This operation shall handle the case where there already is such
    /// a rule present gracefully.
    async fn add_jump(
        &mut self,
        conf: &Config,
        remote_addr: IpAddr,
        targets: &FirewallJumpTargets,
    ) -> ah::Result<()>;
}

// vim: ts=4 sw=4 expandtab
