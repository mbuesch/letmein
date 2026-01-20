// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub mod nftables;

use anyhow::{self as ah, format_err as err};
use letmein_conf::{Config, Resource};
use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

/// Firewall chain type.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum FirewallChain {
    Input,
    Forward,
    Output,
}

impl std::fmt::Display for FirewallChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::Input => write!(f, "chain-input"),
            Self::Forward => write!(f, "chain-forward"),
            Self::Output => write!(f, "chain-output"),
        }
    }
}

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

impl TryFrom<Resource> for LeasePort {
    type Error = ah::Error;

    fn try_from(res: Resource) -> ah::Result<Self> {
        if let Resource::Port {
            id: _,
            port,
            tcp,
            udp,
            timeout: _,
            users: _,
        } = res
        {
            match (tcp, udp) {
                (true, false) => Ok(Self::Tcp(port)),
                (false, true) => Ok(Self::Udp(port)),
                (true, true) => Ok(Self::TcpUdp(port)),
                (false, false) => Err(err!("LeasePort: Invalid port info in config.")),
            }
        } else {
            Err(err!("LeasePort: Resource is not a Port resource"))
        }
    }
}

impl LeasePort {
    pub fn port(&self) -> u16 {
        match self {
            Self::Tcp(port) | Self::Udp(port) | Self::TcpUdp(port) => *port,
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

/// Dynamic resource lease type.
#[derive(Clone)]
enum LeaseType {
    Port {
        port: LeasePort,
    },
    Jump {
        chain: FirewallChain,
        target: String,
        match_saddr: bool,
    },
}

impl std::fmt::Display for LeaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::Port { port } => {
                write!(f, "Port({port})")
            }
            Self::Jump {
                chain,
                target,
                match_saddr: _,
            } => {
                write!(f, "Jump({chain}.{target})")
            }
        }
    }
}

/// Dynamic resource lease.
#[derive(Clone)]
struct Lease {
    addr: Option<IpAddr>,
    timeout: Instant,
    type_: LeaseType,
}

impl Lease {
    /// Create a new port-lease.
    pub fn new_port(
        conf: &Config,
        addr: IpAddr,
        port: LeasePort,
        timeout: Option<Duration>,
    ) -> Self {
        // The upper layers must never give us a lease request for the control port.
        assert_ne!(
            conf.port().port,
            match port {
                LeasePort::Tcp(p) | LeasePort::Udp(p) | LeasePort::TcpUdp(p) => p,
            }
        );
        Self::new(conf, Some(addr), LeaseType::Port { port }, timeout)
    }

    /// Create a new jump-lease.
    pub fn new_jump(
        conf: &Config,
        addr: Option<IpAddr>,
        chain: FirewallChain,
        target: &str,
        match_saddr: bool,
        timeout: Option<Duration>,
    ) -> Self {
        Self::new(
            conf,
            addr,
            LeaseType::Jump {
                chain,
                target: target.to_string(),
                match_saddr,
            },
            timeout,
        )
    }

    fn new(
        conf: &Config,
        addr: Option<IpAddr>,
        type_: LeaseType,
        timeout: Option<Duration>,
    ) -> Self {
        let timeout = Instant::now() + timeout.unwrap_or_else(|| conf.nft_timeout());
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
    pub fn addr(&self) -> Option<IpAddr> {
        self.addr
    }

    /// Get the lease type.
    pub fn type_(&self) -> &LeaseType {
        &self.type_
    }
}

impl std::fmt::Display for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let addr = self
            .addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "any".to_string());
        write!(f, "Lease(addr={addr}, {})", self.type_())
    }
}

/// Key in the port lease map.
///
/// - `0`: Address of the client that the port is opened for.
/// - `1`: Port number and type that is opened.
type PortLeaseId = (IpAddr, LeasePort);

/// A map of port [Lease]s.
type PortLeaseMap = HashMap<PortLeaseId, Lease>;

/// Key in the jump lease map.
///
/// - `0`: Address of the client that the jump uses as saddr condition
///   or `None` if the jump is unconditional.
/// - `1`: The firewall chain that the jump is added to.
/// - `2`: The name of the target chain that the jump jumps to.
type JumpLeaseId = (Option<IpAddr>, FirewallChain, String);

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
    async fn shutdown(&self, conf: &Config) -> ah::Result<()>;

    /// Run periodic maintenance.
    /// This shall be called in regular intervals every couple of seconds.
    /// This operation shall remove all timed-out leases.
    async fn maintain(&self, conf: &Config) -> ah::Result<()>;
}

/// Firewall jump targets for a jump lease.
#[derive(Clone, Default)]
pub struct FirewallJumpTargets {
    pub input: Option<String>,
    pub input_match_saddr: bool,
    pub forward: Option<String>,
    pub forward_match_saddr: bool,
    pub output: Option<String>,
    pub output_match_saddr: bool,
}

impl std::fmt::Display for FirewallJumpTargets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        if let Some(input) = &self.input {
            write!(f, "input={input} ")?;
        }
        if let Some(forward) = &self.forward {
            write!(f, "forward={forward} ")?;
        }
        if let Some(output) = &self.output {
            write!(f, "output={output} ")?;
        }
        Ok(())
    }
}

impl TryFrom<Resource> for FirewallJumpTargets {
    type Error = ah::Error;

    fn try_from(res: Resource) -> ah::Result<Self> {
        if let Resource::Jump {
            id: _,
            input,
            input_match_saddr,
            forward,
            forward_match_saddr,
            output,
            output_match_saddr,
            timeout: _,
            users: _,
        } = res
        {
            Ok(Self {
                input,
                input_match_saddr,
                forward,
                forward_match_saddr,
                output,
                output_match_saddr,
            })
        } else {
            Err(err!("FirewallJumpTargets: Resource is not a Jump resource"))
        }
    }
}

/// Firewall action operations.
pub trait FirewallAction {
    /// Add a rule to open the specified `port` for the specified `remote_addr`.
    ///
    /// This operation shall handle the case where there already is such
    /// a rule present gracefully.
    ///
    /// Warning: This function is *not* async cancel safe.
    async fn open_port(
        &self,
        conf: &Config,
        remote_addr: IpAddr,
        port: LeasePort,
        timeout: Option<Duration>,
    ) -> ah::Result<()>;

    /// Revoke/remove a port rule.
    ///
    /// This operation shall handle the case where there is no such
    /// rule present gracefully.
    ///
    /// Warning: This function is *not* async cancel safe.
    async fn revoke_port(
        &self,
        conf: &Config,
        remote_addr: IpAddr,
        port: LeasePort,
    ) -> ah::Result<()>;

    /// Add jump rules to jump to the specified processing rule chains.
    ///
    /// This operation shall handle the case where there already is such
    /// a rule present gracefully.
    ///
    /// Warning: This function is *not* async cancel safe.
    async fn add_jump(
        &self,
        conf: &Config,
        remote_addr: IpAddr,
        targets: &FirewallJumpTargets,
        timeout: Option<Duration>,
    ) -> ah::Result<()>;

    /// Revoke/remove a jump rule.
    ///
    /// This operation shall handle the case where there is no such
    /// rule present gracefully.
    ///
    /// Warning: This function is *not* async cancel safe.
    async fn revoke_jump(
        &self,
        conf: &Config,
        remote_addr: IpAddr,
        targets: &FirewallJumpTargets,
    ) -> ah::Result<()>;
}

// vim: ts=4 sw=4 expandtab
