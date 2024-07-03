// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    firewall::{prune_all_lease_timeouts, FirewallMaintain, FirewallOpen, Lease, LeaseMap},
    ConfigRef,
};
use anyhow::{self as ah, format_err as err, Context as _};
use nftables::{
    batch::Batch,
    expr::{Expression, NamedExpression, Payload, PayloadField},
    helper::apply_ruleset,
    schema::{Chain, FlushObject, NfCmd, NfListObject, Rule},
    stmt::{Match, Operator, Statement},
    types::NfFamily,
};
use std::net::IpAddr;

/// Create an nftables IP source address match statement.
fn statement_match_saddr(addr: IpAddr) -> Statement {
    let (protocol, addr) = match addr {
        IpAddr::V4(addr) => ("ip", addr.to_string()),
        IpAddr::V6(addr) => {
            if let Some(addr) = addr.to_ipv4_mapped() {
                ("ip", addr.to_string())
            } else {
                ("ip6", addr.to_string())
            }
        }
    };
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
            PayloadField {
                protocol: protocol.to_string(),
                field: "saddr".to_string(),
            },
        ))),
        right: Expression::String(addr),
        op: Operator::EQ,
    })
}

/// Create an nftables port match statement.
fn statement_match_dport(port: u16) -> Statement {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
            PayloadField {
                protocol: "tcp".to_string(),
                field: "dport".to_string(),
            },
        ))),
        right: Expression::Number(port.into()),
        op: Operator::EQ,
    })
}

/// Create an nftables `accept` statement.
fn statement_accept() -> Statement {
    Statement::Accept(None)
}

/// Generate a nftables rule for this lease.
/// This rule will open the port for the IP address.
fn gen_lease_rule(
    conf: &ConfigRef<'_>,
    family: NfFamily,
    table: &str,
    chain_input: &str,
    lease: &Lease,
) -> NfListObject {
    let rule = NfListObject::Rule(Rule::new(
        family,
        table.to_string(),
        chain_input.to_string(),
        vec![
            statement_match_saddr(lease.addr()),
            statement_match_dport(lease.port()),
            statement_accept(),
        ],
    ));
    if conf.debug() {
        println!(
            "nftables: Rule saddr={}, dport={}",
            lease.addr(),
            lease.port()
        );
    }
    rule
}

pub struct NftFirewall {
    leases: LeaseMap,
}

impl NftFirewall {
    /// Create a new firewall handler instance.
    /// This will also remove all rules from the kernel.
    pub async fn new(conf: &ConfigRef<'_>) -> ah::Result<Self> {
        let mut this = Self {
            leases: LeaseMap::new(),
        };
        this.clear(conf).await.context("nftables initialization")?;
        Ok(this)
    }

    /// Generate the nftables rules and apply them to the kernel.
    fn apply_nftables(&mut self, conf: &ConfigRef<'_>) -> ah::Result<()> {
        let family = match conf.nft_family() {
            "inet" => NfFamily::INet,
            "ip" => NfFamily::IP,
            "ip6" => NfFamily::IP6,
            fam => {
                return Err(err!("Unknown nftables family: {fam}"));
            }
        };
        let table = conf.nft_table();
        let chain_input = conf.nft_chain_input();

        let mut batch = Batch::new();

        // Remove all rules from our chain.
        batch.add_cmd(NfCmd::Flush(FlushObject::Chain(Chain::new(
            family,
            table.to_string(),
            chain_input.to_string(),
            None,
            None,
            None,
            None,
            None,
        ))));

        // Open the port letmeind is listening on.
        batch.add(NfListObject::Rule(Rule::new(
            family,
            table.to_string(),
            chain_input.to_string(),
            vec![statement_match_dport(conf.port()), statement_accept()],
        )));
        if conf.debug() {
            println!("nftables: Rule dport={}", conf.port());
        }

        // Open all lease ports, restricted to the peer addresses.
        for lease in self.leases.values() {
            batch.add(gen_lease_rule(conf, family, table, chain_input, lease));
        }

        // Apply all rules to the kernel.
        let ruleset = batch.to_nftables();
        apply_ruleset(&ruleset, None, None).context("Apply nftables")?;

        if conf.debug() {
            println!("nftables: {} rules installed.", self.leases.len() + 1);
        }
        Ok(())
    }
}

impl FirewallMaintain for NftFirewall {
    /// Remove all leases and remove all rules from the kernel.
    async fn clear(&mut self, conf: &ConfigRef<'_>) -> ah::Result<()> {
        self.leases.clear();
        self.apply_nftables(conf)
    }

    /// Run the periodic maintenance of the firewall.
    /// This will remove timed-out leases.
    async fn maintain(&mut self, conf: &ConfigRef<'_>) -> ah::Result<()> {
        let old_len = self.leases.len();
        prune_all_lease_timeouts(conf, &mut self.leases);
        if old_len != self.leases.len() {
            self.apply_nftables(conf)?;
        }
        Ok(())
    }

    /// Perform a reload (SIGHUP) of the firewall.
    /// This will always re-apply the rules to the kernel.
    async fn reload(&mut self, conf: &ConfigRef<'_>) -> ah::Result<()> {
        prune_all_lease_timeouts(conf, &mut self.leases);
        self.apply_nftables(conf)?;
        Ok(())
    }
}

impl FirewallOpen for NftFirewall {
    /// Add a lease and open the port for the specified IP address.
    /// If a lease for this port/address is already present, the timeout will be reset.
    /// Apply the rules to the kernel, if required.
    async fn open_port(
        &mut self,
        conf: &ConfigRef<'_>,
        remote_addr: IpAddr,
        port: u16,
    ) -> ah::Result<()> {
        let id = (remote_addr, port);
        if let Some(lease) = self.leases.get_mut(&id) {
            lease.refresh_timeout(conf);
        } else {
            self.leases.insert(id, Lease::new(conf, remote_addr, port));
            if let Err(e) = self.apply_nftables(conf) {
                self.leases.remove(&id);
                return Err(e);
            }
        }
        Ok(())
    }
}

// vim: ts=4 sw=4 expandtab
