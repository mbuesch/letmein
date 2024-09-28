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
    helper::{apply_ruleset, get_current_ruleset},
    schema::{Chain, FlushObject, NfCmd, NfListObject, NfObject, Rule},
    stmt::{Match, Operator, Statement},
    types::NfFamily,
};
use std::net::IpAddr;

struct NftNames<'a> {
    family: NfFamily,
    table: &'a str,
    chain_input: &'a str,
}

impl<'a> NftNames<'a> {
    fn get(conf: &'a ConfigRef<'_>) -> ah::Result<Self> {
        let family = match conf.nft_family() {
            "inet" => NfFamily::INet,
            "ip" => NfFamily::IP,
            "ip6" => NfFamily::IP6,
            fam => {
                return Err(err!("Unknown nftables family: {fam}"));
            }
        };
        let table = match conf.nft_table() {
            "" => {
                return Err(err!("nftables table not specified."));
            }
            table => table,
        };
        let chain_input = match conf.nft_chain_input() {
            "" => {
                return Err(err!("nftables chain-input not specified."));
            }
            table => table,
        };
        Ok(NftNames {
            family,
            table,
            chain_input,
        })
    }
}

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

/// Comment string for a `Rule`.
/// It can be used as unique identifier for lease rules.
fn gen_rule_comment(lease: Option<&Lease>) -> String {
    const BASE: &str = "GENERATED/letmein";
    if let Some(lease) = lease {
        format!("[{}]:{}/{}", lease.addr(), lease.port(), BASE)
    } else {
        BASE.to_string()
    }
}

/// Generate a nftables add-rule for this lease.
/// This rule will open the port for the IP address.
fn gen_add_lease_cmd(conf: &ConfigRef<'_>, lease: &Lease) -> ah::Result<NfCmd> {
    let names = NftNames::get(conf).context("Read configuration")?;
    let mut rule = Rule::new(
        names.family,
        names.table.to_string(),
        names.chain_input.to_string(),
        vec![
            statement_match_saddr(lease.addr()),
            statement_match_dport(lease.port()),
            statement_accept(),
        ],
    );
    rule.comment = Some(gen_rule_comment(Some(lease)));
    if conf.debug() {
        println!("nftables: Adding rule for {lease}");
    }
    Ok(NfCmd::Add(NfListObject::Rule(rule)))
}

struct ListedRuleset {
    objs: Vec<NfObject>,
}

impl ListedRuleset {
    /// Get the active ruleset from the kernel.
    pub fn from_kernel() -> ah::Result<Self> {
        let ruleset = get_current_ruleset(
            None, // program
            None, // args
        )?;
        Ok(Self {
            objs: ruleset.objects,
        })
    }

    /// Get the nftables handle corresponding to the lease.
    /// The rule's comment is the main identifier.
    fn find_handle(
        &self,
        family: NfFamily,
        table: &str,
        chain_input: &str,
        lease: &Lease,
    ) -> ah::Result<u32> {
        let comment = gen_rule_comment(Some(lease));
        for obj in &self.objs {
            match obj {
                NfObject::ListObject(NfListObject::Rule(Rule {
                    family: rule_family,
                    table: rule_table,
                    chain: rule_chain,
                    handle: Some(rule_handle),
                    comment: Some(rule_comment),
                    ..
                })) if *rule_family == family
                    && *rule_table == table
                    && *rule_chain == chain_input
                    && *rule_comment == comment =>
                {
                    return Ok(*rule_handle);
                }
                _ => (),
            }
        }
        Err(err!(
            "Nftables 'handle' for {lease} not found in the kernel ruleset."
        ))
    }

    /// Generate a nftables delete-rule for this lease.
    /// This rule will close the port for the IP address.
    pub fn gen_delete_lease_cmd(&self, conf: &ConfigRef<'_>, lease: &Lease) -> ah::Result<NfCmd> {
        let names = NftNames::get(conf).context("Read configuration")?;
        let mut rule = Rule::new(
            names.family,
            names.table.to_string(),
            names.chain_input.to_string(),
            vec![],
        );
        rule.handle =
            Some(self.find_handle(names.family, names.table, names.chain_input, lease)?);
        if conf.debug() {
            println!("nftables: Deleting rule for {lease}");
        }
        Ok(NfCmd::Delete(NfListObject::Rule(rule)))
    }
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

    /// Apply a rules batch to the kernel.
    fn nftables_apply_batch(&self, conf: &ConfigRef<'_>, batch: Batch) -> ah::Result<()> {
        let ruleset = batch.to_nftables();
        apply_ruleset(
            &ruleset, // rules
            None,     // program
            None,     // args
        )
        .context("Apply nftables")?;
        if conf.debug() {
            println!(
                "nftables: A total of {} rules is installed.",
                self.leases.len() + 1
            );
        }
        Ok(())
    }

    /// Generate all nftables rules and apply them to the kernel after flushing the chain.
    fn nftables_full_rebuild(&mut self, conf: &ConfigRef<'_>) -> ah::Result<()> {
        let names = NftNames::get(conf).context("Read configuration")?;

        let mut batch = Batch::new();

        // Remove all rules from our chain.
        batch.add_cmd(NfCmd::Flush(FlushObject::Chain(Chain::new(
            names.family,
            names.table.to_string(),
            names.chain_input.to_string(), // name
            None,                          // _type
            None,                          // hook
            None,                          // prio
            None,                          // dev
            None,                          // policy
        ))));
        if conf.debug() {
            println!("nftables: Chain flushed");
        }

        // Open the port letmeind is listening on.
        let mut rule = Rule::new(
            names.family,
            names.table.to_string(),
            names.chain_input.to_string(),
            vec![statement_match_dport(conf.port()), statement_accept()],
        );
        rule.comment = Some(gen_rule_comment(None));
        batch.add_cmd(NfCmd::Add(NfListObject::Rule(rule)));
        if conf.debug() {
            println!(
                "nftables: Adding control port rule for port={}",
                conf.port()
            );
        }

        // Open all lease ports, restricted to the peer addresses.
        for lease in self.leases.values() {
            batch.add_cmd(gen_add_lease_cmd(conf, lease)?);
        }

        // Apply all batch commands to the kernel.
        self.nftables_apply_batch(conf, batch)
    }

    /// Generate one lease rule and apply it to the kernel.
    fn nftables_add_lease(&mut self, conf: &ConfigRef<'_>, lease: &Lease) -> ah::Result<()> {
        // Open the lease port, restricted to the peer address.
        let mut batch = Batch::new();
        batch.add_cmd(gen_add_lease_cmd(conf, lease)?);

        // Apply all batch commands to the kernel.
        self.nftables_apply_batch(conf, batch)
    }

    /// Remove an existing lease rule from the kernel.
    fn nftables_remove_leases(&mut self, conf: &ConfigRef<'_>, leases: &[Lease]) -> ah::Result<()> {
        if !leases.is_empty() {
            // Get the active ruleset from the kernel.
            let ruleset = ListedRuleset::from_kernel()?;

            // Add delete commands to remove the lease ports.
            let mut batch = Batch::new();
            for lease in leases {
                batch.add_cmd(ruleset.gen_delete_lease_cmd(conf, lease)?);
            }

            // Apply all batch commands to the kernel.
            self.nftables_apply_batch(conf, batch)?;
        }
        Ok(())
    }
}

impl FirewallMaintain for NftFirewall {
    /// Remove all leases and remove all rules from the kernel.
    async fn clear(&mut self, conf: &ConfigRef<'_>) -> ah::Result<()> {
        self.leases.clear();
        self.nftables_full_rebuild(conf)
    }

    /// Run the periodic maintenance of the firewall.
    /// This will remove timed-out leases.
    async fn maintain(&mut self, conf: &ConfigRef<'_>) -> ah::Result<()> {
        let pruned = prune_all_lease_timeouts(conf, &mut self.leases);
        if let Err(e) = self.nftables_remove_leases(conf, &pruned) {
            eprintln!("WARNING: Failed to remove lease(s): '{e}'.");
            eprintln!("Trying full rebuild.");
            self.nftables_full_rebuild(conf)?;
        }
        Ok(())
    }

    /// Perform a reload (SIGHUP) of the firewall.
    /// This will always re-apply the rules to the kernel.
    async fn reload(&mut self, conf: &ConfigRef<'_>) -> ah::Result<()> {
        let _pruned = prune_all_lease_timeouts(conf, &mut self.leases);
        self.nftables_full_rebuild(conf)?;
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
            let lease = Lease::new(conf, remote_addr, port);
            self.nftables_add_lease(conf, &lease)?;
            self.leases.insert(id, lease);
        }
        Ok(())
    }
}

// vim: ts=4 sw=4 expandtab
