// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::firewall::{
    prune_all_lease_timeouts, FirewallMaintain, FirewallOpen, Lease, LeaseMap, LeasePort,
    SingleLeasePort,
};
use anyhow::{self as ah, format_err as err, Context as _};
use letmein_conf::Config;
use nftables::{
    batch::Batch,
    expr::{Expression, NamedExpression, Payload, PayloadField},
    helper::{apply_ruleset_with_args_async, get_current_ruleset_with_args_async, DEFAULT_ARGS},
    schema::{Chain, FlushObject, NfCmd, NfListObject, NfObject, Rule},
    stmt::{Match, Operator, Statement},
    types::NfFamily,
};
use std::{borrow::Cow, fmt::Write as _, net::IpAddr};

struct NftNames<'a> {
    family: NfFamily,
    table: &'a str,
    chain_input: &'a str,
}

impl<'a> NftNames<'a> {
    fn get(conf: &'a Config) -> ah::Result<Self> {
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
fn statement_match_saddr<'a>(family: NfFamily, addr: IpAddr) -> ah::Result<Statement<'a>> {
    let (protocol, addr) = match addr {
        IpAddr::V4(addr) => match family {
            NfFamily::INet | NfFamily::IP => ("ip", addr.to_string()),
            _ => {
                return Err(err!("IP version not supported by nftables firewall family"));
            }
        },
        IpAddr::V6(addr) => {
            if let Some(addr) = addr.to_ipv4_mapped() {
                match family {
                    NfFamily::INet | NfFamily::IP => ("ip", addr.to_string()),
                    _ => {
                        return Err(err!("IP version not supported by nftables firewall family"));
                    }
                }
            } else {
                match family {
                    NfFamily::INet | NfFamily::IP6 => ("ip6", addr.to_string()),
                    _ => {
                        return Err(err!("IP version not supported by nftables firewall family"));
                    }
                }
            }
        }
    };
    Ok(Statement::Match(Match {
        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
            PayloadField {
                protocol: Cow::Borrowed(protocol),
                field: Cow::Borrowed("saddr"),
            },
        ))),
        right: Expression::String(Cow::Owned(addr)),
        op: Operator::EQ,
    }))
}

/// Create an nftables port match statement.
fn statement_match_dport<'a>(port: SingleLeasePort) -> Statement<'a> {
    let (protocol, port) = match port {
        SingleLeasePort::Tcp(port) => ("tcp", port),
        SingleLeasePort::Udp(port) => ("udp", port),
    };
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
            PayloadField {
                protocol: Cow::Borrowed(protocol),
                field: Cow::Borrowed("dport"),
            },
        ))),
        right: Expression::Number(port.into()),
        op: Operator::EQ,
    })
}

/// Create an nftables `accept` statement.
fn statement_accept<'a>() -> Statement<'a> {
    Statement::Accept(None)
}

/// Comment string for a `Rule`.
/// It can be used as unique identifier for lease rules.
fn gen_rule_comment(addr: Option<IpAddr>, port: SingleLeasePort) -> ah::Result<String> {
    let mut comment = String::with_capacity(256);
    if let Some(addr) = addr {
        write!(&mut comment, "{addr}/")?;
    } else {
        write!(&mut comment, "any/")?;
    }
    write!(&mut comment, "{port}/accept/letmein/GENERATED")?;
    Ok(comment)
}

/// Generate a nftables add-rule for this addr/port.
/// This rule will open the port for the IP address.
fn gen_add_lease_cmd(
    conf: &Config,
    addr: Option<IpAddr>,
    port: SingleLeasePort,
) -> ah::Result<NfCmd> {
    let names = NftNames::get(conf).context("Read configuration")?;
    let mut expr = Vec::with_capacity(3);
    if let Some(addr) = addr {
        expr.push(statement_match_saddr(names.family, addr)?);
    }
    expr.push(statement_match_dport(port));
    expr.push(statement_accept());
    let mut rule = Rule {
        family: names.family,
        table: Cow::Borrowed(names.table),
        chain: Cow::Borrowed(names.chain_input),
        expr: Cow::Owned(expr),
        ..Default::default()
    };
    rule.comment = Some(Cow::Owned(gen_rule_comment(addr, port)?));
    Ok(NfCmd::Add(NfListObject::Rule(rule)))
}

/// Generate the nftables add-rule commands for this lease.
/// These commands will open the port(s) for the IP address.
fn gen_add_lease_cmds<'a>(conf: &'a Config, lease: &Lease) -> ah::Result<Vec<NfCmd<'a>>> {
    let mut cmds = Vec::with_capacity(2);
    let addr = Some(lease.addr());
    match lease.port() {
        LeasePort::Tcp(port) => {
            cmds.push(gen_add_lease_cmd(conf, addr, SingleLeasePort::Tcp(port))?);
        }
        LeasePort::Udp(port) => {
            cmds.push(gen_add_lease_cmd(conf, addr, SingleLeasePort::Udp(port))?);
        }
        LeasePort::TcpUdp(port) => {
            cmds.push(gen_add_lease_cmd(conf, addr, SingleLeasePort::Tcp(port))?);
            cmds.push(gen_add_lease_cmd(conf, addr, SingleLeasePort::Udp(port))?);
        }
    }
    if conf.debug() {
        println!("nftables: Adding rules for {lease}");
    }
    Ok(cmds)
}

struct ListedRuleset<'a> {
    objs: Cow<'a, [NfObject<'static>]>,
}

impl ListedRuleset<'_> {
    /// Get the active ruleset from the kernel.
    pub async fn from_kernel(conf: &Config) -> ah::Result<Self> {
        let ruleset = get_current_ruleset_with_args_async(
            Some(conf.nft_exe()), // program
            DEFAULT_ARGS,         // args
        )
        .await?;
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
        addr: IpAddr,
        port: SingleLeasePort,
    ) -> ah::Result<u32> {
        let comment = gen_rule_comment(Some(addr), port)?;
        for obj in &*self.objs {
            if let NfObject::ListObject(obj) = obj {
                match obj {
                    NfListObject::Rule(Rule {
                        family: rule_family,
                        table: rule_table,
                        chain: rule_chain,
                        handle: Some(rule_handle),
                        comment: Some(rule_comment),
                        ..
                    }) if *rule_family == family
                        && *rule_table == table
                        && *rule_chain == chain_input
                        && *rule_comment == comment =>
                    {
                        return Ok(*rule_handle);
                    }
                    _ => (),
                }
            }
        }
        Err(err!(
            "Nftables 'handle' for {addr}:{port} not found in the kernel ruleset."
        ))
    }

    /// Generate nftables delete-rules for this lease.
    /// These rules will close the ports for the IP address.
    pub fn gen_delete_lease_cmds<'a>(
        &self,
        conf: &'a Config,
        lease: &Lease,
    ) -> ah::Result<Vec<NfCmd<'a>>> {
        let mut cmds = Vec::with_capacity(2);
        let names = NftNames::get(conf).context("Read configuration")?;
        let addr = lease.addr();

        let new_rule = |port: SingleLeasePort| -> ah::Result<NfCmd> {
            let mut rule = Rule {
                family: names.family,
                table: Cow::Borrowed(names.table),
                chain: Cow::Borrowed(names.chain_input),
                expr: Cow::Owned(vec![]),
                ..Default::default()
            };
            rule.handle =
                Some(self.find_handle(names.family, names.table, names.chain_input, addr, port)?);
            Ok(NfCmd::Delete(NfListObject::Rule(rule)))
        };

        match lease.port() {
            LeasePort::Tcp(port) => {
                cmds.push(new_rule(SingleLeasePort::Tcp(port))?);
            }
            LeasePort::Udp(port) => {
                cmds.push(new_rule(SingleLeasePort::Udp(port))?);
            }
            LeasePort::TcpUdp(port) => {
                cmds.push(new_rule(SingleLeasePort::Tcp(port))?);
                cmds.push(new_rule(SingleLeasePort::Udp(port))?);
            }
        }
        if conf.debug() {
            println!("nftables: Deleting rules for {lease}");
        }
        Ok(cmds)
    }
}

pub struct NftFirewall {
    leases: LeaseMap,
    shutdown: bool,
    num_ctrl_rules: u8,
}

impl NftFirewall {
    /// Create a new firewall handler instance.
    /// This will also remove all rules from the kernel.
    pub async fn new(conf: &Config) -> ah::Result<Self> {
        // Test if the `nft` binary is available.
        if let Err(e) = std::process::Command::new(conf.nft_exe())
            .args(["--help"])
            .output()
        {
            return Err(err!(
                "Failed to execute the 'nft' program.\n\
                Did you install the 'nftables' support package in your distribution's package manager?\n\
                Is the 'nft' binary available in the $PATH?\n\
                The execution error was: {e:?}"
            ));
        }

        let mut this = Self {
            leases: LeaseMap::new(),
            shutdown: false,
            num_ctrl_rules: 0,
        };

        this.nftables_full_rebuild(conf)
            .await
            .context("nftables initialization")?;
        this.print_total_rule_count(conf);

        Ok(this)
    }

    /// Print the number of rules required for all leases.
    fn print_total_rule_count(&self, conf: &Config) {
        if conf.debug() {
            let mut count: usize = self.num_ctrl_rules.into();
            for lease in self.leases.values() {
                count += match lease.port() {
                    LeasePort::Tcp(_) | LeasePort::Udp(_) => 1,
                    LeasePort::TcpUdp(_) => 2,
                };
            }
            println!("nftables: A total of {count} rules is installed.");
        }
    }

    /// Apply a rules batch to the kernel.
    async fn nftables_apply_batch(&self, conf: &Config, batch: Batch<'_>) -> ah::Result<()> {
        let ruleset = batch.to_nftables();
        apply_ruleset_with_args_async(
            &ruleset,             // rules
            Some(conf.nft_exe()), // program
            DEFAULT_ARGS,         // args
        )
        .await
        .context("Apply nftables")?;
        Ok(())
    }

    /// Generate all nftables rules and apply them to the kernel after flushing the chain.
    async fn nftables_full_rebuild(&mut self, conf: &Config) -> ah::Result<()> {
        let names = NftNames::get(conf).context("Read configuration")?;

        let mut batch = Batch::new();

        // Remove all rules from our chain.
        batch.add_cmd(NfCmd::Flush(FlushObject::Chain(Chain {
            family: names.family,
            table: Cow::Borrowed(names.table),
            name: Cow::Borrowed(names.chain_input),
            ..Default::default()
        })));
        if conf.debug() {
            println!("nftables: Chain flushed");
        }

        self.num_ctrl_rules = 0;
        if !self.shutdown {
            // Open the port letmeind is listening on.
            if conf.port().tcp {
                let p = SingleLeasePort::Tcp(conf.port().port);
                batch.add_cmd(gen_add_lease_cmd(conf, None, p)?);
                if conf.debug() {
                    println!("nftables: Adding control port rule for port={p}");
                }
                self.num_ctrl_rules += 1;
            }
            if conf.port().udp {
                let p = SingleLeasePort::Udp(conf.port().port);
                batch.add_cmd(gen_add_lease_cmd(conf, None, p)?);
                if conf.debug() {
                    println!("nftables: Adding control port rule for port={p}");
                }
                self.num_ctrl_rules += 1;
            }

            // Open all lease ports, restricted to the peer addresses.
            for lease in self.leases.values() {
                for cmd in gen_add_lease_cmds(conf, lease)? {
                    batch.add_cmd(cmd);
                }
            }
        }

        // Apply all batch commands to the kernel.
        self.nftables_apply_batch(conf, batch).await
    }

    /// Generate one lease rule and apply it to the kernel.
    async fn nftables_add_lease(&mut self, conf: &Config, lease: &Lease) -> ah::Result<()> {
        // Open the lease port, restricted to the peer address.
        let mut batch = Batch::new();
        for cmd in gen_add_lease_cmds(conf, lease)? {
            batch.add_cmd(cmd);
        }

        // Apply all batch commands to the kernel.
        self.nftables_apply_batch(conf, batch).await
    }

    /// Remove an existing lease rule from the kernel.
    async fn nftables_remove_leases(&mut self, conf: &Config, leases: &[Lease]) -> ah::Result<()> {
        if !leases.is_empty() {
            // Get the active ruleset from the kernel.
            let ruleset = ListedRuleset::from_kernel(conf).await?;

            // Add delete commands to remove the lease ports.
            let mut batch = Batch::new();
            for lease in leases {
                for cmd in ruleset.gen_delete_lease_cmds(conf, lease)? {
                    batch.add_cmd(cmd);
                }
            }

            // Apply all batch commands to the kernel.
            self.nftables_apply_batch(conf, batch).await?;
        }
        Ok(())
    }
}

impl FirewallMaintain for NftFirewall {
    /// Remove all leases and remove all rules from the kernel.
    async fn shutdown(&mut self, conf: &Config) -> ah::Result<()> {
        assert!(!self.shutdown);
        self.shutdown = true;
        self.leases.clear();
        self.nftables_full_rebuild(conf).await?;
        self.print_total_rule_count(conf);
        Ok(())
    }

    /// Run the periodic maintenance of the firewall.
    /// This will remove timed-out leases.
    async fn maintain(&mut self, conf: &Config) -> ah::Result<()> {
        assert!(!self.shutdown);
        let pruned = prune_all_lease_timeouts(conf, &mut self.leases);
        if !pruned.is_empty() {
            if let Err(e) = self.nftables_remove_leases(conf, &pruned).await {
                eprintln!("WARNING: Failed to remove lease(s): {e:?}");
                eprintln!("Trying full rebuild.");
                self.nftables_full_rebuild(conf).await?;
            }
            self.print_total_rule_count(conf);
        }
        Ok(())
    }
}

impl FirewallOpen for NftFirewall {
    /// Add a lease and open the port for the specified IP address.
    /// If a lease for this port/address is already present, the timeout will be reset.
    /// Apply the rules to the kernel, if required.
    async fn open_port(
        &mut self,
        conf: &Config,
        remote_addr: IpAddr,
        port: LeasePort,
    ) -> ah::Result<()> {
        assert!(!self.shutdown);
        let id = (remote_addr, port);
        if let Some(lease) = self.leases.get_mut(&id) {
            lease.refresh_timeout(conf);
        } else {
            let lease = Lease::new(conf, remote_addr, port);
            self.nftables_add_lease(conf, &lease).await?;
            self.leases.insert(id, lease);
            self.print_total_rule_count(conf);
        }
        Ok(())
    }
}

// vim: ts=4 sw=4 expandtab
