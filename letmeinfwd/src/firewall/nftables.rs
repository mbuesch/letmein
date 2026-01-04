// -*- coding: utf-8 -*-
//
// Copyright (C) 2024-2025 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::firewall::{
    FirewallAction, FirewallChain, FirewallJumpTargets, FirewallMaintain, JumpLeaseMap, Lease,
    LeaseMapOps as _, LeasePort, LeaseType, PortLeaseMap, SingleLeasePort,
};
use anyhow::{self as ah, format_err as err, Context as _};
use letmein_conf::Config;
use nftables::{
    batch::Batch,
    expr::{Expression, NamedExpression, Payload, PayloadField},
    helper::{apply_ruleset_with_args_async, get_current_ruleset_with_args_async, DEFAULT_ARGS},
    schema::{Chain, FlushObject, NfCmd, NfListObject, NfObject, Rule},
    stmt::{Counter, JumpTarget, Match, Operator, Statement},
    types::NfFamily,
};
use std::{borrow::Cow, fmt::Write as _, net::IpAddr, slice, time::Duration};
use tokio::sync::Mutex;

const NFTNL_UDATA_COMMENT_MAXLEN: usize = 128;

struct NftNames<'a> {
    family: NfFamily,
    table: &'a str,
    chain_input: &'a str,
    chain_forward: Option<&'a str>,
    chain_output: Option<&'a str>,
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
            chain => chain,
        };
        let chain_forward = match conf.nft_chain_forward() {
            "" => None,
            chain => Some(chain),
        };
        let chain_output = match conf.nft_chain_output() {
            "" => None,
            chain => Some(chain),
        };
        Ok(NftNames {
            family,
            table,
            chain_input,
            chain_forward,
            chain_output,
        })
    }

    fn get_chain_input(&self) -> ah::Result<&'a str> {
        Ok(self.chain_input)
    }

    fn get_chain_forward(&self) -> ah::Result<&'a str> {
        if let Some(chain_forward) = self.chain_forward {
            Ok(chain_forward)
        } else {
            Err(err!(
                "[NFTABLES] 'chain-forward=' is not specified in the configuration"
            ))
        }
    }

    fn get_chain_output(&self) -> ah::Result<&'a str> {
        if let Some(chain_output) = self.chain_output {
            Ok(chain_output)
        } else {
            Err(err!(
                "[NFTABLES] 'chain-output=' is not specified in the configuration"
            ))
        }
    }

    fn get_chain(&self, chain: FirewallChain) -> ah::Result<&'a str> {
        match chain {
            FirewallChain::Input => self.get_chain_input(),
            FirewallChain::Forward => self.get_chain_forward(),
            FirewallChain::Output => self.get_chain_output(),
        }
    }
}

fn option_if<T>(t: T, c: bool) -> Option<T> {
    if c {
        Some(t)
    } else {
        None
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

/// Create an nftables anonymous `counter` statement.
fn statement_counter<'a>() -> Statement<'a> {
    Statement::Counter(Counter::Anonymous(None))
}

/// Create an nftables `jump` statement.
fn statement_jump(target: &str) -> Statement<'_> {
    Statement::Jump(JumpTarget {
        target: Cow::Borrowed(target),
    })
}

/// Create an nftables `accept` statement.
fn statement_accept<'a>() -> Statement<'a> {
    Statement::Accept(None)
}

/// Comment string for a `Rule`.
/// It can be used as unique identifier for lease rules.
fn gen_rule_comment(
    addr: Option<IpAddr>,
    port: Option<SingleLeasePort>,
    target: Option<&str>,
) -> ah::Result<String> {
    let mut comment = String::with_capacity(NFTNL_UDATA_COMMENT_MAXLEN);

    if let Some(addr) = addr {
        write!(&mut comment, "{addr}/")?;
    } else {
        write!(&mut comment, "any/")?;
    }
    if let Some(port) = port {
        write!(&mut comment, "port/{port}/accept/")?;
    }
    if let Some(target) = target {
        write!(&mut comment, "jump/{target}/")?;
    }
    write!(&mut comment, "LETMEIN")?;

    if comment.len() > NFTNL_UDATA_COMMENT_MAXLEN {
        Err(err!(
            "Could not generate nftables rule comment. \
            The length {} is longer than the maximum of {}.",
            comment.len(),
            NFTNL_UDATA_COMMENT_MAXLEN
        ))
    } else {
        Ok(comment)
    }
}

/// Generate a nftables add-rule for this addr/port.
/// This rule will open the port for the IP address.
fn gen_add_port_lease_cmd<'a>(
    names: &'a NftNames<'a>,
    addr: Option<IpAddr>,
    port: SingleLeasePort,
) -> ah::Result<NfCmd<'a>> {
    let mut expr = Vec::with_capacity(4);
    if let Some(addr) = addr {
        expr.push(statement_match_saddr(names.family, addr)?);
    }
    expr.push(statement_match_dport(port));
    expr.push(statement_counter());
    expr.push(statement_accept());
    let mut rule = Rule {
        family: names.family,
        table: Cow::Borrowed(names.table),
        chain: Cow::Borrowed(names.chain_input),
        expr: Cow::Owned(expr),
        ..Default::default()
    };
    rule.comment = Some(Cow::Owned(gen_rule_comment(addr, Some(port), None)?));
    Ok(NfCmd::Add(NfListObject::Rule(rule)))
}

/// Generate a nftables jump-rule for this chain.
fn gen_add_jump_cmd<'a>(
    names: &'a NftNames,
    chain: &'a str,
    addr: Option<IpAddr>,
    target: &'a str,
) -> ah::Result<NfCmd<'a>> {
    let mut expr = Vec::with_capacity(2);
    if let Some(addr) = addr {
        expr.push(statement_match_saddr(names.family, addr)?);
    }
    expr.push(statement_jump(target));
    let mut rule = Rule {
        family: names.family,
        table: Cow::Borrowed(names.table),
        chain: Cow::Borrowed(chain),
        expr: Cow::Owned(expr),
        ..Default::default()
    };
    rule.comment = Some(Cow::Owned(gen_rule_comment(addr, None, Some(target))?));
    Ok(NfCmd::Add(NfListObject::Rule(rule)))
}

/// Generate the nftables add-rule commands for this lease.
/// These commands will open the port(s) for the IP address.
fn gen_add_lease_cmds<'a>(
    conf: &'a Config,
    names: &'a NftNames<'a>,
    lease: &'a Lease,
) -> ah::Result<Vec<NfCmd<'a>>> {
    let mut cmds = Vec::with_capacity(3);
    match lease.type_() {
        LeaseType::Port { port } => {
            let addr = lease.addr();
            assert!(addr.is_some());
            match port {
                LeasePort::Tcp(port) => {
                    let port = SingleLeasePort::Tcp(*port);
                    cmds.push(gen_add_port_lease_cmd(names, addr, port)?);
                }
                LeasePort::Udp(port) => {
                    let port = SingleLeasePort::Udp(*port);
                    cmds.push(gen_add_port_lease_cmd(names, addr, port)?);
                }
                LeasePort::TcpUdp(port) => {
                    let port_tcp = SingleLeasePort::Tcp(*port);
                    let port_udp = SingleLeasePort::Udp(*port);
                    cmds.push(gen_add_port_lease_cmd(names, addr, port_tcp)?);
                    cmds.push(gen_add_port_lease_cmd(names, addr, port_udp)?);
                }
            }
        }
        LeaseType::Jump {
            chain,
            target,
            match_saddr,
        } => {
            assert_eq!(*match_saddr, lease.addr().is_some());
            let chain = names.get_chain(*chain)?;
            cmds.push(gen_add_jump_cmd(names, chain, lease.addr(), target)?);
        }
    }
    if conf.debug() {
        println!("nftables: Adding rules for {lease}");
    }
    Ok(cmds)
}

/// Generate the nftables flush-chain command to delete the contents of a chain.
fn gen_flush_chain_cmd<'a>(names: &'a NftNames<'a>, chain: &'a str) -> ah::Result<NfCmd<'a>> {
    Ok(NfCmd::Flush(FlushObject::Chain(Chain {
        family: names.family,
        table: Cow::Borrowed(names.table),
        name: Cow::Borrowed(chain),
        ..Default::default()
    })))
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
        chain: &str,
        addr: Option<IpAddr>,
        port: Option<SingleLeasePort>,
        target: Option<&str>,
    ) -> ah::Result<u32> {
        let comment = gen_rule_comment(addr, port, target)?;
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
                        && *rule_chain == chain
                        && *rule_comment == comment =>
                    {
                        return Ok(*rule_handle);
                    }
                    _ => (),
                }
            }
        }
        Err(err!(
            "Nftables handle for {}/{}/{} not found in the kernel ruleset.",
            addr.map(|a| a.to_string()).unwrap_or_default(),
            port.map(|p| p.to_string()).unwrap_or_default(),
            target.unwrap_or_default()
        ))
    }

    /// Generate nftables delete-rules for this lease.
    /// These rules will close the ports for the IP address.
    pub fn gen_delete_lease_cmds<'a>(
        &self,
        conf: &'a Config,
        names: &'a NftNames,
        lease: &Lease,
    ) -> ah::Result<Vec<NfCmd<'a>>> {
        let addr = lease.addr();

        let new_rule = |chain: &'a str,
                        port: Option<SingleLeasePort>,
                        target: Option<&str>|
         -> ah::Result<NfCmd> {
            let mut rule = Rule {
                family: names.family,
                table: Cow::Borrowed(names.table),
                chain: Cow::Borrowed(chain),
                expr: Cow::Owned(vec![]),
                ..Default::default()
            };
            rule.handle =
                Some(self.find_handle(names.family, names.table, chain, addr, port, target)?);
            Ok(NfCmd::Delete(NfListObject::Rule(rule)))
        };

        let mut cmds = Vec::with_capacity(2);
        match lease.type_() {
            LeaseType::Port { port } => match port {
                LeasePort::Tcp(port) => {
                    let chain = names.get_chain_input()?;
                    cmds.push(new_rule(chain, Some(SingleLeasePort::Tcp(*port)), None)?);
                }
                LeasePort::Udp(port) => {
                    let chain = names.get_chain_input()?;
                    cmds.push(new_rule(chain, Some(SingleLeasePort::Udp(*port)), None)?);
                }
                LeasePort::TcpUdp(port) => {
                    let chain = names.get_chain_input()?;
                    cmds.push(new_rule(chain, Some(SingleLeasePort::Tcp(*port)), None)?);
                    cmds.push(new_rule(chain, Some(SingleLeasePort::Udp(*port)), None)?);
                }
            },
            LeaseType::Jump {
                chain,
                target,
                match_saddr,
            } => {
                assert_eq!(*match_saddr, lease.addr().is_some());
                let chain = names.get_chain(*chain)?;
                cmds.push(new_rule(chain, None, Some(target))?);
            }
        }
        if conf.debug() {
            println!("nftables: Deleting rules for {lease}");
        }
        Ok(cmds)
    }
}

struct NftFirewallInner {
    port_leases: PortLeaseMap,
    jump_leases: JumpLeaseMap,
    shutdown: bool,
    num_ctrl_rules: u8,
}

impl NftFirewallInner {
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
            port_leases: PortLeaseMap::new(),
            jump_leases: JumpLeaseMap::new(),
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
            for lease in self.port_leases.values() {
                count += match lease.type_() {
                    LeaseType::Port { port } => match port {
                        LeasePort::Tcp(_) | LeasePort::Udp(_) => 1,
                        LeasePort::TcpUdp(_) => 2,
                    },
                    _ => unreachable!(),
                };
            }
            for lease in self.jump_leases.values() {
                count += match lease.type_() {
                    LeaseType::Jump { .. } => 1,
                    _ => unreachable!(),
                }
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

        // Remove all rules from our chains.
        batch.add_cmd(gen_flush_chain_cmd(&names, names.chain_input)?);
        if let Some(chain_forward) = &names.chain_forward {
            batch.add_cmd(gen_flush_chain_cmd(&names, chain_forward)?);
        }
        if let Some(chain_output) = &names.chain_output {
            batch.add_cmd(gen_flush_chain_cmd(&names, chain_output)?);
        }
        if conf.debug() {
            println!("nftables: All chains flushed");
        }

        let mut num_ctrl_rules = 0;
        if !self.shutdown {
            // Open the port letmeind is listening on.
            if conf.port().tcp {
                let p = SingleLeasePort::Tcp(conf.port().port);
                batch.add_cmd(gen_add_port_lease_cmd(&names, None, p)?);
                if conf.debug() {
                    println!("nftables: Adding control port rule for port={p}");
                }
                num_ctrl_rules += 1;
            }
            if conf.port().udp {
                let p = SingleLeasePort::Udp(conf.port().port);
                batch.add_cmd(gen_add_port_lease_cmd(&names, None, p)?);
                if conf.debug() {
                    println!("nftables: Adding control port rule for port={p}");
                }
                num_ctrl_rules += 1;
            }

            // Open all lease ports, restricted to the peer addresses.
            for lease in self.port_leases.values().chain(self.jump_leases.values()) {
                for cmd in gen_add_lease_cmds(conf, &names, lease)? {
                    batch.add_cmd(cmd);
                }
            }
        }

        // Apply all batch commands to the kernel.
        self.nftables_apply_batch(conf, batch).await?;

        self.num_ctrl_rules = num_ctrl_rules;

        Ok(())
    }

    /// Generate one lease rule and apply it to the kernel.
    async fn nftables_add_lease(&mut self, conf: &Config, lease: &Lease) -> ah::Result<()> {
        let names = NftNames::get(conf).context("Read configuration")?;

        // Open the lease port, restricted to the peer address.
        let mut batch = Batch::new();
        for cmd in gen_add_lease_cmds(conf, &names, lease)? {
            batch.add_cmd(cmd);
        }

        // Apply all batch commands to the kernel.
        self.nftables_apply_batch(conf, batch).await
    }

    /// Remove an existing lease rule from the kernel.
    async fn nftables_remove_leases_no_rebuild(
        &mut self,
        conf: &Config,
        leases: &[Lease],
    ) -> ah::Result<()> {
        if !leases.is_empty() {
            let names = NftNames::get(conf).context("Read configuration")?;

            // Get the active ruleset from the kernel.
            let ruleset = ListedRuleset::from_kernel(conf).await?;

            // Add delete commands to remove the lease ports.
            let mut batch = Batch::new();
            for lease in leases {
                for cmd in ruleset.gen_delete_lease_cmds(conf, &names, lease)? {
                    batch.add_cmd(cmd);
                }
            }

            // Apply all batch commands to the kernel.
            self.nftables_apply_batch(conf, batch).await?;
        }
        Ok(())
    }

    /// Remove an existing lease rule from the kernel
    /// and rebuild the whole table on failure.
    async fn nftables_remove_leases(&mut self, conf: &Config, leases: &[Lease]) -> ah::Result<()> {
        if let Err(e) = self.nftables_remove_leases_no_rebuild(conf, leases).await {
            eprintln!("WARNING: Failed to remove lease(s): {e:?}");
            eprintln!("Trying full rebuild.");
            self.nftables_full_rebuild(conf).await?;
        }
        Ok(())
    }

    /// Remove all leases and remove all rules from the kernel.
    async fn shutdown(&mut self, conf: &Config) -> ah::Result<()> {
        assert!(!self.shutdown);

        self.shutdown = true;
        self.port_leases.clear();
        self.jump_leases.clear();
        self.nftables_full_rebuild(conf).await?;
        self.print_total_rule_count(conf);

        Ok(())
    }

    /// Run the periodic maintenance of the firewall.
    /// This will remove timed-out leases.
    async fn maintain(&mut self, conf: &Config) -> ah::Result<()> {
        assert!(!self.shutdown);

        let mut pruned = self.port_leases.prune_timeouts(conf);
        pruned.append(&mut self.jump_leases.prune_timeouts(conf));

        if !pruned.is_empty() {
            self.nftables_remove_leases(conf, &pruned).await?;
            self.print_total_rule_count(conf);
        }
        Ok(())
    }

    /// Add a lease and open the port for the specified IP address.
    /// If a lease for this port/address is already present, the timeout will be reset.
    /// Apply the rules to the kernel, if required.
    async fn open_port(
        &mut self,
        conf: &Config,
        remote_addr: IpAddr,
        port: LeasePort,
        timeout: Option<Duration>,
    ) -> ah::Result<()> {
        assert!(!self.shutdown);

        let key = (remote_addr, port);
        if let Some(lease) = self.port_leases.get_mut(&key) {
            lease.refresh_timeout(conf);
        } else {
            let lease = Lease::new_port(conf, remote_addr, port, timeout);
            self.nftables_add_lease(conf, &lease).await?;
            self.port_leases.insert(key, lease);
            self.print_total_rule_count(conf);
        }
        Ok(())
    }

    async fn revoke_port(
        &mut self,
        conf: &Config,
        remote_addr: IpAddr,
        port: LeasePort,
    ) -> ah::Result<()> {
        assert!(!self.shutdown);

        let key = (remote_addr, port);
        if let Some(lease) = self.port_leases.remove(&key) {
            if let Err(e) = self
                .nftables_remove_leases(conf, slice::from_ref(&lease))
                .await
            {
                // Removal from kernel failed. Add it back into our map.
                self.port_leases.insert(key, lease);
                return Err(e);
            }
            self.print_total_rule_count(conf);
        }
        Ok(())
    }

    async fn add_jump(
        &mut self,
        conf: &Config,
        remote_addr: IpAddr,
        targets: &FirewallJumpTargets,
        timeout: Option<Duration>,
    ) -> ah::Result<()> {
        assert!(!self.shutdown);

        let mut added = false;
        for (target_chain, match_saddr, chain) in &[
            (
                targets.input.as_ref(),
                targets.input_match_saddr,
                FirewallChain::Input,
            ),
            (
                targets.forward.as_ref(),
                targets.forward_match_saddr,
                FirewallChain::Forward,
            ),
            (
                targets.output.as_ref(),
                targets.output_match_saddr,
                FirewallChain::Output,
            ),
        ] {
            let Some(target_chain) = target_chain else {
                continue;
            };

            let addr = option_if(remote_addr, *match_saddr);
            let key = (addr, *chain, (**target_chain).clone());

            if let Some(lease) = self.jump_leases.get_mut(&key) {
                lease.refresh_timeout(conf);
            } else {
                let lease =
                    Lease::new_jump(conf, addr, *chain, target_chain, *match_saddr, timeout);
                self.nftables_add_lease(conf, &lease).await?;
                self.jump_leases.insert(key, lease);
                added = true;
            }
        }
        if added {
            self.print_total_rule_count(conf);
        }
        Ok(())
    }

    async fn revoke_jump(
        &mut self,
        conf: &Config,
        remote_addr: IpAddr,
        targets: &FirewallJumpTargets,
    ) -> ah::Result<()> {
        assert!(!self.shutdown);

        let mut removed = false;
        for (target_chain, match_saddr, chain) in &[
            (
                targets.input.as_ref(),
                targets.input_match_saddr,
                FirewallChain::Input,
            ),
            (
                targets.forward.as_ref(),
                targets.forward_match_saddr,
                FirewallChain::Forward,
            ),
            (
                targets.output.as_ref(),
                targets.output_match_saddr,
                FirewallChain::Output,
            ),
        ] {
            let Some(target_chain) = target_chain else {
                continue;
            };

            let addr = option_if(remote_addr, *match_saddr);
            let key = (addr, *chain, (**target_chain).clone());

            if let Some(lease) = self.jump_leases.remove(&key) {
                if let Err(e) = self
                    .nftables_remove_leases(conf, slice::from_ref(&lease))
                    .await
                {
                    // Removal from kernel failed. Add it back into our map.
                    self.jump_leases.insert(key, lease);
                    return Err(e);
                }
                removed = true;
            }
        }
        if removed {
            self.print_total_rule_count(conf);
        }
        Ok(())
    }
}

pub struct NftFirewall {
    inner: Mutex<NftFirewallInner>,
}

impl NftFirewall {
    /// Create a new firewall handler instance.
    /// This will also remove all rules from the kernel.
    pub async fn new(conf: &Config) -> ah::Result<Self> {
        Ok(Self {
            inner: Mutex::new(NftFirewallInner::new(conf).await?),
        })
    }
}

impl FirewallMaintain for NftFirewall {
    /// Remove all leases and remove all rules from the kernel.
    async fn shutdown(&self, conf: &Config) -> ah::Result<()> {
        self.inner.lock().await.shutdown(conf).await
    }

    /// Run the periodic maintenance of the firewall.
    /// This will remove timed-out leases.
    async fn maintain(&self, conf: &Config) -> ah::Result<()> {
        self.inner.lock().await.maintain(conf).await
    }
}

impl FirewallAction for NftFirewall {
    async fn open_port(
        &self,
        conf: &Config,
        remote_addr: IpAddr,
        port: LeasePort,
        timeout: Option<Duration>,
    ) -> ah::Result<()> {
        self.inner
            .lock()
            .await
            .open_port(conf, remote_addr, port, timeout)
            .await
    }

    async fn revoke_port(
        &self,
        conf: &Config,
        remote_addr: IpAddr,
        port: LeasePort,
    ) -> ah::Result<()> {
        self.inner
            .lock()
            .await
            .revoke_port(conf, remote_addr, port)
            .await
    }

    async fn add_jump(
        &self,
        conf: &Config,
        remote_addr: IpAddr,
        targets: &FirewallJumpTargets,
        timeout: Option<Duration>,
    ) -> ah::Result<()> {
        self.inner
            .lock()
            .await
            .add_jump(conf, remote_addr, targets, timeout)
            .await
    }

    async fn revoke_jump(
        &self,
        conf: &Config,
        remote_addr: IpAddr,
        targets: &FirewallJumpTargets,
    ) -> ah::Result<()> {
        self.inner
            .lock()
            .await
            .revoke_jump(conf, remote_addr, targets)
            .await
    }
}

// vim: ts=4 sw=4 expandtab
