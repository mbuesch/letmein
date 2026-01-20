// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    client::Client,
    resolver::{is_ipv4_addr, is_ipv6_addr, ResConf, ResCrypt, ResMode, ResSrv},
};
use anyhow::{self as ah, format_err as err, Context as _};
use letmein_conf::{Config, ControlPort};
use letmein_proto::{Key, Message, Operation, ResourceId, UserId};
use std::{path::Path, time::Duration};

/// Address types to knock.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum AddrMode {
    #[default]
    TryBoth,
    Both,
    Ipv6,
    Ipv4,
}

impl From<(bool, bool)> for AddrMode {
    fn from(ipv4_ipv6: (bool, bool)) -> Self {
        match ipv4_ipv6 {
            (false, false) => AddrMode::TryBoth,
            (true, true) => AddrMode::Both,
            (false, true) => AddrMode::Ipv6,
            (true, false) => AddrMode::Ipv4,
        }
    }
}

/// Knock protocol sequence - client side.
struct KnockSeq<'a> {
    pub initial_oper: Operation,
    pub verbose: bool,
    pub addr: &'a str,
    pub resolve_srv: &'a ResSrv,
    pub resolve_crypt: &'a ResCrypt,
    pub control_port: ControlPort,
    pub control_timeout: Duration,
    pub user: UserId,
    pub resource: ResourceId,
    pub key: &'a Key,
}

impl KnockSeq<'_> {
    /// Check if the server replied with a valid message.
    fn check_reply(&self, msg: &Message) -> ah::Result<()> {
        if msg.user() != self.user {
            eprintln!(
                "Warning: The server replied with a different user identifier. \
                 Expected {}, but received {}.",
                self.user,
                msg.user(),
            );
            // continue processing this message.
        }
        if msg.resource() != self.resource {
            eprintln!(
                "Warning: The server replied with a different resource identifier. \
                 Expected {}, but received {}.",
                self.resource,
                msg.resource(),
            );
            // continue processing this message.
        }
        Ok(())
    }

    /// Run the knock protocol sequence.
    pub async fn knock_sequence(
        &self,
        resolve_mode: ResMode,
        suppress_warnings: bool,
    ) -> ah::Result<()> {
        if self.verbose {
            println!(
                "Connecting to letmein server '{}:{}'.",
                self.addr, self.control_port
            );
        }
        let mut client = Client::new(
            self.addr,
            self.control_port,
            self.control_timeout,
            &ResConf {
                mode: resolve_mode,
                srv: self.resolve_srv.clone(),
                crypt: self.resolve_crypt.clone(),
                suppress_warnings,
            },
        )
        .await
        .context("Client init")?;

        if self.verbose {
            println!("Sending '{:?}' packet.", self.initial_oper);
        }
        let mut knock = Message::new(self.initial_oper, self.user, self.resource);
        knock.generate_auth_no_challenge(self.key);
        client.send_msg(knock).await.context("Send knock")?;

        if self.verbose {
            println!("Receiving '{:?}' packet.", Operation::Challenge);
        }
        let challenge = client.recv_specific_msg(Operation::Challenge).await?;
        self.check_reply(&challenge)?;

        if self.verbose {
            println!("Sending '{:?}' packet.", Operation::Response);
        }
        let mut response = Message::new(Operation::Response, self.user, self.resource);
        response.generate_auth(self.key, challenge);
        client.send_msg(response).await.context("Send response")?;

        if self.verbose {
            println!("Receiving '{:?}' packet.", Operation::ComeIn);
        }
        let comein = client.recv_specific_msg(Operation::ComeIn).await?;
        self.check_reply(&comein)?;

        if self.verbose {
            println!("Knock sequence successful.");
        }
        Ok(())
    }
}

pub struct KnockServer<'a> {
    pub addr: &'a str,
    pub addr_mode: AddrMode,
    pub port: Option<u16>,
    pub port_tcp: bool,
    pub port_udp: bool,
}

impl KnockServer<'_> {
    pub fn to_control_port(&self, conf: &Config) -> ControlPort {
        let mut control_port = conf.port();
        if let Some(server_port) = self.port {
            control_port.port = server_port;
        }
        if self.port_udp {
            control_port.tcp = false;
            control_port.udp = true;
        }
        if self.port_tcp {
            control_port.tcp = true;
            control_port.udp = false;
        }
        if control_port.tcp && control_port.udp {
            control_port.udp = false; // prefer TCP
        }
        control_port
    }
}

pub enum KnockResource {
    Resource(ResourceId),
    Port(u16),
}

#[allow(clippy::too_many_arguments)]
async fn run_knock_or_revoke(
    initial_oper: Operation,
    conf: &Config,
    verbose: bool,
    server: KnockServer<'_>,
    resource: KnockResource,
    user: Option<UserId>,
    resolve_srv: &ResSrv,
    resolve_crypt: &ResCrypt,
) -> ah::Result<()> {
    let confpath = conf.get_path().unwrap_or(Path::new(""));

    let user = user.unwrap_or_else(|| conf.default_user());
    let Some(key) = conf.key(user) else {
        return Err(err!(
            "No key found in {} for user {user}",
            confpath.display()
        ));
    };

    let resource = match resource {
        KnockResource::Resource(id) => id,
        KnockResource::Port(port) => {
            let Some(resource) = conf.resource_id_by_port(port, Some(user)) else {
                return Err(err!(
                    "Port {port} is not mapped to a port-resource in {}",
                    confpath.display()
                ));
            };
            resource
        }
    };

    let control_port = server.to_control_port(conf);

    let control_timeout = conf.control_timeout();

    let seq = KnockSeq {
        initial_oper,
        verbose,
        addr: server.addr,
        resolve_srv,
        resolve_crypt,
        control_port,
        control_timeout,
        user,
        resource,
        key,
    };

    match server.addr_mode {
        AddrMode::TryBoth => {
            if verbose {
                println!(
                    "Trying to knock on '{}:{resource}' IPv6 and IPv4.",
                    server.addr
                );
            }
            if is_ipv4_addr(server.addr) {
                // For a raw IPv4 address only knock IPv4.
                seq.knock_sequence(ResMode::Ipv4, false).await?;
            } else if is_ipv6_addr(server.addr) {
                // For a raw IPv6 address only knock IPv6.
                seq.knock_sequence(ResMode::Ipv6, false).await?;
            } else {
                // For host names try both.
                let res6 = seq.knock_sequence(ResMode::Ipv6, true).await;
                let res4 = seq.knock_sequence(ResMode::Ipv4, res6.is_ok()).await;
                if res6.is_err() && res4.is_err() {
                    return res6;
                }
            }
        }
        AddrMode::Both => {
            if verbose {
                println!("Knocking on '{}:{resource}' IPv6 and IPv4.", server.addr);
            }
            seq.knock_sequence(ResMode::Ipv6, false).await?;
            seq.knock_sequence(ResMode::Ipv4, false).await?;
        }
        AddrMode::Ipv6 => {
            if verbose {
                println!("Knocking on '{}:{resource}' IPv6.", server.addr);
            }
            seq.knock_sequence(ResMode::Ipv6, false).await?;
        }
        AddrMode::Ipv4 => {
            if verbose {
                println!("Knocking on '{}:{resource}' IPv4.", server.addr);
            }
            seq.knock_sequence(ResMode::Ipv4, false).await?;
        }
    }
    Ok(())
}

/// Run the `knock` command.
pub async fn run_knock(
    conf: &Config,
    verbose: bool,
    server: KnockServer<'_>,
    resource: KnockResource,
    user: Option<UserId>,
    resolve_srv: &ResSrv,
    resolve_crypt: &ResCrypt,
) -> ah::Result<()> {
    run_knock_or_revoke(
        Operation::Knock,
        conf,
        verbose,
        server,
        resource,
        user,
        resolve_srv,
        resolve_crypt,
    )
    .await
}

/// Run the `revoke` command.
pub async fn run_revoke(
    conf: &Config,
    verbose: bool,
    server: KnockServer<'_>,
    resource: KnockResource,
    user: Option<UserId>,
    resolve_srv: &ResSrv,
    resolve_crypt: &ResCrypt,
) -> ah::Result<()> {
    run_knock_or_revoke(
        Operation::Revoke,
        conf,
        verbose,
        server,
        resource,
        user,
        resolve_srv,
        resolve_crypt,
    )
    .await
}

// vim: ts=4 sw=4 expandtab
