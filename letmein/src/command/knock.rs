// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    client::Client,
    resolver::{is_ipv4_addr, is_ipv6_addr, ResMode},
};
use anyhow::{self as ah, format_err as err, Context as _};
use letmein_conf::Config;
use letmein_proto::{Key, Message, Operation, ResourceId, UserId};
use std::{path::Path, sync::Arc, time::Duration};

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
    pub verbose: bool,
    pub addr: &'a str,
    pub server_port: u16,
    pub control_timeout: Duration,
    pub user: UserId,
    pub resource: ResourceId,
    pub key: &'a Key,
}

impl<'a> KnockSeq<'a> {
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
    pub async fn knock_sequence(&self, resolver_mode: ResMode) -> ah::Result<()> {
        if self.verbose {
            println!(
                "Connecting to letmein server '{}:{}'.",
                self.addr, self.server_port
            );
        }
        let mut client = Client::new(
            self.addr,
            self.server_port,
            self.control_timeout,
            resolver_mode,
        )
        .await
        .context("Client init")?;

        if self.verbose {
            println!("Sending 'Knock' packet.");
        }
        let mut knock = Message::new(Operation::Knock, self.user, self.resource);
        knock.generate_auth_no_challenge(self.key);
        client.send_msg(knock).await.context("Send knock")?;

        if self.verbose {
            println!("Receiving 'Challenge' packet.");
        }
        let challenge = client.recv_specific_msg(Operation::Challenge).await?;
        self.check_reply(&challenge)?;

        if self.verbose {
            println!("Sending 'Response' packet.");
        }
        let mut response = Message::new(Operation::Response, self.user, self.resource);
        response.generate_auth(self.key, challenge);
        client.send_msg(response).await.context("Send response")?;

        if self.verbose {
            println!("Receiving 'ComeIn' packet.");
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
}

/// Run the `knock` command.
pub async fn run_knock(
    conf: Arc<Config>,
    verbose: bool,
    server: KnockServer<'_>,
    knock_port: u16,
    user: Option<UserId>,
) -> ah::Result<()> {
    let confpath = conf.get_path().unwrap_or(Path::new(""));
    let user = user.unwrap_or_else(|| conf.default_user());
    let Some(key) = conf.key(user) else {
        return Err(err!("No key found in {confpath:?} for user {user}"));
    };
    let Some(resource) = conf.resource_id_by_port(knock_port, Some(user)) else {
        return Err(err!(
            "Port {knock_port} is not mapped to a resource in {confpath:?}"
        ));
    };
    let server_port = server.port.unwrap_or_else(|| conf.port());
    let control_timeout = conf.control_timeout();

    let seq = KnockSeq {
        verbose,
        addr: server.addr,
        server_port,
        control_timeout,
        user,
        resource,
        key,
    };

    match server.addr_mode {
        AddrMode::TryBoth => {
            if verbose {
                println!(
                    "Trying to knock on '{}:{knock_port}' IPv6 and IPv4.",
                    server.addr
                );
            }
            if is_ipv4_addr(server.addr) {
                // For a raw IPv4 address only knock IPv4.
                seq.knock_sequence(ResMode::Ipv4).await?;
            } else if is_ipv6_addr(server.addr) {
                // For a raw IPv6 address only knock IPv6.
                seq.knock_sequence(ResMode::Ipv6).await?;
            } else {
                // For host names try both.
                let res6 = seq.knock_sequence(ResMode::Ipv6).await;
                let res4 = seq.knock_sequence(ResMode::Ipv4).await;
                if res6.is_err() && res4.is_err() {
                    return res6;
                }
            }
        }
        AddrMode::Both => {
            if verbose {
                println!("Knocking on '{}:{knock_port}' IPv6 and IPv4.", server.addr);
            }
            seq.knock_sequence(ResMode::Ipv6).await?;
            seq.knock_sequence(ResMode::Ipv4).await?;
        }
        AddrMode::Ipv6 => {
            if verbose {
                println!("Knocking on '{}:{knock_port}' IPv6.", server.addr);
            }
            seq.knock_sequence(ResMode::Ipv6).await?;
        }
        AddrMode::Ipv4 => {
            if verbose {
                println!("Knocking on '{}:{knock_port}' IPv4.", server.addr);
            }
            seq.knock_sequence(ResMode::Ipv4).await?;
        }
    }
    Ok(())
}

// vim: ts=4 sw=4 expandtab
