// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{client::Client, resolver::ResMode};
use anyhow::{self as ah, format_err as err, Context as _};
use letmein_conf::Config;
use letmein_proto::{Key, Message, Operation};
use std::sync::Arc;

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

struct KnockSeq<'a> {
    pub verbose: bool,
    pub addr: &'a str,
    pub server_port: u16,
    pub user: u32,
    pub resource: u32,
    pub key: &'a Key,
}

impl<'a> KnockSeq<'a> {
    pub async fn knock_sequence(&self, resolver_mode: ResMode) -> ah::Result<()> {
        if self.verbose {
            println!(
                "Connecting to letmein server '{}:{}'.",
                self.addr, self.server_port
            );
        }
        let mut client = Client::new(self.addr, self.server_port, resolver_mode)
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

        if self.verbose {
            println!("Sending 'Response' packet.");
        }
        let mut response = Message::new(Operation::Response, self.user, self.resource);
        response.generate_auth(self.key, challenge);
        client.send_msg(response).await.context("Send response")?;

        if self.verbose {
            println!("Receiving 'ComeIn' packet.");
        }
        let _ = client.recv_specific_msg(Operation::ComeIn).await?;

        if self.verbose {
            println!("Knock sequence successful.");
        }
        Ok(())
    }
}

pub async fn run_knock(
    conf: Arc<Config>,
    verbose: bool,
    addr: &str,
    addr_mode: AddrMode,
    server_port: Option<u16>,
    knock_port: u16,
    user: Option<u32>,
) -> ah::Result<()> {
    let user = user.unwrap_or_else(|| conf.default_user());
    let Some(key) = conf.key(user) else {
        return Err(err!("No key found in letmein.conf for user {user:08X}"));
    };
    let Some(resource) = conf.resource_id_by_port(knock_port) else {
        return Err(err!(
            "Port {knock_port} is not mapped to a resource in letmein.conf"
        ));
    };
    let server_port = server_port.unwrap_or_else(|| conf.port());

    let seq = KnockSeq {
        verbose,
        addr,
        server_port,
        user,
        resource,
        key,
    };

    match addr_mode {
        AddrMode::TryBoth => {
            if verbose {
                println!("Trying to knock on '{addr}:{knock_port}' IPv6 and IPv4.");
            }
            let res6 = seq.knock_sequence(ResMode::Ipv6).await;
            let res4 = seq.knock_sequence(ResMode::Ipv4).await;
            if res6.is_err() && res4.is_err() {
                return res6;
            }
        }
        AddrMode::Both => {
            if verbose {
                println!("Knocking on '{addr}:{knock_port}' IPv6 and IPv4.");
            }
            seq.knock_sequence(ResMode::Ipv6).await?;
            seq.knock_sequence(ResMode::Ipv4).await?;
        }
        AddrMode::Ipv6 => {
            if verbose {
                println!("Knocking on '{addr}:{knock_port}' IPv6.");
            }
            seq.knock_sequence(ResMode::Ipv6).await?;
        }
        AddrMode::Ipv4 => {
            if verbose {
                println!("Knocking on '{addr}:{knock_port}' IPv4.");
            }
            seq.knock_sequence(ResMode::Ipv4).await?;
        }
    }
    Ok(())
}

// vim: ts=4 sw=4 expandtab
