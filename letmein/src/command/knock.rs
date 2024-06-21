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

async fn knock_seq(
    addr: &str,
    server_port: u16,
    resolver_mode: ResMode,
    user: u32,
    resource: u32,
    key: &Key,
) -> ah::Result<()> {
    let mut client = Client::new(addr, server_port, resolver_mode)
        .await
        .context("Client init")?;

    let mut knock = Message::new(Operation::Knock, user, resource);
    knock.generate_auth_no_challenge(key);
    client.send_msg(knock).await.context("Send knock")?;

    let challenge = client.recv_specific_msg(Operation::Challenge).await?;

    let mut response = Message::new(Operation::Response, user, resource);
    response.generate_auth(key, challenge);
    client.send_msg(response).await.context("Send response")?;

    let _ = client.recv_specific_msg(Operation::ComeIn).await?;

    Ok(())
}

pub async fn run_knock(
    conf: Arc<Config>,
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

    match addr_mode {
        AddrMode::TryBoth => {
            let res6 = knock_seq(addr, server_port, ResMode::Ipv6, user, resource, key).await;
            let res4 = knock_seq(addr, server_port, ResMode::Ipv4, user, resource, key).await;
            if res6.is_err() && res4.is_err() {
                return res6;
            }
        }
        AddrMode::Both => {
            knock_seq(addr, server_port, ResMode::Ipv6, user, resource, key).await?;
            knock_seq(addr, server_port, ResMode::Ipv4, user, resource, key).await?;
        }
        AddrMode::Ipv6 => {
            knock_seq(addr, server_port, ResMode::Ipv6, user, resource, key).await?;
        }
        AddrMode::Ipv4 => {
            knock_seq(addr, server_port, ResMode::Ipv4, user, resource, key).await?;
        }
    }
    Ok(())
}

// vim: ts=4 sw=4 expandtab
