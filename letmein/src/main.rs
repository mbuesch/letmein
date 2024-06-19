// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

mod client;
mod resolver;

use crate::{client::Client, resolver::ResMode};
use anyhow::{self as ah, format_err as err, Context as _};
use clap::{Parser, Subcommand};
use letmein_conf::{Config, ConfigVariant};
use letmein_proto::{secure_random, Key, Message, Operation};
use std::{path::Path, sync::Arc};

const CONF_PATH: &str = "/opt/letmein/etc/letmein.conf";

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

async fn run_knock(
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

async fn run_genkey(conf: Arc<Config>, user: Option<u32>) -> ah::Result<()> {
    let user = user.unwrap_or_else(|| conf.default_user());
    let key: Key = secure_random();
    let key: Vec<String> = key.iter().map(|b| format!("{b:02X}")).collect();
    let key: String = key.join("");
    println!("{user:08X} = {key}");
    Ok(())
}

#[derive(Parser, Debug)]
struct Opts {
    #[command(subcommand)]
    command: Command,
}

fn parse_hex(s: &str) -> ah::Result<u32> {
    Ok(u32::from_str_radix(s.trim(), 16)?)
}

#[derive(Subcommand, Debug)]
enum Command {
    Knock {
        /// The host name, IPv4 or IPv6 address that you want to knock on.
        host: String,

        /// The port on the remote host that you want to knock open.
        port: u16,

        /// The user identifier for authenticating the knock request.
        ///
        /// The user identifier is a 8 digits hex number.
        ///
        /// The authentication key associated with this user identifier
        /// will be fetched from the letmein.conf configuration file.
        ///
        /// If not given, then the `[CLIENT] default_user` from the
        /// configuration file will be used instead.
        /// If the configuration is not available, user 00000000 will
        /// be used instead.
        #[arg(short, long, value_parser = parse_hex)]
        user: Option<u32>,

        /// letmein server port number.
        ///
        /// You normally don't have to use this option.
        ///
        /// Set the letmein server port number to use when contacting the letmein server.
        ///
        /// If not given, then the `[GENERAL] port` from the
        /// letmein.conf configuration file will be used instead.
        /// If the configuration is not available, port 5800 will
        /// be used instead.
        #[arg(short = 'P', long)]
        server_port: Option<u16>,

        /// Resolve HOST into an IPv4 address.
        ///
        /// Resolve the HOST into an IPv4 address and knock on that address.
        ///
        /// If none of the --ipv4 and --ipv6 options are given,
        /// then knocking on both IPv4 and IPv6 is tried, but no error is
        /// shown, if one of them failed.
        ///
        /// If both of the --ipv4 and --ipv6 options are given,
        /// then knocking on both IPv4 and IPv6 is done and an error is shown,
        /// if any one fails.
        #[arg(short = '4', long)]
        ipv4: bool,

        /// Resolve HOST into an IPv6 address.
        ///
        /// Resolve the HOST into an IPv6 address and knock on that address.
        ///
        /// If none of the --ipv4 and --ipv6 options are given,
        /// then knocking on both IPv4 and IPv6 is tried, but no error is
        /// shown, if one of them failed.
        ///
        /// If both of the --ipv4 and --ipv6 options are given,
        /// then knocking on both IPv4 and IPv6 is done and an error is shown,
        /// if any one fails.
        #[arg(short = '6', long)]
        ipv6: bool,
    },
    GenKey {
        /// The user identifier (8 digits hex number) to use in the
        /// generated key string.
        /// If not given, then the `[CLIENT] default_user` from the
        /// configuration file will be used instead.
        /// If the configuration is not available, user 00000000 will
        /// be used instead.
        #[arg(long, short, value_parser = parse_hex)]
        user: Option<u32>,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ah::Result<()> {
    let opts = Opts::parse();

    let mut conf = Config::new(ConfigVariant::Client);
    conf.load(Path::new(CONF_PATH))
        .context("Configuration file")?;
    let conf = Arc::new(conf);

    match opts.command {
        Command::Knock {
            host,
            port,
            user,
            server_port,
            ipv4,
            ipv6,
        } => {
            run_knock(conf, &host, (ipv4, ipv6).into(), server_port, port, user).await?;
        }
        Command::GenKey { user } => run_genkey(conf, user).await?,
    }

    Ok(())
}

// vim: ts=4 sw=4 expandtab
