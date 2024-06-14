// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

mod client;

use crate::client::Client;
use anyhow::{self as ah, format_err as err, Context as _};
use clap::{Parser, Subcommand};
use letmein_conf::{Config, ConfigVariant};
use letmein_proto::{secure_random, Key, Message, Operation};
use std::{path::Path, sync::Arc};

const CONF_PATH: &str = "/opt/letmein/etc/letmein.conf";

async fn recv_msg(client: &mut Client, expect_operation: Operation) -> ah::Result<Message> {
    let reply = client.recv_msg().await.context("Receive knock reply")?;
    let Some(reply) = reply else {
        return Err(err!("Connection terminated"));
    };
    if reply.operation() == Operation::GoAway {
        return Err(err!("The server rejected the request"));
    }
    if reply.operation() != expect_operation {
        return Err(err!(
            "Invalid reply message operation. Expected {:?}, got {:?}",
            expect_operation,
            reply.operation()
        ));
    }
    Ok(reply)
}

async fn run_knock(
    conf: Arc<Config>,
    addr: &str,
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

    let mut client = Client::new(addr, server_port.unwrap_or_else(|| conf.port()))
        .await
        .context("Client init")?;

    let mut knock = Message::new(Operation::Knock, user, resource);
    knock.generate_auth_no_challenge(key);
    client.send_msg(knock).await.context("Send knock")?;

    let challenge = recv_msg(&mut client, Operation::Challenge).await?;

    let mut response = Message::new(Operation::Response, user, resource);
    response.generate_auth(key, challenge);
    client.send_msg(response).await.context("Send response")?;

    let _ = recv_msg(&mut client, Operation::ComeIn).await?;

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

        /// The user identifier (8 digits hex number) to use for
        /// authenticating this knock request.
        /// The authentication key associated with this user identifier
        /// will be fetched from the letmein.conf configuration file.
        /// If not given, then the `[CLIENT] default_user` from the
        /// configuration file will be used instead.
        /// If the configuration is not available, user 00000000 will
        /// be used instead.
        #[arg(long, short, value_parser = parse_hex)]
        user: Option<u32>,

        /// You normally don't have to use this option.
        /// Set the letmein server port number to use when contacting the letmein server.
        /// If not given, then the `[GENERAL] port` from the
        /// letmein.conf configuration file will be used instead.
        /// If the configuration is not available, port 5800 will
        /// be used instead.
        #[arg(long)]
        server_port: Option<u16>,
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
        } => run_knock(conf, &host, server_port, port, user).await?,
        Command::GenKey { user } => run_genkey(conf, user).await?,
    }

    Ok(())
}

// vim: ts=4 sw=4 expandtab
