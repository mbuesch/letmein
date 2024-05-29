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
use letmein_conf::Config;
use letmein_proto::{secure_random, Key, Message, Operation, PORT};
use std::{net::IpAddr, path::Path, sync::Arc};

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
    addr: IpAddr,
    port: u16,
    user: Option<u32>,
) -> ah::Result<()> {
    let user = user.unwrap_or_else(|| conf.default_user());
    let Some(key) = conf.key(user) else {
        return Err(err!("No key found for user {user:X}"));
    };
    let Some(resource) = conf.resource_id_by_port(port) else {
        return Err(err!("Port {port} is not mapped to a resource"));
    };

    let mut client = Client::new(addr, PORT).await.context("Client init")?;

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

#[derive(Subcommand, Debug)]
enum Command {
    Knock {
        addr: IpAddr,
        port: u16,

        #[arg(long, short)]
        user: Option<u32>,
    },
    GenKey {
        #[arg(long, short)]
        user: Option<u32>,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ah::Result<()> {
    let opts = Opts::parse();
    let conf = Arc::new(Config::new(Path::new(CONF_PATH)).context("Configuration file")?);

    match opts.command {
        Command::Knock { addr, port, user } => run_knock(conf, addr, port, user).await?,
        Command::GenKey { user } => run_genkey(conf, user).await?,
    }

    Ok(())
}

// vim: ts=4 sw=4 expandtab
