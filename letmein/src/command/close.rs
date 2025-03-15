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
use letmein_conf::{Config, ControlPort};
use letmein_proto::{Key, Message, Operation, ResourceId, UserId};
use std::{path::Path, sync::Arc, time::Duration};

/// Close protocol sequence - client side.
struct CloseSeq<'a> {
    pub verbose: bool,
    pub addr: &'a str,
    pub control_port: ControlPort,
    pub control_timeout: Duration,
    pub user: UserId,
    pub resource: ResourceId,
    pub key: &'a Key,
}

impl CloseSeq<'_> {
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

    /// Run the close protocol sequence.
    pub async fn close_sequence(&self, resolver_mode: ResMode) -> ah::Result<()> {
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
            resolver_mode,
        )
        .await
        .context("Client init")?;

        if self.verbose {
            println!("Sending 'Close' packet.");
        }
        let mut close = Message::new(Operation::Close, self.user, self.resource);
        close.generate_auth_no_challenge(self.key);
        client.send_msg(close).await.context("Send close")?;

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
            println!("Close sequence successful.");
        }
        Ok(())
    }
}

pub struct CloseServer<'a> {
    pub addr: &'a str,
    pub addr_mode: super::knock::AddrMode,
    pub port: Option<u16>,
    pub port_tcp: bool,
    pub port_udp: bool,
}

impl CloseServer<'_> {
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

/// Run the `close` command.
pub async fn run_close(
    conf: Arc<Config>,
    verbose: bool,
    server: CloseServer<'_>,
    close_port: u16,
    user: Option<UserId>,
) -> ah::Result<()> {
    let confpath = conf.get_path().unwrap_or(Path::new(""));

    let user = user.unwrap_or_else(|| conf.default_user());
    let Some(key) = conf.key(user) else {
        return Err(err!("No key found in {confpath:?} for user {user}"));
    };
    let Some(resource) = conf.resource_id_by_port(close_port, Some(user)) else {
        return Err(err!(
            "Port {close_port} is not mapped to a resource in {confpath:?}"
        ));
    };

    let control_port = server.to_control_port(&conf);

    let control_timeout = conf.control_timeout();

    let seq = CloseSeq {
        verbose,
        addr: server.addr,
        control_port,
        control_timeout,
        user,
        resource,
        key,
    };

    match server.addr_mode {
        super::knock::AddrMode::TryBoth => {
            if verbose {
                println!(
                    "Trying to close port {close_port} on '{}' IPv6 and IPv4.",
                    server.addr
                );
            }
            if is_ipv4_addr(server.addr) {
                // For a raw IPv4 address only close IPv4.
                seq.close_sequence(ResMode::Ipv4).await?;
            } else if is_ipv6_addr(server.addr) {
                // For a raw IPv6 address only close IPv6.
                seq.close_sequence(ResMode::Ipv6).await?;
            } else {
                // For a hostname try IPv6 first, then IPv4.
                match seq.close_sequence(ResMode::Ipv6).await {
                    Ok(()) => {}
                    Err(e) => {
                        if verbose {
                            eprintln!("IPv6 close failed: {e}");
                            println!("Trying IPv4...");
                        }
                        seq.close_sequence(ResMode::Ipv4).await?;
                    }
                }
            }
        }
        super::knock::AddrMode::Both => {
            if verbose {
                println!(
                    "Closing port {close_port} on '{}' IPv6 and IPv4.",
                    server.addr
                );
            }
            seq.close_sequence(ResMode::Ipv6).await?;
            seq.close_sequence(ResMode::Ipv4).await?;
        }
        super::knock::AddrMode::Ipv6 => {
            if verbose {
                println!(
                    "Closing port {close_port} on '{}' IPv6.",
                    server.addr
                );
            }
            seq.close_sequence(ResMode::Ipv6).await?;
        }
        super::knock::AddrMode::Ipv4 => {
            if verbose {
                println!(
                    "Closing port {close_port} on '{}' IPv4.",
                    server.addr
                );
            }
            seq.close_sequence(ResMode::Ipv4).await?;
        }
    }

    Ok(())
}
