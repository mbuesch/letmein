// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, format_err as err, Context as _};
use letmein_conf::ConfigChecksum;
use letmein_fwproto::{FirewallMessage, FirewallOperation, SOCK_FILE};
use letmein_proto::{ResourceId, UserId};
use std::{net::IpAddr, path::Path};
use tokio::net::UnixStream;

pub struct FirewallClient {
    stream: UnixStream,
}

impl FirewallClient {
    /// Connect to the firewall daemon via Unix socket.
    pub async fn new(rundir: &Path) -> ah::Result<Self> {
        let sock_path = rundir.join("letmeinfwd").join(SOCK_FILE);
        let stream = UnixStream::connect(sock_path)
            .await
            .context("Connect to Unix socket")?;
        Ok(Self { stream })
    }

    /// Receive an Ack message.
    async fn recv_ack(&mut self) -> ah::Result<()> {
        let Some(msg_reply) = FirewallMessage::recv(&mut self.stream)
            .await
            .context("Receive ack-reply")?
        else {
            return Err(err!("Connection terminated"));
        };

        match msg_reply.operation() {
            FirewallOperation::Ack => Ok(()),
            FirewallOperation::Nack => Err(err!("The firewall rejected the request")),
            FirewallOperation::Open | FirewallOperation::Jump => {
                Err(err!("Received invalid reply"))
            }
        }
    }

    /// Send a request to open a firewall `port` for the specified `addr`.
    pub async fn open_port(
        &mut self,
        user: UserId,
        resource: ResourceId,
        addr: IpAddr,
        conf_cs: &ConfigChecksum,
    ) -> ah::Result<()> {
        // Send an open-port request to the firewall daemon.
        FirewallMessage::new_open(user, resource, addr, conf_cs)
            .send(&mut self.stream)
            .await
            .context("Send port-open message")?;

        // Receive the acknowledge reply.
        self.recv_ack().await
    }

    /// Send a request to add a firewall "jump" rule.
    pub async fn jump(
        &mut self,
        user: UserId,
        resource: ResourceId,
        addr: IpAddr,
        conf_cs: &ConfigChecksum,
    ) -> ah::Result<()> {
        // Send an add-jump request to the firewall daemon.
        FirewallMessage::new_jump(user, resource, addr, conf_cs)
            .send(&mut self.stream)
            .await
            .context("Send add-jump message")?;

        // Receive the acknowledge reply.
        self.recv_ack().await
    }
}

// vim: ts=4 sw=4 expandtab
