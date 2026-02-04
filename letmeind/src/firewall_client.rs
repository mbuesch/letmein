// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, Context as _, format_err as err};
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
            FirewallOperation::Install | FirewallOperation::Revoke => {
                Err(err!("Received invalid reply"))
            }
        }
    }

    /// Send a request to install firewall rules for the specified `addr`.
    pub async fn install_rules(
        &mut self,
        user: UserId,
        resource: ResourceId,
        addr: IpAddr,
        conf_cs: &ConfigChecksum,
    ) -> ah::Result<()> {
        // Send an install-rules request to the firewall daemon.
        FirewallMessage::new_install(user, resource, addr, conf_cs)
            .send(&mut self.stream)
            .await
            .context("Send install-rules message")?;

        // Receive the acknowledge reply.
        self.recv_ack().await
    }

    /// Send a request to revoke firewall rules for the specified `addr`.
    pub async fn revoke_rules(
        &mut self,
        user: UserId,
        resource: ResourceId,
        addr: IpAddr,
        conf_cs: &ConfigChecksum,
    ) -> ah::Result<()> {
        // Send a revoke-rules request to the firewall daemon.
        FirewallMessage::new_revoke(user, resource, addr, conf_cs)
            .send(&mut self.stream)
            .await
            .context("Send revoke-rules message")?;

        // Receive the acknowledge reply.
        self.recv_ack().await
    }
}

// vim: ts=4 sw=4 expandtab
