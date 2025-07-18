// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{firewall_client::FirewallClient, server::ConnectionOps};
use anyhow::{self as ah, format_err as err};
use letmein_conf::{Config, ErrorPolicy, Resource};
use letmein_proto::{Message, Operation, ResourceId, UserId};
use std::path::Path;
use tokio::time::timeout;

/// Protocol authentication state.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
#[allow(clippy::enum_variant_names)]
enum AuthState {
    /// Not authenticated.
    NotAuth,

    /// Basic (not replay-safe) authentication passed.
    BasicAuth,

    /// Full challenge-response authentication passed.
    ChallengeResponseAuth,
}

/// Implementation of the wire protocol message sequence.
pub struct Protocol<'a, C> {
    conn: &'a C,
    conf: &'a Config,
    rundir: &'a Path,
    user_id: Option<UserId>,
    resource_id: Option<ResourceId>,
    auth_state: AuthState,
}

impl<'a, C: ConnectionOps> Protocol<'a, C> {
    pub fn new(conn: &'a C, conf: &'a Config, rundir: &'a Path) -> Self {
        Self {
            conn,
            conf,
            rundir,
            user_id: None,
            resource_id: None,
            auth_state: AuthState::NotAuth,
        }
    }

    async fn recv_msg(&mut self, expect_operation: Operation) -> ah::Result<Message> {
        if let Some(msg) = timeout(self.conf.control_timeout(), self.conn.recv_msg())
            .await
            .map_err(|_| err!("RX communication with peer timed out"))??
        {
            if msg.operation() != expect_operation {
                let _ = self.send_go_away().await;
                return Err(err!(
                    "Invalid reply message operation. Expected {:?}, got {:?}",
                    expect_operation,
                    msg.operation()
                ));
            }
            if let Some(user_id) = self.user_id {
                if msg.user() != user_id {
                    let _ = self.send_go_away().await;
                    return Err(err!("Received message user mismatch"));
                }
            }
            if let Some(resource_id) = self.resource_id {
                if msg.resource() != resource_id {
                    let _ = self.send_go_away().await;
                    return Err(err!("Received message resource mismatch"));
                }
            }
            Ok(msg)
        } else {
            Err(err!("Disconnected."))
        }
    }

    async fn send_msg(&mut self, msg: &Message) -> ah::Result<()> {
        timeout(self.conf.control_timeout(), self.conn.send_msg(msg))
            .await
            .map_err(|_| err!("TX communication with peer timed out"))?
    }

    async fn send_go_away(&mut self) -> ah::Result<()> {
        // Check if we are allowed to send the error message.
        match self.conf.control_error_policy() {
            ErrorPolicy::Always => (),
            ErrorPolicy::BasicAuth => {
                if self.auth_state != AuthState::BasicAuth
                    && self.auth_state != AuthState::ChallengeResponseAuth
                {
                    return Ok(());
                }
            }
            ErrorPolicy::FullAuth => {
                if self.auth_state != AuthState::ChallengeResponseAuth {
                    return Ok(());
                }
            }
        }

        // Send the error message.
        self.send_msg(&Message::new(
            Operation::GoAway,
            self.user_id.unwrap_or(u32::MAX.into()),
            self.resource_id.unwrap_or(u32::MAX.into()),
        ))
        .await
    }

    async fn connect_to_fw(&mut self) -> ah::Result<FirewallClient> {
        assert_eq!(self.auth_state, AuthState::ChallengeResponseAuth);
        match FirewallClient::new(self.rundir).await {
            Err(e) => {
                let _ = self.send_go_away().await;
                Err(err!("Failed to connect to letmeinfwd: {e}"))
            }
            Ok(fw) => Ok(fw),
        }
    }

    pub async fn run(&mut self) -> ah::Result<()> {
        self.user_id = None;
        self.resource_id = None;
        self.auth_state = AuthState::NotAuth;

        // Receive the initial knock message.
        let knock = self.recv_msg(Operation::Knock).await?;

        let user_id = knock.user();
        self.user_id = Some(user_id);

        let resource_id = knock.resource();
        self.resource_id = Some(resource_id);

        // Get the shared key.
        let Some(key) = self.conf.key(user_id) else {
            let _ = self.send_go_away().await;
            return Err(err!("Unknown user: {user_id}"));
        };

        // Authenticate the received message.
        // This check is not replay-safe. But that's fine.
        if !knock.check_auth_ok_no_challenge(key) {
            let _ = self.send_go_away().await;
            return Err(err!("Knock: Authentication failed"));
        }
        self.auth_state = AuthState::BasicAuth;

        // Get the requested resource from the configuration.
        let Some(resource) = self.conf.resource(resource_id) else {
            let _ = self.send_go_away().await;
            return Err(err!("Unknown resource: {resource_id}"));
        };

        // Check if the authenticating user is allowed to access this resource.
        if !resource.contains_user(user_id) {
            let _ = self.send_go_away().await;
            return Err(err!(
                "Resource {resource_id} not allowed for user {user_id}"
            ));
        }

        // Check if trying to knock the control port.
        match resource {
            Resource::Port { port, .. } => {
                // The control port is never allowed.
                let control_port = self.conf.port().port;
                if *port == control_port {
                    let _ = self.send_go_away().await;
                    return Err(err!(
                        "Incorrect configuration: The resource {resource_id} uses the \
                         letmein control port {control_port}. That is not allowed."
                    ));
                }
            }
        }

        // Generate and send a challenge.
        let mut challenge = Message::new(Operation::Challenge, user_id, resource_id);
        challenge.generate_challenge();
        self.send_msg(&challenge).await?;

        // Receive the response.
        let response = self.recv_msg(Operation::Response).await?;

        // Authenticate the challenge-response.
        if !response.check_auth_ok(key, challenge) {
            let _ = self.send_go_away().await;
            return Err(err!("Response: Authentication failed"));
        }
        self.auth_state = AuthState::ChallengeResponseAuth;

        // Reconfigure the firewall.
        match resource {
            Resource::Port { .. } => {
                // Send an open-port request to letmeinfwd.
                if let Err(e) = self
                    .connect_to_fw()
                    .await?
                    .open_port(
                        user_id,
                        resource_id,
                        self.conn.peer_addr().ip(),
                        self.conf.checksum(),
                    )
                    .await
                {
                    let _ = self.send_go_away().await;
                    return Err(err!("letmeinfwd firewall open: {e}"));
                }
            }
        }

        // Send a come-in message.
        let comein = Message::new(Operation::ComeIn, user_id, resource_id);
        self.send_msg(&comein).await?;

        Ok(())
    }
}

// vim: ts=4 sw=4 expandtab
