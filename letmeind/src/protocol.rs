// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
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

    async fn recv_msg(&mut self, expect_operation: &[Operation]) -> ah::Result<Message> {
        if let Some(msg) = timeout(self.conf.control_timeout(), self.conn.recv_msg())
            .await
            .map_err(|_| err!("RX communication with peer timed out"))??
        {
            if !expect_operation.contains(&msg.operation()) {
                return self
                    .send_go_away(Err(err!(
                        "Invalid reply message operation. Expected {:?}, got {:?}",
                        expect_operation,
                        msg.operation()
                    )))
                    .await;
            }
            if let Some(user_id) = self.user_id {
                if msg.user() != user_id {
                    return self
                        .send_go_away(Err(err!("Received message user mismatch")))
                        .await;
                }
            }
            if let Some(resource_id) = self.resource_id {
                if msg.resource() != resource_id {
                    return self
                        .send_go_away(Err(err!("Received message resource mismatch")))
                        .await;
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

    async fn send_go_away<T>(&mut self, res: ah::Result<T>) -> ah::Result<T> {
        // Check if we are allowed to send the error message.
        let reply_allowed = match self.conf.control_error_policy() {
            ErrorPolicy::Always => true,
            ErrorPolicy::BasicAuth => {
                self.auth_state == AuthState::BasicAuth
                    || self.auth_state == AuthState::ChallengeResponseAuth
            }
            ErrorPolicy::FullAuth => self.auth_state == AuthState::ChallengeResponseAuth,
        };

        if reply_allowed {
            // Send the error message.
            if let Err(e) = self
                .send_msg(&Message::new(
                    Operation::GoAway,
                    self.user_id.unwrap_or(u32::MAX.into()),
                    self.resource_id.unwrap_or(u32::MAX.into()),
                ))
                .await
            {
                // Only print a log message and ignore the error.
                eprintln!("Failed to send GoAway reply: {e}");
            }
        }

        res
    }

    async fn connect_to_fw(&mut self) -> ah::Result<FirewallClient> {
        assert_eq!(self.auth_state, AuthState::ChallengeResponseAuth);
        match FirewallClient::new(self.rundir).await {
            Err(e) => {
                return self
                    .send_go_away(Err(err!("Failed to connect to letmeinfwd: {e}")))
                    .await;
            }
            Ok(fw) => Ok(fw),
        }
    }

    pub async fn run(&mut self) -> ah::Result<()> {
        self.user_id = None;
        self.resource_id = None;
        self.auth_state = AuthState::NotAuth;

        // Receive the initial knock/revoke message.
        let initial_message = self
            .recv_msg(&[Operation::Knock, Operation::Revoke])
            .await?;

        let initial_operation = initial_message.operation();

        let user_id = initial_message.user();
        self.user_id = Some(user_id);

        let resource_id = initial_message.resource();
        self.resource_id = Some(resource_id);

        // Get the shared key.
        let Some(key) = self.conf.key(user_id) else {
            return self
                .send_go_away(Err(err!("Unknown user: {user_id}")))
                .await;
        };

        // Authenticate the received message.
        // This check is not replay-safe. But that's fine.
        if !initial_message.check_auth_ok_no_challenge(key) {
            return self
                .send_go_away(Err(err!("Knock: Authentication failed")))
                .await;
        }
        self.auth_state = AuthState::BasicAuth;

        // Get the requested resource from the configuration.
        let Some(resource) = self.conf.resource(resource_id) else {
            return self
                .send_go_away(Err(err!("Unknown resource: {resource_id}")))
                .await;
        };

        // Check if the authenticating user is allowed to access this resource.
        if !resource.contains_user(user_id) {
            return self
                .send_go_away(Err(err!(
                    "Resource {resource_id} not allowed for user {user_id}"
                )))
                .await;
        }

        // Check if trying to knock/revoke the control port.
        match resource {
            Resource::Port { port, .. } => {
                // The control port is never allowed.
                let control_port = self.conf.port().port;
                if *port == control_port {
                    return self
                        .send_go_away(Err(err!(
                            "Incorrect configuration: The resource {resource_id} uses the \
                         letmein control port {control_port}. That is not allowed."
                        )))
                        .await;
                }
            }
            Resource::Jump { .. } => (),
        }

        // Generate and send a challenge.
        let mut challenge = Message::new(Operation::Challenge, user_id, resource_id);
        challenge.generate_challenge();
        self.send_msg(&challenge).await?;

        // Receive the response.
        let response = self.recv_msg(&[Operation::Response]).await?;

        // Authenticate the challenge-response.
        if !response.check_auth_ok(key, challenge) {
            return self
                .send_go_away(Err(err!("Response: Authentication failed")))
                .await;
        }
        self.auth_state = AuthState::ChallengeResponseAuth;

        // Reconfigure the firewall.
        let peer_ip_addr = self.conn.peer_addr().ip();
        let conf_checksum = self.conf.checksum();
        let ret = match initial_operation {
            Operation::Knock => {
                // Send an install-rules request to letmeinfwd.
                self.connect_to_fw()
                    .await?
                    .install_rules(user_id, resource_id, peer_ip_addr, conf_checksum)
                    .await
            }
            Operation::Revoke => {
                // Send an revoke-rules request to letmeinfwd.
                self.connect_to_fw()
                    .await?
                    .revoke_rules(user_id, resource_id, peer_ip_addr, conf_checksum)
                    .await
            }
            Operation::Challenge | Operation::Response | Operation::ComeIn | Operation::GoAway => {
                unreachable!()
            }
        };
        if let Err(e) = ret {
            return self
                .send_go_away(Err(err!("letmeinfwd firewall: {e}")))
                .await;
        }

        let logaction = if initial_operation == Operation::Knock {
            "knocked"
        } else {
            "revoked"
        };
        println!(
            "[{peer_ip_addr}]: Resource {resource_id} successfully {logaction}. \
             Firewall rules changed.",
        );

        // Send a come-in message.
        let comein = Message::new(Operation::ComeIn, user_id, resource_id);
        self.send_msg(&comein).await?;

        Ok(())
    }
}

// vim: ts=4 sw=4 expandtab
