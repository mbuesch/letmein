// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{firewall_client::FirewallClient, log_security, server::ConnectionOps};
use anyhow::{self as ah, format_err as err};
use letmein_conf::{Config, ErrorPolicy, Resource};
use letmein_proto::{Message, Operation, ResourceId, UserId};
use std::{net::IpAddr, path::Path};
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
    /// IP address of the remote peer (for logging).
    peer_ip: IpAddr,
    /// Layer-4 protocol label (for logging).
    proto: &'a str,
    user_id: Option<UserId>,
    resource_id: Option<ResourceId>,
    auth_state: AuthState,
}

impl<'a, C: ConnectionOps> Protocol<'a, C> {
    pub fn new(conn: &'a C, conf: &'a Config, rundir: &'a Path) -> Self {
        let peer_ip = conn.peer_addr().ip();
        let proto = conn.l4proto();
        Self {
            conn,
            conf,
            rundir,
            peer_ip,
            proto,
            user_id: None,
            resource_id: None,
            auth_state: AuthState::NotAuth,
        }
    }

    async fn recv_msg(&mut self, expect_operation: &[Operation]) -> ah::Result<Message> {
        let msg_result = timeout(self.conf.control_timeout(), self.conn.recv_msg()).await;

        // Distinguish pre-auth timeout from post-auth timeout for fail2ban differentiation.
        let msg_result_inner = match msg_result {
            Err(_elapsed) => {
                if self.auth_state == AuthState::NotAuth {
                    log_security!(
                        WARN,
                        "PREAUTH_TIMEOUT",
                        self.peer_ip,
                        self.proto
                        => "Connection timed out before client sent initial message"
                    );
                } else {
                    log_security!(
                        WARN,
                        "POSTAUTH_TIMEOUT",
                        self.peer_ip,
                        self.proto
                        => "Connection timed out mid-sequence after authentication"
                    );
                }
                return Err(err!("RX communication with peer timed out"));
            }
            Ok(inner) => inner,
        };

        // Propagate any socket-level I/O or deserialization errors.
        // A malformed datagram (wrong size, invalid magic, unknown operation value)
        // is indistinguishable from active probing/fuzzing - log it before dropping.
        let msg_opt = msg_result_inner.map_err(|e| {
            log_security!(
                WARN,
                "PROTOCOL_ABUSE",
                self.peer_ip,
                self.proto,
                &format!("detail={e}")
                => "Malformed message received; connection dropped"
            );
            e
        })?;

        let Some(msg) = msg_opt else {
            return Err(err!("Disconnected."));
        };

        // Validate that the operation is expected at this stage of the sequence.
        if !expect_operation.contains(&msg.operation()) {
            log_security!(
                ERROR,
                "PROTOCOL_ABUSE",
                self.peer_ip,
                self.proto,
                &format!(
                    "expected={:?} got={:?}",
                    expect_operation,
                    msg.operation()
                )
                => "Unexpected message operation - protocol sequence violated"
            );
            return self
                .send_go_away(Err(err!(
                    "Invalid reply message operation. Expected {:?}, got {:?}",
                    expect_operation,
                    msg.operation()
                )))
                .await;
        }

        // Validate that the user ID has not changed mid-session.
        if let Some(user_id) = self.user_id
            && msg.user() != user_id
        {
            log_security!(
                ERROR,
                "PROTOCOL_ABUSE",
                self.peer_ip,
                self.proto,
                &format!("expected_user={user_id} got_user={}", msg.user())
                => "User ID changed mid-session"
            );
            return self
                .send_go_away(Err(err!("Received message user mismatch")))
                .await;
        }

        // Validate that the resource ID has not changed mid-session.
        if let Some(resource_id) = self.resource_id
            && msg.resource() != resource_id
        {
            log_security!(
                ERROR,
                "PROTOCOL_ABUSE",
                self.peer_ip,
                self.proto,
                &format!(
                    "expected_resource={resource_id} got_resource={}",
                    msg.resource()
                )
                => "Resource ID changed mid-session"
            );
            return self
                .send_go_away(Err(err!("Received message resource mismatch")))
                .await;
        }

        Ok(msg)
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
                // Log with peer context so it can be correlated in journal.
                log_security!(
                    WARN,
                    "GOAWAY_SEND_FAILED",
                    self.peer_ip,
                    self.proto
                    => &format!("Failed to send GoAway reply: {e}")
                );
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

    #[allow(clippy::too_many_lines)]
    pub async fn run(&mut self) -> ah::Result<()> {
        self.user_id = None;
        self.resource_id = None;
        self.auth_state = AuthState::NotAuth;

        // Receive the initial knock/revoke message.
        // recv_msg() will log PREAUTH_TIMEOUT or PROTOCOL_ABUSE itself on failure.
        let initial_message = self
            .recv_msg(&[Operation::Knock, Operation::Revoke])
            .await?;

        let initial_operation = initial_message.operation();

        let user_id = initial_message.user();
        self.user_id = Some(user_id);

        let resource_id = initial_message.resource();
        self.resource_id = Some(resource_id);

        // Get the shared key - log unknown user ID.
        let Some(key) = self.conf.key(user_id) else {
            log_security!(
                WARN,
                "UNKNOWN_USER",
                self.peer_ip,
                self.proto,
                &format!("user={user_id}")
                => "User ID not found in server configuration"
            );
            return self
                .send_go_away(Err(err!("Unknown user: {user_id}")))
                .await;
        };

        // Authenticate the received message (not replay-safe, but that's by design).
        if !initial_message.check_auth_ok_no_challenge(key) {
            log_security!(
                WARN,
                "AUTH_FAILURE",
                self.peer_ip,
                self.proto,
                &format!("user={user_id} resource={resource_id} stage=knock")
                => "Initial knock authentication (HMAC) failed"
            );
            return self
                .send_go_away(Err(err!("Knock: Authentication failed")))
                .await;
        }
        self.auth_state = AuthState::BasicAuth;

        // Get the requested resource from the configuration.
        let Some(resource) = self.conf.resource(resource_id) else {
            log_security!(
                WARN,
                "UNKNOWN_RESOURCE",
                self.peer_ip,
                self.proto,
                &format!("user={user_id} resource={resource_id}")
                => "Resource ID not found in server configuration"
            );
            return self
                .send_go_away(Err(err!("Unknown resource: {resource_id}")))
                .await;
        };

        // Check if the authenticating user is allowed to access this resource.
        if !resource.contains_user(user_id) {
            log_security!(
                WARN,
                "ACCESS_DENIED",
                self.peer_ip,
                self.proto,
                &format!("user={user_id} resource={resource_id}")
                => "Authenticated user is not permitted to access this resource"
            );
            return self
                .send_go_away(Err(err!(
                    "Resource {resource_id} not allowed for user {user_id}"
                )))
                .await;
        }

        // Check if trying to knock/revoke port 0 or the control port.
        match resource {
            Resource::Port { port, .. } => {
                // Port 0 is reserved by the operating system and not allowed.
                if *port == 0 {
                    return self
                        .send_go_away(Err(err!(
                            "Incorrect configuration: The resource {resource_id} \
                            is a port resource with port 0. That is not allowed."
                        )))
                        .await;
                }
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
        // recv_msg() will log PROTOCOL_ABUSE / timeout events itself on failure.
        let response = self.recv_msg(&[Operation::Response]).await?;

        // Authenticate the challenge-response.
        if !response.check_auth_ok(key, challenge) {
            log_security!(
                WARN,
                "AUTH_FAILURE",
                self.peer_ip,
                self.proto,
                &format!("user={user_id} resource={resource_id} stage=challenge-response")
                => "Challenge-response authentication (HMAC) failed"
            );
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
                // Send a revoke-rules request to letmeinfwd.
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

        // Log the successful outcome with structured event keyword.
        let (event, action) = if initial_operation == Operation::Knock {
            ("KNOCK_SUCCESS", "knocked")
        } else {
            ("REVOKE_SUCCESS", "revoked")
        };
        log_security!(
            INFO,
            event,
            self.peer_ip,
            self.proto,
            &format!("user={user_id} resource={resource_id}")
            => &format!("Resource {resource_id} successfully {action}. Firewall rules changed.")
        );

        // Send a come-in message.
        let comein = Message::new(Operation::ComeIn, user_id, resource_id);
        self.send_msg(&comein).await?;

        Ok(())
    }
}

// vim: ts=4 sw=4 expandtab
