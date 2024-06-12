// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{firewall::Firewall, server::Connection, ConfigRef};
use anyhow::{self as ah, format_err as err};
use letmein_conf::Resource;
use letmein_proto::{Message, Operation};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct Processor<'a> {
    conn: Connection,
    conf: &'a ConfigRef<'a>,
    fw: Arc<Mutex<Firewall>>,
    user_id: Option<u32>,
    resource_id: Option<u32>,
}

impl<'a> Processor<'a> {
    pub fn new(conn: Connection, conf: &'a ConfigRef<'a>, fw: Arc<Mutex<Firewall>>) -> Self {
        Self {
            conn,
            conf,
            fw,
            user_id: None,
            resource_id: None,
        }
    }

    async fn recv_msg(&mut self, expect_operation: Operation) -> ah::Result<Message> {
        if let Some(msg) = self.conn.recv_msg().await? {
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

    async fn send_msg(&mut self, msg: Message) -> ah::Result<()> {
        self.conn.send_msg(msg).await
    }

    async fn send_go_away(&mut self) -> ah::Result<()> {
        self.send_msg(Message::new(
            Operation::GoAway,
            self.user_id.unwrap_or(u32::MAX),
            self.resource_id.unwrap_or(u32::MAX),
        ))
        .await
    }

    pub async fn run(&mut self) -> ah::Result<()> {
        let knock = self.recv_msg(Operation::Knock).await?;

        let user_id = knock.user();
        self.user_id = Some(user_id);

        let resource_id = knock.resource();
        self.resource_id = Some(resource_id);

        // Get the shared key.
        let Some(key) = self.conf.key(user_id) else {
            let _ = self.send_go_away().await;
            return Err(err!("Unknown user: {user_id:X}"));
        };

        // Authenticate the received message.
        // This check is not replay-safe. But that's fine.
        if !knock.check_auth_ok_no_challenge(key) {
            let _ = self.send_go_away().await;
            return Err(err!("Knock: Authentication failed"));
        }

        // Get the requested resource from the configuration.
        let Some(resource) = self.conf.resource(resource_id) else {
            let _ = self.send_go_away().await;
            return Err(err!("Unknown resource: {resource_id:X}"));
        };

        // Generate and send a challenge.
        let mut challenge = Message::new(Operation::Challenge, user_id, resource_id);
        challenge.generate_challenge();
        self.send_msg(challenge.clone()).await?;

        // Receive the response.
        let response = self.recv_msg(Operation::Response).await?;

        // Authenticate the challenge-response.
        if !response.check_auth_ok(key, challenge) {
            let _ = self.send_go_away().await;
            return Err(err!("Response: Authentication failed"));
        }

        // Reconfigure the firewall.
        match resource {
            Resource::Port(port) => {
                let mut fw = self.fw.lock().await;
                fw.open_port(self.conf, self.conn.addr().ip(), *port)
                    .await?;
            }
        }

        // Send a come-in message.
        let comein = Message::new(Operation::ComeIn, user_id, resource_id);
        self.send_msg(comein).await?;

        Ok(())
    }
}

// vim: ts=4 sw=4 expandtab
