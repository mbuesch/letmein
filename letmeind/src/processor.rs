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
use letmein_proto::{Challenge, Key, Message, Operation};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct Processor<'a> {
    conn: Connection,
    conf: &'a ConfigRef<'a>,
    fw: Arc<Mutex<Firewall>>,
    user_id: Option<u32>,
    resource_id: Option<u32>,
    resource: Option<Resource>,
    challenge: Option<Challenge>,
    key: Option<Key>,
}

impl<'a> Processor<'a> {
    pub fn new(conn: Connection, conf: &'a ConfigRef<'a>, fw: Arc<Mutex<Firewall>>) -> Self {
        Self {
            conn,
            conf,
            fw,
            user_id: None,
            resource_id: None,
            resource: None,
            challenge: None,
            key: None,
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
            self.user_id.unwrap_or(0),
            self.resource_id.unwrap_or(0),
        ))
        .await
    }

    async fn handle_knock(&mut self) -> ah::Result<()> {
        let msg = self.recv_msg(Operation::Knock).await?;

        let user_id = msg.user();
        self.user_id = Some(user_id);

        let resource_id = msg.resource();
        self.resource_id = Some(resource_id);

        // Get the shared key and cache it.
        let Some(key) = self.conf.key(user_id) else {
            let _ = self.send_go_away().await;
            return Err(err!("Unknown user: {user_id:X}"));
        };
        self.key = Some(*key);

        // Authenticate the received message.
        // This check is not replay-safe. But that's fine.
        if !msg.check_auth_ok_no_challenge(key) {
            let _ = self.send_go_away().await;
            return Err(err!("Knock: Authentication failed"));
        }

        // Get the requested resource from the configuration.
        let Some(resource) = self.conf.resource(resource_id) else {
            let _ = self.send_go_away().await;
            return Err(err!("Unknown resource: {resource_id:X}"));
        };
        self.resource = Some(resource.clone());

        // Generate and send a challenge.
        let mut challenge_msg = Message::new(Operation::Challenge, user_id, resource_id);
        self.challenge = Some(challenge_msg.generate_challenge());
        self.send_msg(challenge_msg).await?;

        Ok(())
    }

    async fn handle_challenge_response(&mut self) -> ah::Result<()> {
        let msg = self.recv_msg(Operation::Response).await?;

        // Authenticate the challenge-response.
        if !msg.check_auth_ok(&self.key.take().unwrap(), &self.challenge.take().unwrap()) {
            let _ = self.send_go_away().await;
            return Err(err!("Response: Authentication failed"));
        }

        Ok(())
    }

    async fn handle_open_firewall(&mut self) -> ah::Result<()> {
        // Reconfigure the firewall.
        match self.resource.take().unwrap() {
            Resource::Port(port) => {
                let mut fw = self.fw.lock().await;
                fw.open_port(self.conf, self.conn.addr().ip(), port).await?;
            }
        }

        Ok(())
    }

    async fn handle_come_in(&mut self) -> ah::Result<()> {
        // Send a come-in message.
        let comein_msg = Message::new(
            Operation::ComeIn,
            self.user_id.unwrap(),
            self.resource_id.unwrap(),
        );
        self.send_msg(comein_msg).await?;

        Ok(())
    }

    pub async fn run(&mut self) -> ah::Result<()> {
        self.handle_knock().await?;
        self.handle_challenge_response().await?;
        self.handle_open_firewall().await?;
        self.handle_come_in().await?;
        Ok(())
    }
}

// vim: ts=4 sw=4 expandtab
