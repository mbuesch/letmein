// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::resolver::{resolve, ResMode};
use anyhow::{self as ah, format_err as err, Context as _};
use letmein_proto::{Message, Operation};
use tokio::net::TcpStream;

/// TCP control connection to the server.
pub struct Client {
    stream: TcpStream,
}

impl Client {
    /// Create a new letmein control connection.
    pub async fn new(host: &str, port: u16, mode: ResMode) -> ah::Result<Self> {
        let addr = resolve(host, mode).await.context("Resolve host name")?;
        let stream = TcpStream::connect((addr, port))
            .await
            .context("Connect to server")?;
        Ok(Self { stream })
    }

    /// Receive a message from the TCP control connection.
    pub async fn recv_msg(&mut self) -> ah::Result<Option<Message>> {
        Message::recv(&mut self.stream).await
    }

    /// Receive a specific message type from the TCP control connection.
    ///
    /// Returns an error, if another message type is received.
    /// Returns an error, if a [Operation::GoAway] type Message is received.
    pub async fn recv_specific_msg(&mut self, expect_operation: Operation) -> ah::Result<Message> {
        let reply = self.recv_msg().await.context("Receive knock reply")?;
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

    /// Send a message to the TCP control connection.
    pub async fn send_msg(&mut self, msg: Message) -> ah::Result<()> {
        msg.send(&mut self.stream).await
    }
}

// vim: ts=4 sw=4 expandtab
