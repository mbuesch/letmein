// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::resolver::{resolve, ResConf};
use anyhow::{self as ah, format_err as err, Context as _};
use letmein_conf::ControlPort;
use letmein_proto::{Message, MsgNetSocket, MsgUdpDispatcher, Operation};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpStream, UdpSocket},
    time::timeout,
};

/// TCP control connection to the server.
pub struct Client {
    sock: MsgNetSocket,
    control_timeout: Duration,
}

impl Client {
    /// Create a new letmein control connection.
    pub async fn new(
        host: &str,
        control_port: ControlPort,
        control_timeout: Duration,
        resolve_conf: &ResConf,
    ) -> ah::Result<Self> {
        let addr = resolve(host, resolve_conf)
            .await
            .context("Resolve host name")?;

        let sock = if control_port.tcp {
            assert!(!control_port.udp);

            let stream = TcpStream::connect((addr, control_port.port))
                .await
                .context("Connect to server")?;

            MsgNetSocket::from_tcp(stream)?
        } else {
            assert!(control_port.udp);

            let socket = if addr.is_ipv4() {
                UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await
            } else if addr.is_ipv6() {
                UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await
            } else {
                unreachable!()
            }
            .context("Bind UDP socket")?;

            socket
                .connect((addr, control_port.port))
                .await
                .context("Connect to server")?;
            let peer_addr = socket.peer_addr().context("Get peer address")?;

            MsgNetSocket::from_udp(Arc::new(MsgUdpDispatcher::new(socket, 1)), peer_addr)?
        };

        Ok(Self {
            sock,
            control_timeout,
        })
    }

    /// Receive a message from the TCP control connection.
    pub async fn recv_msg(&mut self) -> ah::Result<Option<Message>> {
        timeout(self.control_timeout, Message::recv(&self.sock))
            .await
            .map_err(|_| err!("RX communication with peer timed out"))?
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
        timeout(self.control_timeout, msg.send(&self.sock))
            .await
            .map_err(|_| err!("TX communication with peer timed out"))?
    }
}

// vim: ts=4 sw=4 expandtab
