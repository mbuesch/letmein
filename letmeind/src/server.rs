// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, format_err as err, Context as _};
use letmein_conf::Config;
use letmein_proto::Message;
use letmein_systemd::{systemd_notify_ready, SystemdSocket};
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

pub trait ConnectionOps {
    fn peer_addr(&self) -> SocketAddr;
    async fn recv_msg(&mut self) -> ah::Result<Option<Message>>;
    async fn send_msg(&mut self, msg: &Message) -> ah::Result<()>;
}

pub struct Connection {
    stream: TcpStream,
    peer_addr: SocketAddr,
}

impl Connection {
    fn new(stream: TcpStream, peer_addr: SocketAddr) -> ah::Result<Self> {
        Ok(Self { stream, peer_addr })
    }
}

impl ConnectionOps for Connection {
    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    async fn recv_msg(&mut self) -> ah::Result<Option<Message>> {
        Message::recv(&mut self.stream).await
    }

    async fn send_msg(&mut self, msg: &Message) -> ah::Result<()> {
        msg.send(&mut self.stream).await
    }
}

pub struct Server {
    listener: TcpListener,
}

impl Server {
    pub async fn new(conf: &Config, no_systemd: bool) -> ah::Result<Self> {
        // Get socket from systemd?
        if !no_systemd {
            let sockets = SystemdSocket::get_all()?;
            if let Some(SystemdSocket::Tcp(listener)) = sockets.into_iter().next() {
                println!("Using TCP socket from systemd.");
                listener
                    .set_nonblocking(true)
                    .context("Set socket non-blocking")?;
                let listener = TcpListener::from_std(listener)
                    .context("Convert std TcpListener to tokio TcpListener")?;
                systemd_notify_ready()?;
                return Ok(Self { listener });
            } else {
                return Err(err!("Received an unusable socket from systemd."));
            }
        }

        // Without systemd.

        // TCP bind.
        let listener = TcpListener::bind(("::0", conf.port()))
            .await
            .context("Bind")?;

        Ok(Self { listener })
    }

    pub async fn accept(&self) -> ah::Result<Connection> {
        let (stream, addr) = self.listener.accept().await?;
        Connection::new(stream, addr)
    }
}

// vim: ts=4 sw=4 expandtab
