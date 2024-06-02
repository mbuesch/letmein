// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    systemd::{systemd_notify_ready, tcp_from_systemd},
    ConfigRef,
};
use anyhow::{self as ah, format_err as err, Context as _};
use letmein_proto::{DeserializeResult, Message, MSG_SIZE};
use std::{io::ErrorKind, net::SocketAddr};
use tokio::net::{TcpListener, TcpStream};

const DEBUG: bool = false;

pub struct Connection {
    stream: TcpStream,
    addr: SocketAddr,
}

impl Connection {
    fn new(stream: TcpStream, addr: SocketAddr) -> ah::Result<Self> {
        Ok(Self { stream, addr })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn recv_msg(&mut self) -> ah::Result<Option<Message>> {
        let mut rxbuf = [0; MSG_SIZE];
        let mut rxcount = 0;
        loop {
            self.stream
                .readable()
                .await
                .context("Socket polling (rx)")?;
            match self.stream.try_read(&mut rxbuf[rxcount..]) {
                Ok(n) => {
                    if n == 0 {
                        return Ok(None);
                    }
                    rxcount += n;
                    assert!(rxcount <= MSG_SIZE);
                    if rxcount == MSG_SIZE {
                        let DeserializeResult::Ok(msg) = Message::try_msg_deserialize(&rxbuf)?
                        else {
                            return Err(err!("RX deserialization failed"));
                        };
                        if DEBUG {
                            println!("RX: {msg:?} {rxbuf:?}");
                        }
                        return Ok(Some(msg));
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => (),
                Err(e) => {
                    return Err(err!("Socket read: {e}"));
                }
            }
        }
    }

    pub async fn send_msg(&mut self, msg: Message) -> ah::Result<()> {
        let txbuf = msg.msg_serialize()?;
        let mut txcount = 0;
        loop {
            self.stream
                .writable()
                .await
                .context("Socket polling (tx)")?;
            match self.stream.try_write(&txbuf[txcount..]) {
                Ok(n) => {
                    txcount += n;
                    if txcount >= txbuf.len() {
                        if DEBUG {
                            println!("TX: {msg:?} {txbuf:?}");
                        }
                        return Ok(());
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => (),
                Err(e) => {
                    return Err(err!("Socket write: {e}"));
                }
            }
        }
    }
}

pub struct Server {
    listener: TcpListener,
}

impl Server {
    pub async fn new(conf: &ConfigRef<'_>, no_systemd: bool) -> ah::Result<Self> {
        if !no_systemd {
            if let Some(listener) = tcp_from_systemd()? {
                println!("Using socket from systemd.");
                listener
                    .set_nonblocking(true)
                    .context("Set socket non-blocking")?;
                let listener = TcpListener::from_std(listener)
                    .context("Convert std TcpListener to tokio TcpListener")?;
                systemd_notify_ready()?;
                return Ok(Self { listener });
            }
        }
        Ok(Self {
            listener: TcpListener::bind(("::0", conf.port()))
                .await
                .context("Bind")?,
        })
    }

    pub async fn accept(&self) -> ah::Result<Connection> {
        let (stream, addr) = self.listener.accept().await?;
        Connection::new(stream, addr)
    }
}

// vim: ts=4 sw=4 expandtab
