// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, format_err as err, Context as _};
use letmein_proto::{DeserializeResult, Message, MSG_SIZE};
use std::{io::ErrorKind, net::IpAddr};
use tokio::net::TcpStream;

const DEBUG: bool = false;

pub struct Client {
    stream: TcpStream,
}

impl Client {
    pub async fn new(addr: IpAddr, port: u16) -> ah::Result<Self> {
        let stream = TcpStream::connect((addr, port))
            .await
            .context("Connect to server")?;
        Ok(Self { stream })
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

// vim: ts=4 sw=4 expandtab
