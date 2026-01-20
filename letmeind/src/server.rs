// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, format_err as err, Context as _};
use letmein_conf::Config;
use letmein_proto::{Message, MsgNetSocket, MsgUdpDispatcher};
use letmein_systemd::{systemd_notify_ready, SystemdSocket};
use std::{
    convert::Infallible,
    net::{Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    task::{self, JoinHandle},
    time,
};

async fn sleep_forever() -> Infallible {
    loop {
        time::sleep(Duration::from_secs(31_536_000_000)).await;
    }
}

pub trait ConnectionOps {
    fn peer_addr(&self) -> SocketAddr;
    fn l4proto(&self) -> &'static str;
    async fn recv_msg(&self) -> ah::Result<Option<Message>>;
    async fn send_msg(&self, msg: &Message) -> ah::Result<()>;
    async fn close(&self);
}

pub struct Connection {
    socket: MsgNetSocket,
    peer_addr: SocketAddr,
    l4proto: &'static str,
}

impl Connection {
    fn new(socket: MsgNetSocket, peer_addr: SocketAddr, l4proto: &'static str) -> Self {
        Self {
            socket,
            peer_addr,
            l4proto,
        }
    }
}

impl ConnectionOps for Connection {
    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    fn l4proto(&self) -> &'static str {
        self.l4proto
    }

    async fn recv_msg(&self) -> ah::Result<Option<Message>> {
        Message::recv(&self.socket).await
    }

    async fn send_msg(&self, msg: &Message) -> ah::Result<()> {
        msg.send(&self.socket).await
    }

    async fn close(&self) {
        self.socket.close().await;
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // close() must have been called and awaited before dropping the object.
        assert!(self.socket.is_closed());
    }
}

type TcpJoinHandle = Pin<Box<JoinHandle<ah::Result<(TcpStream, SocketAddr)>>>>;

fn spawn_tcp_accept(tcp: Arc<Option<TcpListener>>) -> TcpJoinHandle {
    Box::pin(task::spawn(async move {
        if let Some(tcp) = tcp.as_ref() {
            return Ok(tcp.accept().await?);
        }
        sleep_forever().await;
        unreachable!();
    }))
}

type UdpJoinHandle = Pin<Box<JoinHandle<ah::Result<(Arc<MsgUdpDispatcher>, SocketAddr)>>>>;

fn spawn_udp_accept(udp: Arc<Option<Arc<MsgUdpDispatcher>>>) -> UdpJoinHandle {
    Box::pin(task::spawn(async move {
        if let Some(udp) = udp.as_ref() {
            let peer_addr = udp.accept().await?;
            return Ok((Arc::clone(udp), peer_addr));
        }
        sleep_forever().await;
        unreachable!();
    }))
}

pub struct Server {
    tcp: Arc<Option<TcpListener>>,
    tcp_join: TcpJoinHandle,
    udp: Arc<Option<Arc<MsgUdpDispatcher>>>,
    udp_join: UdpJoinHandle,
}

impl Server {
    pub async fn new(conf: &Config, no_systemd: bool, max_nr_udp_conn: usize) -> ah::Result<Self> {
        let mut tcp = None;
        let mut udp = None;

        // Get socket from systemd?
        if !no_systemd {
            for socket in SystemdSocket::get_all()? {
                match socket {
                    SystemdSocket::Tcp(listener) => {
                        if tcp.is_some() {
                            return Err(err!("Received multiple TCP sockets from systemd."));
                        }
                        if !conf.port().tcp {
                            // Received socket from systemd, but TCP is not configured.
                            drop(listener);
                            continue;
                        }
                        println!("Using TCP socket from systemd.");

                        listener
                            .set_nonblocking(true)
                            .context("Set socket non-blocking")?;
                        tcp = Some(
                            TcpListener::from_std(listener)
                                .context("Convert std TcpListener to tokio TcpListener")?,
                        );
                    }
                    SystemdSocket::Udp(socket) => {
                        if udp.is_some() {
                            return Err(err!("Received multiple UDP sockets from systemd."));
                        }
                        if !conf.port().udp {
                            // Received socket from systemd, but UDP is not configured.
                            drop(socket);
                            continue;
                        }
                        println!("Using UDP socket from systemd.");

                        socket
                            .set_nonblocking(true)
                            .context("Set socket non-blocking")?;
                        udp = Some(Arc::new(MsgUdpDispatcher::new(
                            UdpSocket::from_std(socket)
                                .context("Convert std UdpSocket to tokio UdpSocket")?,
                            max_nr_udp_conn,
                        )));
                    }
                    _ => {
                        return Err(err!("Received an unusable socket from systemd."));
                    }
                }
            }

            if tcp.is_some() || udp.is_some() {
                systemd_notify_ready()?;
            }
        }

        // Without systemd.
        if tcp.is_none() && udp.is_none() {
            // TCP bind.
            if conf.port().tcp {
                tcp = Some(
                    TcpListener::bind((Ipv6Addr::UNSPECIFIED, conf.port().port))
                        .await
                        .context("Bind")?,
                );
            }
            // UDP bind.
            if conf.port().udp {
                udp = Some(Arc::new(MsgUdpDispatcher::new(
                    UdpSocket::bind((Ipv6Addr::UNSPECIFIED, conf.port().port))
                        .await
                        .context("Bind")?,
                    max_nr_udp_conn,
                )));
            }
        }

        let tcp = Arc::new(tcp);
        let tcp_join = spawn_tcp_accept(Arc::clone(&tcp));
        let udp = Arc::new(udp);
        let udp_join = spawn_udp_accept(Arc::clone(&udp));
        Ok(Self {
            tcp,
            tcp_join,
            udp,
            udp_join,
        })
    }

    pub async fn accept(&mut self) -> ah::Result<Connection> {
        tokio::select! {
            result = &mut self.tcp_join => {
                self.tcp_join = spawn_tcp_accept(Arc::clone(&self.tcp));
                let (stream, peer_addr) = result??;
                let ns = MsgNetSocket::from_tcp(stream)?;
                Ok(Connection::new(ns, peer_addr, "TCP"))
            }
            result = &mut self.udp_join => {
                self.udp_join = spawn_udp_accept(Arc::clone(&self.udp));
                let (udp_disp, peer_addr) = result??;
                let ns = MsgNetSocket::from_udp(udp_disp, peer_addr)?;
                Ok(Connection::new(ns, peer_addr, "UDP"))
            }
        }
    }
}

// vim: ts=4 sw=4 expandtab
