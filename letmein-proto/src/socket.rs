// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::DEBUG;
use anyhow::{self as ah, format_err as err, Context as _};
use std::{
    collections::{HashMap, VecDeque},
    io::ErrorKind,
    net::SocketAddr,
    sync::{
        atomic::{self, AtomicBool},
        Arc, Mutex as StdMutex,
    },
    time::Duration,
};
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::{
        watch::{channel, Receiver, Sender},
        Mutex,
    },
    time::sleep,
};

/// One connection for use by [`UdpDispatcherRx`].
#[derive(Debug)]
struct UdpConn<const MSG_SIZE: usize, const Q_SIZE: usize> {
    /// The receive-queue for this connection.
    rx_queue: VecDeque<[u8; MSG_SIZE]>,

    /// The peer IP address + source port tuple for this connection.
    peer_addr: SocketAddr,

    /// Is this a new connection that has not been accepted, yet?
    accepted: bool,
}

/// Very simple "connection" tracking for UDP.
///
/// Tracking is purely based on the peer's IP address and source port.
/// There are no other advanced TCP-like functionalities or any
/// safety measures against maliciously crafted datagrams.
///
/// The datagram consumer must be able to handle maliciously crafted
/// datagrams (e.g. source address/port) without problems.
///
/// The maximum number of connections and the maximum number of packets
/// in the RX queue are limited.
/// However, there is no timeout mechanism for the connection.
/// The caller has to take care of timeout detection and handling.
#[derive(Debug)]
struct UdpDispatcherRx<const MSG_SIZE: usize, const Q_SIZE: usize> {
    /// All active connections.
    conn: HashMap<SocketAddr, UdpConn<MSG_SIZE, Q_SIZE>>,

    /// The maximum possible number of connections.
    max_nr_conn: usize,

    /// The number of queued datagrams in all connections.
    nr_queued_dgrams: usize,
}

impl<const MSG_SIZE: usize, const Q_SIZE: usize> UdpDispatcherRx<MSG_SIZE, Q_SIZE> {
    /// Create a new [`UdpDispatcherRx`]
    /// with the given maximum possible number of connections.
    fn new(max_nr_conn: usize) -> Self {
        UdpDispatcherRx {
            conn: HashMap::new(),
            max_nr_conn,
            nr_queued_dgrams: 0,
        }
    }

    /// Try to receive a new datagram from the socket.
    fn try_recv(
        &mut self,
        socket: &UdpSocket,
        accept_notify: &Sender<()>,
        recv_notify: &Sender<()>,
    ) -> ah::Result<()> {
        let mut buf = [0_u8; MSG_SIZE];
        match socket.try_recv_from(&mut buf) {
            Ok((n, peer_addr)) => {
                if n != MSG_SIZE {
                    return Err(err!("Socket read: Invalid datagram size: {n}"));
                }

                // Add the received datagram to an existing connection
                // or create a new connection, if there is none, yet.
                assert!(self.conn.len() <= self.max_nr_conn);
                let conn = self.conn.entry(peer_addr).or_insert_with(|| UdpConn {
                    rx_queue: VecDeque::new(),
                    peer_addr,
                    accepted: false,
                });

                // Check if the RX queue is full
                // and if not, then push the received datagram to the queue.
                assert!(conn.rx_queue.len() <= Q_SIZE);
                if conn.rx_queue.len() == Q_SIZE {
                    self.conn.remove(&peer_addr); // Close connection.
                    return Err(err!("UDP socket read: RX queue overflow (max={Q_SIZE})."));
                }
                conn.rx_queue.push_back(buf);
                let accepted = conn.accepted;

                // Check if this was a new connection and
                // we exceeded the maximum number of connections.
                if self.conn.len() > self.max_nr_conn {
                    self.conn.remove(&peer_addr); // Close connection.
                    return Err(err!(
                        "UDP socket read: Too many connections (max={}).",
                        self.max_nr_conn
                    ));
                }

                self.nr_queued_dgrams += 1;
                assert!(self.nr_queued_dgrams <= self.max_nr_conn * Q_SIZE);

                if !accepted {
                    if DEBUG {
                        println!("UDP-dispatcher: Notifying accept-watchers.");
                    }
                    // There is an un-accepted connection. Wake watcher.
                    let _ = accept_notify.send(());
                    let _ = recv_notify.send(());
                }

                Ok(())
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(err!("Socket read: {e}")),
        }
    }

    /// Notify receivers based on whether more datagrams are queued.
    fn recv_notify(&self, recv_notify: &Sender<()>) {
        if self.nr_queued_dgrams > 0 {
            // There is queued RX data for an accepted connection. Wake watcher.
            if DEBUG {
                println!("UDP-dispatcher: Notifying recv-watchers.");
            }
            let _ = recv_notify.send(());
        }
    }

    /// Get the first not-accepted connection, or None.
    fn try_accept(
        &mut self,
        socket: &UdpSocket,
        accept_notify: &Sender<()>,
        recv_notify: &Sender<()>,
    ) -> Option<SocketAddr> {
        if let Err(e) = self.try_recv(socket, accept_notify, recv_notify) {
            if DEBUG {
                eprintln!("UDP-dispatcher: try_recv error during try_accept: {e:?}");
            }
            return None;
        }
        for conn in &mut self.conn.values_mut() {
            if !conn.accepted {
                conn.accepted = true;
                return Some(conn.peer_addr);
            }
        }
        self.recv_notify(recv_notify);
        None
    }

    /// Get the oldest element from the RX queue.
    fn try_recv_from(
        &mut self,
        socket: &UdpSocket,
        peer_addr: SocketAddr,
        accept_notify: &Sender<()>,
        recv_notify: &Sender<()>,
    ) -> ah::Result<Option<[u8; MSG_SIZE]>> {
        self.try_recv(socket, accept_notify, recv_notify)?;
        let buf = self
            .conn
            .get_mut(&peer_addr)
            .and_then(|conn| conn.rx_queue.pop_front());
        if buf.is_some() {
            self.nr_queued_dgrams -= 1;
        }
        self.recv_notify(recv_notify);
        Ok(buf)
    }

    /// Disconnect the connection identified by the `peer_addr`.
    fn disconnect(&mut self, peer_addr: SocketAddr) {
        if let Some(conn) = self.conn.get(&peer_addr) {
            self.nr_queued_dgrams -= conn.rx_queue.len();
        }
        self.conn.remove(&peer_addr);
        if self.conn.is_empty() {
            assert_eq!(self.nr_queued_dgrams, 0);
        }
    }
}

/// Simple TX/RX dispatcher for UDP.
///
/// The datagram consumer must be able to handle maliciously crafted
/// datagrams (e.g. source address/port) without problems.
#[derive(Debug)]
pub struct UdpDispatcher<const MSG_SIZE: usize, const Q_SIZE: usize> {
    /// RX connection tracking.
    rx: StdMutex<UdpDispatcherRx<MSG_SIZE, Q_SIZE>>,

    /// The UDP socket we use for sending and receiving.
    socket: UdpSocket,

    /// Watch signal: New accept-connections are available.
    accept_watch: (Sender<()>, Mutex<Receiver<()>>),

    /// Watch signal: new data for an established connection is available.
    recv_watch: (Sender<()>, Mutex<Receiver<()>>),
}

impl<const MSG_SIZE: usize, const Q_SIZE: usize> UdpDispatcher<MSG_SIZE, Q_SIZE> {
    /// Create a new [`UdpDispatcher`]
    /// with the given UDP socket and
    /// with the given maximum possible number of connections.
    pub fn new(socket: UdpSocket, max_nr_conn: usize) -> Self {
        let accept_watch = channel(());
        let recv_watch = channel(());
        Self {
            rx: StdMutex::new(UdpDispatcherRx::new(max_nr_conn)),
            socket,
            accept_watch: (accept_watch.0, Mutex::new(accept_watch.1)),
            recv_watch: (recv_watch.0, Mutex::new(recv_watch.1)),
        }
    }

    /// Asynchronously wait for a new connection.
    pub async fn accept(&self) -> ah::Result<SocketAddr> {
        // Try to avoid returning an error Result from here.
        // Only unrecoverable errors shall be returned.
        // Everything else shall be retried.
        loop {
            {
                let mut accept_watch = self.accept_watch.1.lock().await;
                tokio::select! {
                    _ = self.socket.readable() => (),
                    _ = accept_watch.changed() => (),
                }
            }

            if DEBUG {
                println!("UDP-dispatcher: Trying accept.");
            }
            let peer_addr = self.rx.lock().expect("Mutex poisoned").try_accept(
                &self.socket,
                &self.accept_watch.0,
                &self.recv_watch.0,
            );
            if let Some(peer_addr) = peer_addr {
                if DEBUG {
                    println!("UDP-dispatcher: Accepted new connection.");
                }
                break Ok(peer_addr);
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    /// Asynchronously wait for a new datagram from the specified
    /// peer identified by the IP address + port tuple `peer_addr`.
    pub async fn recv_from(&self, peer_addr: SocketAddr) -> ah::Result<[u8; MSG_SIZE]> {
        loop {
            {
                let mut recv_watch = self.recv_watch.1.lock().await;
                tokio::select! {
                    _ = self.socket.readable() => (),
                    _ = recv_watch.changed() => (),
                }
            }

            if DEBUG {
                println!("UDP-dispatcher: Trying recv.");
            }
            let buf = self.rx.lock().expect("Mutex poisoned").try_recv_from(
                &self.socket,
                peer_addr,
                &self.accept_watch.0,
                &self.recv_watch.0,
            )?;
            if let Some(buf) = buf {
                if DEBUG {
                    println!("UDP-dispatcher: Received datagram.");
                }
                break Ok(buf);
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    /// Asynchronously send a datagram `data` to the specified
    /// peer identified by the UP address + port tuple `peer_addr`.
    pub async fn send_to(&self, peer_addr: SocketAddr, data: [u8; MSG_SIZE]) -> ah::Result<()> {
        self.socket
            .writable()
            .await
            .context("Socket await writable")?;
        self.socket
            .send_to(&data, peer_addr)
            .await
            .context("UDP socket send_to")?;
        if DEBUG {
            println!("UDP-dispatcher: Sent datagram.");
        }
        Ok(())
    }

    /// Disconnect the connection identified by the `peer_addr`.
    #[allow(clippy::unused_async)]
    pub async fn disconnect(&self, peer_addr: SocketAddr) {
        self.rx
            .lock()
            .expect("Mutex poisoned")
            .disconnect(peer_addr);
    }
}

/// Socket abstraction for sending and receiving data
/// over a TCP connection.
#[derive(Debug)]
pub struct NetSocketTcp {
    /// The [`TcpStream`] of this TCP connection.
    stream: TcpStream,

    /// Closed-flag. Note that this does *not* mean that the `stream` is closed.
    closed: AtomicBool,
}

/// Socket abstraction for sending and receiving data
/// over a UDP connection.
#[derive(Debug)]
pub struct NetSocketUdp<const MSG_SIZE: usize, const Q_SIZE: usize> {
    /// UDP datagram dispatcher for sending and receiving datagrams.
    disp: Arc<UdpDispatcher<MSG_SIZE, Q_SIZE>>,

    /// The peer this connection is connected to.
    peer_addr: SocketAddr,

    /// Closed-flag.
    closed: AtomicBool,
}

/// Socket abstraction for sending and receiving data
/// over a TCP or UDP connection.
#[derive(Debug)]
pub enum NetSocket<const MSG_SIZE: usize, const Q_SIZE: usize> {
    /// TCP variant.
    Tcp(NetSocketTcp),

    /// UDP variant.
    Udp(NetSocketUdp<MSG_SIZE, Q_SIZE>),
}

impl<const MSG_SIZE: usize, const Q_SIZE: usize> NetSocket<MSG_SIZE, Q_SIZE> {
    /// Create a new [`NetSocket`] from a [`TcpStream`] connection.
    pub fn from_tcp(stream: TcpStream) -> ah::Result<Self> {
        // Disable Nagle's algorithm.
        // We want to send our small packets as quickly as possible.
        stream.set_nodelay(true).context("Set TCP_NODELAY")?;

        Ok(Self::Tcp(NetSocketTcp {
            stream,
            closed: AtomicBool::new(false),
        }))
    }

    /// Create a new [`NetSocket`] from a [`UdpDispatcher`]
    /// and the specified connected `peer_addr`.
    pub fn from_udp(
        disp: Arc<UdpDispatcher<MSG_SIZE, Q_SIZE>>,
        peer_addr: SocketAddr,
    ) -> ah::Result<Self> {
        Ok(Self::Udp(NetSocketUdp {
            disp,
            peer_addr,
            closed: AtomicBool::new(false),
        }))
    }

    /// Send a message to the connected peer.
    pub async fn send(&self, buf: [u8; MSG_SIZE]) -> ah::Result<()> {
        // For good measure, check if we're not closed. But this check is racy.
        if self.is_closed() {
            Err(err!("Socket is closed."))
        } else {
            match self {
                Self::Tcp(inner) => {
                    // Send the message via TCP.
                    let mut count = 0;
                    loop {
                        inner
                            .stream
                            .writable()
                            .await
                            .context("Socket polling (tx)")?;
                        match inner.stream.try_write(&buf[count..]) {
                            Ok(n) => {
                                count += n;
                                assert!(count <= buf.len());
                                if count == buf.len() {
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
                Self::Udp(inner) => {
                    // Send the message via UDP.
                    inner.disp.send_to(inner.peer_addr, buf).await
                }
            }
        }
    }

    /// Receive a message from the connected peer.
    pub async fn recv(&self) -> ah::Result<Option<[u8; MSG_SIZE]>> {
        // For good measure, check if we're not closed. But this check is racy.
        if self.is_closed() {
            Err(err!("Socket is closed."))
        } else {
            match self {
                Self::Tcp(inner) => {
                    // Receive a message via TCP.
                    let mut buf = [0; MSG_SIZE];
                    let mut count = 0;
                    loop {
                        inner
                            .stream
                            .readable()
                            .await
                            .context("Socket polling (rx)")?;
                        match inner.stream.try_read(&mut buf[count..]) {
                            Ok(n) => {
                                if n == 0 {
                                    return Ok(None);
                                }
                                count += n;
                                assert!(count <= MSG_SIZE);
                                if count == MSG_SIZE {
                                    return Ok(Some(buf));
                                }
                            }
                            Err(e) if e.kind() == ErrorKind::WouldBlock => (),
                            Err(e) => {
                                return Err(err!("Socket read: {e}"));
                            }
                        }
                    }
                }
                Self::Udp(inner) => {
                    // Receive a message via UDP.
                    inner.disp.recv_from(inner.peer_addr).await.map(Some)
                }
            }
        }
    }

    /// Close this connection.
    ///
    /// This marks both UDP and TCP as closed and no further TX/RX can happen.
    ///
    /// Note that this does not actually close the TCP connection.
    /// Dropping this object will close the TCP connection.
    pub async fn close(&self) {
        match self {
            Self::Tcp(inner) => {
                inner.closed.store(true, atomic::Ordering::SeqCst);
            }
            Self::Udp(inner) => {
                if !inner.closed.swap(true, atomic::Ordering::SeqCst) {
                    inner.disp.disconnect(inner.peer_addr).await;
                }
            }
        }
    }

    /// Check if this connection is marked as closed.
    pub fn is_closed(&self) -> bool {
        match self {
            Self::Tcp(inner) => inner.closed.load(atomic::Ordering::SeqCst),
            Self::Udp(inner) => inner.closed.load(atomic::Ordering::SeqCst),
        }
    }
}

// vim: ts=4 sw=4 expandtab
