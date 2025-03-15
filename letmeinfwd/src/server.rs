// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    firewall::{FirewallOpen, LeasePort},
    set_owner_mode, Opts, LETMEIND_GID, LETMEIND_UID,
};
use anyhow::{self as ah, format_err as err, Context as _};
use letmein_conf::Config;
use letmein_fwproto::{FirewallMessage, FirewallOperation, PortType, SOCK_FILE};
use letmein_systemd::{systemd_notify_ready, SystemdSocket};
use std::{
    fs::{metadata, remove_file, OpenOptions},
    io::Read as _,
    net::IpAddr,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    sync::{atomic::Ordering::Relaxed, Arc},
};
use tokio::{
    net::{unix::pid_t, UnixListener, UnixStream},
    sync::Mutex,
};

/// Get the actual PID of the `letmeind` daemon process.
fn get_letmeind_pid(rundir: &Path) -> ah::Result<pid_t> {
    let mut pid = String::new();
    OpenOptions::new()
        .read(true)
        .open(rundir.join("letmeind/letmeind.pid"))
        .context("Open PID-file of 'letmeind' daemon")?
        .read_to_string(&mut pid)
        .context("Read PID-file of 'letmeind' daemon")?;
    pid.trim()
        .parse()
        .context("Parse 'letmeind' PID-file string to number")
}

/// Some basic address sanity checks.
fn addr_check(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => {
            let addr = u32::from_be_bytes(addr.octets());
            addr != 0 && addr != u32::MAX
        }
        IpAddr::V6(addr) => {
            let addr = u128::from_be_bytes(addr.octets());
            addr != 0 && addr != u128::MAX
        }
    }
}

pub struct FirewallConnection {
    stream: UnixStream,
}

impl FirewallConnection {
    fn new(stream: UnixStream) -> ah::Result<Self> {
        Ok(Self { stream })
    }

    async fn recv_msg(&mut self) -> ah::Result<Option<FirewallMessage>> {
        FirewallMessage::recv(&mut self.stream).await
    }

    async fn send_msg(&mut self, msg: &FirewallMessage) -> ah::Result<()> {
        msg.send(&mut self.stream).await
    }

    /// Handle the firewall daemon unix socket communication.
    pub async fn handle_message(
        &mut self,
        conf: &Config,
        fw: Arc<Mutex<impl FirewallOpen>>,
    ) -> ah::Result<()> {
        let Some(msg) = self.recv_msg().await? else {
            return Err(err!("Disconnected."));
        };
        match msg.operation() {
            FirewallOperation::Open => {
                // Get the address from the socket message.
                let Some(addr) = msg.addr() else {
                    self.send_msg(&FirewallMessage::new_nack()).await?;
                    return Err(err!("No addr."));
                };

                // Check if addr is valid.
                if !addr_check(&addr) {
                    self.send_msg(&FirewallMessage::new_nack()).await?;
                    return Err(err!("Invalid addr."));
                }

                // Get the port from the socket message.
                let Some((port_type, port)) = msg.port() else {
                    self.send_msg(&FirewallMessage::new_nack()).await?;
                    return Err(err!("No port."));
                };

                // Check if the port is actually configured.
                if conf.resource_id_by_port(port, None).is_none() {
                    // Whoops, letmeind should never send us a request for an
                    // unconfigured port. Did some other process write to the unix socket?
                    self.send_msg(&FirewallMessage::new_nack()).await?;
                    return Err(err!("The port {port} is not configured in letmeind.conf."));
                }

                // Don't allow the user to manage the control port.
                if port == conf.port().port {
                    // Whoops, letmeind should never send us a request for the
                    // control port. Did some other process write to the unix socket?
                    self.send_msg(&FirewallMessage::new_nack()).await?;
                    return Err(err!("The knocked port {port} is the letmein control port."));
                }

                // Convert from protocol port type to lease port type.
                let lease_port = match port_type {
                    PortType::Tcp => LeasePort::Tcp(port),
                    PortType::Udp => LeasePort::Udp(port),
                    PortType::TcpUdp => LeasePort::TcpUdp(port),
                };

                // Open the firewall.
                let ok = {
                    let mut fw = fw.lock().await;
                    fw.open_port(conf, addr, lease_port).await.is_ok()
                };

                if ok {
                    self.send_msg(&FirewallMessage::new_ack()).await?;
                } else {
                    self.send_msg(&FirewallMessage::new_nack()).await?;
                }
            }
            FirewallOperation::Close => {
                // Get the address from the socket message.
                let Some(addr) = msg.addr() else {
                    self.send_msg(&FirewallMessage::new_nack()).await?;
                    return Err(err!("No addr."));
                };

                // Check if addr is valid.
                if !addr_check(&addr) {
                    self.send_msg(&FirewallMessage::new_nack()).await?;
                    return Err(err!("Invalid addr."));
                }

                // Get the port from the socket message.
                let Some((port_type, port)) = msg.port() else {
                    self.send_msg(&FirewallMessage::new_nack()).await?;
                    return Err(err!("No port."));
                };

                // Check if the port is actually configured.
                if conf.resource_id_by_port(port, None).is_none() {
                    // Whoops, letmeind should never send us a request for an
                    // unconfigured port. Did some other process write to the unix socket?
                    self.send_msg(&FirewallMessage::new_nack()).await?;
                    return Err(err!("The port {port} is not configured in letmeind.conf."));
                }

                // Don't allow the user to manage the control port.
                if port == conf.port().port {
                    // Whoops, letmeind should never send us a request for the
                    // control port. Did some other process write to the unix socket?
                    self.send_msg(&FirewallMessage::new_nack()).await?;
                    return Err(err!("The port {port} is the letmein control port."));
                }

                // Convert from protocol port type to lease port type.
                let lease_port = match port_type {
                    PortType::Tcp => LeasePort::Tcp(port),
                    PortType::Udp => LeasePort::Udp(port),
                    PortType::TcpUdp => LeasePort::TcpUdp(port),
                };

                // Close the firewall port.
                let ok = {
                    let mut fw = fw.lock().await;
                    fw.close_port(conf, addr, lease_port).await.is_ok()
                };

                if ok {
                    self.send_msg(&FirewallMessage::new_ack()).await?;
                } else {
                    self.send_msg(&FirewallMessage::new_nack()).await?;
                }
            }
            FirewallOperation::Ack | FirewallOperation::Nack => {
                return Err(err!("Received invalid message"));
            }
        }
        Ok(())
    }
}

pub struct FirewallServer {
    listener: UnixListener,
    rundir: PathBuf,
}

impl FirewallServer {
    pub async fn new(no_systemd: bool, opts: &Opts) -> ah::Result<Self> {
        // Get socket from systemd?
        if !no_systemd {
            let sockets = SystemdSocket::get_all()?;
            if let Some(SystemdSocket::Unix(socket)) = sockets.into_iter().next() {
                println!("Using Unix socket from systemd.");

                socket
                    .set_nonblocking(true)
                    .context("Set socket non-blocking")?;
                let listener = UnixListener::from_std(socket)
                    .context("Convert std UnixListener to tokio UnixListener")?;

                systemd_notify_ready()?;

                return Ok(Self {
                    listener,
                    rundir: opts.rundir.to_owned(),
                });
            } else {
                return Err(err!("Received an unusable socket from systemd."));
            }
        }

        // Without systemd.

        // Remove the socket, if it exists.
        let runsubdir = opts.rundir.join("letmeinfwd");
        let sock_path = runsubdir.join(SOCK_FILE);
        if let Ok(meta) = metadata(&sock_path) {
            const S_IFMT: u32 = libc::S_IFMT as _;
            const S_IFSOCK: u32 = libc::S_IFSOCK as _;
            if (meta.mode() & S_IFMT) == S_IFSOCK {
                remove_file(&sock_path).context("Remove existing socket")?;
            }
        }

        // Bind to the Unix socket.
        let listener = UnixListener::bind(&sock_path).context("Bind socket")?;
        if !opts.test_mode() {
            set_owner_mode(
                &sock_path,
                0, /* root */
                LETMEIND_GID.load(Relaxed),
                0o660,
            )
            .context("Set unix socket owner and mode")?;
        }

        Ok(Self {
            listener,
            rundir: opts.rundir.to_owned(),
        })
    }

    /// Accept a connection on the Unix socket.
    pub async fn accept(&self, opts: &Opts) -> ah::Result<FirewallConnection> {
        let (stream, _addr) = self.listener.accept().await?;

        // Get the credentials of the connected process.
        let cred = stream
            .peer_cred()
            .context("Get Unix socket peer credentials")?;

        // Only the letmeind service process is allowed to connect.
        // Check the PID.
        // This check is racy, if the letmeind service is restarted. But that's Ok.
        // This is an additional check that is not strictly needed for the security
        // concept. The socket is only accessible by the `letmeind` group and user.
        let Some(pid) = cred.pid() else {
            return Err(err!("The connected pid is not known. Rejecting."));
        };
        let expected_pid = get_letmeind_pid(&self.rundir)?;
        if pid != expected_pid {
            return Err(err!(
                "The connected pid {pid} is not letmeind ({expected_pid}). Rejecting."
            ));
        }

        if !opts.test_mode() {
            // Check if the connected process is letmeind user and group.
            // This is an additional check that is not strictly needed for the security
            // concept. The socket is only accessible by the `letmeind` group and user.
            if cred.uid() != LETMEIND_UID.load(Relaxed) {
                return Err(err!(
                    "The connected uid {} is not letmeind ({}). Rejecting. \
                    Please ensure that the 'letmeind' daemon is running as 'letmeind' user.",
                    cred.uid(),
                    LETMEIND_UID.load(Relaxed),
                ));
            }
            if cred.gid() != LETMEIND_GID.load(Relaxed) {
                return Err(err!(
                    "The connected gid {} is not letmeind ({}). Rejecting. \
                    Please ensure that the 'letmeind' daemon is running as 'letmeind' group.",
                    cred.gid(),
                    LETMEIND_GID.load(Relaxed),
                ));
            }
        }

        FirewallConnection::new(stream)
    }
}

// vim: ts=4 sw=4 expandtab
