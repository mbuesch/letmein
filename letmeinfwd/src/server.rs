// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    firewall::{FirewallAction, LeasePort},
    set_owner_mode, Opts, LETMEIND_GID, LETMEIND_UID,
};
use anyhow::{self as ah, format_err as err, Context as _};
use letmein_conf::{Config, Resource};
use letmein_fwproto::{FirewallMessage, FirewallOperation, SOCK_FILE};
use letmein_systemd::{systemd_notify_ready, SystemdSocket};
use std::{
    fs::{metadata, remove_file, OpenOptions},
    io::Read as _,
    net::IpAddr,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    sync::{atomic::Ordering::Relaxed, Arc},
};
use tokio::net::{unix::pid_t, UnixListener, UnixStream};

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

    async fn send_result<T>(&mut self, res: ah::Result<T>) -> ah::Result<T> {
        if res.is_ok() {
            self.send_msg(&FirewallMessage::new_ack()).await?;
        } else {
            self.send_msg(&FirewallMessage::new_nack()).await?;
        }
        res
    }

    async fn check_conf_checksum(
        &mut self,
        conf: &Config,
        msg: &FirewallMessage,
    ) -> ah::Result<()> {
        let Some(conf_cs) = msg.conf_checksum() else {
            let res = Err(err!("No configuration checksum in message."));
            return self.send_result(res).await;
        };
        if *conf_cs != *conf.checksum() {
            let res = Err(err!(
                "letmeind.conf checksum mismatch between letmeind and letmeinfwd."
            ));
            return self.send_result(res).await;
        }
        Ok(())
    }

    async fn get_addr(&mut self, msg: &FirewallMessage) -> ah::Result<IpAddr> {
        let Some(addr) = msg.addr() else {
            let res = Err(err!("No address in message."));
            return self.send_result(res).await;
        };
        // Check if addr is valid.
        if !addr_check(&addr) {
            let res = Err(err!("Invalid address in message."));
            return self.send_result(res).await;
        }
        Ok(addr)
    }

    async fn get_resource(&mut self, conf: &Config, msg: &FirewallMessage) -> ah::Result<Resource> {
        // Get the resource and user IDs.
        let resource_id = msg.resource();
        let user_id = msg.user();

        // Get the resource from the configuration.
        let Some(resource) = conf.resource(resource_id) else {
            let res = Err(err!(
                "The resource {resource_id} is not configured in letmeind.conf."
            ));
            return self.send_result(res).await;
        };

        // Check if the user is allowed to use the resource.
        if !resource.contains_user(user_id) {
            let res = Err(err!(
                "The resource {resource_id} is not allowed for user {user_id}."
            ));
            return self.send_result(res).await;
        }

        Ok(resource.clone())
    }

    /// Handle the firewall daemon unix socket communication.
    pub async fn handle_message(
        &mut self,
        conf: &Config,
        fw: Arc<impl FirewallAction>,
    ) -> ah::Result<()> {
        let Some(msg) = self.recv_msg().await? else {
            return Err(err!("Disconnected."));
        };

        // Compare the configuration checksum to ensure that
        // letmeind and letmeinfwd have the same view of the configuration.
        self.check_conf_checksum(conf, &msg).await?;

        // Get the address from the socket message.
        let addr = self.get_addr(&msg).await?;

        // Get the resource from the socket message.
        let resource = self.get_resource(conf, &msg).await?;
        let timeout = resource.timeout();

        match msg.operation() {
            FirewallOperation::Install => match &resource {
                Resource::Port { .. } => {
                    let port: LeasePort = resource.try_into().expect("Not a port resource");

                    // Don't allow the user to manage the control port.
                    if port.port() == conf.port().port {
                        // Whoops, letmeind should never send us a request for the
                        // control port. Did some other process write to the unix socket?
                        let res = Err(err!("The knocked port {port} is the letmein control port."));
                        return self.send_result(res).await;
                    }

                    // Open the firewall.
                    let res = fw.open_port(conf, addr, port, timeout).await;
                    self.send_result(res).await
                }
                Resource::Jump { .. } => {
                    let targets = resource.try_into().expect("Not a jump resource");

                    // Add the jump-rules to the firewall.
                    let res = fw.add_jump(conf, addr, &targets, timeout).await;
                    self.send_result(res).await
                }
            },
            FirewallOperation::Revoke => match &resource {
                Resource::Port { .. } => {
                    let lease_port = resource.try_into().expect("Not a port resource");

                    // Close the port.
                    let res = fw.revoke_port(conf, addr, lease_port).await;
                    self.send_result(res).await
                }
                Resource::Jump { .. } => {
                    let targets = resource.try_into().expect("Not a jump resource");

                    // Remove the jump-rules from the firewall.
                    let res = fw.revoke_jump(conf, addr, &targets).await;
                    self.send_result(res).await
                }
            },
            FirewallOperation::Ack | FirewallOperation::Nack => {
                Err(err!("Received invalid message"))
            }
        }
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
