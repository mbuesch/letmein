// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! This crate is an abstraction of the `systemd` interfaces needed by `letmein`.

#[cfg(not(any(target_os = "linux", target_os = "android")))]
std::compile_error!("letmeind server and letmein-systemd do not support non-Linux platforms.");

use anyhow::{self as ah, format_err as err, Context as _};

#[cfg(any(feature = "tcp", feature = "unix"))]
use std::{
    mem::size_of_val,
    os::fd::{FromRawFd as _, RawFd},
};

#[cfg(feature = "udp")]
use std::net::UdpSocket;

#[cfg(feature = "tcp")]
use std::net::TcpListener;

#[cfg(feature = "unix")]
use std::os::unix::net::UnixListener;

#[cfg(any(feature = "udp", feature = "tcp"))]
const INET46: [Option<libc::c_int>; 2] = [Some(libc::AF_INET), Some(libc::AF_INET6)];

/// Check if the passed raw `fd` is a socket.
#[cfg(any(feature = "udp", feature = "tcp", feature = "unix"))]
fn is_socket(fd: RawFd) -> bool {
    // SAFETY: Initializing `libc::stat64` structure with zero is an allowed pattern.
    let mut stat: libc::stat64 = unsafe { std::mem::zeroed() };

    // SAFETY: The `fd` is valid and `stat` is initialized and valid.
    let ret = unsafe { libc::fstat64(fd, &raw mut stat) };

    if ret == 0 {
        const S_IFMT: libc::mode_t = libc::S_IFMT as libc::mode_t;
        const S_IFSOCK: libc::mode_t = libc::S_IFSOCK as libc::mode_t;
        (stat.st_mode as libc::mode_t & S_IFMT) == S_IFSOCK
    } else {
        false
    }
}

/// Get the socket type of the passed socket `fd`.
///
/// SAFETY: The passed `fd` must be a socket `fd`.
#[cfg(any(feature = "udp", feature = "tcp", feature = "unix"))]
unsafe fn get_socket_type(fd: RawFd) -> Option<libc::c_int> {
    let mut sotype: libc::c_int = 0;
    let sizeof_sotype: u32 = size_of_val(&sotype).try_into().expect("libc::c_int size");
    let mut len: libc::socklen_t = sizeof_sotype as _;

    // SAFETY: The `fd` is valid, `sotype` and `len` are initialized and valid.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &raw mut sotype as _,
            &raw mut len,
        )
    };

    if ret == 0 && len == sizeof_sotype as _ {
        Some(sotype)
    } else {
        None
    }
}

/// Get the socket family of the passed socket `fd`.
///
/// SAFETY: The passed `fd` must be a socket `fd`.
#[cfg(any(feature = "udp", feature = "tcp", feature = "unix"))]
unsafe fn get_socket_family(fd: RawFd) -> Option<libc::c_int> {
    // SAFETY: Initializing `libc::sockaddr` structure with zero is an allowed pattern.
    let mut saddr: libc::sockaddr = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = size_of_val(&saddr) as _;

    // SAFETY: The `fd` is valid, `saddr` and `len` are initialized and valid.
    let ret = unsafe { libc::getsockname(fd, &raw mut saddr, &raw mut len) };

    if ret == 0 && len >= size_of_val(&saddr) as _ {
        Some(saddr.sa_family.into())
    } else {
        None
    }
}

#[cfg(feature = "udp")]
fn is_udp_socket(fd: RawFd) -> bool {
    // SAFETY: Check if `fd` is a socket before using the socket functions.
    unsafe {
        is_socket(fd)
            && get_socket_type(fd) == Some(libc::SOCK_DGRAM)
            && INET46.contains(&get_socket_family(fd))
    }
}

#[cfg(feature = "tcp")]
fn is_tcp_socket(fd: RawFd) -> bool {
    // SAFETY: Check if `fd` is a socket before using the socket functions.
    unsafe {
        is_socket(fd)
            && get_socket_type(fd) == Some(libc::SOCK_STREAM)
            && INET46.contains(&get_socket_family(fd))
    }
}

#[cfg(feature = "unix")]
fn is_unix_socket(fd: RawFd) -> bool {
    // SAFETY: Check if `fd` is a socket before using the socket functions.
    unsafe {
        is_socket(fd)
            && get_socket_type(fd) == Some(libc::SOCK_STREAM)
            && get_socket_family(fd) == Some(libc::AF_UNIX)
    }
}

/// A socket that systemd handed us over.
#[derive(Debug)]
#[non_exhaustive]
pub enum SystemdSocket {
    /// UDP socket.
    #[cfg(feature = "udp")]
    Udp(UdpSocket),

    /// TCP socket.
    #[cfg(feature = "tcp")]
    Tcp(TcpListener),

    /// Unix socket.
    #[cfg(feature = "unix")]
    Unix(UnixListener),
}

impl SystemdSocket {
    /// Get all sockets from systemd.
    ///
    /// All environment variables related to this operation will be cleared.
    #[allow(unused_mut)]
    pub fn get_all() -> ah::Result<Vec<SystemdSocket>> {
        let mut sockets = vec![];
        if sd_notify::booted().unwrap_or(false) {
            for fd in sd_notify::listen_fds().context("Systemd listen_fds")? {
                #[cfg(feature = "udp")]
                if is_udp_socket(fd) {
                    // SAFETY:
                    // The fd from systemd is good and lives for the lifetime of the program.
                    let sock = unsafe { UdpSocket::from_raw_fd(fd) };
                    sockets.push(SystemdSocket::Udp(sock));
                    continue;
                }

                #[cfg(feature = "tcp")]
                if is_tcp_socket(fd) {
                    // SAFETY:
                    // The fd from systemd is good and lives for the lifetime of the program.
                    let sock = unsafe { TcpListener::from_raw_fd(fd) };
                    sockets.push(SystemdSocket::Tcp(sock));
                    continue;
                }

                #[cfg(feature = "unix")]
                if is_unix_socket(fd) {
                    // SAFETY:
                    // The fd from systemd is good and lives for the lifetime of the program.
                    let sock = unsafe { UnixListener::from_raw_fd(fd) };
                    sockets.push(SystemdSocket::Unix(sock));
                    continue;
                }

                let _ = fd;
                return Err(err!("Received unknown socket from systemd"));
            }
        }
        Ok(sockets)
    }
}

/// Notify ready-status to systemd.
///
/// All environment variables related to this operation will be cleared.
pub fn systemd_notify_ready() -> ah::Result<()> {
    sd_notify::notify(true, &[sd_notify::NotifyState::Ready])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_systemd() {
        assert!(SystemdSocket::get_all().unwrap().is_empty());

        systemd_notify_ready().unwrap();
    }
}

// vim: ts=4 sw=4 expandtab
