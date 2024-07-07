// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! This crate is an abstraction of the `systemd` interfaces needed by `letmein`.

#[cfg(not(any(target_os = "linux", target_os = "android")))]
std::compile_error!("letmeind server and letmein-systemd do not support non-Linux platforms.");

use anyhow as ah;

#[cfg(any(feature = "tcp", feature = "unix"))]
use anyhow::{format_err as err, Context as _};

#[cfg(any(feature = "tcp", feature = "unix"))]
use std::{
    mem::size_of_val,
    os::fd::{FromRawFd as _, RawFd},
};

#[cfg(feature = "tcp")]
use std::net::TcpListener;

#[cfg(feature = "unix")]
use std::os::unix::net::UnixListener;

/// Check if the passed raw `fd` is a socket.
#[cfg(any(feature = "tcp", feature = "unix"))]
fn is_socket(fd: RawFd) -> bool {
    let mut stat: libc::stat64 = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstat64(fd, &mut stat) };
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
#[cfg(any(feature = "tcp", feature = "unix"))]
unsafe fn get_socket_type(fd: RawFd) -> Option<libc::c_int> {
    let mut sotype: libc::c_int = 0;
    let mut len: libc::socklen_t = size_of_val(&sotype) as _;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut sotype as *mut _ as _,
            &mut len,
        )
    };
    if ret == 0 && len >= size_of_val(&sotype) as _ {
        Some(sotype)
    } else {
        None
    }
}

/// Get the socket family of the passed socket `fd`.
///
/// SAFETY: The passed `fd` must be a socket `fd`.
#[cfg(any(feature = "tcp", feature = "unix"))]
unsafe fn get_socket_family(fd: RawFd) -> Option<libc::c_int> {
    let mut saddr: libc::sockaddr = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = size_of_val(&saddr) as _;
    let ret = unsafe { libc::getsockname(fd, &mut saddr, &mut len) };
    if ret == 0 && len >= size_of_val(&saddr) as _ {
        Some(saddr.sa_family.into())
    } else {
        None
    }
}

#[cfg(feature = "tcp")]
fn is_tcp_socket(fd: RawFd) -> bool {
    let inet46 = [Some(libc::AF_INET), Some(libc::AF_INET6)];
    // SAFETY: Check if `fd` is a socket before using the socket functions.
    unsafe {
        is_socket(fd)
            && get_socket_type(fd) == Some(libc::SOCK_STREAM)
            && inet46.contains(&get_socket_family(fd))
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

/// Create a new [TcpListener] with the socket provided by systemd.
///
/// All environment variables related to this operation will be cleared.
#[cfg(feature = "tcp")]
pub fn tcp_from_systemd() -> ah::Result<Option<TcpListener>> {
    if sd_notify::booted().unwrap_or(false) {
        for fd in sd_notify::listen_fds().context("Systemd listen_fds")? {
            if is_tcp_socket(fd) {
                // SAFETY:
                // The fd from systemd is good and lives for the lifetime of the program.
                return Ok(Some(unsafe { TcpListener::from_raw_fd(fd) }));
            }
        }
        return Err(err!(
            "Booted with systemd, but no TCP listen_fds received from systemd."
        ));
    }
    Ok(None)
}

/// Create a new [UnixListener] with the socket provided by systemd.
///
/// All environment variables related to this operation will be cleared.
#[cfg(feature = "unix")]
pub fn unix_from_systemd() -> ah::Result<Option<UnixListener>> {
    if sd_notify::booted().unwrap_or(false) {
        for fd in sd_notify::listen_fds().context("Systemd listen_fds")? {
            if is_unix_socket(fd) {
                // SAFETY:
                // The fd from systemd is good and lives for the lifetime of the program.
                return Ok(Some(unsafe { UnixListener::from_raw_fd(fd) }));
            }
        }
        return Err(err!(
            "Booted with systemd, but no Unix listen_fds received from systemd."
        ));
    }
    Ok(None)
}

/// Notify ready-status to systemd.
///
/// All environment variables related to this operation will be cleared.
pub fn systemd_notify_ready() -> ah::Result<()> {
    sd_notify::notify(true, &[sd_notify::NotifyState::Ready])?;
    Ok(())
}

// vim: ts=4 sw=4 expandtab
