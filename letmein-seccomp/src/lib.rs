// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

#[cfg(not(any(target_os = "linux", target_os = "android")))]
std::compile_error!("letmeind server and letmein-seccomp do not support non-Linux platforms.");

use anyhow::{self as ah, Context as _};
use seccompiler::{
    apply_filter_all_threads, BpfProgram, SeccompAction, SeccompFilter, SeccompRule,
};
use std::{collections::BTreeMap, env::consts::ARCH};

macro_rules! sys {
    ($ident:ident) => {{
        #[allow(clippy::useless_conversion)]
        let id: i64 = libc::$ident.into();
        id
    }};
}

/// Returns `true` if seccomp is supported on this platform.
pub fn seccomp_supported() -> bool {
    // This is what `seccompiler` currently supports:
    cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
}

/// Abstract allow-list features that map to one or more syscalls each.
#[derive(Clone, Debug)]
pub enum Allow {
    Mmap,
    Mprotect,
    UnixConnect,
    TcpAccept,
    Read,
    Write,
    Recv,
    Send,
    Prctl,
    Signal,
    Futex,
}

/// Action to be performed, if a syscall is executed that is not in the allow-list.
#[derive(Clone, Debug)]
pub enum Action {
    /// Kill the process.
    Kill,
    /// Only log the event and keep running. See the kernel logs.
    Log,
}

/// A compiled seccomp filter program.
pub struct Filter(BpfProgram);

impl Filter {
    pub fn compile(allow: &[Allow], deny_action: Action) -> ah::Result<Self> {
        Self::compile_for_arch(allow, deny_action, ARCH)
    }

    pub fn compile_for_arch(allow: &[Allow], deny_action: Action, arch: &str) -> ah::Result<Self> {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = [
            (sys!(SYS_brk), vec![]),
            (sys!(SYS_close), vec![]),
            #[cfg(not(target_os = "android"))]
            (sys!(SYS_close_range), vec![]),
            (sys!(SYS_exit), vec![]),
            (sys!(SYS_exit_group), vec![]),
            (sys!(SYS_getpid), vec![]),
            (sys!(SYS_getrandom), vec![]),
            (sys!(SYS_gettid), vec![]),
            (sys!(SYS_madvise), vec![]),
            (sys!(SYS_munmap), vec![]),
            (sys!(SYS_sched_getaffinity), vec![]),
            (sys!(SYS_sigaltstack), vec![]),
            (sys!(SYS_nanosleep), vec![]),
            (sys!(SYS_clock_gettime), vec![]),
            (sys!(SYS_clock_getres), vec![]),
            (sys!(SYS_clock_nanosleep), vec![]),
            (sys!(SYS_gettimeofday), vec![]),
        ]
        .into();

        let add_read_write_rules = |rules: &mut BTreeMap<_, _>| {
            rules.insert(sys!(SYS_epoll_create1), vec![]);
            rules.insert(sys!(SYS_epoll_ctl), vec![]);
            rules.insert(sys!(SYS_epoll_pwait), vec![]);
            #[cfg(all(any(target_arch = "x86_64", target_arch = "arm"), target_os = "linux"))]
            rules.insert(sys!(SYS_epoll_pwait2), vec![]);
            rules.insert(sys!(SYS_epoll_wait), vec![]);
            rules.insert(sys!(SYS_lseek), vec![]);
            rules.insert(sys!(SYS_ppoll), vec![]);
            rules.insert(sys!(SYS_pselect6), vec![]);
        };

        for allow in allow {
            match *allow {
                Allow::Mmap => {
                    #[cfg(any(
                        target_arch = "x86",
                        target_arch = "x86_64",
                        target_arch = "aarch64"
                    ))]
                    rules.insert(sys!(SYS_mmap), vec![]);
                    #[cfg(any(target_arch = "x86", target_arch = "arm"))]
                    rules.insert(sys!(SYS_mmap2), vec![]);
                    rules.insert(sys!(SYS_mremap), vec![]);
                    rules.insert(sys!(SYS_munmap), vec![]);
                }
                Allow::Mprotect => {
                    rules.insert(sys!(SYS_mprotect), vec![]);
                }
                Allow::UnixConnect => {
                    rules.insert(sys!(SYS_connect), vec![]);
                    rules.insert(sys!(SYS_socket), vec![]); //TODO: Restrict to AF_UNIX
                    rules.insert(sys!(SYS_getsockopt), vec![]);
                }
                Allow::TcpAccept => {
                    rules.insert(sys!(SYS_accept4), vec![]);
                    rules.insert(sys!(SYS_socket), vec![]); //TODO: Restrict to AF_UNIX
                    rules.insert(sys!(SYS_getsockopt), vec![]);
                }
                Allow::Read => {
                    rules.insert(sys!(SYS_pread64), vec![]);
                    rules.insert(sys!(SYS_preadv2), vec![]);
                    rules.insert(sys!(SYS_read), vec![]);
                    rules.insert(sys!(SYS_readv), vec![]);
                    add_read_write_rules(&mut rules);
                }
                Allow::Write => {
                    rules.insert(sys!(SYS_fdatasync), vec![]);
                    rules.insert(sys!(SYS_fsync), vec![]);
                    rules.insert(sys!(SYS_pwrite64), vec![]);
                    rules.insert(sys!(SYS_pwritev2), vec![]);
                    rules.insert(sys!(SYS_write), vec![]);
                    rules.insert(sys!(SYS_writev), vec![]);
                    add_read_write_rules(&mut rules);
                }
                Allow::Recv => {
                    rules.insert(sys!(SYS_recvfrom), vec![]);
                    rules.insert(sys!(SYS_recvmsg), vec![]);
                    rules.insert(sys!(SYS_recvmmsg), vec![]);
                }
                Allow::Send => {
                    rules.insert(sys!(SYS_sendto), vec![]);
                    rules.insert(sys!(SYS_sendmsg), vec![]);
                    rules.insert(sys!(SYS_sendmmsg), vec![]);
                }
                Allow::Prctl => {
                    //TODO: The arguments should be restricted to what is needed.
                    rules.insert(sys!(SYS_prctl), vec![]);
                }
                Allow::Signal => {
                    rules.insert(sys!(SYS_rt_sigaction), vec![]);
                    rules.insert(sys!(SYS_rt_sigreturn), vec![]);
                    rules.insert(sys!(SYS_rt_sigprocmask), vec![]);
                }
                Allow::Futex => {
                    rules.insert(sys!(SYS_futex), vec![]);
                    rules.insert(sys!(SYS_get_robust_list), vec![]);
                    rules.insert(sys!(SYS_set_robust_list), vec![]);
                    #[cfg(all(
                        any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm"),
                        target_os = "linux"
                    ))]
                    rules.insert(sys!(SYS_futex_waitv), vec![]);
                    //rules.insert(sys!(SYS_futex_wake), vec![]);
                    //rules.insert(sys!(SYS_futex_wait), vec![]);
                    //rules.insert(sys!(SYS_futex_requeue), vec![]);
                }
            }
        }

        let filter = SeccompFilter::new(
            rules,
            match deny_action {
                Action::Kill => SeccompAction::KillProcess,
                Action::Log => SeccompAction::Log,
            },
            SeccompAction::Allow,
            arch.try_into().context("Unsupported CPU ARCH")?,
        )
        .context("Create seccomp filter")?;

        let filter: BpfProgram = filter.try_into().context("Seccomp to BPF")?;

        Ok(Self(filter))
    }

    pub fn install(&self) -> ah::Result<()> {
        apply_filter_all_threads(&self.0).context("Apply seccomp filter")
    }
}

// vim: ts=4 sw=4 expandtab
