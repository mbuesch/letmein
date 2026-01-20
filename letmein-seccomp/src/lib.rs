// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_possible_wrap)]

#[cfg(not(any(target_os = "linux", target_os = "android")))]
std::compile_error!("letmeind server and letmein-seccomp do not support non-Linux platforms.");

use anyhow::{self as ah, Context as _};
use seccompiler::{apply_filter_all_threads, BpfProgram};
use std::env::consts::ARCH;

#[cfg(has_seccomp_support)]
const NULL: u64 = 0;
#[cfg(has_seccomp_support)]
const PTR: u8 = 0xFF;

#[cfg(has_seccomp_support)]
macro_rules! sys {
    ($ident:ident) => {{
        #[allow(clippy::useless_conversion)]
        let id: i64 = libc::$ident.into();
        id
    }};
}

#[cfg(has_seccomp_support)]
#[allow(clippy::cast_sign_loss)]
fn seccomp_cond(idx: u8, value: i64, bit_width: u8) -> ah::Result<seccompiler::SeccompCondition> {
    use seccompiler::{SeccompCmpArgLen, SeccompCmpOp, SeccompCondition};

    let value = value as u64;

    let bit_width = match bit_width {
        PTR => {
            #[cfg(target_pointer_width = "32")]
            let bit_width = 32;

            #[cfg(target_pointer_width = "64")]
            let bit_width = 64;

            bit_width
        }
        bit_width => bit_width,
    };

    let arglen = match bit_width {
        32 => {
            if value & 0x8000_0000 == 0 {
                assert_eq!(value & 0xFFFF_FFFF_0000_0000, 0);
            } else {
                assert_eq!(value & 0xFFFF_FFFF_0000_0000, 0xFFFF_FFFF_0000_0000);
            }
            SeccompCmpArgLen::Dword
        }
        64 => SeccompCmpArgLen::Qword,
        bit_width => panic!("seccomp_cond: Invalid bit_width: {bit_width}"),
    };

    Ok(SeccompCondition::new(idx, arglen, SeccompCmpOp::Eq, value)?)
}

#[cfg(has_seccomp_support)]
macro_rules! args {
    ($([ $arg:literal ] ($bit_width:expr) == $value:expr),*) => {
        SeccompRule::new(
            vec![
                $(
                    seccomp_cond($arg, ($value) as _, $bit_width)?,
                )*
            ]
        )?
    };
}

/// Returns `true` if seccomp is supported on this platform.
#[must_use]
pub fn seccomp_supported() -> bool {
    cfg!(any(has_seccomp_support))
}

/// Abstract allow-list features that map to one or more syscalls each.
#[derive(Clone, Copy, Debug)]
pub enum Allow {
    Mmap,
    Mprotect,
    GetUidGid,
    ArchPrctl { op: Option<u32> },
    Dup,
    Pipe,
    Listen,
    UnixAccept,
    UnixConnect,
    TcpAccept,
    TcpConnect,
    Netlink,
    SetSockOpt { level_optname: Option<(i32, i32)> },
    Access,
    Open,
    Read,
    Write,
    Ioctl { op: Option<u32> },
    Fcntl { op: Option<u32> },
    Stat,
    Recv,
    Send,
    Signal,
    SigAction,
    Futex,
    SetTidAddress,
    Rseq,
    Clone,
    Exec,
    Wait,
    GetRlimit,
    Uname,
    Pidfd,
}

/// Action to be performed, if a syscall is executed that is not in the allow-list.
#[derive(Clone, Copy, Debug)]
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

    #[cfg(has_seccomp_support)]
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::items_after_statements)]
    pub fn compile_for_arch(allow: &[Allow], deny_action: Action, arch: &str) -> ah::Result<Self> {
        assert!(!allow.is_empty());

        use seccompiler::{SeccompAction, SeccompFilter, SeccompRule};
        use std::collections::BTreeMap;

        type RulesMap = BTreeMap<i64, Vec<SeccompRule>>;

        fn add_sys(map: &mut RulesMap, sys: i64) {
            let _rules = map.entry(sys).or_default();
        }

        fn add_sys_args_match(map: &mut RulesMap, sys: i64, rule: SeccompRule) {
            let rules = map.entry(sys).or_default();
            rules.push(rule);
        }

        let mut map: RulesMap = [].into();

        add_sys(&mut map, sys!(SYS_brk));
        add_sys(&mut map, sys!(SYS_close));
        #[cfg(target_os = "linux")]
        add_sys(&mut map, sys!(SYS_close_range));
        add_sys(&mut map, sys!(SYS_exit));
        add_sys(&mut map, sys!(SYS_exit_group));
        add_sys(&mut map, sys!(SYS_getpid));
        add_sys(&mut map, sys!(SYS_getrandom));
        add_sys(&mut map, sys!(SYS_gettid));
        add_sys(&mut map, sys!(SYS_madvise));
        add_sys(&mut map, sys!(SYS_munmap));
        add_sys(&mut map, sys!(SYS_sched_getaffinity));
        add_sys(&mut map, sys!(SYS_sigaltstack));
        add_sys(&mut map, sys!(SYS_nanosleep));
        add_sys(&mut map, sys!(SYS_clock_gettime));
        add_sys(&mut map, sys!(SYS_clock_getres));
        add_sys(&mut map, sys!(SYS_clock_nanosleep));
        add_sys(&mut map, sys!(SYS_gettimeofday));

        fn add_read_write_rules(map: &mut RulesMap) {
            add_sys(map, sys!(SYS_epoll_create1));
            add_sys(map, sys!(SYS_epoll_ctl));
            add_sys(map, sys!(SYS_epoll_pwait));
            #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
            add_sys(map, sys!(SYS_epoll_pwait2));
            #[cfg(target_arch = "x86_64")]
            add_sys(map, sys!(SYS_epoll_wait));
            add_sys(map, sys!(SYS_lseek));
            #[cfg(target_arch = "x86_64")]
            add_sys(map, sys!(SYS_poll));
            add_sys(map, sys!(SYS_ppoll));
            add_sys(map, sys!(SYS_pselect6));
        }

        for allow in allow {
            match *allow {
                Allow::Mmap => {
                    add_sys(&mut map, sys!(SYS_mmap));
                    add_sys(&mut map, sys!(SYS_mremap));
                    add_sys(&mut map, sys!(SYS_munmap));
                }
                Allow::Mprotect => {
                    add_sys(&mut map, sys!(SYS_mprotect));
                }
                Allow::GetUidGid => {
                    add_sys(&mut map, sys!(SYS_getuid));
                    add_sys(&mut map, sys!(SYS_geteuid));
                    add_sys(&mut map, sys!(SYS_getgid));
                    add_sys(&mut map, sys!(SYS_getegid));
                }
                Allow::ArchPrctl { op: _ } => {
                    //TODO restrict to op
                    #[cfg(target_arch = "x86_64")]
                    add_sys(&mut map, sys!(SYS_arch_prctl));
                }
                Allow::Dup => {
                    add_sys(&mut map, sys!(SYS_dup));
                    #[cfg(target_arch = "x86_64")]
                    add_sys(&mut map, sys!(SYS_dup2));
                    add_sys(&mut map, sys!(SYS_dup3));
                }
                Allow::Pipe => {
                    #[cfg(target_arch = "x86_64")]
                    add_sys(&mut map, sys!(SYS_pipe));
                    add_sys(&mut map, sys!(SYS_pipe2));
                }
                Allow::Listen => {
                    add_sys(&mut map, sys!(SYS_bind));
                    add_sys(&mut map, sys!(SYS_listen));
                }
                Allow::UnixAccept => {
                    add_sys(&mut map, sys!(SYS_accept4));
                    add_sys_args_match(&mut map, sys!(SYS_socket), args!([0](32) == libc::AF_UNIX));
                    add_sys(&mut map, sys!(SYS_getsockopt));
                    add_sys(&mut map, sys!(SYS_getpeername));
                }
                Allow::UnixConnect => {
                    add_sys(&mut map, sys!(SYS_connect));
                    add_sys_args_match(&mut map, sys!(SYS_socket), args!([0](32) == libc::AF_UNIX));
                    add_sys(&mut map, sys!(SYS_getsockopt));
                    add_sys(&mut map, sys!(SYS_getpeername));
                }
                Allow::TcpAccept => {
                    add_sys(&mut map, sys!(SYS_accept4));
                    add_sys_args_match(&mut map, sys!(SYS_socket), args!([0](32) == libc::AF_INET));
                    add_sys_args_match(
                        &mut map,
                        sys!(SYS_socket),
                        args!([0](32) == libc::AF_INET6),
                    );
                    add_sys(&mut map, sys!(SYS_getsockopt));
                    add_sys(&mut map, sys!(SYS_getpeername));
                }
                Allow::TcpConnect => {
                    add_sys(&mut map, sys!(SYS_connect));
                    add_sys_args_match(&mut map, sys!(SYS_socket), args!([0](32) == libc::AF_INET));
                    add_sys_args_match(
                        &mut map,
                        sys!(SYS_socket),
                        args!([0](32) == libc::AF_INET6),
                    );
                    add_sys(&mut map, sys!(SYS_getsockopt));
                    add_sys(&mut map, sys!(SYS_getpeername));
                }
                Allow::Netlink => {
                    add_sys(&mut map, sys!(SYS_connect));
                    add_sys_args_match(
                        &mut map,
                        sys!(SYS_socket),
                        args!([0](32) == libc::AF_NETLINK),
                    );
                    add_sys(&mut map, sys!(SYS_getsockopt));
                }
                Allow::SetSockOpt { level_optname } => {
                    if let Some((level, optname)) = level_optname {
                        add_sys_args_match(
                            &mut map,
                            sys!(SYS_setsockopt),
                            args!([1](32) == level, [2](32) == optname),
                        );
                    } else {
                        add_sys(&mut map, sys!(SYS_setsockopt));
                    }
                }
                Allow::Access => {
                    #[cfg(target_arch = "x86_64")]
                    add_sys(&mut map, sys!(SYS_access));
                    add_sys(&mut map, sys!(SYS_faccessat));
                    #[cfg(target_os = "linux")]
                    add_sys(&mut map, sys!(SYS_faccessat2));
                }
                Allow::Open => {
                    //TODO: This should be restricted
                    #[cfg(target_arch = "x86_64")]
                    add_sys(&mut map, sys!(SYS_open));
                    add_sys(&mut map, sys!(SYS_openat));
                }
                Allow::Read => {
                    add_sys(&mut map, sys!(SYS_pread64));
                    add_sys(&mut map, sys!(SYS_preadv2));
                    add_sys(&mut map, sys!(SYS_read));
                    add_sys(&mut map, sys!(SYS_readv));
                    add_read_write_rules(&mut map);
                }
                Allow::Write => {
                    add_sys(&mut map, sys!(SYS_fdatasync));
                    add_sys(&mut map, sys!(SYS_fsync));
                    add_sys(&mut map, sys!(SYS_pwrite64));
                    add_sys(&mut map, sys!(SYS_pwritev2));
                    add_sys(&mut map, sys!(SYS_write));
                    add_sys(&mut map, sys!(SYS_writev));
                    add_read_write_rules(&mut map);
                }
                Allow::Ioctl { op: _ } => {
                    //TODO restrict to op
                    add_sys(&mut map, sys!(SYS_ioctl));
                }
                Allow::Fcntl { op } => match op {
                    Some(op) => {
                        add_sys_args_match(&mut map, sys!(SYS_fcntl), args!([1](32) == op));
                    }
                    None => {
                        add_sys(&mut map, sys!(SYS_fcntl));
                    }
                },
                Allow::Stat => {
                    add_sys(&mut map, sys!(SYS_fstat));
                    add_sys(&mut map, sys!(SYS_statx));
                    add_sys(&mut map, sys!(SYS_newfstatat));
                }
                Allow::Recv => {
                    add_sys(&mut map, sys!(SYS_recvfrom));
                    add_sys(&mut map, sys!(SYS_recvmsg));
                    add_sys(&mut map, sys!(SYS_recvmmsg));
                }
                Allow::Send => {
                    add_sys(&mut map, sys!(SYS_sendto));
                    add_sys(&mut map, sys!(SYS_sendmsg));
                    add_sys(&mut map, sys!(SYS_sendmmsg));
                }
                Allow::Signal => {
                    add_sys(&mut map, sys!(SYS_rt_sigreturn));
                    add_sys(&mut map, sys!(SYS_rt_sigprocmask));
                }
                Allow::SigAction => {
                    add_sys(&mut map, sys!(SYS_rt_sigaction));
                }
                Allow::Futex => {
                    add_sys(&mut map, sys!(SYS_futex));
                    add_sys(&mut map, sys!(SYS_get_robust_list));
                    add_sys(&mut map, sys!(SYS_set_robust_list));
                    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
                    add_sys(&mut map, sys!(SYS_futex_waitv));
                    //add_sys(&mut map, sys!(SYS_futex_wake));
                    //add_sys(&mut map, sys!(SYS_futex_wait));
                    //add_sys(&mut map, sys!(SYS_futex_requeue));
                }
                Allow::SetTidAddress => {
                    add_sys(&mut map, sys!(SYS_set_tid_address));
                }
                Allow::Rseq => {
                    #[cfg(target_os = "linux")]
                    add_sys(&mut map, sys!(SYS_rseq));
                }
                Allow::Clone => {
                    #[cfg(target_os = "linux")]
                    add_sys(&mut map, sys!(SYS_clone3));
                    #[cfg(target_arch = "aarch64")]
                    add_sys(&mut map, sys!(SYS_clone));
                }
                Allow::Exec => {
                    //TODO restrict the path
                    add_sys(&mut map, sys!(SYS_execve));
                }
                Allow::Wait => {
                    add_sys(&mut map, sys!(SYS_wait4));
                }
                Allow::GetRlimit => {
                    add_sys_args_match(
                        &mut map,
                        sys!(SYS_prlimit64),
                        args!([0](32) == 0, [2](PTR) == NULL),
                    );
                }
                Allow::Uname => {
                    add_sys(&mut map, sys!(SYS_uname));
                }
                Allow::Pidfd => {
                    add_sys(&mut map, sys!(SYS_pidfd_open));
                }
            }
        }

        let filter = SeccompFilter::new(
            map,
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

    #[cfg(not(has_seccomp_support))]
    pub fn compile_for_arch(
        _allow: &[Allow],
        _deny_action: Action,
        _arch: &str,
    ) -> ah::Result<Self> {
        Err(ah::format_err!("seccomp is not supported on this platform"))
    }

    pub fn install(&self) -> ah::Result<()> {
        apply_filter_all_threads(&self.0).context("Apply seccomp filter")
    }
}

// vim: ts=4 sw=4 expandtab
