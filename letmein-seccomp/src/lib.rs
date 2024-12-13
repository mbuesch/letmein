// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]
#![allow(unused_imports)]

#[cfg(not(any(target_os = "linux", target_os = "android")))]
std::compile_error!("letmeind server and letmein-seccomp do not support non-Linux platforms.");

use anyhow::{self as ah, Context as _};
use seccompiler::{
    apply_filter_all_threads, sock_filter, BpfProgram, SeccompAction, SeccompCmpArgLen,
    SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
};
use std::{collections::BTreeMap, env::consts::ARCH, fs::OpenOptions, io::Write as _, path::Path};

/// Include the raw serialized bytes of the precompiled seccomp BPF code.
#[cfg(all(feature = "install", feature = "de"))]
#[macro_export]
macro_rules! include_precompiled_filters {
    ($kill:ident, $log:ident) => {
        const $kill: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/seccomp_filter_kill.bpf"));
        const $log: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/seccomp_filter_log.bpf"));
    };
}

#[cfg(feature = "compile")]
macro_rules! sys {
    ($ident:ident) => {{
        #[allow(clippy::useless_conversion)]
        let id: i64 = libc::$ident.into();
        id
    }};
}

#[cfg(feature = "compile")]
macro_rules! args {
    ($($arg:literal == $value:expr),*) => {
        SeccompRule::new(
            vec![
                $(
                    SeccompCondition::new(
                        $arg,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::Eq,
                        ($value) as _,
                    )?,
                )*
            ]
        )?
    };
}

/// Returns `true` if seccomp is supported on this platform.
pub fn seccomp_supported() -> bool {
    // This is what `seccompiler` currently supports:
    cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
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
    SetSockOpt,
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
    Rlimit,
    Uname,
}

/// Action to be performed, if a syscall is executed that is not in the allow-list.
#[derive(Clone, Copy, Debug)]
pub enum Action {
    /// Kill the process.
    Kill,
    /// Only log the event and keep running. See the kernel logs.
    Log,
}

impl Action {
    /// Get the file name of the precompiled BPF file for this action.
    pub const fn get_bytecode_filename(&self) -> &'static str {
        match self {
            Action::Kill => "seccomp_filter_kill.bpf",
            Action::Log => "seccomp_filter_log.bpf",
        }
    }
}

/// A compiled seccomp filter program.
#[allow(dead_code)]
pub struct Filter(BpfProgram);

impl Filter {
    /// Simple serialization, without serde.
    #[cfg(feature = "ser")]
    pub fn serialize(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(self.0.len() * 8);
        for insn in &self.0 {
            raw.extend_from_slice(&insn.code.to_le_bytes());
            raw.push(insn.jt);
            raw.push(insn.jf);
            raw.extend_from_slice(&insn.k.to_le_bytes());
        }
        assert_eq!(raw.len(), self.0.len() * 8);
        assert!(!raw.is_empty());
        raw
    }

    /// Simple de-serialization, without serde.
    #[cfg(feature = "de")]
    pub fn deserialize(raw: &[u8]) -> Self {
        assert!(!raw.is_empty());
        assert_eq!(raw.len() % 8, 0);
        let mut bpf = Vec::with_capacity(raw.len() / 8);
        for i in (0..raw.len()).step_by(8) {
            let code = u16::from_le_bytes(raw[i..i + 2].try_into().unwrap());
            let jt = raw[i + 2];
            let jf = raw[i + 3];
            let k = u32::from_le_bytes(raw[i + 4..i + 8].try_into().unwrap());
            bpf.push(sock_filter { code, jt, jf, k });
        }
        assert_eq!(bpf.len(), raw.len() / 8);
        Self(bpf)
    }

    /// Pre-compile the given allow-list for the given `arch` for
    /// [Action::Kill] and [Action::Log] actions
    /// and put the BPF byte code into files in the `out_dir`.
    ///
    /// See [Action::get_bytecode_filename] for the file names used.
    ///
    /// If compilation fails, empty files will be written.
    #[cfg(all(feature = "compile", feature = "ser"))]
    pub fn precompile(allow: &[Allow], arch: &str, out_dir: &Path) -> ah::Result<()> {
        Self::precompile_action(allow, Action::Kill, arch, out_dir)?;
        Self::precompile_action(allow, Action::Log, arch, out_dir)?;
        Ok(())
    }

    /// Pre-compile the given allow-list for the given `arch` and `deny_action`.
    /// and put the BPF byte code into a file in the `out_dir`.
    ///
    /// See [Action::get_bytecode_filename] for the file name used.
    ///
    /// If compilation fails, an empty file will be written.
    #[cfg(all(feature = "compile", feature = "ser"))]
    pub fn precompile_action(
        allow: &[Allow],
        deny_action: Action,
        arch: &str,
        out_dir: &Path,
    ) -> ah::Result<()> {
        let filter = Self::compile_for_arch(allow, deny_action, arch)
            .map(|filter| filter.serialize())
            .unwrap_or_default();
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(out_dir.join(deny_action.get_bytecode_filename()))?
            .write_all(&filter)?;
        Ok(())
    }

    #[cfg(feature = "compile")]
    pub fn compile(allow: &[Allow], deny_action: Action) -> ah::Result<Self> {
        Self::compile_for_arch(allow, deny_action, ARCH)
    }

    #[cfg(feature = "compile")]
    pub fn compile_for_arch(allow: &[Allow], deny_action: Action, arch: &str) -> ah::Result<Self> {
        assert!(!allow.is_empty());

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
        #[cfg(not(target_os = "android"))]
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
            #[cfg(all(any(target_arch = "x86_64", target_arch = "arm"), target_os = "linux"))]
            add_sys(map, sys!(SYS_epoll_pwait2));
            add_sys(map, sys!(SYS_epoll_wait));
            add_sys(map, sys!(SYS_lseek));
            add_sys(map, sys!(SYS_poll));
            add_sys(map, sys!(SYS_ppoll));
            add_sys(map, sys!(SYS_pselect6));
        }

        for allow in allow {
            match *allow {
                Allow::Mmap => {
                    #[cfg(any(
                        target_arch = "x86",
                        target_arch = "x86_64",
                        target_arch = "aarch64"
                    ))]
                    add_sys(&mut map, sys!(SYS_mmap));
                    #[cfg(any(target_arch = "x86", target_arch = "arm"))]
                    add_sys(&mut map, sys!(SYS_mmap2));
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
                    add_sys(&mut map, sys!(SYS_dup2));
                    add_sys(&mut map, sys!(SYS_dup3));
                }
                Allow::Pipe => {
                    add_sys(&mut map, sys!(SYS_pipe));
                    add_sys(&mut map, sys!(SYS_pipe2));
                }
                Allow::Listen => {
                    add_sys(&mut map, sys!(SYS_bind));
                    add_sys(&mut map, sys!(SYS_listen));
                }
                Allow::UnixAccept => {
                    add_sys(&mut map, sys!(SYS_accept4));
                    add_sys_args_match(&mut map, sys!(SYS_socket), args!(0 == libc::AF_UNIX));
                    add_sys(&mut map, sys!(SYS_getsockopt));
                }
                Allow::UnixConnect => {
                    add_sys(&mut map, sys!(SYS_connect));
                    add_sys_args_match(&mut map, sys!(SYS_socket), args!(0 == libc::AF_UNIX));
                    add_sys(&mut map, sys!(SYS_getsockopt));
                }
                Allow::TcpAccept => {
                    add_sys(&mut map, sys!(SYS_accept4));
                    add_sys_args_match(&mut map, sys!(SYS_socket), args!(0 == libc::AF_INET));
                    add_sys_args_match(&mut map, sys!(SYS_socket), args!(0 == libc::AF_INET6));
                    add_sys(&mut map, sys!(SYS_getsockopt));
                }
                Allow::TcpConnect => {
                    add_sys(&mut map, sys!(SYS_connect));
                    add_sys_args_match(&mut map, sys!(SYS_socket), args!(0 == libc::AF_INET));
                    add_sys_args_match(&mut map, sys!(SYS_socket), args!(0 == libc::AF_INET6));
                    add_sys(&mut map, sys!(SYS_getsockopt));
                }
                Allow::Netlink => {
                    add_sys(&mut map, sys!(SYS_connect));
                    add_sys_args_match(&mut map, sys!(SYS_socket), args!(0 == libc::AF_NETLINK));
                    add_sys(&mut map, sys!(SYS_getsockopt));
                }
                Allow::SetSockOpt => {
                    add_sys(&mut map, sys!(SYS_setsockopt));
                }
                Allow::Access => {
                    add_sys(&mut map, sys!(SYS_access));
                    add_sys(&mut map, sys!(SYS_faccessat));
                    #[cfg(not(target_os = "android"))]
                    add_sys(&mut map, sys!(SYS_faccessat2));
                }
                Allow::Open => {
                    //TODO: This should be restricted
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
                        add_sys_args_match(&mut map, sys!(SYS_fcntl), args!(1 == op));
                    }
                    None => {
                        add_sys(&mut map, sys!(SYS_fcntl));
                    }
                },
                Allow::Stat => {
                    add_sys(&mut map, sys!(SYS_fstat));
                    add_sys(&mut map, sys!(SYS_statx));
                    #[cfg(target_arch = "x86_64")]
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
                    #[cfg(all(
                        any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm"),
                        target_os = "linux"
                    ))]
                    add_sys(&mut map, sys!(SYS_futex_waitv));
                    //add_sys(&mut map, sys!(SYS_futex_wake));
                    //add_sys(&mut map, sys!(SYS_futex_wait));
                    //add_sys(&mut map, sys!(SYS_futex_requeue));
                }
                Allow::SetTidAddress => {
                    add_sys(&mut map, sys!(SYS_set_tid_address));
                }
                Allow::Rseq => {
                    #[cfg(not(target_os = "android"))]
                    add_sys(&mut map, sys!(SYS_rseq));
                }
                Allow::Clone => {
                    #[cfg(not(target_os = "android"))]
                    add_sys(&mut map, sys!(SYS_clone3));
                }
                Allow::Exec => {
                    //TODO restrict the path
                    add_sys(&mut map, sys!(SYS_execve));
                }
                Allow::Wait => {
                    add_sys(&mut map, sys!(SYS_wait4));
                }
                Allow::Rlimit => {
                    //TODO do we only need `get`?
                    add_sys(&mut map, sys!(SYS_prlimit64));
                }
                Allow::Uname => {
                    add_sys(&mut map, sys!(SYS_uname));
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

    #[cfg(feature = "install")]
    pub fn install(&self) -> ah::Result<()> {
        apply_filter_all_threads(&self.0).context("Apply seccomp filter")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_filter_serialize() {
        if seccomp_supported() {
            let filter = Filter::compile(&[Allow::Read], Action::Kill).unwrap();
            let filter2 = Filter::deserialize(&filter.serialize());
            assert_eq!(filter.0.len(), filter2.0.len());
            for i in 0..filter.0.len() {
                assert_eq!(filter.0[i], filter2.0[i]);
            }
        }
    }
}

// vim: ts=4 sw=4 expandtab
