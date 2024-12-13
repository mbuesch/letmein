// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use build_target::target_arch;
use letmein_seccomp::{Allow, Filter};
use std::path::Path;

const SECCOMP_ALLOW_LIST: [Allow; 28] = [
    Allow::Mmap,
    Allow::Mprotect,
    Allow::GetUidGid,
    Allow::ArchPrctl { op: None }, //TODO
    Allow::Dup,
    Allow::Pipe,
    Allow::Access,
    Allow::Open,
    Allow::Read,
    Allow::Write,
    Allow::Ioctl { op: None }, //TODO
    Allow::Fcntl { op: None },
    Allow::Stat,
    Allow::Recv,
    Allow::Send,
    Allow::Listen,
    Allow::UnixAccept,
    Allow::Netlink,
    Allow::SetSockOpt,
    Allow::Signal,
    Allow::SigAction,
    Allow::Futex,
    Allow::SetTidAddress,
    Allow::Rseq,
    Allow::Clone,
    Allow::Exec,
    Allow::Wait,
    Allow::Rlimit,
];

fn main() {
    let arch = target_arch().expect("Failed to get build target architecture");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR is not set");

    // Precompile the seccomp filters.
    Filter::precompile(&SECCOMP_ALLOW_LIST, arch.as_str(), Path::new(&out_dir))
        .expect("Failed to precompile seccomp BPF");
}

// vim: ts=4 sw=4 expandtab
