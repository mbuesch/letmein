// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use build_target::target_arch;
use std::path::Path;

#[cfg(any(target_os = "linux", target_os = "android"))]
use letmein_seccomp::{Allow, Filter};

#[cfg(any(target_os = "linux", target_os = "android"))]
const SECCOMP_ALLOW_LIST: [Allow; 13] = [
    Allow::Mmap,
    Allow::Mprotect,
    Allow::Open,
    Allow::Read,
    Allow::Write,
    Allow::Fcntl {
        op: libc::F_GETFD as _,
    },
    Allow::Stat,
    Allow::Recv,
    Allow::Send,
    Allow::Listen,
    Allow::TcpConnect,
    Allow::Futex,
    Allow::Uname,
];

fn main() {
    let arch = target_arch().expect("Failed to get build target architecture");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR is not set");

    // Precompile the seccomp filters.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Filter::precompile(&SECCOMP_ALLOW_LIST, arch.as_str(), Path::new(&out_dir))
        .expect("Failed to precompile seccomp BPF");
}

// vim: ts=4 sw=4 expandtab
