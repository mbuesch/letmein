// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use build_target::{target_arch, Arch};
use letmein_seccomp::{Action, Allow, Filter};
use std::{env, fs::OpenOptions, io::Write, path::Path};

const SECCOMP_ALLOW_LIST: [Allow; 10] = [
    Allow::Mmap,
    Allow::Mprotect,
    Allow::Read,
    Allow::Write,
    Allow::Recv,
    Allow::Send,
    Allow::TcpAccept,
    Allow::UnixConnect,
    Allow::Signal,
    Allow::Futex,
];

fn seccomp_compile_action(arch: &Arch, action: Action) {
    let filter =
        if let Ok(filter) = Filter::compile_for_arch(&SECCOMP_ALLOW_LIST, action, arch.as_str()) {
            filter.serialize()
        } else {
            vec![]
        };

    let suffix = match action {
        Action::Kill => "kill",
        Action::Log => "log",
    };

    let filter_file = format!("seccomp_filter_{suffix}.bpf");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR is not set");

    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(Path::new(&out_dir).join(filter_file))
        .expect("Failed to open filter.bpf")
        .write_all(&filter)
        .expect("Failed to write filter.bpf");
}

fn seccomp_compile(arch: &Arch) {
    seccomp_compile_action(arch, Action::Kill);
    seccomp_compile_action(arch, Action::Log);
}

fn main() {
    let arch = target_arch().expect("Failed to get build target architecture");
    seccomp_compile(&arch);
}

// vim: ts=4 sw=4 expandtab
