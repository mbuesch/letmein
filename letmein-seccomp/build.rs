// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

fn probe_syscall(ac: &autocfg::AutoCfg, name: &str) {
    ac.emit_path_cfg(&format!("libc::SYS_{name}"), &format!("has_SYS_{name}"));
    println!("cargo:rustc-check-cfg=cfg(has_SYS_{name})");
}

fn main() {
    let ac = autocfg::new();

    probe_syscall(&ac, "mmap");
    probe_syscall(&ac, "mmap2");
    probe_syscall(&ac, "futex_waitv");
    probe_syscall(&ac, "futex_wake");
    probe_syscall(&ac, "futex_wait");
    probe_syscall(&ac, "futex_requeue");

    autocfg::rerun_path("build.rs");
}

// vim: ts=4 sw=4 expandtab
