// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use build_target::{target_arch, target_os, Arch, Os};

fn main() {
    let arch = target_arch().expect("Failed to get build target architecture");
    let os = target_os().expect("Failed to get build target OS");

    println!("cargo:rustc-check-cfg=cfg(has_seccomp_support)");
    match os {
        Os::Linux | Os::Android => {
            match arch {
                // This is what `seccompiler` currently supports:
                Arch::X86_64 | Arch::AARCH64 => {
                    println!("cargo:rustc-cfg=has_seccomp_support");
                }
                _ => (),
            }
        }
        _ => (),
    }
}

// vim: ts=4 sw=4 expandtab
