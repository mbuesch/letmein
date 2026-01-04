// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use std::env;

fn main() {
    let os = env::var("CARGO_CFG_TARGET_OS").expect("Failed to get build target OS");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("Failed to get build target architecture");

    println!("cargo:rustc-check-cfg=cfg(has_seccomp_support)");
    match os.as_str() {
        "linux" | "android" => {
            match arch.as_str() {
                // This is what `seccompiler` currently supports:
                "x86_64" | "aarch64" => {
                    println!("cargo:rustc-cfg=has_seccomp_support");
                }
                _ => (),
            }
        }
        _ => (),
    }
}

// vim: ts=4 sw=4 expandtab
