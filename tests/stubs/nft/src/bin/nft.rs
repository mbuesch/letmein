// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use std::{
    env,
    io::{stdin, Read as _},
};

fn main() {
    let args: Vec<String> = env::args().collect();
    assert_eq!(args, ["nft", "-j", "-f", "-"]);

    let mut json_raw: Vec<u8> = vec![];
    stdin().read_to_end(&mut json_raw).unwrap();
    let json = std::str::from_utf8(&json_raw).unwrap();

    //eprintln!("{json:?}");
    let _ = json; // We could have some json payload checks here...
}

// vim: ts=4 sw=4 expandtab
