// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use anyhow::{self as ah, format_err as err, Context as _};
use std::{
    env,
    io::{stdin, Read as _},
};

fn main() -> ah::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args != ["nft", "-j", "-f", "-"] {
        return Err(err!("nft-stub: Invalid command line: {args:?}"));
    }

    let mut json_raw: Vec<u8> = vec![];
    stdin().read_to_end(&mut json_raw).context("Read stdin")?;
    let json = std::str::from_utf8(&json_raw).context("Parse JSON")?;

    //eprintln!("{json:?}");
    let _ = json; // We could have some json payload checks here...

    Ok(())
}

// vim: ts=4 sw=4 expandtab
