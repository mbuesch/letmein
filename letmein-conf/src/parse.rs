// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, format_err as err};

pub fn parse_bool(s: &str) -> ah::Result<bool> {
    let s = s.to_lowercase();
    let s = s.trim();
    match s {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(err!("Invalid boolean string")),
    }
}

pub fn parse_u16(s: &str) -> ah::Result<u16> {
    let s = s.trim();
    if let Some(s) = s.strip_prefix("0x") {
        Ok(u16::from_str_radix(s, 16)?)
    } else {
        Ok(s.parse::<u16>()?)
    }
}

pub fn parse_u32(s: &str) -> ah::Result<u32> {
    let s = s.trim();
    if let Some(s) = s.strip_prefix("0x") {
        Ok(u32::from_str_radix(s, 16)?)
    } else {
        Ok(s.parse::<u32>()?)
    }
}

fn parse_hexdigit(s: &str) -> ah::Result<u8> {
    assert_eq!(s.len(), 1);
    Ok(u8::from_str_radix(s, 16)?)
}

pub fn parse_hex<const SIZE: usize>(s: &str) -> ah::Result<[u8; SIZE]> {
    let s = s.trim();
    if !s.is_ascii() {
        return Err(err!("Hex string contains invalid characters."));
    }
    let len = s.len();
    if len != SIZE * 2 {
        return Err(err!(
            "Hex string is too short: Expected {}, got {} chars",
            SIZE * 2,
            len,
        ));
    }
    let mut ret = [0; SIZE];
    for i in 0..SIZE {
        ret[i] = parse_hexdigit(&s[i * 2..i * 2 + 1])? << 4;
        ret[i] |= parse_hexdigit(&s[i * 2 + 1..i * 2 + 2])?;
    }
    Ok(ret)
}

// vim: ts=4 sw=4 expandtab
