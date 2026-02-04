// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, format_err as err};
use std::time::Duration;

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

fn parse_u32(s: &str) -> ah::Result<u32> {
    let s = s.trim();
    if let Some(s) = s.strip_prefix("0x") {
        Ok(u32::from_str_radix(s, 16)?)
    } else {
        Ok(s.parse::<u32>()?)
    }
}

fn parse_f64(s: &str) -> ah::Result<f64> {
    let s = s.trim();
    let value = s.parse::<f64>()?;
    if value.is_finite() {
        Ok(value)
    } else {
        Err(err!("Invalid floating point value (Inf or NaN)"))
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
            "Hex string is not correct: Expected {}, got {} chars",
            SIZE * 2,
            len,
        ));
    }
    let mut ret = [0; SIZE];
    for i in 0..SIZE {
        ret[i] = parse_hexdigit(&s[(i * 2)..=(i * 2)])? << 4;
        ret[i] |= parse_hexdigit(&s[(i * 2 + 1)..=(i * 2 + 1)])?;
    }
    Ok(ret)
}

pub fn parse_duration(s: &str) -> ah::Result<Duration> {
    if let Ok(secs) = parse_u32(s) {
        return Ok(Duration::from_secs(secs.into()));
    }
    if let Ok(secs) = parse_f64(s)
        && secs >= 0.0
        && secs <= u32::MAX.into()
    {
        return Ok(Duration::from_secs_f64(secs));
    }
    Err(err!("Invalid Duration"))
}

/// Check if the string is a decimal or hexadecimal number (prefix 0x).
pub fn is_number(s: &str) -> bool {
    let s = s.trim();
    if let Some(s) = s.strip_prefix("0x") {
        s.chars().all(|c| c.is_ascii_hexdigit())
    } else {
        s.chars().all(|c| c.is_ascii_digit())
    }
}

// vim: ts=4 sw=4 expandtab
