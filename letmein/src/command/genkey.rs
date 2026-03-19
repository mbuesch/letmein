// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow as ah;
use letmein_conf::Config;
use letmein_proto::{Key, UserId, secure_random};

/// Generate a new truly random and secure user key.
#[allow(clippy::unused_async)]
pub async fn run_genkey(conf: &Config, user: Option<UserId>) -> ah::Result<String> {
    let user = user.unwrap_or_else(|| conf.default_user());
    let key: Key = secure_random();
    let key: Vec<String> = key.iter().map(|b| format!("{b:02X}")).collect();
    let key: String = key.join("");
    Ok(format!("{user} = {key}"))
}

// vim: ts=4 sw=4 expandtab
