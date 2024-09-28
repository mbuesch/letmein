// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, format_err as err, Context as _};
use std::fs::read_to_string;

/// Resolve a user name into a UID.
pub fn os_get_uid(user_name: &str) -> ah::Result<u32> {
    let data = read_to_string("/etc/passwd").context("Read /etc/passwd database")?;

    for line in data.lines() {
        let mut fields = line.splitn(7, ':');

        let name = fields.next().context("Get passwd name")?;
        if name == user_name {
            let _pw = fields.next().context("Get passwd password")?;
            let uid = fields.next().context("Get passwd uid")?;

            return uid.parse().context("Parse passwd uid");
        }
    }

    Err(err!("User '{user_name}' not found in /etc/passwd"))
}

/// Resolve a group name into a GID.
pub fn os_get_gid(group_name: &str) -> ah::Result<u32> {
    let data = read_to_string("/etc/group").context("Read /etc/group database")?;

    for line in data.lines() {
        let mut fields = line.splitn(4, ':');

        let name = fields.next().context("Get group name")?;
        if name == group_name {
            let _pw = fields.next().context("Get group password")?;
            let gid = fields.next().context("Get group gid")?;

            return gid.parse().context("Parse group gid");
        }
    }

    Err(err!("Group '{group_name}' not found in /etc/group"))
}

// vim: ts=4 sw=4 expandtab
