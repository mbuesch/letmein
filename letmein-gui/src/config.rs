// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, Context as _};
use letmein_conf::{Config, ConfigVariant, Ini, Resource};
use letmein_proto::PORT;
use std::{fs, path::PathBuf};

const CONFIG_FILE: &str = "letmein.conf";
const SERVERS_CONF_FILE: &str = "servers.conf";

pub fn gui_config_dir() -> ah::Result<PathBuf> {
    #[cfg(target_os = "android")]
    {
        let dir = PathBuf::from("/data/data/ch.bues.letmein/files");
        fs::create_dir_all(&dir).context("Failed to create config directory")?;
        Ok(dir)
    }

    #[cfg(not(target_os = "android"))]
    {
        let mut dir = if let Ok(dir) = std::env::var("XDG_CONFIG_HOME") {
            PathBuf::from(dir)
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".config")
        } else {
            PathBuf::from(".")
        };
        dir = dir.join("letmein-gui");
        fs::create_dir_all(&dir).context("Failed to create config directory")?;
        Ok(dir)
    }
}

pub fn config_file_path() -> ah::Result<PathBuf> {
    Ok(gui_config_dir()?.join(CONFIG_FILE))
}

pub fn load_config() -> ah::Result<Config> {
    let path = config_file_path()?;
    let mut config = Config::new(ConfigVariant::Client);
    if path.exists() {
        config.load(&path).context("Failed to load configuration")?;
    }
    Ok(config)
}

#[derive(Clone, PartialEq)]
pub struct ServerEntry {
    pub name: String,
    pub addr: String,
    pub user_id: String,
    pub control_port: String,
}

impl Default for ServerEntry {
    fn default() -> Self {
        Self {
            name: String::new(),
            addr: String::new(),
            user_id: String::new(),
            control_port: PORT.to_string(),
        }
    }
}

pub fn load_server_list() -> ah::Result<Vec<ServerEntry>> {
    let path = gui_config_dir()?.join(SERVERS_CONF_FILE);
    if !path.exists() {
        return Ok(vec![]);
    }
    let ini = Ini::new_from_file(&path).context("Failed to read server list file")?;
    let mut entries = Vec::with_capacity(32);
    let mut i: usize = 0;
    loop {
        let section = format!("server-{i}");
        if ini.options_iter(&section).is_none() {
            break;
        }
        let name = ini
            .get(&section, "name")
            .context("Failed to get server list 'name'")?
            .trim()
            .to_string();
        let addr = ini
            .get(&section, "addr")
            .context("Failed to get server list 'addr'")?
            .trim()
            .to_string();
        let user_id = ini
            .get(&section, "user")
            .context("Failed to get server list 'user'")?
            .trim()
            .to_string();
        let control_port = ini
            .get(&section, "control-port")
            .map_or_else(|| PORT.to_string(), |s| s.trim().to_string());
        entries.push(ServerEntry {
            name,
            addr,
            user_id,
            control_port,
        });
        i += 1;
    }
    Ok(entries)
}

pub fn save_server_list(entries: &[ServerEntry]) -> ah::Result<()> {
    let path = gui_config_dir()?.join(SERVERS_CONF_FILE);
    let mut ini = Ini::new();
    for (i, entry) in entries.iter().enumerate() {
        let section = format!("server-{i}");
        ini.set(&section, "name", &entry.name);
        ini.set(&section, "addr", &entry.addr);
        ini.set(&section, "user", &entry.user_id);
        ini.set(&section, "control-port", &entry.control_port);
    }
    ini.write_file(&path).context("Failed to save server list")
}

pub fn resource_display_name(res: &Resource) -> (String, String) {
    match res {
        Resource::Port {
            id, port, tcp, udp, ..
        } => {
            let proto = match (tcp, udp) {
                (true, true) => "TCP/UDP",
                (true, false) => "TCP",
                (false, true) => "UDP",
                _ => "",
            };
            (
                format!("Port {port}"),
                format!("{proto}  \u{2022}  ID {id}"),
            )
        }
        Resource::Jump { id, .. } => ("Jump rule".into(), format!("ID {id}")),
    }
}

// vim: ts=4 sw=4 expandtab
