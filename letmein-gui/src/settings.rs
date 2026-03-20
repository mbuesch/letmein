// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::{self as ah, Context as _, format_err as err};
use letmein_conf::{Config, ConfigVariant, Ini, Resource};
use std::fmt::Write as _;

#[derive(Clone, Default, PartialEq)]
pub struct KeyEntry {
    pub user_id: String,
    pub key_hex: String,
    pub show_key: bool,
}

#[derive(Clone, PartialEq)]
pub struct ResourceEntry {
    pub id: String,
    pub port: String,
    pub tcp: bool,
    pub udp: bool,
}

impl Default for ResourceEntry {
    fn default() -> Self {
        Self {
            id: String::new(),
            port: String::new(),
            tcp: true,
            udp: false,
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct AppSettings {
    pub keys: Vec<KeyEntry>,
    pub resources: Vec<ResourceEntry>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            keys: vec![KeyEntry::default()],
            resources: vec![ResourceEntry::default()],
        }
    }
}

impl AppSettings {
    pub fn from_config(conf: &Config) -> Self {
        let keys: Vec<KeyEntry> = conf
            .users()
            .iter()
            .map(|uid| {
                let user_id = uid.to_string();
                let key_hex = conf
                    .key(*uid)
                    .map(|k| {
                        let mut s = String::with_capacity(k.len() * 2);
                        for b in k {
                            write!(s, "{b:02X}").unwrap();
                        }
                        s
                    })
                    .unwrap_or_default();
                KeyEntry {
                    user_id,
                    key_hex,
                    show_key: false,
                }
            })
            .collect();
        let resources: Vec<ResourceEntry> = conf
            .resources()
            .iter()
            .filter_map(|res| match res {
                Resource::Port {
                    id, port, tcp, udp, ..
                } => Some(ResourceEntry {
                    id: id.to_string(),
                    port: port.to_string(),
                    tcp: *tcp,
                    udp: *udp,
                }),
                Resource::Jump { .. } => None,
            })
            .collect();
        AppSettings { keys, resources }
    }

    pub fn to_ini(&self) -> ah::Result<Ini> {
        let mut ini = Ini::new();

        for key in &self.keys {
            let uid = key.user_id.trim();
            let k = key.key_hex.trim();
            if !uid.is_empty() && !k.is_empty() {
                ini.set("KEYS", uid, k);
            }
        }

        for res in &self.resources {
            let id = res.id.trim();
            let port = res.port.trim();
            if !id.is_empty() && !port.is_empty() {
                let proto = match (res.tcp, res.udp) {
                    (true, true) => " / tcp, udp",
                    (false, true) => " / udp",
                    (true, false) => " / tcp",
                    (false, false) => {
                        return Err(err!("Resource {id} has no protocol tcp/udp enabled"));
                    }
                };
                ini.set("RESOURCES", id, &format!("port: {port}{proto}"));
            }
        }

        Ok(ini)
    }

    pub fn to_config(&self) -> ah::Result<(Config, Ini)> {
        let mut conf = Config::new(ConfigVariant::Client);
        let ini = self.to_ini().context("Failed to convert settings to ini")?;
        conf.load_ini(&ini)
            .context("Failed to convert settings to configuration")?;
        Ok((conf, ini))
    }

    pub fn set_user_id(&mut self, index: usize, user_id: String) {
        if let Some(key) = self.keys.get_mut(index) {
            key.user_id = user_id;
        }
    }

    pub fn set_key(&mut self, index: usize, key_hex: String) {
        if let Some(key) = self.keys.get_mut(index) {
            key.key_hex = key_hex;
        }
    }

    pub fn toggle_key_visibility(&mut self, index: usize) {
        if let Some(key) = self.keys.get_mut(index) {
            key.show_key = !key.show_key;
        }
    }

    pub fn remove(&mut self, index: usize) {
        if index < self.keys.len() {
            self.keys.remove(index);
        }
    }

    pub fn add_resource(&mut self, res: ResourceEntry) {
        self.resources.push(res);
    }

    pub fn remove_resource(&mut self, index: usize) {
        if index < self.resources.len() {
            self.resources.remove(index);
        }
    }

    pub fn set_resource_id(&mut self, index: usize, id: String) {
        if let Some(res) = self.resources.get_mut(index) {
            res.id = id;
        }
    }

    pub fn set_resource_port(&mut self, index: usize, port: String) {
        if let Some(res) = self.resources.get_mut(index) {
            res.port = port;
        }
    }

    pub fn set_resource_tcp(&mut self, index: usize, tcp: bool) {
        if let Some(res) = self.resources.get_mut(index) {
            res.tcp = tcp;
        }
    }

    pub fn set_resource_udp(&mut self, index: usize, udp: bool) {
        if let Some(res) = self.resources.get_mut(index) {
            res.udp = udp;
        }
    }
}

// vim: ts=4 sw=4 expandtab
