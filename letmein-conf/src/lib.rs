// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

use anyhow::{self as ah, format_err as err, Context as _};
use configparser::ini::Ini;
use letmein_proto::{Key, PORT};
use std::{collections::HashMap, path::Path, time::Duration};

const DEFAULT_NFT_TIMEOUT: u32 = 600;

/// Configured resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resource {
    /// Port resource.
    Port(u16),
}

fn parse_bool(s: &str) -> ah::Result<bool> {
    let s = s.to_lowercase();
    let s = s.trim();
    match s {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(err!("Invalid boolean string")),
    }
}

fn parse_u16(s: &str) -> ah::Result<u16> {
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

fn parse_hex_u32(s: &str) -> ah::Result<u32> {
    let s = s.trim();
    Ok(u32::from_str_radix(s, 16)?)
}

fn parse_hexdigit(s: &str) -> ah::Result<u8> {
    assert_eq!(s.len(), 1);
    Ok(u8::from_str_radix(s, 16)?)
}

fn parse_hex<const SIZE: usize>(s: &str) -> ah::Result<[u8; SIZE]> {
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

fn get_debug(ini: &Ini) -> ah::Result<bool> {
    if let Some(debug) = ini.get("GENERAL", "debug") {
        return parse_bool(&debug);
    }
    Ok(false)
}

fn get_port(ini: &Ini) -> ah::Result<u16> {
    if let Some(port) = ini.get("GENERAL", "port") {
        return parse_u16(&port);
    }
    Ok(PORT)
}

fn get_keys(ini: &Ini) -> ah::Result<HashMap<u32, Key>> {
    let mut keys = HashMap::new();
    if let Some(sect_keys) = ini.get_map_ref().get("KEYS") {
        for (key_id, key_val) in sect_keys.iter() {
            let Some(key_val) = key_val else {
                return Err(err!("Missing key value"));
            };
            let key_id = parse_hex_u32(key_id).context("KEYS")?;
            let key_val = parse_hex(key_val).context("KEYS")?;
            if key_val == [0; std::mem::size_of::<Key>()] {
                return Err(err!("Invalid key {key_id:08X}: Key is all zeros (00)"));
            }
            if key_val == [0xFF; std::mem::size_of::<Key>()] {
                return Err(err!("Invalid key {key_id:08X}: Key is all ones (FF)"));
            }
            keys.insert(key_id, key_val);
        }
    }
    Ok(keys)
}

fn get_resources(ini: &Ini) -> ah::Result<HashMap<u32, Resource>> {
    let mut resources = HashMap::new();
    if let Some(sect_resources) = ini.get_map_ref().get("RESOURCES") {
        for (res_id, res_val) in sect_resources.iter() {
            let Some(res_val) = res_val else {
                return Err(err!("Missing resource value"));
            };
            let res_id = parse_hex_u32(res_id).context("RESOURCES")?;
            let Some(idx) = res_val.find(':') else {
                return Err(err!("Invalid resource value. No colon."));
            };
            let res_name = res_val[0..idx].trim();
            let res_value = res_val[idx + 1..].trim();
            let res = match res_name {
                "port" => Resource::Port(parse_u16(res_value)?),
                n => {
                    return Err(err!("Unknown resource name: {n}"));
                }
            };
            resources.insert(res_id, res);
        }
    }
    Ok(resources)
}

fn get_default_user(ini: &Ini) -> ah::Result<u32> {
    if let Some(default_user) = ini.get("CLIENT", "default-user") {
        return parse_hex_u32(&default_user);
    }
    Ok(0)
}

fn get_nft_family(ini: &Ini) -> ah::Result<String> {
    if let Some(nft_family) = ini.get("NFTABLES", "family") {
        let nft_family = nft_family.trim();
        Ok(match nft_family {
            "inet" | "ip" | "ip6" => nft_family,
            nft_family => {
                return Err(err!("[NFTABLES] family={nft_family} is invalid"));
            }
        }
        .to_string())
    } else {
        Ok("".to_string())
    }
}

fn get_nft_table(ini: &Ini) -> ah::Result<String> {
    if let Some(nft_table) = ini.get("NFTABLES", "table") {
        Ok(nft_table.trim().to_string())
    } else {
        Ok("".to_string())
    }
}

fn get_nft_chain_input(ini: &Ini) -> ah::Result<String> {
    if let Some(nft_chain_input) = ini.get("NFTABLES", "chain-input") {
        Ok(nft_chain_input.trim().to_string())
    } else {
        Ok("".to_string())
    }
}

fn get_nft_timeout(ini: &Ini) -> ah::Result<u32> {
    if let Some(nft_timeout) = ini.get("NFTABLES", "timeout") {
        parse_u32(&nft_timeout)
    } else {
        Ok(DEFAULT_NFT_TIMEOUT)
    }
}

/// Configuration variant.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConfigVariant {
    /// Parse the configuration as a server configuration (letmeind.conf).
    Server,
    /// Parse the configuration as a client configuration (letmein.conf).
    Client,
}

/// Parsed letmein.conf or letmeind.conf. (See [ConfigVariant]).
#[derive(Clone, Default, Debug)]
pub struct Config {
    debug: bool,
    port: u16,
    keys: HashMap<u32, Key>,
    resources: HashMap<u32, Resource>,
    default_user: u32,
    nft_family: String,
    nft_table: String,
    nft_chain_input: String,
    nft_timeout: u32,
}

impl Config {
    /// Parse a configuration file.
    pub fn new(path: &Path, variant: ConfigVariant) -> ah::Result<Self> {
        let mut this: Config = Self {
            port: PORT,
            nft_timeout: DEFAULT_NFT_TIMEOUT,
            ..Default::default()
        };
        this.load(path, variant)?;
        Ok(this)
    }

    /// (Re-)load a configuration from a file.
    pub fn load(&mut self, path: &Path, variant: ConfigVariant) -> ah::Result<()> {
        let mut ini = Ini::new_cs();
        if let Err(e) = ini.load(path) {
            if variant == ConfigVariant::Server {
                return Err(err!("Failed to load configuration {path:?}: {e}"));
            } else {
                return Ok(());
            }
        };

        let mut default_user = Default::default();
        let mut nft_family = Default::default();
        let mut nft_table = Default::default();
        let mut nft_chain_input = Default::default();
        let mut nft_timeout = DEFAULT_NFT_TIMEOUT;

        let debug = get_debug(&ini)?;
        let port = get_port(&ini)?;
        let keys = get_keys(&ini)?;
        let resources = get_resources(&ini)?;
        if variant == ConfigVariant::Client {
            default_user = get_default_user(&ini)?;
        }
        if variant == ConfigVariant::Server {
            nft_family = get_nft_family(&ini)?;
            nft_table = get_nft_table(&ini)?;
            nft_chain_input = get_nft_chain_input(&ini)?;
            nft_timeout = get_nft_timeout(&ini)?;
        }

        self.debug = debug;
        self.port = port;
        self.keys = keys;
        self.resources = resources;
        self.default_user = default_user;
        self.nft_family = nft_family;
        self.nft_table = nft_table;
        self.nft_chain_input = nft_chain_input;
        self.nft_timeout = nft_timeout;
        Ok(())
    }

    pub fn debug(&self) -> bool {
        self.debug
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn key(&self, id: u32) -> Option<&Key> {
        self.keys.get(&id)
    }

    pub fn resource(&self, id: u32) -> Option<&Resource> {
        self.resources.get(&id)
    }

    pub fn resource_id_by_port(&self, port: u16) -> Option<u32> {
        for (k, v) in &self.resources {
            match v {
                Resource::Port(p) if *p == port => {
                    return Some(*k);
                }
                _ => (),
            }
        }
        None
    }

    pub fn default_user(&self) -> u32 {
        self.default_user
    }

    pub fn nft_family(&self) -> &str {
        &self.nft_family
    }

    pub fn nft_table(&self) -> &str {
        &self.nft_table
    }

    pub fn nft_chain_input(&self) -> &str {
        &self.nft_chain_input
    }

    pub fn nft_timeout(&self) -> Duration {
        Duration::from_secs(self.nft_timeout.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_general() {
        let mut ini = Ini::new_cs();
        ini.read("[GENERAL]\ndebug = true\n".to_string()).unwrap();
        assert!(get_debug(&ini).unwrap());
    }

    #[test]
    fn test_keys() {
        let mut ini = Ini::new_cs();
        ini.read(
            "[KEYS]\nABCD1234 = 998877665544332211009988776655443322110099887766554433221100CDEF\n"
                .to_string(),
        )
        .unwrap();
        let keys = get_keys(&ini).unwrap();
        assert_eq!(
            keys.get(&0xABCD1234).unwrap(),
            &[
                0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99, 0x88, 0x77, 0x66,
                0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
                0x11, 0x00, 0xCD, 0xEF
            ]
        );
    }

    #[test]
    fn test_resources() {
        let mut ini = Ini::new_cs();
        ini.read("[RESOURCES]\n9876ABCD = port : 4096\n".to_string())
            .unwrap();
        let resources = get_resources(&ini).unwrap();
        assert_eq!(resources.get(&0x9876ABCD).unwrap(), &Resource::Port(4096));
    }

    #[test]
    fn test_client() {
        let mut ini = Ini::new_cs();
        ini.read("[CLIENT]\ndefault-user = 123\n".to_string())
            .unwrap();
        let default_user = get_default_user(&ini).unwrap();
        assert_eq!(default_user, 0x123);
    }

    #[test]
    fn test_nft() {
        let mut ini = Ini::new_cs();
        ini.read(
            "[NFTABLES]\nfamily = inet\ntable = filter\nchain-input = LETMEIN-INPUT\ntimeout = 50\n".to_string(),
        )
        .unwrap();
        let nft_family = get_nft_family(&ini).unwrap();
        let nft_table = get_nft_table(&ini).unwrap();
        let nft_chain_input = get_nft_chain_input(&ini).unwrap();
        let nft_timeout = get_nft_timeout(&ini).unwrap();
        assert_eq!(nft_family, "inet");
        assert_eq!(nft_table, "filter");
        assert_eq!(nft_chain_input, "LETMEIN-INPUT");
        assert_eq!(nft_timeout, 50);
    }
}

// vim: ts=4 sw=4 expandtab
