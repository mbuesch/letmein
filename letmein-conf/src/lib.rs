// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! This crate implements the server and client configuration
//! file parsing of `letmein`.
//!
//! Defaults for missing configuration files
//! or missing individual configuration entries are implemented here.

#![forbid(unsafe_code)]

mod ini;
mod parse;
mod parse_items;

use crate::{
    ini::Ini,
    parse::{parse_bool, parse_duration, parse_hex, parse_u16},
    parse_items::{Map, MapItem},
};
use anyhow::{self as ah, format_err as err, Context as _};
use letmein_proto::{Key, ResourceId, UserId, PORT};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Duration,
};

/// The default server configuration path, relative to the install prefix.
#[cfg(not(target_os = "windows"))]
const SERVER_CONF_PATH: &str = "etc/letmeind.conf";
#[cfg(target_os = "windows")]
const SERVER_CONF_PATH: &str = "letmeind.conf";

/// The default client configuration path, relative to the install prefix.
#[cfg(not(target_os = "windows"))]
const CLIENT_CONF_PATH: &str = "etc/letmein.conf";
#[cfg(target_os = "windows")]
const CLIENT_CONF_PATH: &str = "letmein.conf";

const DEFAULT_CONTROL_TIMEOUT: Duration = Duration::from_millis(5_000);
const DEFAULT_NFT_TIMEOUT: Duration = Duration::from_millis(600_000);

/// Configured resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resource {
    /// Port resource.
    Port {
        port: u16,
        tcp: bool,
        udp: bool,
        users: Vec<UserId>,
    },
}

impl Resource {
    pub fn contains_user(&self, id: UserId) -> bool {
        match self {
            Self::Port {
                port: _,
                tcp: _,
                udp: _,
                users,
            } => {
                if users.is_empty() {
                    // This resource is unrestricted.
                    return true;
                }
                users.contains(&id)
            }
        }
    }
}

/// Error reporting policy.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum ErrorPolicy {
    /// Always report errors.
    #[default]
    Always,

    /// Only report errors if basic authentication passed.
    BasicAuth,

    /// Only report errors if full authentication passed.
    FullAuth,
}

/// Seccomp setting.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum Seccomp {
    /// Seccomp is disabled (default).
    #[default]
    Off,

    /// Seccomp is enabled with logging only.
    ///
    /// The event will be logged, if a syscall is called that is not allowed.
    /// See the Linux kernel logs for seccomp audit messages.
    Log,

    /// Seccomp is enabled with killing (recommended).
    ///
    /// The process will be killed, if a syscall is called that is not allowed.
    Kill,
}

impl std::fmt::Display for Seccomp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::Off => write!(f, "Off"),
            Self::Log => write!(f, "Logging only"),
            Self::Kill => write!(f, "Process killing"),
        }
    }
}

impl std::str::FromStr for Seccomp {
    type Err = ah::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "off" => Ok(Self::Off),
            "log" => Ok(Self::Log),
            "kill" => Ok(Self::Kill),
            other => Err(err!(
                "Config option 'seccomp = {other}' is not valid. Valid values are: off, log, kill."
            )),
        }
    }
}

fn get_debug(ini: &Ini) -> ah::Result<bool> {
    if let Some(debug) = ini.get("GENERAL", "debug") {
        return parse_bool(debug);
    }
    Ok(false)
}

fn get_port(ini: &Ini) -> ah::Result<u16> {
    if let Some(port) = ini.get("GENERAL", "port") {
        return parse_u16(port);
    }
    Ok(PORT)
}

fn get_control_timeout(ini: &Ini) -> ah::Result<Duration> {
    if let Some(timeout) = ini.get("GENERAL", "control-timeout") {
        return parse_duration(timeout);
    }
    Ok(DEFAULT_CONTROL_TIMEOUT)
}

fn get_control_error_policy(ini: &Ini) -> ah::Result<ErrorPolicy> {
    if let Some(policy) = ini.get("GENERAL", "control-error-policy") {
        return match policy.to_lowercase().trim() {
            "always" => Ok(ErrorPolicy::Always),
            "basic-auth" => Ok(ErrorPolicy::BasicAuth),
            "full-auth" => Ok(ErrorPolicy::FullAuth),
            other => Err(err!(
                "Config option 'control-error-policy = {other}' is not valid. \
                    Valid values are: always, basic-auth, full-auth."
            )),
        };
    }
    Ok(Default::default())
}

fn get_seccomp(ini: &Ini) -> ah::Result<Seccomp> {
    if let Some(seccomp) = ini.get("GENERAL", "seccomp") {
        return seccomp.parse();
    }
    Ok(Default::default())
}

fn get_keys(ini: &Ini) -> ah::Result<HashMap<UserId, Key>> {
    let mut keys = HashMap::new();
    if let Some(options) = ini.options_iter("KEYS") {
        for (id, key) in options {
            let id = id.parse().context("[KEYS]")?;
            let key = parse_hex(key).context("[KEYS]")?;
            if key == [0; std::mem::size_of::<Key>()] {
                return Err(err!("Invalid key {id}: Key is all zeros (00)"));
            }
            if key == [0xFF; std::mem::size_of::<Key>()] {
                return Err(err!("Invalid key {id}: Key is all ones (FF)"));
            }
            if keys.contains_key(&id) {
                return Err(err!("[KEYS] Multiple definitions of key '{id}'"));
            }
            keys.insert(id, key);
        }
    }
    Ok(keys)
}

fn get_resources(ini: &Ini) -> ah::Result<HashMap<ResourceId, Resource>> {
    let mut resources = HashMap::new();
    if let Some(options) = ini.options_iter("RESOURCES") {
        for (id, resource) in options {
            let id = id.parse().context("[RESOURCES]")?;
            let map = resource.parse::<Map>().context("[RESOURCES]")?;

            let mut port: Option<u16> = None;
            let mut users: Vec<String> = vec![];
            let mut tcp = false;
            let mut udp = false;

            for item in map.items() {
                match item {
                    MapItem::KeyValue(k, v) => {
                        if k == "port" {
                            if port.is_some() {
                                return Err(err!("[RESOURCE] multiple 'port' values"));
                            }
                            port = Some(parse_u16(v).context("[RESOURCES] port")?);
                        } else if k == "users" {
                            if !users.is_empty() {
                                return Err(err!("[RESOURCE] multiple 'users' values"));
                            }
                            users.push(v.clone());
                        } else {
                            return Err(err!("[RESOURCE] unknown option: {k}"));
                        }
                    }
                    MapItem::KeyValues(k, vs) => {
                        if k == "port" {
                            return Err(err!("[RESOURCE] invalid 'port' option"));
                        } else if k == "users" {
                            if !users.is_empty() {
                                return Err(err!("[RESOURCE] multiple 'users' values"));
                            }
                            users = vs.clone();
                        } else {
                            return Err(err!("[RESOURCE] unknown option: {k}"));
                        }
                    }
                    MapItem::Values(vs) => {
                        for v in vs {
                            match &v.to_lowercase()[..] {
                                "tcp" => {
                                    tcp = true;
                                }
                                "udp" => {
                                    udp = true;
                                }
                                v => {
                                    return Err(err!("[RESOURCE] unknown option: {v}"));
                                }
                            }
                        }
                    }
                }
            }
            if !tcp && !udp {
                // Default, if no tcp/udp option is given.
                tcp = true;
            }
            let Some(port) = port else {
                return Err(err!("[RESOURCE] '{id}': No 'port' value present"));
            };

            let mut res_users = vec![];
            for user in users {
                if let Ok(user) = user.parse() {
                    res_users.push(user);
                } else {
                    return Err(err!("[RESOURCE] '{id}': 'user' id is invalid"));
                }
            }

            for (res_id, res) in &resources {
                let Resource::Port { port: res_port, .. } = res;
                if *res_id == id {
                    return Err(err!(
                        "[RESOURCE] Multiple definitions of resource ID '{id}'"
                    ));
                }
                if *res_port == port {
                    return Err(err!(
                        "[RESOURCE] Multiple definitions of resource port '{port}'"
                    ));
                }
            }

            let res = Resource::Port {
                port,
                tcp,
                udp,
                users: res_users,
            };
            resources.insert(id, res);
        }
    }
    Ok(resources)
}

fn get_default_user(ini: &Ini) -> ah::Result<UserId> {
    if let Some(default_user) = ini.get("CLIENT", "default-user") {
        return default_user.parse();
    }
    Ok(Default::default())
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

fn get_nft_timeout(ini: &Ini) -> ah::Result<Duration> {
    if let Some(nft_timeout) = ini.get("NFTABLES", "timeout") {
        parse_duration(nft_timeout)
    } else {
        Ok(DEFAULT_NFT_TIMEOUT)
    }
}

/// Configuration variant.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum ConfigVariant {
    /// Parse the configuration as a server configuration (letmeind.conf).
    #[default]
    Server,
    /// Parse the configuration as a client configuration (letmein.conf).
    Client,
}

/// Parsed letmein.conf or letmeind.conf. (See [ConfigVariant]).
#[derive(Clone, Default, Debug)]
pub struct Config {
    variant: ConfigVariant,
    path: Option<PathBuf>,
    debug: bool,
    port: u16,
    control_timeout: Duration,
    control_error_policy: ErrorPolicy,
    seccomp: Seccomp,
    keys: HashMap<UserId, Key>,
    resources: HashMap<ResourceId, Resource>,
    default_user: UserId,
    nft_family: String,
    nft_table: String,
    nft_chain_input: String,
    nft_timeout: Duration,
}

impl Config {
    /// Create a new configuration instance with all-default values.
    pub fn new(variant: ConfigVariant) -> Self {
        Self {
            variant,
            port: PORT,
            control_timeout: DEFAULT_CONTROL_TIMEOUT,
            nft_timeout: DEFAULT_NFT_TIMEOUT,
            ..Default::default()
        }
    }

    /// Get the default configuration file path.
    pub fn get_default_path(variant: ConfigVariant) -> PathBuf {
        // The build-time environment variable LETMEIN_CONF_PREFIX can be
        // used to give an additional prefix.
        let prefix = match option_env!("LETMEIN_CONF_PREFIX") {
            Some(env_prefix) => env_prefix,
            None => {
                #[cfg(not(target_os = "windows"))]
                let prefix = "/";
                #[cfg(target_os = "windows")]
                let prefix = "";
                prefix
            }
        };

        let mut path = PathBuf::new();
        path.push(prefix);
        match variant {
            ConfigVariant::Client => {
                path.push(CLIENT_CONF_PATH);
            }
            ConfigVariant::Server => {
                path.push(SERVER_CONF_PATH);
            }
        }
        path
    }

    /// Get the actual path the configuration was read from.
    pub fn get_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// (Re-)load a configuration from a file.
    pub fn load(&mut self, path: &Path) -> ah::Result<()> {
        if let Ok(ini) = Ini::new_from_file(path) {
            self.load_ini(&ini)?;
        } else if self.variant == ConfigVariant::Server {
            return Err(err!("Failed to load configuration {path:?}"));
        }
        self.path = Some(path.to_path_buf());
        Ok(())
    }

    /// (Re-)load a configuration from a parsed [Ini] instance.
    fn load_ini(&mut self, ini: &Ini) -> ah::Result<()> {
        let mut default_user = Default::default();
        let mut nft_family = Default::default();
        let mut nft_table = Default::default();
        let mut nft_chain_input = Default::default();
        let mut nft_timeout = DEFAULT_NFT_TIMEOUT;

        let debug = get_debug(ini)?;
        let port = get_port(ini)?;
        let control_timeout = get_control_timeout(ini)?;
        let control_error_policy = get_control_error_policy(ini)?;
        let seccomp = get_seccomp(ini)?;
        let keys = get_keys(ini)?;
        let resources = get_resources(ini)?;
        if self.variant == ConfigVariant::Client {
            default_user = get_default_user(ini)?;
        }
        if self.variant == ConfigVariant::Server {
            nft_family = get_nft_family(ini)?;
            nft_table = get_nft_table(ini)?;
            nft_chain_input = get_nft_chain_input(ini)?;
            nft_timeout = get_nft_timeout(ini)?;
        }

        self.debug = debug;
        self.port = port;
        self.control_timeout = control_timeout;
        self.control_error_policy = control_error_policy;
        self.seccomp = seccomp;
        self.keys = keys;
        self.resources = resources;
        self.default_user = default_user;
        self.nft_family = nft_family;
        self.nft_table = nft_table;
        self.nft_chain_input = nft_chain_input;
        self.nft_timeout = nft_timeout;
        Ok(())
    }

    /// Get the `debug` option from `[GENERAL]` section.
    pub fn debug(&self) -> bool {
        self.debug
    }

    /// Get the `port` option from `[GENERAL]` section.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the `control-timeout` option from `[GENERAL]` section.
    pub fn control_timeout(&self) -> Duration {
        self.control_timeout
    }

    /// Get the `control-error-policy` option from `[GENERAL]` section.
    pub fn control_error_policy(&self) -> ErrorPolicy {
        self.control_error_policy
    }

    /// Get the `seccomp` option from `[GENERAL]` section.
    pub fn seccomp(&self) -> Seccomp {
        self.seccomp
    }

    /// Get a key value by key identifier from the `[KEYS]` section.
    pub fn key(&self, id: UserId) -> Option<&Key> {
        self.keys.get(&id)
    }

    /// Get a resource value by resource identifier from the `[RESOURCES]` section.
    pub fn resource(&self, id: ResourceId) -> Option<&Resource> {
        self.resources.get(&id)
    }

    /// Lookup a resource id by a port number in the `[RESOURCES]` section.
    pub fn resource_id_by_port(&self, port: u16, user_id: Option<UserId>) -> Option<ResourceId> {
        for (k, v) in &self.resources {
            match v {
                Resource::Port { port: p, .. } => {
                    if *p == port {
                        if let Some(user_id) = user_id {
                            if v.contains_user(user_id) {
                                return Some(*k);
                            }
                        } else {
                            return Some(*k);
                        }
                    }
                }
            }
        }
        None
    }

    /// Get the `default-user` option from `[CLIENT]` section.
    pub fn default_user(&self) -> UserId {
        self.default_user
    }

    /// Get the `family` option from `[NFTABLES]` section.
    pub fn nft_family(&self) -> &str {
        &self.nft_family
    }

    /// Get the `table` option from `[NFTABLES]` section.
    pub fn nft_table(&self) -> &str {
        &self.nft_table
    }

    /// Get the `chain-input` option from `[NFTABLES]` section.
    pub fn nft_chain_input(&self) -> &str {
        &self.nft_chain_input
    }

    /// Get the `timeout` option from `[NFTABLES]` section.
    pub fn nft_timeout(&self) -> Duration {
        self.nft_timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_general() {
        let mut ini = Ini::new();
        ini.parse_str(
            "[GENERAL]\ndebug = true\nport = 1234\ncontrol-timeout=1.5\n\
            control-error-policy= basic-auth \nseccomp = kill",
        )
        .unwrap();
        assert!(get_debug(&ini).unwrap());
        assert_eq!(get_port(&ini).unwrap(), 1234);
        assert_eq!(
            get_control_timeout(&ini).unwrap(),
            Duration::from_millis(1500)
        );
        assert_eq!(
            get_control_error_policy(&ini).unwrap(),
            ErrorPolicy::BasicAuth
        );
        assert_eq!(get_seccomp(&ini).unwrap(), Seccomp::Kill);
    }

    #[test]
    fn test_keys() {
        let mut ini = Ini::new();
        ini.parse_str(
            "[KEYS]\nABCD1234 = 998877665544332211009988776655443322110099887766554433221100CDEF\n",
        )
        .unwrap();
        let keys = get_keys(&ini).unwrap();
        assert_eq!(
            keys.get(&0xABCD1234.into()).unwrap(),
            &[
                0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99, 0x88, 0x77, 0x66,
                0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
                0x11, 0x00, 0xCD, 0xEF
            ]
        );
    }

    #[test]
    fn test_resources() {
        let mut ini = Ini::new();
        ini.parse_str("[RESOURCES]\n9876ABCD = port : 4096\n")
            .unwrap();
        let resources = get_resources(&ini).unwrap();
        assert_eq!(
            resources.get(&0x9876ABCD.into()).unwrap(),
            &Resource::Port {
                port: 4096,
                tcp: true,
                udp: false,
                users: vec![]
            }
        );

        let mut ini = Ini::new();
        ini.parse_str("[RESOURCES]\n9876ABCD = port : 4096 / TCP\n")
            .unwrap();
        let resources = get_resources(&ini).unwrap();
        assert_eq!(
            resources.get(&0x9876ABCD.into()).unwrap(),
            &Resource::Port {
                port: 4096,
                tcp: true,
                udp: false,
                users: vec![]
            }
        );

        let mut ini = Ini::new();
        ini.parse_str("[RESOURCES]\n9876ABCD = port : 4096 / udp / users: 1, 2 ,3  \n")
            .unwrap();
        let resources = get_resources(&ini).unwrap();
        assert_eq!(
            resources.get(&0x9876ABCD.into()).unwrap(),
            &Resource::Port {
                port: 4096,
                tcp: false,
                udp: true,
                users: vec![1.into(), 2.into(), 3.into()]
            }
        );

        let mut ini = Ini::new();
        ini.parse_str("[RESOURCES]\n9876ABCD = port : 4096 / udp, tcp / users: 4\n")
            .unwrap();
        let resources = get_resources(&ini).unwrap();
        assert_eq!(
            resources.get(&0x9876ABCD.into()).unwrap(),
            &Resource::Port {
                port: 4096,
                tcp: true,
                udp: true,
                users: vec![4.into()]
            }
        );
    }

    #[test]
    fn test_client() {
        let mut ini = Ini::new();
        ini.parse_str("[CLIENT]\ndefault-user = 123\n").unwrap();
        let default_user = get_default_user(&ini).unwrap();
        assert_eq!(default_user, 0x123.into());
    }

    #[test]
    fn test_nft() {
        let mut ini = Ini::new();
        ini.parse_str(
            "[NFTABLES]\nfamily = inet\ntable = filter\nchain-input = LETMEIN-INPUT\ntimeout = 50\n",
        )
        .unwrap();
        let nft_family = get_nft_family(&ini).unwrap();
        let nft_table = get_nft_table(&ini).unwrap();
        let nft_chain_input = get_nft_chain_input(&ini).unwrap();
        let nft_timeout = get_nft_timeout(&ini).unwrap();
        assert_eq!(nft_family, "inet");
        assert_eq!(nft_table, "filter");
        assert_eq!(nft_chain_input, "LETMEIN-INPUT");
        assert_eq!(nft_timeout, Duration::from_secs(50));
    }
}

// vim: ts=4 sw=4 expandtab
