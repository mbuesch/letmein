// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
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
    parse::{is_number, parse_bool, parse_duration, parse_hex, parse_u16},
    parse_items::{Map, MapItem},
};
use anyhow::{self as ah, format_err as err, Context as _};
use letmein_proto::{Key, ResourceId, UserId, PORT};
use sha3::{Digest, Sha3_256};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Duration,
};
use subtle::ConstantTimeEq as _;

pub use crate::ini::{Ini, IniSectionIter};

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

const MAX_CHAIN_LEN: usize = 64;

/// Configuration content checksum.
#[derive(Clone, Debug, Default, Eq)]
pub struct ConfigChecksum([u8; ConfigChecksum::SIZE]);

impl ConfigChecksum {
    /// Digest size, in bytes.
    pub const SIZE: usize = 32;

    /// Calculate the checksum from a raw byte stream.
    #[must_use]
    pub fn calculate(content: &[u8]) -> Self {
        let mut hash = Sha3_256::new();
        hash.update((content.len() as u64).to_be_bytes());
        hash.update(content);
        let digest = hash.finalize();
        Self((*digest).try_into().expect("Unwrap sha digest"))
    }

    /// Get the calculated checksum digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ConfigChecksum::SIZE] {
        &self.0
    }
}

impl PartialEq for ConfigChecksum {
    fn eq(&self, other: &ConfigChecksum) -> bool {
        // Constant-time compare.
        self.0.ct_eq(&other.0).into()
    }
}

impl TryFrom<&[u8]> for ConfigChecksum {
    type Error = ah::Error;

    /// Convert a raw checksum digest into `ConfigChecksum`.
    fn try_from(data: &[u8]) -> ah::Result<Self> {
        Ok(ConfigChecksum(data.try_into()?))
    }
}

/// Configured control port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlPort {
    pub port: u16,
    pub tcp: bool,
    pub udp: bool,
}

impl Default for ControlPort {
    fn default() -> Self {
        Self {
            port: PORT,
            tcp: true,
            udp: false,
        }
    }
}

impl std::fmt::Display for ControlPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}(", self.port)?;
        if self.tcp {
            write!(f, "TCP")?;
            if self.udp {
                write!(f, "/")?;
            }
        }
        if self.udp {
            write!(f, "UDP")?;
        }
        write!(f, ")")
    }
}

/// Configured resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resource {
    /// Port resource.
    Port {
        id: ResourceId,
        port: u16,
        tcp: bool,
        udp: bool,
        timeout: Option<Duration>,
        users: Vec<UserId>,
    },
    Jump {
        id: ResourceId,
        input: Option<String>,
        input_match_saddr: bool,
        forward: Option<String>,
        forward_match_saddr: bool,
        output: Option<String>,
        output_match_saddr: bool,
        timeout: Option<Duration>,
        users: Vec<UserId>,
    },
}

impl Resource {
    #[must_use]
    pub fn id(&self) -> ResourceId {
        match self {
            Self::Port { id, .. } | Self::Jump { id, .. } => *id,
        }
    }

    #[must_use]
    pub fn contains_user(&self, id: UserId) -> bool {
        let users = match self {
            Self::Port { users, .. } | Self::Jump { users, .. } => users,
        };
        if users.is_empty() {
            // This resource is unrestricted.
            true
        } else {
            users.contains(&id)
        }
    }

    #[must_use]
    pub fn timeout(&self) -> Option<Duration> {
        match self {
            Self::Port { timeout, .. } | Self::Jump { timeout, .. } => *timeout,
        }
    }
}

impl std::fmt::Display for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fn write_users(
            f: &mut std::fmt::Formatter<'_>,
            users: &[UserId],
        ) -> Result<(), std::fmt::Error> {
            if !users.is_empty() {
                write!(f, "  Users: ")?;
                for (i, user) in users.iter().enumerate() {
                    if i != 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{user}")?;
                }
                writeln!(f)?;
            }
            Ok(())
        }

        fn write_timeout(
            f: &mut std::fmt::Formatter<'_>,
            timeout: Option<&Duration>,
        ) -> Result<(), std::fmt::Error> {
            if let Some(timeout) = timeout {
                writeln!(f, "  timeout: {} s", timeout.as_secs())?;
            }
            Ok(())
        }

        fn write_chain(
            f: &mut std::fmt::Formatter<'_>,
            chain: Option<&str>,
            match_saddr: bool,
            name: &str,
        ) -> Result<(), std::fmt::Error> {
            if let Some(chain) = chain {
                let match_saddr = if match_saddr { " match-saddr" } else { "" };
                writeln!(f, "  {name}-chain: {chain}{match_saddr}")?;
            }
            Ok(())
        }

        match self {
            Self::Port {
                id,
                port,
                tcp,
                udp,
                timeout,
                users,
            } => {
                let tcpudp = if *tcp && *udp {
                    "TCP/UDP"
                } else if *tcp {
                    "TCP"
                } else if *udp {
                    "UDP"
                } else {
                    ""
                };
                writeln!(f, "Port resource:")?;
                writeln!(f, "  id: {id}")?;
                writeln!(f, "  port: {port} {tcpudp}")?;
                write_timeout(f, timeout.as_ref())?;
                write_users(f, users)?;
            }
            Self::Jump {
                id,
                input,
                input_match_saddr,
                forward,
                forward_match_saddr,
                output,
                output_match_saddr,
                timeout,
                users,
            } => {
                writeln!(f, "Jump resource:")?;
                writeln!(f, "  id: {id}")?;
                write_chain(f, input.as_deref(), *input_match_saddr, "input")?;
                write_chain(f, forward.as_deref(), *forward_match_saddr, "forward")?;
                write_chain(f, output.as_deref(), *output_match_saddr, "output")?;
                write_timeout(f, timeout.as_ref())?;
                write_users(f, users)?;
            }
        }
        Ok(())
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

impl std::fmt::Display for ErrorPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::Always => write!(f, "Always"),
            Self::BasicAuth => write!(f, "Basic authentication"),
            Self::FullAuth => write!(f, "Full challenge-response authentication"),
        }
    }
}

impl std::str::FromStr for ErrorPolicy {
    type Err = ah::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "always" => Ok(ErrorPolicy::Always),
            "basic-auth" => Ok(ErrorPolicy::BasicAuth),
            "full-auth" => Ok(ErrorPolicy::FullAuth),
            other => Err(err!(
                "Config option 'control-error-policy = {other}' is not valid. \
                Valid values are: always, basic-auth, full-auth."
            )),
        }
    }
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
                "Config option 'seccomp = {other}' is not valid. \
                Valid values are: off, log, kill."
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

fn get_port(ini: &Ini) -> ah::Result<ControlPort> {
    if let Some(port) = ini.get("GENERAL", "port") {
        let mut control_port = ControlPort {
            port: PORT,
            tcp: false,
            udp: false,
        };
        let map = port.parse::<Map>().context("[GENERAL] port")?;
        for item in map.items() {
            match item {
                MapItem::KeyValues(k, _) => {
                    return Err(err!("[GENERAL] port: Unknown option: {k}"));
                }
                MapItem::Values(vs) => {
                    if vs.len() == 1 && is_number(&vs[0]) {
                        control_port.port = parse_u16(&vs[0])?;
                    } else {
                        for v in vs {
                            match &v.to_lowercase()[..] {
                                "tcp" => control_port.tcp = true,
                                "udp" => control_port.udp = true,
                                v => {
                                    return Err(err!("[GENERAL] port: Unknown option: {v}"));
                                }
                            }
                        }
                    }
                }
            }
        }
        if !control_port.tcp && !control_port.udp {
            // Default, if no tcp/udp option is given.
            control_port.tcp = true;
        }
        return Ok(control_port);
    }
    Ok(Default::default())
}

fn get_control_timeout(ini: &Ini) -> ah::Result<Duration> {
    if let Some(timeout) = ini.get("GENERAL", "control-timeout") {
        return parse_duration(timeout);
    }
    Ok(DEFAULT_CONTROL_TIMEOUT)
}

fn get_control_error_policy(ini: &Ini) -> ah::Result<ErrorPolicy> {
    if let Some(policy) = ini.get("GENERAL", "control-error-policy") {
        return policy.parse();
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

fn extract_users(id: ResourceId, users: &[String]) -> ah::Result<Vec<UserId>> {
    let mut ret = Vec::with_capacity(users.len());
    for user in users {
        if let Ok(user) = user.parse() {
            ret.push(user);
        } else {
            return Err(err!("[RESOURCE] '{id}': 'user' id is invalid"));
        }
    }
    Ok(ret)
}

fn extract_resource_port(
    id: ResourceId,
    resources: &mut HashMap<ResourceId, Resource>,
    map: &Map,
) -> ah::Result<()> {
    let mut port: Option<u16> = None;
    let mut timeout: Option<Duration> = None;
    let mut users: Vec<String> = vec![];
    let mut tcp = false;
    let mut udp = false;

    for item in map.items() {
        match item {
            MapItem::KeyValues(k, vs) => {
                if k == "port" {
                    if vs.len() == 1 {
                        if port.is_some() {
                            return Err(err!("[RESOURCE] multiple 'port' values"));
                        }
                        port = Some(parse_u16(&vs[0]).context("[RESOURCES] port")?);
                    } else {
                        return Err(err!("[RESOURCE] invalid 'port' option"));
                    }
                } else if k == "timeout" {
                    if vs.len() == 1 {
                        if timeout.is_some() {
                            return Err(err!("[RESOURCE] multiple 'timeout' values"));
                        }
                        timeout = Some(parse_duration(&vs[0]).context("[RESOURCES] timeout")?);
                    } else {
                        return Err(err!("[RESOURCE] invalid 'timeout' option"));
                    }
                } else if k == "users" {
                    if !users.is_empty() {
                        return Err(err!("[RESOURCE] multiple 'users' values"));
                    }
                    users.clone_from(vs);
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

    let users = extract_users(id, &users)?;

    for (_, res) in resources.iter() {
        match res {
            Resource::Port { port: res_port, .. } => {
                if *res_port == port {
                    return Err(err!(
                        "[RESOURCE] Multiple definitions of resource port '{port}'"
                    ));
                }
            }
            Resource::Jump { .. } => (),
        }
    }

    resources.insert(
        id,
        Resource::Port {
            id,
            port,
            tcp,
            udp,
            timeout,
            users,
        },
    );
    Ok(())
}

fn extract_resource_jump(
    id: ResourceId,
    resources: &mut HashMap<ResourceId, Resource>,
    map: &Map,
) -> ah::Result<()> {
    let mut input: Option<String> = None;
    let mut input_match_saddr = false;
    let mut forward: Option<String> = None;
    let mut forward_match_saddr = false;
    let mut output: Option<String> = None;
    let mut output_match_saddr = false;
    let mut timeout: Option<Duration> = None;
    let mut users: Vec<String> = vec![];

    for item in map.items() {
        match item {
            MapItem::KeyValues(k, vs) => {
                if k == "jump" {
                    return Err(err!("[RESOURCE] invalid 'jump' option"));
                } else if k == "input" {
                    if vs.len() == 1 {
                        input = Some(vs[0].trim().to_string());
                    } else {
                        return Err(err!("[RESOURCE] invalid 'input' option"));
                    }
                } else if k == "input-match" {
                    if vs.len() == 1 && vs[0].trim() == "saddr" {
                        input_match_saddr = true;
                    } else {
                        return Err(err!("[RESOURCE] invalid 'input-match' option"));
                    }
                } else if k == "forward" {
                    if vs.len() == 1 {
                        forward = Some(vs[0].trim().to_string());
                    } else {
                        return Err(err!("[RESOURCE] invalid 'forward' option"));
                    }
                } else if k == "forward-match" {
                    if vs.len() == 1 && vs[0].trim() == "saddr" {
                        forward_match_saddr = true;
                    } else {
                        return Err(err!("[RESOURCE] invalid 'forward-match' option"));
                    }
                } else if k == "output" {
                    if vs.len() == 1 {
                        output = Some(vs[0].trim().to_string());
                    } else {
                        return Err(err!("[RESOURCE] invalid 'output' option"));
                    }
                } else if k == "output-match" {
                    if vs.len() == 1 && vs[0].trim() == "saddr" {
                        output_match_saddr = true;
                    } else {
                        return Err(err!("[RESOURCE] invalid 'output-match' option"));
                    }
                } else if k == "timeout" {
                    if vs.len() == 1 {
                        if timeout.is_some() {
                            return Err(err!("[RESOURCE] multiple 'timeout' values"));
                        }
                        timeout = Some(parse_duration(&vs[0]).context("[RESOURCES] timeout")?);
                    } else {
                        return Err(err!("[RESOURCE] invalid 'timeout' option"));
                    }
                } else if k == "users" {
                    if !users.is_empty() {
                        return Err(err!("[RESOURCE] multiple 'users' values"));
                    }
                    users.clone_from(vs);
                } else {
                    return Err(err!("[RESOURCE] unknown option: {k}"));
                }
            }
            MapItem::Values(vs) => {
                if vs.len() == 1 && vs[0].trim() == "jump" {
                    // jump resource.
                } else {
                    return Err(err!("[RESOURCE] unknown values: {vs:?}"));
                }
            }
        }
    }

    if input.is_none() && forward.is_none() && output.is_none() {
        return Err(err!(
            "[RESOURCE] '{id}': 'jump' resource has no 'input', 'forward' or 'output' target."
        ));
    }

    let users = extract_users(id, &users)?;

    resources.insert(
        id,
        Resource::Jump {
            id,
            input,
            input_match_saddr,
            forward,
            forward_match_saddr,
            output,
            output_match_saddr,
            timeout,
            users,
        },
    );
    Ok(())
}

fn get_resources(ini: &Ini) -> ah::Result<HashMap<ResourceId, Resource>> {
    let mut resources = HashMap::new();
    if let Some(options) = ini.options_iter("RESOURCES") {
        for (id, resource) in options {
            let id: ResourceId = id.parse().context("[RESOURCES]")?;

            for res_id in resources.keys() {
                if *res_id == id {
                    return Err(err!(
                        "[RESOURCE] Multiple definitions of resource ID '{id}'"
                    ));
                }
            }

            let map = resource.parse::<Map>().context("[RESOURCES]")?;
            let mut is_port = false;
            let mut is_jump = false;

            for item in map.items() {
                match item.key() {
                    Some("port") => is_port = true,
                    Some("jump") => is_jump = true,
                    _ => (),
                }
            }

            if is_port && !is_jump {
                extract_resource_port(id, &mut resources, &map)?;
            } else if !is_port && is_jump {
                extract_resource_jump(id, &mut resources, &map)?;
            } else {
                return Err(err!(
                    "[RESOURCE] Resource ID '{id}' is not a 'port' resource."
                ));
            }
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

#[allow(clippy::unnecessary_wraps)]
fn get_nft_exe(ini: &Ini) -> ah::Result<PathBuf> {
    if let Some(nft_exe) = ini.get("NFTABLES", "exe") {
        return Ok(nft_exe.trim().into());
    }
    Ok("nft".into())
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
        Ok(String::new())
    }
}

#[allow(clippy::unnecessary_wraps)]
fn get_nft_table(ini: &Ini) -> ah::Result<String> {
    if let Some(nft_table) = ini.get("NFTABLES", "table") {
        Ok(nft_table.trim().to_string())
    } else {
        Ok(String::new())
    }
}

fn get_nft_chain(ini: &Ini, field: &str) -> ah::Result<String> {
    if let Some(chain) = ini.get("NFTABLES", field) {
        let chain = chain.trim().to_string();
        if chain.len() > MAX_CHAIN_LEN {
            Err(err!(
                "[NFTABLES] {} is {} bytes long. \
                Which exceeds the maximum of {} bytes. \
                Please choose a smaller chain name.",
                field,
                chain.len(),
                MAX_CHAIN_LEN
            ))
        } else {
            Ok(chain)
        }
    } else {
        Ok(String::new())
    }
}

fn get_nft_chain_input(ini: &Ini) -> ah::Result<String> {
    get_nft_chain(ini, "chain-input")
}

fn get_nft_chain_forward(ini: &Ini) -> ah::Result<String> {
    get_nft_chain(ini, "chain-forward")
}

fn get_nft_chain_output(ini: &Ini) -> ah::Result<String> {
    get_nft_chain(ini, "chain-output")
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

/// Parsed letmein.conf or letmeind.conf. (See [`ConfigVariant`]).
#[derive(Clone, Default, Debug)]
pub struct Config {
    checksum: ConfigChecksum,
    variant: ConfigVariant,
    path: Option<PathBuf>,
    debug: bool,
    port: ControlPort,
    control_timeout: Duration,
    control_error_policy: ErrorPolicy,
    seccomp: Seccomp,
    keys: HashMap<UserId, Key>,
    resources: HashMap<ResourceId, Resource>,
    default_user: UserId,
    nft_exe: PathBuf,
    nft_family: String,
    nft_table: String,
    nft_chain_input: String,
    nft_chain_forward: String,
    nft_chain_output: String,
    nft_timeout: Duration,
}

impl Config {
    /// Create a new configuration instance with all-default values.
    #[must_use]
    pub fn new(variant: ConfigVariant) -> Self {
        Self {
            checksum: Default::default(),
            variant,
            control_timeout: DEFAULT_CONTROL_TIMEOUT,
            nft_timeout: DEFAULT_NFT_TIMEOUT,
            ..Default::default()
        }
    }

    /// Get the default configuration file path.
    #[must_use]
    #[allow(clippy::single_match_else)]
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
    #[must_use]
    pub fn get_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// (Re-)load a configuration from a file.
    pub fn load(&mut self, path: &Path) -> ah::Result<()> {
        if let Ok(ini) = Ini::new_from_file(path) {
            self.load_ini(&ini)?;
        } else if self.variant == ConfigVariant::Server {
            return Err(err!("Failed to load configuration {}", path.display()));
        }
        self.path = Some(path.to_path_buf());
        Ok(())
    }

    /// (Re-)load a configuration from a parsed [Ini] instance.
    pub fn load_ini(&mut self, ini: &Ini) -> ah::Result<()> {
        let mut default_user = Default::default();
        let mut nft_exe = Default::default();
        let mut nft_family = Default::default();
        let mut nft_table = Default::default();
        let mut nft_chain_input = Default::default();
        let mut nft_chain_forward = Default::default();
        let mut nft_chain_output = Default::default();
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
            nft_exe = get_nft_exe(ini)?;
            nft_family = get_nft_family(ini)?;
            nft_table = get_nft_table(ini)?;
            nft_chain_input = get_nft_chain_input(ini)?;
            nft_chain_forward = get_nft_chain_forward(ini)?;
            nft_chain_output = get_nft_chain_output(ini)?;
            nft_timeout = get_nft_timeout(ini)?;
        }

        self.checksum = ini.checksum().clone();
        self.debug = debug;
        self.port = port;
        self.control_timeout = control_timeout;
        self.control_error_policy = control_error_policy;
        self.seccomp = seccomp;
        self.keys = keys;
        self.resources = resources;
        self.default_user = default_user;
        self.nft_exe = nft_exe;
        self.nft_family = nft_family;
        self.nft_table = nft_table;
        self.nft_chain_input = nft_chain_input;
        self.nft_chain_forward = nft_chain_forward;
        self.nft_chain_output = nft_chain_output;
        self.nft_timeout = nft_timeout;
        Ok(())
    }

    /// Calculate a checksum that represents the content.
    #[must_use]
    pub fn checksum(&self) -> &ConfigChecksum {
        &self.checksum
    }

    /// Get the `debug` option from `[GENERAL]` section.
    #[must_use]
    pub fn debug(&self) -> bool {
        self.debug
    }

    /// Get the `port` option from `[GENERAL]` section.
    #[must_use]
    pub fn port(&self) -> ControlPort {
        self.port
    }

    /// Get the `control-timeout` option from `[GENERAL]` section.
    #[must_use]
    pub fn control_timeout(&self) -> Duration {
        self.control_timeout
    }

    /// Get the `control-error-policy` option from `[GENERAL]` section.
    #[must_use]
    pub fn control_error_policy(&self) -> ErrorPolicy {
        self.control_error_policy
    }

    /// Get the `seccomp` option from `[GENERAL]` section.
    #[must_use]
    pub fn seccomp(&self) -> Seccomp {
        self.seccomp
    }

    /// Get a list of all configured users.
    #[must_use]
    pub fn users(&self) -> Vec<UserId> {
        let mut users: Vec<UserId> = self.keys.keys().copied().collect();
        users.sort();
        users
    }

    /// Get a key value by key identifier from the `[KEYS]` section.
    #[must_use]
    pub fn key(&self, id: UserId) -> Option<&Key> {
        self.keys.get(&id)
    }

    /// Get a list of all configured resources.
    #[must_use]
    pub fn resources(&self) -> Vec<Resource> {
        let mut resources: Vec<Resource> = self.resources.values().cloned().collect();
        resources.sort_by_key(Resource::id);
        resources
    }

    /// Get a resource value by resource identifier from the `[RESOURCES]` section.
    #[must_use]
    pub fn resource(&self, id: ResourceId) -> Option<&Resource> {
        self.resources.get(&id)
    }

    /// Lookup a resource id by a port number in the `[RESOURCES]` section.
    #[must_use]
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
                Resource::Jump { .. } => (),
            }
        }
        None
    }

    /// Get the `default-user` option from `[CLIENT]` section.
    #[must_use]
    pub fn default_user(&self) -> UserId {
        self.default_user
    }

    /// Get the `exe` option from `[NFTABLES]` section.
    #[must_use]
    pub fn nft_exe(&self) -> &Path {
        &self.nft_exe
    }

    /// Get the `family` option from `[NFTABLES]` section.
    #[must_use]
    pub fn nft_family(&self) -> &str {
        &self.nft_family
    }

    /// Get the `table` option from `[NFTABLES]` section.
    #[must_use]
    pub fn nft_table(&self) -> &str {
        &self.nft_table
    }

    /// Get the `chain-input` option from `[NFTABLES]` section.
    #[must_use]
    pub fn nft_chain_input(&self) -> &str {
        &self.nft_chain_input
    }

    /// Get the `chain-forward` option from `[NFTABLES]` section.
    #[must_use]
    pub fn nft_chain_forward(&self) -> &str {
        &self.nft_chain_forward
    }

    /// Get the `chain-output` option from `[NFTABLES]` section.
    #[must_use]
    pub fn nft_chain_output(&self) -> &str {
        &self.nft_chain_output
    }

    /// Get the `timeout` option from `[NFTABLES]` section.
    #[must_use]
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
        let cs_empty = ini.checksum().clone();
        ini.parse_str(
            "[GENERAL]\ndebug = true\nport = 1234\ncontrol-timeout=1.5\n\
            control-error-policy= basic-auth \nseccomp = kill",
        )
        .unwrap();
        let cs_parsed = ini.checksum().clone();
        assert_ne!(cs_empty, cs_parsed);
        assert!(get_debug(&ini).unwrap());
        assert_eq!(
            get_port(&ini).unwrap(),
            ControlPort {
                port: 1234,
                tcp: true,
                udp: false
            }
        );
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
    fn test_port() {
        let mut ini = Ini::new();
        ini.parse_str("[GENERAL]\nport=1234").unwrap();
        let cs_a = ini.checksum().clone();
        assert_eq!(
            get_port(&ini).unwrap(),
            ControlPort {
                port: 1234,
                tcp: true,
                udp: false
            }
        );
        ini.parse_str("[GENERAL]\nport=1234 / TCP ").unwrap();
        let cs_b = ini.checksum().clone();
        assert_eq!(
            get_port(&ini).unwrap(),
            ControlPort {
                port: 1234,
                tcp: true,
                udp: false
            }
        );
        ini.parse_str("[GENERAL]\nport=1234/UDP").unwrap();
        let cs_c = ini.checksum().clone();
        assert_eq!(
            get_port(&ini).unwrap(),
            ControlPort {
                port: 1234,
                tcp: false,
                udp: true
            }
        );
        ini.parse_str("[GENERAL]\nport=1234/ UDP , TCP").unwrap();
        assert_eq!(
            get_port(&ini).unwrap(),
            ControlPort {
                port: 1234,
                tcp: true,
                udp: true
            }
        );
        ini.parse_str("[GENERAL]\nport=udp, tcp / 1234").unwrap();
        assert_eq!(
            get_port(&ini).unwrap(),
            ControlPort {
                port: 1234,
                tcp: true,
                udp: true
            }
        );
        assert_ne!(cs_a, cs_b);
        assert_ne!(cs_b, cs_c);
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
            keys.get(&0xABCD_1234.into()).unwrap(),
            &[
                0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99, 0x88, 0x77, 0x66,
                0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
                0x11, 0x00, 0xCD, 0xEF
            ]
        );
    }

    #[test]
    fn test_resources_port() {
        let mut ini = Ini::new();
        ini.parse_str("[RESOURCES]\n9876ABCD = port : 4096\n")
            .unwrap();
        let resources = get_resources(&ini).unwrap();
        assert_eq!(
            resources.get(&0x9876_ABCD.into()).unwrap(),
            &Resource::Port {
                id: 0x9876_ABCD.into(),
                port: 4096,
                tcp: true,
                udp: false,
                timeout: None,
                users: vec![]
            }
        );

        let mut ini = Ini::new();
        ini.parse_str("[RESOURCES]\n9876ABCD = port : 4096 / TCP\n")
            .unwrap();
        let resources = get_resources(&ini).unwrap();
        assert_eq!(
            resources.get(&0x9876_ABCD.into()).unwrap(),
            &Resource::Port {
                id: 0x9876_ABCD.into(),
                port: 4096,
                tcp: true,
                udp: false,
                timeout: None,
                users: vec![]
            }
        );

        let mut ini = Ini::new();
        ini.parse_str("[RESOURCES]\n9876ABCD = port : 4096 / udp / users: 1, 2 ,3  \n")
            .unwrap();
        let resources = get_resources(&ini).unwrap();
        assert_eq!(
            resources.get(&0x9876_ABCD.into()).unwrap(),
            &Resource::Port {
                id: 0x9876_ABCD.into(),
                port: 4096,
                tcp: false,
                udp: true,
                timeout: None,
                users: vec![1.into(), 2.into(), 3.into()]
            }
        );

        let mut ini = Ini::new();
        ini.parse_str("[RESOURCES]\n9876ABCD = port : 4096 / udp, tcp / users: 4 / timeout:42\n")
            .unwrap();
        let resources = get_resources(&ini).unwrap();
        assert_eq!(
            resources.get(&0x9876_ABCD.into()).unwrap(),
            &Resource::Port {
                id: 0x9876_ABCD.into(),
                port: 4096,
                tcp: true,
                udp: true,
                timeout: Some(Duration::from_secs(42)),
                users: vec![4.into()]
            }
        );
    }

    #[test]
    fn test_resources_jump() {
        let mut ini = Ini::new();
        ini.parse_str("[RESOURCES]\n1234FEDC = jump / input: FOO\n")
            .unwrap();
        let resources = get_resources(&ini).unwrap();
        assert_eq!(
            resources.get(&0x1234_FEDC.into()).unwrap(),
            &Resource::Jump {
                id: 0x1234_FEDC.into(),
                input: Some("FOO".to_string()),
                input_match_saddr: false,
                forward: None,
                forward_match_saddr: false,
                output: None,
                output_match_saddr: false,
                timeout: None,
                users: vec![]
            }
        );

        let mut ini = Ini::new();
        ini.parse_str(
            "[RESOURCES]\n1234FEDC = jump / input: FOO / forward:BAR / input-match: saddr\n",
        )
        .unwrap();
        let resources = get_resources(&ini).unwrap();
        assert_eq!(
            resources.get(&0x1234_FEDC.into()).unwrap(),
            &Resource::Jump {
                id: 0x1234_FEDC.into(),
                input: Some("FOO".to_string()),
                input_match_saddr: true,
                forward: Some("BAR".to_string()),
                forward_match_saddr: false,
                output: None,
                output_match_saddr: false,
                timeout: None,
                users: vec![]
            }
        );

        let mut ini = Ini::new();
        ini.parse_str("[RESOURCES]\n1234FEDC = jump / input: FOO / forward:BAR / output: BIZ / users: 1, 10, 100 / output-match: saddr\n")
            .unwrap();
        let resources = get_resources(&ini).unwrap();
        assert_eq!(
            resources.get(&0x1234_FEDC.into()).unwrap(),
            &Resource::Jump {
                id: 0x1234_FEDC.into(),
                input: Some("FOO".to_string()),
                input_match_saddr: false,
                forward: Some("BAR".to_string()),
                forward_match_saddr: false,
                output: Some("BIZ".to_string()),
                output_match_saddr: true,
                timeout: None,
                users: vec![0x1.into(), 0x10.into(), 0x100.into()]
            }
        );

        let mut ini = Ini::new();
        ini.parse_str(
            "[RESOURCES]\n1234FEDC = jump / forward:BAR / forward-match: saddr / timeout: 3\n",
        )
        .unwrap();
        let resources = get_resources(&ini).unwrap();
        assert_eq!(
            resources.get(&0x1234_FEDC.into()).unwrap(),
            &Resource::Jump {
                id: 0x1234_FEDC.into(),
                input: None,
                input_match_saddr: false,
                forward: Some("BAR".to_string()),
                forward_match_saddr: true,
                output: None,
                output_match_saddr: false,
                timeout: Some(Duration::from_secs(3)),
                users: vec![]
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
            "[NFTABLES]\nexe = mynft \nfamily = ip6\ntable = myfilter\nchain-input = myLETMEIN-INPUT\ntimeout = 50\n",
        )
        .unwrap();
        let nft_exe = get_nft_exe(&ini).unwrap();
        let nft_family = get_nft_family(&ini).unwrap();
        let nft_table = get_nft_table(&ini).unwrap();
        let nft_chain_input = get_nft_chain_input(&ini).unwrap();
        let nft_timeout = get_nft_timeout(&ini).unwrap();
        assert_eq!(nft_exe, Path::new("mynft"));
        assert_eq!(nft_family, "ip6");
        assert_eq!(nft_table, "myfilter");
        assert_eq!(nft_chain_input, "myLETMEIN-INPUT");
        assert_eq!(nft_timeout, Duration::from_secs(50));
    }

    #[test]
    fn test_checksum() {
        let checksum = ConfigChecksum::calculate(b"foo");
        assert_eq!(
            checksum.as_bytes(),
            &[
                169, 20, 32, 235, 39, 155, 209, 150, 21, 4, 157, 0, 214, 7, 7, 53, 175, 241, 233,
                40, 193, 191, 156, 101, 63, 41, 34, 51, 17, 221, 76, 170
            ]
        );
    }
}

// vim: ts=4 sw=4 expandtab
