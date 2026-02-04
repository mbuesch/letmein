// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

mod client;
mod command;
mod resolver;
mod seccomp;

use crate::{
    command::{
        genkey::run_genkey,
        knock::{KnockResource, KnockServer, run_knock, run_revoke},
    },
    resolver::{ResCrypt, ResSrv},
    seccomp::install_seccomp_rules,
};
use anyhow::{self as ah, Context as _, format_err as err};
use clap::{CommandFactory as _, Parser, Subcommand};
use letmein_conf::{Config, ConfigVariant, Seccomp};
use letmein_proto::{ResourceId, UserId};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::runtime;

/// Parse `ResSrv` helper for command line argument parsing.
fn parse_dns(dns: &str) -> ah::Result<ResSrv> {
    let mut srv = ResSrv {
        system: false,
        quad9: false,
        google: false,
        cloudflare: false,
    };
    for dns in dns.split(',') {
        match &dns.trim().to_lowercase()[..] {
            "system" => srv.system = true,
            "quad9" => srv.quad9 = true,
            "google" => srv.google = true,
            "cloudflare" => srv.cloudflare = true,
            _ => return Err(err!("Unknown DNS resolver: {dns}")),
        }
    }
    Ok(srv)
}

/// Parse `ResCrypt` helper for command line argument parsing.
fn parse_dns_crypt(dns_crypt: &str) -> ah::Result<ResCrypt> {
    let mut crypt = ResCrypt {
        tls: false,
        https: false,
        unencrypted: false,
    };
    for dns_crypt in dns_crypt.split(',') {
        match &dns_crypt.trim().to_lowercase()[..] {
            "tls" => crypt.tls = true,
            "https" => crypt.https = true,
            "unencrypted" => crypt.unencrypted = true,
            _ => return Err(err!("Unknown DNS transport encryption: {dns_crypt}")),
        }
    }
    Ok(crypt)
}

#[derive(Parser, Debug)]
struct Opts {
    /// Override the default path to the configuration file.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Show detailed information about what happens internally.
    #[arg(long)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Command>,

    /// DNS resolver service.
    ///
    /// The DNS resolver service to be used to resolve host names to IP addresses.
    /// A comma separated list with any of the following fields can be given:
    ///
    /// - system: Try the operating system resolver.
    ///   This will be tried first, if specified.
    ///
    /// - quad9: Try the Quad9 DNS service.
    ///
    /// - google: Try the Google DNS service.
    ///
    /// - cloudflare: Try the Cloudflare DNS service.
    #[arg(long, default_value = "system,quad9,google,cloudflare", value_parser = parse_dns)]
    dns: ResSrv,

    /// DNS resolver transport encryption.
    ///
    /// For all but the system resolver it may be chosen which transport
    /// encryptions to use for DNS lookup.
    /// A comma separated list with any of the following fields can be given:
    ///
    /// - tls: Use TLS encryption.
    ///
    /// - https: Use HTTPS encryption.
    ///
    /// - unencrypted: Use plain DNS lookup without encryption.
    ///   This will be tried last, if specified.
    #[arg(long, default_value = "tls,https,unencrypted", value_parser = parse_dns_crypt)]
    dns_crypt: ResCrypt,

    /// Override the `seccomp` setting from the configuration file.
    ///
    /// If this option is not given, then the value
    /// from the configuration file is used instead.
    #[arg(long)]
    seccomp: Option<Seccomp>,

    /// Show version information and exit.
    #[arg(long, short = 'v')]
    version: bool,
}

impl Opts {
    /// Get the configuration path from command line or default.
    pub fn get_config(&self) -> PathBuf {
        if let Some(config) = &self.config {
            config.clone()
        } else {
            Config::get_default_path(ConfigVariant::Client)
        }
    }
}

#[derive(Parser, Debug)]
struct KnockOrRevokeOpts {
    /// The host name, IPv4 or IPv6 address that you want to knock on.
    host: String,

    /// The port on the remote host that you want to knock open.
    /// Also see --resource
    ///
    /// The resource that will be used will be looked up by this
    /// port number from the letmein.conf configuration file.
    ///
    /// Alternatively you can use the --resource option to directly
    /// specify a resource ID.
    #[arg(conflicts_with = "resource")]
    port: Option<u16>,

    /// Specify the resource ID instead of the [PORT] to knock open.
    ///
    /// This can be used to knock open a `jump` resource.
    #[arg(long, short = 'r', conflicts_with = "port")]
    resource: Option<ResourceId>,

    /// The user identifier for authenticating the knock request.
    ///
    /// The user identifier is a 8 digits hex number.
    ///
    /// The authentication key associated with this user identifier
    /// will be fetched from the letmein.conf configuration file.
    ///
    /// If not given, then the `[CLIENT] default_user` from the
    /// configuration file will be used instead.
    /// If the configuration is not available, user 00000000 will
    /// be used instead.
    #[arg(short, long)]
    user: Option<UserId>,

    /// letmein server port number.
    ///
    /// You normally don't have to use this option.
    ///
    /// Set the letmein server port number to use when contacting the letmein server.
    ///
    /// If not given, then the `[GENERAL] port` from the
    /// letmein.conf configuration file will be used instead.
    /// If the configuration is not available, port 5800 will
    /// be used instead.
    #[arg(short = 'P', long)]
    server_port: Option<u16>,

    /// Enforce TCP connection to letmein server port.
    ///
    /// You normally don't have to use this option.
    ///
    /// If not given, then the `[GENERAL] port` from the
    /// letmein.conf configuration file will be used instead.
    /// TCP will be preferred, if both TCP and UDP are specified.
    #[arg(short = 'T', long)]
    server_port_tcp: bool,

    /// Enforce UDP connection to letmein server port.
    ///
    /// You normally don't have to use this option.
    ///
    /// If not given, then the `[GENERAL] port` from the
    /// letmein.conf configuration file will be used instead.
    /// TCP will be preferred, if both TCP and UDP are specified.
    #[arg(short = 'U', long)]
    server_port_udp: bool,

    /// Resolve HOST into an IPv4 address.
    ///
    /// Resolve the HOST into an IPv4 address and knock on that address.
    ///
    /// If none of the --ipv4 and --ipv6 options are given,
    /// then knocking on both IPv4 and IPv6 is tried, but no error is
    /// shown, if one of them failed.
    ///
    /// If both of the --ipv4 and --ipv6 options are given,
    /// then knocking on both IPv4 and IPv6 is done and an error is shown,
    /// if any one fails.
    #[arg(short = '4', long)]
    ipv4: bool,

    /// Resolve HOST into an IPv6 address.
    ///
    /// Resolve the HOST into an IPv6 address and knock on that address.
    ///
    /// If none of the --ipv4 and --ipv6 options are given,
    /// then knocking on both IPv4 and IPv6 is tried, but no error is
    /// shown, if one of them failed.
    ///
    /// If both of the --ipv4 and --ipv6 options are given,
    /// then knocking on both IPv4 and IPv6 is done and an error is shown,
    /// if any one fails.
    #[arg(short = '6', long)]
    ipv6: bool,
}

impl KnockOrRevokeOpts {
    pub fn get_server(&self) -> KnockServer<'_> {
        KnockServer {
            addr: &self.host,
            addr_mode: (self.ipv4, self.ipv6).into(),
            port: self.server_port,
            port_tcp: self.server_port_tcp,
            port_udp: self.server_port_udp,
        }
    }

    pub fn get_resource(&self) -> ah::Result<KnockResource> {
        if let Some(port) = self.port {
            Ok(KnockResource::Port(port))
        } else if let Some(resource) = self.resource {
            Ok(KnockResource::Resource(resource))
        } else {
            Err(err!(
                "Neither [PORT] nor --resource command line options were provided."
            ))
        }
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Knock a resource on a server.
    ///
    /// This opens the port in the firewall or adds jump rules to the firewall,
    /// depending on the resource type. See configuration.
    Knock {
        #[command(flatten)]
        knock: KnockOrRevokeOpts,
    },

    /// Revoke a resource on a server.
    ///
    /// This closes the port in the firewall or removes jump rules from the firewall,
    /// depending on the resource type. See configuration.
    Revoke {
        #[command(flatten)]
        revoke: KnockOrRevokeOpts,
    },

    /// Generate a new shared secret key.
    GenKey {
        /// The user identifier (8 digits hex number) to use in the
        /// generated key string.
        /// If not given, then the `[CLIENT] default_user` from the
        /// configuration file will be used instead.
        /// If the configuration is not available, user 00000000 will
        /// be used instead.
        #[arg(long, short)]
        user: Option<UserId>,
    },
}

#[rustfmt::skip]
async fn async_main(opts: Opts) -> ah::Result<()> {
    // Read the letmein.conf configuration file.
    let mut conf = Config::new(ConfigVariant::Client);
    conf.load(&opts.get_config())
        .context("Configuration file")?;
    let conf = Arc::new(conf);

    // Install `seccomp` rules, if required.
    install_seccomp_rules(opts.seccomp.unwrap_or(conf.seccomp()))?;

    // Run the user specified command.
    if let Some(command) = opts.command {
        match command {
            Command::Knock { knock } => {
                run_knock(
                    &conf,
                    opts.verbose,
                    knock.get_server(),
                    knock.get_resource()?,
                    knock.user,
                    &opts.dns,
                    &opts.dns_crypt,
                )
                .await
            }
            Command::Revoke { revoke } => {
                run_revoke(
                    &conf,
                    opts.verbose,
                    revoke.get_server(),
                    revoke.get_resource()?,
                    revoke.user,
                    &opts.dns,
                    &opts.dns_crypt,
                )
                .await
            }
            Command::GenKey {
                user,
            } => {
                run_genkey(
                    &conf,
                    user,
                )
                .await
            }
        }
    } else {
        Opts::command()
            .print_help()
            .context("Failed to print help")?;
        println!();
        Err(err!(
            "'letmein' requires a subcommand but one was not provided. \
            Please run 'letmein --help' for more information."
        ))
    }
}

fn main() -> ah::Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!("letmein version {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    runtime::Builder::new_current_thread()
        .thread_keep_alive(Duration::from_millis(0))
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .context("Tokio runtime builder")?
        .block_on(async_main(opts))
}

// vim: ts=4 sw=4 expandtab
