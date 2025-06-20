// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
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
        knock::{run_knock, KnockServer},
        close::{run_close, CloseServer},
    },
    resolver::{ResCrypt, ResSrv},
    seccomp::install_seccomp_rules,
};
use anyhow::{self as ah, format_err as err, Context as _};
use clap::{Parser, Subcommand};
use letmein_conf::{Config, ConfigVariant, Seccomp};
use letmein_proto::UserId;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::runtime;

/// Parse `UserId` helper for command line argument parsing.
fn parse_user(s: &str) -> ah::Result<UserId> {
    s.parse()
}

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

#[derive(Subcommand, Debug)]
enum Command {
    /// Close a previously opened port on a server.
    Close {
        /// The host name, IPv4 or IPv6 address that you want to close the port on.
        host: String,

        /// The port on the remote host that you want to close.
        port: u16,

        /// The user identifier for authenticating the close request.
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
        #[arg(short, long, value_parser = parse_user)]
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
        /// Resolve the HOST into an IPv4 address and close the port on that address.
        ///
        /// If none of the --ipv4 and --ipv6 options are given,
        /// then closing on both IPv4 and IPv6 is tried, but no error is
        /// shown, if one of them failed.
        ///
        /// If both of the --ipv4 and --ipv6 options are given,
        /// then closing on both IPv4 and IPv6 is done and an error is shown,
        /// if any one fails.
        #[arg(short = '4', long)]
        ipv4: bool,

        /// Resolve HOST into an IPv6 address.
        ///
        /// Resolve the HOST into an IPv6 address and close the port on that address.
        ///
        /// If none of the --ipv4 and --ipv6 options are given,
        /// then closing on both IPv4 and IPv6 is tried, but no error is
        /// shown, if one of them failed.
        ///
        /// If both of the --ipv4 and --ipv6 options are given,
        /// then closing on both IPv4 and IPv6 is done and an error is shown,
        /// if any one fails.
        #[arg(short = '6', long)]
        ipv6: bool,
    },
    /// Knock a port open on a server.
    Knock {
        /// The host name, IPv4 or IPv6 address that you want to knock on.
        host: String,

        /// The port on the remote host that you want to knock open.
        port: u16,

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
        #[arg(short, long, value_parser = parse_user)]
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
    },

    /// Generate a new shared secret key.
    GenKey {
        /// The user identifier (8 digits hex number) to use in the
        /// generated key string.
        /// If not given, then the `[CLIENT] default_user` from the
        /// configuration file will be used instead.
        /// If the configuration is not available, user 00000000 will
        /// be used instead.
        #[arg(long, short, value_parser = parse_user)]
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
            Command::Knock {
                host,
                port,
                user,
                server_port,
                server_port_tcp,
                server_port_udp,
                ipv4,
                ipv6,
            } => {
                let server = KnockServer {
                    addr: &host,
                    addr_mode: (ipv4, ipv6).into(),
                    port: server_port,
                    port_tcp: server_port_tcp,
                    port_udp: server_port_udp,
                };
                run_knock(
                    conf,
                    opts.verbose,
                    server,
                    port,
                    user,
                    &opts.dns,
                    &opts.dns_crypt,
                )
                .await
            }
            Command::Close {
                host,
                port,
                user,
                server_port,
                server_port_tcp,
                server_port_udp,
                ipv4,
                ipv6,
            } => {
                let server = CloseServer {
                    addr: &host,
                    addr_mode: (ipv4, ipv6).into(),
                    port: server_port,
                    port_tcp: server_port_tcp,
                    port_udp: server_port_udp,
                };
                run_close(
                    conf,
                    opts.verbose,
                    server,
                    port,
                    user,
                )
                .await
            }
            Command::GenKey {
                user,
            } => {
                run_genkey(
                    conf,
                    user,
                )
                .await
            }
        }
    } else {
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
