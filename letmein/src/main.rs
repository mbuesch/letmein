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

use crate::command::{genkey::run_genkey, knock::run_knock};
use anyhow::{self as ah, format_err as err, Context as _};
use clap::{Parser, Subcommand};
use letmein_conf::{Config, ConfigVariant};
use letmein_proto::UserId;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::runtime;

#[cfg(any(target_os = "linux", target_os = "android"))]
use letmein_conf::Seccomp;
#[cfg(any(target_os = "linux", target_os = "android"))]
use letmein_seccomp::{include_precompiled_filters, seccomp_supported, Filter as SeccompFilter};

/// Install the precompiled `seccomp` rules, if requested.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn install_seccomp_rules(seccomp: Seccomp) -> ah::Result<()> {
    if seccomp == Seccomp::Off {
        return Ok(());
    }

    // See build.rs for the filter definition.
    include_precompiled_filters!(SECCOMP_FILTER_KILL, SECCOMP_FILTER_LOG);
    let filter_bytes = match seccomp {
        Seccomp::Log => SECCOMP_FILTER_LOG,
        Seccomp::Kill => SECCOMP_FILTER_KILL,
        Seccomp::Off => unreachable!(),
    };

    // Install seccomp filter.
    if seccomp_supported() {
        SeccompFilter::deserialize(filter_bytes)
            .install()
            .context("Install seccomp filter")?;
    } else {
        eprintln!(
            "WARNING: Not using seccomp. \
            Letmein does not support seccomp on this architecture, yet."
        );
    }

    Ok(())
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

    /// Override the `seccomp` setting from the configuration file.
    ///
    /// If this option is not given, then the value
    /// from the configuration file is used instead.
    #[cfg(any(target_os = "linux", target_os = "android"))]
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

/// Parse `UserId` helper for command line argument parsing.
fn parse_user(s: &str) -> ah::Result<UserId> {
    s.parse()
}

#[derive(Subcommand, Debug)]
enum Command {
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
    #[cfg(any(target_os = "linux", target_os = "android"))]
    install_seccomp_rules(opts.seccomp.unwrap_or(conf.seccomp()))?;

    // Run the user specified command.
    if let Some(command) = opts.command {
        match command {
            Command::Knock {
                host,
                port,
                user,
                server_port,
                ipv4,
                ipv6,
            } => {
                run_knock(
                    conf,
                    opts.verbose,
                    &host,
                    (ipv4, ipv6).into(),
                    server_port,
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
