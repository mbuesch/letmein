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
use anyhow::{self as ah, Context as _};
use clap::{Parser, Subcommand};
use letmein_conf::{Config, ConfigVariant, CLIENT_CONF_PATH, INSTALL_PREFIX};
use std::{path::PathBuf, sync::Arc};

#[derive(Parser, Debug)]
struct Opts {
    /// Override the default path to the configuration file.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Show detailed information about what happens internally.
    #[arg(long)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

impl Opts {
    pub fn get_config(&self) -> PathBuf {
        if let Some(config) = &self.config {
            config.clone()
        } else {
            format!("{INSTALL_PREFIX}{CLIENT_CONF_PATH}").into()
        }
    }
}

fn parse_hex(s: &str) -> ah::Result<u32> {
    Ok(u32::from_str_radix(s.trim(), 16)?)
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
        #[arg(short, long, value_parser = parse_hex)]
        user: Option<u32>,

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
        #[arg(long, short, value_parser = parse_hex)]
        user: Option<u32>,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ah::Result<()> {
    let opts = Opts::parse();

    let mut conf = Config::new(ConfigVariant::Client);
    conf.load(&opts.get_config())
        .context("Configuration file")?;
    let conf = Arc::new(conf);

    match opts.command {
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
                user.map(|user| user.into()),
            )
            .await?;
        }
        Command::GenKey { user } => run_genkey(conf, user.map(|user| user.into())).await?,
    }

    Ok(())
}

// vim: ts=4 sw=4 expandtab
