// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

mod firewall;
mod processor;
mod server;

use crate::{firewall::Firewall, processor::Processor, server::Server};
use anyhow::{self as ah, format_err as err, Context as _};
use clap::Parser;
use letmein_conf::{Config, ConfigVariant};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::{self, Mutex, RwLock, RwLockReadGuard},
    task, time,
};

const CONF_PATH: &str = "/opt/letmein/etc/letmeind.conf";

pub type ConfigRef<'a> = RwLockReadGuard<'a, Config>;

#[derive(Parser, Debug, Clone)]
struct Opts {
    /// Path to the configuration file.
    #[arg(long, default_value = CONF_PATH)]
    config: PathBuf,

    #[arg(long, default_value = "false")]
    no_systemd: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ah::Result<()> {
    let opts = Opts::parse();

    let mut conf = Config::new(ConfigVariant::Server);
    conf.load(Path::new(CONF_PATH))
        .context("Configuration file")?;
    let conf = Arc::new(RwLock::new(conf));

    let fw = Arc::new(Mutex::new(Firewall::new(&conf.read().await).await?));

    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sighup = signal(SignalKind::hangup()).unwrap();

    let (exit_sock_tx, mut exit_sock_rx) = sync::mpsc::channel(1);
    let (exit_fw_tx, mut exit_fw_rx) = sync::mpsc::channel(1);

    let srv = Server::new(&conf.read().await, opts.no_systemd)
        .await
        .context("Server init")?;

    // Task: Socket handler.
    let conf_clone = Arc::clone(&conf);
    let fw_clone = Arc::clone(&fw);
    task::spawn(async move {
        loop {
            let conf = Arc::clone(&conf_clone);
            let fw = Arc::clone(&fw_clone);
            match srv.accept().await {
                Ok(conn) => {
                    // Socket connection handler.
                    task::spawn(async move {
                        let conf = conf.read().await;
                        let mut proc = Processor::new(conn, &conf, fw);
                        if let Err(e) = proc.run().await {
                            eprintln!("Client error: {e}");
                        }
                    });
                }
                Err(e) => {
                    let _ = exit_sock_tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });

    // Firewall task.
    let conf_clone = Arc::clone(&conf);
    let fw_clone = Arc::clone(&fw);
    task::spawn(async move {
        let mut interval = time::interval(Duration::from_millis(5000));
        loop {
            interval.tick().await;
            let conf = conf_clone.read().await;
            let mut fw = fw_clone.lock().await;
            if let Err(e) = fw.maintain(&conf).await {
                let _ = exit_fw_tx.send(Err(e)).await;
                break;
            }
        }
    });

    // Main task.
    let mut exitcode;
    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                eprintln!("SIGTERM: Terminating.");
                exitcode = Ok(());
                break;
            }
            _ = sigint.recv() => {
                exitcode = Err(err!("Interrupted by SIGINT."));
                break;
            }
            _ = sighup.recv() => {
                println!("SIGHUP: Reloading.");
                {
                    let mut conf = conf.write().await;
                    if let Err(e) = conf.load(Path::new(CONF_PATH)) {
                        eprintln!("Failed to load configuration file: {e}");
                    }
                }
                {
                    let conf = conf.read().await;
                    let mut fw = fw.lock().await;
                    if let Err(e) = fw.reload(&conf).await {
                        eprintln!("Failed to reload filewall rules: {e}");
                    }
                }
            }
            code = exit_sock_rx.recv() => {
                exitcode = code.unwrap_or_else(|| Err(err!("Unknown error code.")));
                break;
            }
            code = exit_fw_rx.recv() => {
                exitcode = code.unwrap_or_else(|| Err(err!("Unknown error code.")));
                break;
            }
        }
    }

    // Exiting...
    // Try to remove all firewall rules.
    {
        let conf = conf.read().await;
        let mut fw = fw.lock().await;
        if let Err(e) = fw.clear(&conf).await {
            eprintln!("WARNING: Failed to remove firewall rules: {e}");
            if exitcode.is_ok() {
                exitcode = Err(err!("Failed to remove firewall rules"));
            }
        }
    }

    exitcode
}

// vim: ts=4 sw=4 expandtab
