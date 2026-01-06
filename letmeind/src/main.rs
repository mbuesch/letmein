// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 - 2026 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

#[cfg(not(any(target_os = "linux", target_os = "android")))]
std::compile_error!("letmeind server does not support non-Linux platforms.");

mod firewall_client;
mod protocol;
mod seccomp;
mod server;

use crate::{
    protocol::Protocol,
    seccomp::install_seccomp_rules,
    server::{ConnectionOps as _, Server},
};
use anyhow::{self as ah, format_err as err, Context as _};
use clap::Parser;
use letmein_conf::{Config, ConfigVariant, Seccomp};
use std::{
    fs::{create_dir_all, metadata, OpenOptions},
    io::Write as _,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    runtime,
    signal::unix::{signal, SignalKind},
    sync::{self, Semaphore},
    task,
};

/// Create a directory, if it does not exist already.
fn create_dir_if_not_exists(path: &Path) -> ah::Result<()> {
    match metadata(path) {
        Err(_) => {
            create_dir_all(path)?;
        }
        Ok(meta) => {
            const S_IFMT: u32 = libc::S_IFMT as _;
            const S_IFDIR: u32 = libc::S_IFDIR as _;
            if (meta.mode() & S_IFMT) != S_IFDIR {
                return Err(err!("Path '{path:?}' exists, but is not a directory."));
            }
        }
    }
    Ok(())
}

/// Create the /run subdirectory.
fn make_run_subdir(rundir: &Path) -> ah::Result<()> {
    let runsubdir = rundir.join("letmeind");
    create_dir_if_not_exists(&runsubdir).context("Create /run subdirectory")?;
    Ok(())
}

/// Create the PID-file in the /run subdirectory.
fn make_pidfile(rundir: &Path) -> ah::Result<()> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(rundir.join("letmeind/letmeind.pid"))
        .context("Open PID-file")?
        .write_all(format!("{}\n", std::process::id()).as_bytes())
        .context("Write to PID-file")
}

#[derive(Parser, Debug, Clone)]
struct Opts {
    /// Override the default path to the configuration file.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// The run directory for runtime data.
    #[arg(long, default_value = "/run")]
    rundir: PathBuf,

    /// Maximum number of simultaneous connections.
    #[arg(short, long, default_value = "8")]
    num_connections: usize,

    /// Force-disable use of systemd socket.
    ///
    /// Do not use systemd socket,
    /// even if a systemd socket has been passed to the application.
    #[arg(long, default_value = "false")]
    no_systemd: bool,

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
            Config::get_default_path(ConfigVariant::Server)
        }
    }
}

async fn async_main(opts: Arc<Opts>) -> ah::Result<()> {
    // Create directories in /run
    make_run_subdir(&opts.rundir)?;

    // Read the letmeind.conf configuration file.
    let mut conf = Config::new(ConfigVariant::Server);
    conf.load(&opts.get_config())
        .context("Configuration file")?;
    let conf = Arc::new(conf);

    // Register unix signal handlers.
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sighup = signal(SignalKind::hangup()).unwrap();

    // Create async IPC channels.
    let (exit_tx, mut exit_rx) = sync::mpsc::channel(1);

    // Start the TCP control port listener.
    let mut srv = Server::new(&conf, opts.no_systemd, opts.num_connections)
        .await
        .context("Server init")?;

    // Create the PID-file.
    make_pidfile(&opts.rundir)?;

    // Install `seccomp` rules, if required.
    let seccomp = opts.seccomp.unwrap_or(conf.seccomp());
    install_seccomp_rules(seccomp)?;

    // Spawn task: Socket handler.
    task::spawn({
        let conf = Arc::clone(&conf);
        let opts = Arc::clone(&opts);

        async move {
            let conn_semaphore = Arc::new(Semaphore::new(opts.num_connections));
            loop {
                let conf = Arc::clone(&conf);
                let opts = Arc::clone(&opts);
                let conn_semaphore = Arc::clone(&conn_semaphore);
                match srv.accept().await {
                    Ok(conn) => {
                        // Socket connection handler.
                        let conn = Arc::new(conn);
                        if let Ok(permit) = conn_semaphore.acquire_owned().await {
                            let conn = Arc::clone(&conn);
                            task::spawn(async move {
                                let mut proto = Protocol::new(&*conn, &conf, &opts.rundir);
                                if let Err(e) = proto.run().await {
                                    eprintln!(
                                        "Client '{}/{}' ERROR: {}",
                                        conn.peer_addr(),
                                        conn.l4proto(),
                                        e
                                    );
                                }
                                conn.close().await;
                                drop(permit);
                            });
                        } else {
                            conn.close().await;
                        }
                    }
                    Err(e) => {
                        let _ = exit_tx.send(Err(e)).await;
                        break;
                    }
                }
            }
        }
    });

    // Task: Main loop.
    loop {
        tokio::select! {
            biased;
            code = exit_rx.recv() => {
                break code.unwrap_or_else(|| Err(err!("Unknown error code.")));
            }
            _ = sigint.recv() => {
                break Err(err!("Interrupted by SIGINT."));
            }
            _ = sigterm.recv() => {
                eprintln!("SIGTERM: Terminating.");
                break Ok(());
            }
            _ = sighup.recv() => {
                eprintln!("SIGHUP: Reloading is not supported. Please restart letmeind instead.");
            }
        }
    }
}

fn main() -> ah::Result<()> {
    let opts = Arc::new(Opts::parse());

    if opts.version {
        println!("letmeind version {}", env!("CARGO_PKG_VERSION"));
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
