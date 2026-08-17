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
mod limiter;
mod logging;
mod protocol;
mod seccomp;
mod server;

use crate::{
    limiter::Limiter,
    protocol::Protocol,
    seccomp::install_seccomp_rules,
    server::{ConnectionOps as _, Server},
};
use anyhow::{self as ah, Context as _, format_err as err};
use clap::Parser;
use letmein_conf::{Config, ConfigVariant, Seccomp};
use std::{
    fs::{OpenOptions, create_dir_all, metadata},
    io::Write as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    runtime,
    signal::unix::{SignalKind, signal},
    sync, task,
};

/// On the UDP level allow a higher connection limit.
/// The main limiter will quickly drop connections beyond the configured limit.
const UDP_MAXCONN_SLACK_PERCENT: usize = 25;

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
                return Err(err!(
                    "Path '{}' exists, but is not a directory.",
                    path.display()
                ));
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
        .custom_flags(libc::O_NOFOLLOW) // Trailing component must not be a symlink.
        .write(true)
        .create(true)
        .truncate(true)
        .open(rundir.join("letmeind/letmeind.pid"))
        .context("Open PID-file")?
        .write_all(format!("{}\n", std::process::id()).as_bytes())
        .context("Write to PID-file")
}

#[derive(Parser, Debug, Clone)]
pub struct Opts {
    /// Override the default path to the configuration file.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// The run directory for runtime data.
    #[arg(long, default_value = "/run")]
    rundir: PathBuf,

    /// Maximum number of simultaneous connections.
    #[arg(short, long, default_value = "64")]
    num_connections: usize,

    /// Maximum number of simultaneous connections from the same IP address.
    #[arg(short = 'N', long, default_value = "8")]
    num_ip_connections: usize,

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
    #[must_use]
    pub fn get_config(&self) -> PathBuf {
        if let Some(config) = &self.config {
            config.clone()
        } else {
            Config::get_default_path(ConfigVariant::Server)
        }
    }

    /// Get the maximum number of simultaneous UDP connections.
    #[must_use]
    pub fn get_num_udp_connections(&self) -> usize {
        (self
            .num_connections
            .saturating_mul(100 + UDP_MAXCONN_SLACK_PERCENT))
        .div_ceil(100)
        .max(1)
    }
}

fn is_expected_connection_error(err: &str) -> bool {
    matches!(
        err,
        s if s.starts_with("Unknown user:")
            || s.starts_with("Unknown resource:")
            || s.starts_with("Access denied:")
            || s == "Knock: Authentication failed"
            || s == "ComeIn: Authentication failed"
    )
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

    // Start the TCP/UDP control port listener.
    let mut srv = Server::new(&conf, opts.no_systemd, opts.get_num_udp_connections())
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
            let limiter = Arc::new(Limiter::new(&opts));

            loop {
                match srv.accept().await {
                    Ok(conn) => {
                        let limiter = Arc::clone(&limiter);
                        let conn = Arc::new(conn);

                        let Some(permit) = limiter.acquire_permit(&conn).await else {
                            log_security!(
                                WARN,
                                "CONN_LIMIT_EXCEEDED",
                                conn.peer_addr().ip(),
                                conn.l4proto()
                                => "Per-IP simultaneous connection limit exceeded. Connection dropped."
                            );
                            continue;
                        };

                        task::spawn({
                            let conf = Arc::clone(&conf);
                            let opts = Arc::clone(&opts);

                            async move {
                                let mut proto = Protocol::new(&*conn, &conf, &opts.rundir);
                                if let Err(e) = proto.run().await {
                                    let e = e.to_string();
                                    // Security events that have a dedicated log_security! call
                                    // inside Protocol::run() do not need a second line here.
                                    // This catch-all covers unexpected I/O errors and
                                    // early disconnects that are not security events.
                                    if !is_expected_connection_error(&e) {
                                        eprintln!(
                                            "letmeind: peer={}/{} -- Connection error: {}",
                                            conn.peer_addr().ip(),
                                            conn.l4proto(),
                                            e
                                        );
                                    }
                                }
                                permit.drop_permit().await;
                            }
                        });
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
