// -*- coding: utf-8 -*-
//
// Copyright (C) 2024 Michael Büsch <m@bues.ch>
//
// Licensed under the Apache License version 2.0
// or the MIT license, at your option.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_code)]

#[cfg(not(any(target_os = "linux", target_os = "android")))]
std::compile_error!("letmeind server does not support non-Linux platforms.");

mod firewall_client;
mod protocol;
mod server;

use crate::{protocol::Protocol, server::Server};
use anyhow::{self as ah, format_err as err, Context as _};
use clap::Parser;
use letmein_conf::{Config, ConfigVariant, Seccomp, INSTALL_PREFIX, SERVER_CONF_PATH};
use letmein_seccomp::{
    seccomp_supported, Action as SeccompAction, Allow as SeccompAllow, Filter as SeccompFilter,
};
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
    sync::{self, RwLock, RwLockReadGuard, Semaphore},
    task,
};

pub type ConfigRef<'a> = RwLockReadGuard<'a, Config>;

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

fn seccomp_to_action(seccomp: Seccomp) -> SeccompAction {
    match seccomp {
        Seccomp::Off | Seccomp::Log => SeccompAction::Log,
        Seccomp::Kill => SeccompAction::Kill,
    }
}

fn install_seccomp_rules(seccomp: Seccomp) -> ah::Result<()> {
    match seccomp {
        Seccomp::Log | Seccomp::Kill => {
            if seccomp_supported() {
                println!("Seccomp mode: {}", seccomp);
                SeccompFilter::compile(
                    &[
                        SeccompAllow::Mmap,
                        SeccompAllow::Mprotect,
                        SeccompAllow::Read,
                        SeccompAllow::Write,
                        SeccompAllow::Recv,
                        SeccompAllow::Send,
                        SeccompAllow::TcpAccept,
                        SeccompAllow::UnixConnect,
                        SeccompAllow::Prctl,
                        SeccompAllow::Signal,
                        SeccompAllow::Futex,
                    ],
                    seccomp_to_action(seccomp),
                )
                .context("Compile seccomp filter")?
                .install()
                .context("Install seccomp filter")?;
            } else {
                println!(
                    "WARNING: Not using seccomp. \
                    Letmein does not support seccomp on this architecture, yet."
                );
            }
        }
        Seccomp::Off => (),
    }
    Ok(())
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
}

impl Opts {
    pub fn get_config(&self) -> PathBuf {
        if let Some(config) = &self.config {
            config.clone()
        } else {
            format!("{INSTALL_PREFIX}{SERVER_CONF_PATH}").into()
        }
    }
}

async fn async_main(opts: Arc<Opts>) -> ah::Result<()> {
    make_run_subdir(&opts.rundir)?;

    let mut conf = Config::new(ConfigVariant::Server);
    conf.load(&opts.get_config())
        .context("Configuration file")?;
    let conf = Arc::new(RwLock::new(conf));

    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sighup = signal(SignalKind::hangup()).unwrap();

    let (exit_sock_tx, mut exit_sock_rx) = sync::mpsc::channel(1);

    let srv = Server::new(&conf.read().await, opts.no_systemd)
        .await
        .context("Server init")?;

    make_pidfile(&opts.rundir)?;

    install_seccomp_rules(conf.read().await.seccomp())?;

    // Task: Socket handler.
    let conf_clone = Arc::clone(&conf);
    let opts_clone = Arc::clone(&opts);
    task::spawn(async move {
        let conn_semaphore = Semaphore::new(opts_clone.num_connections);
        loop {
            let conf = Arc::clone(&conf_clone);
            let opts = Arc::clone(&opts_clone);
            match srv.accept().await {
                Ok(conn) => {
                    // Socket connection handler.
                    if let Ok(_permit) = conn_semaphore.acquire().await {
                        task::spawn(async move {
                            let conf = conf.read().await;
                            let mut proto = Protocol::new(conn, &conf, &opts.rundir);
                            if let Err(e) = proto.run().await {
                                eprintln!("Client error: {e}");
                            }
                        });
                    }
                }
                Err(e) => {
                    let _ = exit_sock_tx.send(Err(e)).await;
                    break;
                }
            }
        }
    });

    // Task: Main loop.
    let exitcode;
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
                let mut conf = conf.write().await;
                match conf.seccomp() {
                    Seccomp::Log | Seccomp::Kill => {
                        eprintln!("SIGHUP: Error: Reloading not possible with --seccomp enabled.");
                    }
                    Seccomp::Off => {
                        println!("SIGHUP: Reloading.");
                        if let Err(e) = conf.load(&opts.get_config()) {
                            eprintln!("Failed to load configuration file: {e}");
                        }
                    }
                }
            }
            code = exit_sock_rx.recv() => {
                exitcode = code.unwrap_or_else(|| Err(err!("Unknown error code.")));
                break;
            }
        }
    }

    exitcode
}

fn main() -> ah::Result<()> {
    let opts = Arc::new(Opts::parse());
    runtime::Builder::new_current_thread()
        .thread_keep_alive(Duration::from_millis(0))
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .context("Tokio runtime builder")?
        .block_on(async_main(opts))
}

// vim: ts=4 sw=4 expandtab
